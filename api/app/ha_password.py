# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster ha_password storage and RAM management.

The ha_password is the cluster-membership secret. Distinct from the master
password : knowing the master decrypts secrets, knowing the ha_password lets
a node join the HA mesh.

Persistence
-----------
At-rest in `vault_cluster_config(key='ha_password_encrypted', value=hex)`,
wrapped under the dedicated `ha_wrap_key` HKDF sub-key (derived from master
alongside hmac/dek/audit -- info `ha-wrap`, constant, so DEK-key rotation
never breaks the encrypted row). Bound to AAD `vault-cluster:ha_password`
to prevent row swaps in `vault_cluster_config`.

In RAM
------
Cached on the `VaultState` singleton as a 5th encrypted buffer
(`_ha_password_enc`), wrapped by the per-process WrapKey just like
`_hmac_enc`/`_dek_enc`/`_audit_enc`/`_ha_wrap_enc`. Zeroized on seal
alongside the other sub-keys.

Lifecycle
---------
- set_ha_password : called by /cluster/init and /cluster/rotate-ha-password.
  Requires unsealed vault. Emits an audit row (`ha_password_set`) with len +
  actor; plaintext never logged.
- load_ha_password_into_ram : called from /unseal after vault.unseal,
  best-effort -- absent row is normal pre-cluster-init.
- get_encrypted_buffer : returns the wrapped bytes for HMAC-style ops via
  vault._wrap.hmac_sha512(buf, msg), used for JOIN proof verification
  without ever materialising plaintext in Python.
- clear : zero the RAM buffer (does not touch DB row). Called by seal()
  via the vault_state buffer loop.

Master-password rotation re-wraps the at-rest row under the new
ha_wrap_key in the same transaction that re-derives sub-keys, so the
ha_password survives rotation transparently. DEK-key rotation does
not touch the ha_password row (different HKDF info).

The operator re-provides the ha_password at reboot; rotation is an
immediate invalidation with no grace period.
"""

import logging

from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .audit import log_action
from .cluster_rpc import CustodianRpcClient
from .config import settings
from .key_epoch import require_generation_current
from .vault_state import VaultSealedError, vault

log = logging.getLogger("rhorizon.ha_password")

_CONFIG_KEY = "ha_password_encrypted"
_AAD = b"vault-cluster:ha_password"

# Per-node key wrap. HKDF info + AES-GCM AAD prefixes are constants ; the
# per-call binding is the node_uuid suffix. The joiner replays the same
# derivation client side using its locally-held ha_password (cf docstring
# of `wrap_node_key_for_joiner`).
_NODE_KEY_INFO_PREFIX = b"cluster-node-key-wrap:"
_NODE_KEY_AAD_PREFIX = b"vault-cluster:node-key:"

# Per-node server key wrap. Separate HKDF / AAD domains from the node-key
# wrap so a captured wrapped-server-key blob cannot be re-used as a
# node-key (or vice versa), even when the attacker knows ha_password.
_SERVER_KEY_INFO_PREFIX = b"cluster-server-key-wrap:"
_SERVER_KEY_AAD_PREFIX = b"vault-cluster:server-key:"


class HaPasswordError(RuntimeError):
    """Base error for ha_password lifecycle violations."""


class HaPasswordTooShortError(HaPasswordError):
    """Raised when set_ha_password receives a value below the configured floor."""


class HaPasswordNotLoadedError(HaPasswordError):
    """Raised when a getter is called but no ha_password is cached."""


async def _wrap_for_db(plain: bytes) -> bytes:
    """AES-256-GCM-encrypt plaintext under ha_wrap_key with AAD binding.

    Routes via :meth:`VaultState.ha_wrap_encrypt`, so a follower-routed call
    delegates to the master; master workers wrap locally (no RPC overhead).
    """
    return await vault.ha_wrap_encrypt(bytes(plain), _AAD)


async def _unwrap_from_db(wrapped: bytes) -> bytearray:
    """Mirror of :func:`_wrap_for_db`. Raises on tamper / wrong key."""
    return await vault.ha_wrap_decrypt(bytes(wrapped), _AAD)


async def set_ha_password(
    session: AsyncSession,
    plain: bytes,
    actor: str,
    ip_address: str | None = None,
) -> None:
    """Validate, encrypt at-rest, persist, cache in RAM, and audit.

    `actor` and `ip_address` are forwarded to the audit log. Callers MUST
    pass the authenticated principal -- a sentinel like 'bootstrap' or
    'system' is acceptable only when the action is genuinely system-driven.
    """
    if vault.sealed:
        raise VaultSealedError()
    if not isinstance(plain, (bytes, bytearray)):
        raise TypeError("ha_password must be bytes")
    if len(plain) < settings.ha_password_min_length:
        raise HaPasswordTooShortError(
            f"ha_password too short: {len(plain)} < {settings.ha_password_min_length}"
        )

    await require_generation_current(session, vault)
    wrapped_db = await _wrap_for_db(bytes(plain))
    await session.execute(
        text(
            "INSERT INTO vault_cluster_config (key, value) "
            "VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": _CONFIG_KEY, "v": wrapped_db.hex()},
    )

    external_custodian = isinstance(vault._rpc_client, CustodianRpcClient)
    if external_custodian:
        # The database envelope is already authenticated under ha_wrap_key.
        # Let the external custodian decrypt it directly into locked memory;
        # do not reconstruct the password in Python-owned storage.
        await vault._call_rpc("replace_ha_password", {"wrapped": wrapped_db.hex()})
    else:
        vault._ha_password_enc = vault._encrypt(bytes(plain))
        await _propagate_ha_password_to_master_rpc(plain=bytes(plain))
    await log_action(
        session,
        actor=actor,
        action="ha_password_set",
        detail={"length": len(plain)},
        ip_address=ip_address,
    )
    owner = "Rust custodian" if external_custodian else "process RAM"
    log.info(
        "ha_password: set + loaded into %s by %s (len=%d)",
        owner,
        actor,
        len(plain),
    )


async def load_ha_password_into_ram(session: AsyncSession) -> bool:
    """Best-effort load from DB to RAM. Returns True if loaded, False if absent.

    Called from /unseal after vault.unseal. A missing row is the normal
    pre-cluster-init state and is not an error -- the node simply boots
    without HA capability until /cluster/init or /cluster/join wires it.
    """
    if vault.sealed:
        raise VaultSealedError()

    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY},
        )
    ).fetchone()
    if row is None:
        log.info("ha_password: no row in vault_cluster_config (pre-cluster-init)")
        return False

    try:
        wrapped_db = bytes.fromhex(row.value)
    except (TypeError, ValueError) as exc:
        log.error("ha_password: invalid database envelope (%s)", exc)
        from . import metrics as _metrics

        _metrics.ha_password_load_failures.labels(reason="decrypt_fail").inc()
        return False

    if isinstance(vault._rpc_client, CustodianRpcClient):
        try:
            await vault._call_rpc("install_ha_password", {"wrapped": wrapped_db.hex()})
            log.info("ha_password: loaded from DB into Rust custodian")
            return True
        except Exception as exc:
            log.error("ha_password: Rust custodian install failed (%s)", exc)
            from . import metrics as _metrics

            _metrics.ha_password_load_failures.labels(
                reason="custodian_install_fail"
            ).inc()
            return False

    try:
        plain = await _unwrap_from_db(wrapped_db)
    except Exception as exc:
        log.error("ha_password: decrypt failed (%s); leaving buffer empty", exc)
        # The silent return-False path is observable via Prometheus. A
        # non-zero rate after an unseal means the cluster auth path is
        # broken even though the vault is otherwise healthy.
        from . import metrics as _metrics

        _metrics.ha_password_load_failures.labels(reason="decrypt_fail").inc()
        return False

    try:
        vault._ha_password_enc = vault._encrypt(plain)
        await _propagate_ha_password_to_master_rpc(plain=plain)
    finally:
        secure_zero(plain)
    log.info("ha_password: loaded into RAM from DB")
    return True


def is_loaded() -> bool:
    """True if a ha_password is cached in RAM on the **local worker**.

    Per-worker view : the worker that handled /cluster/init / failover
    promotion has the wrapped buffer ; sibling workers do not. Propagation
    pushes the plaintext to the **master worker's Rust state** (not to every
    worker's Python state), so a follower asking ``is_loaded`` naturally
    returns False even when the cluster is fully provisioned. Use
    :func:`is_loaded_anywhere` for the cluster-truth view (intended for
    /cluster/ha reporting from any worker).
    """
    return vault._ha_password_enc is not None


async def is_loaded_anywhere() -> bool:
    """Cluster-view ``ha_loaded`` reporting.

    Returns True if ``ha_password`` is held by *any* worker reachable
    from this process. Resolution order :

    1. Local Python ``vault._ha_password_enc`` is populated -- return
       True without an RPC hop. This covers the master worker (post-
       /unseal load or post-failover reload) and the follower that
       happens to have handled the /cluster/init that set it locally
       before propagation.
    2. We have a master RPC client attached (we are a follower) -- ask
       the master via the ``has_ha_password`` op. Surfaces "1" (master
       holds the wrapped buffer) or "0".
    3. Neither path resolves -- return False. Includes the sealed
       master pre-/unseal and the unwired-cluster case.

    Errors during the RPC hop (master unreachable, transient) degrade
    to False rather than raising : ``/cluster/ha`` is a status surface,
    not a crypto path. A follower-during-failover briefly reports False
    until the new master attaches its RPC server.

    Master-worker note: when the calling worker IS the master,
    ``vault._rpc_client`` is None (the master doesn't RPC to itself), so a
    plain RPC-client check would report False for every /cluster/ha hit
    landing on the master while another worker handled /cluster/init. Hence
    the local ``_master_rpc_server.has_ha_password_enc`` query (same process,
    no socket hop) before the RPC-client fallback.
    """
    if vault._ha_password_enc is not None:
        return True
    server = getattr(vault, "_master_rpc_server", None)
    if server is not None and hasattr(server, "has_ha_password_enc"):
        try:
            if server.has_ha_password_enc():
                return True
        except Exception as exc:
            log.debug("is_loaded_anywhere: local has_ha_password_enc raised %s", exc)
    if vault._rpc_client is None:
        return False
    try:
        result = await vault._call_rpc("has_ha_password", {})
    except Exception as exc:
        log.debug("is_loaded_anywhere: has_ha_password RPC failed (%s)", exc)
        return False
    return result == "1"


def get_encrypted_buffer() -> bytes:
    """Return the wrap-key-encrypted buffer for subkey ops.

    Pass to `vault._wrap.hmac_sha512(buf, msg)` to compute a JOIN proof
    without ever decrypting to Python. Raises if not loaded or sealed.
    """
    if vault.sealed:
        raise VaultSealedError()
    if vault._ha_password_enc is None:
        raise HaPasswordNotLoadedError("ha_password is not loaded in RAM")
    return vault._ha_password_enc


async def clear_async() -> None:
    """Drop the RAM buffer + clear the master RPC state. Idempotent.
    Does not touch the DB row. Async variant."""
    vault._ha_password_enc = None
    await _propagate_ha_password_to_master_rpc(plain=None)


def clear() -> None:
    """Sync compatibility wrapper. Drops the local buffer ; the master
    RPC state is cleared only when the local worker IS the master (the
    sync path has no event loop access for an RPC call). Async callers
    should prefer :func:`clear_async`.
    """
    vault._ha_password_enc = None
    server = getattr(vault, "_master_rpc_server", None)
    if server is not None and hasattr(server, "set_ha_password_enc"):
        try:
            server.set_ha_password_enc(None)
        except Exception as exc:  # pragma: no cover -- defensive
            log.warning("clear: set_ha_password_enc(None) raised %s", exc)


async def _propagate_ha_password_to_master_rpc(
    plain: bytes | bytearray | None,
) -> None:
    """Push the ha_password buffer to the Rust master RPC state so any
    worker's ha_password_hmac / wrap_node_key_for_joiner /
    wrap_server_key_for_joiner ops see the current value.

    Two paths :

    * **Local master** (the calling worker holds the rust server) : call
      ``set_ha_password_enc`` / ``set_ha_password_enc(None)`` directly
      on the in-process PyO3 object. No socket hop.
    * **Follower** : the calling worker has no rust server of its own ;
      route via :meth:`VaultState._call_rpc` to the master process using
      ``set_ha_password_from_plain`` / ``clear_ha_password``. Master
      receives the plaintext over the authenticated Unix socket (same
      trust boundary as ``ha_password_hmac``), encrypts under its own
      master key, and stores in state.

    Without this propagation, a /cluster/init landing on a follower
    worker writes the DB row correctly (via the ha_wrap_encrypt RPC path)
    but leaves the master's rust state ``ha_password_enc`` None ; the next
    /cluster/join then 500s on the master with "ha_password not loaded".
    """
    server = getattr(vault, "_master_rpc_server", None)
    if server is not None and hasattr(server, "set_ha_password_enc"):
        # Local master path : we ARE the master worker.
        try:
            server.set_ha_password_enc(vault._ha_password_enc)
        except Exception as exc:  # pragma: no cover -- defensive
            log.warning(
                "_propagate_ha_password_to_master_rpc: set_ha_password_enc raised %s",
                exc,
            )
        return

    if vault._rpc_client is None:
        # Neither master nor follower-with-rpc-client : nothing to push
        # (e.g. a unit test running on a bare VaultState).
        return

    # Follower path : RPC to master.
    try:
        if plain is None:
            await vault._call_rpc("clear_ha_password", {})
        else:
            await vault._call_rpc("set_ha_password_from_plain", {"plain": plain.hex()})
    except Exception as exc:  # pragma: no cover -- defensive
        log.warning(
            "_propagate_ha_password_to_master_rpc: RPC push raised %s",
            exc,
        )


async def wrap_node_key_for_joiner_dispatch(
    node_key_pem: bytes, node_uuid: str
) -> bytes:
    """Follower-safe dispatch of :func:`wrap_node_key_for_joiner`.

    Master executes the wrap locally (no RPC overhead). Followers
    delegate via :meth:`VaultState._call_rpc` because only the master
    process holds ``vault._ha_password_enc`` in RAM. Wire format : hex
    blob of ``nonce || ct``. Matches the pattern of
    :meth:`VaultState.ha_wrap_encrypt` / :meth:`VaultState.ha_password_hmac`.
    """
    if vault._rpc_client is not None:
        result_hex = await vault._call_rpc(
            "wrap_node_key_for_joiner",
            {"node_key_pem": node_key_pem.hex(), "node_uuid": node_uuid},
        )
        return bytes.fromhex(result_hex)
    return wrap_node_key_for_joiner(node_key_pem, node_uuid)


async def wrap_server_key_for_joiner_dispatch(
    server_key_pem: bytes, node_uuid: str
) -> bytes:
    """Follower-safe dispatch of :func:`wrap_server_key_for_joiner`.

    Same routing rationale as :func:`wrap_node_key_for_joiner_dispatch`,
    distinct HKDF info / AAD domain (cf module-level constants).
    """
    if vault._rpc_client is not None:
        result_hex = await vault._call_rpc(
            "wrap_server_key_for_joiner",
            {"server_key_pem": server_key_pem.hex(), "node_uuid": node_uuid},
        )
        return bytes.fromhex(result_hex)
    return wrap_server_key_for_joiner(server_key_pem, node_uuid)


def wrap_node_key_for_joiner(node_key_pem: bytes, node_uuid: str) -> bytes:
    """Encrypt ``node_key_pem`` under HKDF-SHA512(ha_password, info)[:32].

    The master mints a fresh Ed25519 keypair for a joining node
    (cf :func:`cluster_ca.sign_node_cert`) and ships the private key over
    the wire wrapped under a key derived from the cluster ha_password. The
    joiner replays the same HKDF on its locally-held ``ha_password`` to
    recover the private key, then persists it to its volume (mode 0400).

    Wrap recipe (matches the Rust primitive
    ``WrapKey.derive_and_aesgcm_encrypt``) :

      info    = b"cluster-node-key-wrap:" + node_uuid.encode()
      aad     = b"vault-cluster:node-key:" + node_uuid.encode()
      derived = HKDF-SHA512(salt=None, ikm=ha_password, info, L=32)
      nonce   = os.urandom(12)
      ct      = AES-256-GCM(derived).encrypt(nonce, node_key_pem, aad)
      output  = nonce || ct

    The derived 32B key lives only on the Rust stack and is zeroized before
    return -- it never crosses the Python boundary (doctrine: no key material
    in Python heap).

    Threat properties :
    - Wire sniffer without ``ha_password`` cannot decrypt.
    - Wire sniffer *with* ``ha_password`` could also JOIN as a new
      node themselves -- the wrap adds no leverage beyond what
      ha_password leak already gives.
    - Per-uuid info isolation : a wrapped key for node-A cannot be
      decrypted by a key derived for node-B, even with the same
      ha_password (mitigates accidental cross-node identity reuse
      and prevents a compromised node from harvesting other nodes'
      private keys via a captured JOIN response).
    """
    if vault.sealed:
        raise VaultSealedError()
    if vault._ha_password_enc is None:
        raise HaPasswordNotLoadedError("ha_password is not loaded in RAM")
    info = _NODE_KEY_INFO_PREFIX + node_uuid.encode()
    aad = _NODE_KEY_AAD_PREFIX + node_uuid.encode()
    return bytes(
        vault._wrap.derive_and_aesgcm_encrypt(
            vault._ha_password_enc, info, node_key_pem, aad
        )
    )


def unwrap_node_key_for_joiner(
    wrapped: bytes, ha_password_plain: bytes, node_uuid: str
) -> bytes:
    """Decrypt the wrapped node private key returned by /cluster/join.

    Joiner-side counterpart of :func:`wrap_node_key_for_joiner` (Rust
    primitive ``WrapKey.derive_and_aesgcm_encrypt``). The joiner replays
    the same HKDF derivation using its locally-held ``ha_password``
    plaintext (read once from ``RHORIZON_HA_PASSWORD_FILE`` at boot) to
    recover ``node_key_pem``.

    Recipe (must match the wrap side bit-for-bit) ::

        info    = b"cluster-node-key-wrap:" + node_uuid.encode()
        aad     = b"vault-cluster:node-key:" + node_uuid.encode()
        derived = HKDF-SHA512(salt=None, ikm=ha_password, info, L=32)
        nonce, ct = wrapped[:12], wrapped[12:]
        plain   = AES-256-GCM(derived).decrypt(nonce, ct, aad)

    Implementation note : ``ha_password_plain`` lives briefly on the
    Python heap here -- routing this through a Rust primitive (mirroring
    ``derive_and_aesgcm_encrypt``) was not worth re-running the full cargo
    test / clippy / miri / fuzz battery for a one-shot bootstrap-only
    decrypt path. The plaintext is read once from a tmpfs file at JOIN time
    and unlinked after the cert persists ; the production hot path (master
    signing certs for new joiners) keeps the Rust primitive.

    Raises :class:`HaPasswordError` if ``wrapped`` is shorter than the
    minimum nonce+tag size, or if AES-GCM authentication fails (wrong
    ha_password, wrong node_uuid, or tampered payload).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(wrapped) < 12 + 16:
        raise HaPasswordError(
            f"wrapped node key too short: {len(wrapped)} bytes "
            "(expected >= 28 = 12 nonce + 16 GCM tag)"
        )
    if not isinstance(ha_password_plain, (bytes, bytearray)):
        raise TypeError("ha_password_plain must be bytes")

    info = _NODE_KEY_INFO_PREFIX + node_uuid.encode()
    aad = _NODE_KEY_AAD_PREFIX + node_uuid.encode()
    nonce, ct = wrapped[:12], wrapped[12:]

    hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=None, info=info)
    derived = hkdf.derive(bytes(ha_password_plain))
    try:
        plain = AESGCM(derived).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise HaPasswordError(
            "node key unwrap failed (wrong ha_password, node_uuid, or tampered payload)"
        ) from exc
    # `derived` (the HKDF output) is immutable bytes; Python cannot zeroize it
    # in place, so the residue lingers until GC. True custody needs the
    # derive + AES-GCM to run in Rust.
    return plain


def wrap_server_key_for_joiner(server_key_pem: bytes, node_uuid: str) -> bytes:
    """Wrap an nginx server private key for a joiner.

    Same Rust primitive as :func:`wrap_node_key_for_joiner` modulo the
    HKDF info / AAD domain :

      info    = b"cluster-server-key-wrap:" + node_uuid.encode()
      aad     = b"vault-cluster:server-key:" + node_uuid.encode()
      derived = HKDF-SHA512(salt=None, ikm=ha_password, info, L=32)
      nonce   = os.urandom(12)
      ct      = AES-256-GCM(derived).encrypt(nonce, server_key_pem, aad)
      output  = nonce || ct

    Separate domain from the node-key wrap : a wrapped server-key blob
    cannot be re-cast as a node-key blob (or vice versa), even with the
    same ``ha_password`` and ``node_uuid``.
    """
    if vault.sealed:
        raise VaultSealedError()
    if vault._ha_password_enc is None:
        raise HaPasswordNotLoadedError("ha_password is not loaded in RAM")
    info = _SERVER_KEY_INFO_PREFIX + node_uuid.encode()
    aad = _SERVER_KEY_AAD_PREFIX + node_uuid.encode()
    return bytes(
        vault._wrap.derive_and_aesgcm_encrypt(
            vault._ha_password_enc, info, server_key_pem, aad
        )
    )


def unwrap_server_key_for_joiner(
    wrapped: bytes, ha_password_plain: bytes, node_uuid: str
) -> bytes:
    """Joiner-side counterpart of :func:`wrap_server_key_for_joiner`.

    Mirror of :func:`unwrap_node_key_for_joiner` (Python fallback path
    used briefly at JOIN time before the joiner has the Rust primitive
    loaded in a worker process). Same recipe modulo the info / AAD domain.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(wrapped) < 12 + 16:
        raise HaPasswordError(
            f"wrapped server key too short: {len(wrapped)} bytes "
            "(expected >= 28 = 12 nonce + 16 GCM tag)"
        )
    if not isinstance(ha_password_plain, (bytes, bytearray)):
        raise TypeError("ha_password_plain must be bytes")

    info = _SERVER_KEY_INFO_PREFIX + node_uuid.encode()
    aad = _SERVER_KEY_AAD_PREFIX + node_uuid.encode()
    nonce, ct = wrapped[:12], wrapped[12:]

    hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=None, info=info)
    derived = hkdf.derive(bytes(ha_password_plain))
    try:
        plain = AESGCM(derived).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise HaPasswordError(
            "server key unwrap failed "
            "(wrong ha_password, node_uuid, or tampered payload)"
        ) from exc
    # `derived` (the HKDF output) is immutable bytes; Python cannot zeroize it
    # in place, so the residue lingers until GC. True custody needs the
    # derive + AES-GCM to run in Rust.
    return plain


async def rewrap_for_master_rotation(
    session: AsyncSession, old_ha_wrap_key: bytes, new_ha_wrap_key: bytes
) -> bool:
    """Re-wrap the at-rest ha_password row when the master password rotates.

    Master rotation re-derives sub-keys via HKDF -- the OLD ha_wrap_key
    cannot decrypt under the NEW one. Called from /rotate-password BEFORE
    `vault.unseal(new_keys)` flips state so we can decrypt under the old
    key and re-encrypt under the new one in the same transaction.

    Returns True on successful re-wrap, False if no row exists (no-op).
    Raises on decrypt failure (master rotation must abort if at-rest data
    is unrecoverable -- silent loss of ha_password is worse than the
    failed rotation).
    """
    from rhorizon_crypto import DekCipher

    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY},
        )
    ).fetchone()
    if row is None:
        return False

    wrapped_db = bytes.fromhex(row.value)
    old_cipher = DekCipher(old_ha_wrap_key)
    new_cipher = DekCipher(new_ha_wrap_key)
    try:
        new_blob = bytes(old_cipher.rewrap_to(new_cipher, wrapped_db, _AAD)).hex()
    finally:
        del old_cipher
        del new_cipher

    await session.execute(
        text("UPDATE vault_cluster_config SET value = :v WHERE key = :k"),
        {"v": new_blob, "k": _CONFIG_KEY},
    )
    log.info("ha_password: re-wrapped under new ha_wrap_key (master rotation)")
    return True
