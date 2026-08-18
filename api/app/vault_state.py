# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Vault seal/unseal state machine.

Author: shdw <horizon@resurgamus.com>
Project: Resurgamus Horizon - minimal AGPL-3.0 vault for infra automation.
License: AGPL-3.0-or-later - closed-source relicensing prohibited.
AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
See: NOTICE, LICENSE-AI.md, /.well-known/tdmrep.json

The vault releases its references to long-lived runtime keys when sealed.
Rust-managed plaintext buffers are zeroized on drop. Temporary plaintext
copies owned by third-party Python libraries follow those libraries' memory
semantics and are not covered by that guarantee.

Memory encryption:
  Subkeys stored in the Python object are AES-256-GCM wrapped under a random
  per-process key. Cryptographic operations keep long-lived plaintext subkeys
  inside Rust instead of exposing them through Python properties.

  Rust extension (rhorizon_crypto):
    - mlock is best-effort by default and fail-closed in required mode
    - SecureBuffer always zeroizes and uses mlock when available
    - Rust-managed plaintext buffers live outside Python's garbage collector

Per-worker caches:
  - 2FA status: avoids 3 queries per /status call (TTL 10s + invalidation)
  - dek_key cipher: master-only Rust DekCipher; follows the configured
    memory-lock policy

Multi-worker safety (compartmentalisation):
  - Sub-keys: only the master process holds them. Followers attach a
    MasterRpcClient and delegate every crypto-op via a filesystem Unix socket.
  - DekCipher cache: master-only. Followers do not need it.
  - 2FA cache: affects status display for at most 10s; unseal reads PostgreSQL
  - Challenges: shared through the vault_challenges PostgreSQL table
  - Full audit chain: reads prev_sig under a cluster-wide transaction lock;
    audit-lite follows its separate, explicitly unchained path
"""

import asyncio
import hmac
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

import rhorizon_crypto
from rhorizon_crypto import AuditSigner, DekCipher, KeyServer, ShamirShare, WrapKey
from rhorizon_crypto import MasterRpcServer as RustMasterRpcServer

from .cluster_rpc import MasterRpcClient
from .cluster_rpc import MasterRpcServer as PythonMasterRpcServer
from .key_epoch import validate_key_epoch

log = logging.getLogger("rhorizon")

# 2FA status cache TTL (seconds)
_2FA_CACHE_TTL = 10
_RUNTIME_KEY_NAMES = (
    "hmac_key",
    "dek_key",
    "audit_key",
    "ha_wrap_key",
    "pki_wrap_key",
)
_RUNTIME_KEY_BYTES = 32
_RUNTIME_BUNDLE_BYTES = len(_RUNTIME_KEY_NAMES) * _RUNTIME_KEY_BYTES
_SHAMIR_SHARE_BYTES = 1 + _RUNTIME_BUNDLE_BYTES
_SHAMIR_PENDING_TTL_SECS = 300
_RpcRecoveryHook = Callable[[], Coroutine[Any, Any, bool]]


class VaultState:
    def __init__(self):
        self._sealed = True
        self._unsealed_at: float | None = None
        # Previous hmac_key for lazy token migration after password rotation
        self._prev_hmac_enc = None
        # Monotonic, process-local cache generation. Cleanup snapshots it before
        # committing and only clears the same generation afterwards, so a
        # concurrent password rotation cannot have its fresh prev_hmac erased.
        self._prev_hmac_generation = 0
        # dek_key cipher (Rust DekCipher: policy-locked key, AESGCM-compatible API)
        self._aesgcm: DekCipher | None = None
        # 2FA status cache: (mode, yk_count, totp_enabled, wa_count, expires_at)
        self._2fa_cache: tuple[str, int, bool, int, float] | None = None
        # Legacy one-at-a-time operator unseal accumulator. New multi-worker
        # clients submit all threshold shares atomically in one request. These
        # bytearrays are bounded, expire after five minutes, and are zeroized
        # on every clear/seal path.
        self._shamir_shares: list[bytearray] = []
        self._shamir_started_at: float | None = None
        # The key generation this process' in-RAM keys belong to. Set at
        # unseal (and after each rotation) to the DB
        # vault_config['key_epoch']. The per-node fence loop compares this to
        # the DB value: a mismatch means another host rotated and our keys are
        # stale (we would serve 500s + false audit breaks), so the node is
        # quarantined out of /readiness. Plain int -- it is metadata, not a
        # secret. None means "unstamped": after any rotation, the fence must
        # prove current-DEK decryptability before adopting the DB epoch;
        # otherwise the node is quarantined.
        self._key_epoch: int | None = None

        # Wrap key lives in Rust heap: policy-locked, zeroized on drop
        self._wrap: WrapKey = WrapKey()

        # Encrypted key storage
        self._hmac_enc: bytes | None = None
        self._dek_enc: bytes | None = None
        self._audit_enc: bytes | None = None
        # HKDF sub-key for at-rest wrap of the cluster ha_password. Constant
        # HKDF info, so dek_key rotation does not invalidate the encrypted row.
        self._ha_wrap_enc: bytes | None = None
        # Wrapped cluster ha_password itself. Loaded from
        # vault_cluster_config at unseal time. See ha_password.py.
        self._ha_password_enc: bytes | None = None
        # HKDF sub-key wrapping the PKI-engine CA private key at rest in
        # vault_pki_config. Constant HKDF info (like ha_wrap), so dek_key
        # rotation never invalidates the encrypted CA key. See pki_ca.py.
        self._pki_wrap_enc: bytes | None = None

        # Rekey-envelope X25519 keypair, dedicated to this process. The
        # rotating master seals the new-generation key bundle to each live
        # peer's rekey_pub; only the intended peer's private key can open it.
        # The origin signature authenticates the sender independently.
        # RAM-only:
        #   - _rekey_sk_enc : the 32-byte X25519 private key, wrapped under the
        #     process WrapKey (policy-locked in Rust), exactly like the subkeys.
        #   - _rekey_pub    : the 32-byte X25519 public key (published to
        #     vault_cluster_nodes.rekey_pub ; public material).
        # Generated lazily via ensure_rekey_keypair() (NOT in unseal(), so the
        # keypair is STABLE across a rotation re-unseal -- otherwise the
        # published pub would desync every rotation). seal() drops the wrapped
        # private-key ciphertext and public-key references; a fresh unseal
        # cycle regenerates the pair. A dedicated keypair (not the Ed25519 mTLS
        # identity) keeps encryption separate from signing and avoids coupling
        # the envelope to certificate rotation. The Ed25519 identity signs the
        # origin; it is never used for confidentiality.
        self._rekey_sk_enc: bytes | None = None
        self._rekey_pub: bytes | None = None

        # Primary Ed25519 audit identity signer. The symmetric audit_key remains
        # available for legacy entries and fail-safe fallback.
        # The 32-byte seed is loaded from vault_config at unseal time, decrypted
        # under dek_key, and handed directly from DekCipher to a Rust AuditSigner
        # (policy-locked, zeroize on Drop); the production load/generate/rewrap path
        # returns no clear seed to Python. Held only on the MASTER (it holds
        # dek_key); followers delegate audit_sign_identity via
        # RPC, mirroring the symmetric audit_sign path. Dropped at seal().
        self._audit_signer: AuditSigner | None = None
        # The same seed wrapped under the process WrapKey (stable across
        # rotation), pushed to the master RPC listener so followers can delegate
        # ed25519 audit signing without ever holding the seed. Dropped at seal().
        self._audit_seed_enc: bytes | None = None
        # Cached cluster audit signer fingerprint (public, derived from the
        # shared vault_config). Lets a follower tag its delegated-ed25519 rows
        # without a DB read per write. Cleared at seal() (re-read at next unseal).
        self._cluster_audit_fpr: str | None = None

        # Optional RPC client for non-master workers. When set, public crypto
        # methods delegate to the master via IPC instead of executing locally.
        # Master process keeps this None.
        self._rpc_client: MasterRpcClient | None = None
        # Optional master-side RPC server. Master starts this post-unseal so
        # workers can call in. Held here so seal() can tear it down.
        self._master_rpc_server: RustMasterRpcServer | PythonMasterRpcServer | None = (
            None
        )
        # This worker's single 161-byte Shamir share: one x-coordinate byte
        # plus a share of five 32-byte subkeys. Master keeps the first generated
        # share (x = 1); followers receive theirs at boot for failover recovery.
        self._cluster_share: ShamirShare | None = None
        # The KeyServer that exposes `_cluster_share` over a per-worker
        # share-back socket. Master serves N-1 shares to peers via this;
        # followers serve their own single share for failover collection.
        self._cluster_share_server: KeyServer | None = None
        # The blocking KeyServer accept runs through asyncio.to_thread. Track
        # its owner so failover can let the outstanding Rust borrow finish
        # before closing or replacing the server.
        self._cluster_share_task: asyncio.Task | None = None

        # Proactive RPC recovery hook.
        # Optional async callable () -> bool that detaches the stale RPC
        # client and re-attaches to whichever master is current. Set by the
        # cluster boot path (cluster_setup.wire_rpc_recovery). Returns True
        # on successful re-attach. Multiple concurrent failing crypto ops
        # share a single in-flight task via `_rpc_recovery_task` so we run
        # the recovery once per failure burst, not once per request.
        self._rpc_recover_fn: _RpcRecoveryHook | None = None
        self._rpc_recovery_task: asyncio.Task[bool] | None = None
        # A follower whose RPC recovery budget was exhausted must leave HTTP
        # rotation even while PostgreSQL still reports a fresh master
        # heartbeat. The timestamp is process-local: fencing one broken
        # worker must not evict healthy siblings or trigger an election.
        self._rpc_unreachable_since: float | None = None
        # Per-request wait budget for quick reattachment when a new master is
        # already available. A full election may take longer; the shielded
        # recovery task continues in the background. Past 3s the request gets
        # 429 + Retry-After and readiness fences until an RPC probe succeeds.
        self._rpc_recovery_budget_secs: float = 3.0
        # Serializes local role transitions that cross await points
        # (operator unseal/seal, follower attach, failover promotion/rollback).
        # Locks are event-loop-bound, so tests that reuse the singleton across
        # pytest loops receive a fresh lock; production has one loop/process.
        self._master_transition_lock: asyncio.Lock | None = None
        self._master_transition_loop: asyncio.AbstractEventLoop | None = None

    def master_transition_lock(self) -> asyncio.Lock:
        """Return this process's event-loop-local master transition lock."""
        loop = asyncio.get_running_loop()
        if (
            self._master_transition_lock is None
            or self._master_transition_loop is not loop
        ):
            self._master_transition_lock = asyncio.Lock()
            self._master_transition_loop = loop
        return self._master_transition_lock

    def _encrypt(self, plaintext: bytes | bytearray) -> bytes:
        """Encrypt key for at-rest storage in RAM."""
        if isinstance(plaintext, bytearray):
            return self._wrap.encrypt_bytearray(plaintext)
        return self._wrap.encrypt(plaintext)

    @property
    def sealed(self) -> bool:
        return self._sealed

    @property
    def key_epoch(self) -> int | None:
        """Generation marker of the in-RAM keys (None if unknown)."""
        return self._key_epoch

    def set_key_epoch(self, epoch: int | None) -> None:
        """Record the key generation this process' keys belong to.

        Called after every operation that establishes or replaces the
        in-RAM keys (unseal, rotate-password, rotate-dek-key) with the
        DB ``vault_config['key_epoch']`` value the keys correspond to.
        """
        self._key_epoch = validate_key_epoch(epoch)

    # -- Rekey envelope : X25519 keypair (RAM-only) ------------------------

    def ensure_rekey_keypair(self) -> bytes | None:
        """Generate this process' X25519 rekey keypair if absent ; return the pub.

        Idempotent : a keypair already present (same unseal lifetime) is kept,
        so the published ``rekey_pub`` stays stable across a rotation
        re-unseal. Returns the 32-byte public key, or None if the vault is
        sealed (a sealed process holds no key material to wrap the privkey
        under). Caller (the per-node heartbeat, gated on ``is_master``)
        publishes the returned pub to ``vault_cluster_nodes.rekey_pub``.

        Key generation and private-key wrapping happen atomically inside Rust.
        Python receives only the public key and wrapped private-key ciphertext;
        plaintext private-key material never enters Python memory.
        """
        if self._sealed:
            return None
        if self._rekey_sk_enc is not None:
            if self._rekey_pub is None:
                raise RuntimeError("inconsistent rekey keypair state")
            return self._rekey_pub
        public_key, encrypted_private = self._wrap.generate_rekey_keypair()
        self._rekey_pub = bytes(public_key)
        self._rekey_sk_enc = bytes(encrypted_private)
        return self._rekey_pub

    @property
    def rekey_public_key(self) -> bytes | None:
        """This process' published X25519 rekey public key (None if unset)."""
        return self._rekey_pub

    def rekey_seal_open(self, wrapped_k: bytes) -> bytearray:
        """Open a ``crypto_box_seal``'d ephemeral key K addressed to this node.

        ``wrapped_k`` is the per-node ``vault_rekey_envelope.wrapped_k``
        (libsodium sealed box to ``_rekey_pub``). Recovers K using the RAM-held
        private key. Raises if the vault is sealed, no keypair was generated,
        or the ciphertext does not open (wrong recipient / tampered). The
        returned K is the caller's to ``secure_zero`` after unwrapping the blob.
        """
        if self._sealed or self._rekey_sk_enc is None:
            raise VaultSealedError()
        return self._wrap.rekey_seal_open(self._rekey_sk_enc, wrapped_k)

    # Note: plaintext hmac_key/dek_key/audit_key/prev_hmac_key properties were
    # removed -- they leaked the subkey into Python's heap as immutable `bytes`
    # (non-zeroizable, GC-tracked). Use the operation methods below
    # (hmac_sha512_hex, aesgcm_encrypt/decrypt, audit_sign, hmac_sha512_hex_prev)
    # which keep the subkey inside Rust.

    def set_prev_hmac(self, key: bytes | bytearray | None) -> None:
        """Store previous hmac_key for lazy token migration.

        If the master RPC server is running, propagate the new encrypted
        prev-hmac to it so followers' `hmac_sha512_prev` calls keep working
        through the rotation.
        """
        if key is not None and len(key) != _RUNTIME_KEY_BYTES:
            raise ValueError("previous HMAC key must be exactly 32 bytes")
        self._prev_hmac_enc = self._encrypt(key) if key is not None else None
        self._prev_hmac_generation += 1
        if self._master_rpc_server is not None:
            try:
                self._master_rpc_server.set_prev_hmac(self._prev_hmac_enc)
            except Exception:
                # Don't fail the rotation on a sync issue; the legacy
                # Python MasterRpcServer reads `_prev_hmac_enc` directly
                # so it sees the update even without the explicit push.
                log.warning(
                    "failed to sync previous HMAC key to master RPC", exc_info=True
                )

    def clear_prev_hmac(self):
        """Remove previous hmac_key after all tokens are migrated."""
        self._prev_hmac_enc = None
        self._prev_hmac_generation += 1
        if self._master_rpc_server is not None:
            try:
                self._master_rpc_server.set_prev_hmac(None)
            except Exception:
                log.warning(
                    "failed to clear previous HMAC key from master RPC", exc_info=True
                )

    @property
    def prev_hmac_generation(self) -> int:
        """Opaque marker used to make post-commit cache cleanup race-safe."""
        return self._prev_hmac_generation

    def clear_prev_hmac_if_generation(self, generation: int) -> bool:
        """Clear only if no rotation replaced the observed cache meanwhile."""
        if self._prev_hmac_generation != generation:
            return False
        self.clear_prev_hmac()
        return True

    @property
    def aesgcm(self) -> DekCipher | None:
        """Cached AESGCM instance for DEK wrapping/unwrapping.

        Used by rotate-password (which holds old/new aesgcm as locals in
        parallel) and by internal master-side wrap paths (prev-hmac, audit
        seed, key-epoch resolution). Prefer aesgcm_encrypt/aesgcm_decrypt for
        new code; reach for the raw instance only where both keys must be
        held at once.
        """
        return self._aesgcm

    # -- subkey ops --
    #
    # Two layers:
    #   1. _*_local() methods perform the op locally in Rust (sub-keys never
    #      reach Python). Used by master process directly and by the RPC
    #      server when serving a worker request.
    #   2. async wrappers (hmac_sha512_hex, audit_sign, aesgcm_*) decide
    #      whether to execute locally or delegate to the master via RPC,
    #      based on whether _rpc_client is attached. Workers without
    #      sub-keys (token, secret, ephemeral, rotation) attach an RPC
    #      client at boot; the master process keeps it None.

    def attach_rpc_client(self, client: MasterRpcClient) -> None:
        """Attach a MasterRpcClient - non-master workers delegate crypto-ops."""
        self._rpc_client = client
        self._rpc_unreachable_since = None

    def detach_rpc_client(self) -> None:
        """Drop the RPC client (e.g. if this worker is being promoted to master)."""
        self._rpc_client = None
        self._rpc_unreachable_since = None

    @property
    def rpc_fenced(self) -> bool:
        """Whether this follower exhausted RPC recovery and must leave rotation."""
        return self._rpc_unreachable_since is not None

    def _mark_rpc_unreachable(self) -> None:
        """Fence this process after a recovery cycle failed to restore RPC."""
        if self._rpc_unreachable_since is None:
            self._rpc_unreachable_since = time.monotonic()

    def _mark_rpc_healthy(self) -> None:
        self._rpc_unreachable_since = None

    async def probe_fenced_rpc(self) -> bool:
        """Probe and clear a follower's local RPC readiness fence.

        Called only by readiness after a completed recovery failure, so normal
        probes add no crypto-RPC traffic. This tests the actual data path and
        never starts an election. A one-second outer bound keeps an unhealthy
        backend's readiness probe cheap even though normal RPC calls allow a
        longer operation timeout.
        """
        if not self.rpc_fenced:
            return True
        client = self._rpc_client
        if client is None:
            return False

        from .cluster_rpc import MasterUnreachable, RpcError

        try:
            await asyncio.wait_for(
                client.call(
                    "hmac_sha512",
                    {"message": b"rhorizon-readiness-rpc-healthcheck".hex()},
                ),
                timeout=1.0,
            )
        except (MasterUnreachable, RpcError, asyncio.TimeoutError):
            return False
        self._mark_rpc_healthy()
        return True

    def set_rpc_recovery_hook(self, recover_fn: _RpcRecoveryHook) -> None:
        """Install the async recovery callback used by `_call_rpc` on
        `MasterUnreachable`. `recover_fn` takes no arguments and returns True
        if a fresh RPC client was attached. Called at most once per concurrent
        failure burst (shared `Task`).
        """
        self._rpc_recover_fn = recover_fn

    async def _trigger_recovery(self) -> bool:
        """Either start a recovery cycle or join one in flight. Returns
        True if a new RPC client is attached within the budget. Used by
        `_call_rpc` only -- not part of the public API.
        """
        import asyncio as _asyncio

        if self._rpc_recover_fn is None:
            return False
        if self._rpc_recovery_task is None or self._rpc_recovery_task.done():
            self._rpc_recovery_task = _asyncio.create_task(self._rpc_recover_fn())
        try:
            return await _asyncio.wait_for(
                _asyncio.shield(self._rpc_recovery_task),
                self._rpc_recovery_budget_secs,
            )
        except _asyncio.TimeoutError:
            return False
        except Exception:
            # The recovery callable itself blew up (e.g. DB unreachable
            # mid-attach). Don't propagate -- `_call_rpc` re-raises the
            # original MasterUnreachable for the 429 handler and local
            # readiness fence.
            log.warning("rpc recovery hook raised", exc_info=True)
            return False

    async def _call_rpc(self, op: str, args: dict):
        """Dispatch one RPC op with proactive recovery on master loss.

        On `MasterUnreachable` (stale RPC client after a master container
        restart), trigger a detach+reattach cycle and retry once. Surface
        the original failure (re-raised
        `MasterUnreachable`) when recovery budget is exhausted; the
        FastAPI handler maps that request to `429 + Retry-After`; readiness
        independently removes this worker from rotation until RPC recovers.
        """
        from . import metrics as _m
        from .cluster_rpc import MasterUnreachable

        if self._rpc_client is None:
            # Defensive: caller must check is_master/has-client before us.
            self._mark_rpc_unreachable()
            raise MasterUnreachable("no rpc client attached")
        try:
            result = await self._rpc_client.call(op, args)
            self._mark_rpc_healthy()
            return result
        except MasterUnreachable:
            recovered = await self._trigger_recovery()
            if self.is_master:
                # Promotion completed while this request was recovering. The
                # current request still carries the follower failure, but the
                # next request will use the local crypto path.
                _m.cluster_rpc_recovery.labels(outcome="promoted").inc()
                self._mark_rpc_healthy()
                raise
            if not recovered or self._rpc_client is None:
                outcome = "timeout" if self._rpc_recover_fn else "unwired"
                if recovered and self._rpc_client is None:
                    outcome = "no_master"
                _m.cluster_rpc_recovery.labels(outcome=outcome).inc()
                self._mark_rpc_unreachable()
                raise
            try:
                result = await self._rpc_client.call(op, args)
            except MasterUnreachable:
                _m.cluster_rpc_recovery.labels(outcome="retry_failed").inc()
                self._mark_rpc_unreachable()
                raise
            _m.cluster_rpc_recovery.labels(outcome="success").inc()
            self._mark_rpc_healthy()
            return result

    @property
    def is_master(self) -> bool:
        """A process is master when it does NOT have an RPC client (it does
        the crypto locally) AND has the keys unsealed."""
        return self._rpc_client is None and not self._sealed

    def current_subkey_bundle(self) -> bytearray:
        """Assemble the 160-byte ``hmac||dek||audit||ha_wrap||pki_wrap`` sub-key
        bundle from the in-RAM subkeys, for a rekey-envelope (re)publish
        (red-timing reconciler re-seal). Master-side only; the caller MUST
        zeroize the returned bytearray. Same brief Python-heap exposure as the
        seal path and the rotation path that first builds the bundle for
        publish_envelope.
        """
        from rhorizon_crypto import secure_zero

        wrapped_keys = (
            self._hmac_enc,
            self._dek_enc,
            self._audit_enc,
            self._ha_wrap_enc,
            self._pki_wrap_enc,
        )
        if self._sealed or any(wrapped is None for wrapped in wrapped_keys):
            raise VaultSealedError()

        temporaries: list[bytearray] = []
        bundle = bytearray()
        try:
            for wrapped in wrapped_keys:
                temporary = self._wrap.decrypt(wrapped).to_bytearray()
                temporaries.append(temporary)
                if len(temporary) != 32:
                    raise ValueError("invalid wrapped subkey length")
                bundle.extend(temporary)
            return bundle
        except BaseException:
            secure_zero(bundle)
            raise
        finally:
            for temporary in temporaries:
                secure_zero(temporary)

    # -- Local-only ops (sync, used by master and by the RPC server) --

    def _hmac_sha512_hex_local(self, message) -> str:
        if self._hmac_enc is None:
            raise VaultSealedError()
        msg = message.encode() if isinstance(message, str) else message
        return self._wrap.hmac_sha512(self._hmac_enc, msg).hex()

    def _hmac_sha512_hex_prev_local(self, message) -> str | None:
        if self._prev_hmac_enc is None:
            return None
        msg = message.encode() if isinstance(message, str) else message
        return self._wrap.hmac_sha512(self._prev_hmac_enc, msg).hex()

    def _audit_sign_local(self, payload: str, prev_signature: str = "") -> str:
        if self._audit_enc is None:
            raise VaultSealedError()
        chained = (prev_signature + payload).encode()
        return self._wrap.hmac_sha512(self._audit_enc, chained).hex()

    # -- Audit chain Ed25519 identity (asymmetric signing) --

    def install_audit_signer(self, signer: AuditSigner) -> None:
        """Install a Rust ``AuditSigner`` without exposing its seed to Python.

        The signer is constructed directly from the PostgreSQL ciphertext by
        ``DekCipher`` (see audit_identity.py). ``WrapKey`` then wraps the seed
        Rust-to-Rust for the master RPC listener; Python receives ciphertext
        only. Master-side only. Replaces any previously installed signer.
        """
        # The wrap key is stable across master rotation, so this ciphertext
        # survives a rotation re-unseal.
        self._audit_seed_enc = bytes(self._wrap.wrap_audit_signer_seed(signer))
        self._audit_signer = signer
        # Push to the live master RPC listener (if this worker is master) so its
        # followers can delegate audit_sign_identity. No-op pre-master-start.
        if self._master_rpc_server is not None:
            try:
                self._master_rpc_server.set_audit_seed_enc(self._audit_seed_enc)
            except Exception:
                log.warning(
                    "failed to sync audit signer seed to master RPC", exc_info=True
                )

    def _audit_sign_identity_local(self, payload: str, prev_signature: str = "") -> str:
        """Ed25519-sign ``prev_signature || payload``. Master-side."""
        if self._audit_signer is None:
            raise VaultSealedError()
        return self._audit_signer.sign(payload, prev_signature)

    @property
    def can_audit_sign_raw(self) -> bool:
        """True for a local signer or a verified external Rust custodian."""
        if self._audit_signer is not None:
            return True
        from .cluster_rpc import CustodianRpcClient

        return isinstance(self._rpc_client, CustodianRpcClient) and bool(
            self._cluster_audit_fpr
        )

    async def audit_sign_raw(self, message: bytes) -> bytes:
        """Ed25519-sign raw bytes with the mlock'd seed -> 64-byte signature.

        Used only for standalone audit certificate issuance. A compatibility
        master signs locally; an external Rust custodian signs over its
        authenticated Unix socket. Unlike ``audit_sign_identity`` (the
        ``prev||payload`` chain message), this signs the bytes verbatim.
        """
        if self._rpc_client is not None:
            from .cluster_rpc import CustodianRpcClient

            if not isinstance(self._rpc_client, CustodianRpcClient):
                raise VaultSealedError()
            result = await self._call_rpc("audit_sign_raw", {"message": message.hex()})
            return bytes.fromhex(result)
        if self._audit_signer is None:
            raise VaultSealedError()
        return bytes(self._audit_signer.sign_raw(message))

    @property
    def has_audit_identity(self) -> bool:
        """True if this (master) process holds an audit-signing identity."""
        return self._audit_signer is not None

    @property
    def audit_identity_pub(self) -> bytes | None:
        """Raw 32-byte Ed25519 public key of the audit identity, or None."""
        if self._audit_signer is None:
            return None
        return bytes(self._audit_signer.public_key())

    @property
    def audit_identity_fpr(self) -> str | None:
        """SHA-256 hex of the audit public key -- the signer fingerprint that
        tags each audit row and keys the public cert registry. None if unset."""
        pub = self.audit_identity_pub
        if pub is None:
            return None
        import hashlib

        return hashlib.sha256(pub).hexdigest()

    def _aesgcm_encrypt_local(
        self, plaintext: bytes, aad: bytes
    ) -> tuple[bytes, bytes]:
        if self._dek_enc is None:
            raise VaultSealedError()
        wrapped = bytes(self._wrap.aesgcm_subkey_encrypt(self._dek_enc, plaintext, aad))
        return wrapped[12:], wrapped[:12]

    def _aesgcm_decrypt_local(
        self, ciphertext: bytes, nonce: bytes, aad: bytes
    ) -> bytes:
        if self._dek_enc is None:
            raise VaultSealedError()
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        wrapped = nonce + ciphertext
        plaintext = self._wrap.aesgcm_subkey_decrypt(self._dek_enc, wrapped, aad)
        try:
            return bytes(plaintext)
        finally:
            from rhorizon_crypto import secure_zero

            secure_zero(plaintext)

    @staticmethod
    def _parse_chained_secret_wire(
        result_hex: str,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """Parse wrapped_dek(60) || secret_nonce(24) || ciphertext."""
        raw = bytes.fromhex(result_hex)
        if len(raw) < 100:  # 60-byte wrapped DEK + 24-byte nonce + 16-byte tag
            raise ValueError("invalid chained secret RPC response")
        return raw[12:60], raw[:12], raw[84:], raw[60:84]

    def _secret_encrypt_local(
        self, plaintext: bytes, dek_aad: bytes, secret_aad: bytes
    ) -> tuple[bytes, bytes, bytes, bytes]:
        if self._dek_enc is None:
            raise VaultSealedError()
        result = self._wrap.chained_secret_encrypt(
            self._dek_enc, plaintext, dek_aad, secret_aad
        )
        return tuple(bytes(part) for part in result)

    def _secret_decrypt_local(
        self,
        encrypted_dek: bytes,
        dek_nonce: bytes,
        dek_aad: bytes,
        ciphertext: bytes,
        secret_nonce: bytes,
        secret_aad: bytes,
    ) -> bytearray:
        if self._dek_enc is None:
            raise VaultSealedError()
        return self._wrap.chained_secret_decrypt(
            self._dek_enc,
            encrypted_dek,
            dek_nonce,
            dek_aad,
            ciphertext,
            secret_nonce,
            secret_aad,
        )

    def _secret_reencrypt_local(
        self,
        old_encrypted_dek: bytes,
        old_dek_nonce: bytes,
        old_dek_aad: bytes,
        old_ciphertext: bytes,
        old_secret_nonce: bytes,
        old_secret_aad: bytes,
        new_dek_aad: bytes,
        new_secret_aad: bytes,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        if self._dek_enc is None:
            raise VaultSealedError()
        result = self._wrap.chained_secret_reencrypt(
            self._dek_enc,
            old_encrypted_dek,
            old_dek_nonce,
            old_dek_aad,
            old_ciphertext,
            old_secret_nonce,
            old_secret_aad,
            new_dek_aad,
            new_secret_aad,
        )
        return tuple(bytes(part) for part in result)

    def rotate_secret_from_backup(
        self,
        backup_ctx,
        dek_wrapped: bytes,
        dek_id_aad: bytes,
        ciphertext: bytes,
        nonce: bytes,
        secret_aad: bytes,
        new_dek_aad: bytes,
        new_secret_aad: bytes,
    ) -> tuple[bytes, bytes, bytes, bytes] | None:
        """Decrypt a BACKUP-context secret and re-encrypt it under the
        CURRENT vault's dek_key, entirely in Rust - the plaintext and
        both DEKs never enter Python. Master-only: `backup_ctx` (an
        ephemeral, password-derived rhorizon_crypto.BackupCryptoContext)
        exists only in this process, and reconstructing it on a follower
        via RPC would mean re-running Argon2id (~0.5-1.5s) per secret
        instead of once per restore - unacceptable for a backup with
        many secrets. Returns None on a follower; the caller falls back
        to the pre-existing Python-orchestrated path for that case
        (see api/app/routes/backup.py), which is unchanged and still
        correct, just not plaintext-free.
        """
        if not self.is_master or self._dek_enc is None:
            return None
        result = backup_ctx.rotate_secret(
            dek_wrapped,
            dek_id_aad,
            ciphertext,
            nonce,
            secret_aad,
            self._wrap,
            self._dek_enc,
            new_dek_aad,
            new_secret_aad,
        )
        return tuple(bytes(part) for part in result)

    def _ha_wrap_encrypt_local(self, plaintext: bytes, aad: bytes) -> bytes:
        """AES-256-GCM wrap under _ha_wrap_enc. Returns ``nonce || ct``.

        Master-side primitive backing the ``ha_wrap_encrypt`` RPC op. Mirrors
        :meth:`_aesgcm_encrypt_local` but uses the dedicated ha_wrap_key
        subkey (used for cluster CA
        private key + ha_password row at-rest wrapping, see
        ``cluster_ca`` and ``ha_password`` modules). Returns the combined
        ``nonce || ct`` blob (12B nonce prefix) because every consumer
        (DB row hex, RPC wire) wants it as one piece.
        """
        if self._ha_wrap_enc is None:
            raise VaultSealedError()
        return bytes(
            self._wrap.aesgcm_subkey_encrypt(self._ha_wrap_enc, plaintext, aad)
        )

    def _ha_wrap_decrypt_local(self, wrapped: bytes, aad: bytes) -> bytearray:
        """AES-256-GCM unwrap of a ``nonce || ct`` blob under _ha_wrap_enc."""
        if self._ha_wrap_enc is None:
            raise VaultSealedError()
        return self._wrap.aesgcm_subkey_decrypt(self._ha_wrap_enc, wrapped, aad)

    def _pki_wrap_encrypt_local(
        self, plaintext: bytes | bytearray, aad: bytes
    ) -> bytes:
        """AES-256-GCM wrap under _pki_wrap_enc. Returns ``nonce || ct``.

        Master-side primitive backing the ``pki_wrap_encrypt`` RPC op. Mirrors
        :meth:`_ha_wrap_encrypt_local` but uses the dedicated pki_wrap_key
        subkey (wraps the PKI-engine CA private key at rest in vault_pki_config,
        see ``pki_ca`` module).
        """
        if self._pki_wrap_enc is None:
            raise VaultSealedError()
        if isinstance(plaintext, bytearray):
            return bytes(
                self._wrap.aesgcm_subkey_encrypt_bytearray(
                    self._pki_wrap_enc, plaintext, aad
                )
            )
        return bytes(
            self._wrap.aesgcm_subkey_encrypt(self._pki_wrap_enc, plaintext, aad)
        )

    def _pki_wrap_decrypt_local(self, wrapped: bytes, aad: bytes) -> bytearray:
        """AES-256-GCM unwrap of a ``nonce || ct`` blob under _pki_wrap_enc."""
        if self._pki_wrap_enc is None:
            raise VaultSealedError()
        return self._wrap.aesgcm_subkey_decrypt(self._pki_wrap_enc, wrapped, aad)

    def _ha_password_hmac_local(self, message: str | bytes) -> str:
        """HMAC-SHA512(ha_password, message) -> hex. Master-side.

        The JOIN-proof verification recomputes this HMAC on the canonical
        message (cluster_id || node_uuid || source_ip || nonce || issued_at)
        and compares it in constant time. The HA password plaintext stays
        inside the Rust WrapKey operation; only the 64-byte HMAC tag crosses
        into Python.
        """
        if self._ha_password_enc is None:
            raise VaultSealedError()
        msg = message.encode() if isinstance(message, str) else message
        return self._wrap.hmac_sha512(self._ha_password_enc, msg).hex()

    @property
    def has_prev_hmac(self) -> bool:
        """True if a previous hmac_key is currently stored for lazy migration."""
        # Master always knows its own state. Non-master workers can't tell -
        # they only get a prev_hmac via RPC at usage time, so we conservatively
        # say "yes, ask the master" by defaulting to True when an RPC client
        # is attached. The actual prev value is None-handled at the master.
        if self._rpc_client is not None:
            return True
        return self._prev_hmac_enc is not None

    # -- Async wrappers (public API): dispatch local vs RPC --

    async def hmac_sha512_hex(self, message: str | bytes) -> str:
        if self._rpc_client is not None:
            msg_bytes = message.encode() if isinstance(message, str) else message
            return await self._call_rpc("hmac_sha512", {"message": msg_bytes.hex()})
        return self._hmac_sha512_hex_local(message)

    async def hmac_sha512_hex_prev(self, message: str | bytes) -> str | None:
        if self._rpc_client is not None:
            msg_bytes = message.encode() if isinstance(message, str) else message
            result = await self._call_rpc(
                "hmac_sha512_prev", {"message": msg_bytes.hex()}
            )
            return result if result else None
        return self._hmac_sha512_hex_prev_local(message)

    async def audit_sign(self, payload: str, prev_signature: str = "") -> str:
        if self._rpc_client is not None:
            return await self._call_rpc(
                "audit_sign",
                {"payload": payload, "prev_signature": prev_signature},
            )
        return self._audit_sign_local(payload, prev_signature)

    async def audit_sign_identity(self, payload: str, prev_signature: str = "") -> str:
        """Ed25519-sign an audit entry with the per-node identity.

        Master signs locally with the mlock'd Rust AuditSigner. A follower
        delegates to the master over RPC (op ``audit_sign_identity``), mirroring
        the symmetric ``audit_sign`` path -- the seed never leaves the master.
        """
        if self._rpc_client is not None:
            return await self._call_rpc(
                "audit_sign_identity",
                {"payload": payload, "prev_signature": prev_signature},
            )
        return self._audit_sign_identity_local(payload, prev_signature)

    async def aesgcm_encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "aesgcm_encrypt",
                {"plaintext": plaintext.hex(), "aad": aad.hex()},
            )
            # Format: 24 hex chars nonce || ciphertext
            nonce = bytes.fromhex(result_hex[:24])
            ct = bytes.fromhex(result_hex[24:])
            return ct, nonce
        return self._aesgcm_encrypt_local(plaintext, aad)

    async def aesgcm_decrypt(
        self, ciphertext: bytes, nonce: bytes, aad: bytes
    ) -> bytes:
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "aesgcm_decrypt",
                {
                    "ciphertext": ciphertext.hex(),
                    "nonce": nonce.hex(),
                    "aad": aad.hex(),
                },
            )
            return bytes.fromhex(result_hex)
        return self._aesgcm_decrypt_local(ciphertext, nonce, aad)

    async def secret_encrypt(
        self, plaintext: bytes, dek_aad: bytes, secret_aad: bytes
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """Generate/wrap a DEK and encrypt a secret without exposing the DEK."""
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "secret_encrypt",
                {
                    "plaintext": plaintext.hex(),
                    "dek_aad": dek_aad.hex(),
                    "secret_aad": secret_aad.hex(),
                },
            )
            return self._parse_chained_secret_wire(result_hex)
        return self._secret_encrypt_local(plaintext, dek_aad, secret_aad)

    async def secret_decrypt(
        self,
        encrypted_dek: bytes,
        dek_nonce: bytes,
        dek_aad: bytes,
        ciphertext: bytes,
        secret_nonce: bytes,
        secret_aad: bytes,
    ) -> bytearray:
        """Unwrap a DEK and decrypt a secret without exposing the DEK."""
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "secret_decrypt",
                {
                    "encrypted_dek": encrypted_dek.hex(),
                    "dek_nonce": dek_nonce.hex(),
                    "dek_aad": dek_aad.hex(),
                    "ciphertext": ciphertext.hex(),
                    "secret_nonce": secret_nonce.hex(),
                    "secret_aad": secret_aad.hex(),
                },
            )
            return bytearray.fromhex(result_hex)
        return self._secret_decrypt_local(
            encrypted_dek,
            dek_nonce,
            dek_aad,
            ciphertext,
            secret_nonce,
            secret_aad,
        )

    async def secret_reencrypt(
        self,
        old_encrypted_dek: bytes,
        old_dek_nonce: bytes,
        old_dek_aad: bytes,
        old_ciphertext: bytes,
        old_secret_nonce: bytes,
        old_secret_aad: bytes,
        new_dek_aad: bytes,
        new_secret_aad: bytes,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """Re-encrypt a secret under a fresh DEK entirely inside Rust."""
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "secret_reencrypt",
                {
                    "old_encrypted_dek": old_encrypted_dek.hex(),
                    "old_dek_nonce": old_dek_nonce.hex(),
                    "old_dek_aad": old_dek_aad.hex(),
                    "old_ciphertext": old_ciphertext.hex(),
                    "old_secret_nonce": old_secret_nonce.hex(),
                    "old_secret_aad": old_secret_aad.hex(),
                    "new_dek_aad": new_dek_aad.hex(),
                    "new_secret_aad": new_secret_aad.hex(),
                },
            )
            return self._parse_chained_secret_wire(result_hex)
        return self._secret_reencrypt_local(
            old_encrypted_dek,
            old_dek_nonce,
            old_dek_aad,
            old_ciphertext,
            old_secret_nonce,
            old_secret_aad,
            new_dek_aad,
            new_secret_aad,
        )

    async def ha_wrap_encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        """Wrap ``plaintext`` under ha_wrap_key. Returns ``nonce || ct``.

        Public async API used by ``ha_password.set`` and ``cluster_ca`` to
        persist at-rest blobs. On the master the
        call runs locally; on a follower it delegates via
        :meth:`_call_rpc` to the master process (only the master holds
        ``_ha_wrap_enc`` in RAM). The wire format matches
        :meth:`_ha_wrap_encrypt_local`.
        """
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "ha_wrap_encrypt",
                {"plaintext": plaintext.hex(), "aad": aad.hex()},
            )
            return bytes.fromhex(result_hex)
        return self._ha_wrap_encrypt_local(plaintext, aad)

    async def ha_wrap_decrypt(self, wrapped: bytes, aad: bytes) -> bytearray:
        """Unwrap a ``nonce || ct`` blob produced by :meth:`ha_wrap_encrypt`."""
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "ha_wrap_decrypt",
                {"wrapped": wrapped.hex(), "aad": aad.hex()},
            )
            return bytearray.fromhex(result_hex)
        return self._ha_wrap_decrypt_local(wrapped, aad)

    async def pki_wrap_encrypt(self, plaintext: bytes | bytearray, aad: bytes) -> bytes:
        """Wrap ``plaintext`` under pki_wrap_key. Returns ``nonce || ct``.

        Public async API used by ``pki_ca`` to persist the CA private key at
        rest. On the master the call runs locally; on a follower it delegates
        via :meth:`_call_rpc` to the master (only the master holds
        ``_pki_wrap_enc``). Wire format matches :meth:`_pki_wrap_encrypt_local`.
        """
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "pki_wrap_encrypt",
                {"plaintext": plaintext.hex(), "aad": aad.hex()},
            )
            return bytes.fromhex(result_hex)
        return self._pki_wrap_encrypt_local(plaintext, aad)

    async def pki_wrap_decrypt(self, wrapped: bytes, aad: bytes) -> bytearray:
        """Unwrap a ``nonce || ct`` blob produced by :meth:`pki_wrap_encrypt`."""
        if self._rpc_client is not None:
            result_hex = await self._call_rpc(
                "pki_wrap_decrypt",
                {"wrapped": wrapped.hex(), "aad": aad.hex()},
            )
            return bytearray.fromhex(result_hex)
        return self._pki_wrap_decrypt_local(wrapped, aad)

    async def ha_password_hmac(self, message: str | bytes) -> str:
        """HMAC-SHA512(ha_password, message) -> hex. Follower-safe.

        On the master, runs the local op directly. On a follower,
        delegates to the master via RPC -- only the master holds the
        wrapped ha_password buffer. Raises ``VaultSealedError`` on the master
        if the cluster has not been initialised and no HA password is loaded.
        On a follower, the master's ``VaultSealedError`` surfaces as
        ``RpcError``.
        """
        # Histogram observation wraps both the RPC path and the master-local
        # path so the metric reflects total end-to-end latency seen by JOIN.
        import time as _time

        from . import metrics as _metrics

        _start = _time.perf_counter()
        try:
            if self._rpc_client is not None:
                msg_bytes = message.encode() if isinstance(message, str) else message
                return await self._call_rpc(
                    "ha_password_hmac", {"message": msg_bytes.hex()}
                )
            return self._ha_password_hmac_local(message)
        finally:
            _metrics.cluster_rpc_latency.labels(op="ha_password_hmac").observe(
                _time.perf_counter() - _start
            )

    def export_subkeys_for_shamir(self) -> bytearray:
        """Return hmac||dek||audit||ha_wrap||pki_wrap (160B) for Shamir split.

        Shamir SSS needs the plaintext key material to split into shares -
        no way around it. Returns a bytearray (mutable) so the caller can
        zeroize it via rhorizon_crypto.secure_zero immediately after splitting.
        DO NOT use for any other purpose.

        The blob is 160B (5 sub-keys incl. ha_wrap_key + pki_wrap_key) so Shamir
        failover preserves the cluster HA membership wrap key AND the PKI CA
        wrap key (both HKDF-derived, NOT recoverable post-failover since the
        master key is never reconstructed). Reconstruct callers MUST slice
        5*32 = 160B.
        """
        return self.current_subkey_bundle()

    @property
    def uptime(self) -> str | None:
        if self._unsealed_at is None:
            return None
        elapsed = int(time.monotonic() - self._unsealed_at)
        h, m = divmod(elapsed, 3600)
        m, s = divmod(m, 60)
        return f"{h}h{m:02d}m"

    @property
    def memory_protection(self) -> str:
        """Return the Rust sensitive-buffer protection backend."""
        status = getattr(rhorizon_crypto, "memory_lock_status", None)
        return status() if status is not None else "mlock"

    @property
    def process_memory_protection(self) -> str:
        """Return the whole-process memory-lock state for this worker."""
        from .mem_hardening import process_memory_protection

        return process_memory_protection()

    @property
    def swap_protection(self) -> str:
        """Return whether persistent swap can receive plaintext pages."""
        from .mem_hardening import swap_protection

        return swap_protection()

    def unseal(self, keys: dict[str, bytes | bytearray]) -> None:
        """Store derived keys encrypted in memory - vault becomes operational."""
        missing = [name for name in _RUNTIME_KEY_NAMES if name not in keys]
        if missing:
            raise ValueError(f"missing runtime keys: {', '.join(missing)}")
        for name in _RUNTIME_KEY_NAMES:
            if len(keys[name]) != _RUNTIME_KEY_BYTES:
                raise ValueError(f"{name} must be exactly 32 bytes")

        hmac_enc = self._encrypt(keys["hmac_key"])
        dek_enc = self._encrypt(keys["dek_key"])
        audit_enc = self._encrypt(keys["audit_key"])
        ha_wrap_enc = self._encrypt(keys["ha_wrap_key"])
        pki_wrap_enc = self._encrypt(keys["pki_wrap_key"])
        # dek_key cipher: held mlock'd in Rust (DekCipher) for the whole unsealed
        # session -- the dek_key unwraps every DEK, so it gets the same anti-swap
        # custody as the other sub-keys. Drop-in for AESGCM(nonce, data, aad).
        aesgcm = DekCipher(keys["dek_key"])
        (
            self._hmac_enc,
            self._dek_enc,
            self._audit_enc,
            self._ha_wrap_enc,
            self._pki_wrap_enc,
            self._aesgcm,
        ) = (hmac_enc, dek_enc, audit_enc, ha_wrap_enc, pki_wrap_enc, aesgcm)
        self._sealed = False
        self._unsealed_at = time.monotonic()
        self._2fa_cache = None
        # If this worker is already serving as master, refresh the running
        # RPC listener's snapshot to the generation we just derived. The
        # Rust MasterRpcServer freezes its sub-keys at construction (its
        # accept loop captures one Arc and never re-reads the handle), so
        # without this push a master that rotated its own password keeps
        # serving the pre-rotation generation to its followers -- they 401
        # every fresh token and tag-fail every re-wrapped DEK while the
        # rotating master itself looks healthy. No-op at the initial unseal
        # and at failover reconstruction (server is None there; the later
        # start_master_services constructs it with the current keys).
        server = self._master_rpc_server
        if isinstance(server, RustMasterRpcServer):
            try:
                server.set_subkeys(self._hmac_enc, self._dek_enc, self._audit_enc)
                server.set_ha_wrap_enc(self._ha_wrap_enc)
                server.set_pki_wrap_enc(self._pki_wrap_enc)
                # Re-push the audit seed (stable across rotation) so the
                # refreshed listener keeps serving audit_sign_identity.
                if self._audit_seed_enc is not None:
                    server.set_audit_seed_enc(self._audit_seed_enc)
            except Exception:
                log.critical(
                    "failed to refresh master RPC key generation", exc_info=True
                )

    def seal(self) -> None:
        """Zero all encrypted buffers - vault becomes inoperative.

        NOTE: this drops the Shamir share server but intentionally does NOT
        stop ``_master_rpc_server`` (the crypto-ops listener) - seal() is
        sync and the legacy Python ``server.stop()`` is async, so it cannot
        be awaited here. Any path that seals a *master* worker must call
        ``cluster_setup.stop_master_services()`` first (see the /seal route
        and start_master_services_or_rollback) or the crypto-ops socket
        leaks as a live listener and blocks every subsequent /unseal with
        "already bound by an alive process".
        """
        # Fail-closed safety net: if a master RPC listener is still up, flip its
        # sync seal latch so it refuses crypto ops at once -- even if the async
        # stop_master_services() teardown is skipped/fails. Full key zeroization
        # still happens in stop_master_services()/Drop. The legacy Python server
        # reads vault._*_enc live, so nulling the buffers below already seals it.
        server = self._master_rpc_server
        if isinstance(server, RustMasterRpcServer):
            try:
                server.seal()
            except Exception:
                log.critical("failed to seal master RPC listener", exc_info=True)
                try:
                    server.stop()
                except Exception:
                    log.critical("failed to stop master RPC listener", exc_info=True)
        for attr in (
            "_hmac_enc",
            "_dek_enc",
            "_audit_enc",
            "_prev_hmac_enc",
            "_ha_wrap_enc",
            "_pki_wrap_enc",
            "_ha_password_enc",
            # Drop the wrapped X25519 rekey private key; a sealed process holds
            # no key material. The next unseal cycle regenerates
            # a fresh keypair (forward-secret across a seal).
            "_rekey_sk_enc",
        ):
            setattr(self, attr, None)
        self._rekey_pub = None
        # Drop the audit signer -- the Rust AuditSigner Drop zeroizes + munlocks
        # the mlock'd seed. A sealed process holds no signing key; the next
        # unseal re-loads it from vault_config.
        self._audit_signer = None
        self._audit_seed_enc = None
        self._cluster_audit_fpr = None
        self._aesgcm = None
        self._sealed = True
        self._unsealed_at = None
        self._2fa_cache = None
        self.clear_shares()
        # Drop the key generation marker -- a sealed process holds no keys,
        # so it has no epoch. A subsequent unseal re-reads it from the DB.
        self._key_epoch = None
        # Drop cluster share + share-back server.
        # The ShamirShare wraps a SecureBuffer (mlock'd); dropping triggers
        # zeroize. The share-back KeyServer.close() zeros leftover shares.
        if self._cluster_share_server is not None:
            try:
                self._cluster_share_server.close()
            except Exception:
                log.error("failed to close Shamir share server", exc_info=True)
            finally:
                self._cluster_share_server = None
        self._cluster_share_task = None
        self._cluster_share = None

    # -- Shamir share accumulation --

    def _expire_pending_shares(self) -> None:
        if (
            self._shamir_started_at is not None
            and time.monotonic() - self._shamir_started_at >= _SHAMIR_PENDING_TTL_SECS
        ):
            self.clear_shares()

    def add_share(self, share: bytes | bytearray) -> int:
        """Copy one validated operator share into the bounded accumulator."""
        from rhorizon_crypto import secure_zero

        self._expire_pending_shares()
        if len(share) != _SHAMIR_SHARE_BYTES:
            raise ValueError(
                f"Shamir share must be exactly {_SHAMIR_SHARE_BYTES} bytes"
            )
        x = share[0]
        if not 1 <= x <= 255:
            raise ValueError("Shamir share index must be between 1 and 255")

        candidate = bytearray(share)
        for existing in self._shamir_shares:
            if existing[0] == x:
                if hmac.compare_digest(existing, candidate):
                    secure_zero(candidate)
                    return len(self._shamir_shares)
                secure_zero(candidate)
                self.clear_shares()
                raise ValueError(
                    "Conflicting Shamir share index; pending shares cleared"
                )
        if not self._shamir_shares:
            self._shamir_started_at = time.monotonic()
        self._shamir_shares.append(candidate)
        return len(self._shamir_shares)

    @property
    def shamir_progress(self) -> int:
        self._expire_pending_shares()
        return len(self._shamir_shares)

    @property
    def pending_shares(self) -> list[bytearray]:
        self._expire_pending_shares()
        return list(self._shamir_shares)

    def clear_shares(self) -> None:
        from rhorizon_crypto import secure_zero

        for share in self._shamir_shares:
            secure_zero(share)
        self._shamir_shares.clear()
        self._shamir_started_at = None

    def require_unsealed(self) -> None:
        """Raise if vault is sealed."""
        if self._sealed:
            raise VaultSealedError()

    # -- 2FA status cache --

    def get_2fa_cache(self) -> tuple[str, int, bool, int] | None:
        """Return cached (mode, yk_count, totp_enabled, wa_count) or None."""
        if self._2fa_cache is None:
            return None
        mode, yk_count, totp_on, wa_count, expires = self._2fa_cache
        if time.monotonic() >= expires:
            self._2fa_cache = None
            return None
        return mode, yk_count, totp_on, wa_count

    def set_2fa_cache(
        self, mode: str, yk_count: int, totp_on: bool, wa_count: int
    ) -> None:
        self._2fa_cache = (
            mode,
            yk_count,
            totp_on,
            wa_count,
            time.monotonic() + _2FA_CACHE_TTL,
        )

    def invalidate_2fa_cache(self) -> None:
        self._2fa_cache = None


class VaultSealedError(Exception):
    pass


# Singleton
vault = VaultState()
