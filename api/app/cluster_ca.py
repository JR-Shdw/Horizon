# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster certificate authority (Option C).

The cluster mints its own self-signed CA at /cluster/init time and
uses it later to sign per-node certificates issued at /cluster/join.
After bootstrap, all node-to-cluster RPC traffic uses mTLS with these
certs ; the ha_password is only used for the initial JOIN of
brand-new nodes.

Persistence
-----------
Two rows in `vault_cluster_config` :

- ``cluster_ca_cert`` -- PEM of the self-signed CA certificate (public,
  stored in clear text -- it travels back to joiners in JOIN responses).
- ``cluster_ca_key``  -- hex(nonce || ciphertext) of the PEM-encoded CA
  private key, AES-256-GCM-wrapped under the dedicated ``ha_wrap_key``
  HKDF sub-key (info ``ha-wrap``, constant across DEK-key rotations) and
  AAD-bound to ``vault-cluster:ca_key`` (mirrors the ``ha_password``
  pattern in :mod:`api.app.ha_password`).

The CA private key never appears in plaintext outside the master
process. It is unwrapped under ``ha_wrap_key`` only when signing a
fresh node cert (/cluster/join handler) or rotating the CA itself.

Algorithm
---------
Ed25519 -- picked over RSA 4096 for the smaller key + signature
footprint, deterministic signing, and zero parameter choices (curve,
padding, hash).

Master-password rotation
------------------------
When the master password rotates, sub-keys are re-derived via HKDF ;
the OLD ``ha_wrap_key`` cannot decrypt under the NEW one.
:func:`rewrap_for_master_rotation` is called from /rotate-password
BEFORE ``vault.unseal(new_keys)`` flips state so we can decrypt under
the old key and re-encrypt under the new one in the same transaction.
"""

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from rhorizon_crypto import DekCipher
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .key_epoch import require_generation_current
from .vault_state import VaultSealedError, vault

log = logging.getLogger("rhorizon.cluster_ca")

_CONFIG_KEY_CERT = "cluster_ca_cert"
_CONFIG_KEY_KEY = "cluster_ca_key"
_CONFIG_KEY_CERT_PREV = "cluster_ca_cert_prev"
_CONFIG_KEY_ROTATED_AT = "cluster_ca_rotated_at"
_AAD = b"vault-cluster:ca_key"

_DEFAULT_CN = "rhorizon-cluster"
_DEFAULT_VALIDITY_DAYS = 365 * 10  # 10 years


def _node_cert_validity_days() -> int:
    """Per-node cert validity in days, from settings at call time.

    Reads ``settings.cluster_node_cert_validity_days`` (default 90 days,
    LE-style baseline). Tests override via env or by mutating
    ``settings``; callers may pass an explicit ``validity_days`` to
    :func:`sign_node_cert` to lock a specific span (e.g. /cluster/init
    pinning the primary's first cert at the cluster default).
    """
    return settings.cluster_node_cert_validity_days


class ClusterCaError(RuntimeError):
    """Base error for cluster CA lifecycle violations."""


class ClusterCaNotInitialisedError(ClusterCaError):
    """Raised when the CA is queried but no rows exist in vault_cluster_config."""


class ClusterCaRotationInGraceError(ClusterCaError):
    """Raised when /cluster/rotate-ca is called while a previous rotation
    is still inside its grace window (``cluster_ca_cert_prev`` row exists).

    Policy : a single generation of CA in transit at a time -- chained
    rotations would mean accepting certs signed by N CAs in parallel,
    and the audit trail of "which CA signed this cert" gets fuzzy. The
    route layer maps this to ``409 cluster_ca_rotation_in_grace``.
    Operator path : wait for the reaper to drop the prev (all-nodes-rotated
    OR grace_window expired -- see :mod:`cluster_ha_loops._reap_ca_grace`).
    """


def mint_cluster_ca(
    common_name: str = _DEFAULT_CN,
    validity_days: int = _DEFAULT_VALIDITY_DAYS,
) -> tuple[bytes, bytes, str]:
    """Generate a fresh Ed25519 self-signed CA.

    Returns ``(cert_pem, key_pem, fingerprint_hex)`` :

    - ``cert_pem`` -- PEM-encoded X.509 certificate (public, suitable for
      direct INSERT into ``vault_cluster_config('cluster_ca_cert')``).
    - ``key_pem`` -- PEM-encoded PKCS8 private key (caller MUST wrap this
      via :func:`set_cluster_ca` before persisting).
    - ``fingerprint_hex`` -- SHA-256 fingerprint of the DER form of the
      cert, lowercase hex (no colons). The cert fingerprint is the trust
      anchor advertised to joiners.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
    )
    # Ed25519 ignores the hash parameter ; cryptography requires None.
    cert = builder.sign(private_key=private_key, algorithm=None)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fingerprint_hex = compute_fingerprint(cert_pem)
    return cert_pem, key_pem, fingerprint_hex


def compute_fingerprint(cert_pem: bytes) -> str:
    """Lowercase hex SHA-256 of the DER form of a PEM-encoded cert."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return sha256(der).hexdigest()


async def _wrap_key_for_db(key_pem: bytes) -> bytes:
    """AES-256-GCM-encrypt the CA private key PEM under ha_wrap_key + AAD.

    Routes via :meth:`VaultState.ha_wrap_encrypt` so a follower-routed
    cluster route (eg /cluster/init) delegates the wrap to the master
    process.
    """
    return await vault.ha_wrap_encrypt(bytes(key_pem), _AAD)


async def _unwrap_key_from_db(wrapped: bytes) -> bytearray:
    """Mirror of :func:`_wrap_key_for_db`. Raises on tamper / wrong key / wrong AAD."""
    return await vault.ha_wrap_decrypt(bytes(wrapped), _AAD)


async def set_cluster_ca(
    session: AsyncSession, cert_pem: bytes, key_pem: bytes
) -> None:
    """Persist a freshly-minted CA in ``vault_cluster_config``.

    Both rows are INSERTed (no UPSERT) -- /cluster/init owns the lifecycle,
    so an existing row means a prior init has already happened and the
    caller MUST treat the PK violation as ``cluster already initialised``.
    CA rotation writes via a different path that explicitly swaps the rows
    in a single transaction.
    """
    if vault.sealed:
        raise VaultSealedError()
    if not cert_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise ClusterCaError("cert_pem is not a PEM-encoded certificate")
    if b"PRIVATE KEY-----" not in key_pem:
        raise ClusterCaError("key_pem is not a PEM-encoded private key")

    await require_generation_current(session, vault)
    wrapped_key = await _wrap_key_for_db(key_pem)
    await session.execute(
        text("INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v)"),
        {"k": _CONFIG_KEY_CERT, "v": cert_pem.decode("ascii")},
    )
    await session.execute(
        text("INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v)"),
        {"k": _CONFIG_KEY_KEY, "v": wrapped_key.hex()},
    )
    log.info("cluster_ca: persisted cert + wrapped key (cert %d bytes)", len(cert_pem))


async def load_cluster_ca(session: AsyncSession) -> tuple[bytes, bytearray] | None:
    """Return ``(cert_pem, key_pem)`` decrypted, or ``None`` if not initialised.

    The plaintext key PEM only leaves Rust+AES-GCM at the moment of a
    sign-operation (issuing node certs, CA rotation). Callers MUST treat
    the returned key as sensitive: do not log or persist it, and wipe the
    bytearray with ``secure_zero`` immediately after use.
    """
    if vault.sealed:
        raise VaultSealedError()

    rows = (
        await session.execute(
            text("SELECT key, value FROM vault_cluster_config WHERE key IN (:kc, :kk)"),
            {"kc": _CONFIG_KEY_CERT, "kk": _CONFIG_KEY_KEY},
        )
    ).fetchall()
    by_key = {r.key: r.value for r in rows}
    cert_pem = by_key.get(_CONFIG_KEY_CERT)
    key_blob = by_key.get(_CONFIG_KEY_KEY)
    if cert_pem is None or key_blob is None:
        return None

    key_pem = await _unwrap_key_from_db(bytes.fromhex(key_blob))
    return cert_pem.encode("ascii"), key_pem


async def load_cluster_ca_cert(session: AsyncSession) -> bytes | None:
    """Return the current CA cert PEM (public, no unwrap), or ``None``.

    Cert-only sibling of :func:`load_cluster_ca`: callers that just need the
    public CA cert (the renewal-loop chain check) skip unwrapping the key, which
    on a follower would mean a needless master RPC round-trip.
    """
    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY_CERT},
        )
    ).fetchone()
    return str(row.value).encode("ascii") if row else None


def verify_signed_by_ca(cert_pem: bytes, ca_cert_pem: bytes) -> bool:
    """True iff ``cert_pem``'s signature verifies under ``ca_cert_pem``'s key.

    Pure check (no web-layer deps), Ed25519 only (the cluster CA is Ed25519).
    The renewal loop uses it to refuse a refreshed cert that is not issued by the
    cluster CA it already trusts.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca = x509.load_pem_x509_certificate(ca_cert_pem)
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        return True
    except InvalidSignature:
        return False


async def is_initialised(session: AsyncSession) -> bool:
    """True iff both the cert and the wrapped key rows exist."""
    row = (
        await session.execute(
            text(
                "SELECT COUNT(*) AS n FROM vault_cluster_config WHERE key IN (:kc, :kk)"
            ),
            {"kc": _CONFIG_KEY_CERT, "kk": _CONFIG_KEY_KEY},
        )
    ).fetchone()
    return int(row.n) == 2


async def rewrap_for_master_rotation(
    session: AsyncSession, old_ha_wrap_key: bytes, new_ha_wrap_key: bytes
) -> bool:
    """Re-wrap the at-rest CA private key under the new ha_wrap_key.

    Master rotation re-derives sub-keys via HKDF -- the OLD ha_wrap_key
    cannot decrypt under the NEW one. Called from /rotate-password BEFORE
    ``vault.unseal(new_keys)`` flips state so we can decrypt under the
    old key and re-encrypt under the new one in the same transaction.

    Returns True on successful re-wrap, False if no row exists (no-op).
    Raises on decrypt failure -- master rotation must abort if at-rest
    data is unrecoverable (silent loss of the CA key is worse than the
    failed rotation : new node JOINs would still work via ha_password
    but no cert could ever be signed again).
    """
    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY_KEY},
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
        {"v": new_blob, "k": _CONFIG_KEY_KEY},
    )
    log.info("cluster_ca: re-wrapped CA private key under new ha_wrap_key")
    return True


def parse_cert(cert_pem: bytes) -> x509.Certificate:
    """Convenience wrapper used when issuing node certs."""
    return x509.load_pem_x509_certificate(cert_pem)


def parse_key(key_pem: bytes) -> Ed25519PrivateKey:
    """Convenience wrapper used when issuing node certs."""
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ClusterCaError("cluster CA key is not Ed25519")
    return key


def sign_node_cert(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    node_uuid: str,
    source_ip: str,
    validity_days: int | None = None,
) -> tuple[bytes, bytes]:
    """Mint a fresh Ed25519 node keypair + sign it with the cluster CA.

    Returns ``(cert_pem, key_pem)`` :

    - ``cert_pem`` -- PEM-encoded X.509 cert (CN = ``node_uuid``,
      SAN = ``source_ip``, NotAfter = now + ``validity_days``).
    - ``key_pem``  -- PEM-encoded PKCS8 private key (plaintext). The
      /cluster/join handler immediately wraps this via
      :func:`ha_password.wrap_node_key_for_joiner` before putting it on
      the wire ; the plaintext never reaches the JSON response.

    The keypair is generated server-side intentionally (hybrid model
    Option C) :  the joiner walks in with
    nothing but its ``ha_password`` and ``node_uuid``, gets a
    ready-to-use identity bundle, persists, runs. No client-side
    crypto burden, no CSR step, no "what if the joiner sends garbage
    as a pub key" failure mode. The wire confidentiality of the
    private key is provided by the wrap stage above.

    ``source_ip`` is the address as observed by the server (set by
    the route from ``request.client.host`` / ``X-Forwarded-For``
    chain) -- never what the joiner claims in its body. Encoded in a
    SubjectAlternativeName so future mTLS verification can pin the
    cert to the IP that originally bootstrapped (volume-wipe-rejoin
    from the same IP still hits the (uuid, ip) binding check at JOIN
    time -- this just keeps the binding visible inside the cert too).

    Raises :class:`ClusterCaError` if the CA key parses as anything
    other than Ed25519, or if ``source_ip`` is not a valid IPv4/IPv6
    literal. ``node_uuid`` is treated as opaque text -- callers
    enforce format upstream.
    """
    if validity_days is None:
        validity_days = _node_cert_validity_days()
    if validity_days <= 0:
        raise ClusterCaError(f"validity_days must be positive: {validity_days}")
    try:
        ip_obj = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise ClusterCaError(
            f"source_ip is not a valid IP literal: {source_ip}"
        ) from exc

    ca_cert = parse_cert(ca_cert_pem)
    ca_key = parse_key(ca_key_pem)

    node_private_key = Ed25519PrivateKey.generate()
    node_public_key = node_private_key.public_key()

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_uuid)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(node_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_obj)]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(node_public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    # Ed25519 ignores the hash parameter ; cryptography requires None.
    node_cert = builder.sign(private_key=ca_key, algorithm=None)

    cert_pem = node_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = node_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    log.info(
        "cluster_ca: signed node cert for uuid=%s ip=%s validity=%dd",
        node_uuid,
        source_ip,
        validity_days,
    )
    return cert_pem, key_pem


def _server_cert_validity_days() -> int:
    """Per-node server cert validity in days.

    Mirrors :func:`_node_cert_validity_days` but reads
    ``settings.cluster_server_cert_validity_days``. The two settings
    track separately so an operator who wants different renewal cadences
    for identity vs. nginx server certs can dial them independently ;
    the defaults match (90 days, LE-baseline).
    """
    return settings.cluster_server_cert_validity_days


_DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def sign_server_cert(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    san_ips: list[str],
    san_dns: list[str],
    validity_days: int | None = None,
) -> tuple[bytes, bytes]:
    """Mint a fresh Ed25519 server keypair + sign it with the cluster CA.

    primitive. Returns ``(cert_pem, key_pem)`` PEM
    pair :

    - ``cert_pem`` -- X.509 cert with EKU=server_auth, SAN populated
      from ``san_ips`` (IPAddress entries) and ``san_dns`` (DNSName
      entries). Subject CN is the first ``san_dns`` if any, otherwise
      the first ``san_ips`` -- nginx never relies on CN for TLS, the
      SAN is what matters, but a non-empty CN keeps tools happy.
    - ``key_pem`` -- PEM PKCS8 plaintext. Same wire-confidentiality
      story as :func:`sign_node_cert` -- the caller (``/cluster/join``
      handler or ``/cluster/issue-server-cert`` route) wraps it under
      HKDF(ha_password, "cluster-server-key-wrap:<uuid>") or returns
      it directly over an admin-authenticated channel.

    Differences vs. :func:`sign_node_cert` :

    - EKU is ``SERVER_AUTH`` only (no CLIENT_AUTH). A server cert that
      could also act as a mTLS client cert collapses the trust surfaces
      we explicitly want kept apart.
    - SAN carries IPs *and* DNS names. ``/cluster/join`` and
      ``/cluster/issue-server-cert`` both fill these from the caller's
      authoritative view (observed source IP, primary hostname).
    - No ``node_uuid`` in the cert -- this cert authenticates the
      *nginx endpoint*, not the node identity.

    Validation :

    - ``validity_days`` clamped to ``[1, 4 * cluster_server_cert_validity_days]``
      so a runaway operator call cannot mint a 10-year server cert.
    - At least one SAN entry required (no SAN-less cert).
    - Each ``san_ips`` entry must parse as IPv4 or IPv6.
    - Each ``san_dns`` entry must match the standard DNS label syntax
      (RFC 1035 + RFC 5890 surface) -- rejects empty labels, leading
      hyphens, length overflow.

    Raises :class:`ClusterCaError` on any of the above.
    """
    if validity_days is None:
        validity_days = _server_cert_validity_days()
    if validity_days <= 0:
        raise ClusterCaError(f"validity_days must be positive: {validity_days}")
    # Cap an operator-supplied validity at 4x the SERVER cadence. Basing it on
    # the node setting could reject the server default itself (node=7, server=90
    # -> ceiling 28 < 90 bricks every /cluster/join server-cert mint).
    ceiling = 4 * settings.cluster_server_cert_validity_days
    if validity_days > ceiling:
        raise ClusterCaError(f"validity_days {validity_days} exceeds ceiling {ceiling}")

    if not san_ips and not san_dns:
        raise ClusterCaError("at least one SAN entry required (san_ips or san_dns)")

    ip_objs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in san_ips:
        try:
            ip_objs.append(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ClusterCaError(
                f"san_ips entry is not a valid IP literal: {raw}"
            ) from exc

    for name in san_dns:
        if not _DNS_RE.match(name):
            raise ClusterCaError(f"san_dns entry is not a valid DNS name: {name}")

    ca_cert = parse_cert(ca_cert_pem)
    ca_key = parse_key(ca_key_pem)

    server_private_key = Ed25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    cn = san_dns[0] if san_dns else san_ips[0]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    san_entries: list[x509.GeneralName] = [x509.IPAddress(ip) for ip in ip_objs]
    san_entries.extend(x509.DNSName(n) for n in san_dns)

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    server_cert = builder.sign(private_key=ca_key, algorithm=None)

    cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    log.info(
        "cluster_ca: signed server cert cn=%s san_ips=%d san_dns=%d validity=%dd",
        cn,
        len(ip_objs),
        len(san_dns),
        validity_days,
    )
    return cert_pem, key_pem


# -- CA rotation ------------------------------------------------
# Storage shape (additions to vault_cluster_config) :
#   cluster_ca_cert_prev  : PEM of the previous CA cert, kept during the grace
#     window so the mTLS verifier can still authenticate node certs signed under
#     the outgoing CA (cluster_mtls.authenticate falls back when current fails).
#   cluster_ca_rotated_at : ISO 8601 UTC, written at rotation. The reaper
#     (cluster_ha_loops) reads it for the grace-expiry drop trigger.
# Both are DELETEd by drop_cluster_ca_prev (reaper) once the grace window closes
# or all active nodes have rotated.
# No cluster_ca_key_prev is stored : the prev CA private key isn't needed after
# rotation (we sign with the NEW key only); the prev cert's public key is enough
# for the mTLS verifier to check signatures on still-deployed node certs.


async def has_active_rotation(session: AsyncSession) -> bool:
    """True iff ``cluster_ca_cert_prev`` is set (rotation grace window open).

    The rotate-ca endpoint refuses while True with
    ``ClusterCaRotationInGraceError`` -- only one CA rotation may be in
    flight at any time (no chained prev/prev-prev). Reaper queries the
    same predicate to know whether its drop-prev sub-op has anything to
    do.
    """
    row = (
        await session.execute(
            text("SELECT 1 FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY_CERT_PREV},
        )
    ).fetchone()
    return row is not None


async def load_cluster_ca_prev_cert(session: AsyncSession) -> bytes | None:
    """Return the previous CA cert PEM, or ``None`` if no rotation in grace.

    The cert is stored in clear text (it is public material -- it travels
    back to joiners in JOIN responses). No unwrap step needed.
    """
    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY_CERT_PREV},
        )
    ).fetchone()
    if row is None:
        return None
    return str(row.value).encode("ascii")


async def get_rotated_at(session: AsyncSession) -> datetime | None:
    """Return the rotation timestamp as a tz-aware datetime, or ``None``.

    The reaper uses this to evaluate the grace-expired path of the
    hybrid drop trigger (``NOW - rotated_at > cluster_ca_grace_window_secs``).
    Stored as ISO 8601 string in ``vault_cluster_config``.
    """
    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _CONFIG_KEY_ROTATED_AT},
        )
    ).fetchone()
    if row is None:
        return None
    dt = datetime.fromisoformat(str(row.value))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def rotate_cluster_ca(
    session: AsyncSession,
) -> tuple[bytes, str, datetime]:
    """Atomically rotate the cluster CA. Caller commits the transaction.

    Steps (all under the caller's transaction so a rollback restores the
    prior state cleanly) :

    1. Verify a current CA exists (``ClusterCaError`` if missing -- only
       /cluster/init mints the initial CA, rotate cannot bootstrap).
    2. Verify no prior rotation is still in grace
       (``ClusterCaRotationInGraceError`` if ``cluster_ca_cert_prev``
       row exists).
    3. Mint a fresh Ed25519 CA (``mint_cluster_ca``) -- pure compute,
       no DB side effect.
    4. INSERT ``cluster_ca_cert_prev = <current cert>`` + INSERT
       ``cluster_ca_rotated_at = <NOW ISO8601>`` + UPDATE
       ``cluster_ca_cert = <new cert>`` + UPDATE ``cluster_ca_key =
       <new wrapped key>``.

    Returns ``(new_cert_pem, new_fingerprint_hex, rotated_at_dt)``.

    Caller (route handler) is responsible for :
    - Calling ``cluster_nodes.set_force_renew_all`` after this returns,
      to push a broadcast refresh to every active node.
    - Emitting the ``cluster_ca_rotated`` audit row + the
      ``cluster_ca_rotations_total`` metric increment.
    - Committing the transaction.
    """
    if vault.sealed:
        raise VaultSealedError()

    await require_generation_current(session, vault)
    current_cert_pem = await load_cluster_ca_cert(session)
    if current_cert_pem is None:
        raise ClusterCaError(
            "cluster CA is not initialised -- call /cluster/init first"
        )

    if await has_active_rotation(session):
        raise ClusterCaRotationInGraceError(
            "a previous CA rotation is still inside its grace window"
        )

    new_cert_pem, new_key_pem, new_fingerprint = mint_cluster_ca()
    new_wrapped_key = await _wrap_key_for_db(new_key_pem)
    rotated_at = datetime.now(timezone.utc)
    rotated_at_iso = rotated_at.isoformat()

    await session.execute(
        text("INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v)"),
        {"k": _CONFIG_KEY_CERT_PREV, "v": current_cert_pem.decode("ascii")},
    )
    await session.execute(
        text("INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v)"),
        {"k": _CONFIG_KEY_ROTATED_AT, "v": rotated_at_iso},
    )
    await session.execute(
        text("UPDATE vault_cluster_config SET value = :v WHERE key = :k"),
        {"k": _CONFIG_KEY_CERT, "v": new_cert_pem.decode("ascii")},
    )
    await session.execute(
        text("UPDATE vault_cluster_config SET value = :v WHERE key = :k"),
        {"k": _CONFIG_KEY_KEY, "v": new_wrapped_key.hex()},
    )
    log.info(
        "cluster_ca: rotated CA -- new fingerprint=%s rotated_at=%s",
        new_fingerprint,
        rotated_at_iso,
    )
    return new_cert_pem, new_fingerprint, rotated_at


async def drop_cluster_ca_prev(session: AsyncSession) -> bool:
    """DELETE the prev cert + rotated_at rows. Caller commits.

    Reaper-invoked once the grace window has closed (either by
    all-nodes-rotated or by time expiry -- see ``cluster_ha_loops``).
    Returns True iff a row was actually deleted (idempotent -- a
    second call after the first returns False).
    """
    result = await session.execute(
        text("DELETE FROM vault_cluster_config WHERE key IN (:kp, :kr) RETURNING key"),
        {"kp": _CONFIG_KEY_CERT_PREV, "kr": _CONFIG_KEY_ROTATED_AT},
    )
    deleted = result.fetchall()
    if deleted:
        log.info(
            "cluster_ca: dropped prev CA grace window (cleared %d row(s))",
            len(deleted),
        )
        return True
    return False
