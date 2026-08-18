# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""mTLS-authenticated cluster member identity.

Nginx terminates TLS in front of the API with ``ssl_verify_client
optional_no_ca`` ; the presented client cert is forwarded to the API
via the ``X-Client-Cert`` header carrying the URL-escaped PEM
(canonical form on nginx is ``$ssl_client_escaped_cert``). The route
dependency :func:`require_cluster_member_cert` :

1. Refuses requests whose direct peer is NOT in
   ``proxy_trusted_ips`` (only trusted nginx instances may forward
   client certs ; an attacker on the bare API socket cannot forge the
   header). Mirror of the trust pattern in
   :mod:`api.app.routes.auth_proxy`.
2. Parses the ``X-Client-Cert`` header, ``urllib.parse.unquote`` ->
   PEM bytes -> ``x509.load_pem_x509_certificate``. 400 on malformed.
3. Verifies the cert was signed by the cluster CA (decrypted from
   ``vault_cluster_config`` via :func:`cluster_ca.load_cluster_ca`).
   During a CA rotation grace window (when ``cluster_ca_cert_prev`` is
   present), falls back to verifying against the previous CA cert. Both
   are tried ``current -> prev`` ; auth fails only if both reject.
4. Checks the cert's NotAfter window (5 min skew tolerance both ways
   to absorb wall-clock drift between nodes).
5. Checks ``cluster_membership.is_revoked(node_uuid)`` -- a uuid in
   the revoked list is rejected with 403, regardless of the cert
   chain validity. This is the load-bearing eviction primitive: a
   binary revocation check propagates an eviction across the cluster
   at the next request.

On success returns a :class:`ClusterMemberIdentity` dataclass with
``node_uuid`` (cert CN) + ``cert_fingerprint`` + ``source_ip``. The
route handler reads this via FastAPI ``Depends``.

Channel security : with ``ssl_verify_client optional_no_ca`` nginx does
NOT validate the chain at the edge ; it forwards whatever client cert is
presented. So the in-process checks here are the PRIMARY authentication,
not defence in depth: the cluster-CA signature plus the clientAuth /
CA:FALSE constraints below are what actually authenticate a member. The
peer-IP gate only limits who may submit the header, never who is trusted.
"""

import ipaddress
import logging
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from . import cluster_ca, cluster_membership
from .config import settings
from .database import get_db
from .vault_state import VaultSealedError, vault

log = logging.getLogger("rhorizon.cluster_mtls")

_HEADER = "X-Client-Cert"
# Skew tolerance on either side of the cert validity window. 5 min
# matches the slack the CA itself takes when minting (see
# :func:`cluster_ca.sign_node_cert` ``not_valid_before`` clause).
_CLOCK_SKEW = timedelta(minutes=5)


@dataclass(frozen=True)
class ClusterMemberIdentity:
    """Authenticated identity surfaced to the route handler.

    Frozen dataclass : the route should not mutate the identity. The
    caller reads ``node_uuid`` to scope writes (only the named node
    can refresh its own cert -- the membership table key is the cert
    CN, not a body field).
    """

    node_uuid: str
    cert_fingerprint: str
    source_ip: str


class ClusterMtlsError(HTTPException):
    """Common base -- subclasses pin the HTTP status code."""


class MtlsUntrustedProxyError(ClusterMtlsError):
    def __init__(self) -> None:
        super().__init__(
            status_code=403,
            detail="X-Client-Cert forwarded from an untrusted proxy IP",
        )


class MtlsMissingCertError(ClusterMtlsError):
    def __init__(self) -> None:
        super().__init__(
            status_code=401,
            detail="X-Client-Cert header is required for this endpoint",
        )


class MtlsMalformedCertError(ClusterMtlsError):
    def __init__(self, reason: str) -> None:
        super().__init__(status_code=400, detail=f"X-Client-Cert malformed: {reason}")


class MtlsExpiredCertError(ClusterMtlsError):
    def __init__(self) -> None:
        super().__init__(
            status_code=401,
            detail="client cert is outside its validity window",
        )


class MtlsBadSignatureError(ClusterMtlsError):
    def __init__(self) -> None:
        super().__init__(
            status_code=401, detail="client cert not signed by the cluster CA"
        )


class MtlsUnusableCertError(ClusterMtlsError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            status_code=401,
            detail=f"client cert not usable for member auth: {reason}",
        )


class MtlsRevokedError(ClusterMtlsError):
    def __init__(self, node_uuid: str) -> None:
        super().__init__(
            status_code=403,
            detail=f"node_uuid {node_uuid} is revoked",
        )


class MtlsRevocationUnavailableError(ClusterMtlsError):
    def __init__(self) -> None:
        super().__init__(
            status_code=503,
            detail="revocation status unavailable -- denying (fail-closed)",
        )


def _is_trusted_proxy(peer_ip: str) -> bool:
    """True iff the direct TCP peer is in ``settings.proxy_trusted_ips``.

    Mirror of ``api.app.routes.auth_proxy._is_trusted`` semantics --
    same setting governs both trust decisions (SSO header forwarding
    and X-Client-Cert forwarding). An empty / unparsable list returns
    False (fail-closed). Even loopback must be explicitly trusted.
    """
    raw = (settings.proxy_trusted_ips or "").strip()
    if not raw:
        return False
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False


def parse_x_client_cert(header_value: str) -> x509.Certificate:
    """Decode the URL-escaped PEM header into an X.509 cert.

    Nginx ``$ssl_client_escaped_cert`` URL-escapes the multi-line PEM
    so it fits in a single HTTP header. We reverse the escape and
    load. Anything that does not parse as a valid PEM cert raises
    :class:`MtlsMalformedCertError` (400) -- the caller is expected to
    be nginx, which would not normally send junk.
    """
    if not header_value:
        raise MtlsMalformedCertError("empty header")
    try:
        pem_bytes = urllib.parse.unquote(header_value).encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise MtlsMalformedCertError(f"non-ascii after unquote: {exc}") from exc
    if b"-----BEGIN CERTIFICATE-----" not in pem_bytes:
        raise MtlsMalformedCertError("not a PEM-encoded certificate")
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except ValueError as exc:
        raise MtlsMalformedCertError(f"cryptography parse error: {exc}") from exc


def _verify_signature(client_cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """Verify ``client_cert.signature`` against ``ca_cert.public_key``.

    Ed25519 path : the cluster CA mints Ed25519 keys exclusively
    (cf :func:`cluster_ca.mint_cluster_ca`). The verify call takes
    raw signature bytes + raw signed bytes ; the algorithm parameter
    is unused for Ed25519 (cryptography library quirk -- mirrors what
    :func:`cluster_ca.sign_node_cert` does on the signing side).
    """
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
        )
    except InvalidSignature as exc:
        raise MtlsBadSignatureError() from exc


def _verify_signature_dual(
    client_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    prev_ca_cert: x509.Certificate | None,
) -> None:
    """Verify against the current CA, fall back to the prev CA during grace.

    When ``cluster_ca_cert_prev`` is set (rotation grace window open),
    node certs still signed under the OLD CA must keep authenticating
    until the renewal loop pushes a fresh cert under the new CA. Tries
    the current CA first (post-rotation steady state); only on signature
    failure does it try the prev CA. ``MtlsBadSignatureError`` is raised
    only if both reject. Outside a grace window ``prev_ca_cert`` is
    ``None`` and this is the plain single-CA path.
    """
    try:
        _verify_signature(client_cert, ca_cert)
        return
    except MtlsBadSignatureError:
        if prev_ca_cert is None:
            raise
    # Grace fallback : the cert was not signed by the current CA, but a
    # previous CA is still in service. Try the prev CA -- if it also
    # rejects, surface the original 401.
    _verify_signature(client_cert, prev_ca_cert)


def _verify_client_cert_usage(client_cert: x509.Certificate) -> None:
    """Reject a CA cert or a serverAuth-only cert presented as a member identity.

    The cluster CA also signs serverAuth-only server certs and is itself a public
    self-signed CA cert; only an end-entity clientAuth cert is a valid member.
    Enforces on the verify side the separation sign_node_cert/sign_server_cert
    keep on the issue side. Absent BasicConstraints == end-entity (RFC 5280).
    """
    try:
        bc = client_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise MtlsUnusableCertError("certificate is a CA")
    except x509.ExtensionNotFound:
        pass
    try:
        eku = client_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as exc:
        raise MtlsUnusableCertError("no Extended Key Usage") from exc
    if x509.ExtendedKeyUsageOID.CLIENT_AUTH not in eku.value:
        raise MtlsUnusableCertError("not valid for clientAuth")


def _verify_validity_window(client_cert: x509.Certificate) -> None:
    """NotAfter / NotBefore check with ``_CLOCK_SKEW`` tolerance."""
    now = datetime.now(timezone.utc)
    if client_cert.not_valid_before_utc > now + _CLOCK_SKEW:
        raise MtlsExpiredCertError()
    if client_cert.not_valid_after_utc < now - _CLOCK_SKEW:
        raise MtlsExpiredCertError()


def _extract_cn(client_cert: x509.Certificate) -> str:
    """Pull the Common Name out of the cert subject.

    Cluster CA conventions (see :func:`cluster_ca.sign_node_cert`) put
    ``CN = node_uuid``. Multi-attribute subjects or empty CN raises
    :class:`MtlsMalformedCertError` -- the cluster CA never mints
    such certs.
    """
    cns = client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(cns) != 1:
        raise MtlsMalformedCertError(f"expected exactly 1 CN, got {len(cns)}")
    val = cns[0].value
    if not val:
        raise MtlsMalformedCertError("empty CN")
    return str(val)


async def authenticate(request: Request, db: AsyncSession) -> ClusterMemberIdentity:
    """Run the full mTLS auth pipeline. Returns the identity on success.

    Split from :func:`require_cluster_member_cert` so unit tests can
    exercise the pipeline without spinning the FastAPI dependency
    machinery. Raises one of the :class:`ClusterMtlsError` subclasses
    on any failure ; the FastAPI dep just re-raises.
    """
    if vault.sealed:
        raise VaultSealedError()

    # Direct peer trust -- the IP the kernel sees as the TCP peer is
    # the only IP that cannot be forged. X-Forwarded-For is irrelevant
    # here ; nginx is the trust anchor, not the original caller.
    peer_ip = request.client.host if request.client else ""
    if not _is_trusted_proxy(peer_ip):
        log.warning(
            "cluster_mtls: rejecting X-Client-Cert from untrusted peer %s",
            peer_ip,
        )
        raise MtlsUntrustedProxyError()

    header_value = request.headers.get(_HEADER)
    if not header_value:
        raise MtlsMissingCertError()

    client_cert = parse_x_client_cert(header_value)

    ca_cert_pem = await cluster_ca.load_cluster_ca_cert(db)
    if ca_cert_pem is None:
        # No CA on this cluster -- nothing to verify against.
        # /cluster/init mints the CA at bootstrap, so reaching this
        # branch on a HA-enabled deployment is a real fault.
        raise HTTPException(
            status_code=503,
            detail="cluster CA not initialised",
        )
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    # Dual-CA verify during a rotation grace window. The prev cert is
    # loaded only when present (one extra hot-path row read, bounded by
    # cluster_ca_grace_window_secs).
    prev_ca_cert: x509.Certificate | None = None
    prev_ca_cert_pem = await cluster_ca.load_cluster_ca_prev_cert(db)
    if prev_ca_cert_pem is not None:
        prev_ca_cert = x509.load_pem_x509_certificate(prev_ca_cert_pem)

    _verify_signature_dual(client_cert, ca_cert, prev_ca_cert)
    _verify_client_cert_usage(client_cert)
    _verify_validity_window(client_cert)

    node_uuid = _extract_cn(client_cert)
    try:
        revoked = await cluster_membership.is_revoked(db, node_uuid)
    except cluster_membership.RevokedListError as exc:
        # Corrupt revocation list -> deny, never admit a maybe-revoked node.
        log.error("cluster_mtls: revoked list unreadable -- denying %s", node_uuid)
        raise MtlsRevocationUnavailableError() from exc
    if revoked:
        raise MtlsRevokedError(node_uuid)

    fingerprint = cluster_ca.compute_fingerprint(
        client_cert.public_bytes(serialization_encoding())
    )
    source_ip = peer_ip
    return ClusterMemberIdentity(
        node_uuid=node_uuid,
        cert_fingerprint=fingerprint,
        source_ip=source_ip,
    )


def serialization_encoding():
    """Lazy import to avoid a top-level cryptography.hazmat dependency.

    The compute_fingerprint helper needs ``Encoding.PEM`` ; pulling
    the import in here keeps the module's top-level imports tight.
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.PEM


async def require_cluster_member_cert(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ClusterMemberIdentity:
    """FastAPI dependency -- attach mTLS identity to a route handler.

    Usage in :mod:`routes.cluster` ::

        @router.post("/cluster/refresh-cert")
        async def cluster_refresh_cert(
            identity: ClusterMemberIdentity = Depends(require_cluster_member_cert),
            db: AsyncSession = Depends(get_db),
        ):
            ...

    The dep raises :class:`HTTPException` subclasses on any failure ;
    FastAPI's error handling propagates them with the correct status
    code and JSON body.
    """
    return await authenticate(request, db)
