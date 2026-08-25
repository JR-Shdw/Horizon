# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Peer observations used while the local PostgreSQL authority is absent.

PostgreSQL remains the authority.  This module only asks authenticated cluster
peers what they last observed and classifies those facts locally.  A peer can
never return a frozen node to service: the only non-destructive action is a
bounded extension of the existing seal deadline.  A strictly newer PostgreSQL
term or key epoch can instead ask the existing fence to seal sooner.

The peer roster and public cluster-CA certificates are cached while the
database is healthy.  Polling therefore performs no local database I/O and can
run after the authority route has been blackholed.  Responses are fetched from
the per-node HTTPS listener with the local node certificate and server
verification pinned to the cached cluster CA bundle.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

import httpx
from cryptography import x509
from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from . import cluster_ca, cluster_nodes
from .config import settings

log = logging.getLogger("rhorizon.cluster_peer_frozen")

_PEER_STATUS_PATH = "/internal/ha/peer-status"


@dataclass(frozen=True)
class PeerRosterEntry:
    node_id: str
    address: str
    cert_fingerprint: str


@dataclass(frozen=True)
class PeerObservation:
    node_id: str
    state: str
    serving: bool
    db_authority_confirmed: bool
    primary_since: str | None
    key_epoch: int | None


class PeerVerdict(str, Enum):
    """Local action permitted by a set of peer observations."""

    LOCAL_FENCE = "local_fence"
    SHARED_OUTAGE = "shared_outage"
    SEAL_EARLY = "seal_early"


@dataclass(frozen=True)
class PeerDecision:
    verdict: PeerVerdict
    reason: str
    peer_count: int


@dataclass(frozen=True)
class PeerSnapshot:
    peers: tuple[PeerRosterEntry, ...] = ()
    ca_cert_pem: bytes | None = None
    prev_ca_cert_pem: bytes | None = None
    refreshed_at: float | None = None


_snapshot = PeerSnapshot()


def _parse_timestamp(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _valid_epoch(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def classify_frozen_peers(
    *,
    local_primary_since: str | None,
    local_key_epoch: int | None,
    observations: list[PeerObservation],
) -> PeerDecision:
    """Classify facts without granting authority to a peer.

    Stronger evidence wins regardless of response order.  A peer term is only
    comparable when this node has its own PostgreSQL-stamped baseline; ``None``
    is unknown, not negative infinity.  Malformed facts are ignored.
    """

    local_term = _parse_timestamp(local_primary_since)
    local_epoch = _valid_epoch(local_key_epoch)

    for observation in observations:
        peer_epoch = _valid_epoch(observation.key_epoch)
        if (
            local_epoch is not None
            and peer_epoch is not None
            and peer_epoch > local_epoch
        ):
            return PeerDecision(
                PeerVerdict.SEAL_EARLY,
                "newer_key_epoch",
                len(observations),
            )

        peer_term = _parse_timestamp(observation.primary_since)
        if local_term is not None and peer_term is not None and peer_term > local_term:
            return PeerDecision(
                PeerVerdict.SEAL_EARLY,
                "newer_primary_since",
                len(observations),
            )

    shared = sum(
        observation.state in {"frozen", "sealing"}
        and observation.serving is False
        and observation.db_authority_confirmed is False
        for observation in observations
    )
    if shared:
        return PeerDecision(PeerVerdict.SHARED_OUTAGE, "peer_frozen", shared)

    return PeerDecision(PeerVerdict.LOCAL_FENCE, "no_peer_evidence", len(observations))


def snapshot_needs_refresh() -> bool:
    """Refresh often enough that every worker has a recent outage roster."""

    refreshed = _snapshot.refreshed_at
    if refreshed is None:
        return True
    interval = max(5.0, float(settings.cluster_heartbeat_interval_secs) * 3.0)
    return time.monotonic() - refreshed >= interval


async def refresh_peer_snapshot(db: AsyncSession, local_node_id: str) -> None:
    """Cache peer addresses and public trust anchors from a healthy DB tick."""

    global _snapshot

    rows = await cluster_nodes.list_nodes(db)
    ca_cert = await cluster_ca.load_cluster_ca_cert(db)
    prev_ca_cert = await cluster_ca.load_cluster_ca_prev_cert(db)
    peers = tuple(
        PeerRosterEntry(
            str(row.node_uuid),
            str(row.source_ip),
            str(row.cert_fingerprint).lower(),
        )
        for row in rows
        if str(row.node_uuid) != local_node_id
        and row.ha_state in {"primary", "secondary"}
    )
    _snapshot = PeerSnapshot(
        peers=peers,
        ca_cert_pem=ca_cert,
        prev_ca_cert_pem=prev_ca_cert,
        refreshed_at=time.monotonic(),
    )


def authenticate_cached_peer(request: Request) -> str:
    """Authenticate a peer certificate without consulting PostgreSQL.

    The cache was populated from PostgreSQL during the last healthy heartbeat.
    Stale or absent cache entries reject the request; they never broaden trust.
    That may remove the optional peer hint during a badly timed rotation, which
    safely falls back to the local terminal fence.
    """

    from . import cluster_mtls
    from .vault_state import VaultSealedError, vault

    if vault.sealed:
        raise VaultSealedError()
    peer_ip = request.client.host if request.client else ""
    if not cluster_mtls._is_trusted_proxy(peer_ip):
        raise cluster_mtls.MtlsUntrustedProxyError()
    encoded_cert = request.headers.get("X-Client-Cert")
    if not encoded_cert:
        raise cluster_mtls.MtlsMissingCertError()

    cert = cluster_mtls.parse_x_client_cert(encoded_cert)
    snapshot = _snapshot
    if snapshot.ca_cert_pem is None:
        raise HTTPException(status_code=503, detail="peer trust cache unavailable")
    current_ca = x509.load_pem_x509_certificate(snapshot.ca_cert_pem)
    previous_ca = (
        x509.load_pem_x509_certificate(snapshot.prev_ca_cert_pem)
        if snapshot.prev_ca_cert_pem
        else None
    )
    cluster_mtls._verify_signature_dual(cert, current_ca, previous_ca)
    cluster_mtls._verify_client_cert_usage(cert)
    cluster_mtls._verify_validity_window(cert)
    node_id = cluster_mtls._extract_cn(cert)

    roster_entry = next(
        (peer for peer in snapshot.peers if peer.node_id == node_id),
        None,
    )
    if roster_entry is None:
        raise HTTPException(
            status_code=403, detail="peer absent from cached membership"
        )
    fingerprint = cluster_mtls.cluster_ca.compute_fingerprint(
        cert.public_bytes(cluster_mtls.serialization_encoding())
    )
    if fingerprint.lower() != roster_entry.cert_fingerprint:
        raise HTTPException(
            status_code=403, detail="peer certificate no longer current"
        )
    return node_id


def _peer_url(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    host = f"[{parsed.compressed}]" if parsed.version == 6 else parsed.compressed
    return f"https://{host}:{settings.cluster_peer_https_port}{_PEER_STATUS_PATH}"


def _ssl_context(snapshot: PeerSnapshot) -> ssl.SSLContext | None:
    if snapshot.ca_cert_pem is None:
        return None
    bundle = snapshot.ca_cert_pem
    if snapshot.prev_ca_cert_pem:
        bundle += b"\n" + snapshot.prev_ca_cert_pem
    try:
        # Build an isolated trust store rather than extending the host's
        # public roots: only the current/previous Horizon cluster CA may
        # authenticate a peer listener.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cadata=bundle.decode("ascii"))
        context.load_cert_chain(
            certfile=settings.cluster_cert_path,
            keyfile=settings.cluster_cert_key_path,
        )
    except (OSError, UnicodeError, ssl.SSLError):
        log.warning("peer classifier: cached mTLS material is unusable", exc_info=True)
        return None
    return context


def _decode_observation(
    expected: PeerRosterEntry, payload: object
) -> PeerObservation | None:
    if not isinstance(payload, dict) or payload.get("node_id") != expected.node_id:
        return None
    state = payload.get("state")
    serving = payload.get("serving")
    confirmed = payload.get("db_authority_confirmed")
    if state not in {"active", "frozen", "sealing", "sealed"}:
        return None
    if not isinstance(serving, bool) or not isinstance(confirmed, bool):
        return None
    primary_since = payload.get("primary_since")
    if primary_since is not None and not isinstance(primary_since, str):
        primary_since = None
    return PeerObservation(
        node_id=expected.node_id,
        state=state,
        serving=serving,
        db_authority_confirmed=confirmed,
        primary_since=primary_since,
        key_epoch=_valid_epoch(payload.get("key_epoch")),
    )


async def poll_peer_observations() -> list[PeerObservation]:
    """Fetch cached peers concurrently, bounded and without local DB access."""

    snapshot = _snapshot
    if not snapshot.peers:
        return []
    context = _ssl_context(snapshot)
    if context is None:
        return []

    timeout_seconds = max(
        1.0,
        min(3.0, float(settings.cluster_heartbeat_interval_secs)),
    )
    timeout = httpx.Timeout(timeout_seconds, connect=timeout_seconds)

    async with httpx.AsyncClient(
        verify=context,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:

        async def fetch(peer: PeerRosterEntry) -> PeerObservation | None:
            try:
                response = await client.get(_peer_url(peer.address))
                response.raise_for_status()
                return _decode_observation(peer, response.json())
            except (httpx.HTTPError, ValueError):
                return None

        fetched = await asyncio.gather(*(fetch(peer) for peer in snapshot.peers))

    return [observation for observation in fetched if observation is not None]
