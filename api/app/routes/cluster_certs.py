# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster CA and per-node certificate routes (admin:w).

  - ``POST /cluster/refresh-cert``     -- reissue this node's own cert
  - ``POST /cluster/issue-server-cert`` -- issue a server cert for a node
  - ``POST /cluster/rotate-cert``      -- rotate a node's client cert
  - ``GET  /cluster/ca``               -- CA bundle (cluster:r)
  - ``POST /cluster/rotate-ca``        -- roll the CA with a grace window

Whoever issues a node certificate can impersonate that node in the cluster
mTLS, so these endpoints are kept readable in one sitting.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .. import (
    cluster_ca,
    cluster_membership,
    cluster_mtls,
    cluster_nodes,
)
from .. import metrics as _metrics
from ..audit import log_action
from ..auth import require_permission
from ..client_ip import get_client_ip
from ..config import settings
from ..database import get_db
from ..vault_state import vault

log = logging.getLogger("rhorizon.routes.cluster_certs")

router = APIRouter()


# ---------------------------------------------------------------------------
# mTLS refresh-cert + admin force-rotate + ca-bundle
# ---------------------------------------------------------------------------


class ClusterRefreshCertResponse(BaseModel):
    node_uuid: str
    node_cert_pem: str
    node_cert_key_pem: str
    cert_fingerprint: str
    cert_not_after: str
    # Refresh-cert also returns a fresh nginx server cert
    # signed by the cluster CA. SAN = [source_ip] (the membership row's
    # stored source_ip, same authoritative source as the node cert SAN).
    # The caller persists both pairs and reloads nginx.
    server_cert_pem: str
    server_cert_key_pem: str
    server_cert_fingerprint: str
    server_cert_not_after: str


class ClusterIssueServerCertRequest(BaseModel):
    san_ips: list[str] = Field(default_factory=list, max_length=16)
    san_dns: list[str] = Field(default_factory=list, max_length=16)
    validity_days: int | None = Field(default=None, ge=1, le=3650)


class ClusterIssueServerCertResponse(BaseModel):
    server_cert_pem: str
    server_key_pem: str
    fingerprint: str
    not_after: str


class ClusterRotateCertResponse(BaseModel):
    scope: str  # "one" | "all"
    flipped: int
    target: str  # node_uuid or "all"


class ClusterCaBundleResponse(BaseModel):
    ca_cert_pem: str
    fingerprint: str


class ClusterRotateCaResponse(BaseModel):
    new_fingerprint: str  # SHA-256 of the freshly-minted CA cert
    rotated_at: str  # ISO 8601 UTC, written to vault_cluster_config
    grace_window_secs: int  # snapshot of the live setting at rotation
    flipped: int  # number of vault_cluster_nodes rows force-renew set


@router.post(
    "/cluster/refresh-cert",
    response_model=ClusterRefreshCertResponse,
)
async def cluster_refresh_cert(
    identity: cluster_mtls.ClusterMemberIdentity = Depends(
        cluster_mtls.require_cluster_member_cert
    ),
    db: AsyncSession = Depends(get_db),
):
    """Re-mint the caller's node cert. mTLS-authenticated.

    The dependency authenticates the caller via X-Client-Cert ; the
    identity carries ``node_uuid`` (= cert CN) which is the SOLE
    target of the refresh -- a node can only refresh its own cert.
    The membership row's existing ``source_ip`` is preserved to keep
    the (uuid, ip) binding consistent. If the cluster
    operator legitimately moved the node to a new IP, they evict +
    re-JOIN rather than refresh.

    On success :

    - mints a fresh Ed25519 keypair + signs it with the cluster CA
      (90 days validity, configurable via cluster_node_cert_validity_days),
    - UPDATEs vault_cluster_nodes (cert_fingerprint, cert_not_after,
      force_renew_at=NULL),
    - emits an audit row ``cluster_cert_refreshed``,
    - returns the new (cert_pem, key_pem) in CLEAR over the
      mTLS-protected channel. The caller persists them locally via
      :func:`cluster_cert.save_cluster_cert`.
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")

    row = await cluster_nodes.get_node(db, identity.node_uuid)
    if row is None:
        # Identity authenticated against the CA but no membership row exists --
        # reaped or evicted. Either way the node should re-JOIN, not refresh.
        raise HTTPException(
            status_code=404,
            detail="no membership row for this node_uuid -- re-JOIN required",
        )
    if row.ha_state == "evicted":
        # Belt-and-suspenders : the mTLS dep already rejects revoked
        # uuids, but a node could be evicted (ha_state) without being
        # revoked (revoked_node_uuids) in degenerate ops sequences.
        raise HTTPException(
            status_code=403,
            detail=f"node {identity.node_uuid} is evicted -- refresh denied",
        )
    # cluster_nodes.get_node returns ``source_ip::TEXT`` which carries
    # the PG INET /32 (resp. /128) mask. sign_node_cert rejects masked
    # forms, so we normalise via ipaddress.ip_interface before passing
    # the literal to the CA helper.
    import ipaddress as _ipaddress

    source_ip = str(_ipaddress.ip_interface(row.source_ip).ip)

    ca_pair = await cluster_ca.load_cluster_ca(db)
    if ca_pair is None:
        raise HTTPException(
            status_code=503,
            detail="cluster CA not loaded",
            headers={"Retry-After": "1"},
        )
    ca_cert_pem, ca_key_pem = ca_pair

    try:
        new_cert_pem, new_key_pem = cluster_ca.sign_node_cert(
            ca_cert_pem, ca_key_pem, identity.node_uuid, source_ip
        )

        # Mint a fresh server cert too. The renewal loop on the
        # caller side persists both pairs and reloads nginx. Returned in the
        # clear over the mTLS-protected channel; no per-key wrap needed
        # (unlike /cluster/join where the wire is plain HTTP-with-trust-anchor).
        new_server_cert_pem, new_server_key_pem = cluster_ca.sign_server_cert(
            ca_cert_pem, ca_key_pem, [source_ip], []
        )
    finally:
        secure_zero(ca_key_pem)
    server_parsed = cluster_ca.parse_cert(new_server_cert_pem)
    new_server_fpr = cluster_ca.compute_fingerprint(new_server_cert_pem)
    new_server_nbf = server_parsed.not_valid_after_utc

    parsed = cluster_ca.parse_cert(new_cert_pem)
    new_fpr = cluster_ca.compute_fingerprint(new_cert_pem)
    new_nbf = parsed.not_valid_after_utc

    updated = await cluster_nodes.update_cert_metadata(
        db, identity.node_uuid, new_fpr, new_nbf
    )
    if not updated:
        # Race window : the row existed at the get_node call but is
        # gone by the UPDATE. Surface as 503 so the caller retries
        # next tick.
        raise HTTPException(
            status_code=503,
            detail="membership row disappeared mid-refresh",
            headers={"Retry-After": "5"},
        )

    await log_action(
        db,
        actor=f"node:{identity.node_uuid}",
        action="cluster_cert_refreshed",
        target=identity.node_uuid,
        detail={
            "cert_fingerprint": new_fpr,
            "source_ip": source_ip,
            "prev_fingerprint": identity.cert_fingerprint,
        },
        ip_address=source_ip,
    )
    await db.commit()

    log.info(
        "cluster_refresh_cert: node=%s new_fpr=%s prev_fpr=%s",
        identity.node_uuid,
        new_fpr,
        identity.cert_fingerprint,
    )

    return ClusterRefreshCertResponse(
        node_uuid=identity.node_uuid,
        node_cert_pem=new_cert_pem.decode("ascii"),
        node_cert_key_pem=new_key_pem.decode("ascii"),
        cert_fingerprint=new_fpr,
        cert_not_after=new_nbf.isoformat(),
        server_cert_pem=new_server_cert_pem.decode("ascii"),
        server_cert_key_pem=new_server_key_pem.decode("ascii"),
        server_cert_fingerprint=new_server_fpr,
        server_cert_not_after=new_server_nbf.isoformat(),
    )


@router.post(
    "/cluster/issue-server-cert",
    response_model=ClusterIssueServerCertResponse,
)
async def cluster_issue_server_cert(
    body: ClusterIssueServerCertRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Mint a fresh nginx server cert signed by the cluster CA. Admin:w.

    Operator-facing primitive. Used at bootstrap to give the
    primary's nginx a CA-signed server cert before any joiner trusts the
    cluster trust anchor, and as an admin escape hatch for ad-hoc
    re-issuance (changing SAN list, debugging, etc.). Joiners receive
    their server cert via :class:`ClusterJoinResponse` during the
    auto-JOIN flow ; cluster members renew via :func:`cluster_refresh_cert`
    (mTLS).

    Body :

    - ``san_ips`` : list of IPv4/IPv6 literals (e.g. the host's LAN IP).
    - ``san_dns`` : list of DNS names (e.g. ``rhorizon-1``,
      ``vault.example.com``). At least one of ``san_ips``/``san_dns``
      must be non-empty.
    - ``validity_days`` : optional explicit span. Defaults to
      ``settings.cluster_server_cert_validity_days`` ; clamped to
      ``[1, 4 * cluster_node_cert_validity_days]`` by the helper.

    Response carries the cert PEM, key PEM (in the clear, on an
    admin-authenticated channel), SHA-256 fingerprint, and ISO 8601
    NotAfter. The cert is NOT persisted in vault_cluster_config or
    vault_cluster_nodes -- the operator's ansible play (or curl
    script) drops it on disk and reloads nginx.

    /cluster/issue-server-cert no longer 503s on a
    follower. The CA private key unwrap routes through
    :meth:`VaultState.ha_wrap_decrypt` (RPC dispatch). The
    sign-and-return path is pure crypto on a transient key (returned in
    the clear over the admin-authenticated channel ; not persisted on
    server side, no wrap).
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")

    ca_pair = await cluster_ca.load_cluster_ca(db)
    if ca_pair is None:
        raise HTTPException(
            status_code=503,
            detail="cluster CA not initialised",
        )
    ca_cert_pem, ca_key_pem = ca_pair

    # Gate the mint under PRIMARY_ELECTION_LOCK so a fresh server cert isn't
    # signed under stale primary state mid-election (the autonomous election and
    # every operator op hold the same lock). xact-scoped, released by the commit
    # below; the name reproduces the with_cluster_lock prefix so the gates compose.
    try:
        gate_acquired = (
            await db.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtext(:n))"),
                {"n": (f"rhorizon:cluster:{cluster_membership.PRIMARY_ELECTION_LOCK}")},
            )
        ).scalar()
        if not gate_acquired:
            raise HTTPException(
                status_code=503,
                detail="election_in_progress",
                headers={"Retry-After": "5"},
            )

        try:
            cert_pem, key_pem = cluster_ca.sign_server_cert(
                ca_cert_pem,
                ca_key_pem,
                list(body.san_ips),
                list(body.san_dns),
                body.validity_days,
            )
        except cluster_ca.ClusterCaError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        secure_zero(ca_key_pem)

    parsed = cluster_ca.parse_cert(cert_pem)
    fingerprint = cluster_ca.compute_fingerprint(cert_pem)
    not_after = parsed.not_valid_after_utc

    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)
    await log_action(
        db,
        actor=actor,
        action="cluster_server_cert_issued",
        target="server",
        detail={
            "san_ips": list(body.san_ips),
            "san_dns": list(body.san_dns),
            "fingerprint": fingerprint,
            "not_after": not_after.isoformat(),
        },
        ip_address=client_ip,
    )
    await db.commit()

    log.info(
        "cluster_issue_server_cert: san_ips=%s san_dns=%s fpr=%s by=%s",
        body.san_ips,
        body.san_dns,
        fingerprint,
        actor,
    )

    return ClusterIssueServerCertResponse(
        server_cert_pem=cert_pem.decode("ascii"),
        server_key_pem=key_pem.decode("ascii"),
        fingerprint=fingerprint,
        not_after=not_after.isoformat(),
    )


@router.post(
    "/cluster/rotate-cert/{target}",
    response_model=ClusterRotateCertResponse,
)
async def cluster_rotate_cert(
    target: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Force-renew a node's cert at the next renewal tick. Admin:w.

    Two scopes :

    - ``POST /cluster/rotate-cert/{node_uuid}`` -- single node.
      Flips ``force_renew_at = NOW()`` on the row. The named node's
      per-node renewal loop picks it up at the next poll
      (cluster_cert_renewal_poll_secs) and refreshes via mTLS.
    - ``POST /cluster/rotate-cert/all`` -- cluster-wide broadcast.
      Same flip on every non-evicted row. CA rotation is
      the canonical use case ; here it serves as a debug primitive
      and a forward-compat hook.

    A flipped row whose loop is wedged stays flipped until either the
    loop ticks or an operator calls /cluster/refresh-cert directly
    on its behalf. The force_renew_at column is set unconditionally
    -- there is no "already pending" state, the operator's intent
    just re-stamps the timestamp.
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")

    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    if target == "all":
        flipped = await cluster_nodes.set_force_renew_all(db)
        await log_action(
            db,
            actor=actor,
            action="cluster_cert_force_rotate",
            target="all",
            detail={"flipped": flipped},
            ip_address=client_ip,
        )
        await db.commit()
        _metrics.cluster_cert_force_rotates.labels(scope="all").inc()
        log.info("cluster_rotate_cert: scope=all flipped=%d by=%s", flipped, actor)
        return ClusterRotateCertResponse(scope="all", flipped=flipped, target="all")

    # Single-node case -- treat target as a node_uuid.
    node_uuid = target
    flipped_one = await cluster_nodes.set_force_renew_one(db, node_uuid)
    if not flipped_one:
        raise HTTPException(
            status_code=404,
            detail=f"node_uuid {node_uuid} not found or evicted",
        )
    await log_action(
        db,
        actor=actor,
        action="cluster_cert_force_rotate",
        target=node_uuid,
        detail={"scope": "one"},
        ip_address=client_ip,
    )
    await db.commit()
    _metrics.cluster_cert_force_rotates.labels(scope="one").inc()
    log.info("cluster_rotate_cert: scope=one node=%s by=%s", node_uuid, actor)
    return ClusterRotateCertResponse(scope="one", flipped=1, target=node_uuid)


@router.get(
    "/cluster/ca-bundle",
    response_model=ClusterCaBundleResponse,
    dependencies=[Depends(require_permission("cluster", "r"))],
)
async def cluster_ca_bundle(db: AsyncSession = Depends(get_db)):
    """Return the cluster CA cert PEM + its SHA-256 fingerprint. Cluster:r.

    Operator-facing : the human (or a deployment script with a cluster:r
    token) curls this once per cluster to install the bundle on nginx
    (`ssl_client_certificate /path/to/ca-bundle.pem`). The CA cert is
    public material ; the wrapped private key never leaves the master
    process and is NOT returned by this endpoint.

    Returns 409 when the vault is sealed or 503 when no CA row exists yet (the
    cluster has not run /cluster/init). The route reads only the public cert
    row; it must not unwrap the private signer key for bundle distribution.
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")
    ca_cert_pem = await cluster_ca.load_cluster_ca_cert(db)
    if ca_cert_pem is None:
        raise HTTPException(
            status_code=503,
            detail="cluster CA not initialised",
        )
    fingerprint = cluster_ca.compute_fingerprint(ca_cert_pem)
    return ClusterCaBundleResponse(
        ca_cert_pem=ca_cert_pem.decode("ascii"),
        fingerprint=fingerprint,
    )


@router.post(
    "/cluster/rotate-ca",
    response_model=ClusterRotateCaResponse,
)
async def cluster_rotate_ca(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Mint a fresh cluster CA, keep the prev for a grace window. Admin:w.

    One of the rare ops in the cluster lifecycle. Triggers :

    - Suspected CA key compromise (the wrapped key never leaves the
      master process, but a defensive rotation closes the question).
    - Planned algorithm migration (today the CA is Ed25519 ; a future
      slice may switch to a PQC primitive -- rotate-ca is the
      forward-compat handle).
    - Periodic hygiene at the operator's discretion (the default CA
      validity is 10 years ; daily rotation buys nothing, but a yearly
      rotation is reasonable for compliance-heavy deployments).

    Atomic sequence (single transaction) :

    1. Refuse with 409 if a previous rotation is still in its grace
       window (``cluster_ca_cert_prev`` set). Policy : a
       single generation of CA in transit at a time -- the operator
       waits for the reaper to drop the prev (all-nodes-rotated OR
       grace expired) before staging another rotation.
    2. ``cluster_ca.rotate_cluster_ca`` mints a fresh Ed25519 CA,
       moves the current cert to ``cluster_ca_cert_prev``, writes
       ``cluster_ca_rotated_at = NOW``, and swaps in the new
       cert + wrapped key.
    3. ``cluster_nodes.set_force_renew_all`` flips
       ``force_renew_at = NOW()`` on every non-evicted membership row.
       The per-node renewal loop (default poll 12h) picks
       up the flag and refreshes via mTLS -- the cluster_mtls
       dependency falls back to the prev CA during the grace window
       so the still-old cert authenticates the refresh call.
    4. Emit ``cluster_ca_rotated`` audit row + bump
       ``cluster_ca_rotations_total`` metric.

    Grace window mechanics : while ``cluster_ca_cert_prev`` is set, the
    mTLS verifier (``cluster_mtls._verify_signature_dual``) tries the
    current CA first, falls back to the prev on signature failure.
    Two CAs accepted in parallel = the grace window. The reaper
    (``cluster_ha_loops._reap_ca_grace``) drops the prev once :
      (a) every active row has ``force_renew_at IS NULL`` (all
          nodes refreshed) -- the fast path, audit
          ``reason=all_rotated`` ; or
      (b) ``NOW - cluster_ca_rotated_at > cluster_ca_grace_window_secs``
          -- the time-fallback path, audit ``reason=grace_expired``
          with a warning listing the lagging nodes.

    Returns the new CA fingerprint (for operator-side hash check),
    the rotation timestamp, the live grace window setting, and the
    count of rows force-renewed (= active cluster size).

    409 paths :
    - vault sealed
    - cluster CA not initialised (no /cluster/init yet)
    - a previous rotation is still in its grace window
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")

    # Follower-safe: rotate_cluster_ca re-wraps the fresh CA key via
    # VaultState.ha_wrap_encrypt (RPC to master).
    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    # Load the current fingerprint BEFORE the rotation so the audit row
    # captures the (prev, new) pair. cluster_ca.load_cluster_ca_cert raises
    # VaultSealedError on sealed, already short-circuited above.
    current_cert_pem = await cluster_ca.load_cluster_ca_cert(db)
    if current_cert_pem is None:
        raise HTTPException(
            status_code=503,
            detail="cluster CA not initialised",
        )
    prev_fingerprint = cluster_ca.compute_fingerprint(current_cert_pem)

    try:
        new_cert_pem, new_fingerprint, rotated_at = await cluster_ca.rotate_cluster_ca(
            db
        )
    except cluster_ca.ClusterCaRotationInGraceError as exc:
        raise HTTPException(
            status_code=409,
            detail="cluster_ca_rotation_in_grace",
        ) from exc

    flipped = await cluster_nodes.set_force_renew_all(db)

    await log_action(
        db,
        actor=actor,
        action="cluster_ca_rotated",
        target="cluster",
        detail={
            "prev_fingerprint": prev_fingerprint,
            "new_fingerprint": new_fingerprint,
            "grace_window_secs": settings.cluster_ca_grace_window_secs,
            "flipped": flipped,
        },
        ip_address=client_ip,
    )
    await db.commit()
    _metrics.cluster_ca_rotations.inc()
    log.info(
        "cluster_rotate_ca: new_fp=%s prev_fp=%s flipped=%d grace=%ds by=%s",
        new_fingerprint,
        prev_fingerprint,
        flipped,
        settings.cluster_ca_grace_window_secs,
        actor,
    )
    return ClusterRotateCaResponse(
        new_fingerprint=new_fingerprint,
        rotated_at=rotated_at.isoformat(),
        grace_window_secs=settings.cluster_ca_grace_window_secs,
        flipped=flipped,
    )
