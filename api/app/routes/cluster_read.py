# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Read-only cluster health, topology and production preflight routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .. import cluster_mtls, cluster_preflight, cluster_status
from ..auth import require_permission
from ..database import get_db
from ..vault_state import vault

router = APIRouter()


@router.get(
    "/cluster",
    dependencies=[Depends(require_permission("cluster", "r"))],
)
async def cluster_topology(db: AsyncSession = Depends(get_db)):
    """Return fresh worker/custodian topology and held cluster locks."""
    return await cluster_status.topology_snapshot(db)


@router.get(
    "/cluster/health",
    dependencies=[Depends(require_permission("cluster", "r"))],
)
async def cluster_health_endpoint(
    summary: bool = False, db: AsyncSession = Depends(get_db)
):
    """Return provider-neutral health, optionally without topology detail."""
    health = await cluster_status.health_snapshot(db, vault)
    if not summary:
        return health
    return {
        "overall": health.get("overall"),
        "ready": health.get("ready"),
        "components": {
            name: {"state": component.get("state"), "reason": component.get("reason")}
            for name, component in (health.get("components") or {}).items()
        },
    }


@router.get(
    "/cluster/preflight",
    dependencies=[Depends(require_permission("cluster", "r"))],
)
async def cluster_preflight_endpoint(
    live: bool = False,
    summary: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """Explain HA readiness; ``live`` traverses the real mTLS proxy path."""
    health = await cluster_status.health_snapshot(db, vault)
    topology = await cluster_status.topology_snapshot(db)
    result = await cluster_preflight.build_preflight(
        db,
        health=health,
        topology=topology,
        live=live,
    )
    return cluster_preflight.project_preflight(result) if summary else result


@router.get("/cluster/mtls-self")
async def cluster_mtls_self(
    identity: cluster_mtls.ClusterMemberIdentity = Depends(
        cluster_mtls.require_cluster_member_cert
    ),
):
    """Return the identity established by the end-to-end mTLS path."""
    return {
        "authenticated": True,
        "node_uuid": identity.node_uuid,
        "cert_fingerprint": identity.cert_fingerprint,
    }
