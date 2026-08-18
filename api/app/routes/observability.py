# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Observability snapshot for the in-app Nova view.

A JSON view over the same Prometheus metrics that /metrics exposes, gated by a
vault token (audit:r) instead of the /metrics CIDR allowlist so the browser UI
can poll it. Route-layer only: reads already-computed metric values, never
touches keys, crypto, or the seal/unseal path.
"""

from fastapi import APIRouter, Depends

from ..auth import require_permission
from ..metrics import observability_snapshot
from ..vault_state import vault

router = APIRouter(prefix="/api/v1/vault", tags=["observability"])


@router.get("/observability")
async def get_observability(_token: dict = Depends(require_permission("audit", "r"))):
    """Live counters + gauges for the Nova dashboard. Counters are monotonic;
    the client diffs successive polls to render per-second rates."""
    snap = observability_snapshot()
    snap["sealed"] = vault.sealed
    return snap
