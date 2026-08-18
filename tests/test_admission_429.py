# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression: transient backpressure surfaces as 429, not 503.

Rationale (rhorizon_ha battery 2026-06-07): a passive LB / outlier detector
(HAProxy on-error mark-down, Envoy consecutive_5xx, nginx http_503) ejects a
backend on 5xx. Load-shed and "cluster recovering" are TRANSIENT -- a 503 there
would eject a healthy-but-busy node and cascade a spike into an outage. They
must be 429 (not a 5xx -> back off without ejecting). Persistent unavailability
(sealed / quarantined) stays 503 so the chain DOES pull the node.
"""

import json
from types import SimpleNamespace

from api.app.cluster_rpc import MasterUnreachable
from api.app.custody_generation import CustodyOrchestrationBusy
from api.app.main import (
    _custody_busy_handler,
    _load_shed_response,
    _master_unreachable_handler,
    _retry_after,
)


def test_load_shed_is_429_with_jittered_retry_after():
    r = _load_shed_response()
    assert r.status_code == 429, "overload shed must be 429 (back off), not 5xx (eject)"
    ra = int(r.headers["Retry-After"])
    assert 1 <= ra <= 3, f"Retry-After should be jittered 1..3, got {ra}"
    assert r.headers["X-Rhorizon-Overload"] == "request_concurrency_limit"
    body = json.loads(r.body)
    assert body == {
        "error": "capacity_overloaded",
        "reason": "request_concurrency_limit",
        "message": "Node request capacity reached; retry after backoff",
        "retryable": True,
    }


def test_unseal_shed_reports_reserved_slot_limit():
    r = _load_shed_response("unseal_concurrency_limit")
    assert r.status_code == 429
    assert r.headers["X-Rhorizon-Overload"] == "unseal_concurrency_limit"
    body = json.loads(r.body)
    assert body["reason"] == "unseal_concurrency_limit"
    assert body["message"] == "Another unseal attempt is active; retry after backoff"


def test_retry_after_jitter_spreads():
    # Not a fixed constant -> a shed crowd doesn't re-stampede in lockstep.
    vals = {_retry_after() for _ in range(200)}
    assert len(vals) > 1, "Retry-After must vary (jitter), not be constant"
    assert all(1 <= int(v) <= 3 for v in vals)


async def test_custody_orchestration_busy_is_429_with_retry_after():
    """Boot of a large worker pool holds CUSTODY_ORCHESTRATION_LOCK while
    /health already answers, so an unseal issued right then can lose the race.
    It is transient -- the same call succeeds moments later -- so it must not
    be a 5xx that ejects the node, and must not be the uncaught 500 it was.
    """
    req = SimpleNamespace(method="POST", url=SimpleNamespace(path="/v1/vault/unseal"))
    r = await _custody_busy_handler(
        req, CustodyOrchestrationBusy("another custody generation operation")
    )
    assert r.status_code == 429, "lock contention is transient -> 429, not 5xx"
    assert "Retry-After" in r.headers
    assert json.loads(r.body)["error"] == "custody_busy"


async def test_master_unreachable_is_429_with_retry_after():
    req = SimpleNamespace(method="GET", url=SimpleNamespace(path="/v1/secrets/x"))
    r = await _master_unreachable_handler(req, MasterUnreachable("stale rpc client"))
    assert r.status_code == 429, "cluster_recovering is transient -> 429, not 503"
    assert "Retry-After" in r.headers
