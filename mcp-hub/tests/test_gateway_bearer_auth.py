# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""BearerAuth cache pruning (mcp-hub daemon mode).

Regression coverage for the "MCP auth cache DoS" finding (docs/SECURITY-AUDIT.md):
_pos / _neg / _rl were plain dicts with no active eviction -- an entry only
expired lazily, on next lookup of that SAME key, so many distinct bogus
bearers or source IPs grew them without bound. _prune_locked() now runs
opportunistically on every cache-miss resolve() call (the exact traffic that
causes growth) and hard-caps each dict as a backstop.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rhorizon_mcp_hub.gateway import _MAX_ENTRIES, _NEG_TTL, _POS_TTL, BearerAuth


class _RejectingSidecar:
    """Every whoami call fails auth (401-shaped: not a dict with an id)."""

    def request(self, bearer, method, path, body=None):
        return 401, {"error": "unauthorized"}


class _AcceptingSidecar:
    def request(self, bearer, method, path, body=None):
        return 200, {"id": f"agent-{bearer}", "name": bearer}


def test_expired_entries_are_pruned_on_cache_miss():
    auth = BearerAuth(_RejectingSidecar())
    now = time.monotonic()

    # Seed both caches directly with long-expired entries, simulating
    # accumulated garbage from earlier, never-repeated bearers.
    auth._pos = {f"stale-pos-{i}": (now - _POS_TTL - 10, {}) for i in range(50)}
    auth._neg = {f"stale-neg-{i}": now - _NEG_TTL - 10 for i in range(50)}
    auth._rl = {f"10.0.0.{i}": [now - 3600] for i in range(50)}

    # A fresh, distinct bearer: cache miss, falls through to
    # _rate_limited() -> _prune_locked().
    auth.resolve("brand-new-bearer", "10.0.0.1")

    assert len(auth._pos) == 0, "expired positive entries were not pruned"
    assert len(auth._neg) == 1, "expired negative entries were not pruned"
    assert "10.0.0.1" not in [k for k, v in auth._rl.items() if not v]
    for hits in auth._rl.values():
        assert all(now - t < 60.0 for t in hits), "expired rate-limit hits linger"


def test_hard_cap_evicts_oldest_when_pruning_is_not_enough():
    auth = BearerAuth(_RejectingSidecar())
    now = time.monotonic()

    # All entries still within TTL (genuine sustained load, not garbage),
    # exceeding the hard cap by a comfortable margin.
    n = _MAX_ENTRIES + 500
    auth._pos = {f"pos-{i}": (now - i * 0.0001, {"id": i}) for i in range(n)}

    auth.resolve("another-new-bearer", "10.0.0.2")

    assert len(auth._pos) <= _MAX_ENTRIES, (
        f"_pos grew to {len(auth._pos)}, hard cap {_MAX_ENTRIES} was not enforced"
    )
    # The newest entries (lowest i, freshest timestamp) must survive eviction.
    assert "pos-0" in auth._pos, (
        "eviction dropped the newest entry instead of the oldest"
    )


def test_positive_and_negative_cache_still_work_after_pruning():
    """Pruning must not break the actual caching behaviour it guards."""
    accept = _AcceptingSidecar()
    auth = BearerAuth(accept)

    first = auth.resolve("good-bearer", "10.0.0.3")
    assert first == {"id": "agent-good-bearer", "name": "good-bearer"}

    # Swap in a sidecar that would fail every request, to prove the SECOND
    # resolve() is served from the positive cache, not re-validated.
    auth._sidecar = _RejectingSidecar()
    second = auth.resolve("good-bearer", "10.0.0.3")
    assert second == first, "positive cache did not serve the cached identity"

    reject = BearerAuth(_RejectingSidecar())
    denied_first = reject.resolve("bad-bearer", "10.0.0.4")
    assert denied_first is None
    reject._sidecar = accept  # would now succeed if re-validated
    denied_second = reject.resolve("bad-bearer", "10.0.0.4")
    assert denied_second is None, "negative cache did not serve the cached rejection"


if __name__ == "__main__":
    test_expired_entries_are_pruned_on_cache_miss()
    test_hard_cap_evicts_oldest_when_pruning_is_not_enough()
    test_positive_and_negative_cache_still_work_after_pruning()
    print("all tests passed")
