# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Worker churn must not permanently drain the Shamir share pool.

Shares are minted exactly once, at unseal, by ``split_and_bind``. Every share
handed out is *removed* from the server's pool. With ``total`` equal to the
worker count the pool is empty as soon as every worker has attached, so a
worker that dies and is replaced can never obtain one: the live share count
only ever falls. Below ``threshold`` no failover can reconstruct and the node
seals, with no way back short of a manual unseal.

Observed on a 3-node lab cluster: repeated `worker registration was reaped;
terminating pid=N` entries, then `failover: only 2 shares (need 3)`, then
`only 1 shares (need 3)`, and all three nodes sealed.

Two defences, both tested here:

1. A live worker whose row was reaped re-registers instead of terminating, so
   its share survives (`cluster._reregister_after_reap`).
2. The pool is minted with spare shares beyond the worker count, so a
   replacement worker can still obtain one.

Spares must come from the SAME polynomial as the rest. A second
``shamir_split`` draws fresh random coefficients, and mixing shares from two
polynomials makes ``shamir_combine`` return a plausible but WRONG secret
rather than raising -- which is why the fix is over-provisioning up front, not
re-splitting later. The last test pins that property.
"""

import pytest
from api.app import cluster_setup
from api.app.config import settings


def _resolve(monkeypatch, *, workers, spares, total=0, threshold=0):
    monkeypatch.setattr(settings, "workers", workers)
    monkeypatch.setattr(settings, "cluster_shamir_spare_shares", spares)
    monkeypatch.setattr(settings, "cluster_shamir_total", total)
    monkeypatch.setattr(settings, "cluster_shamir_threshold", threshold)
    return cluster_setup._shamir_total_threshold()


def test_pool_has_headroom_beyond_the_worker_count(monkeypatch):
    """The regression: total == workers meant zero spare shares."""
    total, threshold = _resolve(monkeypatch, workers=5, spares=8)
    assert total == 13
    assert threshold == 3
    # A master + 4 followers consume 5 ; the rest are available to replacements.
    assert total - 5 == 8


def test_threshold_is_pegged_to_workers_not_to_the_padded_total(monkeypatch):
    """Padding the pool must not raise the failover quorum."""
    base_total, base_threshold = _resolve(monkeypatch, workers=5, spares=0)
    padded_total, padded_threshold = _resolve(monkeypatch, workers=5, spares=50)
    assert padded_total > base_total
    assert padded_threshold == base_threshold == 3


def test_churn_budget_is_no_longer_two(monkeypatch):
    """With no spares a node tolerated total-threshold = 2 worker deaths for
    its entire unsealed life. That is the number that ran out."""
    no_spares, threshold = _resolve(monkeypatch, workers=5, spares=0)
    assert no_spares - threshold == 2  # the old, observed budget
    with_spares, threshold2 = _resolve(monkeypatch, workers=5, spares=8)
    assert with_spares - threshold2 == 10


@pytest.mark.parametrize("workers", [1, 2, 5, 16, 64])
def test_total_never_exceeds_the_gf256_share_limit(monkeypatch, workers):
    """x-coordinates are one byte, so 255 shares is the hard ceiling."""
    total, threshold = _resolve(monkeypatch, workers=workers, spares=200)
    assert total <= 255
    assert threshold >= 2
    assert threshold <= total


def test_explicit_operator_values_still_win(monkeypatch):
    total, threshold = _resolve(monkeypatch, workers=5, spares=8, total=7, threshold=4)
    assert (total, threshold) == (7, 4)


def test_zero_spares_restores_the_old_behaviour(monkeypatch):
    total, _ = _resolve(monkeypatch, workers=9, spares=0)
    assert total == 9


def test_shares_from_two_splits_do_not_combine():
    """Why the fix is over-provisioning, not re-splitting.

    Each shamir_split call draws fresh coefficients. Mixing shares across two
    splits of the same secret does not error -- it yields the wrong secret.
    Any 'refill by re-splitting' would therefore corrupt failover silently.
    """
    rhorizon_crypto = pytest.importorskip("rhorizon_crypto")
    secret = bytes(range(96))
    a = rhorizon_crypto.shamir_split_bytes(secret, 3, 5)
    b = rhorizon_crypto.shamir_split_bytes(secret, 3, 5)

    # Same polynomial: reconstructs exactly.
    assert bytes(rhorizon_crypto.shamir_combine_bytes([a[0], a[1], a[2]])) == secret

    # Mixed polynomials: no exception, but the result is not the secret.
    try:
        mixed = bytes(rhorizon_crypto.shamir_combine_bytes([a[0], a[1], b[2]]))
    except Exception:
        return  # raising would be acceptable too
    assert mixed != secret, "mixing splits must not silently appear to work"


# ---------------------------------------------------------------------------
# Defence 1: a live worker whose row was reaped must not kill itself.
# ---------------------------------------------------------------------------


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _session_factory():
    return _FakeSession()


@pytest.mark.asyncio
async def test_reaped_but_live_worker_reregisters_and_survives(monkeypatch):
    """The share dies with the process, so the process must not die."""
    import asyncio

    from api.app import cluster

    calls = {"terminate": 0, "reregister": 0}

    async def fake_reregister(_sf):
        calls["reregister"] += 1
        return True

    async def always_reaped(_db, **_kw):
        raise cluster.WorkerRegistrationLost("row gone")

    monkeypatch.setattr(cluster, "_reregister_after_reap", fake_reregister)
    monkeypatch.setattr(cluster, "heartbeat_once", always_reaped)
    monkeypatch.setattr(
        cluster, "_terminate_lost_worker", lambda: calls.__setitem__("terminate", 1)
    )
    monkeypatch.setattr(cluster, "HEARTBEAT_INTERVAL_SECS", 0.01)

    stop = asyncio.Event()
    task = asyncio.create_task(cluster.heartbeat_loop(_session_factory, stop))
    await asyncio.sleep(0.15)
    stop.set()
    await asyncio.wait_for(task, timeout=2)

    assert calls["terminate"] == 0, "a live worker must not fail-close on reap"
    assert calls["reregister"] >= 1
    # It must also not spin: the sleep is not skipped after a reap.
    assert calls["reregister"] < 50, "re-registration should be paced by the heartbeat"


@pytest.mark.asyncio
async def test_terminates_only_when_reregistration_fails(monkeypatch):
    """Fail-close is still the last resort, not the first response."""
    import asyncio

    from api.app import cluster

    calls = {"terminate": 0}

    async def failed_reregister(_sf):
        return False

    async def always_reaped(_db, **_kw):
        raise cluster.WorkerRegistrationLost("row gone")

    monkeypatch.setattr(cluster, "_reregister_after_reap", failed_reregister)
    monkeypatch.setattr(cluster, "heartbeat_once", always_reaped)
    monkeypatch.setattr(
        cluster, "_terminate_lost_worker", lambda: calls.__setitem__("terminate", 1)
    )
    monkeypatch.setattr(cluster, "HEARTBEAT_INTERVAL_SECS", 0.01)

    stop = asyncio.Event()
    await asyncio.wait_for(cluster.heartbeat_loop(_session_factory, stop), timeout=2)
    assert calls["terminate"] == 1
