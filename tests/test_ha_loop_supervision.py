# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""HA daemon loops must not be able to die unnoticed -- or to cost a share.

``asyncio.create_task`` drops the exception of a task nobody awaits: the
coroutine dies, the reference lingers in a list, and the process keeps serving
as if the loop were running. ``cluster_ha_heartbeat_loop`` ends each tick in a
hard-fence block that calls ``vault_state.seal()``; a raise from there killed
the task silently.

FROZEN already makes that fail-CLOSED -- nothing renews the authority lease, it
lapses, and the node stops being authoritative with no code running (see
tests/test_ha_frozen_authority.py). What was missing was visibility and
recovery, which is all ``main._supervised`` adds.

It must NOT escalate to killing the process. ``cluster._terminate_lost_worker``
seals, and seal() drops this worker's Shamir share, which cannot be reissued
while the vault is unsealed. A bug that kills one loop kills it on every worker
-- identical code, identical state -- so terminating would burn the whole
Shamir quorum and leave the cluster unable to reconstruct on a real master
failure. test_loop_death_never_costs_a_shamir_share is that guard.
"""

import asyncio

import pytest
from api.app import main


def _counter_value(loop: str) -> float:
    from api.app.metrics import ha_loop_deaths

    for metric in ha_loop_deaths.collect():
        for sample in metric.samples:
            if sample.labels.get("loop") == loop and sample.name.endswith("_total"):
                return sample.value
    return 0.0


@pytest.mark.asyncio
async def test_dying_loop_is_counted_and_restarted():
    starts = []

    async def flaky():
        starts.append(1)
        raise RuntimeError("seal() blew up inside the hard fence")

    before = _counter_value("ha-heartbeat")
    task = main._supervised(flaky, "ha-heartbeat")
    await asyncio.sleep(1.4)  # first failure is immediate, retry after ~1s
    task.cancel()

    assert len(starts) >= 2, f"loop was not restarted (started {len(starts)}x)"
    assert _counter_value("ha-heartbeat") >= before + 2


@pytest.mark.asyncio
async def test_loop_death_never_costs_a_shamir_share(monkeypatch):
    """The release-blocking guard: a dead loop must not seal or kill anything.

    Terminating drops the worker's Shamir share permanently. Since a loop bug
    hits every worker at once, that would cost the whole failover quorum.
    """
    terminated = []
    sealed = []
    monkeypatch.setattr(
        "api.app.cluster._terminate_lost_worker", lambda: terminated.append(1)
    )
    from api.app.vault_state import vault

    monkeypatch.setattr(vault, "seal", lambda: sealed.append(1))

    async def boom():
        raise RuntimeError("dead")

    task = main._supervised(boom, "ha-heartbeat")
    await asyncio.sleep(0.3)
    task.cancel()

    assert not terminated, "a dead HA loop must NOT terminate the worker"
    assert not sealed, "a dead HA loop must NOT seal (that drops the Shamir share)"


@pytest.mark.asyncio
async def test_backoff_is_capped_not_hot():
    """A persistently failing loop must not become a hot loop."""
    starts = []

    async def always_dies():
        starts.append(1)
        raise RuntimeError("dead")

    task = main._supervised(always_dies, "ha-reaper")
    await asyncio.sleep(1.4)
    task.cancel()
    # 1s then 2s backoff: a hot loop would have thousands of starts here.
    assert len(starts) < 10, f"restart loop is hot ({len(starts)} starts in 1.4s)"


@pytest.mark.asyncio
async def test_cancellation_is_clean_shutdown():
    """Shutdown cancels these loops; that must propagate, not restart."""
    started = []

    async def forever():
        started.append(1)
        await asyncio.sleep(3600)

    task = main._supervised(forever, "ha-state-machine")
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(started) == 1, "cancellation must not trigger a restart"


@pytest.mark.asyncio
async def test_clean_return_is_still_a_fault_and_restarts():
    """These loops are `while True`; returning at all means something broke."""
    starts = []

    async def returns():
        starts.append(1)

    task = main._supervised(returns, "ha-reaper")
    await asyncio.sleep(1.3)
    task.cancel()
    assert len(starts) >= 2, "a loop that returns must be restarted"
