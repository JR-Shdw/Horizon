# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Lease-loss HARD fence (key-material drop, not step-down).

Targets ``cluster_ha_loops._lease_fence_should_seal`` -- the decision a
node makes when it last held the primary lease but can no longer confirm
it (e.g. partitioned from Patroni while still reachable by joiners). The
DB-driven self-demote in ``_heartbeat_body`` cannot fire on that path (it
needs a live read).

This is NO LONGER what stops the node serving. Stepping down happens at
``cluster_primary_lease_ttl_secs``, when the VaultState authority deadline
lapses and the node goes FROZEN -- keys retained, every route refused. That
transition is a deadline recomputed on read, so it needs no code to run and
holds even if the heartbeat task is dead. See tests/test_ha_frozen_authority.py.

What remains here is the hard fence: after a further
``cluster_frozen_max_secs`` of being frozen, drop the key material too. The
two were split because there is no auto-unseal, so sealing at the TTL made
every PostgreSQL outage longer than it cost a manual /unseal on the primary,
while a routine Patroni failover takes 10-30s against a 20s default.

The decision is a pure function of (last-confirm timestamp, now) against
``ttl + frozen_max`` ; we drive it directly rather than running the daemon loop.
"""

from api.app import cluster_ha_loops as loops
from api.app.config import settings


def test_disarmed_never_seals():
    # last_confirm is None : this node is not (or no longer) the canonical
    # primary, so the LEASE fence is disarmed -- there is no lease to have
    # lost. That is a statement about this function, not about the node.
    #
    # The original rationale here read "a secondary partitioned from the DB
    # keeps serving reads and must NOT seal". Both halves are now wrong. A
    # partitioned secondary does not serve: `frozen` is role-independent and
    # refuses every route at the TTL. And it does eventually seal -- via the
    # AUTHORITY fence (`vault_state.must_seal`), which needs no lease and no
    # database. See tests/test_ha_offline_seal_fence.py.
    #
    # Leaving this trigger disarmed on a secondary was exactly the gap that
    # let a blacked-out secondary sit in `sealing` holding its keys, so the
    # assertion below must NOT be read as "a secondary keeps its keys".
    assert loops._lease_fence_should_seal(None, 1_000_000.0) is False


def test_within_ttl_does_not_seal():
    ttl = settings.cluster_primary_lease_ttl_secs
    confirmed_at = 1_000_000.0
    # Re-confirmed strictly inside the TTL window : still the live leader.
    now = confirmed_at + ttl - 0.001
    assert loops._lease_fence_should_seal(confirmed_at, now) is False


def test_at_ttl_boundary_does_not_seal():
    # At the TTL the node FREEZES, it does not seal. Keys are retained so a
    # database failover shorter than cluster_frozen_max_secs costs no unseal.
    ttl = settings.cluster_primary_lease_ttl_secs
    confirmed_at = 1_000_000.0
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + ttl) is False


def test_beyond_ttl_freezes_but_does_not_seal(monkeypatch):
    """Past the TTL the node is frozen; the keys survive the grace window."""
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 20)
    monkeypatch.setattr(settings, "cluster_frozen_max_secs", 300)
    confirmed_at = 1_000_000.0
    # Well past the lease, deep inside the frozen window: authority is gone
    # (asserted in test_ha_frozen_authority.py) but the key material is not.
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 21) is False
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 200) is False


def test_beyond_frozen_max_seals(monkeypatch):
    """Only after ttl + frozen_max does the hard fence drop the keys."""
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 20)
    monkeypatch.setattr(settings, "cluster_frozen_max_secs", 300)
    confirmed_at = 1_000_000.0
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 320) is False
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 320.1) is True


def test_threshold_follows_settings(monkeypatch):
    # The fence tracks the configured TTL + frozen window, not a constant.
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 5)
    monkeypatch.setattr(settings, "cluster_frozen_max_secs", 10)
    confirmed_at = 42.0
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 14) is False
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 16) is True


async def test_lease_fence_seal_stops_master_services_before_seal(monkeypatch):
    """The fence must release master services BEFORE sealing: seal() does not
    stop the RPC server, so a bare seal on the master worker leaks the
    crypto-ops socket and wedges the next /unseal."""
    from api.app import cluster_setup

    calls = []

    async def _fake_stop(vault_state, db=None, pid=None):
        calls.append("stop")

    monkeypatch.setattr(cluster_setup, "stop_master_services", _fake_stop)

    class _FakeVault:
        def seal(self):
            calls.append("seal")

    await loops._lease_fence_seal(_FakeVault())
    assert calls == ["stop", "seal"]


async def test_lease_fence_seal_still_seals_when_stop_raises(monkeypatch):
    """A teardown failure must not block the fence -- the seal still fires."""
    from api.app import cluster_setup

    calls = []

    async def _boom(vault_state, db=None, pid=None):
        raise RuntimeError("stop failed")

    monkeypatch.setattr(cluster_setup, "stop_master_services", _boom)

    class _FakeVault:
        def seal(self):
            calls.append("seal")

    await loops._lease_fence_seal(_FakeVault())
    assert calls == ["seal"]
