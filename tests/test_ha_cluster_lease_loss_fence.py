# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Lease-loss self-fence (active-node step-down semantics).

Targets ``cluster_ha_loops._lease_fence_should_seal`` -- the decision a
node makes when it last held the primary lease but can no longer confirm
it (e.g. partitioned from Patroni while still reachable by joiners). The
DB-driven self-demote in ``_heartbeat_body`` cannot fire on that path (it
needs a live read), so the per-node heartbeat loop seals instead, dropping
the CA / master keys -- a fail-closed fence against a stale primary
issuing certs or admitting members under lost authority.

The decision is a pure function of (last-confirm timestamp, now) against
``cluster_primary_lease_ttl_secs`` ; we drive it directly rather than
running the daemon loop.
"""

from api.app import cluster_ha_loops as loops
from api.app.config import settings


def test_disarmed_never_seals():
    # last_confirm is None : this node is not (or no longer) the canonical
    # primary -- a secondary partitioned from the DB keeps serving reads and
    # must NOT seal.
    assert loops._lease_fence_should_seal(None, 1_000_000.0) is False


def test_within_ttl_does_not_seal():
    ttl = settings.cluster_primary_lease_ttl_secs
    confirmed_at = 1_000_000.0
    # Re-confirmed strictly inside the TTL window : still the live leader.
    now = confirmed_at + ttl - 0.001
    assert loops._lease_fence_should_seal(confirmed_at, now) is False


def test_at_ttl_boundary_does_not_seal():
    # Exactly at the TTL is not yet "> ttl" : the lease has not provably
    # expired, so hold (matches the strict > in the implementation).
    ttl = settings.cluster_primary_lease_ttl_secs
    confirmed_at = 1_000_000.0
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + ttl) is False


def test_beyond_ttl_seals():
    ttl = settings.cluster_primary_lease_ttl_secs
    confirmed_at = 1_000_000.0
    # One full interval past the lease TTL : the old lease has expired
    # cluster-wide and a secondary has auto-promoted -> fence.
    now = confirmed_at + ttl + 0.001
    assert loops._lease_fence_should_seal(confirmed_at, now) is True


def test_threshold_follows_settings(monkeypatch):
    # The fence tracks the configured lease TTL, not a hard-coded constant.
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 5)
    confirmed_at = 42.0
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 4) is False
    assert loops._lease_fence_should_seal(confirmed_at, confirmed_at + 6) is True


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
