# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Offline seal: the hard fence must fire, and drop keys, with NO database.

Two defects against the same invariant, both observed on rhorizon-4 in the
lab (a 340s PostgreSQL blackout left a secondary parked in `sealing` for
~350s, still holding its keys):

  1. THE GATE was lease-derived. ``_lease_fence_should_seal`` reads
     ``last_lease_confirm``, which the heartbeat sets to None on any node that
     is not the canonical primary -- so it returned False before looking at a
     clock and A SECONDARY COULD NEVER FIRE IT. Same blind spot that motivated
     FROZEN ("a secondary holds no primary lease, so a lease-derived fence
     cannot see it"): ``frozen`` was made role-independent, this was not.

  2. THE ACTION sealed the API view only. Under Rust custody the runtime
     bundle lives in the custodians, not in this worker, so that zeroized the
     wrong process. The operator path (``deactivate_rust_custody``) does seal
     them -- but persists ``unsealed=False`` FIRST, and that is a database
     write, unusable in precisely the outage the fence exists for.

Why this is a security bug and not a tidiness one: the attacker chooses when
it starts. Cut the database link and a secondary freezes, never seals, and
holds key material for the life of the process -- then snapshot the guest.
mlock stops swap and zeroize stops post-drop recovery; neither touches a
live-VM memory snapshot. Sealing is the only control that removes the
material.
"""

import pytest
from api.app import cluster_ha_loops as loops
from api.app.config import settings


class _FakeVault:
    """Minimal VaultState surface the fence decision reads."""

    def __init__(self, *, sealed=False, must_seal=False):
        self.sealed = sealed
        self.must_seal = must_seal
        self.seal_calls = 0

    def seal(self):
        self.seal_calls += 1
        self.sealed = True


class _FakePool:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.seal_all_calls = 0

    async def seal_all(self):
        self.seal_all_calls += 1
        if self.fail:
            raise RuntimeError("slot 2: custodian unreachable")


# --------------------------------------------------------------------------
# 1. The gate
# --------------------------------------------------------------------------


def test_secondary_past_deadline_now_seals():
    """THE REGRESSION. No lease (secondary), but the authority deadline passed.

    Before the fix this returned False forever and the node sat in `sealing`
    with its keys resident.
    """
    vs = _FakeVault(must_seal=True)
    fire, trigger = loops._fence_should_seal(None, 1_000_000.0, vs)
    assert fire is True
    assert trigger == "authority_fence"


def test_secondary_before_deadline_does_not_seal():
    """Freezing is not sealing: a secondary inside the grace window keeps keys."""
    vs = _FakeVault(must_seal=False)
    fire, trigger = loops._fence_should_seal(None, 1_000_000.0, vs)
    assert fire is False
    assert trigger is None


def test_primary_lease_path_unchanged(monkeypatch):
    """The original trigger still fires, and still reports as itself.

    The new trigger is ADDITIVE. If this flips to `authority_fence` the two
    causes have been conflated and the primary path has been retuned behind
    a change that was only meant to widen coverage.
    """
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 20)
    monkeypatch.setattr(settings, "cluster_frozen_max_secs", 300)
    confirmed_at = 1_000_000.0
    vs = _FakeVault(must_seal=False)
    fire, trigger = loops._fence_should_seal(confirmed_at, confirmed_at + 321.0, vs)
    assert fire is True
    assert trigger == "lease_loss_fence"


def test_already_sealed_is_not_resealed():
    vs = _FakeVault(sealed=True, must_seal=True)
    fire, _ = loops._fence_should_seal(None, 1_000_000.0, vs)
    assert fire is False


# --------------------------------------------------------------------------
# 2. The action
# --------------------------------------------------------------------------


async def test_custodians_sealed_without_touching_the_database(monkeypatch):
    """The whole point: key material dropped with no session, no query.

    ``_persist_rust_custody_activation`` is the only database step in the
    operator path, and it must NOT be on this one -- it would block on exactly
    the outage that fired the fence.
    """
    from api.app import rust_custody_backend as rcb

    pool = _FakePool()
    monkeypatch.setattr(rcb, "_configured_pool", pool)

    async def _explode(*a, **kw):
        raise AssertionError("offline seal must not touch the database")

    monkeypatch.setattr(rcb, "_persist_rust_custody_activation", _explode)

    assert await rcb.seal_custodians_offline() is True
    assert pool.seal_all_calls == 1


async def test_no_custody_configured_is_a_noop(monkeypatch):
    from api.app import rust_custody_backend as rcb

    monkeypatch.setattr(rcb, "_configured_pool", None)
    assert await rcb.seal_custodians_offline() is False


async def test_vault_is_sealed_even_if_a_custodian_is_unreachable(monkeypatch):
    """Drop what we can reach rather than nothing.

    ``seal_all`` accumulates per-slot failures and raises. If that exception
    escaped, one unreachable custodian would keep this worker's own keys in
    RAM too -- turning a partial failure into a total one.
    """
    from api.app import rust_custody_backend as rcb

    pool = _FakePool(fail=True)
    monkeypatch.setattr(rcb, "_configured_pool", pool)

    async def _noop_stop(*a, **kw):
        return None

    monkeypatch.setattr("api.app.cluster_setup.stop_master_services", _noop_stop)

    vs = _FakeVault()
    await loops._lease_fence_seal(vs)

    assert pool.seal_all_calls == 1
    assert vs.seal_calls == 1, "API-view seal must survive a custodian failure"
    assert vs.sealed is True


async def test_fence_seal_drops_custodians_and_local_keys(monkeypatch):
    from api.app import rust_custody_backend as rcb

    pool = _FakePool()
    monkeypatch.setattr(rcb, "_configured_pool", pool)

    stopped = []

    async def _record_stop(vault, db=None, **kw):
        # db=None is load-bearing: a DB-touching teardown reintroduces the
        # dependency this whole path exists to avoid.
        assert db is None
        stopped.append(vault)

    monkeypatch.setattr("api.app.cluster_setup.stop_master_services", _record_stop)

    vs = _FakeVault()
    await loops._lease_fence_seal(vs)

    assert stopped == [vs]
    assert pool.seal_all_calls == 1
    assert vs.seal_calls == 1


@pytest.mark.parametrize("must_seal", [True, False])
def test_authority_fence_needs_no_clock_argument(must_seal):
    """must_seal is a deadline the node evaluates alone.

    Guards the property the offline seal rests on: the decision must not
    depend on a value only a reachable database could supply.
    """
    vs = _FakeVault(must_seal=must_seal)
    fire, _ = loops._fence_should_seal(None, 0.0, vs)
    assert fire is must_seal
