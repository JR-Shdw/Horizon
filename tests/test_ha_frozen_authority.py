# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""FROZEN : losing PostgreSQL authority suspends service without dropping keys.

Sealing at the primary-lease TTL was expensive in a way nothing compensated
for: there is no auto-unseal, so every PostgreSQL outage longer than the TTL
cost a manual /unseal on the primary -- and a routine Patroni failover takes
10-30s against a 20s default. The node now goes FROZEN instead: keys retained,
all authority refused, and it recovers by itself once it can confirm against
the database that it is still the canonical primary.

The property these tests exist for is that frozen is a DEADLINE recomputed on
read, not a flag pushed by the heartbeat loop. The previous fence armed inside
that loop and sealed from there, with the seal call outside the loop's try; a
raise from it killed the task, main.py registers no done-callback, and the node
kept serving with its keys. test_frozen_survives_the_refresher_dying is that
scenario, and it is the release-blocking one.

Cf api/app/vault_state.py (renew_authority / frozen) and
cluster_ha_loops._lease_fence_should_seal.
"""

import time

import pytest
from api.app.config import settings
from api.app.vault_state import VaultFrozenError, VaultSealedError, VaultState


def _unsealed() -> VaultState:
    """A VaultState that reports unsealed, without real key material."""
    vs = VaultState()
    vs._sealed = False
    return vs


# ---------------------------------------------------------------------------
# The lease itself
# ---------------------------------------------------------------------------


def test_no_lease_means_never_frozen():
    """Non-HA deployments carry no deadline and must be untouched.

    The loops that set a deadline only run under settings.cluster_ha_enabled,
    so a single-node vault keeps _db_confirmation_deadline None forever.
    """
    vs = _unsealed()
    assert vs.frozen is False
    assert vs.frozen_for() == 0.0
    vs.require_unsealed()  # must not raise


def test_renew_then_lapse_freezes():
    vs = _unsealed()
    vs.renew_db_confirmation(0.15, 3600)
    assert vs.frozen is False
    vs.require_unsealed()
    time.sleep(0.25)
    assert vs.frozen is True
    assert vs.frozen_for() > 0
    with pytest.raises(VaultFrozenError):
        vs.require_unsealed()


def test_release_db_confirmation_is_not_frozen():
    """A node that is legitimately not primary carries no obligation.

    Distinct from letting the deadline lapse: releasing must not freeze.
    """
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 3600)
    time.sleep(0.15)
    assert vs.frozen is True
    vs.release_db_confirmation()
    assert vs.frozen is False
    vs.require_unsealed()


def test_renewal_unfreezes():
    """Recovery path: confirming primacy against PG returns the node to ACTIVE."""
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 3600)
    time.sleep(0.15)
    assert vs.frozen is True
    vs.renew_db_confirmation(settings.cluster_primary_lease_ttl_secs, 3600)
    assert vs.frozen is False
    vs.require_unsealed()


def test_frozen_keeps_keys_sealed_does_not():
    """Frozen is not sealed -- that distinction is the entire point."""
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 3600)
    time.sleep(0.15)
    assert vs.frozen is True
    assert vs.sealed is False, "frozen must NOT drop key material"
    with pytest.raises(VaultFrozenError):
        vs.require_unsealed()


def test_sealed_takes_precedence_over_frozen():
    """A sealed vault reports sealed, so operators get the actionable error."""
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 3600)
    time.sleep(0.15)
    vs._sealed = True
    with pytest.raises(VaultSealedError):
        vs.require_unsealed()


# ---------------------------------------------------------------------------
# The release-blocking invariant
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_frozen_survives_the_refresher_dying():
    """Killing the refresher must NOT keep the node authoritative.

    Reproduces the old failure exactly: a task that raises partway through and
    dies, with nobody watching it. Under the previous design the fence lived in
    that task, so its death meant the node never stopped serving. Here the
    deadline is state, so the node freezes anyway.
    """
    import asyncio

    vs = _unsealed()
    vs.renew_db_confirmation(0.2, 3600)

    async def refresher():
        await asyncio.sleep(0.05)
        raise RuntimeError("refresher died (seal() blew up / spurious cancel)")

    task = asyncio.create_task(refresher())  # no done-callback, as in main.py
    await asyncio.sleep(0.35)

    assert task.done() and task.exception() is not None, "task should be dead"
    assert vs.frozen is True, "node stayed authoritative after its refresher died"
    with pytest.raises(VaultFrozenError):
        vs.require_unsealed()


# ---------------------------------------------------------------------------
# Hard fence timing: freeze at ttl, seal only at ttl + frozen_max
# ---------------------------------------------------------------------------


def test_hard_fence_waits_for_frozen_max(monkeypatch):
    from api.app import cluster_ha_loops as loops

    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 20)
    monkeypatch.setattr(settings, "cluster_frozen_max_secs", 300)
    t0 = 1_000_000.0
    # Frozen at 20s, but the keys stay until 320s.
    assert loops._lease_fence_should_seal(t0, t0 + 25) is False
    assert loops._lease_fence_should_seal(t0, t0 + 319) is False
    assert loops._lease_fence_should_seal(t0, t0 + 321) is True


def test_hard_fence_needs_a_prior_confirmation(monkeypatch):
    """Never held the lease -> nothing to fence."""
    from api.app import cluster_ha_loops as loops

    monkeypatch.setattr(settings, "cluster_frozen_max_secs", 300)
    assert loops._lease_fence_should_seal(None, 1_000_000.0) is False


# ---------------------------------------------------------------------------
# Non-HA single instance must be completely unaffected
# ---------------------------------------------------------------------------


def test_ha_is_off_by_default():
    """The whole default deployment shape is non-HA.

    This is why the rest of the suite is itself the regression proof: with
    cluster_ha_enabled False, the loops that could set an authority deadline
    are never spawned, so every other test runs a vault that can never freeze.
    """
    from api.app.config import Settings

    assert Settings().cluster_ha_enabled is False


def test_single_instance_never_freezes_however_long_it_runs():
    """No lease is ever taken out, so no amount of elapsed time freezes it.

    A single-node vault holds _db_confirmation_deadline None for its whole life. The
    property is not "the deadline is far away" but "there is no deadline",
    which is what makes elapsed time irrelevant.
    """
    vs = _unsealed()
    assert vs._db_confirmation_deadline is None
    # Simulate an arbitrarily long uptime: frozen is computed from the
    # deadline, and there is none, so this cannot drift into frozen.
    for _ in range(3):
        assert vs.frozen is False
        assert vs.frozen_for() == 0.0
        vs.require_unsealed()


def test_only_the_two_mode_owners_can_confirm_db_authority():
    """Guard the blast radius: exactly two modules may arm the deadline.

    cluster_ha_loops owns it under HA (renewed from a round-trip that also
    confirms this node is still the canonical primary); main owns it in
    standalone (renewed from a local database probe). Each is gated on
    cluster_ha_enabled, on opposite sides, so a deployment runs exactly one.

    Any third caller means some path can freeze a node without owning the
    reason it froze. Catch that here rather than in production.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "api" / "app"
    callers = {
        p.name
        for p in root.rglob("*.py")
        if p.name != "vault_state.py" and "renew_db_confirmation(" in p.read_text()
    }
    assert callers == {"cluster_ha_loops.py", "main.py"}, (
        f"renew_db_confirmation() is reachable from {callers or 'nowhere'}; it must "
        "must stay confined to the HA heartbeat loop and the standalone watchdog"
    )


# ---------------------------------------------------------------------------
# Invariant 3 : peers may prolong FROZEN, they may never grant ACTIVE
# ---------------------------------------------------------------------------


def test_peers_cannot_grant_active():
    """The whole point: peer input can buy time, never permission to serve.

    Structural rather than a rule the peer code must remember. prolong_frozen
    touches _seal_deadline only, and `frozen` is derived from
    _db_confirmation_deadline, which only a confirmed write-authority round-trip
    against PostgreSQL can push. A compromised peer, or a stale cached roster,
    therefore cannot make this node serve.
    """
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 10)
    time.sleep(0.15)
    assert vs.frozen is True

    assert vs.prolong_frozen(60) is True  # peers bought time
    assert vs.frozen is True, "peer evidence must NOT return the node to service"
    with pytest.raises(VaultFrozenError):
        vs.require_unsealed()


def test_peers_can_delay_the_seal_but_not_cancel_it():
    """Prolonging is bounded, so peer input cannot waive invariant 6."""
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 0.2)
    time.sleep(0.1)

    # Each call may push the seal deadline further, up to the cap fixed at
    # renewal from the last moment authority was actually proven.
    assert vs.prolong_frozen(5) is True
    moved_again = vs.prolong_frozen(5)
    assert vs.prolong_frozen(9999) is False or moved_again, "must converge on the cap"
    # Hammering it cannot walk the ceiling forward.
    for _ in range(20):
        vs.prolong_frozen(9999)
    assert vs._seal_deadline <= vs._seal_deadline_cap

    # And the node still seals once the capped window elapses.
    remaining = vs._seal_deadline_cap - time.monotonic()
    time.sleep(max(0.0, remaining) + 0.1)
    assert vs.must_seal is True, "a bounded prolongation must still end sealed"


def test_prolong_is_a_noop_without_a_lease():
    """A node carrying no obligation has nothing for peers to extend."""
    vs = _unsealed()
    assert vs.prolong_frozen(60) is False
    vs.renew_db_confirmation(0.05, 10)
    vs.release_db_confirmation()
    assert vs.prolong_frozen(60) is False


# ---------------------------------------------------------------------------
# DB-authority freshness is role-independent; the primary lease is not
#
# Found by fault injection, not by unit tests: a secondary blacked out from
# PostgreSQL held no deadline at all, so it never froze and answered requests
# with raw database exceptions (500s). It could no longer prove it was still a
# secondary -- since its last read the primary may have changed, its epoch may
# have moved, it may have been promoted or demoted, and its tokens and ACLs may
# have been rewritten. That is not enough authority to serve on.
# ---------------------------------------------------------------------------


def test_a_secondary_freezes_when_it_cannot_confirm_db_state():
    """No primary lease, but it still freezes: serving needs DB confirmation."""
    vs = _unsealed()
    # Exactly what the heartbeat does on a secondary.
    vs.renew_db_confirmation(0.05, 3600)
    vs.release_primary_lease()

    assert vs.holds_primary_lease is False
    assert vs.frozen is False, "a secondary with fresh DB state serves normally"
    vs.require_unsealed()

    time.sleep(0.15)
    assert vs.frozen is True, "a secondary that lost the database must freeze"
    with pytest.raises(VaultFrozenError):
        vs.require_unsealed()


def test_losing_the_primary_lease_alone_does_not_stop_serving():
    """Demotion is not a reason to refuse requests.

    The converse of the test above, and why the two deadlines are separate: a
    node demoted to secondary keeps serving, it simply stops being primary.
    Conflating them would take a healthy node out of service on every failover.
    """
    vs = _unsealed()
    vs.renew_db_confirmation(3600, 3600)
    vs.renew_primary_lease(0.05)
    time.sleep(0.15)

    assert vs.holds_primary_lease is False, "the lease lapsed"
    assert vs.frozen is False, "but canonical state is still confirmable"
    vs.require_unsealed()  # must not raise


def test_the_primary_lease_does_not_by_itself_permit_serving():
    """A stale-DB node cannot serve on the strength of an unexpired lease."""
    vs = _unsealed()
    vs.renew_db_confirmation(0.05, 3600)
    vs.renew_primary_lease(3600)
    time.sleep(0.15)

    assert vs.holds_primary_lease is True, "lease still nominally valid"
    assert vs.frozen is True, "but it cannot confirm canonical state"
    with pytest.raises(VaultFrozenError):
        vs.require_unsealed()
