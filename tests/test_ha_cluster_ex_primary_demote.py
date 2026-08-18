# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Sprint 1.1 (2026-06-01) -- ex-primary self-demote split-brain fix.

Targets the new branch in ``cluster_ha_loops._heartbeat_body`` :

- If our row still says ``ha_state='primary'`` but the canonical
  ``primary_uuid`` points elsewhere with a fresh lease, transition self
  ``primary -> secondary`` in the same heartbeat tick and emit a
  ``cluster_primary_self_demoted`` audit row.

This is the per-host recovery path for the K2 split-brain symptom
observed on 2026-06-01 : kill -9 ex-primary, the rest of the cluster
auto-promotes a replacement, the ex-primary restarts and re-reads its
own (stale) row believing it is still primary.

The state-machine loop runs cluster-wide-singleton (the lock holder is
usually NOT the ex-primary), so the heartbeat loop is the only loop
guaranteed to fire on the ex-primary itself.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from api.app import cluster_ha_loops as loops
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from sqlalchemy import text

_OTHER_NODE_UUID = "ffffeeeeddddccccbbbbaaaa99998888"


async def _insert_node(
    *,
    node_uuid: str,
    source_ip: str = "10.0.0.1",
    ha_state: str = "secondary",
    quarantine_secs: int = -60,
    heartbeat_offset_secs: int | None = 1,
):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until, "
                "    joined_at, cluster_version, cert_fingerprint, "
                "    cert_not_after, last_heartbeat"
                ") VALUES ("
                "    :u, CAST(:ip AS INET), :s, "
                "    NOW() + make_interval(secs => :qs), "
                "    NOW(), '1.0.0-beta', 'fpr', "
                "    NOW() + INTERVAL '30 days', "
                "    CASE WHEN CAST(:hb AS INT) IS NULL THEN NULL ELSE "
                "         NOW() - make_interval(secs => CAST(:hb AS INT)) END"
                ")"
            ),
            {
                "u": node_uuid,
                "ip": source_ip,
                "s": ha_state,
                "qs": quarantine_secs,
                "hb": heartbeat_offset_secs,
            },
        )
        await db.commit()


async def _set_config(key: str, value: str):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"k": key, "v": value},
        )
        await db.commit()


async def _read_config(key: str) -> str | None:
    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": key},
        )
        row = r.fetchone()
        return row.value if row else None


async def _get_state(node_uuid: str) -> str | None:
    async with async_session() as db:
        r = await db.execute(
            text("SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        row = r.fetchone()
        return row.ha_state if row else None


async def _wipe():
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text(
                "DELETE FROM vault_cluster_config WHERE key IN ("
                "    'primary_uuid', 'primary_since', "
                "    'primary_lease_expires_at'"
                ")"
            )
        )
        await db.execute(
            text(
                "DELETE FROM vault_audit WHERE action = 'cluster_primary_self_demoted'"
            )
        )
        await db.commit()


def _fresh_lease_iso(secs_in_future: int = 60) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=secs_in_future)).isoformat()


def _stale_lease_iso(secs_in_past: int = 60) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=secs_in_past)).isoformat()


@pytest_asyncio.fixture
async def fresh(setup_db):
    """Clean cluster state + ensure node_uuid file exists."""
    nu.init_node_uuid(settings.node_uuid_path)
    await _wipe()
    yield
    await _wipe()


# ---------------------------------------------------------------------------
# Main case : ex-primary detects split-brain and self-demotes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_self_demotes_when_canonical_primary_is_other_and_lease_fresh(fresh):
    """Our row says primary but primary_uuid points elsewhere + fresh lease."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _set_config("primary_lease_expires_at", _fresh_lease_iso(60))

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True

    # Self transitioned primary -> secondary.
    assert await _get_state(self_uuid) == "secondary"
    # Canonical primary unchanged.
    assert await _read_config("primary_uuid") == _OTHER_NODE_UUID


@pytest.mark.asyncio
async def test_self_demote_emits_audit_row(fresh):
    """The split-brain demote emits cluster_primary_self_demoted with detail."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    lease_iso = _fresh_lease_iso(60)
    await _set_config("primary_lease_expires_at", lease_iso)

    async with async_session() as db:
        await loops._heartbeat_body(db, self_uuid)

    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT actor, action, target, detail FROM vault_audit "
                "WHERE action = 'cluster_primary_self_demoted' "
                "ORDER BY timestamp DESC LIMIT 1"
            )
        )
        row = r.fetchone()
    assert row is not None
    assert row.actor == "self-demote"
    assert row.target == self_uuid
    detail = json.loads(row.detail) if isinstance(row.detail, str) else row.detail
    assert detail["reason"] == "lost_lease"
    assert detail["canonical_primary"] == _OTHER_NODE_UUID
    # lease_expires is the same ISO string we wrote (parsed-then-isoformat
    # is idempotent for tz-aware UTC strings).
    assert detail["lease_expires"] == lease_iso


# ---------------------------------------------------------------------------
# Guards : conditions under which self-demote MUST NOT fire
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_demote_when_no_canonical_primary(fresh):
    """primary_uuid absent -> no signal, no demote (pre-cluster-init state)."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    # No primary_uuid, no lease.

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True
    assert await _get_state(self_uuid) == "primary"


@pytest.mark.asyncio
async def test_no_demote_when_lease_stale(fresh):
    """Stale lease : normal failover window, not a split-brain. No demote.

    A stale lease means the canonical primary is gone -- this is exactly
    the case ``_maybe_auto_promote`` is meant to resolve. Demoting an
    ex-primary here would needlessly burn a candidate during failover.
    """
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _set_config("primary_lease_expires_at", _stale_lease_iso(60))

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True
    assert await _get_state(self_uuid) == "primary"


@pytest.mark.asyncio
async def test_no_demote_when_self_is_canonical_primary(fresh):
    """Self IS the canonical primary -> extend lease, never demote.

    Regression guard for the inversion bug (would self-demote the
    legitimate primary on every heartbeat).
    """
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", self_uuid)

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True

    assert await _get_state(self_uuid) == "primary"
    # Lease was extended (existing behavior, must not regress).
    lease = await _read_config("primary_lease_expires_at")
    assert lease is not None
    lease_dt = datetime.fromisoformat(lease)
    delta = (lease_dt - datetime.now(timezone.utc)).total_seconds()
    ttl = settings.cluster_primary_lease_ttl_secs
    assert ttl - 2 <= delta <= ttl + 2


@pytest.mark.asyncio
async def test_no_demote_when_self_already_secondary(fresh):
    """Already secondary + canonical elsewhere -> no audit row, no churn."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _set_config("primary_lease_expires_at", _fresh_lease_iso(60))

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True
    assert await _get_state(self_uuid) == "secondary"

    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT COUNT(*) AS n FROM vault_audit "
                "WHERE action = 'cluster_primary_self_demoted'"
            )
        )
        n = r.fetchone().n
    assert n == 0


# ---------------------------------------------------------------------------
# Integration : after self-demote, the next heartbeat does not extend lease
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_heartbeat_does_not_extend_lease_after_self_demote(fresh):
    """One tick demotes ; next tick must NOT touch the lease.

    Sanity check that the existing lease-extend guard
    (primary_uuid == self) holds after the demote: the row says
    'secondary' AND primary_uuid still points elsewhere, so the lease
    write branch must not fire.
    """
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    canonical_lease_iso = _fresh_lease_iso(60)
    await _set_config("primary_lease_expires_at", canonical_lease_iso)

    # First heartbeat : self-demote fires.
    async with async_session() as db:
        await loops._heartbeat_body(db, self_uuid)
    assert await _get_state(self_uuid) == "secondary"

    # Second heartbeat : we are now secondary, canonical lease must
    # remain untouched (no other node has heartbeated in between).
    async with async_session() as db:
        await loops._heartbeat_body(db, self_uuid)
    assert await _get_state(self_uuid) == "secondary"
    assert await _read_config("primary_lease_expires_at") == canonical_lease_iso
