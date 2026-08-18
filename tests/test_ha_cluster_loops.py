# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""background loop bodies + metrics wiring.

Tests target the synchronous body functions (``_state_machine_body``,
``_reaper_body``, ``_heartbeat_body``) directly rather than driving the
asyncio loop wrappers. The wrappers are thin and uncovered by design
(``# pragma: no cover``) ; their behaviour is captured by exercising
the bodies under explicit DB states.

Also covers :
- ``ha_password_load_failures_total`` increments on ``decrypt_fail``.
- ``cluster_rpc_latency_seconds`` observed on the master-local path
  of ``ha_password_hmac``.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest_asyncio
from api.app import cluster_ha_loops as loops
from api.app import metrics as _m
from api.app.database import async_session
from sqlalchemy import text

_TEST_NODE_UUID = "0123456789abcdef0123456789abcdef"


async def _insert_node(
    *,
    node_uuid: str,
    source_ip: str = "10.0.0.1",
    ha_state: str = "joining",
    quarantine_secs: int = 60,
    joined_offset_secs: int = 0,
    heartbeat_offset_secs: int | None = None,
):
    """Insert a vault_cluster_nodes row with explicit timing offsets.

    ``joined_offset_secs`` is subtracted from NOW() (positive = older
    row). ``heartbeat_offset_secs`` is subtracted from NOW() (positive
    = staler heartbeat). ``None`` leaves last_heartbeat NULL.
    """
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
                "    NOW() - make_interval(secs => :jo), "
                "    '1.0.0-beta', 'fpr', NOW() + INTERVAL '30 days', "
                "    CASE WHEN CAST(:hb AS INT) IS NULL THEN NULL ELSE "
                "         NOW() - make_interval(secs => CAST(:hb AS INT)) END"
                ")"
            ),
            {
                "u": node_uuid,
                "ip": source_ip,
                "s": ha_state,
                "qs": quarantine_secs,
                "jo": joined_offset_secs,
                "hb": heartbeat_offset_secs,
            },
        )
        await db.commit()


async def _get_state(node_uuid: str) -> str | None:
    async with async_session() as db:
        r = await db.execute(
            text("SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        row = r.fetchone()
        return row.ha_state if row else None


async def _get_address_and_renewal(node_uuid: str):
    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT host(source_ip) AS source_ip, force_renew_at "
                "FROM vault_cluster_nodes WHERE node_uuid = :u"
            ),
            {"u": node_uuid},
        )
        return result.fetchone()


async def _wipe_nodes():
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.commit()


@pytest_asyncio.fixture
async def _wipe():
    await _wipe_nodes()
    yield
    await _wipe_nodes()


# ---------------------------------------------------------------------------
# State machine body
# ---------------------------------------------------------------------------


async def test_state_machine_promotes_on_fresh_heartbeat(setup_db, _wipe):
    """joining + quarantine elapsed + fresh heartbeat -> secondary."""
    await _insert_node(
        node_uuid="aaaa" * 8,
        quarantine_secs=-10,  # already elapsed
        heartbeat_offset_secs=1,  # heartbeat 1s ago
    )
    before = _m.cluster_state_transitions.labels(
        from_state="joining", to_state="secondary"
    )._value.get()
    async with async_session() as db:
        n = await loops._state_machine_body(db)
    assert n == 1
    assert await _get_state("aaaa" * 8) == "secondary"
    after = _m.cluster_state_transitions.labels(
        from_state="joining", to_state="secondary"
    )._value.get()
    assert after == before + 1


async def test_state_machine_keeps_joining_in_quarantine(setup_db, _wipe):
    """quarantine_until still in the future -> stays joining."""
    await _insert_node(
        node_uuid="bbbb" * 8,
        quarantine_secs=60,  # 60s in the future
        heartbeat_offset_secs=1,
    )
    async with async_session() as db:
        n = await loops._state_machine_body(db)
    assert n == 0
    assert await _get_state("bbbb" * 8) == "joining"


async def test_state_machine_keeps_joining_when_heartbeat_stale(setup_db, _wipe):
    """quarantine elapsed but heartbeat stale (> 3x interval) -> stays joining.

    A node that crashed mid-quarantine should not be promoted on the
    strength of a window elapse alone.
    """
    from api.app.config import settings as _s

    # Stale by 5x interval -- well past the 3x liveness window.
    stale = _s.cluster_heartbeat_interval_secs * 5
    await _insert_node(
        node_uuid="cccc" * 8,
        quarantine_secs=-10,
        heartbeat_offset_secs=stale,
    )
    async with async_session() as db:
        n = await loops._state_machine_body(db)
    assert n == 0
    assert await _get_state("cccc" * 8) == "joining"


async def test_state_machine_keeps_joining_with_null_heartbeat(setup_db, _wipe):
    """quarantine elapsed but last_heartbeat IS NULL -> stays joining."""
    await _insert_node(
        node_uuid="dddd" * 8,
        quarantine_secs=-10,
        heartbeat_offset_secs=None,
    )
    async with async_session() as db:
        n = await loops._state_machine_body(db)
    assert n == 0
    assert await _get_state("dddd" * 8) == "joining"


async def test_state_machine_ignores_non_joining_states(setup_db, _wipe):
    """secondary/primary/draining/evicted rows are untouched."""
    await _insert_node(
        node_uuid="eeee" * 8,
        ha_state="secondary",
        quarantine_secs=-10,
        heartbeat_offset_secs=1,
    )
    async with async_session() as db:
        n = await loops._state_machine_body(db)
    assert n == 0
    assert await _get_state("eeee" * 8) == "secondary"


async def test_state_machine_batches_multiple_rows(setup_db, _wipe):
    """Two eligible rows in one tick -> both promoted, counter += 2."""
    await _insert_node(
        node_uuid="ffff" * 8,
        source_ip="10.0.0.1",
        quarantine_secs=-10,
        heartbeat_offset_secs=1,
    )
    await _insert_node(
        node_uuid="9999" * 8,
        source_ip="10.0.0.1",
        quarantine_secs=-10,
        heartbeat_offset_secs=1,
    )
    before = _m.cluster_state_transitions.labels(
        from_state="joining", to_state="secondary"
    )._value.get()
    async with async_session() as db:
        n = await loops._state_machine_body(db)
    assert n == 2
    after = _m.cluster_state_transitions.labels(
        from_state="joining", to_state="secondary"
    )._value.get()
    assert after == before + 2


# ---------------------------------------------------------------------------
# Reaper body
# ---------------------------------------------------------------------------


async def test_reaper_purges_orphan_joining(setup_db, _wipe):
    """joining row older than ttl -> deleted."""
    from api.app.config import settings as _s

    older = _s.cluster_joining_orphan_ttl_secs + 5
    await _insert_node(
        node_uuid="8888" * 8,
        ha_state="joining",
        joined_offset_secs=older,
    )
    before = _m.cluster_nodes_reaped.labels(reason="joining_orphan")._value.get()
    async with async_session() as db:
        n = await loops._reaper_body(db)
    assert n == 1
    assert await _get_state("8888" * 8) is None
    after = _m.cluster_nodes_reaped.labels(reason="joining_orphan")._value.get()
    assert after == before + 1


async def test_reaper_preserves_fresh_joining(setup_db, _wipe):
    """joining row younger than ttl -> preserved."""
    await _insert_node(
        node_uuid="7777" * 8,
        ha_state="joining",
        joined_offset_secs=1,
    )
    async with async_session() as db:
        n = await loops._reaper_body(db)
    assert n == 0
    assert await _get_state("7777" * 8) == "joining"


async def test_reaper_preserves_secondary_even_if_old(setup_db, _wipe):
    """Only ha_state='joining' rows are reaped, never secondary/primary."""
    await _insert_node(
        node_uuid="6666" * 8,
        ha_state="secondary",
        joined_offset_secs=3600,  # 1h ago
    )
    async with async_session() as db:
        n = await loops._reaper_body(db)
    assert n == 0
    assert await _get_state("6666" * 8) == "secondary"


# ---------------------------------------------------------------------------
# Heartbeat body
# ---------------------------------------------------------------------------


async def test_heartbeat_touches_existing_row(setup_db, _wipe):
    """Existing row -> last_heartbeat bumped to NOW()."""
    node_uuid = "5555" * 8
    await _insert_node(
        node_uuid=node_uuid,
        ha_state="secondary",
        heartbeat_offset_secs=120,  # 2 min ago
    )
    async with async_session() as db:
        ok = await loops._heartbeat_body(db, node_uuid)
    assert ok is True

    async with async_session() as db:
        r = await db.execute(
            text("SELECT last_heartbeat FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        row = r.fetchone()
    assert row.last_heartbeat is not None
    # Within 5s of now -- generous window for slow test runs.
    delta = datetime.now(timezone.utc) - row.last_heartbeat
    assert delta < timedelta(seconds=5)


async def test_heartbeat_noop_when_row_absent(setup_db, _wipe):
    """No row for our node_uuid (pre-cluster) -> returns False, no error."""
    async with async_session() as db:
        ok = await loops._heartbeat_body(db, "abcd" * 8)
    assert ok is False


async def test_heartbeat_reconciles_configured_advertised_ip(
    setup_db, _wipe, monkeypatch
):
    """A legacy init placeholder self-heals and requests a matching cert."""
    node_uuid = "feed" * 8
    await _insert_node(
        node_uuid=node_uuid,
        source_ip="192.0.2.1",
        ha_state="secondary",
    )
    monkeypatch.setattr(loops.settings, "cluster_advertise_ip", "10.0.0.1")
    from api.app import cluster_cert_renewal

    wake_renewal = Mock()
    monkeypatch.setattr(cluster_cert_renewal, "request_renewal", wake_renewal)

    async with async_session() as db:
        assert await loops._heartbeat_body(db, node_uuid) is True
        await db.commit()

    row = await _get_address_and_renewal(node_uuid)
    assert row.source_ip == "10.0.0.1"
    assert row.force_renew_at is not None
    wake_renewal.assert_called_once_with()


async def test_heartbeat_address_conflict_does_not_break_liveness(
    setup_db, _wipe, monkeypatch
):
    """A duplicate installer address is isolated without rolling back heartbeat."""
    node_uuid = "cafe" * 8
    other_uuid = "beef" * 8
    await _insert_node(
        node_uuid=node_uuid,
        source_ip="192.0.2.1",
        ha_state="secondary",
        heartbeat_offset_secs=120,
    )
    await _insert_node(
        node_uuid=other_uuid,
        source_ip="10.0.0.1",
        ha_state="secondary",
    )
    monkeypatch.setattr(loops.settings, "cluster_advertise_ip", "10.0.0.1")
    from api.app import cluster_cert_renewal

    wake_renewal = Mock()
    monkeypatch.setattr(cluster_cert_renewal, "request_renewal", wake_renewal)

    async with async_session() as db:
        assert await loops._heartbeat_body(db, node_uuid) is True
        await db.commit()

    row = await _get_address_and_renewal(node_uuid)
    assert row.source_ip == "192.0.2.1"
    assert row.force_renew_at is None
    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) AS age "
                "FROM vault_cluster_nodes WHERE node_uuid = :u"
            ),
            {"u": node_uuid},
        )
        assert float(result.scalar_one()) < 5
    wake_renewal.assert_not_called()


# ---------------------------------------------------------------------------
# ha_password_load_failures counter wiring
# ---------------------------------------------------------------------------


async def test_ha_password_load_failure_bumps_counter(setup_db, admin_token):
    """A corrupt vault_cluster_config row triggers decrypt_fail counter."""
    from api.app import ha_password as hp

    # Wipe + plant a bogus row that will fail AES-GCM decrypt.
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = 'ha_password_encrypted'")
        )
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('ha_password_encrypted', :v)"
            ),
            {"v": "00" * 64},  # garbage hex blob
        )
        await db.commit()

    before = _m.ha_password_load_failures.labels(reason="decrypt_fail")._value.get()
    async with async_session() as db:
        ok = await hp.load_ha_password_into_ram(db)
    assert ok is False
    after = _m.ha_password_load_failures.labels(reason="decrypt_fail")._value.get()
    assert after == before + 1

    # Clean up so subsequent tests are not poisoned.
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = 'ha_password_encrypted'")
        )
        await db.commit()


# ---------------------------------------------------------------------------
# cluster_rpc_latency histogram wiring
# ---------------------------------------------------------------------------


def _hist_count(histogram, **labels) -> int:
    """Return total observation count for a labelled Histogram child.

    prometheus_client stores per-bucket counts non-cumulatively in
    ``_buckets`` ; the cumulative +Inf row is only synthesised in
    ``collect()`` output. Total observations = sum of all bucket
    counters.
    """
    child = histogram.labels(**labels)
    return int(sum(b.get() for b in child._buckets))


async def test_cluster_rpc_latency_observed_on_ha_password_hmac(setup_db, admin_token):
    """ha_password_hmac() observes one sample per call (master path)."""
    from api.app import ha_password as hp
    from api.app.vault_state import vault as vs

    # Seed an ha_password in RAM so the master-local path runs.
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 32, actor="test")
        await db.commit()

    count_before = _hist_count(_m.cluster_rpc_latency, op="ha_password_hmac")

    _ = await vs.ha_password_hmac(b"slice-7-test-message")

    count_after = _hist_count(_m.cluster_rpc_latency, op="ha_password_hmac")

    assert count_after == count_before + 1

    # Tidy up so the wrapped buffer does not leak to later tests.
    hp.clear()
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = 'ha_password_encrypted'")
        )
        await db.commit()
