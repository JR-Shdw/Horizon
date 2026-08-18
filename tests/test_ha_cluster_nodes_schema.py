# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""vault_cluster_nodes schema DDL coverage.

This migration introduces a dedicated inter-host HA membership table.
These tests pin the column shapes, the PK, the UNIQUE index, the
partial index and the CHECK constraint so a future migration cannot
silently break the contract the route layer assumes.
"""

from datetime import datetime, timedelta, timezone

import pytest
from api.app.cluster_nodes import SourceIpRebindError, insert_joining_node
from api.app.database import async_session
from sqlalchemy import text


async def test_table_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_name = 'vault_cluster_nodes'"
            )
        )
        assert r.fetchone() is not None, "vault_cluster_nodes table missing"


async def test_node_uuid_is_pk(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT a.attname "
                "FROM pg_index i "
                "JOIN pg_attribute a "
                "  ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                "WHERE i.indrelid = 'vault_cluster_nodes'::regclass "
                "  AND i.indisprimary"
            )
        )
        cols = [row.attname for row in r.fetchall()]
        assert cols == ["node_uuid"], f"PK should be node_uuid, got {cols}"


async def test_source_ip_is_inet_type(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_name = 'vault_cluster_nodes' "
                "  AND column_name = 'source_ip'"
            )
        )
        row = r.fetchone()
        assert row is not None
        assert row.data_type == "inet"
        assert row.is_nullable == "NO"


async def test_all_columns_present(setup_db):
    expected = {
        "node_uuid",
        "source_ip",
        "ha_state",
        "quarantine_until",
        "joined_at",
        "cluster_version",
        "cert_fingerprint",
        "cert_not_after",
        "last_heartbeat",
    }
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'vault_cluster_nodes'"
            )
        )
        cols = {row.column_name for row in r.fetchall()}
        assert expected.issubset(cols), f"missing columns: {expected - cols}"


async def test_uuid_ip_unique_index_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'vault_cluster_nodes_uuid_ip'"
            )
        )
        row = r.fetchone()
        assert row is not None, "vault_cluster_nodes_uuid_ip missing"
        idx = row.indexdef.lower()
        assert "unique" in idx
        assert "node_uuid" in idx and "source_ip" in idx


async def test_active_ip_partial_unique_index_exists(setup_db):
    """Faille 12 guard: a partial UNIQUE on source_ip alone, scoped to
    non-evicted rows. node_uuid must NOT be in it (that would be the
    redundant composite, which enforces nothing beyond the PK)."""
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'vault_cluster_nodes_active_ip'"
            )
        )
        row = r.fetchone()
        assert row is not None, "vault_cluster_nodes_active_ip missing"
        idx = row.indexdef.lower()
        assert "unique" in idx
        assert "source_ip" in idx
        assert "where" in idx and "evicted" in idx
        assert "node_uuid" not in idx


async def test_single_primary_partial_unique_index_exists(setup_db):
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE indexname = 'vault_cluster_nodes_single_primary'"
                )
            )
        ).fetchone()
        assert row is not None, "vault_cluster_nodes_single_primary missing"
        idx = row.indexdef.lower()
        assert "unique" in idx
        assert "ha_state" in idx
        assert "where" in idx and "primary" in idx


async def test_single_primary_index_blocks_double_primary(setup_db):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "node_uuid, source_ip, ha_state, cluster_version, "
                "cert_fingerprint, cert_not_after"
                ") VALUES ("
                "'primary-a', '10.77.1.1', 'primary', '1.0.0', 'fpr-a', NOW()"
                ")"
            )
        )
        with pytest.raises(Exception, match="vault_cluster_nodes_single_primary"):
            await db.execute(
                text(
                    "INSERT INTO vault_cluster_nodes ("
                    "node_uuid, source_ip, ha_state, cluster_version, "
                    "cert_fingerprint, cert_not_after"
                    ") VALUES ("
                    "'primary-b', '10.77.1.2', 'primary', '1.0.0', 'fpr-b', NOW()"
                    ")"
                )
            )
        await db.rollback()


async def test_faille12_active_ip_blocks_rebind(setup_db):
    """A different node_uuid claiming an IP an active node already holds is
    rejected at INSERT -- SourceIpRebindError, not the generic IntegrityError."""
    not_after = datetime.now(timezone.utc) + timedelta(days=30)
    async with async_session() as db:
        await insert_joining_node(
            db,
            node_uuid="faille12-a",
            source_ip="10.77.0.5",
            cluster_version="1.0.0",
            cert_fingerprint="fpr-a",
            cert_not_after=not_after,
            quarantine_secs=60,
        )
        with pytest.raises(SourceIpRebindError):
            await insert_joining_node(
                db,
                node_uuid="faille12-b",
                source_ip="10.77.0.5",
                cluster_version="1.0.0",
                cert_fingerprint="fpr-b",
                cert_not_after=not_after,
                quarantine_secs=60,
            )
        await db.rollback()


async def test_faille12_evicted_row_releases_ip(setup_db):
    """Once a node is evicted, its source_ip is free for a fresh node_uuid
    (the partial WHERE clause drops evicted rows out of the unique scope)."""
    not_after = datetime.now(timezone.utc) + timedelta(days=30)
    async with async_session() as db:
        await insert_joining_node(
            db,
            node_uuid="faille12-evict-a",
            source_ip="10.77.0.9",
            cluster_version="1.0.0",
            cert_fingerprint="fpr-a",
            cert_not_after=not_after,
            quarantine_secs=60,
        )
        await db.execute(
            text(
                "UPDATE vault_cluster_nodes SET ha_state = 'evicted' "
                "WHERE node_uuid = 'faille12-evict-a'"
            )
        )
        # Fresh uuid now claims the released IP -- no exception.
        await insert_joining_node(
            db,
            node_uuid="faille12-evict-b",
            source_ip="10.77.0.9",
            cluster_version="1.0.0",
            cert_fingerprint="fpr-b",
            cert_not_after=not_after,
            quarantine_secs=60,
        )
        await db.rollback()


async def test_ha_state_partial_index_excludes_evicted(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'vault_cluster_nodes_ha_state'"
            )
        )
        row = r.fetchone()
        assert row is not None, "vault_cluster_nodes_ha_state index missing"
        idx = row.indexdef.lower()
        assert "where" in idx
        assert "evicted" in idx


async def test_ha_state_check_constraint(setup_db):
    """Insert with an invalid ha_state must fail the CHECK constraint."""
    async with async_session() as db:
        try:
            await db.execute(
                text(
                    "INSERT INTO vault_cluster_nodes ("
                    "    node_uuid, source_ip, ha_state, cluster_version,"
                    "    cert_fingerprint, cert_not_after"
                    ") VALUES ("
                    "    'test-uuid-bad', CAST('10.0.0.1' AS INET),"
                    "    'not_a_valid_state', '1.0.0', 'fpr', NOW()"
                    ")"
                )
            )
            await db.commit()
            assert False, "expected CHECK violation"
        except Exception as exc:
            assert "check" in str(exc).lower() or "constraint" in str(exc).lower()
        finally:
            await db.rollback()


async def test_inet_round_trip(setup_db):
    """INET stores both IPv4 and IPv6 and round-trips back as TEXT cleanly."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, cluster_version,"
                "    cert_fingerprint, cert_not_after"
                ") VALUES ("
                "    'test-uuid-v4', CAST('10.0.0.1' AS INET),"
                "    'joining', '1.0.0', 'fpr1', NOW() + INTERVAL '30 days'"
                "), ("
                "    'test-uuid-v6', CAST('2001:db8::42' AS INET),"
                "    'joining', '1.0.0', 'fpr2', NOW() + INTERVAL '30 days'"
                ")"
            )
        )
        r = await db.execute(
            text(
                "SELECT node_uuid, host(source_ip) AS ip "
                "FROM vault_cluster_nodes "
                "WHERE node_uuid IN ('test-uuid-v4', 'test-uuid-v6') "
                "ORDER BY node_uuid"
            )
        )
        rows = r.fetchall()
        assert len(rows) == 2
        assert rows[0].ip == "10.0.0.1"
        assert rows[1].ip == "2001:db8::42"
        await db.execute(
            text(
                "DELETE FROM vault_cluster_nodes "
                "WHERE node_uuid IN ('test-uuid-v4', 'test-uuid-v6')"
            )
        )
        await db.commit()
