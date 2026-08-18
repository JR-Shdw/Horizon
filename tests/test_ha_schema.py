"""schema additions structural tests.

Pure DDL coverage : this migration ships no application code, so the only
thing to verify is that schema.sql produces the table/columns/constraint
shape expected by the design (docs/HA-CLUSTER.md section 6).
"""

import os
from pathlib import Path

import asyncpg
import pytest
from api.app.database import async_session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

HA_STATES_VALID = ("unjoined", "joining", "quarantine", "secondary", "primary")


# --- vault_cluster_config table --------------------------------------------


async def test_vault_cluster_config_table_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_name = 'vault_cluster_config'"
            )
        )
        assert r.fetchone() is not None, "vault_cluster_config table missing"


async def test_vault_cluster_config_columns(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT column_name, data_type, is_nullable "
                "FROM information_schema.columns "
                "WHERE table_name = 'vault_cluster_config' "
                "ORDER BY ordinal_position"
            )
        )
        rows = {row[0]: (row[1], row[2]) for row in r.fetchall()}
    assert rows == {
        "key": ("text", "NO"),
        "value": ("text", "NO"),
    }


async def test_vault_cluster_config_primary_key_on_key(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT a.attname "
                "FROM pg_index i "
                "JOIN pg_attribute a "
                "  ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                "WHERE i.indrelid = 'vault_cluster_config'::regclass "
                "  AND i.indisprimary"
            )
        )
        pk_cols = [row[0] for row in r.fetchall()]
    assert pk_cols == ["key"]


async def test_vault_cluster_config_roundtrip(setup_db):
    """INSERT + SELECT of an expected cluster_config key."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_config"))
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('ha_enabled', 'false')"
            )
        )
        await db.commit()
        r = await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'ha_enabled'")
        )
        assert r.scalar() == "false"
        await db.execute(text("DELETE FROM vault_cluster_config"))
        await db.commit()


async def test_vault_cluster_config_pk_uniqueness(setup_db):
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_config"))
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('cluster_id', 'abc')"
            )
        )
        await db.commit()
        with pytest.raises(IntegrityError):
            await db.execute(
                text(
                    "INSERT INTO vault_cluster_config (key, value) "
                    "VALUES ('cluster_id', 'def')"
                )
            )
            await db.commit()
        await db.rollback()
        await db.execute(text("DELETE FROM vault_cluster_config"))
        await db.commit()


async def test_vault_cluster_config_value_not_null(setup_db):
    async with async_session() as db:
        with pytest.raises(IntegrityError):
            await db.execute(
                text("INSERT INTO vault_cluster_config (key, value) VALUES ('x', NULL)")
            )
            await db.commit()
        await db.rollback()


# --- vault_workers: new columns ----------------------------------


async def test_vault_workers_new_columns_present(setup_db):
    expected = {
        "node_uuid": ("text", "YES"),
        "ha_state": ("text", "YES"),
        "quarantine_until": ("timestamp with time zone", "YES"),
    }
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT column_name, data_type, is_nullable "
                "FROM information_schema.columns "
                "WHERE table_name = 'vault_workers' "
                "  AND column_name IN ('node_uuid', 'ha_state', 'quarantine_until')"
            )
        )
        actual = {row[0]: (row[1], row[2]) for row in r.fetchall()}
    assert actual == expected


async def test_vault_workers_ha_state_check_constraint_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "WHERE conname = 'vault_workers_ha_state_check'"
            )
        )
        assert r.fetchone() is not None, "CHECK vault_workers_ha_state_check missing"


@pytest.mark.parametrize("state", HA_STATES_VALID)
async def test_vault_workers_ha_state_accepts_valid_value(setup_db, state):
    """Each of the 5 design states must be accepted by the CHECK."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70013"))
        await db.execute(
            text(
                "INSERT INTO vault_workers (hostname, pid, ha_state) "
                "VALUES ('ha-test', 70013, :st)"
            ),
            {"st": state},
        )
        await db.commit()
        r = await db.execute(
            text("SELECT ha_state FROM vault_workers WHERE pid = 70013")
        )
        assert r.scalar() == state
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70013"))
        await db.commit()


async def test_vault_workers_ha_state_accepts_null(setup_db):
    """Single-node deploys leave ha_state NULL ; CHECK must allow it."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70014"))
        await db.execute(
            text(
                "INSERT INTO vault_workers (hostname, pid, ha_state) "
                "VALUES ('ha-test', 70014, NULL)"
            )
        )
        await db.commit()
        r = await db.execute(
            text("SELECT ha_state FROM vault_workers WHERE pid = 70014")
        )
        assert r.scalar() is None
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70014"))
        await db.commit()


async def test_vault_workers_ha_state_rejects_invalid_value(setup_db):
    async with async_session() as db:
        with pytest.raises(IntegrityError):
            await db.execute(
                text(
                    "INSERT INTO vault_workers (hostname, pid, ha_state) "
                    "VALUES ('ha-test', 70015, 'bogus')"
                )
            )
            await db.commit()
        await db.rollback()


async def test_vault_workers_default_insert_without_ha_columns(setup_db):
    """Backward compat: a INSERT (no HA columns)
    still succeeds. ha_state must default to NULL."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70016"))
        await db.execute(
            text("INSERT INTO vault_workers (hostname, pid) VALUES ('ha-test', 70016)")
        )
        await db.commit()
        r = await db.execute(
            text(
                "SELECT worker_state, node_uuid, ha_state, quarantine_until "
                "FROM vault_workers WHERE pid = 70016"
            )
        )
        row = r.fetchone()
        assert row.worker_state == "sealed"
        assert row.node_uuid is None
        assert row.ha_state is None
        assert row.quarantine_until is None
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70016"))
        await db.commit()


async def test_vault_workers_quarantine_until_timestamptz_roundtrip(setup_db):
    """quarantine_until must store TIMESTAMPTZ-shape values."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70017"))
        await db.execute(
            text(
                "INSERT INTO vault_workers (hostname, pid, quarantine_until) "
                "VALUES ('ha-test', 70017, NOW() + INTERVAL '15 seconds')"
            )
        )
        await db.commit()
        r = await db.execute(
            text(
                "SELECT quarantine_until > NOW(), "
                "       quarantine_until < NOW() + INTERVAL '20 seconds' "
                "FROM vault_workers WHERE pid = 70017"
            )
        )
        future, bounded = r.fetchone()
        assert future is True
        assert bounded is True
        await db.execute(text("DELETE FROM vault_workers WHERE pid = 70017"))
        await db.commit()


# --- Indexes ---------------------------------------------------------------


async def test_vault_workers_ha_indexes_present(setup_db):
    expected = {"idx_vault_workers_node_uuid", "idx_vault_workers_ha_state"}
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = 'public' "
                "  AND tablename = 'vault_workers' "
                "  AND indexname = ANY(:names)"
            ),
            {"names": list(expected)},
        )
        actual = {row[0] for row in r.fetchall()}
    assert actual == expected


# --- Idempotence -----------------------------------------------------------


async def test_schema_sql_is_idempotent(setup_db):
    """Re-applying schema.sql must not fail and must not duplicate the
    CHECK constraint or the indexes. Uses asyncpg directly because
    SQLAlchemy text() can't drive multi-statement scripts with DO blocks
    (the conftest applies schema.sql via the same path)."""
    schema_sql = (Path(__file__).parent.parent / "schema.sql").read_text()
    raw_dsn = os.environ["RHORIZON_DATABASE_URL"].replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    conn = await asyncpg.connect(raw_dsn)
    try:
        await conn.execute(schema_sql)
        check_count = await conn.fetchval(
            "SELECT COUNT(*) FROM pg_constraint "
            "WHERE conname = 'vault_workers_ha_state_check'"
        )
        assert check_count == 1
        index_count = await conn.fetchval(
            "SELECT COUNT(*) FROM pg_indexes "
            "WHERE indexname IN "
            "  ('idx_vault_workers_node_uuid', 'idx_vault_workers_ha_state')"
        )
        assert index_count == 2
    finally:
        await conn.close()
