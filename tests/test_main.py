"""Tests for api/app/main.py - lifespan helpers in isolation.

Targets the global functions used by the FastAPI lifespan without running
the full lifespan (which starts background loops hard to isolate in a test).
Here we check `_apply_schema()`, which applies schema.sql at worker boot.
"""

from pathlib import Path
from unittest.mock import patch

import asyncpg
import pytest
from api.app import main


@pytest.mark.asyncio
async def test_apply_schema_with_existing_file(setup_db):
    """_apply_schema() applies schema.sql when the file exists.

    Patches the "/app/schema.sql" path (Docker path) to point at the real
    repo file. The SQL is idempotent (`IF NOT EXISTS`), so a second pass
    breaks nothing.
    """
    repo_root = Path(__file__).parent.parent
    real_schema = repo_root / "schema.sql"
    assert real_schema.exists()

    with patch.object(main, "Path", return_value=real_schema):
        await main._apply_schema()

    # Verify the key tables are present in the DB
    import os

    raw_dsn = os.environ["RHORIZON_DATABASE_URL"].replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    conn = await asyncpg.connect(raw_dsn)
    try:
        rows = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        )
        names = {r["tablename"] for r in rows}
        for required in ("vault_config", "vault_secrets", "vault_tokens"):
            assert required in names, f"{required} must exist after _apply_schema"
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_apply_schema_missing_file_warns_no_raise(setup_db, caplog):
    """_apply_schema() logs a warning if schema.sql is missing, without raising."""
    nonexistent = Path("/tmp/rhorizon-nonexistent-schema-xyz.sql")
    assert not nonexistent.exists()

    with patch.object(main, "Path", return_value=nonexistent):
        with caplog.at_level("WARNING", logger="rhorizon"):
            # Must not raise, the function logs and returns
            await main._apply_schema()

    assert any("schema.sql not found" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_apply_schema_migrates_untyped_group_principals(setup_db):
    """The deployed username-only table narrows token names to token UUIDs."""
    import os

    raw_dsn = os.environ["RHORIZON_DATABASE_URL"].replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    conn = await asyncpg.connect(raw_dsn)
    try:
        await conn.execute("DROP TABLE vault_group_members")
        await conn.execute("""
            CREATE TABLE vault_group_members (
                group_id UUID NOT NULL
                    REFERENCES vault_groups(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                added_at TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (group_id, username)
            )
        """)
        group_id = await conn.fetchval("""
            INSERT INTO vault_groups (name, permissions)
            VALUES ('migration-principals', '{}')
            RETURNING id
        """)
        token_id = await conn.fetchval("""
            INSERT INTO vault_tokens
                (name, token_hash, permissions, created_by)
            VALUES ('migration-token', 'migration-token-hash', '{}', 'test')
            RETURNING id
        """)
        await conn.executemany(
            "INSERT INTO vault_group_members (group_id, username) VALUES ($1, $2)",
            [
                (group_id, "migration-token"),
                (group_id, "migration-user"),
            ],
        )
    finally:
        await conn.close()

    repo_root = Path(__file__).parent.parent
    with patch.object(main, "Path", return_value=repo_root / "schema.sql"):
        await main._apply_schema()

    conn = await asyncpg.connect(raw_dsn)
    try:
        rows = await conn.fetch(
            """
            SELECT principal_type, external_id, token_id
            FROM vault_group_members
            WHERE group_id = $1
            ORDER BY principal_type
        """,
            group_id,
        )
        assert [dict(r) for r in rows] == [
            {
                "principal_type": "external",
                "external_id": "legacy:migration-user",
                "token_id": None,
            },
            {
                "principal_type": "token",
                "external_id": None,
                "token_id": token_id,
            },
        ]
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_namespace_migration_fails_closed_on_unmapped_secret(monkeypatch):
    """An incomplete namespace backfill must prevent application startup."""

    class FakeConnection:
        def __init__(self):
            self.fetchval_results = [
                "00000000-0000-0000-0000-000000000001",
                1,
            ]
            self.closed = False

        async def execute(self, *_args):
            return None

        async def fetchval(self, *_args):
            return self.fetchval_results.pop(0)

        async def close(self):
            self.closed = True

    conn = FakeConnection()

    async def fake_boot_connect():
        return conn

    monkeypatch.setattr(main, "_boot_connect", fake_boot_connect)

    with pytest.raises(RuntimeError, match="1 secret\\(s\\) unmapped"):
        await main._migrate_namespaces()

    assert conn.closed is True
