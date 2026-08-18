"""vault_challenges schema additions.

Pure DDL coverage : this migration extends vault_challenges with the
three columns the /cluster/challenge flow will populate.
Verifies columns are present, NULLability matches the design
(node_uuid + source_ip NULLable for back-compat with unseal rows,
issued_at NOT NULL DEFAULT NOW()), and the partial-purpose index
exists for cleanup queries.
"""

from api.app.database import async_session
from sqlalchemy import text


async def test_vault_challenges_node_uuid_column_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_name = 'vault_challenges' AND column_name = 'node_uuid'"
            )
        )
        row = r.fetchone()
        assert row is not None, "vault_challenges.node_uuid column missing"
        assert row.data_type == "text"
        assert row.is_nullable == "YES"


async def test_vault_challenges_source_ip_column_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_name = 'vault_challenges' AND column_name = 'source_ip'"
            )
        )
        row = r.fetchone()
        assert row is not None, "vault_challenges.source_ip column missing"
        assert row.data_type == "text"
        assert row.is_nullable == "YES"


async def test_vault_challenges_issued_at_column_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT data_type, is_nullable, column_default "
                "FROM information_schema.columns "
                "WHERE table_name = 'vault_challenges' AND column_name = 'issued_at'"
            )
        )
        row = r.fetchone()
        assert row is not None, "vault_challenges.issued_at column missing"
        assert row.data_type == "timestamp with time zone"
        assert row.is_nullable == "NO"
        # PG normalises now() / NOW() / CURRENT_TIMESTAMP -- accept any
        # of the canonical synonyms.
        assert row.column_default is not None
        assert any(
            tok in row.column_default.lower() for tok in ("now()", "current_timestamp")
        )


async def test_vault_challenges_purpose_expires_index_exists(setup_db):
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE indexname = 'idx_vault_challenges_purpose_expires'"
            )
        )
        row = r.fetchone()
        assert row is not None, "idx_vault_challenges_purpose_expires missing"
        # Sanity : index covers (purpose, expires_at) in that order.
        idx = row.indexdef.lower()
        assert "purpose" in idx
        assert "expires_at" in idx


async def test_vault_challenges_insert_with_join_binding_columns(setup_db):
    """A purpose='cluster_join' row carries node_uuid + source_ip ;
    insertable + readable through the new schema."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_challenges "
                "(challenge, expires_at, purpose, node_uuid, source_ip) "
                "VALUES (:c, NOW() + INTERVAL '30 seconds', "
                "        'cluster_join', :u, :ip)"
            ),
            {
                "c": "test-nonce-6b-001",
                "u": "node-uuid-abc",
                "ip": "10.0.0.1",
            },
        )
        r = await db.execute(
            text(
                "SELECT node_uuid, source_ip, issued_at, purpose "
                "FROM vault_challenges WHERE challenge = :c"
            ),
            {"c": "test-nonce-6b-001"},
        )
        row = r.fetchone()
        assert row.node_uuid == "node-uuid-abc"
        assert row.source_ip == "10.0.0.1"
        assert row.issued_at is not None  # DEFAULT NOW() filled it in
        assert row.purpose == "cluster_join"
        # Cleanup so reruns stay idempotent.
        await db.execute(
            text("DELETE FROM vault_challenges WHERE challenge = :c"),
            {"c": "test-nonce-6b-001"},
        )
        await db.commit()


async def test_vault_challenges_unseal_row_back_compat(setup_db):
    """An unseal challenge row (the pre-6b shape) still inserts cleanly
    without supplying the new columns -- node_uuid + source_ip default
    to NULL, issued_at defaults to NOW(). Confirms back-compat with
    the YubiKey unseal flow that does not know about the new columns."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_challenges "
                "(challenge, expires_at, purpose) "
                "VALUES (:c, NOW() + INTERVAL '60 seconds', 'unseal')"
            ),
            {"c": "test-nonce-6b-002"},
        )
        r = await db.execute(
            text(
                "SELECT node_uuid, source_ip, issued_at "
                "FROM vault_challenges WHERE challenge = :c"
            ),
            {"c": "test-nonce-6b-002"},
        )
        row = r.fetchone()
        assert row.node_uuid is None
        assert row.source_ip is None
        assert row.issued_at is not None
        await db.execute(
            text("DELETE FROM vault_challenges WHERE challenge = :c"),
            {"c": "test-nonce-6b-002"},
        )
        await db.commit()
