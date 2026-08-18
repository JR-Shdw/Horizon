"""One custodian pool per host means one generation row per host.

Custodians are reached over Unix sockets, so a pool cannot be shared. Before
this scoping, a cluster sharing one database had one generation row: the node
that migrated held the shares, and every other node read that row, tried to
unseal its own empty slots, and failed to start -- with no master password
recovery. These tests pin the row to its owner.
"""

import pytest
import pytest_asyncio
from api.app import custody_generation as cg
from api.app.database import async_session
from sqlalchemy import text


@pytest_asyncio.fixture
async def clean_state(setup_db):
    async def _wipe():
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key LIKE :pattern"),
                {"pattern": f"{cg.CUSTODY_STATE_CONFIG_KEY}%"},
            )
            await db.commit()

    await _wipe()
    yield
    await _wipe()


def _state(generation=7, threshold=2, slots=3):
    return cg.CustodyGenerationState(
        version=cg.CUSTODY_STATE_VERSION,
        phase="stable",
        active_generation=generation,
        target_generation=None,
        previous_generation=None,
        threshold=threshold,
        slots=slots,
    )


async def _rows() -> dict[str, str]:
    async with async_session() as db:
        result = await db.execute(
            text("SELECT key, value FROM vault_config WHERE key LIKE :pattern"),
            {"pattern": f"{cg.CUSTODY_STATE_CONFIG_KEY}%"},
        )
        return {row.key: row.value for row in result.fetchall()}


def test_the_key_carries_the_node_identity():
    assert cg.custody_state_key("node-a") == (f"{cg.CUSTODY_STATE_CONFIG_KEY}:node-a")
    # Two hosts never collide, which is the whole point.
    assert cg.custody_state_key("node-a") != cg.custody_state_key("node-b")


def test_a_deployment_without_a_node_uuid_is_its_own_single_scope(monkeypatch):
    # Not clustered, so one scope is the correct answer rather than an error.
    monkeypatch.setattr(cg, "_node_scope", lambda: "standalone")
    assert cg.custody_state_key() == f"{cg.CUSTODY_STATE_CONFIG_KEY}:standalone"


@pytest.mark.asyncio
async def test_each_node_owns_its_own_generation(clean_state, monkeypatch):
    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    async with async_session() as db:
        await cg._write(db, _state(generation=7))
        await db.commit()

    # A second node reads its OWN row, which does not exist yet: it must start
    # empty and migrate its own pool, never inherit shares it does not hold.
    monkeypatch.setattr(cg, "_node_scope", lambda: "node-b")
    async with async_session() as db:
        assert (await cg.get_custody_generation_state(db)).active_generation is None
        await cg._write(db, _state(generation=3))
        await db.commit()

    rows = await _rows()
    assert set(rows) == {
        f"{cg.CUSTODY_STATE_CONFIG_KEY}:node-a",
        f"{cg.CUSTODY_STATE_CONFIG_KEY}:node-b",
    }

    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    async with async_session() as db:
        assert (await cg.get_custody_generation_state(db)).active_generation == 7


@pytest.mark.asyncio
async def test_a_legacy_row_is_adopted_once_by_the_first_node_to_take_it(
    clean_state, monkeypatch
):
    # A single-host deployment upgrading into this scheme: its shares are held
    # by the only pool that ever existed, so that pool claims the row.
    async with async_session() as db:
        await db.execute(
            text("INSERT INTO vault_config (key, value) VALUES (:k, :v)"),
            {
                "k": cg.CUSTODY_STATE_CONFIG_KEY,
                "v": cg.encode_custody_generation_state(_state(generation=9)),
            },
        )
        await db.commit()

    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    async with async_session() as db:
        adopted = await cg._lock_and_read(db)
        await db.commit()
    assert adopted.active_generation == 9

    rows = await _rows()
    assert f"{cg.CUSTODY_STATE_CONFIG_KEY}:node-a" in rows
    # Removed in the same transaction, so a second node cannot also adopt it.
    assert cg.CUSTODY_STATE_CONFIG_KEY not in rows

    monkeypatch.setattr(cg, "_node_scope", lambda: "node-b")
    async with async_session() as db:
        assert (await cg._lock_and_read(db)).active_generation is None


@pytest.mark.asyncio
async def test_a_plain_read_sees_an_unadopted_legacy_row_without_claiming_it(
    clean_state, monkeypatch
):
    # Boot-time probes read this; they must not rewrite durable custody state.
    async with async_session() as db:
        await db.execute(
            text("INSERT INTO vault_config (key, value) VALUES (:k, :v)"),
            {
                "k": cg.CUSTODY_STATE_CONFIG_KEY,
                "v": cg.encode_custody_generation_state(_state(generation=5)),
            },
        )
        await db.commit()

    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    async with async_session() as db:
        assert (await cg.get_custody_generation_state(db)).active_generation == 5

    assert set(await _rows()) == {cg.CUSTODY_STATE_CONFIG_KEY}


@pytest.mark.asyncio
async def test_the_activation_decision_stays_global(clean_state, monkeypatch):
    # Sealing is an instruction about the VAULT, not about one pool: every node
    # must obey it, so this row is deliberately not scoped.
    monkeypatch.setattr(cg, "_node_scope", lambda: "node-a")
    async with async_session() as db:
        await cg.set_rust_custody_activation(db, unsealed=True)
        await db.commit()

    monkeypatch.setattr(cg, "_node_scope", lambda: "node-b")
    async with async_session() as db:
        assert await cg.get_rust_custody_activation(db) is True

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_config WHERE key = :k"),
            {"k": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
        )
        await db.commit()
