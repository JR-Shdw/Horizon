"""node_uuid boot logic tests.

Covers:
- format invariants (uuid4 hex, 32 lowercase chars)
- first-boot file creation (mode 0400, parent 0700, atomic write)
- concurrent first-boot: N workers sharing one volume converge on one uuid
- idempotent re-read across "restarts"
- corruption rejection (wrong length, non-hex, empty, non-file path)
- module-level cache (init + get)
- vault_workers row carries the node_uuid + COALESCE semantics on conflict
"""

import re
from pathlib import Path

import pytest
from api.app import node_uuid as nu
from api.app.cluster import WorkerState, register_worker, update_worker_state
from api.app.database import async_session
from sqlalchemy import text

_HEX_32 = re.compile(r"^[0-9a-f]{32}$")


@pytest.fixture(autouse=True)
def _reset_cache():
    nu._reset_for_tests()
    yield
    nu._reset_for_tests()


# --- format + first-boot creation -----------------------------------------


def test_first_boot_creates_file_with_hex32(tmp_path):
    target = tmp_path / "rhorizon" / "node-uuid"
    value = nu.load_or_create_node_uuid(target)
    assert target.is_file()
    assert _HEX_32.fullmatch(value)
    assert target.read_text(encoding="ascii") == value


def test_first_boot_file_mode_is_0400(tmp_path):
    target = tmp_path / "rhorizon" / "node-uuid"
    nu.load_or_create_node_uuid(target)
    mode = target.stat().st_mode & 0o777
    assert mode == 0o400, f"expected 0o400, got 0o{mode:o}"


def test_first_boot_parent_dir_mode_0700(tmp_path):
    target = tmp_path / "rhorizon" / "node-uuid"
    nu.load_or_create_node_uuid(target)
    parent_mode = target.parent.stat().st_mode & 0o777
    assert parent_mode == 0o700, f"expected 0o700, got 0o{parent_mode:o}"


def test_first_boot_no_temp_left(tmp_path):
    target = tmp_path / "rhorizon" / "node-uuid"
    nu.load_or_create_node_uuid(target)
    # the link()+unlink dance must leave no temp behind
    assert not list(target.parent.glob(".node-uuid.*.tmp"))


# --- idempotent reread -----------------------------------------------------


def test_subsequent_boot_returns_same_value(tmp_path):
    target = tmp_path / "node-uuid"
    first = nu.load_or_create_node_uuid(target)
    second = nu.load_or_create_node_uuid(target)
    third = nu.load_or_create_node_uuid(target)
    assert first == second == third


def test_reread_tolerates_trailing_newline(tmp_path):
    target = tmp_path / "node-uuid"
    target.write_text("0123456789abcdef0123456789abcdef\n", encoding="ascii")
    value = nu.load_or_create_node_uuid(target)
    assert value == "0123456789abcdef0123456789abcdef"


# --- corruption rejection --------------------------------------------------


def test_reject_uppercase_hex(tmp_path):
    target = tmp_path / "node-uuid"
    target.write_text("ABCDEF0123456789ABCDEF0123456789", encoding="ascii")
    with pytest.raises(nu.NodeUUIDError):
        nu.load_or_create_node_uuid(target)


def test_reject_too_short(tmp_path):
    target = tmp_path / "node-uuid"
    target.write_text("deadbeef", encoding="ascii")
    with pytest.raises(nu.NodeUUIDError):
        nu.load_or_create_node_uuid(target)


def test_reject_too_long(tmp_path):
    target = tmp_path / "node-uuid"
    target.write_text("0" * 64, encoding="ascii")
    with pytest.raises(nu.NodeUUIDError):
        nu.load_or_create_node_uuid(target)


def test_reject_non_hex_chars(tmp_path):
    target = tmp_path / "node-uuid"
    target.write_text("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", encoding="ascii")
    with pytest.raises(nu.NodeUUIDError):
        nu.load_or_create_node_uuid(target)


def test_reject_empty_file(tmp_path):
    target = tmp_path / "node-uuid"
    target.write_text("", encoding="ascii")
    with pytest.raises(nu.NodeUUIDError):
        nu.load_or_create_node_uuid(target)


def test_reject_path_is_directory(tmp_path):
    target = tmp_path / "node-uuid"
    target.mkdir()
    with pytest.raises(nu.NodeUUIDError):
        nu.load_or_create_node_uuid(target)


# --- concurrent first-boot (N workers share one volume) -------------------


def test_orphan_temp_does_not_block_boot(tmp_path):
    """A temp left by a crashed peer (unique name, never the final path)
    is irrelevant: mkstemp picks a fresh name, link() lands the identity."""
    target = tmp_path / "rhorizon" / "node-uuid"
    target.parent.mkdir(parents=True)
    (target.parent / ".node-uuid.99999.tmp").write_text("partial", encoding="ascii")
    value = nu.load_or_create_node_uuid(target)
    assert _HEX_32.fullmatch(value)
    assert target.read_text(encoding="ascii").strip() == value


def test_lost_link_race_adopts_peer_uuid(tmp_path, monkeypatch):
    """When a peer wins the os.link race we must ADOPT its uuid, not the
    one we generated -- otherwise the on-disk value and our in-memory /
    registered value diverge (split identity)."""
    target = tmp_path / "rhorizon" / "node-uuid"
    peer_uuid = "abcdef0123456789abcdef0123456789"

    def _peer_wins(src, dst, *a, **k):
        # the peer linked its own uuid onto the final path just before us
        Path(dst).write_text(peer_uuid, encoding="ascii")
        raise FileExistsError(17, "File exists")

    monkeypatch.setattr(nu.os, "link", _peer_wins)
    value = nu.load_or_create_node_uuid(target)
    assert value == peer_uuid
    assert target.read_text(encoding="ascii").strip() == peer_uuid
    assert not list(target.parent.glob(".node-uuid.*.tmp"))  # our temp cleaned


def test_concurrent_first_boot_single_identity(tmp_path):
    """N workers racing on a fresh volume must converge on ONE uuid:
    every caller returns the same value and it matches the file."""
    import threading

    target = tmp_path / "rhorizon" / "node-uuid"
    target.parent.mkdir(parents=True)
    results: list[str] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait()  # maximise overlap on the create path
            results.append(nu.load_or_create_node_uuid(target))
        except BaseException as exc:  # noqa: BLE001 -- surface any racer crash
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"workers crashed: {errors}"
    assert len(results) == 8
    assert len(set(results)) == 1, f"workers disagreed: {set(results)}"
    assert target.read_text(encoding="ascii").strip() == results[0]
    assert not list(target.parent.glob(".node-uuid.*.tmp"))  # all temps cleaned


# --- module-level cache ----------------------------------------------------


def test_get_before_init_raises():
    with pytest.raises(nu.NodeUUIDError):
        nu.get_node_uuid()


def test_init_caches_value_for_get(tmp_path):
    target = tmp_path / "node-uuid"
    init_value = nu.init_node_uuid(target)
    assert nu.get_node_uuid() == init_value


def test_init_is_idempotent_across_calls(tmp_path):
    target = tmp_path / "node-uuid"
    first = nu.init_node_uuid(target)
    # Second call should re-read the persisted file and reset the cache
    # to the same value (not regenerate).
    second = nu.init_node_uuid(target)
    assert first == second == nu.get_node_uuid()


# --- vault_workers DB integration -----------------------------------------


@pytest.fixture
async def _wipe_workers(setup_db):
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()


@pytest.mark.asyncio
async def test_register_worker_persists_node_uuid(_wipe_workers):
    uid = "0123456789abcdef0123456789abcdef"
    async with async_session() as db:
        await register_worker(db, pid=55501, node_uuid=uid)
        r = await db.execute(
            text("SELECT node_uuid FROM vault_workers WHERE pid = 55501")
        )
        row = r.fetchone()
    assert row.node_uuid == uid


@pytest.mark.asyncio
async def test_register_worker_node_uuid_defaults_null(_wipe_workers):
    """Back-compat : tests that don't pass node_uuid leave the column NULL."""
    async with async_session() as db:
        await register_worker(db, pid=55502)
        r = await db.execute(
            text("SELECT node_uuid FROM vault_workers WHERE pid = 55502")
        )
        row = r.fetchone()
    assert row.node_uuid is None


@pytest.mark.asyncio
async def test_register_worker_reregistration_preserves_node_uuid(_wipe_workers):
    """COALESCE keeps the originally written uuid when a follow-up
    register call omits it (idempotency on the (hostname, pid) PK)."""
    uid = "fedcba9876543210fedcba9876543210"
    async with async_session() as db:
        await register_worker(db, pid=55503, node_uuid=uid)
        # Simulate a downstream re-register without node_uuid
        await register_worker(db, pid=55503, node_uuid=None)
        # And a state transition (shouldn't touch node_uuid either)
        await update_worker_state(db, WorkerState.MASTER, pid=55503)
        r = await db.execute(
            text("SELECT node_uuid FROM vault_workers WHERE pid = 55503")
        )
        row = r.fetchone()
    assert row.node_uuid == uid


@pytest.mark.asyncio
async def test_register_worker_with_node_uuid_settable_after_null(_wipe_workers):
    """A worker that originally registered without node_uuid (legacy /
    test path) can be filled in later by a register call that supplies
    one."""
    uid = "11111111222222223333333344444444"
    async with async_session() as db:
        await register_worker(db, pid=55504, node_uuid=None)
        await register_worker(db, pid=55504, node_uuid=uid)
        r = await db.execute(
            text("SELECT node_uuid FROM vault_workers WHERE pid = 55504")
        )
        row = r.fetchone()
    assert row.node_uuid == uid


@pytest.mark.asyncio
async def test_register_worker_node_uuid_indexed(_wipe_workers):
    """Sanity-check that idx_vault_workers_node_uuid (btree) exists so
    future joins / lookups by node_uuid hit the planner-friendly path."""
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT 1 FROM pg_indexes "
                "WHERE tablename = 'vault_workers' "
                "  AND indexname = 'idx_vault_workers_node_uuid'"
            )
        )
        assert r.fetchone() is not None
