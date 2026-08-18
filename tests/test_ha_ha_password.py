"""cluster ha_password storage + mlock'd RAM management.

Covers:
- state machine (sealed/unsealed guard rails)
- length validation (>= settings.ha_password_min_length)
- type validation (bytes only)
- DB roundtrip via Rust subkey AES-GCM wrap (ha_wrap_key + AAD)
- UPSERT idempotency (overwriting an existing row)
- vault_cluster_config row key = 'ha_password_encrypted'
- AAD binding: wrong AAD on ciphertext fails to decrypt
- seal() drops the RAM buffer (is_loaded -> False after seal)
- load_ha_password_into_ram is a no-op when row absent (pre-cluster-init)
- full lifecycle: set -> seal -> unseal -> load -> same value
- audit row emitted on set_ha_password (action=ha_password_set)
- master rotation re-wraps the at-rest row under the new ha_wrap_key
"""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app.cluster_rpc import CustodianRpcClient, MasterUnreachable, RpcError
from api.app.config import settings
from api.app.database import async_session
from api.app.vault_state import VaultSealedError, vault
from sqlalchemy import text


@pytest_asyncio.fixture(autouse=True)
async def _wipe_ha_password_row():
    """Each test gets a clean vault_cluster_config row for ha_password."""
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": hp._CONFIG_KEY},
        )
        await db.commit()
    hp.clear()
    yield
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": hp._CONFIG_KEY},
        )
        await db.commit()
    hp.clear()


# --- state machine: sealed vault rejects all ops --------------------------


@pytest.mark.asyncio
async def test_set_rejected_when_sealed(admin_token):
    vault.seal()
    try:
        async with async_session() as db:
            with pytest.raises(VaultSealedError):
                await hp.set_ha_password(db, b"x" * 64, actor="test")
    finally:
        # Re-unseal so subsequent tests reuse a working vault.
        from api.app.main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            await ac.post(
                "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
            )


@pytest.mark.asyncio
async def test_load_rejected_when_sealed(admin_token):
    vault.seal()
    try:
        async with async_session() as db:
            with pytest.raises(VaultSealedError):
                await hp.load_ha_password_into_ram(db)
    finally:
        from api.app.main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            await ac.post(
                "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
            )


def test_get_encrypted_buffer_when_sealed_raises():
    vault.seal()
    try:
        with pytest.raises(VaultSealedError):
            hp.get_encrypted_buffer()
    finally:
        # Leave the vault sealed -- the next async test's admin_token
        # fixture will unseal again. Sync test, no client at hand.
        pass


# --- input validation -----------------------------------------------------


@pytest.mark.asyncio
async def test_too_short_rejected(admin_token):
    floor = settings.ha_password_min_length
    async with async_session() as db:
        with pytest.raises(hp.HaPasswordTooShortError):
            await hp.set_ha_password(db, b"x" * (floor - 1), actor="test")


@pytest.mark.asyncio
async def test_min_length_exact_accepted(admin_token):
    floor = settings.ha_password_min_length
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * floor, actor="test")
        await db.commit()
    assert hp.is_loaded()


@pytest.mark.asyncio
async def test_non_bytes_type_rejected(admin_token):
    async with async_session() as db:
        with pytest.raises(TypeError):
            await hp.set_ha_password(db, "x" * 64, actor="test")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_bytearray_accepted(admin_token):
    """bytearray is bytes-like; the module coerces via bytes(plain)."""
    async with async_session() as db:
        await hp.set_ha_password(db, bytearray(b"y" * 64), actor="test")
        await db.commit()
    assert hp.is_loaded()


# --- DB persistence + roundtrip ------------------------------------------


@pytest.mark.asyncio
async def test_set_persists_row_under_canonical_key(admin_token):
    secret = b"a" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()
    assert row is not None
    # Stored as hex(nonce(12) || ciphertext_with_tag(N+16))
    assert len(row.value) >= (12 + 48 + 16) * 2
    assert all(c in "0123456789abcdef" for c in row.value)


@pytest.mark.asyncio
async def test_get_encrypted_buffer_roundtrips_to_original(admin_token):
    secret = b"plain-secret-padded-to-pass-floor" + b"!" * 32
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    buf = hp.get_encrypted_buffer()
    recovered = bytes(vault._wrap.decrypt(buf).to_bytearray())
    assert recovered == secret


@pytest.mark.asyncio
async def test_set_upsert_overwrites_previous_value(admin_token):
    first = b"first-cluster-password-pad-32B!!"
    second = b"second-cluster-password-pad-32B!"
    async with async_session() as db:
        await hp.set_ha_password(db, first, actor="test")
        await db.commit()
    async with async_session() as db:
        await hp.set_ha_password(db, second, actor="test")
        await db.commit()
    async with async_session() as db:
        rows = (
            await db.execute(
                text("SELECT COUNT(*) AS c FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()
    assert rows.c == 1
    buf = hp.get_encrypted_buffer()
    assert bytes(vault._wrap.decrypt(buf).to_bytearray()) == second


@pytest.mark.asyncio
async def test_set_caches_in_ram_immediately(admin_token):
    assert not hp.is_loaded()
    async with async_session() as db:
        await hp.set_ha_password(db, b"z" * 64, actor="test")
        await db.commit()
    assert hp.is_loaded()


# --- load_ha_password_into_ram -------------------------------------------


@pytest.mark.asyncio
async def test_load_returns_false_when_row_absent(admin_token):
    async with async_session() as db:
        loaded = await hp.load_ha_password_into_ram(db)
    assert loaded is False
    assert not hp.is_loaded()


@pytest.mark.asyncio
async def test_load_returns_true_after_set(admin_token):
    secret = b"q" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    hp.clear()
    assert not hp.is_loaded()
    async with async_session() as db:
        loaded = await hp.load_ha_password_into_ram(db)
    assert loaded is True
    assert hp.is_loaded()
    buf = hp.get_encrypted_buffer()
    assert bytes(vault._wrap.decrypt(buf).to_bytearray()) == secret


@pytest.mark.asyncio
async def test_load_returns_false_on_corrupted_ciphertext(admin_token):
    """A tampered hex blob should fail decrypt cleanly, not crash."""
    secret = b"r" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    # Corrupt the stored ciphertext.
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()
        corrupted = row.value[:-2] + ("00" if row.value[-2:] != "00" else "01")
        await db.execute(
            text("UPDATE vault_cluster_config SET value = :v WHERE key = :k"),
            {"v": corrupted, "k": hp._CONFIG_KEY},
        )
        await db.commit()
    hp.clear()
    async with async_session() as db:
        loaded = await hp.load_ha_password_into_ram(db)
    assert loaded is False
    assert not hp.is_loaded()


@pytest.mark.asyncio
async def test_load_sends_database_envelope_directly_to_custodian(
    admin_token, monkeypatch
):
    secret = b"c" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()

    hp.clear()
    monkeypatch.setattr(
        vault,
        "_rpc_client",
        CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
    )
    rpc = AsyncMock(return_value="installed")
    monkeypatch.setattr(vault, "_call_rpc", rpc)

    async with async_session() as db:
        assert await hp.load_ha_password_into_ram(db) is True

    rpc.assert_awaited_once_with("install_ha_password", {"wrapped": row.value})
    assert vault._ha_password_enc is None


@pytest.mark.asyncio
async def test_load_does_not_fallback_to_python_when_custodian_rejects(
    admin_token, monkeypatch
):
    async with async_session() as db:
        await hp.set_ha_password(db, b"e" * 48, actor="test")
        await db.commit()

    hp.clear()
    monkeypatch.setattr(
        vault,
        "_rpc_client",
        CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
    )
    rpc = AsyncMock(side_effect=RuntimeError("rejected envelope"))
    monkeypatch.setattr(vault, "_call_rpc", rpc)

    async with async_session() as db:
        assert await hp.load_ha_password_into_ram(db) is False

    rpc.assert_awaited_once()
    assert vault._ha_password_enc is None


@pytest.mark.asyncio
async def test_set_rotates_custodian_from_database_envelope(admin_token, monkeypatch):
    wrapped = b"\xab" * 60
    monkeypatch.setattr(
        vault,
        "_rpc_client",
        CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
    )
    rpc = AsyncMock(return_value="")
    monkeypatch.setattr(vault, "_call_rpc", rpc)
    monkeypatch.setattr(hp, "_wrap_for_db", AsyncMock(return_value=wrapped))
    monkeypatch.setattr(hp, "log_action", AsyncMock())

    async with async_session() as db:
        await hp.set_ha_password(db, b"d" * 48, actor="test")
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()

    rpc.assert_awaited_once_with("replace_ha_password", {"wrapped": wrapped.hex()})
    assert row.value == wrapped.hex()
    assert vault._ha_password_enc is None


# --- AAD binding ---------------------------------------------------------


@pytest.mark.asyncio
async def test_aad_binding_rejects_wrong_aad(admin_token):
    """Decrypting the stored ciphertext with a non-canonical AAD fails."""
    secret = b"s" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()
    wrapped = bytes.fromhex(row.value)
    with pytest.raises(Exception):
        vault._wrap.aesgcm_subkey_decrypt(vault._ha_wrap_enc, wrapped, b"wrong-aad")


# --- seal lifecycle -------------------------------------------------------


@pytest.mark.asyncio
async def test_seal_clears_ram_buffer(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"t" * 64, actor="test")
        await db.commit()
    assert hp.is_loaded()
    vault.seal()
    assert not hp.is_loaded()
    assert vault._ha_password_enc is None
    # Re-unseal for downstream tests.
    from api.app.main import app
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        await ac.post(
            "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
        )


@pytest.mark.asyncio
async def test_seal_does_not_touch_db_row(admin_token):
    secret = b"u" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    vault.seal()
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()
    assert row is not None  # row survives seal
    # Re-unseal so subsequent tests work + verify load survives the cycle.
    from api.app.main import app
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post(
            "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
        )
        assert r.status_code == 200
    # /unseal auto-loads via load_ha_password_into_ram
    assert hp.is_loaded()
    buf = hp.get_encrypted_buffer()
    assert bytes(vault._wrap.decrypt(buf).to_bytearray()) == secret


# --- /unseal best-effort wiring -------------------------------------------


@pytest.mark.asyncio
async def test_unseal_loads_ha_password_when_row_present(admin_token, client):
    secret = b"v" * 48
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="test")
        await db.commit()
    vault.seal()
    assert not hp.is_loaded()
    r = await client.post(
        "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
    )
    assert r.status_code == 200
    assert hp.is_loaded()


@pytest.mark.asyncio
async def test_unseal_succeeds_when_ha_password_row_absent(admin_token, client):
    """A vault with no cluster config should still unseal cleanly."""
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": hp._CONFIG_KEY},
        )
        await db.commit()
    vault.seal()
    r = await client.post(
        "/api/v1/vault/unseal", json={"password": "test-master-password-2024"}
    )
    assert r.status_code == 200
    assert not hp.is_loaded()


# --- get_encrypted_buffer not loaded -------------------------------------


@pytest.mark.asyncio
async def test_get_encrypted_buffer_raises_when_not_loaded(admin_token):
    hp.clear()
    assert not hp.is_loaded()
    with pytest.raises(hp.HaPasswordNotLoadedError):
        hp.get_encrypted_buffer()


def test_clear_is_idempotent():
    hp.clear()
    hp.clear()
    assert not hp.is_loaded()


# --- audit ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_emits_audit_row(admin_token):
    """An audit row with action=ha_password_set must follow every set."""
    async with async_session() as db:
        before = (
            await db.execute(
                text("SELECT COUNT(*) AS c FROM vault_audit WHERE action = :a"),
                {"a": "ha_password_set"},
            )
        ).fetchone()
    async with async_session() as db:
        await hp.set_ha_password(db, b"w" * 48, actor="audit-test-actor")
        await db.commit()
    async with async_session() as db:
        after = (
            await db.execute(
                text(
                    "SELECT actor, action, detail FROM vault_audit "
                    "WHERE action = :a ORDER BY timestamp DESC LIMIT 1"
                ),
                {"a": "ha_password_set"},
            )
        ).fetchone()
        count_after = (
            await db.execute(
                text("SELECT COUNT(*) AS c FROM vault_audit WHERE action = :a"),
                {"a": "ha_password_set"},
            )
        ).fetchone()
    assert count_after.c == before.c + 1
    assert after.actor == "audit-test-actor"
    # detail must NEVER carry the plaintext, only metadata.
    assert "w" * 48 not in str(after.detail)


# --- master rotation re-wrap (unit test on rewrap helper) ---------------


@pytest.mark.asyncio
async def test_rewrap_for_master_rotation_changes_ciphertext(admin_token):
    """rewrap_for_master_rotation re-encrypts the at-rest row under a new
    ha_wrap_key without going through the full /rotate-password flow.
    Verifies that the stored hex changes and that decrypting under the new
    key yields the same plaintext."""
    import os as _os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    secret = b"rewrap-unit-test-padded-" + _os.urandom(24)
    async with async_session() as db:
        await hp.set_ha_password(db, secret, actor="rewrap-test")
        await db.commit()

    async with async_session() as db:
        row_before = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()

    # Derive the current ha_wrap_key (plaintext, since we need it for the
    # rewrap helper). Pulling it through the wrap layer is fine in a test.
    old_ha_wrap = bytes(vault._wrap.decrypt(vault._ha_wrap_enc).to_bytearray())
    new_ha_wrap = _os.urandom(32)

    async with async_session() as db:
        changed = await hp.rewrap_for_master_rotation(db, old_ha_wrap, new_ha_wrap)
        await db.commit()
    assert changed is True

    async with async_session() as db:
        row_after = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": hp._CONFIG_KEY},
            )
        ).fetchone()
    assert row_after.value != row_before.value, "ciphertext must change on rewrap"

    # The new ciphertext decrypts to the same plaintext under the new key.
    wrapped = bytes.fromhex(row_after.value)
    plain = AESGCM(new_ha_wrap).decrypt(wrapped[:12], wrapped[12:], hp._AAD)
    assert plain == secret


@pytest.mark.asyncio
async def test_rewrap_returns_false_when_row_absent(admin_token):
    import os as _os

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": hp._CONFIG_KEY},
        )
        await db.commit()
    async with async_session() as db:
        ok = await hp.rewrap_for_master_rotation(db, _os.urandom(32), _os.urandom(32))
    assert ok is False


# --- is_loaded_anywhere cluster-view -------------------


@pytest.mark.asyncio
async def test_is_loaded_anywhere_returns_true_when_local_set(admin_token):
    """Master worker / locally-set state : skip the RPC hop and return True
    based on the local Python buffer alone. Covers the single-worker test
    runtime and the master-after-/cluster/init case."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"q" * 48, actor="slicev-local-set")
        await db.commit()
    assert hp.is_loaded() is True
    assert await hp.is_loaded_anywhere() is True


@pytest.mark.asyncio
async def test_is_loaded_anywhere_returns_false_when_local_empty_and_no_rpc(
    admin_token,
):
    """No local buffer + no RPC client attached (master worker on a fresh
    pre-/cluster/init cluster). Returns False without exception."""
    assert hp.is_loaded() is False
    assert vault._rpc_client is None
    assert await hp.is_loaded_anywhere() is False


@pytest.mark.asyncio
async def test_is_loaded_anywhere_consults_master_via_rpc_when_local_empty(
    admin_token, monkeypatch
):
    """Follower path : local Python buffer empty, but the master's Rust
    state has the wrapped ha_password (via RPC propagation). The follower
    dispatches ``has_ha_password`` and returns True on "1"."""
    assert hp.is_loaded() is False

    class _FakeRpcClient:
        async def call(self, op, args):
            assert op == "has_ha_password"
            assert args == {}
            return "1"

    monkeypatch.setattr(vault, "_rpc_client", _FakeRpcClient())
    try:
        assert await hp.is_loaded_anywhere() is True
    finally:
        # monkeypatch restores _rpc_client to None at teardown.
        pass


@pytest.mark.asyncio
async def test_is_loaded_anywhere_returns_false_when_master_reports_zero(
    admin_token, monkeypatch
):
    """Follower path on an unprovisioned cluster : master's slot is empty,
    op returns "0", helper returns False."""
    assert hp.is_loaded() is False

    class _FakeRpcClient:
        async def call(self, op, args):
            return "0"

    monkeypatch.setattr(vault, "_rpc_client", _FakeRpcClient())
    assert await hp.is_loaded_anywhere() is False


@pytest.mark.asyncio
async def test_is_loaded_anywhere_degrades_on_master_unreachable(
    admin_token, monkeypatch
):
    """Transport-level failure : the master socket times out / refuses /
    closes mid-read. ``cluster_rpc`` surfaces these as ``MasterUnreachable``
    (cluster_rpc.py:101-134). ``/cluster/ha`` is a status surface, not a
    crypto path -- must degrade to False without raising rather than
    bubble a 5xx to the operator."""
    assert hp.is_loaded() is False

    class _UnreachableRpcClient:
        async def call(self, op, args):
            raise MasterUnreachable("master response timeout")

    monkeypatch.setattr(vault, "_rpc_client", _UnreachableRpcClient())
    assert await hp.is_loaded_anywhere() is False


@pytest.mark.asyncio
async def test_is_loaded_anywhere_degrades_on_master_rpc_error(
    admin_token, monkeypatch
):
    """Operation-side failure : transport works, master responded with
    ``{"error": "..."}`` (the RPC equivalent of an HTTP 500). ``cluster_rpc``
    raises ``RpcError`` in that case (cluster_rpc.py:129). Same status-
    surface contract as the unreachable path : degrade to False rather
    than propagate the master's internal failure mode out to the
    ``/cluster/ha`` caller."""
    assert hp.is_loaded() is False

    class _ErroringRpcClient:
        async def call(self, op, args):
            raise RpcError("master internal failure on has_ha_password")

    monkeypatch.setattr(vault, "_rpc_client", _ErroringRpcClient())
    assert await hp.is_loaded_anywhere() is False


@pytest.mark.asyncio
async def test_is_loaded_anywhere_prefers_local_over_rpc(admin_token, monkeypatch):
    """Short-circuit : local buffer non-empty must skip the RPC hop entirely.
    A raising fake RPC client must NOT be reached -- protects the hot path
    on the master worker from gratuitous socket traffic on every
    /cluster/ha hit."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"r" * 48, actor="slicev-prefer-local")
        await db.commit()
    assert hp.is_loaded() is True

    class _ExplodingRpcClient:
        async def call(self, op, args):  # pragma: no cover -- must not fire
            raise AssertionError("local buffer non-empty ; RPC must not be called")

    monkeypatch.setattr(vault, "_rpc_client", _ExplodingRpcClient())
    assert await hp.is_loaded_anywhere() is True


# --- follow-up: master-worker local Rust state ------------


@pytest.mark.asyncio
async def test_is_loaded_anywhere_consults_local_master_rpc_server(
    admin_token, monkeypatch
):
    """Master worker path : local Python buffer empty (e.g. /cluster/init
    handled by a different worker, a follow-up routed plain via RPC
    to populate the master Rust state but cannot write back into this
    process's Python state) ; ``_rpc_client`` also None (master does not
    RPC to itself). Pre-fix : returned False for ~16% of /cluster/ha hits
    on a 5-worker deployment. Fix : query local ``_master_rpc_server``
    via the follow-up ``has_ha_password_enc`` PyO3 method before
    falling through."""
    assert hp.is_loaded() is False
    assert vault._rpc_client is None

    class _FakeMasterRpcServer:
        def __init__(self, has_it: bool):
            self._has = has_it

        def has_ha_password_enc(self) -> bool:
            return self._has

    monkeypatch.setattr(vault, "_master_rpc_server", _FakeMasterRpcServer(True))
    assert await hp.is_loaded_anywhere() is True

    monkeypatch.setattr(vault, "_master_rpc_server", _FakeMasterRpcServer(False))
    assert await hp.is_loaded_anywhere() is False


@pytest.mark.asyncio
async def test_is_loaded_anywhere_degrades_on_local_master_rpc_server_raise(
    admin_token, monkeypatch
):
    """Defensive : a raising ``has_ha_password_enc`` on the local Rust
    server (lock poisoning, server stopped) must not propagate -- fall
    through to the rpc_client path (which itself degrades to False on
    the master since rpc_client is None). Status surface, not crypto."""
    assert hp.is_loaded() is False
    assert vault._rpc_client is None

    class _RaisingMasterRpcServer:
        def has_ha_password_enc(self) -> bool:
            raise RuntimeError("rust state poisoned")

    monkeypatch.setattr(vault, "_master_rpc_server", _RaisingMasterRpcServer())
    assert await hp.is_loaded_anywhere() is False


# --- Coverage gaps : clear_async + clear() sync + _propagate paths ---------


@pytest.mark.asyncio
async def test_clear_async_drops_local_buffer(admin_token):
    """async variant: ``clear_async()`` drops the local
    Python buffer and fires the async propagation hook (which no-ops here
    since neither master_rpc_server nor rpc_client is wired in tests)."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"k" * 48, actor="clear-async-test")
        await db.commit()
    assert hp.is_loaded() is True
    await hp.clear_async()
    assert hp.is_loaded() is False


@pytest.mark.asyncio
async def test_clear_sync_propagates_to_local_master_rpc_server(
    admin_token, monkeypatch
):
    """Sync ``clear()`` calls ``set_ha_password_enc(None)`` on the local
    master Rust server when one is attached. Mirrors the
    propagation contract for the sync path."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"l" * 48, actor="clear-sync-test")
        await db.commit()

    calls = []

    class _FakeRpcServer:
        def set_ha_password_enc(self, enc):
            calls.append(enc)

    monkeypatch.setattr(vault, "_master_rpc_server", _FakeRpcServer())
    hp.clear()
    assert hp.is_loaded() is False
    assert calls == [None]


@pytest.mark.asyncio
async def test_propagate_local_master_path_calls_setter(monkeypatch):
    """``_propagate_ha_password_to_master_rpc`` local-master path :
    the calling worker holds a Rust server with ``set_ha_password_enc`` ;
    propagation calls it directly without an RPC hop."""
    calls = []

    class _FakeRpcServer:
        def set_ha_password_enc(self, enc):
            calls.append(enc)

    monkeypatch.setattr(vault, "_master_rpc_server", _FakeRpcServer())
    plain = b"m" * 48
    vault._ha_password_enc = vault._encrypt(plain)
    try:
        await hp._propagate_ha_password_to_master_rpc(plain=plain)
    finally:
        vault._ha_password_enc = None
    assert len(calls) == 1
    assert calls[0] is not None


@pytest.mark.asyncio
async def test_propagate_follower_path_dispatches_set_op(monkeypatch):
    """Follower path : no local master_rpc_server, but rpc_client attached.
    Dispatches ``set_ha_password_from_plain`` to the master."""
    calls = []

    class _FakeRpcClient:
        async def call(self, op, args):
            calls.append((op, args))
            return ""

    monkeypatch.setattr(vault, "_master_rpc_server", None)
    monkeypatch.setattr(vault, "_rpc_client", _FakeRpcClient())
    plain = b"n" * 48
    await hp._propagate_ha_password_to_master_rpc(plain=plain)
    assert calls == [("set_ha_password_from_plain", {"plain": plain.hex()})]


@pytest.mark.asyncio
async def test_propagate_follower_path_dispatches_clear_op(monkeypatch):
    """Follower path with ``plain=None`` dispatches ``clear_ha_password``."""
    calls = []

    class _FakeRpcClient:
        async def call(self, op, args):
            calls.append((op, args))
            return ""

    monkeypatch.setattr(vault, "_master_rpc_server", None)
    monkeypatch.setattr(vault, "_rpc_client", _FakeRpcClient())
    await hp._propagate_ha_password_to_master_rpc(plain=None)
    assert calls == [("clear_ha_password", {})]


# --- dispatch follower paths ------------------------------------------------


@pytest.mark.asyncio
async def test_wrap_node_key_dispatch_follower_routes_via_rpc(monkeypatch):
    """Follower-routed wrap_node_key_for_joiner dispatches via
    RPC to the master, returns bytes from the master's wrap. Joiner-side
    HKDF + AAD constants verified separately (Rust dispatch + Python
    unwrap_node_key)."""
    expected_wrapped = b"\xff" * 60  # 12 nonce + 48 ct + tag
    calls = []

    class _FakeRpcClient:
        async def call(self, op, args):
            calls.append((op, args))
            return expected_wrapped.hex()

    monkeypatch.setattr(vault, "_rpc_client", _FakeRpcClient())
    out = await hp.wrap_node_key_for_joiner_dispatch(
        b"-----BEGIN-NODE-KEY-----", "node-uuid-abc"
    )
    assert out == expected_wrapped
    assert calls == [
        (
            "wrap_node_key_for_joiner",
            {
                "node_key_pem": b"-----BEGIN-NODE-KEY-----".hex(),
                "node_uuid": "node-uuid-abc",
            },
        )
    ]


@pytest.mark.asyncio
async def test_wrap_server_key_dispatch_follower_routes_via_rpc(monkeypatch):
    """Same shape as wrap_node_key_for_joiner_dispatch
    with distinct op name + AAD domain."""
    expected_wrapped = b"\xee" * 60
    calls = []

    class _FakeRpcClient:
        async def call(self, op, args):
            calls.append((op, args))
            return expected_wrapped.hex()

    monkeypatch.setattr(vault, "_rpc_client", _FakeRpcClient())
    out = await hp.wrap_server_key_for_joiner_dispatch(
        b"-----BEGIN-SRV-KEY-----", "node-uuid-xyz"
    )
    assert out == expected_wrapped
    assert calls == [
        (
            "wrap_server_key_for_joiner",
            {
                "server_key_pem": b"-----BEGIN-SRV-KEY-----".hex(),
                "node_uuid": "node-uuid-xyz",
            },
        )
    ]


# --- Joiner-side unwrap defensive paths ------------------------------------


def test_unwrap_node_key_rejects_non_bytes_ha_password():
    """Defensive : ``ha_password_plain`` must be bytes-like ; a str
    raises TypeError (not a cryptography-internals error)."""
    with pytest.raises(TypeError, match="ha_password_plain must be bytes"):
        hp.unwrap_node_key_for_joiner(b"\x00" * 28, "str-not-bytes", "uuid")


def test_unwrap_server_key_rejects_non_bytes_ha_password():
    """Same defensive on the server-key path."""
    with pytest.raises(TypeError, match="ha_password_plain must be bytes"):
        hp.unwrap_server_key_for_joiner(b"\x00" * 28, "str-not-bytes", "uuid")


def test_unwrap_server_key_wrong_ha_password_raises_HaPasswordError():
    """Wrong ha_password (or wrong node_uuid, or tampered ct) surfaces as
    HaPasswordError -- the joiner sees a typed error, not a raw InvalidTag
    leaking the crypto layer."""
    correct_pw = b"correct-ha-pw" * 4
    server_key = b"-----BEGIN-SERVER-KEY-----"
    node_uuid = "uuid-server-test"

    # Build a valid wrapped payload using the joiner-side primitive
    # (mirrors what wrap_server_key_for_joiner would produce on the master).
    import os as _os

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    info = hp._SERVER_KEY_INFO_PREFIX + node_uuid.encode()
    aad = hp._SERVER_KEY_AAD_PREFIX + node_uuid.encode()
    hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=None, info=info)
    derived = hkdf.derive(correct_pw)
    nonce = _os.urandom(12)
    ct = AESGCM(derived).encrypt(nonce, server_key, aad)
    wrapped = nonce + ct

    wrong_pw = b"wrong-ha-pw" * 5
    with pytest.raises(hp.HaPasswordError, match="server key unwrap failed"):
        hp.unwrap_server_key_for_joiner(wrapped, wrong_pw, node_uuid)
