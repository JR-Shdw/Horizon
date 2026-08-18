"""ha_password HMAC delegation.

Covers :
- ``vault._ha_password_hmac_local`` : raw master-side HMAC over the
  mlock'd ha_password buffer ; verifies determinism, message
  sensitivity, sealed/not-loaded rejection.
- ``vault.ha_password_hmac`` (async dispatcher) : local path on a
  master, RPC path on a follower (mocked RPC client).
- ``cluster_rpc.MasterRpcServer._dispatch`` : the new
  ``op="ha_password_hmac"`` case routes to the local op.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app.cluster_rpc import MasterRpcServer
from api.app.database import async_session
from api.app.vault_state import VaultSealedError, vault
from sqlalchemy import text


@pytest_asyncio.fixture(autouse=True)
async def _wipe_ha_password_row():
    """Each test starts without a ha_password row + drops it after."""
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


# --- _ha_password_hmac_local --------------------------------------------


@pytest.mark.asyncio
async def test_local_hmac_returns_128_hex_chars(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    digest = vault._ha_password_hmac_local(b"payload")
    # HMAC-SHA512 -> 64 bytes -> 128 hex chars
    assert isinstance(digest, str)
    assert len(digest) == 128
    int(digest, 16)  # parses as hex


@pytest.mark.asyncio
async def test_local_hmac_deterministic(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    a = vault._ha_password_hmac_local(b"same message")
    b = vault._ha_password_hmac_local(b"same message")
    assert a == b


@pytest.mark.asyncio
async def test_local_hmac_different_message_different_digest(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    a = vault._ha_password_hmac_local(b"message-a")
    b = vault._ha_password_hmac_local(b"message-b")
    assert a != b


@pytest.mark.asyncio
async def test_local_hmac_different_password_different_digest(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    a = vault._ha_password_hmac_local(b"msg")
    async with async_session() as db:
        await hp.set_ha_password(db, b"y" * 64, actor="test")
        await db.commit()
    b = vault._ha_password_hmac_local(b"msg")
    assert a != b


@pytest.mark.asyncio
async def test_local_hmac_accepts_str_message(admin_token):
    """Mirror of `_hmac_sha512_hex_local` -- str is encoded to bytes."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    bytes_digest = vault._ha_password_hmac_local(b"abc")
    str_digest = vault._ha_password_hmac_local("abc")
    assert bytes_digest == str_digest


@pytest.mark.asyncio
async def test_local_hmac_rejects_when_not_loaded(admin_token):
    # No set_ha_password call -> _ha_password_enc is None even though
    # vault is unsealed. The local op MUST refuse rather than HMAC
    # over an empty / undefined buffer.
    assert vault._ha_password_enc is None
    with pytest.raises(VaultSealedError):
        vault._ha_password_hmac_local(b"msg")


# --- async ha_password_hmac : local + RPC dispatch ----------------------


@pytest.mark.asyncio
async def test_async_hmac_local_path(admin_token):
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    local = vault._ha_password_hmac_local(b"payload")
    async_result = await vault.ha_password_hmac(b"payload")
    assert async_result == local


@pytest.mark.asyncio
async def test_async_hmac_rpc_path(admin_token):
    """When an RPC client is attached, the async wrapper delegates."""
    fake_client = MagicMock()
    fake_client.call = AsyncMock(return_value="cd" * 32)
    vault.attach_rpc_client(fake_client)
    try:
        result = await vault.ha_password_hmac(b"payload")
        assert result == "cd" * 32
        fake_client.call.assert_awaited_once()
        call_args = fake_client.call.await_args
        assert call_args.args[0] == "ha_password_hmac"
        assert call_args.args[1] == {"message": b"payload".hex()}
    finally:
        vault.detach_rpc_client()


@pytest.mark.asyncio
async def test_async_hmac_rpc_path_str_encoded(admin_token):
    """A str message is encoded to bytes before being hex-serialised."""
    fake_client = MagicMock()
    fake_client.call = AsyncMock(return_value="ef" * 32)
    vault.attach_rpc_client(fake_client)
    try:
        await vault.ha_password_hmac("abc")
        fake_client.call.assert_awaited_once()
        assert fake_client.call.await_args.args[1] == {"message": b"abc".hex()}
    finally:
        vault.detach_rpc_client()


# --- cluster_rpc dispatcher case op="ha_password_hmac" ------------------


@pytest.mark.asyncio
async def test_dispatcher_op_ha_password_hmac(admin_token):
    """MasterRpcServer._dispatch routes op='ha_password_hmac' to the
    local op and serialises the result as hex."""
    async with async_session() as db:
        await hp.set_ha_password(db, b"x" * 64, actor="test")
        await db.commit()
    server = MasterRpcServer(socket_name="/tmp/dummy.sock", vault=vault)
    result = server._dispatch("ha_password_hmac", {"message": b"hello".hex()})
    assert result == vault._ha_password_hmac_local(b"hello")


@pytest.mark.asyncio
async def test_dispatcher_unknown_op_still_raises(admin_token):
    """Sanity : we did not break the catch-all for unknown ops."""
    server = MasterRpcServer(socket_name="/tmp/dummy.sock", vault=vault)
    with pytest.raises(ValueError):
        server._dispatch("not-a-real-op", {})
