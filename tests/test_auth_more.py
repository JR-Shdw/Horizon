# SPDX-License-Identifier: AGPL-3.0-or-later
"""auth.load_prev_hmac_into_ram: prev-hmac reload after an in-place unseal.

After a master-password rotation the previous hmac key is kept (lazy migration)
so already-minted tokens keep authenticating for the grace window. A corrupt
envelope must fail closed (no prev hmac) rather than crash.
"""

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from api.app import auth
from api.app.auth import load_prev_hmac_into_ram
from api.app.cluster_rpc import CustodianRpcClient
from api.app.database import async_session
from api.app.vault_state import vault
from fastapi import HTTPException
from sqlalchemy import text


class _Result:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Db:
    def __init__(self, row):
        self.row = row

    async def execute(self, *_args, **_kwargs):
        return _Result(self.row)


@pytest.mark.asyncio
@pytest.mark.parametrize("permissions", [{"secrets": "write"}, ["secrets"], None])
async def test_require_permission_rejects_malformed_grants(permissions):
    from api.app.auth import require_permission

    dependency = require_permission("secrets", "w")
    with pytest.raises(HTTPException) as exc_info:
        await dependency({"permissions": permissions})

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_lazy_migration_rejects_stale_concurrent_update(monkeypatch):
    from api.app import auth

    raw_token = "rh_" + "A" * 43
    token_row = SimpleNamespace(id="00000000-0000-0000-0000-000000000001")
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[
            _Result(None),
            _Result(token_row),
            _Result(None),
        ]
    )
    monkeypatch.setattr(auth.vault, "require_unsealed", MagicMock())
    monkeypatch.setattr(
        auth.vault, "hmac_sha512_hex", AsyncMock(return_value="current-hash")
    )
    monkeypatch.setattr(
        auth.vault, "hmac_sha512_hex_prev", AsyncMock(return_value="old-hash")
    )
    monkeypatch.setattr(auth, "get_client_ip", MagicMock(return_value="127.0.0.1"))
    monkeypatch.setattr(auth, "check_rate_limit", AsyncMock())
    record_failure = AsyncMock()
    monkeypatch.setattr(auth, "record_failure", record_failure)
    monkeypatch.setattr(auth, "log_authfail", MagicMock())

    with pytest.raises(HTTPException) as exc_info:
        await auth.require_vault_token(
            request=MagicMock(),
            authorization=f"Bearer {raw_token}",
            db=db,
        )

    assert exc_info.value.status_code == 401
    assert db.execute.await_args_list[2].args[1] == {
        "new_hash": "current-hash",
        "old_hash": "old-hash",
        "id": token_row.id,
    }
    record_failure.assert_awaited_once_with(db, "127.0.0.1")


@pytest.mark.asyncio
async def test_load_prev_hmac_into_ram_good_and_bad(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        key = os.urandom(32)
        nonce = os.urandom(12)
        blob = (nonce + vault.aesgcm.encrypt(nonce, key, None)).hex()
        async with async_session() as db:
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) VALUES "
                    "('prev_hmac_key', :v) ON CONFLICT (key) DO UPDATE SET value = :v"
                ),
                {"v": blob},
            )
            await db.commit()
            assert await load_prev_hmac_into_ram(db) is True
            assert vault.has_prev_hmac is True

        # Corrupt envelope -> decrypt fails -> fail closed (False), no crash.
        bad = (os.urandom(12) + os.urandom(48)).hex()
        async with async_session() as db:
            await db.execute(
                text("UPDATE vault_config SET value = :v WHERE key = 'prev_hmac_key'"),
                {"v": bad},
            )
            await db.commit()
            assert await load_prev_hmac_into_ram(db) is False
            assert vault.has_prev_hmac is False
    finally:
        vault.set_prev_hmac(None)
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = 'prev_hmac_key'")
            )
            await db.commit()


@pytest.mark.asyncio
async def test_external_custodian_loads_previous_hmac_envelope(monkeypatch):
    rpc = AsyncMock(return_value="installed")
    fake_vault = SimpleNamespace(
        sealed=False,
        aesgcm=None,
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
        _call_rpc=rpc,
    )
    monkeypatch.setattr(auth, "vault", fake_vault)

    assert await auth.load_prev_hmac_into_ram(_Db(SimpleNamespace(value="ab" * 60)))
    rpc.assert_awaited_once_with("install_prev_hmac", {"wrapped_key": "ab" * 60})


@pytest.mark.asyncio
async def test_external_custodian_cleanup_is_envelope_conditional(monkeypatch):
    rpc = AsyncMock(side_effect=["stale", "cleared"])
    fake_vault = SimpleNamespace(
        _rpc_client=CustodianRpcClient("/tmp/not-used.sock", "/tmp/not-read.token"),
        _call_rpc=rpc,
    )
    monkeypatch.setattr(auth, "vault", fake_vault)

    assert not await auth.clear_prev_hmac_if_observed(1, None)
    assert not await auth.clear_prev_hmac_if_observed(1, "ab" * 60)
    assert await auth.clear_prev_hmac_if_observed(1, "cd" * 60)
    assert rpc.await_args_list == [
        call("clear_prev_hmac_if_envelope", {"wrapped_key": "ab" * 60}),
        call("clear_prev_hmac_if_envelope", {"wrapped_key": "cd" * 60}),
    ]
