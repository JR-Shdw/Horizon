"""Disposable API workers attach to crypto without consuming Shamir shares."""

from unittest.mock import AsyncMock

import pytest
from api.app import cluster_setup


class _Transition:
    async def __aenter__(self):
        return None

    async def __aexit__(self, *_exc):
        return False


class _Vault:
    def __init__(self):
        self._rpc_client = None
        self._sealed = True

    @property
    def sealed(self):
        return self._sealed

    def master_transition_lock(self):
        return _Transition()

    def attach_rpc_client(self, client):
        self._rpc_client = client

    def detach_rpc_client(self):
        self._rpc_client = None


@pytest.mark.asyncio
async def test_api_attach_uses_rpc_without_fetching_or_publishing_share(monkeypatch):
    vault = _Vault()
    client = AsyncMock()
    monkeypatch.setattr(
        cluster_setup,
        "_wait_for_master_sockets",
        AsyncMock(
            return_value=("/run/rhorizon/crypto.sock", "/run/rhorizon/keys.sock")
        ),
    )
    monkeypatch.setattr(cluster_setup, "MasterRpcClient", lambda _path: client)
    fetch = AsyncMock()
    monkeypatch.setattr(cluster_setup, "_fetch_and_expose_share", fetch)

    assert await cluster_setup.attach_api_to_custodian(object(), vault)
    assert vault.sealed is False
    assert vault._rpc_client is client
    client.call.assert_awaited_once()
    fetch.assert_not_awaited()


@pytest.mark.asyncio
async def test_api_attach_stays_sealed_when_no_custodian_exists(monkeypatch):
    vault = _Vault()
    monkeypatch.setattr(
        cluster_setup,
        "_wait_for_master_sockets",
        AsyncMock(return_value=None),
    )

    assert not await cluster_setup.attach_api_to_custodian(
        object(), vault, expect_master=False
    )
    assert vault.sealed is True
    assert vault._rpc_client is None
