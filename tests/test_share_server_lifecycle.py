"""Share-server task ownership during seal and failover."""

import asyncio

import pytest
from api.app.cluster_setup import _drain_share_server
from api.app.vault_state import VaultState


@pytest.mark.asyncio
async def test_drain_detaches_task_before_closing_server():
    vault = VaultState()
    events = []

    class _Server:
        def close(self):
            events.append("closed")

    vault._cluster_share_server = _Server()

    async def _borrow_owner():
        while vault._cluster_share_server is not None:
            await asyncio.sleep(0)
        events.append("borrow_released")

    vault._cluster_share_task = asyncio.create_task(_borrow_owner())
    await asyncio.sleep(0)
    await _drain_share_server(vault)

    assert events == ["borrow_released", "closed"]
    assert vault._cluster_share_server is None
    assert vault._cluster_share_task is None
