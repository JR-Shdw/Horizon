# SPDX-License-Identifier: AGPL-3.0-or-later
"""Alert once per node when it is still sealed after start."""

import asyncio
from unittest.mock import AsyncMock

import pytest
from api.app import boot_alert
from api.app.config import settings
from api.app.metrics import notification_undelivered
from api.app.routes import notifications

WORKERS = 5


class _Vault:
    def __init__(self, sealed: bool) -> None:
        self.sealed = sealed


@pytest.fixture
def node(monkeypatch, tmp_path):
    url_file = tmp_path / "boot-url"
    url_file.write_text("https://relay.example/alert\n")
    monkeypatch.setattr(settings, "node_uuid_path", str(tmp_path / "node-uuid"))
    monkeypatch.setattr(settings, "notify_boot_url_file", str(url_file))
    monkeypatch.setattr(settings, "notify_boot_grace_secs", 0)
    monkeypatch.setattr(boot_alert, "RETRY_SECS", 0)
    monkeypatch.setattr(boot_alert, "vault", _Vault(sealed=True))
    send = AsyncMock()
    monkeypatch.setattr(notifications, "_send_webhook", send)
    return send, url_file


async def _run_workers(count: int) -> None:
    tasks = [
        asyncio.create_task(boot_alert.boot_sealed_alert_task()) for _ in range(count)
    ]
    await asyncio.sleep(0.05)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_one_alert_per_node_across_workers(node):
    send, _ = node
    await _run_workers(WORKERS)
    send.assert_awaited_once()
    config, event, message = send.await_args.args
    assert config == {"url": "https://relay.example/alert"}
    assert event == "started_sealed"
    assert "still sealed" in message


@pytest.mark.asyncio
async def test_no_alert_when_unsealed_within_grace(node, monkeypatch):
    send, _ = node
    monkeypatch.setattr(boot_alert, "vault", _Vault(sealed=False))
    await _run_workers(WORKERS)
    send.assert_not_awaited()


@pytest.mark.asyncio
async def test_lock_released_when_owner_stops(node):
    send, _ = node
    await _run_workers(1)
    await _run_workers(1)
    assert send.await_count == 2


@pytest.mark.asyncio
async def test_retries_then_counts_undelivered(node):
    send, _ = node
    send.side_effect = OSError("down")
    before = notification_undelivered.labels(event="started_sealed")._value.get()
    assert await boot_alert.alert_if_sealed() is False
    assert send.await_count == boot_alert.ATTEMPTS
    after = notification_undelivered.labels(event="started_sealed")._value.get()
    assert after == before + 1


@pytest.mark.asyncio
async def test_stops_retrying_once_unsealed(node, monkeypatch):
    send, _ = node
    state = _Vault(sealed=True)
    monkeypatch.setattr(boot_alert, "vault", state)

    async def fail_then_unseal(*_args):
        state.sealed = False
        raise OSError("down")

    send.side_effect = fail_then_unseal
    assert await boot_alert.alert_if_sealed() is False
    send.assert_awaited_once()


@pytest.mark.asyncio
async def test_failure_log_omits_url(node, caplog):
    send, _ = node
    send.side_effect = OSError("https://relay.example/alert refused")
    await boot_alert.alert_if_sealed()
    assert "relay.example" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [None, "  \n"])
async def test_missing_or_empty_url_file(node, content):
    send, url_file = node
    if content is None:
        url_file.unlink()
    else:
        url_file.write_text(content)
    assert await boot_alert.alert_if_sealed() is False
    send.assert_not_awaited()
