# SPDX-License-Identifier: AGPL-3.0-or-later
"""One JOIN per node: every repeat resets quarantine and re-mints the cert."""

import asyncio

import pytest
from api.app import cluster_auto_join
from api.app.config import settings

WORKERS = 5


class _Unsealed:
    sealed = False


@pytest.fixture
def node(monkeypatch, tmp_path):
    cert = tmp_path / "cluster.pem"
    key = tmp_path / "cluster.key"
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.example")
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_password_file", str(tmp_path / "password"))
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key))
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 20)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)
    (tmp_path / "password").write_bytes(b"x" * 32)
    monkeypatch.setattr(cluster_auto_join, "vault", _Unsealed())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "a" * 32)
    monkeypatch.setattr(
        cluster_auto_join.cluster_cert,
        "has_cluster_cert",
        lambda cert_path, key_path: cert.exists() and key.exists(),
    )

    async def member(_node_uuid):
        return None

    monkeypatch.setattr(cluster_auto_join, "_reconcile_stale_cert", member)
    return cert, key


async def _run_workers():
    tasks = [cluster_auto_join.cluster_auto_join_task() for _ in range(WORKERS)]
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)


def _joiner(monkeypatch, node, failures):
    cert, key = node
    joins = []

    async def attempt(_node_uuid):
        joins.append(_node_uuid)
        await asyncio.sleep(0)
        if len(joins) <= failures:
            raise cluster_auto_join.AutoJoinError("join unexpected 503: sealed")
        cert.write_bytes(b"cert")
        key.write_bytes(b"key")
        return True

    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    return joins


@pytest.mark.asyncio
async def test_workers_of_one_node_join_once(monkeypatch, node):
    joins = _joiner(monkeypatch, node, failures=0)
    await _run_workers()
    assert len(joins) == 1


@pytest.mark.asyncio
async def test_sealed_primary_does_not_multiply_joins(monkeypatch, node):
    joins = _joiner(monkeypatch, node, failures=2)
    await _run_workers()
    assert len(joins) == 3


@pytest.mark.asyncio
async def test_sibling_takes_over_after_permanent_failure(monkeypatch, node):
    cert, key = node
    joins = []

    async def attempt(_node_uuid):
        joins.append(_node_uuid)
        if len(joins) == 1:
            raise cluster_auto_join.AutoJoinPermanentError("bad password")
        cert.write_bytes(b"cert")
        key.write_bytes(b"key")
        return True

    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await _run_workers()
    assert len(joins) == 2


@pytest.mark.asyncio
async def test_join_still_runs_when_the_lock_cannot_be_created(monkeypatch, node):
    blocked = node[0].parent / "file"
    blocked.write_text("")
    monkeypatch.setattr(settings, "cluster_cert_path", str(blocked / "cluster.pem"))
    calls = []

    async def attempt(_node_uuid):
        calls.append(_node_uuid)
        return True

    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=5)
    assert calls
