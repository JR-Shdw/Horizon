# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Contracts for durable, memory-bounded full-audit verification."""

import asyncio
import inspect
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from api.app.audit_verify_jobs import (
    _claim_job,
    _finish_job,
    enqueue_audit_verify,
    get_audit_verify_job,
)
from sqlalchemy import text


async def _clear_jobs():
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_verify_jobs"))
        await db.commit()


def test_full_verify_streams_in_bounded_batches():
    from api.app.routes.audit import verify_chain

    source = inspect.getsource(verify_chain)
    assert "await db.stream" in source
    assert "yield_per=_VERIFY_STREAM_BATCH" in source
    assert ".fetchall()" not in source


@pytest.mark.asyncio
async def test_create_verify_job_is_authenticated_and_returns_202(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    job_id = uuid4()

    async def fake_enqueue(actor):
        assert actor == "test-admin"
        return {
            "job_id": str(job_id),
            "status": "pending",
            "requested_at": "2026-07-21T00:00:00+00:00",
            "started_at": None,
            "finished_at": None,
            "requested_by": actor,
            "worker_host": None,
            "worker_pid": None,
            "heartbeat_at": None,
            "result": None,
            "error": None,
        }, True

    monkeypatch.setattr("api.app.audit_verify_jobs.enqueue_audit_verify", fake_enqueue)
    response = await client.post(
        "/api/v1/vault/audit/verify/jobs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 202
    assert response.json()["job_id"] == str(job_id)
    assert response.json()["created"] is True


@pytest.mark.asyncio
async def test_read_verify_job_returns_full_result(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    job_id = uuid4()

    async def fake_get(requested_id):
        assert requested_id == job_id
        return {
            "job_id": str(job_id),
            "status": "succeeded",
            "result": {"chain_intact": True, "evidence_intact": True},
        }

    monkeypatch.setattr("api.app.audit_verify_jobs.get_audit_verify_job", fake_get)
    response = await client.get(
        f"/api/v1/vault/audit/verify/jobs/{job_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["result"]["chain_intact"] is True


@pytest.mark.asyncio
async def test_read_verify_job_404(client, master_password, admin_token, monkeypatch):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    async def fake_get(_job_id):
        return None

    monkeypatch.setattr("api.app.audit_verify_jobs.get_audit_verify_job", fake_get)
    response = await client.get(
        f"/api/v1/vault/audit/verify/jobs/{uuid4()}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_preflight_queues_full_job_when_anchor_is_missing(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    job_id = uuid4()

    async def no_anchor(_db):
        return None

    async def fake_enqueue(actor):
        assert actor == "test-admin"
        return {
            "job_id": str(job_id),
            "status": "pending",
            "requested_by": actor,
        }, True

    monkeypatch.setattr(
        "api.app.audit_verify_anchor.latest_verification_anchor", no_anchor
    )
    monkeypatch.setattr("api.app.audit_verify_jobs.enqueue_audit_verify", fake_enqueue)
    response = await client.post(
        "/api/v1/vault/audit/verify/preflight",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["preflight_ready"] is False
    assert body["full_verification_required"] is True
    assert body["full_verification_job"]["job_id"] == str(job_id)
    assert body["full_verification_job"]["created"] is True


@pytest.mark.asyncio
async def test_job_is_cluster_singleton_and_persists_result(admin_token):
    await _clear_jobs()
    first, created = await enqueue_audit_verify("operator-a")
    duplicate, duplicate_created = await enqueue_audit_verify("operator-b")

    assert created is True
    assert duplicate_created is False
    assert duplicate["job_id"] == first["job_id"]

    job_id = await _claim_job()
    assert str(job_id) == first["job_id"]
    running = await get_audit_verify_job(job_id)
    assert running["status"] == "running"
    assert running["heartbeat_at"] is not None

    result = {"chain_intact": True, "evidence_intact": True}
    await _finish_job(job_id, status="succeeded", result=result)
    completed = await get_audit_verify_job(job_id)
    assert completed["status"] == "succeeded"
    assert completed["result"] == result
    assert completed["finished_at"] is not None
    await _clear_jobs()


@pytest.mark.asyncio
async def test_execute_job_runs_verifier_and_stores_result(admin_token, monkeypatch):
    from api.app import audit_verify_jobs
    from api.app.routes import audit

    await _clear_jobs()
    pending, _ = await audit_verify_jobs.enqueue_audit_verify("operator")
    job_id = await audit_verify_jobs._claim_job()
    assert str(job_id) == pending["job_id"]

    async def fake_verify_chain(db, token_info):
        assert token_info["permissions"] == {"audit": "r"}
        return {"chain_intact": True, "total_entries": 123}

    monkeypatch.setattr(audit, "verify_chain", fake_verify_chain)
    await audit_verify_jobs._execute_job(job_id)

    completed = await audit_verify_jobs.get_audit_verify_job(job_id)
    assert completed["status"] == "succeeded"
    assert completed["result"]["total_entries"] == 123
    await _clear_jobs()


def test_job_dict_decodes_json_result():
    from api.app.audit_verify_jobs import _job_dict

    now = datetime.now(timezone.utc)
    row = SimpleNamespace(
        id=uuid4(),
        status="succeeded",
        requested_at=now,
        started_at=now,
        finished_at=now,
        requested_by="operator",
        worker_host="host",
        worker_pid=42,
        heartbeat_at=now,
        result='{"chain_intact": true}',
        error=None,
    )
    assert _job_dict(row)["result"] == {"chain_intact": True}


@pytest.mark.asyncio
async def test_claim_job_skips_when_vault_is_sealed(monkeypatch):
    from api.app import audit_verify_jobs

    monkeypatch.setattr(audit_verify_jobs, "vault", SimpleNamespace(sealed=True))
    assert await audit_verify_jobs._claim_job() is None


@pytest.mark.asyncio
async def test_cancelled_job_is_requeued(admin_token, monkeypatch):
    from api.app import audit_verify_jobs
    from api.app.routes import audit

    await _clear_jobs()
    pending, _ = await audit_verify_jobs.enqueue_audit_verify("operator")
    job_id = await audit_verify_jobs._claim_job()
    assert str(job_id) == pending["job_id"]

    async def cancelled(**_kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(audit, "verify_chain", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await audit_verify_jobs._execute_job(job_id)
    requeued = await audit_verify_jobs.get_audit_verify_job(job_id)
    assert requeued["status"] == "pending"
    assert requeued["error"] == "worker stopped; job requeued"
    await _clear_jobs()


@pytest.mark.asyncio
async def test_failed_job_persists_bounded_error(admin_token, monkeypatch):
    from api.app import audit_verify_jobs
    from api.app.routes import audit

    await _clear_jobs()
    await audit_verify_jobs.enqueue_audit_verify("operator")
    job_id = await audit_verify_jobs._claim_job()

    async def failed(**_kwargs):
        raise RuntimeError("verification failed")

    monkeypatch.setattr(audit, "verify_chain", failed)
    await audit_verify_jobs._execute_job(job_id)
    completed = await audit_verify_jobs.get_audit_verify_job(job_id)
    assert completed["status"] == "failed"
    assert completed["error"] == "RuntimeError: verification failed"
    await _clear_jobs()


@pytest.mark.asyncio
async def test_heartbeat_updates_owner_and_propagates_cancellation(monkeypatch):
    from api.app import audit_verify_jobs

    calls = []

    class Db:
        async def execute(self, _query, params):
            calls.append(params)

        async def commit(self):
            calls.append("commit")

    class Session:
        async def __aenter__(self):
            return Db()

        async def __aexit__(self, *_args):
            return False

    sleeps = 0

    async def sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(audit_verify_jobs, "async_session", Session)
    monkeypatch.setattr(audit_verify_jobs.asyncio, "sleep", sleep)
    job_id = uuid4()
    with pytest.raises(asyncio.CancelledError):
        await audit_verify_jobs._heartbeat_job(job_id)
    assert calls[-1] == "commit"
    assert calls[0]["job_id"] == str(job_id)


@pytest.mark.asyncio
async def test_heartbeat_logs_transient_database_failure(monkeypatch, caplog):
    from api.app import audit_verify_jobs

    class BrokenSession:
        async def __aenter__(self):
            raise RuntimeError("database unavailable")

        async def __aexit__(self, *_args):
            return False

    sleeps = 0

    async def sleep(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(audit_verify_jobs, "async_session", BrokenSession)
    monkeypatch.setattr(audit_verify_jobs.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        await audit_verify_jobs._heartbeat_job(uuid4())
    assert "heartbeat failed" in caplog.text
