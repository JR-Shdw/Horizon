# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit fallback paths that must stay writable during partial failures."""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from api.app import audit, audit_keyring


class _Result:
    def fetchone(self):
        return None

    def scalar_one(self):
        # audit.chain_timestamp reads the row timestamp from PostgreSQL.
        return datetime(2026, 1, 1, tzinfo=timezone.utc)


class _Db:
    def __init__(self):
        self.calls = []

    async def execute(self, query, params=None):
        self.calls.append((str(query), params))
        return _Result()


@pytest.mark.asyncio
async def test_audit_keyring_requires_an_explicit_decryptor():
    with pytest.raises(TypeError, match="requires aesgcm or decrypt_blob"):
        await audit_keyring.load_audit_keyring(object())


@pytest.mark.asyncio
async def test_audit_writers_reject_non_object_detail_before_database_write():
    db = _Db()
    with pytest.raises(ValueError, match="JSON object"):
        await audit.log_action(db, actor="operator", action="invalid", detail=[])
    with pytest.raises(ValueError, match="JSON object"):
        await audit.log_read(db, actor="operator", action="invalid", detail=[])
    assert db.calls == []


def _audit_vault(*, identity_failure=False):
    async def identity(_payload, _previous):
        if identity_failure:
            raise RuntimeError("signer reloading")
        return "ed-signature"

    async def hmac(_payload, _previous):
        return "hmac-signature"

    return SimpleNamespace(
        sealed=False,
        has_audit_identity=True,
        audit_sign_identity=identity,
        audit_sign=hmac,
    )


async def _epoch(_db):
    return 3


@pytest.mark.asyncio
async def test_critical_audit_survives_notification_scheduler_failure(
    monkeypatch, caplog
):
    async def no_signer(_db):
        return None

    monkeypatch.setattr(audit, "vault", _audit_vault())
    monkeypatch.setattr(audit, "resolve_signer_fpr", no_signer)
    monkeypatch.setattr(audit, "get_key_epoch", _epoch)
    monkeypatch.setattr(audit, "_write_file", lambda _entry: None)
    monkeypatch.setattr(audit, "record_audit_event", lambda *_a, **_k: None)
    monkeypatch.setattr(audit, "_dispatch_critical_event", lambda _message: object())
    monkeypatch.setattr(
        asyncio,
        "create_task",
        lambda _work: (_ for _ in ()).throw(RuntimeError("scheduler stopped")),
    )

    db = _Db()
    await audit.log_action(
        db,
        actor="operator",
        action="emergency",
        target="vault",
        critical=True,
    )
    assert db.calls[-1][1]["detail"] == '{"_critical":true}'
    assert db.calls[-1][1]["payload_version"] == 2
    assert "could not be scheduled" in caplog.text


@pytest.mark.asyncio
async def test_mcp_identity_failure_falls_back_to_hmac(monkeypatch):
    async def signer(_db):
        return "fingerprint"

    monkeypatch.setattr(audit, "vault", _audit_vault(identity_failure=True))
    monkeypatch.setattr(audit, "resolve_signer_fpr", signer)
    monkeypatch.setattr(audit, "get_key_epoch", _epoch)
    db = _Db()
    await audit.log_mcp_action(
        db,
        agent_token_id=None,
        actor="agent",
        backend="git",
        tool="read",
        decision="allowed",
    )
    inserted = db.calls[-1][1]
    assert inserted["sig"] == "hmac-signature"
    assert inserted["sig_alg"] == "hmac"
    assert inserted["signer_fpr"] is None


@pytest.mark.asyncio
async def test_mcp_without_identity_uses_hmac(monkeypatch):
    async def no_signer(_db):
        return None

    monkeypatch.setattr(audit, "vault", _audit_vault())
    monkeypatch.setattr(audit, "resolve_signer_fpr", no_signer)
    monkeypatch.setattr(audit, "get_key_epoch", _epoch)
    db = _Db()
    await audit.log_mcp_action(
        db,
        agent_token_id=None,
        actor="agent",
        backend="git",
        tool="read",
        decision="allowed",
    )
    assert db.calls[-1][1]["sig"] == "hmac-signature"


@pytest.mark.asyncio
async def test_mcp_audit_is_explicitly_unsigned_while_sealed(monkeypatch):
    sealed = _audit_vault()
    sealed.sealed = True
    monkeypatch.setattr(audit, "vault", sealed)
    monkeypatch.setattr(audit, "get_key_epoch", _epoch)
    db = _Db()
    await audit.log_mcp_action(
        db,
        agent_token_id=None,
        actor="agent",
        backend="git",
        tool="read",
        decision="denied",
    )
    inserted = db.calls[-1][1]
    assert inserted["sig"] == "unsigned"
    assert inserted["sig_alg"] == "hmac"


def test_record_seal_swallows_metric_and_scheduler_failures(monkeypatch, caplog):
    class BrokenMetric:
        def labels(self, **_kwargs):
            raise RuntimeError("metrics unavailable")

    monkeypatch.setattr(audit, "seal_events", BrokenMetric())
    monkeypatch.setattr(audit, "_dispatch_critical_event", lambda _message: object())
    monkeypatch.setattr(
        asyncio,
        "create_task",
        lambda _work: (_ for _ in ()).throw(RuntimeError("scheduler stopped")),
    )
    audit.record_seal("rollback")
    assert "seal notification could not be scheduled" in caplog.text
