# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""A full-verification anchor is self-authenticating and fail-closed."""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from api.app.audit import log_action
from api.app.audit_identity import ensure_audit_identity
from api.app.audit_verify_anchor import (
    LEGACY_ADOPTION_SCHEMA,
    build_anchor_payload,
    canonical_anchor_payload,
    create_verification_anchor,
    latest_verification_anchor,
    legacy_unsigned_row_commitment,
    validate_legacy_adoption,
)
from api.app.crypto import (
    generate_audit_identity,
    sign_audit_ed25519,
    verify_audit_ed25519,
)
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text


def _full_result(**changes):
    result = {
        "verification_scope": "full",
        "chain_intact": True,
        "evidence_intact": True,
        "evidence_incomplete_reasons": [],
        "snapshot_stable": True,
        "total_entries": 7,
        "main_highwater_timestamp": "2026-08-16T10:00:00+00:00",
        "main_highwater_id": str(uuid4()),
        "main_head_signature": "a" * 128,
        "chain_anchored_at_day": None,
        "chain_pruned_rows": 0,
        "audit_lite_total_rows": 11,
        "audit_lite_checkpoints": 2,
        "audit_lite_checkpointed_rows": 11,
        "audit_lite_head_checkpoint_id": str(uuid4()),
        "audit_lite_head_timestamp": "2026-08-16T10:00:01Z",
        "audit_lite_head_id": str(uuid4()),
        "audit_lite_head_root": "sha256:" + "c" * 64,
        "archive_seals": 1,
        "archive_head_day": "2026-08-15",
        "archive_head_digest": "sha256:" + "b" * 64,
    }
    result.update(changes)
    return result


def _legacy_commitment(**changes):
    row = {
        "id": str(uuid4()),
        "timestamp": "2026-08-15T21:03:11.482462Z",
        "action": "audit_lite_checkpoint",
        "digest": "sha256:" + "d" * 64,
    }
    row.update(changes)
    return row


def _empty_full_result(**changes):
    result = _full_result(
        total_entries=0,
        main_highwater_timestamp=None,
        main_highwater_id=None,
        main_head_signature=None,
        audit_lite_total_rows=0,
        audit_lite_checkpoints=0,
        audit_lite_checkpointed_rows=0,
        audit_lite_head_checkpoint_id=None,
        audit_lite_head_timestamp=None,
        audit_lite_head_id=None,
        audit_lite_head_root=None,
        archive_seals=0,
        archive_head_day=None,
        archive_head_digest=None,
    )
    result.update(changes)
    return result


async def _seed_empty_anchor() -> dict:
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await db.execute(text("DELETE FROM vault_audit_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit_lite_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit_lite"))
        await db.execute(text("DELETE FROM vault_audit"))
        await ensure_audit_identity(db)
        await db.commit()
    async with async_session() as db:
        anchor = await create_verification_anchor(db, _empty_full_result())
        await db.commit()
    return anchor


async def _resign_anchor(anchor_id: str, mutate, *, completed_at=None) -> None:
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT payload FROM vault_audit_verification_anchors "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": anchor_id},
            )
        ).one()
        payload = dict(row.payload)
        mutate(payload)
        if completed_at is not None:
            payload["completed_at"] = completed_at.isoformat().replace("+00:00", "Z")
        signature = await vault.audit_sign_identity(
            canonical_anchor_payload(payload), ""
        )
        await db.execute(
            text("""
                UPDATE vault_audit_verification_anchors
                SET payload = CAST(:payload AS jsonb), signature = :signature,
                    completed_at = COALESCE(:completed_at, completed_at)
                WHERE id = CAST(:id AS uuid)
            """),
            {
                "id": anchor_id,
                "payload": json.dumps(payload),
                "signature": signature,
                "completed_at": completed_at,
            },
        )
        await db.commit()


def test_anchor_payload_is_canonical_and_signature_detects_tamper():
    seed, public = generate_audit_identity()
    payload = build_anchor_payload(
        anchor_id=uuid4(),
        completed_at=datetime(2026, 8, 16, tzinfo=timezone.utc),
        signer_fpr="f" * 64,
        result=_full_result(),
    )
    canonical = canonical_anchor_payload(payload)
    signature = sign_audit_ed25519(seed, canonical, "")

    assert verify_audit_ed25519(public, canonical, "", signature) is True
    payload["main"]["row_count"] += 1
    assert (
        verify_audit_ed25519(public, canonical_anchor_payload(payload), "", signature)
        is False
    )


def test_anchor_canonicalization_rejects_wrong_schema_and_handles_naive_time():
    with pytest.raises(ValueError, match="unsupported"):
        canonical_anchor_payload({"schema": "wrong"})
    payload = build_anchor_payload(
        anchor_id=uuid4(),
        completed_at=datetime(2026, 8, 16),
        signer_fpr="f" * 64,
        result=_full_result(),
    )
    assert payload["completed_at"].endswith("Z")


def test_legacy_row_commitment_covers_stored_fields():
    row = SimpleNamespace(
        id=uuid4(),
        timestamp=datetime(2026, 8, 15, 21, 3, tzinfo=timezone.utc),
        actor="audit-mtree",
        action="audit_lite_checkpoint",
        target="vault_audit_lite",
        detail={"row_count": 42},
        ip_address="127.0.0.1",
        signature="unsigned",
        key_epoch=0,
        sig_alg="hmac",
        signer_fpr=None,
        payload_version=1,
    )
    first = legacy_unsigned_row_commitment(row)
    assert first == legacy_unsigned_row_commitment(row)
    row.detail = {"row_count": 43}
    assert legacy_unsigned_row_commitment(row)["digest"] != first["digest"]


def test_legacy_candidate_requires_exact_safe_gap_and_rows():
    commitment = _legacy_commitment()
    adoption = {
        "schema": LEGACY_ADOPTION_SCHEMA,
        "unsigned_rows": [commitment],
    }
    result = _full_result(
        evidence_intact=False,
        evidence_incomplete_reasons=["unsigned_main_chain_entries"],
        unsigned_entries=1,
    )
    payload = build_anchor_payload(
        anchor_id=uuid4(),
        completed_at=datetime.now(timezone.utc),
        signer_fpr="f" * 64,
        result=result,
        legacy_adoption=adoption,
        verification_mode="legacy_candidate",
    )
    assert payload["verification_mode"] == "legacy_candidate"
    assert payload["legacy_adoption"]["unsigned_rows"] == [commitment]

    for changes in (
        {"chain_intact": False},
        {"evidence_incomplete_reasons": ["unsigned_main_chain_entries", "other"]},
        {"unsigned_entries": 2},
    ):
        with pytest.raises(ValueError):
            build_anchor_payload(
                anchor_id=uuid4(),
                completed_at=datetime.now(timezone.utc),
                signer_fpr="f" * 64,
                result={**result, **changes},
                legacy_adoption=adoption,
                verification_mode="legacy_candidate",
            )


@pytest.mark.parametrize(
    "adoption",
    [
        {"schema": "wrong", "unsigned_rows": [_legacy_commitment()]},
        {
            "schema": LEGACY_ADOPTION_SCHEMA,
            "unsigned_rows": [_legacy_commitment(action="not-a-checkpoint")],
        },
        {
            "schema": LEGACY_ADOPTION_SCHEMA,
            "unsigned_rows": [_legacy_commitment(digest="sha256:bad")],
        },
    ],
)
def test_legacy_adoption_validation_is_fail_closed(adoption):
    with pytest.raises((KeyError, ValueError)):
        validate_legacy_adoption(adoption)


class _AnchorResult:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class _AnchorDb:
    def __init__(self, row=None):
        self.row = row

    async def execute(self, *_args, **_kwargs):
        return _AnchorResult(self.row)


@pytest.mark.asyncio
async def test_anchor_creation_requires_provisioned_identity(monkeypatch):
    async def no_identity(_db):
        return None

    monkeypatch.setattr("api.app.audit_verify_anchor.resolve_signer_fpr", no_identity)
    with pytest.raises(RuntimeError, match="not provisioned"):
        await create_verification_anchor(_AnchorDb(), _full_result())


@pytest.mark.asyncio
async def test_anchor_loader_handles_empty_and_malformed_rows():
    assert await latest_verification_anchor(_AnchorDb()) is None
    malformed = SimpleNamespace(
        id=uuid4(),
        completed_at=datetime.now(timezone.utc),
        payload=[],
        signature="0" * 128,
        signer_fpr="f" * 64,
        public_key=None,
    )
    assert (await latest_verification_anchor(_AnchorDb(malformed)))["reason"] == (
        "payload_not_object"
    )

    invalid_schema = SimpleNamespace(
        id=uuid4(),
        completed_at=datetime.now(timezone.utc),
        payload={"schema": "wrong"},
        signature="0" * 128,
        signer_fpr="f" * 64,
        public_key=b"bad",
    )
    checked = await latest_verification_anchor(_AnchorDb(invalid_schema))
    assert checked["valid"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"verification_scope": "incremental"},
        {"evidence_intact": False},
        {"snapshot_stable": False},
    ],
)
def test_anchor_builder_rejects_non_authoritative_result(changes):
    with pytest.raises(ValueError):
        build_anchor_payload(
            anchor_id=uuid4(),
            completed_at=datetime.now(timezone.utc),
            signer_fpr="f" * 64,
            result=_full_result(**changes),
        )


@pytest.mark.asyncio
async def test_persisted_anchor_verifies_and_json_tamper_fails(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
            await db.commit()

        async with async_session() as db:
            created = await create_verification_anchor(db, _full_result())
            await db.commit()
        async with async_session() as db:
            loaded = await latest_verification_anchor(db)
        assert loaded is not None
        assert loaded["valid"] is True
        assert loaded["id"] == created["id"]

        async with async_session() as db:
            await db.execute(
                text("""
                    UPDATE vault_audit_verification_anchors
                    SET payload = jsonb_set(payload, '{main,row_count}', '999'::jsonb)
                    WHERE id = CAST(:id AS uuid)
                """),
                {"id": created["id"]},
            )
            await db.commit()
        async with async_session() as db:
            tampered = await latest_verification_anchor(db)
        assert tampered is not None
        assert tampered["valid"] is False
    finally:
        async with async_session() as db:
            await db.execute(text("DELETE FROM vault_audit"))
            await db.execute(text("DELETE FROM vault_audit_lite"))
            await db.execute(text("DELETE FROM vault_audit_key_archive"))
            await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('audit_identity_seed_enc', 'audit_identity_pub')"
                )
            )
            await db.execute(text("DELETE FROM vault_audit_signer_certs"))
            await db.commit()
        vault._audit_signer = None
        vault._audit_seed_enc = None
        vault._cluster_audit_fpr = None


async def _incremental(client, token: str) -> dict:
    response = await client.get(
        "/api/v1/vault/audit/verify/incremental",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_incremental_empty_signed_anchor_is_intact(client, admin_token):
    await _seed_empty_anchor()
    result = await _incremental(client, admin_token)
    assert result["evidence_intact"] is True
    assert result["verification_scope"] == "incremental"
    assert result["suffix_entries_verified"] == 0
    assert result["historical_entries_not_reread"] == 0


@pytest.mark.asyncio
async def test_incremental_rejects_invalid_anchor_signature(client, admin_token):
    anchor = await _seed_empty_anchor()
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_verification_anchors "
                "SET signature = repeat('0', 128) WHERE id = CAST(:id AS uuid)"
            ),
            {"id": anchor["id"]},
        )
        await db.commit()
    result = await _incremental(client, admin_token)
    assert result["evidence_status"] == "broken", result
    assert result["evidence_incomplete_reasons"] == ["verification_anchor_invalid"]


@pytest.mark.asyncio
async def test_incremental_rejects_signed_but_incoherent_anchor(client, admin_token):
    anchor = await _seed_empty_anchor()

    def make_invalid(payload):
        payload["main"]["row_count"] = -1

    await _resign_anchor(anchor["id"], make_invalid)
    result = await _incremental(client, admin_token)
    assert result["evidence_incomplete_reasons"] == [
        "verification_anchor_state_invalid"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("offset", "reason"),
    [
        (timedelta(days=-2), "full_verification_anchor_stale"),
        (timedelta(hours=1), "verification_anchor_timestamp_in_future"),
    ],
)
async def test_incremental_rejects_stale_or_future_anchor(
    client, admin_token, monkeypatch, offset, reason
):
    anchor = await _seed_empty_anchor()
    completed_at = datetime.now(timezone.utc) + offset
    await _resign_anchor(anchor["id"], lambda _payload: None, completed_at=completed_at)
    monkeypatch.setattr(
        "api.app.routes.audit.settings.audit_verify_anchor_max_age_seconds", 60
    )
    result = await _incremental(client, admin_token)
    assert result["evidence_status"] == "incomplete"
    assert reason in result["evidence_incomplete_reasons"]
    assert result["full_verification_required"] is True


@pytest.mark.asyncio
async def test_incremental_reports_unsigned_and_prune_suffixes(client, admin_token):
    await _seed_empty_anchor()
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_audit
                    (id, actor, action, detail, signature, key_epoch,
                     sig_alg, payload_version)
                VALUES
                    (gen_random_uuid(), 'sealed-node', 'unsigned-probe',
                     '{}'::jsonb, 'unsigned', 0, 'hmac', 1)
            """)
        )
        await db.commit()
    unsigned = await _incremental(client, admin_token)
    assert "unsigned_main_chain_entries" in unsigned["evidence_incomplete_reasons"]

    # A valid prune row changes which historical prefix a walk must trust. The
    # incremental verifier refuses to reinterpret its older anchor.
    await _seed_empty_anchor()
    async with async_session() as db:
        await log_action(
            db,
            actor="test",
            action="audit_chain_prune",
            detail={"schema": "test-prune"},
        )
        await db.commit()
    pruned = await _incremental(client, admin_token)
    assert (
        "prune_requires_new_full_verification" in pruned["evidence_incomplete_reasons"]
    )
    assert pruned["full_verification_required"] is True


@pytest.mark.asyncio
async def test_legacy_adoption_requires_signed_candidate_and_detects_tamper(
    client, admin_token, monkeypatch
):
    unsigned_id = uuid4()
    unsigned_timestamp = datetime.now(timezone.utc)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await db.execute(text("DELETE FROM vault_audit_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit_lite_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit_lite"))
        await db.execute(text("DELETE FROM vault_audit"))
        await db.execute(
            text("""
                INSERT INTO vault_audit
                    (id, timestamp, actor, action, target, detail, signature,
                     key_epoch, sig_alg, signer_fpr, payload_version)
                VALUES
                    (CAST(:id AS uuid), :timestamp, 'audit-mtree',
                     'audit_lite_checkpoint', 'vault_audit_lite',
                     CAST(:detail AS jsonb), 'unsigned', 0, 'hmac', NULL, 1)
            """),
            {
                "id": str(unsigned_id),
                "timestamp": unsigned_timestamp,
                "detail": json.dumps({"legacy": True}),
            },
        )
        row = (
            await db.execute(
                text("""
                    SELECT id, timestamp, actor, action, target, detail,
                           ip_address, signature, key_epoch, sig_alg, signer_fpr,
                           payload_version
                    FROM vault_audit WHERE id = CAST(:id AS uuid)
                """),
                {"id": str(unsigned_id)},
            )
        ).one()
        commitment = legacy_unsigned_row_commitment(row)
        candidate_result = _empty_full_result(
            chain_intact=True,
            evidence_intact=False,
            evidence_incomplete_reasons=["unsigned_main_chain_entries"],
            total_entries=1,
            unsigned_entries=1,
            main_highwater_timestamp=unsigned_timestamp.isoformat(),
            main_highwater_id=str(unsigned_id),
            main_highwater_stored_signature="unsigned",
            main_head_signature=None,
        )
        candidate = await create_verification_anchor(
            db,
            candidate_result,
            legacy_adoption={
                "schema": LEGACY_ADOPTION_SCHEMA,
                "unsigned_rows": [commitment],
            },
            verification_mode="legacy_candidate",
        )
        await db.commit()

    # A candidate proves the scan result but is deliberately not usable as the
    # routine incremental anchor until an authenticated operator adopts it.
    before = await _incremental(client, admin_token)
    assert before["evidence_incomplete_reasons"] == ["full_verification_anchor_missing"]

    job_id = uuid4()

    async def completed_job(_job_id):
        return {
            "status": "succeeded",
            "requested_by": "test-admin",
            "result": {
                "legacy_adoption_candidate": {"id": candidate["id"]},
            },
        }

    monkeypatch.setattr("api.app.audit_verify_jobs.get_audit_verify_job", completed_job)
    response = await client.post(
        "/api/v1/vault/audit/verify/legacy-adopt",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "job_id": str(job_id),
            "unsigned_row_ids": [str(unsigned_id)],
            "confirmation": "ADOPT LEGACY AUDIT BASELINE",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["legacy_adopted_unsigned_entries"] == 1

    adopted = await _incremental(client, admin_token)
    assert adopted["evidence_intact"] is True, adopted
    assert adopted["legacy_adopted_unsigned_entries"] == 1

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit SET detail = CAST(:detail AS jsonb) "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": str(unsigned_id), "detail": json.dumps({"legacy": False})},
        )
        await db.commit()
    tampered = await _incremental(client, admin_token)
    assert tampered["chain_intact"] is False
    assert tampered["evidence_incomplete_reasons"] == ["legacy_adopted_row_changed"]


@pytest.mark.asyncio
async def test_incremental_detects_broken_suffix_signature(client, admin_token):
    await _seed_empty_anchor()
    async with async_session() as db:
        await log_action(db, actor="test", action="suffix-row", detail={})
        await db.execute(
            text(
                "UPDATE vault_audit SET signature = repeat('0', 128) "
                "WHERE action = 'suffix-row'"
            )
        )
        await db.commit()
    result = await _incremental(client, admin_token)
    assert result["chain_intact"] is False
    assert result["evidence_incomplete_reasons"] == ["main_chain_suffix_broken"]


@pytest.mark.asyncio
async def test_incremental_detects_historical_main_row_deletion(client, admin_token):
    await _seed_empty_anchor()
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await log_action(db, actor="test", action="historical-row", detail={})
        await db.commit()
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT id, timestamp, signature FROM vault_audit "
                    "ORDER BY timestamp DESC, id DESC LIMIT 1"
                )
            )
        ).one()
        result = _empty_full_result(
            total_entries=1,
            main_highwater_timestamp=row.timestamp.isoformat(),
            main_highwater_id=str(row.id),
            main_head_signature=row.signature,
        )
        await create_verification_anchor(db, result)
        await db.commit()
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit WHERE action='historical-row'"))
        await db.commit()
    checked = await _incremental(client, admin_token)
    assert checked["evidence_status"] == "broken"
    assert "historical_main_row_count_changed" in checked["evidence_incomplete_reasons"]


@pytest.mark.asyncio
async def test_incremental_detects_missing_historical_archive_head(client, admin_token):
    anchor = await _seed_empty_anchor()

    def claim_archive(payload):
        payload["archive"] = {
            "seal_count": 1,
            "head_day": "2026-08-15",
            "head_digest": "sha256:" + "d" * 64,
        }

    await _resign_anchor(anchor["id"], claim_archive)
    result = await _incremental(client, admin_token)
    assert result["evidence_status"] == "broken", result
    assert "historical_archive_anchor_changed" in result["evidence_incomplete_reasons"]


@pytest.mark.asyncio
async def test_incremental_reports_archive_unavailable_and_snapshot_race(
    client, admin_token, monkeypatch
):
    from api.app import audit_archive
    from api.app.routes import audit as audit_route

    await _seed_empty_anchor()

    async def unavailable(*_args, **_kwargs):
        raise OSError("archive temporarily unavailable")

    monkeypatch.setattr(audit_archive, "verify_archive_seals", unavailable)
    unavailable_result = await _incremental(client, admin_token)
    assert (
        "archive_seals_not_verified"
        in unavailable_result["evidence_incomplete_reasons"]
    )

    monkeypatch.undo()
    original = audit_route._current_audit_state
    calls = 0

    async def advancing(db):
        nonlocal calls
        calls += 1
        state = await original(db)
        if calls == 2:
            state = {**state, "lite_count": int(state["lite_count"]) + 1}
        return state

    monkeypatch.setattr(audit_route, "_current_audit_state", advancing)
    raced = await _incremental(client, admin_token)
    assert "evidence_advanced_during_verify" in raced["evidence_incomplete_reasons"]
