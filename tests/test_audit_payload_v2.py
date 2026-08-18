"""Audit payload v2 covers the complete immutable stored row."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from api.app.audit import log_action
from api.app.audit_identity import ensure_audit_identity
from api.app.audit_payload import audit_payload_v1, audit_row_payload
from api.app.crypto import sign_audit_ed25519, verify_audit_ed25519
from api.app.database import async_session
from api.app.key_epoch import get_key_epoch
from api.app.vault_state import vault
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

SEED = bytes(range(32))
PUBLIC = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw()


def _row(**changes):
    values = {
        "id": UUID("12345678-1234-5678-9234-567812345678"),
        "timestamp": datetime(2026, 8, 16, 12, 34, 56, 789012, tzinfo=timezone.utc),
        "actor": "operator",
        "action": "rotate",
        "target": None,
        "detail": {"nested": {"b": 2, "a": 1}, "unicode": "é"},
        "ip_address": "2001:db8::1",
        "signature": "not-part-of-payload",
        "key_epoch": 7,
        "sig_alg": "ed25519",
        "signer_fpr": "ab" * 32,
        "payload_version": 2,
    }
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", UUID("22345678-1234-5678-9234-567812345678")),
        ("timestamp", datetime(2026, 8, 16, 12, 34, 57, tzinfo=timezone.utc)),
        ("actor", "other-operator"),
        ("action", "delete"),
        ("target", ""),
        ("detail", {"nested": {"a": 1, "b": 3}, "unicode": "é"}),
        ("ip_address", "192.0.2.1"),
        ("key_epoch", 8),
        ("sig_alg", "hmac"),
        ("signer_fpr", "cd" * 32),
        ("payload_version", 1),
    ],
)
def test_each_v2_stored_field_is_cryptographically_bound(field, replacement):
    original = _row()
    payload = audit_row_payload(original)
    signature = sign_audit_ed25519(SEED, payload, "previous-signature")
    changed = _row(**{field: replacement})

    assert audit_row_payload(changed) != payload
    assert not verify_audit_ed25519(
        PUBLIC,
        audit_row_payload(changed),
        "previous-signature",
        signature,
    )


def test_v2_normalises_timezone_but_preserves_exact_instant():
    utc = _row()
    offset = timezone(timedelta(hours=2))
    same_instant = _row(timestamp=utc.timestamp.astimezone(offset))
    assert audit_row_payload(same_instant) == audit_row_payload(utc)


def test_v2_distinguishes_null_from_empty_and_rejects_non_object_detail():
    assert audit_row_payload(_row(target=None)) != audit_row_payload(_row(target=""))
    with pytest.raises(ValueError, match="JSON object"):
        audit_row_payload(_row(detail=[]))


def test_v1_payload_remains_byte_compatible_and_lossy_by_design():
    expected = 'operator|rotate||{"a": 1}'
    assert (
        audit_payload_v1(
            actor="operator", action="rotate", target=None, detail={"a": 1}
        )
        == expected
    )
    legacy_row = _row(
        payload_version=1,
        actor="operator",
        action="rotate",
        target=None,
        detail={"a": 1},
    )
    assert audit_row_payload(legacy_row) == expected


def test_signature_column_is_not_recursively_part_of_payload():
    original = _row()
    changed = deepcopy(original)
    changed.signature = "different-signature"
    assert audit_row_payload(changed) == audit_row_payload(original)


async def _verify(client, token):
    response = await client.get(
        "/api/v1/vault/audit/verify", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_database_verifier_detects_each_v2_field_tamper(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    action = "v2_complete_row_tamper_probe"
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
            await log_action(
                db,
                actor="v2-operator",
                action=action,
                target=None,
                detail={"a": 1},
                ip_address="2001:db8::1",
            )
            await db.commit()
        assert (await _verify(client, admin_token))["chain_intact"] is True

        async with async_session() as db:
            original = (
                (
                    await db.execute(
                        text("SELECT * FROM vault_audit WHERE action = :action"),
                        {"action": action},
                    )
                )
                .mappings()
                .one()
            )

        mutations = {
            "id": UUID("32345678-1234-5678-9234-567812345678"),
            "timestamp": original["timestamp"] + timedelta(seconds=1),
            "actor": "tampered-operator",
            "action": "tampered-action",
            "target": "",
            "detail": {"a": 2},
            "ip_address": "192.0.2.55",
            "key_epoch": original["key_epoch"] + 1,
            "sig_alg": "hmac",
            "signer_fpr": "cd" * 32,
            "payload_version": 1,
        }
        for field, replacement in mutations.items():
            value_sql = "CAST(:value AS jsonb)" if field == "detail" else ":value"
            async with async_session() as db:
                await db.execute(
                    text(
                        f"UPDATE vault_audit SET {field} = {value_sql} "
                        "WHERE signature = :signature"
                    ),
                    {
                        "value": ('{"a":2}' if field == "detail" else replacement),
                        "signature": original["signature"],
                    },
                )
                await db.commit()
            broken = await _verify(client, admin_token)
            assert broken["chain_intact"] is False, field

            restore_sql = "CAST(:value AS jsonb)" if field == "detail" else ":value"
            async with async_session() as db:
                await db.execute(
                    text(
                        f"UPDATE vault_audit SET {field} = {restore_sql} "
                        "WHERE signature = :signature"
                    ),
                    {
                        "value": ('{"a":1}' if field == "detail" else original[field]),
                        "signature": original["signature"],
                    },
                )
                await db.commit()
            assert (await _verify(client, admin_token))["chain_intact"] is True
    finally:
        async with async_session() as db:
            await db.execute(text("TRUNCATE vault_audit"))
            await db.commit()


@pytest.mark.asyncio
async def test_mixed_v1_v2_chain_keeps_historical_verification(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await db.execute(text("TRUNCATE vault_audit"))
            epoch = await get_key_epoch(db)
            legacy_payload = audit_payload_v1(
                actor="legacy", action="v1", target=None, detail={"a": 1}
            )
            legacy_signature = await vault.audit_sign(legacy_payload, "")
            await db.execute(
                text("""
                    INSERT INTO vault_audit
                        (actor, action, target, detail, ip_address, signature,
                         key_epoch, sig_alg, signer_fpr, payload_version)
                    VALUES
                        ('legacy', 'v1', NULL, CAST(:detail AS jsonb),
                         '192.0.2.1', :signature, :epoch, 'hmac', NULL, 1)
                """),
                {"detail": '{"a":1}', "signature": legacy_signature, "epoch": epoch},
            )
            await log_action(db, actor="current", action="v2", detail={"b": 2})
            await db.commit()

        result = await _verify(client, admin_token)
        assert result["chain_intact"] is True
        assert result["total_entries"] == 2

        # This metadata was never part of v1. Compatibility deliberately keeps
        # that historical limitation instead of pretending old signatures are
        # stronger than they were.
        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_audit SET ip_address = '198.51.100.9' "
                    "WHERE action = 'v1'"
                )
            )
            await db.commit()
        assert (await _verify(client, admin_token))["chain_intact"] is True
    finally:
        async with async_session() as db:
            await db.execute(text("TRUNCATE vault_audit"))
            await db.commit()
