# SPDX-License-Identifier: AGPL-3.0-or-later
"""S4a -- log_action writes Ed25519-signed audit entries (master/single-worker).

When a per-node audit identity is loaded, log_action signs the chain with it and
tags the row sig_alg='ed25519' + signer_fpr. With no identity it falls back to
the legacy symmetric HMAC chain (sig_alg='hmac') -- so existing deployments are
unaffected until provisioning. The follower->master RPC op for ed25519 signing
lands in S4b.
"""

import pytest
from api.app.audit import log_action
from api.app.audit_identity import ensure_audit_identity
from api.app.audit_payload import audit_row_payload
from api.app.crypto import verify_audit_ed25519
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text


async def _last_signed_sig(db) -> str:
    """Mirror log_action's prev_sig query (timestamp DESC, id DESC)."""
    row = (
        await db.execute(
            text(
                "SELECT signature FROM vault_audit WHERE signature != 'unsigned' "
                "ORDER BY timestamp DESC, id DESC LIMIT 1"
            )
        )
    ).fetchone()
    return row.signature if row else ""


async def _teardown():
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('audit_identity_seed_enc', 'audit_identity_pub')"
            )
        )
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await db.execute(text("DELETE FROM vault_audit_signer_certs"))
        await db.execute(text("TRUNCATE vault_audit"))
        await db.commit()
    vault._audit_signer = None


@pytest.mark.asyncio
async def test_log_action_signs_ed25519_when_identity_present(client, master_password):
    """A logged action under a provisioned identity is ed25519 + publicly verifiable."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            pub = await ensure_audit_identity(db)
        assert vault.has_audit_identity

        actor, action, target, detail = "tester", "unit_probe", "x", {"k": 1}
        async with async_session() as db:
            prev = await _last_signed_sig(db)
            await log_action(
                db, actor=actor, action=action, target=target, detail=detail
            )
            await db.commit()

        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT id, timestamp, actor, action, target, detail, "
                        "ip_address, signature, key_epoch, sig_alg, signer_fpr, "
                        "payload_version FROM vault_audit "
                        "WHERE action = :a ORDER BY timestamp DESC LIMIT 1"
                    ),
                    {"a": action},
                )
            ).fetchone()
        assert row.sig_alg == "ed25519"
        assert row.signer_fpr == vault.audit_identity_fpr
        assert row.payload_version == 2

        payload = audit_row_payload(row)
        assert verify_audit_ed25519(pub, payload, prev, row.signature) is True
    finally:
        await _teardown()


@pytest.mark.asyncio
async def test_log_action_falls_back_to_hmac_without_identity(client, master_password):
    """No audit identity -> the legacy symmetric chain (sig_alg='hmac')."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        vault._audit_signer = None  # ensure no identity loaded
        assert not vault.has_audit_identity
        async with async_session() as db:
            await log_action(db, actor="t", action="hmac_probe", target=None, detail={})
            await db.commit()
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT sig_alg, signer_fpr FROM vault_audit "
                        "WHERE action = 'hmac_probe' ORDER BY timestamp DESC LIMIT 1"
                    )
                )
            ).fetchone()
        assert row.sig_alg == "hmac"
        assert row.signer_fpr is None
    finally:
        await _teardown()
