# SPDX-License-Identifier: AGPL-3.0-or-later
"""S5 -- /audit/verify dispatches per sig_alg, works sealed, never mutates chain.

- ed25519 rows verify with the public signer key (deterministic, host-
  independent, sealed-capable); hmac rows via the per-epoch keyring (unsealed).
- A detected break alerts operators but does NOT append an audit_chain_broken
  row into the chain it is verifying (the live self-inflating-count bug).
"""

import pytest
from api.app.audit import log_action
from api.app.audit_identity import ensure_audit_identity
from api.app.database import async_session
from api.app.routes.audit import verify_chain
from api.app.vault_state import vault
from sqlalchemy import text


async def _count(db, where: str = "") -> int:
    q = "SELECT count(*) FROM vault_audit" + (f" WHERE {where}" if where else "")
    return (await db.execute(text(q))).scalar()


async def _verify():
    async with async_session() as db:
        return await verify_chain(db=db, token_info={"sub": "t"})


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
    vault._audit_seed_enc = None


@pytest.mark.asyncio
async def test_verify_intact_dual_path(client, master_password):
    """A chain of hmac (bootstrap) + ed25519 (post-provision) rows verifies."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
        async with async_session() as db:
            await log_action(db, actor="t", action="probe_a", target=None, detail={})
            await log_action(
                db, actor="t", action="probe_b", target="x", detail={"k": 1}
            )
            await db.commit()

        res = await _verify()
        assert isinstance(res["verified_by"]["host"], str)
        assert isinstance(res["verified_by"]["pid"], int)
        assert res["chain_intact"] is True
        async with async_session() as db:
            n = await _count(db, "sig_alg = 'ed25519'")
        assert n >= 2
    finally:
        await _teardown()


@pytest.mark.asyncio
async def test_break_does_not_mutate_chain(client, master_password):
    """A tampered row is reported broken, but verify writes nothing to the chain."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
        async with async_session() as db:
            await log_action(db, actor="t", action="keep_a", target=None, detail={})
            await log_action(db, actor="t", action="tamper_me", target=None, detail={})
            await db.commit()

        async with async_session() as db:
            total_before = await _count(db)
            await db.execute(
                text(
                    "UPDATE vault_audit SET signature = repeat('0', 128) "
                    "WHERE action = 'tamper_me'"
                )
            )
            await db.commit()

        r1 = await _verify()
        r2 = await _verify()
        assert isinstance(r1["verified_by"]["host"], str)
        assert isinstance(r1["verified_by"]["pid"], int)
        assert r1["chain_intact"] is False
        assert r2["chain_intact"] is False  # deterministic across calls

        async with async_session() as db:
            total_after = await _count(db)
            broken_rows = await _count(db, "action = 'audit_chain_broken'")
        assert broken_rows == 0  # verify did NOT append to the chain
        assert total_after == total_before  # count stable across two verifies
    finally:
        await _teardown()


@pytest.mark.asyncio
async def test_sealed_verify_checks_ed25519(client, master_password):
    """Sealed vault: ed25519 rows still verify via the public key; hmac rows are
    reported unverifiable_while_sealed rather than broken."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    provisioned = False
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
        async with async_session() as db:
            await log_action(
                db, actor="t", action="sealed_probe", target=None, detail={}
            )
            await db.commit()
        provisioned = True

        vault.seal()
        assert vault.sealed
        res = await _verify()
        assert "unverifiable_while_sealed" in res
        assert res["chain_intact"] is True
    finally:
        if provisioned:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )
        await _teardown()
