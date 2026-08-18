# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""New (Ed25519) audit chain -- identity lifecycle + tamper/rotation coverage.

Complements tests/test_audit_verify_ed25519.py (intact dual-path, non-mutating
break, sealed verify) with the identity-management + survivability invariants
the migrated chain relies on:

- fingerprint = sha256(pub) and matches the registry + in-RAM signer
- ensure_audit_identity is idempotent (one cluster identity, not per-call)
- resolve_signer_fpr is None pre-provision (legacy clusters keep the hmac chain)
- the identity reloads from the at-rest seed after the in-RAM signer is dropped
- the chain survives a dek_key rotation (seed re-wrapped, old rows still verify)
- payload/detail tamper on an ed25519 row is caught by /audit/verify
- a corrupted ed25519 link breaks the chain and is localised
- ed25519 rows are tagged sig_alg='ed25519' + signer_fpr

Self-contained on the same pattern as test_audit_verify_ed25519.py: unseal,
ensure_audit_identity, exercise, then reset the audit identity + chain so the
session-scoped DB + in-RAM singleton don't leak into downstream tests.
"""

import json

import pytest
from api.app.audit import log_action
from api.app.audit_identity import (
    ensure_audit_identity,
    fingerprint,
    load_audit_identity_into_ram,
    resolve_signer_fpr,
)
from api.app.database import async_session
from api.app.routes.audit import verify_chain
from api.app.vault_state import vault
from sqlalchemy import text


async def _verify():
    async with async_session() as db:
        return await verify_chain(db=db, token_info={"sub": "t"})


async def _reset_identity():
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
    vault._cluster_audit_fpr = None


async def _drop_inram_signer():
    """Simulate a fresh process / post-seal RAM: identity exists at rest in
    vault_config but the live signer + fpr cache are gone."""
    vault._audit_signer = None
    vault._cluster_audit_fpr = None


@pytest.mark.asyncio
async def test_fingerprint_matches_pub_and_registry(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            pub = await ensure_audit_identity(db)
        assert pub is not None
        fpr = fingerprint(pub)
        # in-RAM signer agrees
        assert vault.audit_identity_fpr == fpr
        # resolve_signer_fpr agrees
        async with async_session() as db:
            assert await resolve_signer_fpr(db) == fpr
        # the public key is registered in the signer registry under that fpr
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT public_key FROM vault_audit_signer_certs "
                        "WHERE fingerprint = :f"
                    ),
                    {"f": fpr},
                )
            ).fetchone()
        assert row is not None
        assert bytes(row.public_key) == pub
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_ensure_audit_identity_idempotent(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            pub1 = await ensure_audit_identity(db)
        async with async_session() as db:
            pub2 = await ensure_audit_identity(db)
        assert pub1 == pub2  # the cluster identity is not regenerated
        async with async_session() as db:
            n = (
                await db.execute(text("SELECT count(*) FROM vault_audit_signer_certs"))
            ).scalar()
        assert n == 1
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_resolve_signer_fpr_none_before_provision(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # guarantee no identity at rest or in RAM
    try:
        async with async_session() as db:
            assert await resolve_signer_fpr(db) is None
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_identity_reloads_from_seed_after_signer_dropped(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            pub = await ensure_audit_identity(db)
        fpr = fingerprint(pub)
        async with async_session() as db:
            await log_action(db, actor="t", action="pre_drop", target=None, detail={})
            await db.commit()

        await _drop_inram_signer()
        assert vault.has_audit_identity is False

        async with async_session() as db:
            loaded = await load_audit_identity_into_ram(db)
        assert loaded is True
        assert vault.audit_identity_fpr == fpr  # same identity restored

        res = await _verify()
        assert res["chain_intact"] is True  # the pre-drop ed25519 row still verifies
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_chain_survives_dek_key_rotation(admin_token, client, master_password):
    """The migrated chain must survive a dek_key rotation: the identity key is
    unchanged, its at-rest seed is re-wrapped under the new dek_key, and rows
    signed before the rotation still verify."""
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            pub = await ensure_audit_identity(db)
        fpr = fingerprint(pub)
        async with async_session() as db:
            await log_action(
                db, actor="t", action="pre_rotate", target="x", detail={"k": 1}
            )
            await db.commit()

        r = await client.post(
            "/api/v1/vault/admin/rotate-dek-key",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"current_password": master_password},
        )
        assert r.status_code == 200, r.text

        # identity unchanged + pre-rotation ed25519 rows still verify
        async with async_session() as db:
            assert await resolve_signer_fpr(db) == fpr
        res = await _verify()
        assert res["chain_intact"] is True

        # the re-wrapped seed loads under the NEW dek_key
        await _drop_inram_signer()
        async with async_session() as db:
            assert await load_audit_identity_into_ram(db) is True
        assert vault.audit_identity_fpr == fpr
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_ed25519_detail_tamper_breaks_verify(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
        async with async_session() as db:
            await log_action(
                db, actor="t", action="tamper_detail", target="x", detail={"v": "orig"}
            )
            await db.commit()

        # Flip the detail payload without touching the (now-stale) ed25519 sig.
        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_audit SET detail = CAST(:d AS jsonb) "
                    "WHERE action = 'tamper_detail'"
                ),
                {"d": json.dumps({"v": "HACKED"})},
            )
            await db.commit()

        res = await _verify()
        assert res["chain_intact"] is False
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_ed25519_broken_link_is_localised(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            await ensure_audit_identity(db)
        async with async_session() as db:
            for a in ("link_1", "link_2", "link_3"):
                await log_action(db, actor="t", action=a, target=None, detail={})
            await db.commit()

        # Corrupt the middle row's signature.
        async with async_session() as db:
            mid = (
                await db.execute(
                    text("SELECT id FROM vault_audit WHERE action = 'link_2'")
                )
            ).fetchone()
            await db.execute(
                text(
                    "UPDATE vault_audit SET signature = repeat('0', 128) WHERE id = :id"
                ),
                {"id": mid.id},
            )
            await db.commit()

        res = await _verify()
        assert res["chain_intact"] is False
        assert res.get("broken_id") == str(mid.id)  # break localised to link_2
    finally:
        await _reset_identity()


@pytest.mark.asyncio
async def test_ed25519_rows_tagged_sig_alg_and_signer_fpr(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_identity()  # drop any stale cross-session identity/chain
    try:
        async with async_session() as db:
            pub = await ensure_audit_identity(db)
        fpr = fingerprint(pub)
        async with async_session() as db:
            await log_action(db, actor="t", action="tag_check", target=None, detail={})
            await db.commit()
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT sig_alg, signer_fpr FROM vault_audit "
                        "WHERE action = 'tag_check' ORDER BY id DESC LIMIT 1"
                    )
                )
            ).fetchone()
        assert row.sig_alg == "ed25519"
        assert row.signer_fpr == fpr
    finally:
        await _reset_identity()
