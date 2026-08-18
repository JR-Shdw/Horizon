"""S1 (audit half) -- audit chain stays verifiable + tamper-evident across
key rotations.

Before the fix, a master-password rotation changed ``audit_key`` and
``/audit/verify`` false-broke the whole chain. The fix epochs the chain and
archives retired audit_keys (api/app/audit_keyring.py); verify picks the key
per entry. These tests assert the chain holds across rotations AND that real
tampering of a pre-rotation entry is still caught.
"""

import json

import pytest
from api.app.database import async_session
from sqlalchemy import text

pytestmark = pytest.mark.asyncio

CANON_PW = "test-master-password-2024"


async def _verify(client, headers):
    r = await client.get("/api/v1/vault/audit/verify", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


async def _rotate_password(client, headers, current, new, force=False):
    body = {"current_password": current, "new_password": new}
    if force:
        body["force"] = True
    r = await client.post("/api/v1/vault/rotate-password", headers=headers, json=body)
    assert r.status_code == 200, r.text


async def _restore_password(client, headers, current):
    # Always force: a prior non-emergency rotation in this test leaves the
    # in-window guard armed.
    await _rotate_password(client, headers, current, CANON_PW, force=True)


async def test_chain_survives_password_rotation(client, master_password, admin_token):
    h = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/", headers=h, json={"name": "ae-1", "value": "v1"}
    )
    assert (await _verify(client, h))["chain_intact"] is True

    await _rotate_password(client, h, master_password, "ae-rot-pw-1")
    try:
        res = await _verify(client, h)
        assert res["chain_intact"] is True, res
    finally:
        await _restore_password(client, h, "ae-rot-pw-1")


async def test_chain_survives_dek_rotation(client, master_password, admin_token):
    h = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/", headers=h, json={"name": "ae-2", "value": "v2"}
    )
    assert (await _verify(client, h))["chain_intact"] is True

    r = await client.post(
        "/api/v1/vault/admin/rotate-dek-key",
        headers=h,
        json={"current_password": master_password},
    )
    assert r.status_code == 200, r.text
    res = await _verify(client, h)
    assert res["chain_intact"] is True, res


async def test_chain_survives_two_password_rotations(
    client, master_password, admin_token
):
    h = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/", headers=h, json={"name": "ae-3", "value": "v3"}
    )
    await _rotate_password(client, h, master_password, "ae-rot-A")
    try:
        await client.post(
            "/api/v1/vault/secrets/", headers=h, json={"name": "ae-3b", "value": "v3b"}
        )
        # Second rotation must re-wrap the epoch-0 archive under the newest
        # dek_key; if that re-wrap is missing the first generation's entries
        # become unverifiable.
        await _rotate_password(client, h, "ae-rot-A", "ae-rot-B", force=True)
        res = await _verify(client, h)
        assert res["chain_intact"] is True, res
    finally:
        await _restore_password(client, h, "ae-rot-B")


async def test_list_audit_verified_after_rotation(client, master_password, admin_token):
    h = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/", headers=h, json={"name": "ae-4", "value": "v4"}
    )
    await _rotate_password(client, h, master_password, "ae-rot-list")
    try:
        r = await client.get("/api/v1/vault/audit/?limit=1000", headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["chain_intact"] is True
    finally:
        await _restore_password(client, h, "ae-rot-list")


async def test_tamper_still_detected_after_rotation(
    client, master_password, admin_token
):
    """The invariant: rotation must NOT blind verify to real tampering."""
    h = {"Authorization": f"Bearer {admin_token}"}
    # A distinctively-named pre-rotation entry we will tamper with.
    await client.post(
        "/api/v1/vault/secrets/",
        headers=h,
        json={"name": "ae-tamper", "value": "secret"},
    )

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT id, detail FROM vault_audit "
                    "WHERE target = 'ae-tamper' ORDER BY timestamp DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None
    target_id = str(row.id)
    original_detail = (
        json.dumps(row.detail) if isinstance(row.detail, dict) else row.detail
    )

    await _rotate_password(client, h, master_password, "ae-rot-tamper")
    try:
        # Sanity: clean chain post-rotation.
        assert (await _verify(client, h))["chain_intact"] is True

        # Tamper a pre-rotation (epoch-0) entry's detail directly in the DB.
        async with async_session() as db:
            await db.execute(
                text("UPDATE vault_audit SET detail = :d WHERE id = CAST(:i AS uuid)"),
                {"d": json.dumps({"tampered": True}), "i": target_id},
            )
            await db.commit()

        res = await _verify(client, h)
        assert res["chain_intact"] is False, res

        # Repair so the shared audit table is clean for other tests.
        async with async_session() as db:
            await db.execute(
                text("UPDATE vault_audit SET detail = :d WHERE id = CAST(:i AS uuid)"),
                {"d": original_detail, "i": target_id},
            )
            await db.commit()
        assert (await _verify(client, h))["chain_intact"] is True
    finally:
        await _restore_password(client, h, "ae-rot-tamper")
