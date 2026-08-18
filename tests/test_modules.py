"""Tests for groups, notifications, backup, dynamic, and coverage gaps."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text

# Groups RBAC


@pytest.mark.asyncio
async def test_group_crud(client, master_password, admin_token):
    """Create, list, update, delete a group."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create
    r = await client.post(
        "/api/v1/vault/groups/",
        json={"name": "test-ops", "permissions": {"secrets": "rw"}},
        headers=headers,
    )
    assert r.status_code == 201
    group_id = r.json()["id"]

    # List
    r = await client.get("/api/v1/vault/groups/", headers=headers)
    assert r.status_code == 200
    names = [g["name"] for g in r.json()["items"]]
    assert "test-ops" in names

    # Update
    r = await client.put(
        f"/api/v1/vault/groups/{group_id}",
        json={"permissions": {"secrets": "r", "audit": "r"}},
        headers=headers,
    )
    assert r.status_code == 200

    # Delete
    r = await client.delete(f"/api/v1/vault/groups/{group_id}", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "deleted"


@pytest.mark.asyncio
async def test_group_duplicate(client, master_password, admin_token):
    """Creating a group with an existing name returns 409."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/groups/",
        json={"name": "dup-group", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    r = await client.post(
        "/api/v1/vault/groups/",
        json={"name": "dup-group", "permissions": {"secrets": "rw"}},
        headers=headers,
    )
    assert r.status_code == 409

    # Cleanup
    r = await client.get("/api/v1/vault/groups/", headers=headers)
    gid = next(g["id"] for g in r.json()["items"] if g["name"] == "dup-group")
    await client.delete(f"/api/v1/vault/groups/{gid}", headers=headers)


@pytest.mark.asyncio
async def test_group_invalid_uuid(client, master_password, admin_token):
    """Invalid UUID returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        "/api/v1/vault/groups/not-a-uuid",
        json={"permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_group_members(client, master_password, admin_token):
    """Add and remove members from a group."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create group
    r = await client.post(
        "/api/v1/vault/groups/",
        json={"name": "member-test", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    gid = r.json()["id"]

    # Add member
    r = await client.post(
        f"/api/v1/vault/groups/{gid}/members",
        json={"principal_type": "external", "principal_id": "ldap:jdoe"},
        headers=headers,
    )
    assert r.status_code == 201
    ldap_member_id = r.json()["member_id"]

    r = await client.post(
        f"/api/v1/vault/groups/{gid}/members",
        json={"principal_type": "external", "principal_id": "proxy:jdoe"},
        headers=headers,
    )
    assert r.status_code == 201
    proxy_member_id = r.json()["member_id"]

    # List members
    r = await client.get(f"/api/v1/vault/groups/{gid}/members", headers=headers)
    assert {
        (item["principal_type"], item["principal_id"]) for item in r.json()["items"]
    } == {
        ("external", "ldap:jdoe"),
        ("external", "proxy:jdoe"),
    }

    # Removing one provider identity leaves the other intact.
    r = await client.delete(
        f"/api/v1/vault/groups/{gid}/members/{ldap_member_id}", headers=headers
    )
    assert r.status_code == 200
    r = await client.get(f"/api/v1/vault/groups/{gid}/members", headers=headers)
    assert [item["principal_id"] for item in r.json()["items"]] == ["proxy:jdoe"]
    await client.delete(
        f"/api/v1/vault/groups/{gid}/members/{proxy_member_id}",
        headers=headers,
    )

    # Cleanup
    await client.delete(f"/api/v1/vault/groups/{gid}", headers=headers)


@pytest.mark.asyncio
async def test_group_delete_nonexistent(client, master_password, admin_token):
    """Deleting a nonexistent group returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete(
        "/api/v1/vault/groups/00000000-0000-0000-0000-000000000000",
        headers=headers,
    )
    assert r.status_code == 404


# Notifications


@pytest.mark.asyncio
async def test_notification_channel_crud(client, master_password, admin_token):
    """Create, list, update, delete a notification channel."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create webhook channel
    r = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "test-hook",
            "channel_type": "webhook",
            "config": {"url": "https://hooks.example.com/test"},
            "events": ["secret_updated"],
        },
        headers=headers,
    )
    assert r.status_code == 201
    channel_id = r.json()["id"]

    # List
    r = await client.get("/api/v1/vault/notifications/", headers=headers)
    assert r.status_code == 200
    names = [c["name"] for c in r.json()["items"]]
    assert "test-hook" in names

    # Update
    r = await client.put(
        f"/api/v1/vault/notifications/{channel_id}",
        json={"enabled": False},
        headers=headers,
    )
    assert r.status_code == 200

    # Delete
    r = await client.delete(
        f"/api/v1/vault/notifications/{channel_id}", headers=headers
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_notification_invalid_type(client, master_password, admin_token):
    """Invalid channel type returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/",
        json={"name": "bad", "channel_type": "telegram", "config": {}},
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_notification_mask_secrets(client, master_password, admin_token):
    """List masks sensitive fields (token, password)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "matrix-mask",
            "channel_type": "matrix",
            "config": {
                "homeserver": "https://matrix.example.com",
                "room_id": "!abc:example.com",
                "token": "syt_secret_token",
            },
        },
        headers=headers,
    )
    channel_id = r.json()["id"]

    r = await client.get("/api/v1/vault/notifications/", headers=headers)
    ch = next(c for c in r.json()["items"] if c["name"] == "matrix-mask")
    assert ch["config"]["token"] == "********"
    assert ch["config"]["homeserver"] == "https://matrix.example.com"

    # Cleanup
    await client.delete(f"/api/v1/vault/notifications/{channel_id}", headers=headers)


@pytest.mark.asyncio
async def test_notification_update_empty(client, master_password, admin_token):
    """Update with no fields returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "empty-upd",
            "channel_type": "webhook",
            "config": {"url": "https://x.com"},
        },
        headers=headers,
    )
    cid = r.json()["id"]

    r = await client.put(
        f"/api/v1/vault/notifications/{cid}",
        json={},
        headers=headers,
    )
    assert r.status_code == 400

    await client.delete(f"/api/v1/vault/notifications/{cid}", headers=headers)


# Backup / Restore


@pytest.mark.asyncio
async def test_backup_and_restore(client, master_password, admin_token):
    """Create backup, verify structure, restore."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a secret to backup
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "backup-test-secret", "value": "backup-value"},
        headers=headers,
    )
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "backup-test-reader", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201
    pre_restore_reader = r.json()["token"]
    pre_restore_reader_headers = {"Authorization": f"Bearer {pre_restore_reader}"}
    r = await client.get(
        "/api/v1/vault/secrets/backup-test-secret",
        headers=pre_restore_reader_headers,
    )
    assert r.status_code == 200

    # Create backup
    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "test-backup-passphrase-2024"},
        headers=headers,
    )
    assert r.status_code == 200
    assert "payload" in r.json()
    assert r.json()["secrets_count"] >= 1
    payload = r.json()["payload"]

    # Delete the secret
    await client.delete("/api/v1/vault/secrets/backup-test-secret", headers=headers)

    # Restore: Bloc G dual-context restore requires the age passphrase,
    # the master password of the vault at backup time (here unchanged,
    # so same as current), and operator-typed "RESTORE" confirmation.
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "test-backup-passphrase-2024",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": payload,
        },
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["secrets"] >= 1
    # Restore seals the vault so the stale in-RAM keys are dropped, the
    # caller must re-unseal with the master password used at backup time.
    # The post-restore unseal mints a fresh root token (existing tokens
    # in the browser/test no longer match the new hmac_key state).
    assert body.get("sealed") is True

    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 503

    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    recovery = r.json()
    assert recovery.get("root_token", "").startswith("rh_")

    # Pre-restore tokens are not silently trusted after the restore. The
    # service token lands as a pending rotation stub, and the old admin token
    # was wiped with vault_tokens.
    r = await client.get(
        "/api/v1/vault/secrets/backup-test-secret",
        headers=pre_restore_reader_headers,
    )
    assert r.status_code == 401
    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 401

    headers = {"Authorization": f"Bearer {recovery['root_token']}"}

    # Verify secret is back
    r = await client.get("/api/v1/vault/secrets/backup-test-secret", headers=headers)
    assert r.status_code == 200
    assert r.json()["value"] == "backup-value"
    r = await client.get("/api/v1/vault/tokens/pending/", headers=headers)
    assert r.status_code == 200
    names = [it["name"] for it in r.json()["items"]]
    assert "backup-test-reader" in names

    # Cleanup
    await client.delete("/api/v1/vault/secrets/backup-test-secret", headers=headers)


@pytest.mark.asyncio
async def test_backup_restore_preserves_secret_lifecycle_fields(
    client, master_password, admin_token
):
    """Age restore preserves current secret-row lifecycle metadata.

    Secret ciphertext is still re-keyed under a fresh restore-time DEK; this
    test covers the non-crypto row attributes that must not silently reset.
    """
    from api.app.database import async_session

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "backup-lifecycle-secret",
            "value": "lifecycle-value",
            "metadata": {"owner": "ci", "tier": "dr"},
            "is_honey": True,
        },
        headers=headers,
    )
    assert r.status_code == 201

    created_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    updated_at = datetime(2026, 1, 3, 4, 5, 6, tzinfo=timezone.utc)
    expires_at = datetime.now(timezone.utc) + timedelta(days=14)
    deleted_at = datetime(2026, 1, 4, 5, 6, 7, tzinfo=timezone.utc)
    purge_after = datetime(2026, 2, 4, 5, 6, 7, tzinfo=timezone.utc)

    async with async_session() as db:
        await db.execute(
            text("""
                UPDATE vault_secrets
                   SET created_at = :created_at,
                       updated_at = :updated_at,
                       expires_at = :expires_at,
                       deleted_at = :deleted_at,
                       purge_after = :purge_after
                 WHERE name = 'backup-lifecycle-secret'
            """),
            {
                "created_at": created_at,
                "updated_at": updated_at,
                "expires_at": expires_at,
                "deleted_at": deleted_at,
                "purge_after": purge_after,
            },
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "lifecycle-backup-passphrase"},
        headers=headers,
    )
    assert r.status_code == 200
    payload = r.json()["payload"]

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "lifecycle-backup-passphrase",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": payload,
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json().get("sealed") is True

    async with async_session() as db:
        row = (
            await db.execute(
                text("""
                    SELECT metadata, created_at, updated_at, expires_at,
                           is_honey, deleted_at, purge_after
                    FROM vault_secrets
                    WHERE name = 'backup-lifecycle-secret'
                """)
            )
        ).fetchone()

    assert row is not None
    assert row.metadata == {"owner": "ci", "tier": "dr"}
    assert row.is_honey is True
    assert row.created_at == created_at
    assert row.updated_at == updated_at
    assert row.expires_at == expires_at
    assert row.deleted_at == deleted_at
    assert row.purge_after == purge_after


@pytest.mark.asyncio
async def test_backup_restore_pending_tokens_and_review(
    client, master_password, admin_token
):
    """Round-trip: tokens land in vault_pending_token_rotations (not vault_tokens),
    pending_restore_review flag is set, namespaces + group_members are
    restored, and the next unseal mints a recovery root token with expires_at."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Seed a secret, a token, a group, group members.
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "bk-roundtrip-secret", "value": "v1"},
        headers=headers,
    )
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "bk-roundtrip-token", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201
    g = await client.post(
        "/api/v1/vault/groups/",
        json={"name": "bk-roundtrip-group", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert g.status_code in (200, 201)
    group_id = g.json()["id"]
    await client.post(
        f"/api/v1/vault/groups/{group_id}/members",
        json={
            "principal_type": "external",
            "principal_id": "proxy:bk-roundtrip-user",
        },
        headers=headers,
    )
    token_rows = await client.get("/api/v1/vault/tokens/", headers=headers)
    original_token_id = next(
        item["id"]
        for item in token_rows.json()["items"]
        if item["name"] == "bk-roundtrip-token"
    )
    added_token = await client.post(
        f"/api/v1/vault/groups/{group_id}/members",
        json={"principal_type": "token", "principal_id": original_token_id},
        headers=headers,
    )
    assert added_token.status_code == 201, added_token.text

    # Backup
    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "test-backup-passphrase-2024"},
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["secrets_count"] >= 1
    assert body["tokens_count"] >= 1
    assert body["groups_count"] >= 1
    assert body["group_members_count"] >= 1
    assert "config_count" in body
    assert body["coverage"]["mode"] == "age-logical-partial"
    assert "vault_secret_versions" in body["coverage"]["excluded_tables"]
    payload = body["payload"]

    # Restore: tokens go to pending_token_rotations (NOT vault_tokens).
    # Bloc G dual-context restore: age passphrase + backup master password +
    # operator-typed confirm phrase all required.
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "test-backup-passphrase-2024",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": payload,
        },
        headers=headers,
    )
    assert r.status_code == 200
    restored = r.json()
    assert restored["secrets"] >= 1
    assert restored["tokens_pending_rotation"] >= 1, (
        f"tokens did not land in pending_token_rotations: {restored}"
    )
    assert restored["groups"] >= 1
    assert restored["group_members"] >= 1
    assert restored.get("sealed") is True

    # Post-restore unseal: mints recovery root token with expires_at.
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200
    body = r.json()
    assert body.get("root_token", "").startswith("rh_")
    assert body.get("bootstrap_kind") == "restore-recovery"
    assert body.get("recovery_token_expires_at"), (
        "recovery root token must carry an expires_at"
    )

    # The recovery root token authenticates
    rec_headers = {"Authorization": f"Bearer {body['root_token']}"}
    r = await client.get("/api/v1/vault/secrets/", headers=rec_headers)
    assert r.status_code == 200

    # Status exposes the post-restore state
    r = await client.get("/api/v1/vault/status")
    st = r.json()
    assert st["pending_restore_review"] is True
    assert st["pending_token_rotations_count"] >= 1
    assert st["recovery_token_expires_at"]

    # Pending list contains our stub
    r = await client.get("/api/v1/vault/tokens/pending/", headers=rec_headers)
    assert r.status_code == 200
    pending_items = r.json()["items"]
    names = [it["name"] for it in pending_items]
    assert "bk-roundtrip-token" in names
    pending = next(it for it in pending_items if it["name"] == "bk-roundtrip-token")
    assert pending["group_names"] == ["bk-roundtrip-group"]

    rotated = await client.post(
        f"/api/v1/vault/tokens/pending/{pending['id']}/rotate",
        headers=rec_headers,
    )
    assert rotated.status_code == 200, rotated.text
    token_rows = await client.get("/api/v1/vault/tokens/", headers=rec_headers)
    restored_token_id = next(
        item["id"]
        for item in token_rows.json()["items"]
        if item["name"] == "bk-roundtrip-token"
    )
    group_rows = await client.get("/api/v1/vault/groups/", headers=rec_headers)
    restored_group_id = next(
        item["id"]
        for item in group_rows.json()["items"]
        if item["name"] == "bk-roundtrip-group"
    )
    members = await client.get(
        f"/api/v1/vault/groups/{restored_group_id}/members", headers=rec_headers
    )
    assert ("token", restored_token_id) in {
        (item["principal_type"], item["principal_id"])
        for item in members.json()["items"]
    }

    # Cleanup
    await client.delete(
        "/api/v1/vault/secrets/bk-roundtrip-secret", headers=rec_headers
    )


@pytest.mark.asyncio
async def test_backup_short_passphrase(client, master_password, admin_token):
    """Short passphrase returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "short"},
        headers=headers,
    )
    assert r.status_code == 422


async def _seed_and_restore(
    client, master_password, admin_token, token_names, honey_names=()
):
    """Helper: unseal, seed one secret + N tokens + one group, backup, restore.

    Returns (recovery_root_token_plaintext, list_of_pending_stub_ids).
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "pend-secret", "value": "v"},
        headers=headers,
    )
    honey_names = set(honey_names)
    for name in token_names:
        body = {"name": name, "permissions": {"secrets": "r"}}
        if name in honey_names:
            body["is_honey"] = True
        await client.post(
            "/api/v1/vault/tokens/",
            json=body,
            headers=headers,
        )

    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "pending-rotation-passphrase-1234"},
        headers=headers,
    )
    payload = r.json()["payload"]
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "pending-rotation-passphrase-1234",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": payload,
        },
        headers=headers,
    )
    assert r.status_code == 200

    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    recovery = r.json()["root_token"]
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    r = await client.get("/api/v1/vault/tokens/pending/", headers=rec_headers)
    pendings = r.json()["items"]
    return recovery, pendings


@pytest.mark.asyncio
async def test_pending_token_rotation_flow(client, master_password, admin_token):
    """Rotate a pending stub: fresh plaintext minted, stub deleted, token works."""
    recovery, pendings = await _seed_and_restore(
        client, master_password, admin_token, ["pend-rot-a", "pend-rot-b"]
    )
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    target = next(p for p in pendings if p["name"] == "pend-rot-a")
    r = await client.post(
        f"/api/v1/vault/tokens/pending/{target['id']}/rotate",
        headers=rec_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token"].startswith("rh_")
    assert body["name"] == "pend-rot-a"
    assert "warning" in body
    rotated_plaintext = body["token"]

    # Stub is gone
    r = await client.get("/api/v1/vault/tokens/pending/", headers=rec_headers)
    remaining = [p["name"] for p in r.json()["items"]]
    assert "pend-rot-a" not in remaining
    assert "pend-rot-b" in remaining

    # The rotated token actually works
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {rotated_plaintext}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_pending_honey_token_rotation_preserves_decoy(
    client, master_password, admin_token
):
    """A restored honey token remains a honey token after admin rotation."""
    from api.app.database import async_session

    recovery, pendings = await _seed_and_restore(
        client,
        master_password,
        admin_token,
        ["pend-honey"],
        honey_names={"pend-honey"},
    )
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    target = next(p for p in pendings if p["name"] == "pend-honey")
    assert target["is_honey"] is True
    r = await client.post(
        f"/api/v1/vault/tokens/pending/{target['id']}/rotate",
        headers=rec_headers,
    )
    assert r.status_code == 200
    assert r.json()["is_honey"] is True

    async with async_session() as db:
        row = (
            await db.execute(
                text("""
                    SELECT is_honey
                    FROM vault_tokens
                    WHERE name = 'pend-honey' AND active = true
                """)
            )
        ).fetchone()
    assert row is not None
    assert row.is_honey is True


@pytest.mark.asyncio
async def test_pending_token_revoke_flow(client, master_password, admin_token):
    """DELETE a pending stub: gone with no token emitted."""
    recovery, pendings = await _seed_and_restore(
        client, master_password, admin_token, ["pend-rev-a"]
    )
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    target = next(p for p in pendings if p["name"] == "pend-rev-a")
    r = await client.delete(
        f"/api/v1/vault/tokens/pending/{target['id']}",
        headers=rec_headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"

    r = await client.get("/api/v1/vault/tokens/pending/", headers=rec_headers)
    assert all(p["name"] != "pend-rev-a" for p in r.json()["items"])


@pytest.mark.asyncio
async def test_pending_token_grace_purge(client, master_password, admin_token):
    """Stubs older than grace period are deleted by the reaper SQL.

    We run the reaper body in isolation (not _reaper_loop, which has a
    `while True` daemon shape unsuited for tests) by exercising the same
    DELETE the loop runs.
    """
    from api.app.config import settings as _settings
    from api.app.database import async_session
    from sqlalchemy import text as sa_text

    recovery, pendings = await _seed_and_restore(
        client, master_password, admin_token, ["pend-old"]
    )
    assert pendings
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    days = _settings.restore_rotation_grace_days
    async with async_session() as db:
        # Age the stub well past the grace window
        await db.execute(
            sa_text(
                "UPDATE vault_pending_token_rotations "
                "SET created_at = NOW() - (CAST(:days AS int) * "
                "INTERVAL '1 day') "
                "WHERE name = 'pend-old'"
            ),
            {"days": days + 5},
        )
        await db.commit()

        # Run the reaper SQL (same statement as main.py _reaper_loop)
        await db.execute(
            sa_text(
                "DELETE FROM vault_pending_token_rotations "
                "WHERE created_at < NOW() - "
                "(CAST(:days AS int) * INTERVAL '1 day')"
            ),
            {"days": days},
        )
        await db.commit()

    r = await client.get("/api/v1/vault/tokens/pending/", headers=rec_headers)
    assert all(p["name"] != "pend-old" for p in r.json()["items"])


@pytest.mark.asyncio
async def test_recovery_token_has_expires_at(client, master_password, admin_token):
    """The root-restore token returned at post-restore unseal has expires_at."""
    from datetime import datetime, timezone

    recovery, _ = await _seed_and_restore(
        client, master_password, admin_token, ["pend-exp"]
    )
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    r = await client.get("/api/v1/vault/tokens/", headers=rec_headers)
    rows = r.json()["items"]
    recovery_rows = [
        t for t in rows if (t.get("created_by") or "") == "restore-recovery"
    ]
    assert recovery_rows, f"no restore-recovery root token found in {rows}"
    rec = recovery_rows[0]
    assert rec["expires_at"]
    exp = datetime.fromisoformat(rec["expires_at"])
    now = datetime.now(timezone.utc)
    # Default TTL is 7 days, clamp 1-30; expect between 1 day and 30 days
    assert (exp - now).days >= 0


@pytest.mark.asyncio
async def test_dismiss_review_revokes_recovery_token(
    client, master_password, admin_token
):
    """POST /post-restore-review/dismiss revokes the recovery root token."""
    recovery, _ = await _seed_and_restore(
        client, master_password, admin_token, ["pend-dis"]
    )
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    # The anti-lockout guard requires a separate durable admin before the
    # one-shot recovery token may revoke itself.
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "post-restore-admin",
            "permissions": {"admin": "rw", "secrets": "r"},
        },
        headers=rec_headers,
    )
    assert r.status_code == 201
    replacement = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/post-restore-review/dismiss", headers=rec_headers
    )
    assert r.status_code == 200
    body = r.json()
    assert body["revoked_recovery_tokens"] >= 1
    # Caller used the recovery root token itself -> warning surfaced
    assert "warning" in body

    # The recovery root token is now revoked, re-using it should 401
    r = await client.get("/api/v1/vault/secrets/", headers=rec_headers)
    assert r.status_code == 401

    # The replacement administrator remains usable after recovery cleanup.
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {replacement}"},
    )
    assert r.status_code == 200

    # Flag is gone
    r = await client.get("/api/v1/vault/status")
    assert r.json()["pending_restore_review"] is False


@pytest.mark.asyncio
async def test_namespace_scoped_token_can_rotate_only_own_ns(
    client, master_password, admin_token
):
    """A token with namespaces:[prod] cannot rotate a pending in staging."""
    recovery, pendings = await _seed_and_restore(
        client, master_password, admin_token, ["pend-prod", "pend-staging"]
    )
    rec_headers = {"Authorization": f"Bearer {recovery}"}

    # Move one stub into 'prod' and the other into 'staging' via direct SQL
    # (simpler than orchestrating the full namespace lifecycle for this test)
    from api.app.database import async_session
    from sqlalchemy import text as sa_text

    async with async_session() as db:
        await db.execute(
            sa_text(
                "UPDATE vault_pending_token_rotations "
                "SET namespace = 'prod' WHERE name = 'pend-prod'"
            )
        )
        await db.execute(
            sa_text(
                "UPDATE vault_pending_token_rotations "
                "SET namespace = 'staging' WHERE name = 'pend-staging'"
            )
        )
        await db.commit()

    # Mint a namespace-restricted operator token (prod only) using the
    # recovery root token, which can grant anything.
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ns-scoped-prod",
            "permissions": {
                "tokens": "rw",
                "secrets": "r",
                "namespaces": ["prod"],
            },
        },
        headers=rec_headers,
    )
    assert r.status_code == 201
    prod_token = r.json()["token"]
    prod_headers = {"Authorization": f"Bearer {prod_token}"}

    # List visible pendings, should only show 'prod'
    r = await client.get("/api/v1/vault/tokens/pending/", headers=prod_headers)
    visible = [p["name"] for p in r.json()["items"]]
    assert "pend-prod" in visible
    assert "pend-staging" not in visible

    # Direct rotate on staging stub via prod token -> 403
    r = await client.get("/api/v1/vault/tokens/pending/", headers=rec_headers)
    all_pendings = {p["name"]: p["id"] for p in r.json()["items"]}
    staging_id = all_pendings["pend-staging"]
    r = await client.post(
        f"/api/v1/vault/tokens/pending/{staging_id}/rotate",
        headers=prod_headers,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_backup_wrong_passphrase(client, master_password, admin_token):
    """Restore with wrong passphrase returns 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "correct-passphrase-here"},
        headers=headers,
    )
    payload = r.json()["payload"]

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "wrong-passphrase-oops",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": payload,
        },
        headers=headers,
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_backup_invalid_payload(client, master_password, admin_token):
    """Non-hex payload returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "doesnt-matter-1234",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": "not-hex!",
        },
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_restore_rejects_wrong_backup_master_password(
    client, master_password, admin_token
):
    """Bloc G: wrong master_password_backup must return 401.

    The BackupCryptoContext constructor validates master_check from
    the backup payload against the password; mismatch raises before
    any DB write happens.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Take a backup under the current master password.
    r = await client.post(
        "/api/v1/vault/backup/create",
        json={"passphrase": "backup-pass-1234abcd"},
        headers=headers,
    )
    payload = r.json()["payload"]

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "backup-pass-1234abcd",
            "master_password_backup": "wrong-master-password",
            "confirm_phrase": "RESTORE",
            "payload": payload,
        },
        headers=headers,
    )
    assert r.status_code == 401
    assert "master password" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_restore_rejects_missing_confirm_phrase(
    client, master_password, admin_token
):
    """Bloc G: body without confirm_phrase fails Pydantic validation."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "doesnt-matter-1234",
            "master_password_backup": master_password,
            "payload": "deadbeef",
        },
        headers=headers,
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_restore_rejects_wrong_confirm_phrase(
    client, master_password, admin_token
):
    """Bloc G: confirm_phrase must be exactly 'RESTORE'. Case-sensitive."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    for bad in ("restore", "Restore", "RESTORE ", "WIPE", ""):
        r = await client.post(
            "/api/v1/vault/backup/restore",
            json={
                "passphrase": "doesnt-matter-1234",
                "master_password_backup": master_password,
                "confirm_phrase": bad,
                "payload": "deadbeef",
            },
            headers=headers,
        )
        assert r.status_code == 422, f"confirm_phrase={bad!r} should be rejected"


# Dynamic secrets, engine + role CRUD (no real DB connection)


@pytest.mark.asyncio
async def test_dynamic_engine_crud(client, master_password, admin_token):
    """Create and delete a dynamic engine."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "test-pg",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pass@db:5432/mydb",
        },
        headers=headers,
    )
    assert r.status_code == 201
    engine_id = r.json()["id"]

    # List
    r = await client.get("/api/v1/vault/dynamic/engines", headers=headers)
    assert r.status_code == 200
    names = [e["name"] for e in r.json()["items"]]
    assert "test-pg" in names

    # Delete
    r = await client.delete(
        f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_dynamic_invalid_engine_type(client, master_password, admin_token):
    """Invalid engine type returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "bad-engine",
            "engine_type": "sqlite",
            "connection_url": "sqlite:///test.db",
        },
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_dynamic_role_crud(client, master_password, admin_token):
    """Create a role for an engine."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create engine
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "role-test-pg",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pass@db:5432/mydb",
        },
        headers=headers,
    )
    engine_id = r.json()["id"]

    # Create role
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "readonly",
            "creation_sql": "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )
    assert r.status_code == 201

    # List roles
    r = await client.get(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles", headers=headers
    )
    assert len(r.json()["items"]) == 1
    assert r.json()["items"][0]["name"] == "readonly"

    # Cleanup
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_dynamic_leases_empty(client, master_password, admin_token):
    """Leases list is empty when no credentials generated."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/dynamic/leases", headers=headers)
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)


@pytest.mark.asyncio
async def test_dynamic_engine_not_found(client, master_password, admin_token):
    """Deleting nonexistent engine returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete(
        "/api/v1/vault/dynamic/engines/00000000-0000-0000-0000-000000000000",
        headers=headers,
    )
    assert r.status_code == 404


# Dynamic: generate credentials with mocked DB


@pytest.mark.asyncio
async def test_dynamic_generate_creds_mock(client, master_password, admin_token):
    """Generate credentials with mocked asyncpg connection."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create engine + role
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "gen-test-pg",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pass@db:5432/test",
        },
        headers=headers,
    )
    engine_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "readwrite",
            "creation_sql": "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )

    # Mock asyncpg.connect so we don't need a real target DB
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.close = AsyncMock()

    with patch(
        "api.app.dynamic_engines.postgresql.asyncpg.connect",
        return_value=mock_conn,
    ):
        r = await client.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/creds/readwrite",
            json={"ttl_seconds": 300},
            headers=headers,
        )

    assert r.status_code == 200
    data = r.json()
    assert data["username"].startswith("rh_readwrite_")
    assert len(data["password"]) == 32
    assert "lease_id" in data
    assert data["ttl_seconds"] == 300

    # Revoke the lease
    lease_id = data["lease_id"]
    with patch(
        "api.app.dynamic_engines.postgresql.asyncpg.connect",
        return_value=mock_conn,
    ):
        r = await client.post(
            f"/api/v1/vault/dynamic/leases/{lease_id}/revoke",
            headers=headers,
        )
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"

    # Cleanup
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_dynamic_creds_role_not_found(client, master_password, admin_token):
    """Generate creds for nonexistent role returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "norole-pg",
            "engine_type": "postgresql",
            "connection_url": "postgresql://a:b@c:5432/d",
        },
        headers=headers,
    )
    engine_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/nonexistent",
        headers=headers,
    )
    assert r.status_code == 404

    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_dynamic_revoke_not_found(client, master_password, admin_token):
    """Revoke nonexistent lease returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/leases/00000000-0000-0000-0000-000000000000/revoke",
        headers=headers,
    )
    assert r.status_code == 404


# Notifications: dispatch + send with mocks


@pytest.mark.asyncio
async def test_notification_test_channel(client, master_password, admin_token):
    """Test channel endpoint with mocked webhook."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "test-send",
            "channel_type": "webhook",
            "config": {"url": "https://hooks.example.com/test"},
        },
        headers=headers,
    )
    cid = r.json()["id"]

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = lambda: None

    with patch("api.app.routes.notifications.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.post = AsyncMock(return_value=mock_resp)
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client.return_value = mock_instance

        r = await client.post(
            f"/api/v1/vault/notifications/{cid}/test", headers=headers
        )

    assert r.status_code == 200
    assert r.json()["status"] == "sent"

    await client.delete(f"/api/v1/vault/notifications/{cid}", headers=headers)


@pytest.mark.asyncio
async def test_notification_test_not_found(client, master_password, admin_token):
    """Test nonexistent channel returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/00000000-0000-0000-0000-000000000000/test",
        headers=headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_notification_delete_not_found(client, master_password, admin_token):
    """Delete nonexistent channel returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete(
        "/api/v1/vault/notifications/00000000-0000-0000-0000-000000000000",
        headers=headers,
    )
    assert r.status_code == 404


# Notifications: unit tests for send functions


class TestNotificationSend:
    @pytest.mark.asyncio
    async def test_send_webhook_ssrf_blocked(self):
        """Webhook to localhost is blocked."""
        from api.app.routes.notifications import _send_webhook

        with pytest.raises(ValueError, match="localhost"):
            await _send_webhook({"url": "http://localhost:8080/admin"}, "test", "msg")

    @pytest.mark.asyncio
    async def test_send_webhook_metadata_blocked(self):
        """Webhook to AWS metadata endpoint is blocked."""
        from api.app.routes.notifications import _send_webhook

        with pytest.raises(ValueError, match="metadata"):
            await _send_webhook(
                {"url": "http://169.254.169.254/latest/meta-data"},
                "test",
                "msg",
            )

    @pytest.mark.asyncio
    async def test_send_matrix_missing_config(self):
        """Matrix with incomplete config raises ValueError."""
        from api.app.routes.notifications import _send_matrix

        with pytest.raises(ValueError, match="Matrix config"):
            await _send_matrix({}, "test", "msg")

    @pytest.mark.asyncio
    async def test_send_webhook_missing_url(self):
        """Webhook with no URL raises ValueError."""
        from api.app.routes.notifications import _send_webhook

        with pytest.raises(ValueError, match="url"):
            await _send_webhook({}, "test", "msg")

    @pytest.mark.asyncio
    async def test_send_notification_email_missing_config(self):
        """Email with no smtp_host/to raises ValueError."""
        from api.app.routes.notifications import _send_email

        with pytest.raises(ValueError, match="smtp_host"):
            await _send_email({}, "test", "msg")

    @pytest.mark.asyncio
    async def test_send_notification_unknown_type(self):
        """Unknown channel type logs warning."""
        from api.app.routes.notifications import _send_notification

        await _send_notification("carrier_pigeon", {}, "test", "msg")


# Secrets: version history + rollback + export


@pytest.mark.asyncio
async def test_secret_version_history(client, master_password, admin_token):
    """Create, update, check version list, read old version."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create v1
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ver-history", "value": "value-v1"},
        headers=headers,
    )

    # Update to v2
    await client.put(
        "/api/v1/vault/secrets/ver-history",
        json={"value": "value-v2"},
        headers=headers,
    )

    # List versions
    r = await client.get("/api/v1/vault/secrets/ver-history/versions", headers=headers)
    assert r.status_code == 200
    versions = r.json()["versions"]
    assert len(versions) >= 2

    # Read v1
    r = await client.get(
        "/api/v1/vault/secrets/ver-history/versions/1", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["value"] == "value-v1"

    # Read v2
    r = await client.get(
        "/api/v1/vault/secrets/ver-history/versions/2", headers=headers
    )
    assert r.json()["value"] == "value-v2"

    # Cleanup
    await client.delete("/api/v1/vault/secrets/ver-history", headers=headers)


@pytest.mark.asyncio
async def test_secret_rollback(client, master_password, admin_token):
    """Rollback to a previous version."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rollback-test", "value": "original"},
        headers=headers,
    )
    await client.put(
        "/api/v1/vault/secrets/rollback-test",
        json={"value": "changed"},
        headers=headers,
    )

    # Rollback to v1
    r = await client.post(
        "/api/v1/vault/secrets/rollback-test/rollback/1", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["restored_from"] == 1
    assert r.json()["new_version"] == 3

    # Verify value is back
    r = await client.get("/api/v1/vault/secrets/rollback-test", headers=headers)
    assert r.json()["value"] == "original"
    assert r.json()["version"] == 3

    await client.delete("/api/v1/vault/secrets/rollback-test", headers=headers)


@pytest.mark.asyncio
async def test_secret_rollback_version_not_found(client, master_password, admin_token):
    """Rollback to nonexistent version returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rb-404", "value": "val"},
        headers=headers,
    )

    r = await client.post("/api/v1/vault/secrets/rb-404/rollback/99", headers=headers)
    assert r.status_code == 404

    await client.delete("/api/v1/vault/secrets/rb-404", headers=headers)


@pytest.mark.asyncio
async def test_secret_version_not_found(client, master_password, admin_token):
    """Read nonexistent version returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ver-404", "value": "val"},
        headers=headers,
    )

    r = await client.get("/api/v1/vault/secrets/ver-404/versions/99", headers=headers)
    assert r.status_code == 404

    await client.delete("/api/v1/vault/secrets/ver-404", headers=headers)


@pytest.mark.asyncio
async def test_secret_export_endpoint_removed(client, master_password, admin_token):
    """Plaintext bulk export is intentionally removed; age backup remains."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get(
        "/api/v1/vault/secrets/export?namespace=cleartext-export-removed",
        headers=headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_secret_export_endpoint_removed_for_non_admin(
    client, master_password, admin_token
):
    """Plaintext bulk export removal is independent from admin scope."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a non-root token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "export-reader", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    reader_token = r.json()["token"]

    r = await client.get(
        "/api/v1/vault/secrets/export?namespace=cleartext-export-removed",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert r.status_code == 404


# auth_ldap: _ldap_escape unit test


class TestLdapEscape:
    def test_normal_username(self):
        from api.app.routes.auth_ldap import _ldap_escape

        assert _ldap_escape("jdoe") == "jdoe"

    def test_asterisk(self):
        from api.app.routes.auth_ldap import _ldap_escape

        assert _ldap_escape("j*doe") == "j\\2adoe"

    def test_parentheses(self):
        from api.app.routes.auth_ldap import _ldap_escape

        assert _ldap_escape("j(d)oe") == "j\\28d\\29oe"

    def test_backslash(self):
        from api.app.routes.auth_ldap import _ldap_escape

        assert _ldap_escape("j\\doe") == "j\\5cdoe"

    def test_null_byte(self):
        from api.app.routes.auth_ldap import _ldap_escape

        assert _ldap_escape("j\x00doe") == "j\\00doe"

    def test_injection_attempt(self):
        from api.app.routes.auth_ldap import _ldap_escape

        result = _ldap_escape("*)(uid=*))(|(uid=*")
        assert "*" not in result
        assert "(" not in result
        assert ")" not in result
