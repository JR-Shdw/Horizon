# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Coverage gaps in api/app/auth.py.

Targets the four code paths still uncovered after the existing suite :

  * lazy migration on first hit after a non-emergency rotate-password
    (auth.py L66-L84)         - old_hash matches a row, row is re-hashed
    (auth.py L124-L134)       - once every active token migrated, the
                                prev_hmac_key entry is purged from
                                vault_config and from vault state.

  * `resolve_namespace_ids`   (auth.py L256-L289) - name resolution,
    UUID short-circuit, archived ns dropped, non-string entries skipped,
    WARN on unknown names.

  * `check_namespace_membership` branches not exercised elsewhere :
    not-found / archived -> 404, agnostic-mode success when the claim
    matches the UUID (L355), strict-mode admin bypass on a pure API
    token (L364-L376).

The lazy-migration tests stub `vault.set_prev_hmac()` directly with a
random key so we don't have to drive a full /rotate-password cycle (and
its cleanup) through the API - that path is already covered by
test_coverage_95.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_token(name: str, token_hash: str, permissions: dict) -> str:
    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text("""
                    INSERT INTO vault_tokens
                        (name, token_hash, permissions, created_by)
                    VALUES (:name, :hash, CAST(:perms AS jsonb), 'auth-cov')
                    ON CONFLICT (name) WHERE active DO UPDATE SET
                        token_hash = :hash,
                        permissions = CAST(:perms AS jsonb),
                        last_used_at = NULL
                    RETURNING id
                """),
                {
                    "name": name,
                    "hash": token_hash,
                    "perms": json.dumps(permissions),
                },
            )
        ).fetchone()
        await db.commit()
        return str(row.id)


async def _seed_group(name: str) -> str:
    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text("""
                    INSERT INTO vault_groups (name, permissions, source)
                    VALUES (:n, '{"admin": "rw"}'::jsonb, 'local')
                    RETURNING id
                """),
                {"n": name},
            )
        ).fetchone()
        await db.commit()
        return str(row.id)


async def _seed_namespace(
    name: str,
    owner_group_id: str,
    *,
    enforce_membership: bool = False,
    archived: bool = False,
) -> str:
    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text("""
                    INSERT INTO vault_namespaces
                        (name, owner_group_id, enforce_membership, archived_at)
                    VALUES (
                        :n,
                        CAST(:gid AS uuid),
                        :enforce,
                        CASE WHEN :archived THEN NOW() ELSE NULL END
                    )
                    RETURNING id
                """),
                {
                    "n": name,
                    "gid": owner_group_id,
                    "enforce": enforce_membership,
                    "archived": archived,
                },
            )
        ).fetchone()
        await db.commit()
        return str(row.id)


# ---------------------------------------------------------------------------
# Cleanup fixture, every row created by a test in this file gets removed
# afterwards so it never collides with other test files in the session.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _wipe_authcov_rows():
    from api.app.database import async_session
    from api.app.vault_state import vault

    async def _wipe():
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_tokens WHERE name LIKE 'authcov-%'")
            )
            await db.execute(
                text("DELETE FROM vault_namespaces WHERE name LIKE 'authcov%'")
            )
            await db.execute(
                text("DELETE FROM vault_groups WHERE name LIKE 'authcov-%'")
            )
            await db.execute(
                text(
                    "DELETE FROM vault_config "
                    "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                )
            )
            await db.commit()
        vault.clear_prev_hmac()

    await _wipe()
    yield
    await _wipe()


# ---------------------------------------------------------------------------
# Lazy migration, auth.py L64-L84
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lazy_migration_rehashes_token_with_current_key(
    client, master_password, admin_token
):
    """Old token (hashed under prev_hmac_key) authenticates and gets
    silently re-hashed under the current hmac_key."""
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    raw = generate_token()
    fake_old_key = os.urandom(32)
    old_hash = _hmac.new(fake_old_key, raw.encode(), hashlib.sha512).hexdigest()
    new_hash_expected = await vault.hmac_sha512_hex(raw)
    assert old_hash != new_hash_expected, (
        "test invariant : prev hash must differ from current hash"
    )

    token_id = await _seed_token("authcov-legacy", old_hash, {"secrets": "r"})

    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('prev_hmac_key', 'test-authority-marker') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        )
        await db.commit()

    # Wire prev_hmac in vault state so hmac_sha512_hex_prev() returns old_hash
    # for `raw`. The wrapper handles _encrypt() internally.
    vault.set_prev_hmac(fake_old_key)
    try:
        r = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {raw}"},
        )
    finally:
        # Force-clear so a failure mid-test doesn't leak prev_hmac state
        # into later tests in the same session.
        vault.clear_prev_hmac()

    assert r.status_code == 200, r.text
    assert r.json()["name"] == "authcov-legacy"

    async with async_session() as db:
        stored = (
            await db.execute(
                text(
                    "SELECT token_hash, last_used_at FROM vault_tokens "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": token_id},
            )
        ).fetchone()
    assert stored.token_hash == new_hash_expected, "row should be re-hashed"
    assert stored.last_used_at is not None


@pytest.mark.asyncio
async def test_stale_prev_hmac_cache_cannot_authorize_without_db_marker(
    client, master_password
):
    """A stale master cache cannot extend migration after durable expiry."""
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    raw = generate_token()
    fake_old_key = os.urandom(32)
    old_hash = _hmac.new(fake_old_key, raw.encode(), hashlib.sha512).hexdigest()
    await _seed_token("authcov-stale-prev", old_hash, {"secrets": "r"})

    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
            )
        )
        await db.commit()

    vault.set_prev_hmac(fake_old_key)
    try:
        response = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {raw}"},
        )
    finally:
        vault.clear_prev_hmac()

    assert response.status_code == 401, response.text
    async with async_session() as db:
        stored_hash = (
            await db.execute(
                text(
                    "SELECT token_hash FROM vault_tokens "
                    "WHERE name = 'authcov-stale-prev'"
                )
            )
        ).scalar_one()
    assert stored_hash == old_hash


@pytest.mark.asyncio
async def test_lazy_migration_purges_prev_hmac_when_all_migrated(
    client, master_password, admin_token
):
    """When the migrating token is the LAST active token without
    last_used_at, the migration purges prev_hmac_key from
    vault_config and from vault state."""
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # 1. Make sure every other active token has last_used_at != NULL so the
    #    cleanup query returns 0. We don't know which other tokens exist
    #    in this session, just touch them all.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_tokens SET last_used_at = NOW() "
                "WHERE active = true AND last_used_at IS NULL"
            )
        )
        # Seed the paired vault_config rows so the cleanup proves it removes
        # both the wrapped key and its migration-window timestamp.
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES
                    ('prev_hmac_key', :v),
                    ('prev_hmac_rotated_at', '2026-01-01T00:00:00+00:00')
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """),
            {"v": "deadbeef"},
        )
        await db.commit()

    raw = generate_token()
    fake_old_key = os.urandom(32)
    old_hash = _hmac.new(fake_old_key, raw.encode(), hashlib.sha512).hexdigest()
    await _seed_token("authcov-lastmig", old_hash, {"secrets": "r"})

    # Roll the cleanup AFTER seeding so our new row's last_used_at stays NULL
    # - but it must be the ONLY one. (Cleanup query : count active tokens
    # with last_used_at IS NULL after the migrating row's UPDATE.)
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_tokens SET last_used_at = NOW() "
                "WHERE active = true AND last_used_at IS NULL "
                "AND name <> 'authcov-lastmig'"
            )
        )
        await db.commit()

    vault.set_prev_hmac(fake_old_key)
    try:
        r = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {raw}"},
        )
    finally:
        # Just in case the cleanup branch didn't run for any reason.
        vault.clear_prev_hmac()
    assert r.status_code == 200, r.text

    # Both vault_config rows are gone.
    async with async_session() as db:
        leftovers = (
            await db.execute(
                text(
                    "SELECT key FROM vault_config "
                    "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                )
            )
        ).fetchall()
    assert leftovers == [], "paired prev_hmac state should be purged after migration"
    # vault state cleared (single-worker test, no RPC client -> property is honest)
    assert vault.has_prev_hmac is False


# ---------------------------------------------------------------------------
# resolve_namespace_ids: auth.py L241-L289
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_namespace_ids_no_claim_returns_none():
    from api.app.auth import resolve_namespace_ids
    from api.app.database import async_session

    async with async_session() as db:
        # Empty perms
        assert await resolve_namespace_ids(db, {"name": "x"}) is None
        # No `namespaces` key
        assert (
            await resolve_namespace_ids(db, {"permissions": {"secrets": "r"}}) is None
        )
        # A present but empty claim is restricted to no namespaces.
        assert (
            await resolve_namespace_ids(db, {"permissions": {"namespaces": []}})
            == set()
        )


@pytest.mark.asyncio
async def test_resolve_namespace_ids_uuid_only_short_circuits():
    """UUID-shaped strings are accepted as-is, no DB lookup needed."""
    from api.app.auth import resolve_namespace_ids
    from api.app.database import async_session

    fake_uuid = str(uuid.uuid4())
    async with async_session() as db:
        out = await resolve_namespace_ids(
            db,
            {
                "name": "authcov-uuid",
                "permissions": {"namespaces": [fake_uuid]},
            },
        )
    assert out == {fake_uuid}


@pytest.mark.asyncio
async def test_resolve_namespace_ids_treats_invalid_uuid_shape_as_name():
    from api.app.auth import resolve_namespace_ids, resolve_namespace_names
    from api.app.database import async_session

    gid = await _seed_group("authcov-uuid-shape-grp")
    namespace_name = "authcovx-name-spac-like-identifierxx"
    namespace_id = await _seed_namespace(namespace_name, gid)

    async with async_session() as db:
        token_info = {
            "name": "authcov-uuid-shape",
            "permissions": {"namespaces": [namespace_name]},
        }
        out = await resolve_namespace_ids(
            db,
            token_info,
        )
        resolved_names = await resolve_namespace_names(db, token_info)

    assert out == {namespace_id}
    assert resolved_names == {namespace_name}


@pytest.mark.asyncio
async def test_resolve_namespace_ids_skips_non_string_entries():
    """Non-string entries in the claim list are silently dropped."""
    from api.app.auth import resolve_namespace_ids
    from api.app.database import async_session

    fake_uuid = str(uuid.uuid4())
    async with async_session() as db:
        out = await resolve_namespace_ids(
            db,
            {
                "name": "authcov-nonstr",
                "permissions": {"namespaces": [fake_uuid, 42, None, {"x": 1}]},
            },
        )
    assert out == {fake_uuid}


@pytest.mark.asyncio
async def test_resolve_namespace_ids_resolves_names_warns_on_missing(caplog):
    """Names are resolved against vault_namespaces, unknown names are
    dropped (NOT 403) with a WARN. Archived namespaces are excluded
    by the SQL filter so their name lands in the missing set too."""
    from api.app.auth import resolve_namespace_ids
    from api.app.database import async_session

    gid = await _seed_group("authcov-resolver-grp")
    live_id = await _seed_namespace("authcov-live", gid)
    await _seed_namespace("authcov-arch", gid, archived=True)
    extra_uuid = str(uuid.uuid4())

    caplog.set_level(logging.WARNING, logger="rhorizon.auth")

    async with async_session() as db:
        out = await resolve_namespace_ids(
            db,
            {
                "name": "authcov-mixed\nFORGED",
                "permissions": {
                    "namespaces": [
                        "authcov-live",  # resolves
                        "authcov-arch",  # excluded (archived) -> missing
                        "authcov-ghost",  # never existed -> missing
                        extra_uuid,  # UUID short-circuit
                    ]
                },
            },
        )

    assert live_id in out
    assert extra_uuid in out
    # ghost + archived names are NOT resolved
    assert "authcov-ghost" not in out
    # WARN line emitted with both missing names sorted
    matching = [r for r in caplog.records if r.name == "rhorizon.auth"]
    assert matching, "expected a WARN log on unknown namespaces"
    msg = matching[-1].getMessage()
    assert "authcov-ghost" in msg and "authcov-arch" in msg
    assert "\n" not in msg
    assert r"authcov-mixed\nFORGED" in msg


@pytest.mark.asyncio
async def test_resolve_namespace_names_drops_archived_and_unknown():
    """Legacy names and UUID claims must both resolve through active namespaces."""
    from api.app.auth import resolve_namespace_names
    from api.app.database import async_session

    gid = await _seed_group("authcov-name-resolver-grp")
    live_id = await _seed_namespace("authcov-name-live", gid)
    await _seed_namespace("authcov-name-archived", gid, archived=True)

    async with async_session() as db:
        out = await resolve_namespace_names(
            db,
            {
                "permissions": {
                    "namespaces": [
                        "authcov-name-live",
                        live_id,
                        "authcov-name-archived",
                        "authcov-name-unknown",
                    ]
                }
            },
        )

    assert out == {"authcov-name-live"}


# ---------------------------------------------------------------------------
# check_namespace_membership: L325-L394
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_namespace_membership_404_when_not_found():
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(
                db,
                {"name": "authcov-x", "permissions": {"admin": "rw"}},
                str(uuid.uuid4()),
            )
    assert exc.value.status_code == 404
    assert "not found" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_check_namespace_membership_404_when_archived():
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    gid = await _seed_group("authcov-arch-grp")
    ns_id = await _seed_namespace("authcov-arch-ns", gid, archived=True)

    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(
                db,
                {"name": "authcov-x", "permissions": {"admin": "rw"}},
                ns_id,
            )
    assert exc.value.status_code == 404
    assert "archived" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_check_namespace_membership_agnostic_claim_match_succeeds():
    """Agnostic ns + non-root token whose `namespaces` claim contains
    the ns UUID -> success path (auth.py L355)."""
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session

    gid = await _seed_group("authcov-agn-grp")
    ns_id = await _seed_namespace("authcov-agn-ns", gid, enforce_membership=False)

    token_info = {
        "name": "authcov-scoped",
        "permissions": {"secrets": "rw", "namespaces": [ns_id]},
    }
    async with async_session() as db:
        ns = await check_namespace_membership(db, token_info, ns_id)
    assert str(ns.id) == ns_id
    assert ns.enforce_membership is False


@pytest.mark.asyncio
async def test_check_namespace_membership_strict_admin_api_token_bypasses_with_audit():
    """Strict ns + admin scope on a *non-human* (API) token -> bypass with
    a loud `admin_bypass_namespace_rbac` audit entry (auth.py L362-L376)."""
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session

    gid = await _seed_group("authcov-strict-grp")
    ns_id = await _seed_namespace("authcov-strict-ns", gid, enforce_membership=True)

    token_info = {
        "name": "authcov-api-admin",  # no `proxy:`/`ldap:` prefix -> API token
        "permissions": {"admin": "rw"},
    }
    async with async_session() as db:
        ns = await check_namespace_membership(db, token_info, ns_id)
        # Do not commit the caller's session. The break-glass audit uses its own
        # committed session and must survive this context's rollback.
    assert str(ns.id) == ns_id
    assert ns.enforce_membership is True

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT actor, target, detail FROM vault_audit "
                    "WHERE action = 'admin_bypass_namespace_rbac' "
                    "AND target = 'authcov-strict-ns' "
                    "ORDER BY timestamp DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None, "expected admin_bypass audit row"
    assert row.actor == "authcov-api-admin"
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail.get("namespace_id") == ns_id
    assert detail.get("write") is True


@pytest.mark.asyncio
async def test_check_namespace_membership_strict_admin_human_session_does_not_bypass():
    """Strict ns + admin claim on a human session token (`proxy:`) -> must
    NOT take the bypass path. With no group membership the actor gets 403,
    proving the `is_external_session` guard fires."""
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    gid = await _seed_group("authcov-human-grp")
    ns_id = await _seed_namespace("authcov-human-ns", gid, enforce_membership=True)

    token_info = {
        "name": "proxy:authcov-bob",  # human session - bypass disabled
        "permissions": {"admin": "rw"},
    }
    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(db, token_info, ns_id)
    assert exc.value.status_code == 403
    assert "owner group" in exc.value.detail


@pytest.mark.asyncio
async def test_strict_namespace_without_owner_group_logs_name_safely(caplog):
    """A malformed strict namespace fails closed without allowing log injection."""
    from api.app.auth import check_namespace_membership
    from fastapi import HTTPException

    namespace_name = "authcov-ownerless\nFORGED"
    ns_id = str(uuid.uuid4())
    row = SimpleNamespace(
        id=uuid.UUID(ns_id),
        name=namespace_name,
        owner_group_id=None,
        enforce_membership=True,
        delete_protection=False,
        archived_at=None,
    )

    class _Result:
        def fetchone(self):
            return row

    class _LegacyRowSession:
        async def execute(self, *args, **kwargs):
            return _Result()

    caplog.set_level(logging.ERROR, logger="rhorizon.auth")

    with pytest.raises(HTTPException) as exc:
        await check_namespace_membership(
            _LegacyRowSession(),
            {"name": "proxy:authcov-user", "permissions": {"secrets": "r"}},
            ns_id,
        )

    assert exc.value.status_code == 403
    messages = [record.getMessage() for record in caplog.records]
    assert messages
    assert "\n" not in messages[-1]
    assert r"authcov-ownerless\nFORGED" in messages[-1]


@pytest.mark.asyncio
async def test_check_namespace_membership_agnostic_claim_mismatch_raises_403():
    """Agnostic ns + non-root token whose `namespaces` claim does NOT
    contain the ns UUID -> 403 (auth.py L353-L354)."""
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    gid = await _seed_group("authcov-mismatch-grp")
    ns_id = await _seed_namespace("authcov-mismatch-ns", gid, enforce_membership=False)
    other_uuid = str(uuid.uuid4())  # token claims a different ns

    token_info = {
        "name": "authcov-mismatch",
        "permissions": {"secrets": "rw", "namespaces": [other_uuid]},
    }
    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(db, token_info, ns_id)
    assert exc.value.status_code == 403
    assert "authcov-mismatch-ns" in exc.value.detail


@pytest.mark.asyncio
async def test_check_namespace_membership_empty_admin_claim_does_not_bypass():
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    gid = await _seed_group("authcov-empty-claim-grp")
    ns_id = await _seed_namespace(
        "authcov-empty-claim-ns",
        gid,
        enforce_membership=False,
    )
    token_info = {
        "name": "authcov-empty-claim-admin",
        "permissions": {"admin": "rw", "namespaces": []},
    }

    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(db, token_info, ns_id)

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_check_namespace_membership_malformed_admin_grant_does_not_bypass():
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    gid = await _seed_group("authcov-malformed-admin-grp")
    ns_id = await _seed_namespace(
        "authcov-malformed-admin-ns",
        gid,
        enforce_membership=False,
    )
    token_info = {
        "name": "authcov-malformed-admin",
        "permissions": {"admin": "wrong"},
    }

    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(db, token_info, ns_id)

    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_read_only_admin_does_not_bypass_strict_namespace_write():
    """admin:r plus secrets:w is not an admin break-glass write grant."""
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session
    from fastapi import HTTPException

    gid = await _seed_group("authcov-admin-r-write-grp")
    ns_id = await _seed_namespace(
        "authcov-admin-r-write-ns",
        gid,
        enforce_membership=True,
    )
    token_info = {
        "name": "authcov-admin-r-write",
        "permissions": {"admin": "r", "secrets": "w"},
    }

    async with async_session() as db:
        with pytest.raises(HTTPException) as exc:
            await check_namespace_membership(
                db,
                token_info,
                ns_id,
                write=True,
            )
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_check_namespace_membership_admin_bypass_swallows_audit_exception(
    monkeypatch,
    caplog,
):
    """Strict ns + admin API token + audit.log_action raises -> bypass MUST
    still succeed (auth.py L374-L375 : `except Exception: pass`). Failing
    audit must never block authz."""
    from api.app import audit as _audit
    from api.app.auth import check_namespace_membership
    from api.app.database import async_session

    gid = await _seed_group("authcov-audfail-grp")
    ns_id = await _seed_namespace("authcov-audfail-ns", gid, enforce_membership=True)

    async def _boom(*a, **kw):
        raise RuntimeError("simulated audit outage")

    monkeypatch.setattr(_audit, "log_action", _boom)
    caplog.set_level(logging.CRITICAL, logger="rhorizon.auth")

    token_info = {
        "name": "authcov-api-admin-2\nFORGED",
        "permissions": {"admin": "rw"},
    }
    async with async_session() as db:
        ns = await check_namespace_membership(db, token_info, ns_id)
    assert str(ns.id) == ns_id
    fallback = [r.getMessage() for r in caplog.records if r.name == "rhorizon.auth"]
    assert fallback
    assert "\n" not in fallback[-1]
    assert r"authcov-api-admin-2\nFORGED" in fallback[-1]


# ---------------------------------------------------------------------------
# require_vault_token: token expired branch (auth.py L97-L100)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_token_returns_401(client, master_password, admin_token):
    """A token whose `expires_at` is in the past gets 401 'Token expired'."""
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by, expires_at)
                VALUES (
                    'authcov-expired',
                    :hash,
                    CAST(:perms AS jsonb),
                    'auth-cov',
                    NOW() - INTERVAL '1 hour'
                )
            """),
            {"hash": token_hash, "perms": json.dumps({"secrets": "r"})},
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 401
    assert "expired" in r.json().get("detail", "").lower()
