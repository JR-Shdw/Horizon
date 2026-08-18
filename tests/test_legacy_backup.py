# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Bloc G regression tests for the dual-context backup/restore.

- test_legacy_backup_roundtrip
    A committed fixture (`tests/fixtures/backup-legacy-v1.age`) is
    restored on a vault whose argon2_salt + master password are
    different from the backup's. Validates that the dual-context
    flow correctly re-wraps secrets under the CURRENT context.

- test_restore_preserves_current_argon2_salt
    Direct regression of the bug observed 2026-05-20 afternoon : the
    live vault's argon2_salt MUST NOT be overwritten by the backup's.

- test_restore_fast_path_needs_no_python_plaintext
    On the master, vault.rotate_secret_from_backup chains decrypt(BACKUP)
    + encrypt(CURRENT) entirely in Rust ; secure_zero must be called
    zero times, since there is no Python-side plaintext to wipe. Catches
    a silent fallback to the old Python-orchestrated path.

- test_restore_fallback_path_calls_secure_zero
    Forces the follower fallback (rotate_secret_from_backup -> None) and
    confirms that path still wipes its Python-side plaintext per secret.
    Proxy test : counts secure_zero invocations, does not by itself prove
    the buffers are zeroed (the zeroize crate is sound Rust-side).

- test_backup_crypto_cross_lang
    Python (api.app.crypto) and Rust (BackupCryptoContext) must derive
    byte-identical material for the same (password, salt, version)
    tuple. The Rust constructor validates master_check internally ;
    mismatch raises ValueError before the assert.
"""

import base64
from pathlib import Path

import pytest
import rhorizon_crypto
from api.app.crypto import derive_keys, derive_master_key, hmac_token
from rhorizon_crypto import BackupCryptoContext
from sqlalchemy import text

FIXTURE = Path(__file__).parent / "fixtures" / "backup-legacy-v1.age"

LEGACY_AGE_PASSPHRASE = "legacy-fixture-pp-1234"
LEGACY_MASTER_PASSWORD = "legacy-fixture-mp-1234"
LEGACY_SALT_HEX = "0123456789abcdef0123456789abcdef"
LEGACY_SECRETS = {
    "db-pw": "secret-value-001",
    "api-key": "secret-value-002",
    "token": "secret-value-003",
}


def _restore_body(payload_bytes: bytes) -> dict:
    return {
        "passphrase": LEGACY_AGE_PASSPHRASE,
        "master_password_backup": LEGACY_MASTER_PASSWORD,
        "confirm_phrase": "RESTORE",
        "payload": base64.b64encode(payload_bytes).decode(),
    }


@pytest.mark.asyncio
async def test_legacy_backup_roundtrip(client, master_password, admin_token):
    """Restore a v=1 backup on a vault whose master password and salt
    differ from the backup's. Post-restore unseal mints a root-restore
    token; each fixture secret must read back with its expected plaintext
    under the CURRENT crypto context.
    """
    assert FIXTURE.exists(), (
        f"fixture missing at {FIXTURE} -- regenerate with "
        "tools/generate_legacy_backup.py"
    )
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json=_restore_body(FIXTURE.read_bytes()),
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("sealed") is True, body

    # Legacy payloads predate RBAC groups. Restore must nevertheless leave the
    # system namespace owner in place so subsequent non-RBAC secret creation
    # can auto-create its namespace.
    from api.app.database import async_session

    async with async_session() as db:
        group = await db.execute(
            text("SELECT permissions FROM vault_groups WHERE name = 'vault-admins'")
        )
        assert group.scalar_one() == {"admin": "rw"}

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 200, r.text
    root_token = r.json().get("root_token")
    assert root_token, f"unseal did not mint a recovery root token: {r.json()}"

    root_headers = {"Authorization": f"Bearer {root_token}"}
    for name, expected in LEGACY_SECRETS.items():
        rr = await client.get(
            f"/api/v1/vault/secrets/{name}?namespace=legacy",
            headers=root_headers,
        )
        assert rr.status_code == 200, f"{name}: {rr.status_code} {rr.text}"
        assert rr.json()["value"] == expected, f"{name}: value mismatch"


@pytest.mark.asyncio
async def test_restore_preserves_current_argon2_salt(client, admin_token):
    """The CURRENT vault's argon2_salt MUST NOT be overwritten by the
    backup's. Direct regression of commit fc57839 RCA #1.
    """
    from api.app.database import async_session

    async with async_session() as db:
        row = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        salt_before = row.scalar_one()

    assert salt_before != LEGACY_SALT_HEX, (
        "test premise broken: current salt happens to match the legacy "
        "fixture salt, the regression would be invisible"
    )

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json=_restore_body(FIXTURE.read_bytes()),
        headers=headers,
    )
    assert r.status_code == 200, r.text

    async with async_session() as db:
        row = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        salt_after = row.scalar_one()

    assert salt_after == salt_before, (
        f"argon2_salt was overwritten during restore: "
        f"before={salt_before[:16]}... after={salt_after[:16]}..."
    )


async def _restore_and_read_back(client, admin_token, master_password) -> dict:
    """Restore the legacy fixture, unseal with the CURRENT password, and
    return {name: value} read back for every LEGACY_SECRETS entry."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json=_restore_body(FIXTURE.read_bytes()),
        headers=headers,
    )
    assert r.status_code == 200, r.text

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 200, r.text
    root_token = r.json().get("root_token")
    assert root_token, f"unseal did not mint a recovery root token: {r.json()}"
    root_headers = {"Authorization": f"Bearer {root_token}"}

    values = {}
    for name in LEGACY_SECRETS:
        rr = await client.get(
            f"/api/v1/vault/secrets/{name}?namespace=legacy",
            headers=root_headers,
        )
        assert rr.status_code == 200, f"{name}: {rr.status_code} {rr.text}"
        values[name] = rr.json()["value"]
    return values


@pytest.mark.asyncio
async def test_restore_fast_path_needs_no_python_plaintext(
    client, admin_token, master_password, monkeypatch
):
    """On the master (this test's single-worker vault), restore chains
    decrypt(BACKUP) + encrypt(CURRENT) entirely in Rust via
    vault.rotate_secret_from_backup - no Python-side plaintext exists to
    wipe, so secure_zero must NOT be called on this path. Proxy test: it
    does not by itself prove no plaintext exists, but it does catch a
    refactor that silently falls back to the old Python-orchestrated
    (plaintext-generating) path when the fast path was available.
    """
    call_count = 0
    real = rhorizon_crypto.secure_zero

    def counting(buf):
        nonlocal call_count
        call_count += 1
        return real(buf)

    monkeypatch.setattr("api.app.routes.backup.secure_zero", counting)

    values = await _restore_and_read_back(client, admin_token, master_password)
    assert values == LEGACY_SECRETS, values

    assert call_count == 0, (
        f"secure_zero called {call_count} times on what should be the "
        "plaintext-free fast path -- did restore silently fall back to "
        "the Python-orchestrated path on the master?"
    )


@pytest.mark.asyncio
async def test_restore_fallback_path_calls_secure_zero(
    client, admin_token, master_password, monkeypatch
):
    """Force the follower fallback (vault.rotate_secret_from_backup
    returns None, as it does on an actual follower) and confirm that
    path still wipes its Python-side plaintext per secret. Regression
    guard for the pre-existing fallback sequence: catches a refactor
    that removes the secure_zero call, letting plaintexts linger in the
    CPython heap on that path.
    """
    from api.app.vault_state import vault

    monkeypatch.setattr(vault, "rotate_secret_from_backup", lambda *a, **k: None)

    call_count = 0
    real = rhorizon_crypto.secure_zero

    def counting(buf):
        nonlocal call_count
        call_count += 1
        return real(buf)

    monkeypatch.setattr("api.app.routes.backup.secure_zero", counting)

    values = await _restore_and_read_back(client, admin_token, master_password)
    assert values == LEGACY_SECRETS, values

    assert call_count >= len(LEGACY_SECRETS), (
        f"secure_zero called {call_count} times for {len(LEGACY_SECRETS)} "
        "secrets on the fallback path -- restore loop is no longer wiping "
        "plaintexts"
    )


def _forge_payload_with_dup_tokens() -> tuple[bytes, str, str]:
    """Forge a backup .age payload that carries two identical token
    entries resolving to the same (name, namespace) pair. Used by
    test_restore_handles_duplicate_token_stubs.
    """
    import hashlib
    import json
    from datetime import datetime, timezone

    from pyrage import passphrase as age_passphrase

    mp = "dup-tokens-mp-1234"
    age_pp = "dup-tokens-pp-1234"
    salt = bytes.fromhex("fedcba9876543210fedcba9876543210")

    master_key = derive_master_key(mp.encode(), salt)
    keys = derive_keys(master_key, dek_key_version=1)
    master_check = hmac_token(keys["hmac_key"], "master-check-value")

    duplicate_token = {
        "name": "duplicated-name",
        "namespace": "default",
        "permissions": {"secrets": "r"},
        "allowed_ips": None,
        "expires_at": None,
    }

    backup_data = {
        "version": "3",
        "format": "age",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tables": {
            "secrets": [],
            "namespaces": [],
            "tokens": [duplicate_token, duplicate_token.copy()],
            "config": [
                {"key": "argon2_salt", "value": salt.hex()},
                {"key": "master_check", "value": master_check},
                {"key": "dek_key_version", "value": "1"},
            ],
            "groups": [],
            "group_members": [],
        },
    }

    raw = json.dumps(backup_data, default=str).encode()
    checksum = hashlib.sha256(raw).hexdigest()
    backup_data["checksum"] = checksum
    raw = json.dumps(backup_data, default=str).encode()

    encrypted = age_passphrase.encrypt(raw, age_pp)
    return encrypted, mp, age_pp


@pytest.mark.asyncio
async def test_restore_handles_duplicate_token_stubs(client, admin_token):
    """Regression : a backup whose tables['tokens'] carries two entries
    resolving to the same (name, namespace) pair must NOT break the
    restore on a UniqueViolationError against
    vault_pending_token_rotations (name, namespace) UNIQUE.

    Scenario observed 2026-05-20 evening on a cross-vault migration:
    the source vault had several `active=true` rows for the same
    `name` (UNIQUE INDEX (name) WHERE active was either missing or
    contained historical duplicates), the payload carried both,
    /backup/restore aborted with 500.

    ON CONFLICT (name, namespace) DO UPDATE makes the loop idempotent:
    the last entry wins, the operator rotates one stub instead of
    facing a 500.
    """
    from api.app.database import async_session

    encrypted, mp, age_pp = _forge_payload_with_dup_tokens()
    payload_b64 = base64.b64encode(encrypted).decode()

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": age_pp,
            "master_password_backup": mp,
            "confirm_phrase": "RESTORE",
            "payload": payload_b64,
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text

    async with async_session() as db:
        rr = await db.execute(
            text(
                "SELECT COUNT(*) FROM vault_pending_token_rotations "
                "WHERE name = 'duplicated-name' AND namespace = 'default'"
            )
        )
        assert rr.scalar_one() == 1, (
            "expected exactly one stub for (duplicated-name, default) "
            "after restore with two identical token entries in the payload"
        )


def _forge_payload_with_2fa() -> tuple[bytes, str, str]:
    """Forge a backup carrying second_factor=totp + a totp_secret (which, in a
    real backup, is ciphertext under the BACKUP dek_key). Used to prove the
    restore does NOT import dek-bound 2FA config (it would be undecryptable under
    the current dek_key -> unseal lockout)."""
    import hashlib
    import json
    from datetime import datetime, timezone

    from pyrage import passphrase as age_passphrase

    mp = "twofa-backup-mp-1234"
    age_pp = "twofa-backup-pp-1234"
    salt = bytes.fromhex("0123456789abcdef0123456789abcdef")
    master_key = derive_master_key(mp.encode(), salt)
    keys = derive_keys(master_key, dek_key_version=1)
    master_check = hmac_token(keys["hmac_key"], "master-check-value")

    backup_data = {
        "version": "3",
        "format": "age",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tables": {
            "secrets": [],
            "namespaces": [],
            "tokens": [],
            "config": [
                {"key": "argon2_salt", "value": salt.hex()},
                {"key": "master_check", "value": master_check},
                {"key": "dek_key_version", "value": "1"},
                {"key": "second_factor", "value": "totp"},
                {"key": "totp_secret", "value": "deadbeefdeadbeefdeadbeef"},
            ],
            "groups": [],
            "group_members": [],
        },
    }
    raw = json.dumps(backup_data, default=str).encode()
    backup_data["checksum"] = hashlib.sha256(raw).hexdigest()
    raw = json.dumps(backup_data, default=str).encode()
    return age_passphrase.encrypt(raw, age_pp), mp, age_pp


@pytest.mark.asyncio
async def test_restore_excludes_2fa_no_lockout(client, master_password, admin_token):
    """A backup's second_factor/totp_secret must NOT overwrite the current
    vault's: the backup blob is under a different dek_key, so importing it would
    brick the next unseal (2FA lockout). 2FA is reconfigured post-restore."""
    from api.app.database import async_session

    # Current vault: no 2FA (deterministic target).
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('second_factor', 'none') "
                "ON CONFLICT (key) DO UPDATE SET value = 'none'"
            )
        )
        await db.execute(text("DELETE FROM vault_config WHERE key = 'totp_secret'"))
        await db.commit()

    encrypted, mp, age_pp = _forge_payload_with_2fa()
    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": age_pp,
            "master_password_backup": mp,
            "confirm_phrase": "RESTORE",
            "payload": base64.b64encode(encrypted).decode(),
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["sealed"] is True

    # Backup 2FA was excluded: current config unchanged.
    async with async_session() as db:
        sf = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'second_factor'")
            )
        ).fetchone()
        ts = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'totp_secret'")
            )
        ).fetchone()
    assert sf is not None and sf.value == "none", "backup second_factor must not import"
    assert ts is None, "backup totp_secret must not import"

    # No lockout: the vault unseals with the CURRENT password, no 2FA code.
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200, r.text


def test_backup_crypto_cross_lang():
    """Python (api.app.crypto) and Rust (BackupCryptoContext) must derive
    byte-identical master_key + master_check for the same inputs. The
    Rust constructor validates master_check internally; any drift in
    Argon2id, HKDF, or HMAC between the two implementations raises
    ValueError here before the assert.
    """
    password = b"cross-lang-vector-pw"
    salt = bytes.fromhex(LEGACY_SALT_HEX)

    py_master_key = derive_master_key(password, salt)
    py_keys = derive_keys(py_master_key, dek_key_version=1)
    py_master_check = hmac_token(py_keys["hmac_key"], "master-check-value")

    ctx = BackupCryptoContext(password, salt, py_master_check, 1)
    assert ctx is not None

    bogus_check = "00" * 64
    with pytest.raises(ValueError):
        BackupCryptoContext(password, salt, bogus_check, 1)
