# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Backup / restore - encrypted logical backup using the age format.

Backups are encrypted with the age standard (scrypt + ChaCha20-Poly1305).
Decrypt with: age -d backup.age

What the backup can restore today:
  - current vault_secrets rows (with their DEK ciphertext, metadata,
    expiration, honey flag, and soft-delete lifecycle fields)
  - vault_dek
  - vault_namespaces
  - vault_groups + vault_group_members
  - vault_config (including argon2_salt / master_check - needed for the
    backup-side DEK context during restore)
  - vault_tokens metadata only (name, namespace, permissions, allowed_ips,
    expires_at, is_honey) - the hash is intentionally NOT carried over,
    since after the restore the hmac_key changes; instead each token row
    lands as a stub in vault_pending_token_rotations that an admin rotates
    on-demand.

What the backup does not restore (operator must reconfigure):
  vault_yubikeys, vault_webauthn, vault_notification_channels,
  vault_dynamic_module_state, vault_dynamic_engines/roles/leases,
  vault_secret_versions,
  vault_audit (chain). See docs/DISASTER-RECOVERY.md.

Captured in the dump but NOT restored (see _CONFIG_KEYS_NEVER_RESTORED):
CURRENT-vault identity, 2FA mode / TOTP secret, LDAP config, and audit-chain
identity. The encrypted config blobs in this set stay under the BACKUP
dek_key; the dual-context restore re-keys only vault_secrets, so importing
those blobs would brick the feature (for TOTP, the next unseal -> 2FA lockout).
Reconfigure them post-restore.

This re-keying is age-backup specific. For full-fidelity disaster recovery
(2FA/LDAP intact), use a raw PostgreSQL dump/restore (pg_dump/pg_restore): it
copies vault_config + vault_dek + master_check verbatim, so the dek_key is
unchanged and every dek-bound blob keeps decrypting.
"""

import base64
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator
from pyrage import passphrase as age_passphrase
from rhorizon_crypto import BackupCryptoContext, secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_client_ip
from ..crypto import (
    SECRET_AAD_VERSION,
    dek_aad,
    encrypt_secret,
    generate_dek,
    secret_aad,
)
from ..custody import is_rust_custody_api
from ..custody_generation import (
    CUSTODY_ACTIVATION_CONFIG_KEY,
    CUSTODY_ORCHESTRATION_LOCK,
    CUSTODY_STATE_CONFIG_KEY,
    set_rust_custody_activation,
)
from ..database import get_db
from ..key_epoch import require_generation_current
from ..vault_state import vault

log = logging.getLogger("rhorizon.backup")

# Restore confirm phrase, must be typed literally by the operator.
# UI overlay (`_showRestoreConfirmOverlay`) and CLI prompt both gate on
# this string; the API re-checks server-side because a compromised
# root token that bypasses the UI / CLI must NOT be able to wipe the
# vault by replaying the JSON body.
RESTORE_CONFIRM_PHRASE = "RESTORE"

# Configuration keys that the restore MUST NOT touch. They belong to
# the CURRENT vault (master_check derived from the current password,
# audit chain head, post-restore flags); copying their values from
# the backup payload would re-create the historical bug (master_check
# overwritten with the backup's, current dek_key invalidated).
#
# Anything not in this set is restored normally (SSO proxy config, rotation
# cadence, IP allowlist defaults, ...).
_CONFIG_KEYS_NEVER_RESTORED = frozenset(
    {
        # CURRENT vault crypto identity, copying the backup's would invalidate
        # the running dek_key and break the post-restore unseal (historical bug).
        "argon2_salt",
        "master_check",
        "dek_key_version",
        "vault_initialized",
        "pending_restore_bootstrap",
        "pending_restore_review",
        "prev_hmac_key",
        # dek_key-bound blobs. The dual-context restore re-keys ONLY vault_secrets;
        # these config values stay encrypted under the BACKUP dek_key, which the
        # CURRENT vault cannot decrypt. Restoring them verbatim bricks the feature
        # - for totp it bricks the next *unseal* (2FA lockout). 2FA + LDAP are
        # reconfigured post-restore, exactly like yubikeys, webauthn, and
        # notification channels (which the backup already drops). Note: this is
        # age-backup-only; a raw pg_dump/restore keeps the same dek_key and
        # carries them intact.
        "second_factor",
        "totp_secret",
        "totp_last_counter",
        "ldap_config",
        "ldap_group_mappings",
        # Audit-chain identity belongs to the CURRENT vault: vault_audit and its
        # key archive are not backed up, so the epoch / seed / pub must stay
        # current (ensure_audit_identity re-bootstraps if absent).
        "audit_identity_seed_enc",
        "audit_identity_pub",
        "key_epoch",
        # Rust custody state describes THIS host's live custodian pool: which
        # share generation the daemons actually hold, and whether the operator
        # decided the pool should be unsealed. A backup carries the generation
        # counter of the vault it was taken from, which has no relationship to
        # the running pool. Importing it points the durable recovery decision
        # at a generation no slot has, and the next repair fails closed with no
        # way back short of hand-editing vault_config. The restore sets the
        # activation itself (sealed), below.
        CUSTODY_STATE_CONFIG_KEY,
        CUSTODY_ACTIVATION_CONFIG_KEY,
    }
)

BACKUP_COVERAGE = {
    "mode": "age-logical-partial",
    "restored_tables": [
        "vault_secrets",
        "vault_dek",
        "vault_namespaces",
        "vault_groups",
        "vault_group_members",
        "vault_config",
    ],
    "pending_rotation_tables": ["vault_tokens"],
    "excluded_tables": [
        "vault_audit",
        "vault_audit_lite",
        "vault_audit_key_archive",
        "vault_audit_signer_certs",
        "vault_yubikeys",
        "vault_webauthn",
        "vault_notification_channels",
        "vault_dynamic_module_state",
        "vault_dynamic_engines",
        "vault_dynamic_roles",
        "vault_leases",
        "vault_secret_versions",
        "vault_challenges",
        "vault_rate_limits",
        "vault_workers",
        "vault_cluster_nodes",
        "vault_cluster_config",
        "vault_join_idempotency",
    ],
    "excluded_config_keys": sorted(_CONFIG_KEYS_NEVER_RESTORED),
}


def _parse_ts(value):
    """Parse an ISO-8601 string to a timezone-aware datetime, or return None.

    asyncpg expects datetime objects for `timestamptz` columns even behind a
    `CAST(... AS timestamptz)` - string inputs are rejected with DataError.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


router = APIRouter(prefix="/api/v1/vault/backup", tags=["backup"])


class BackupRequest(BaseModel):
    passphrase: SecretStr = Field(..., min_length=12, max_length=256)


class RestoreRequest(BaseModel):
    # age passphrase that decrypts the .age envelope
    passphrase: SecretStr = Field(..., min_length=12, max_length=256)
    # master password of the vault AT BACKUP TIME, required to derive
    # the BACKUP-side dek_key and unwrap the backup DEKs. Independent
    # from the age passphrase; both must be provided.
    master_password_backup: SecretStr = Field(..., min_length=8, max_length=256)
    # Operator confirmation phrase, must literally equal RESTORE_CONFIRM_PHRASE.
    # UI overlay + CLI prompt collect this from the operator; the API
    # re-checks server-side as a backstop against compromised tokens
    # that replay a body without going through the UI / CLI.
    confirm_phrase: str = Field(..., min_length=1, max_length=32)
    payload: str = Field(..., max_length=52_428_800)  # 50 MB cap

    @field_validator("confirm_phrase")
    @classmethod
    def _check_confirm_phrase(cls, v: str) -> str:
        if v != RESTORE_CONFIRM_PHRASE:
            raise ValueError(
                f"confirm_phrase must equal {RESTORE_CONFIRM_PHRASE!r} "
                "(operator-typed restore confirmation)"
            )
        return v


def _encrypt_backup(data: bytes, passphrase: str) -> bytes:
    """Encrypt backup with age passphrase (scrypt + ChaCha20-Poly1305)."""
    return age_passphrase.encrypt(data, passphrase)


def _decrypt_backup(payload: bytes, passphrase: str) -> bytes:
    """Decrypt age-encrypted backup with passphrase."""
    return age_passphrase.decrypt(payload, passphrase)


@router.post("/create")
async def create_backup(
    body: BackupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Create an encrypted logical migration backup."""
    vault.require_unsealed()

    backup_data = {
        "version": "4",
        "format": "age",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "coverage": BACKUP_COVERAGE,
        "tables": {},
    }

    # Secrets (encrypted, with DEKs). dek_id is preserved across backup/restore
    # because the DEK ciphertext is bound to it via AAD = f"dek:{dek_id}"
    # restoring under a freshly-generated UUID would invalidate
    # the AEAD tag.
    result = await db.execute(
        text("""
            SELECT s.name, s.namespace, s.ciphertext, s.nonce, s.aad_version,
                   s.version,
                   s.metadata, s.created_by, s.created_at, s.updated_at,
                   s.expires_at, s.is_honey, s.deleted_at, s.purge_after,
                   s.dek_id,
                   encode(d.encrypted_key, 'hex') AS dek_hex,
                   encode(d.nonce, 'hex') AS dek_nonce_hex
            FROM vault_secrets s
            JOIN vault_dek d ON d.id = s.dek_id
            ORDER BY s.name
        """)
    )
    secrets = []
    for r in result.fetchall():
        secrets.append(
            {
                "name": r.name,
                "namespace": r.namespace,
                "ciphertext": bytes(r.ciphertext).hex(),
                "nonce": bytes(r.nonce).hex(),
                "aad_version": r.aad_version,
                "version": r.version,
                "metadata": r.metadata if isinstance(r.metadata, dict) else {},
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "is_honey": bool(r.is_honey),
                "deleted_at": r.deleted_at.isoformat() if r.deleted_at else None,
                "purge_after": r.purge_after.isoformat() if r.purge_after else None,
                "dek_id": str(r.dek_id),
                "dek_encrypted": r.dek_hex,
                "dek_nonce": r.dek_nonce_hex,
            }
        )
    backup_data["tables"]["secrets"] = secrets

    # Namespaces (FK target for vault_secrets.namespace_id).
    # Bloc G: owner_group_name is JOIN-resolved alongside owner_group_id
    # so the dual-context restore can re-link namespaces to their groups
    # by NAME (each restore re-inserts groups with fresh UUIDs; the
    # backup's owner_group_id becomes stale by the time the restore runs).
    # vault_namespaces.owner_group_id is NOT NULL in the schema, so name
    # resolution is the only way to satisfy the constraint without
    # relaxing it.
    result = await db.execute(
        text("""
            SELECT n.name, n.owner_group_id, g.name AS owner_group_name,
                   n.enforce_membership, n.delete_protection,
                   n.archived_at, n.created_by
            FROM vault_namespaces n
            LEFT JOIN vault_groups g ON g.id = n.owner_group_id
            ORDER BY n.name
        """)
    )
    namespaces = []
    for r in result.fetchall():
        namespaces.append(
            {
                "name": r.name,
                "owner_group_id": str(r.owner_group_id) if r.owner_group_id else None,
                "owner_group_name": r.owner_group_name,
                "enforce_membership": r.enforce_membership,
                "delete_protection": r.delete_protection,
                "archived_at": r.archived_at.isoformat() if r.archived_at else None,
                "created_by": r.created_by,
            }
        )
    backup_data["tables"]["namespaces"] = namespaces

    # Tokens: METADATA ONLY. The hash is dropped: after a restore the
    # hmac_key changes (new argon2_salt), so the old hash never authenticates.
    # Each row lands in vault_pending_token_rotations on restore; an admin
    # explicitly rotates them on-demand from the UI.
    result = await db.execute(
        text("""
            SELECT t.name,
                   COALESCE(t.permissions->>'namespaces', '') AS ns_json,
                   t.permissions, t.allowed_ips, t.expires_at, t.is_honey,
                   COALESCE(
                       (
                           SELECT jsonb_agg(g.name ORDER BY g.name)
                           FROM vault_group_members AS m
                           JOIN vault_groups AS g ON g.id = m.group_id
                           WHERE m.principal_type = 'token'
                             AND m.token_id = t.id
                       ),
                       '[]'::jsonb
                   ) AS group_names
            FROM vault_tokens AS t
            WHERE t.active
            ORDER BY t.name
        """)
    )
    tokens = []
    for r in result.fetchall():
        # Extract the first namespace claim (if any) for the stub's namespace
        # column: falls back to 'default'. The full namespaces array is kept
        # inside permissions JSONB for accurate restore.
        ns = "default"
        if isinstance(r.permissions, dict):
            ns_claim = r.permissions.get("namespaces")
            if isinstance(ns_claim, list) and ns_claim:
                ns = str(ns_claim[0])
        tokens.append(
            {
                "name": r.name,
                "namespace": ns,
                "permissions": r.permissions,
                "allowed_ips": r.allowed_ips,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "is_honey": bool(r.is_honey),
                "group_names": r.group_names,
            }
        )
    backup_data["tables"]["tokens"] = tokens

    # Config (all keys, argon2_salt/master_check needed for DEK decryption
    # after restore)
    result = await db.execute(text("SELECT key, value FROM vault_config ORDER BY key"))
    backup_data["tables"]["config"] = [
        {"key": r.key, "value": r.value} for r in result.fetchall()
    ]

    # Groups
    result = await db.execute(
        text("SELECT name, permissions, source, ldap_dn FROM vault_groups")
    )
    backup_data["tables"]["groups"] = [
        {
            "name": r.name,
            "permissions": r.permissions,
            "source": r.source,
            "ldap_dn": r.ldap_dn,
        }
        for r in result.fetchall()
    ]

    # External identities. Native-token memberships travel with token metadata
    # so restore can attach them to the fresh token UUID minted during rotation.
    result = await db.execute(
        text("""
            SELECT g.name AS group_name, m.principal_type,
                   m.external_id AS principal_id, m.added_at
            FROM vault_group_members m
            JOIN vault_groups g ON g.id = m.group_id
            WHERE m.principal_type = 'external'
            ORDER BY g.name, m.external_id
        """)
    )
    backup_data["tables"]["group_members"] = [
        {
            "group_name": r.group_name,
            "principal_type": r.principal_type,
            "principal_id": r.principal_id,
            "added_at": r.added_at.isoformat() if r.added_at else None,
        }
        for r in result.fetchall()
    ]

    # Serialize and encrypt with age
    raw = json.dumps(backup_data, default=str).encode()
    checksum = hashlib.sha256(raw).hexdigest()
    backup_data["checksum"] = checksum
    raw = json.dumps(backup_data, default=str).encode()

    encrypted = _encrypt_backup(raw, body.passphrase.get_secret_value())

    counts = {
        "secrets": len(secrets),
        "tokens": len(tokens),
        "config": len(backup_data["tables"]["config"]),
        "groups": len(backup_data["tables"]["groups"]),
        "namespaces": len(namespaces),
        "group_members": len(backup_data["tables"]["group_members"]),
    }

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_backup",
        detail={**counts, "size_bytes": len(encrypted), "format": "age"},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {
        "status": "created",
        "payload": base64.b64encode(encrypted).decode(),
        "size_bytes": len(encrypted),
        "secrets_count": counts["secrets"],
        "tokens_count": counts["tokens"],
        "config_count": counts["config"],
        "groups_count": counts["groups"],
        "namespaces_count": counts["namespaces"],
        "group_members_count": counts["group_members"],
        "checksum": checksum,
        "format": "age",
        "coverage": BACKUP_COVERAGE,
    }


@router.post("/restore")
async def restore_backup(
    body: RestoreRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Restore the vault from an age-encrypted logical backup.

    Bloc G decrypts payload material under the BACKUP-side crypto
    context (master_key derived from `master_password_backup`, dek_key
    via HKDF), re-encrypts each secret under a fresh DEK wrapped by
    the CURRENT vault dek_key. argon2_salt + master_check + dek_key
    of the running vault are LEFT UNTOUCHED - restoring a backup
    taken under an older KDF / salt does not break the post-restore
    unseal.

    Side effects:
      - vault_tokens rows from the backup land in vault_pending_token_rotations
        as stubs awaiting admin rotation (no usable plaintext exists).
      - vault_config keys 'pending_restore_bootstrap' and 'pending_restore_review'
        are set; the first triggers the next unseal to mint a
        `root-restore-<ts>` with a short TTL, the second drives the UI panel.
      - the vault is automatically sealed at the end as a safety net
        (drops the stale sub-keys cached on the master worker even though
        argon2_salt did not change; the next unseal re-derives them
        and emits the post-restore root token).
      - under the Rust custody canary that seal is a DURABLE decision written
        in the same transaction as the restored rows, and the daemon pool is
        sealed through deactivate_rust_custody afterwards. The custody
        generation itself is untouched: this restore does not replace the
        runtime bundle, so the custodians keep the shares they hold.

    Required inputs (all in the body):
      - passphrase: age passphrase that decrypts the .age envelope
      - master_password_backup: master password of the vault at backup time
      - confirm_phrase: must equal "RESTORE" (UI / CLI gate; the API
                                  re-checks server-side)
      - payload: base64 (default) or hex of the encrypted backup
    """
    vault.require_unsealed()

    actor = actor_display_name(token_info)
    client_ip = get_client_ip(request)

    # Decode + decrypt + parse + checksum BEFORE the audit-log-started
    # entry, so corrupted payloads do not pollute audit with phantom
    # restore attempts. A wrong password / corrupt payload errors here
    # and the admin retries cleanly.
    try:
        payload = base64.b64decode(body.payload)
    except Exception:
        try:
            payload = bytes.fromhex(body.payload)
        except ValueError:
            raise HTTPException(400, "Payload must be base64 or hex encoded")

    try:
        raw = _decrypt_backup(payload, body.passphrase.get_secret_value())
    except Exception:
        raise HTTPException(401, "Invalid age passphrase or corrupted backup")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Corrupted backup data")

    checksum = data.pop("checksum", None)
    verify = json.dumps(data, default=str).encode()
    if checksum and not hmac.compare_digest(
        hashlib.sha256(verify).hexdigest(), checksum
    ):
        raise HTTPException(400, "Backup checksum mismatch")

    tables = data.get("tables", {})

    # Build the BACKUP-side crypto context from the backup's vault_config.
    # argon2_salt + master_check + dek_key_version are PUBLIC-BY-DESIGN
    # - they describe how to derive the BACKUP master_key, not the
    # CURRENT one. The BackupCryptoContext constructor validates the
    # master_password_backup against the backup's master_check; mismatch
    # raises ValueError before any other state changes.
    cfg_rows = tables.get("config", [])
    cfg_dict = {c["key"]: c["value"] for c in cfg_rows}
    backup_salt_hex = cfg_dict.get("argon2_salt")
    backup_master_check = cfg_dict.get("master_check")
    if not backup_salt_hex or not backup_master_check:
        raise HTTPException(
            400,
            "Backup is missing argon2_salt or master_check - the dual-context "
            "restore needs both to derive the backup-side dek_key. Older "
            "backup format not supported.",
        )
    try:
        backup_salt = bytes.fromhex(backup_salt_hex)
    except ValueError:
        raise HTTPException(400, "Backup argon2_salt is not valid hex")
    try:
        backup_dek_v = int(cfg_dict.get("dek_key_version", "1"))
    except (TypeError, ValueError):
        backup_dek_v = 1

    # Audit-log the attempt BEFORE any DB mutation. If the master
    # password is wrong, the 401 below leaves only this entry behind
    # so the audit chain reflects who tried what when.
    counts_pre = {
        "secrets_in_backup": len(tables.get("secrets", [])),
        "tokens_in_backup": len(tables.get("tokens", [])),
        "namespaces_in_backup": len(tables.get("namespaces", [])),
        "groups_in_backup": len(tables.get("groups", [])),
        "config_keys_in_backup": len(cfg_rows),
        "backup_created_at": data.get("created_at"),
        "backup_dek_key_version": backup_dek_v,
    }
    await log_action(
        db,
        actor=actor,
        action="restore_backup_started",
        detail=counts_pre,
        ip_address=client_ip,
    )
    await db.commit()

    await require_generation_current(db, vault)

    # Everything below runs in ONE transaction, and its shared key-rotation
    # lock (taken by require_generation_current above) is held until the final
    # commit -- a password or DEK-key rotation cannot start underneath and
    # re-wrap vault_dek while this loop inserts rows under the old generation.
    #
    # Rust custody needs its own exclusive lock on top: this restore ends by
    # sealing the daemon pool and flipping the durable activation decision, so
    # it must not interleave with a generation transition or with the
    # maintenance leader's repair.
    rust_custody = is_rust_custody_api()
    if rust_custody:
        custody_lock = await db.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
            {"lock_name": CUSTODY_ORCHESTRATION_LOCK},
        )
        if not custody_lock.scalar():
            raise HTTPException(
                status_code=409,
                detail="another Rust custody operation is in progress",
            )

    try:
        backup_pw = body.master_password_backup.get_secret_value().encode()
        backup_ctx = BackupCryptoContext(
            backup_pw,
            backup_salt,
            backup_master_check,
            backup_dek_v,
        )
    except ValueError as e:
        # Wrong backup master password OR mlock failure. The Rust
        # constructor never leaks the derived material on either path
        # (LockedBuf zeroizes on Drop, and mlock failure zeroizes before
        # raising). 401 keeps the response shape consistent with the
        # age-passphrase failure above.
        raise HTTPException(401, f"Backup master password rejected: {e}") from None

    restored = {
        "secrets": 0,
        "tokens_pending_rotation": 0,
        "config": 0,
        "groups": 0,
        "namespaces": 0,
        "group_members": 0,
    }

    try:
        # Wipe business tables in FK-safe order. argon2_salt /
        # master_check / dek_key_version / audit_key / vault_audit are
        # NOT in scope; they belong to the CURRENT vault. This logical restore
        # cannot preserve the target vault's current crypto state while also
        # importing backup-side encrypted payloads.
        #
        # Order: children before parents. vault_dek is the most
        # widely-referenced table (vault_secrets, vault_secret_versions,
        # vault_dynamic_engines all FK to it) so it lands late. vault_leases
        # must precede vault_dynamic_engines (FK, no CASCADE). Notification
        # channels are cleared because the logical backup does not carry
        # external delivery config; dynamic tables are cleared because they
        # would otherwise block the vault_dek wipe. Target-side YubiKey,
        # WebAuthn, and audit tables are not imported from the backup, but
        # this wipe list does not delete them.
        for table in (
            "vault_leases",
            "vault_dynamic_roles",
            "vault_dynamic_engines",
            "vault_secret_versions",
            "vault_secrets",
            "vault_notification_channels",
            "vault_tokens",
            "vault_dek",
            "vault_pending_token_rotations",
            "vault_group_members",
            "vault_namespaces",
            "vault_groups",
        ):
            await db.execute(text(f"DELETE FROM {table}"))

        # Restore vault_config, exclude keys that belong to the CURRENT
        # vault (the bug fixed by Bloc G: copying the backup's
        # argon2_salt / master_check overwrote the running ones).
        for cfg in cfg_rows:
            if cfg["key"] in _CONFIG_KEYS_NEVER_RESTORED:
                continue
            # The custody generation row is per host, so its real key carries a
            # node uuid. Matching the bare name would let a backup taken on one
            # node import ANOTHER node's generation, which is the same failure
            # the exact match exists to prevent: a durable decision pointing at
            # a generation no local slot holds, and no way back short of
            # hand-editing vault_config.
            if cfg["key"].startswith(f"{CUSTODY_STATE_CONFIG_KEY}:"):
                continue
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) "
                    "VALUES (:key, :val) "
                    "ON CONFLICT (key) DO UPDATE SET value = :val"
                ),
                {"key": cfg["key"], "val": cfg["value"]},
            )
            restored["config"] += 1

        # Groups before namespaces (FK target).
        for g in tables.get("groups", []):
            await db.execute(
                text("""
                    INSERT INTO vault_groups (name, permissions, source, ldap_dn)
                    VALUES (:name, CAST(:perms AS jsonb), :source, :ldap_dn)
                """),
                {
                    "name": g["name"],
                    "perms": json.dumps(g.get("permissions", {})),
                    "source": g.get("source", "local"),
                    "ldap_dn": g.get("ldap_dn"),
                },
            )
            restored["groups"] += 1

        # `vault-admins` is a runtime invariant used as the owner of namespaces
        # created in non-RBAC mode. Legacy backups predate groups and therefore
        # do not carry it. Since restore wipes all target-side groups above,
        # re-establish the invariant without overriding a group imported from a
        # current backup.
        await db.execute(
            text("""
                INSERT INTO vault_groups (name, permissions, source)
                VALUES ('vault-admins', '{"admin": "rw"}'::jsonb, 'local')
                ON CONFLICT (name) DO NOTHING
            """)
        )

        # Namespaces. The backup's owner_group_id is a stale UUID
        # (groups got fresh ids during the restore loop above). Bloc G
        # re-links via owner_group_name (added to the backup payload
        # in create_backup). vault_namespaces.owner_group_id is NOT
        # NULL, so an unresolved name surfaces as 400, let the operator
        # know which group is missing rather than silently dropping a
        # namespace.
        for n in tables.get("namespaces", []):
            owner_name = n.get("owner_group_name")
            if not owner_name:
                raise HTTPException(
                    400,
                    f"Backup namespace {n['name']!r} has no "
                    "owner_group_name - older backup format not "
                    "supported by dual-context restore. Re-take the "
                    "backup with the current vault.",
                )
            await db.execute(
                text("""
                    INSERT INTO vault_namespaces
                        (name, owner_group_id, enforce_membership,
                         delete_protection, archived_at, created_by)
                    SELECT :name, g.id, :enforce, :del_prot,
                           :archived, :actor
                    FROM vault_groups g
                    WHERE g.name = :owner_name
                """),
                {
                    "name": n["name"],
                    "owner_name": owner_name,
                    "enforce": n.get("enforce_membership", False),
                    "del_prot": n.get("delete_protection", "free"),
                    "archived": _parse_ts(n.get("archived_at")),
                    "actor": n.get("created_by") or "restore",
                },
            )
            restored["namespaces"] += 1

        # Group members.
        for m in tables.get("group_members", []):
            if m.get("principal_type") != "external" or not m.get("principal_id"):
                raise HTTPException(
                    400,
                    "Backup group member is not a typed external principal; "
                    "create a fresh backup before restoring.",
                )
            await db.execute(
                text("""
                    INSERT INTO vault_group_members
                        (group_id, principal_type, external_id, added_at)
                    SELECT id, 'external', :principal_id,
                           COALESCE(:added_at, NOW())
                    FROM vault_groups
                    WHERE name = :group_name
                """),
                {
                    "group_name": m["group_name"],
                    "principal_id": m["principal_id"],
                    "added_at": _parse_ts(m.get("added_at")),
                },
            )
            restored["group_members"] += 1

        # Dual-context loop on secrets. For each secret in the backup:
        #   1. generate a fresh DEK id (needed up front - it's baked into
        #      the new AAD before either path below encrypts anything),
        #   2. on the master: vault.rotate_secret_from_backup chains
        #      decrypt(BACKUP) + encrypt(CURRENT) entirely in Rust. The
        #      plaintext and both DEKs never enter Python.
        #   3. on a follower: rotate_secret_from_backup returns None
        #      (reconstructing BackupCryptoContext via RPC would re-run
        #      Argon2id, ~0.5-1.5s, PER SECRET instead of once per
        #      restore) and we fall back to the pre-existing sequence -
        #      decrypt under BACKUP context, generate_dek() locally,
        #      wrap it via vault.aesgcm_encrypt (multi-worker safe,
        #      dispatches to master RPC), then encrypt_secret(). Both
        #      the fresh DEK and the plaintext are briefly immutable
        #      Python bytes on this path - documented, known, and only
        #      hit when the restore call lands on a follower.
        #   4. INSERT vault_dek + vault_secrets with the new ciphertexts,
        #   5. on the fallback path, secure_zero the plaintext bytearray
        #      returned by Rust; Drop on backup_ctx (later) zeroes the
        #      BACKUP keys either way.
        for s in tables.get("secrets", []):
            backup_dek_id = s.get("dek_id")
            if not backup_dek_id:
                raise HTTPException(
                    400,
                    "Backup secret is missing dek_id - older pre-AAD "
                    "format not supported by dual-context restore.",
                )
            name = s["name"]
            namespace = s.get("namespace", "default")
            try:
                backup_aad_version = s.get("aad_version", 1)
                backup_secret_aad = secret_aad(
                    name,
                    namespace,
                    version=backup_aad_version,
                )
            except ValueError as exc:
                raise HTTPException(
                    400,
                    f"Backup secret {name!r} has an invalid AAD version",
                ) from exc
            current_secret_aad = secret_aad(name, namespace)
            backup_dek_aad_bytes = dek_aad(backup_dek_id)

            # The vault_dek storage splits encrypted_key + nonce in
            # two columns; recombine into the nonce(12) || ciphertext
            # blob that BackupCryptoContext.decrypt_secret expects (same
            # wire format as WrapKey.aesgcm_subkey_decrypt).
            dek_wrapped = bytes.fromhex(s["dek_nonce"]) + bytes.fromhex(
                s["dek_encrypted"]
            )
            ciphertext_backup = bytes.fromhex(s["ciphertext"])
            nonce_backup = bytes.fromhex(s["nonce"])

            new_dek_id = str(uuid.uuid4())
            new_dek_aad = dek_aad(new_dek_id)

            # Fast path (master, or single-worker): decrypt(BACKUP) +
            # encrypt(CURRENT) chained entirely in Rust. Plaintext and
            # both DEKs never enter Python.
            fast = vault.rotate_secret_from_backup(
                backup_ctx,
                dek_wrapped,
                backup_dek_aad_bytes,
                ciphertext_backup,
                nonce_backup,
                backup_secret_aad,
                new_dek_aad,
                current_secret_aad,
            )
            secret_clear = None
            try:
                if fast is not None:
                    (
                        encrypted_dek,
                        new_dek_nonce,
                        new_ciphertext,
                        new_secret_nonce,
                    ) = fast
                else:
                    # Follower fallback: see the loop comment above for why
                    # this can't just dispatch to the master instead.
                    secret_clear = backup_ctx.decrypt_secret(
                        dek_wrapped,
                        backup_dek_aad_bytes,
                        ciphertext_backup,
                        nonce_backup,
                        backup_secret_aad,
                    )
                    new_dek = generate_dek()
                    encrypted_dek, new_dek_nonce = await vault.aesgcm_encrypt(
                        new_dek, new_dek_aad
                    )
                    new_ciphertext, new_secret_nonce = encrypt_secret(
                        bytes(secret_clear), new_dek, current_secret_aad
                    )

                await db.execute(
                    text("""
                        INSERT INTO vault_dek (id, encrypted_key, nonce)
                        VALUES (CAST(:id AS uuid), :ekey, :nonce)
                    """),
                    {
                        "id": new_dek_id,
                        "ekey": encrypted_dek,
                        "nonce": new_dek_nonce,
                    },
                )
                await db.execute(
                    text("""
                        INSERT INTO vault_secrets
                            (name, namespace, namespace_id, ciphertext, nonce,
                             aad_version, dek_id, metadata, version,
                             created_by, created_at,
                             updated_at, expires_at, is_honey, deleted_at,
                             purge_after)
                        VALUES
                            (:name, :ns,
                             (SELECT id FROM vault_namespaces WHERE name = :ns),
                             :ct, :nonce, :aad_version, CAST(:dek_id AS uuid),
                             CAST(:meta AS jsonb), :ver, :actor,
                             COALESCE(CAST(:created_at AS timestamptz), NOW()),
                             COALESCE(CAST(:updated_at AS timestamptz), NOW()),
                             CAST(:expires_at AS timestamptz),
                             CAST(:is_honey AS boolean),
                             CAST(:deleted_at AS timestamptz),
                             CAST(:purge_after AS timestamptz))
                    """),
                    {
                        "name": name,
                        "ns": namespace,
                        "ct": new_ciphertext,
                        "nonce": new_secret_nonce,
                        "aad_version": SECRET_AAD_VERSION,
                        "dek_id": new_dek_id,
                        "meta": json.dumps(s.get("metadata", {})),
                        "ver": s.get("version", 1),
                        "actor": actor,
                        "created_at": _parse_ts(s.get("created_at")),
                        "updated_at": _parse_ts(s.get("updated_at")),
                        "expires_at": _parse_ts(s.get("expires_at")),
                        "is_honey": bool(s.get("is_honey", False)),
                        "deleted_at": _parse_ts(s.get("deleted_at")),
                        "purge_after": _parse_ts(s.get("purge_after")),
                    },
                )
                restored["secrets"] += 1
            finally:
                # Only the fallback path (follower) produces a Python-side
                # plaintext at all. Zero the PyByteArray Rust returned; two
                # copies remain un-zeroable from Python on that path only -
                # `bytes(secret_clear)` above (PyNaCl's aead binding rejects
                # a bytearray message, forcing an immutable copy) and the
                # immutable `new_dek`. Both are RAM-only (mlockall'd). The
                # master/single-worker fast path above never creates either.
                if secret_clear is not None:
                    secure_zero(secret_clear)

        # Tokens land in vault_pending_token_rotations as stubs
        # awaiting admin rotation (the hashes in the backup were
        # computed under a DIFFERENT hmac_key, the current one;
        # they cannot be revived, so we don't try).
        backup_origin = data.get("created_at") or datetime.now(timezone.utc).isoformat()
        # Defensive: a backup payload may carry several token entries that
        # resolve to the same (name, namespace) pair under the current
        # derivation of namespace from permissions.namespaces[0]. Historical
        # rows (multiple active rows for the
        # same name sneaking past vault_tokens' partial UNIQUE INDEX) or a
        # future evolution of the ns derivation must not break the restore.
        # ON CONFLICT DO UPDATE keeps the loop idempotent: the last entry
        # for a given (name, ns) wins. The operator rotates the stub once
        # post-restore, regardless of how many historical hashes shared
        # that identity.
        for t in tables.get("tokens", []):
            await db.execute(
                text("""
                    INSERT INTO vault_pending_token_rotations
                        (name, namespace, permissions, allowed_ips, expires_at,
                         is_honey, group_names, backup_origin)
                    VALUES
                        (:name, :ns, CAST(:perms AS jsonb), :allowed_ips,
                         :expires_at, CAST(:is_honey AS boolean),
                         CAST(:group_names AS jsonb), :origin)
                    ON CONFLICT (name, namespace) DO UPDATE
                        SET permissions   = EXCLUDED.permissions,
                            allowed_ips   = EXCLUDED.allowed_ips,
                            expires_at    = EXCLUDED.expires_at,
                            is_honey      = EXCLUDED.is_honey,
                            group_names   = EXCLUDED.group_names,
                            backup_origin = EXCLUDED.backup_origin
                """),
                {
                    "name": t["name"],
                    "ns": t.get("namespace", "default"),
                    "perms": json.dumps(t.get("permissions", {})),
                    "allowed_ips": t.get("allowed_ips"),
                    "expires_at": _parse_ts(t.get("expires_at")),
                    "is_honey": bool(t.get("is_honey", False)),
                    "group_names": json.dumps(t.get("group_names", [])),
                    "origin": f"restore-{backup_origin}",
                },
            )
            restored["tokens_pending_rotation"] += 1

        # Post-restore flags:
        # pending_restore_bootstrap drives the next unseal to mint a
        # fresh `root-restore-<ts>` root token (since old token hashes
        # are gone, vault_tokens is wiped). pending_restore_review
        # drives the UI panel listing tables the admin must reconfigure
        # (YubiKeys, WebAuthn, notification channels, dynamic engines, audit
        # chain).
        for flag in ("pending_restore_bootstrap", "pending_restore_review"):
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) "
                    "VALUES (:key, '1') "
                    "ON CONFLICT (key) DO UPDATE SET value = '1'"
                ),
                {"key": flag},
            )

        await log_action(
            db,
            actor=actor,
            action="restore_backup_completed",
            detail=restored,
            ip_address=client_ip,
        )

        # The post-restore seal is a durable decision under Rust custody, not
        # just an in-process state flip: the maintenance leader re-attaches any
        # pool whose recorded activation still says unsealed, so a bare
        # vault.seal() would be undone within one maintenance interval and the
        # pending_restore_bootstrap root-token mint would never happen.
        # Writing it here makes the restore one recoverable operation -- either
        # the restored rows AND the seal decision commit, or neither. A crash
        # between this commit and the daemon seal below leaves the decision
        # durable, and the maintenance loop finishes the seal.
        if rust_custody:
            await set_rust_custody_activation(db, unsealed=False)

        await db.commit()
    finally:
        # Explicit drop = Rust LockedBuf Drop = zeroize + munlock on
        # master_key and dek_key. Even on exception (DB error,
        # decrypt failure mid-loop) the BACKUP keys are gone before
        # the response returns.
        del backup_ctx

    # Auto-seal safety net: even though argon2_salt did not change,
    # the master worker's cached sub-keys reference DEK ciphertexts
    # that have all been re-rotated under fresh DEK ids. The cleanest
    # invariant is "post-restore = sealed", so the next unseal re-
    # derives sub-keys + reads the new DEK rows. Also drives the
    # pending_restore_bootstrap mint of root-restore-<ts>.
    if rust_custody:
        from ..rust_custody_backend import (
            configured_rust_custody_pool,
            deactivate_rust_custody,
        )

        try:
            await deactivate_rust_custody(configured_rust_custody_pool(), vault)
        except Exception:
            # The decision committed above, so the pool is already destined to
            # seal: deactivate_rust_custody seals the local API view in its own
            # finally, and the maintenance leader seals any daemon this call
            # could not reach. Never turn a committed restore into a 500.
            log.warning("post-restore Rust custody seal incomplete", exc_info=True)
            async with vault.master_transition_lock():
                vault.detach_rpc_client()
                vault.seal()
    else:
        from ..cluster_setup import stop_master_services

        try:
            await stop_master_services(vault, db)
        except Exception:
            pass
        vault.seal()
    try:
        from .. import metrics as _m

        _m.seal_events.labels(trigger="restore").inc()
        _m.set_vault_sealed(True)
    except Exception:
        pass

    return {
        "status": "restored",
        "sealed": True,
        "next_step": (
            "Vault sealed after restore. Unseal with the CURRENT master "
            "password (NOT the backup one) - the response will include "
            "a fresh root token (shown once) with a short TTL. "
            "Backed-up tokens are in `Pending rotations` (Quasar) waiting "
            "for an admin to rotate or revoke them."
        ),
        **restored,
    }
