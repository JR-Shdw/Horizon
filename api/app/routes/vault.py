# DO NOT REMOVE: SPDX header + copyright are part of the AGPL-3.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Resurgamus Horizon, Author: shdw, License: AGPL-3.0-or-later
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Vault lifecycle, Shamir, 2FA, key rotation, and administrative controls.

Author: shdw <horizon@resurgamus.com>
Project: Resurgamus Horizon - self-hosted secrets vault.
License: AGPL-3.0-or-later - closed-source relicensing prohibited.
"""

import hmac as _hmac
import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, SecretStr
from rhorizon_crypto import DekCipher, secure_zero

# Operator Shamir (/shamir/init + unseal-from-shares) runs through the Rust
# constant-time GF, same arithmetic as the cluster path. The Python
# crypto.shamir_* stay as the parity reference (tests/test_shamir_parity.py).
from rhorizon_crypto import shamir_combine_bytes as shamir_combine
from rhorizon_crypto import shamir_split_bytes as shamir_split
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..audit_keyring import rotate_audit_keyring
from ..auth import actor_display_name, require_permission
from ..authfail import log_authfail
from ..client_ip import get_client_ip
from ..config import settings
from ..crypto import (
    dek_aad,
    derive_keys,
    derive_master_key_async,
    generate_salt,
    generate_totp_secret,
    get_totp_uri,
    hmac_token,
    verify_totp,
    verify_yubikey_response,
)
from ..database import get_db
from ..key_epoch import (
    KEY_ROTATION_LOCK,
    bump_key_epoch,
    get_key_epoch,
    require_generation_current,
)
from ..metrics import master_password_rotated
from ..rate_limit import check_rate_limit, clear_failures, record_failure
from ..totp_replay import verify_and_consume_totp
from ..vault_state import vault

CHALLENGE_TTL = 60  # seconds
CHALLENGE_BYTES = 32
_TWO_FACTOR_CONFIG_LOCK = "rhorizon:cluster:2fa_config"


def _encrypt_2fa(plaintext: bytes | bytearray, aesgcm: AESGCM | DekCipher) -> str:
    """Encrypt a 2FA secret with dek_key. Returns hex(nonce + ciphertext)."""
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return (nonce + ct).hex()


def _decrypt_2fa(stored: str | bytes, aesgcm: AESGCM | DekCipher) -> bytes:
    """Decrypt a 2FA secret. Accepts hex string or raw bytes."""
    raw = bytes.fromhex(stored) if isinstance(stored, str) else bytes(stored)
    return aesgcm.decrypt(raw[:12], raw[12:], None)


async def _encrypt_2fa_current(plaintext: bytes) -> str:
    """Encrypt a 2FA secret under the CURRENT dek_key, FOLLOWER-SAFE.

    Routes through vault.aesgcm_encrypt: local on the master, RPC-delegated on a
    follower (which holds no dek_key). Empty AAD matches the historical None-AAD
    _encrypt_2fa (None == empty for AES-GCM). Returns hex(nonce + ct)."""
    ct, nonce = await vault.aesgcm_encrypt(plaintext, b"")
    return (nonce + ct).hex()


async def _decrypt_2fa_secret(
    stored: str | bytes, aesgcm: AESGCM | None = None
) -> bytes:
    """Decrypt a 2FA secret, FOLLOWER-SAFE. With an explicit `aesgcm` (a caller-
    derived local key, e.g. unseal's password-derived key) decrypt directly;
    with None, route through vault.aesgcm_decrypt (local on master, RPC on a
    follower). Empty AAD matches the None-AAD _encrypt_2fa scheme."""
    raw = bytes.fromhex(stored) if isinstance(stored, str) else bytes(stored)
    if aesgcm is not None:
        return aesgcm.decrypt(raw[:12], raw[12:], None)
    return await vault.aesgcm_decrypt(raw[12:], raw[:12], b"")


async def rewrap_dek_encrypted_2fa(db, old_aesgcm, new_aesgcm) -> dict[str, int]:
    """Re-wrap every 2FA secret stored directly under dek_key, old -> new.

    Both rotations that derive a fresh dek_key (rotate-password and
    admin/rotate-dek-key) must move these rows in the same transaction. They
    are read at unseal with the dek_key derived from the password, so a missed
    row is an UNSEAL LOCKOUT once second_factor is totp or yubikey -- silent,
    permanent, and only visible at the next restart. One helper for both
    callers is the point: the previous per-route copies drifted apart.

    Wrap format is nonce(12) || ct, no AAD. ``vault_config`` stores it hex,
    ``vault_yubikeys.hmac_secret`` stores the same bytes raw. Fail-closed: an
    undecryptable row aborts the rotation rather than orphaning a factor.
    """
    counts = {"totp_secret": 0, "totp_pending": 0, "yubikeys": 0}

    for key in ("totp_secret", "totp_pending"):
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :k"), {"k": key}
            )
        ).fetchone()
        if row is None:
            continue
        new_blob = bytes(old_aesgcm.rewrap_to(new_aesgcm, bytes.fromhex(row.value)))
        await db.execute(
            text("UPDATE vault_config SET value = :val WHERE key = :k"),
            {"val": new_blob.hex(), "k": key},
        )
        counts[key] = 1

    yk_rows = await db.execute(text("SELECT id, hmac_secret FROM vault_yubikeys"))
    for row in yk_rows.fetchall():
        new_secret = bytes(old_aesgcm.rewrap_to(new_aesgcm, bytes(row.hmac_secret)))
        await db.execute(
            text(
                "UPDATE vault_yubikeys SET hmac_secret = :secret "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"secret": new_secret, "id": str(row.id)},
        )
        counts["yubikeys"] += 1

    return counts


router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


async def _master_transition_guard():
    """Serialize role-changing operator actions with local HA failover."""
    async with vault.master_transition_lock():
        yield


# -- Models ------------------------------------------------------------------


class UnsealRequest(BaseModel):
    password: SecretStr | None = None
    share: SecretStr | None = None  # legacy one-at-a-time hex Shamir share
    shares: list[SecretStr] | None = None  # atomic multi-worker-safe quorum
    yubikey_response: str | None = None  # hex, from YubiKey slot 2
    challenge: str | None = None  # hex, from POST /challenge
    totp_code: str | None = None  # 6-digit TOTP
    webauthn_response: dict | None = None  # WebAuthn assertion from browser


class UnsealResponse(BaseModel):
    status: str
    second_factor: str = "none"  # none | yubikey | totp | any
    shamir_progress: int | None = None  # shares submitted so far
    shamir_threshold: int | None = None  # shares needed


class StatusResponse(BaseModel):
    sealed: bool
    uptime: str | None = None
    version: str
    second_factor: str = "none"  # none | yubikey | totp | any
    yubikeys_registered: int = 0
    totp_enabled: bool = False
    webauthn_registered: int = 0
    shamir_enabled: bool = False
    shamir_threshold: int = 0
    shamir_total: int = 0
    shamir_progress: int = 0
    memory_protection: str = "mlock"
    process_memory_protection: str = "unknown"
    swap_protection: str = "unknown"
    custody_mode: str = "embedded"
    custody_backend: str = "python"
    custodian_workers_expected: int = 0
    custodian_workers_live: int = 0
    custodian_quorum_threshold: int = 0
    custodian_master_present: bool = False
    # Post-restore state, set by /backup/restore, drives the Settings/Core
    # review panel and the Quasar "Pending rotations" tab.
    pending_restore_review: bool = False
    pending_token_rotations_count: int = 0
    recovery_token_expires_at: str | None = None
    # Lazy token-migration window after a non-emergency master password
    # rotation, surfaced so the Core panel can state the real figure instead of
    # hardcoding one. It is a tunable (token_migration_window_days), and a UI
    # that says "15 days" is wrong the moment an operator changes it. No more
    # sensitive than the 2FA mode and Shamir parameters already returned here.
    token_migration_window_days: int = 15
    # Rotation grace window for secrets. 0 (the default) means an update
    # supersedes the old value immediately. When an operator raises it, the
    # PREVIOUS value stays readable via GET ?previous for this long -- which the
    # Eclipse save panel must say, or someone rotating a leaked secret from the
    # UI would believe the old value was already gone.
    secret_grace_seconds: int = 0


class ShamirInitRequest(BaseModel):
    current_password: SecretStr
    threshold: int  # M - minimum shares to unseal
    total: int  # N - total shares generated


class ShamirInitResponse(BaseModel):
    shares: list[str]  # hex-encoded, shown ONCE
    threshold: int
    total: int


class ChallengeResponse(BaseModel):
    challenge: str
    ttl: int = CHALLENGE_TTL


class YubikeyRegister(BaseModel):
    serial: str
    name: str = ""
    hmac_secret: SecretStr  # hex, 20 bytes - the secret programmed in slot 2


class TotpSetupResponse(BaseModel):
    secret: str  # base32
    uri: str  # otpauth:// URI for QR code


class TotpVerify(BaseModel):
    code: str


class _TwoFactorRequest(Protocol):
    challenge: str | None
    yubikey_response: str | None
    totp_code: str | None
    webauthn_response: dict | None


# -- Helpers -----------------------------------------------------------------


async def _get_shamir_config(db: AsyncSession) -> tuple[bool, int, int]:
    """Return authoritative (enabled, threshold, total) from vault_config."""
    result = await db.execute(
        text(
            "SELECT key, value FROM vault_config "
            "WHERE key IN ('shamir_enabled', 'shamir_threshold', 'shamir_total')"
        )
    )
    cfg = {r.key: r.value for r in result.fetchall()}
    enabled = cfg.get("shamir_enabled") == "true"
    threshold = int(cfg.get("shamir_threshold", "0"))
    total = int(cfg.get("shamir_total", "0"))
    return enabled, threshold, total


async def _get_2fa_mode(db: AsyncSession) -> str:
    """Get configured 2FA mode: none | yubikey | totp | any."""
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'second_factor'")
    )
    row = result.fetchone()
    return row.value if row else "none"


async def _lock_2fa_config(db: AsyncSession) -> None:
    """Serialize factor-policy and credential mutations across the cluster."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_name))"),
        {"lock_name": _TWO_FACTOR_CONFIG_LOCK},
    )


async def _set_2fa_mode(db: AsyncSession, mode: str) -> None:
    await _lock_2fa_config(db)
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('second_factor', :mode) "
            "ON CONFLICT (key) DO UPDATE SET value = :mode"
        ),
        {"mode": mode},
    )
    vault.invalidate_2fa_cache()


async def _get_salt(db: AsyncSession) -> bytes:
    """Get or create Argon2id salt."""
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
    )
    row = result.fetchone()
    if row:
        return bytes.fromhex(row.value)

    salt = generate_salt()
    result = await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('argon2_salt', :salt) "
            "ON CONFLICT (key) DO UPDATE SET value = vault_config.value "
            "RETURNING value"
        ),
        {"salt": salt.hex()},
    )
    return bytes.fromhex(result.scalar_one())


async def _get_dek_key_version(db: AsyncSession) -> int:
    """Read the current dek_key version from vault_config.

    Default 1 (v1 info string, backward-compat with pre-rotation data).
    Rotation bumps this counter and re-wraps all vault_dek entries.
    """
    r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'dek_key_version'")
    )
    row = r.fetchone()
    if not row:
        return 1
    try:
        version = int(row.value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            500, "Invalid dek_key_version in vault configuration"
        ) from exc
    if version < 1:
        raise HTTPException(500, "Invalid dek_key_version in vault configuration")
    return version


async def _is_first_boot(db: AsyncSession) -> bool:
    """True only if no vault state exists (fresh install).

    Bootstrap requires absence of all three keys: master_check, argon2_salt,
    vault_initialized. Deleting master_check alone is not enough to re-bootstrap.
    """
    result = await db.execute(
        text("""
            SELECT key FROM vault_config
            WHERE key IN ('master_check', 'argon2_salt', 'vault_initialized')
        """)
    )
    return not result.fetchall()


async def _yubikey_count(db: AsyncSession) -> int:
    result = await db.execute(text("SELECT count(*) FROM vault_yubikeys"))
    return result.scalar()


async def _totp_enabled(db: AsyncSession) -> bool:
    result = await db.execute(
        text("SELECT EXISTS(SELECT 1 FROM vault_config WHERE key = 'totp_secret')")
    )
    return result.scalar()


async def _webauthn_count(db: AsyncSession) -> int:
    result = await db.execute(text("SELECT count(*) FROM vault_webauthn"))
    return result.scalar()


async def _downgrade_2fa_if_unsatisfiable(db: AsyncSession) -> str | None:
    """Drop second_factor to a satisfiable mode after a factor is removed.

    Single source of truth for the auto-fallback (the three factor-removal
    routes -- delete_yubikey, delete_webauthn, totp_disable -- used to each
    carry their own copy, and all three missed mode='any', leaving a hard
    operator lockout: 'any' with no security key AND no totp can never satisfy
    unseal, and the mode can only be changed with an admin token, which needs
    an unsealed vault). Mirrors set_2fa_mode's factor requirements. Returns the
    new mode if a downgrade happened, else None (mode still satisfiable).
    """
    mode = await _get_2fa_mode(db)
    if mode == "none":
        return None
    has_key = (await _yubikey_count(db)) + (await _webauthn_count(db)) > 0
    has_totp = await _totp_enabled(db)
    satisfiable = (
        (mode == "yubikey" and has_key)
        or (mode == "totp" and has_totp)
        or (mode == "any" and (has_key or has_totp))
    )
    if satisfiable:
        return None
    new_mode = "yubikey" if has_key else ("totp" if has_totp else "none")
    await _set_2fa_mode(db, new_mode)
    return new_mode


async def _get_2fa_status(db: AsyncSession) -> tuple[str, int, bool, int]:
    """Get (mode, yubikey_count, totp_enabled, webauthn_count) - cached 10s."""
    cached = vault.get_2fa_cache()
    if cached is not None:
        return cached

    result = await db.execute(
        text("""
            SELECT
                (SELECT value FROM vault_config
                 WHERE key = 'second_factor') AS mode,
                (SELECT count(*) FROM vault_yubikeys) AS yk_count,
                (SELECT EXISTS(SELECT 1 FROM vault_config
                 WHERE key = 'totp_secret')) AS totp_on,
                (SELECT count(*) FROM vault_webauthn) AS wa_count
        """)
    )
    row = result.fetchone()
    mode = row.mode or "none"
    yk_count = row.yk_count
    totp_on = row.totp_on
    wa_count = row.wa_count

    vault.set_2fa_cache(mode, yk_count, totp_on, wa_count)
    return mode, yk_count, totp_on, wa_count


async def _check_challenge_exists(
    db: AsyncSession, challenge: str, client_ip: str | None, purpose: str = "unseal"
) -> None:
    """Verify a challenge exists in DB, not expired, and tagged for `purpose`.

    Raises 400 if missing/expired/wrong-purpose (and persists the audit
    entry). The caller must call _consume_challenge after successful 2FA
    validation to atomically burn the challenge for single-use semantics.
    The purpose tag prevents a register-flow challenge from being consumed by
    an unseal flow and vice versa.
    """
    result = await db.execute(
        text(
            "SELECT 1 FROM vault_challenges "
            "WHERE challenge = :ch AND purpose = :purpose AND expires_at > NOW()"
        ),
        {"ch": challenge, "purpose": purpose},
    )
    if not result.fetchone():
        await log_action(
            db,
            actor="anonymous",
            action="unseal_failed",
            detail={"reason": "invalid_challenge", "purpose": purpose},
            ip_address=client_ip,
        )
        await db.commit()
        raise HTTPException(400, "Invalid or expired challenge")


async def _consume_challenge(
    db: AsyncSession, challenge: str, client_ip: str | None, purpose: str = "unseal"
) -> None:
    """Atomically burn a previously-validated challenge tagged for `purpose`.

    Raises 400 if the row is gone (multi-worker race - another worker won
    the consumption). The caller has already validated the 2FA crypto, so
    this race only causes a cosmetic rejection - the legitimate operation
    succeeded on the winning worker.
    """
    result = await db.execute(
        text(
            "DELETE FROM vault_challenges "
            "WHERE challenge = :ch AND purpose = :purpose AND expires_at > NOW() "
            "RETURNING challenge"
        ),
        {"ch": challenge, "purpose": purpose},
    )
    if not result.fetchone():
        await log_action(
            db,
            actor="anonymous",
            action="unseal_failed",
            detail={"reason": "challenge_race", "purpose": purpose},
            ip_address=client_ip,
        )
        await db.commit()
        raise HTTPException(400, "Challenge already consumed")


async def _verify_2fa(
    db: AsyncSession,
    mode: str,
    body: _TwoFactorRequest,
    client_ip: str | None,
    aesgcm: AESGCM | None = None,
    purpose: str = "unseal",
) -> str:
    """Verify 2FA. Decrypts 2FA secrets with aesgcm (dek_key).

    Raises on failure. Returns which factor was used.

    `purpose` (default 'unseal' for back-compat) tags the DB challenge
    with its consumer flow. Namespace mutations use 'namespace_mutation'.
    The `body` is duck-typed - anything with .challenge / .yubikey_response /
    .totp_code / .webauthn_response attributes works.
    """
    if mode == "none":
        return "none"

    has_yubikey = body.yubikey_response is not None
    has_totp = body.totp_code is not None
    has_webauthn = body.webauthn_response is not None

    if not has_yubikey and not has_totp and not has_webauthn:
        methods = []
        if mode in ("yubikey", "any"):
            methods.append("security key")
        if mode in ("totp", "any"):
            methods.append("totp")
        raise HTTPException(
            400,
            f"Resurgamus Horizon/AGPL-3.0: Second factor required: "
            f"{' or '.join(methods)}",
        )

    # Try WebAuthn (browser-native FIDO2)
    if has_webauthn and mode in ("yubikey", "any"):
        if not body.challenge:
            raise HTTPException(400, "Challenge required with WebAuthn response")
        # Verify challenge exists -- do NOT consume yet
        await _check_challenge_exists(db, body.challenge, client_ip, purpose)

        from fido2.utils import websafe_encode
        from fido2.webauthn import AttestedCredentialData, AuthenticationResponse

        from .webauthn import _get_fido2_server

        wa_rows = await db.execute(
            text("SELECT credential_id, credential_data FROM vault_webauthn")
        )
        rows = wa_rows.fetchall()
        if not rows:
            raise HTTPException(400, "No WebAuthn credentials registered")

        credentials = [AttestedCredentialData(bytes(r.credential_data)) for r in rows]

        try:
            authentication = AuthenticationResponse.from_dict(body.webauthn_response)
        except Exception:
            raise HTTPException(400, "Invalid WebAuthn response format")
        wa_cred_id = bytes(authentication.raw_id)

        try:
            wa_challenge = bytes.fromhex(body.challenge)
        except ValueError:
            raise HTTPException(400, "Challenge must be hex-encoded")
        if len(wa_challenge) != CHALLENGE_BYTES:
            raise HTTPException(400, "Invalid challenge length")

        # fido2 2.x internal state: websafe-b64 challenge + explicit
        # user_verification key (authenticate_complete reads both)
        state = {"challenge": websafe_encode(wa_challenge), "user_verification": None}
        server = _get_fido2_server()
        try:
            server.authenticate_complete(state, credentials, authentication)
        except Exception:
            await log_action(
                db,
                actor="anonymous",
                action="unseal_failed",
                detail={"reason": "webauthn_invalid", "purpose": purpose},
                ip_address=client_ip,
            )
            await db.commit()
            raise HTTPException(401, "WebAuthn verification failed")

        # Crypto valid -- atomically consume the challenge, then advance the
        # sign counter only if this assertion is newer than persisted state.
        new_count = authentication.response.authenticator_data.counter
        await _consume_challenge(db, body.challenge, client_ip, purpose)
        counter_update = await db.execute(
            text(
                "UPDATE vault_webauthn SET sign_count = :count "
                "WHERE credential_id = :cid "
                "AND (:count > sign_count OR (:count = 0 AND sign_count = 0)) "
                "RETURNING credential_id"
            ),
            {"count": new_count, "cid": wa_cred_id},
        )
        if not counter_update.fetchone():
            await log_action(
                db,
                actor="anonymous",
                action="unseal_failed",
                detail={"reason": "webauthn_cloned_key", "purpose": purpose},
                ip_address=client_ip,
            )
            await db.commit()
            raise HTTPException(401, "Security key sign count anomaly")

        return "webauthn"

    # Try YubiKey
    if has_yubikey and mode in ("yubikey", "any"):
        if not body.challenge:
            raise HTTPException(400, "Challenge required with YubiKey response")
        # Verify challenge exists -- do NOT consume yet
        await _check_challenge_exists(db, body.challenge, client_ip, purpose)

        try:
            challenge_bytes = bytes.fromhex(body.challenge)
        except ValueError:
            raise HTTPException(400, "Challenge must be hex-encoded")
        if len(challenge_bytes) != CHALLENGE_BYTES:
            raise HTTPException(400, "Invalid challenge length")

        try:
            response_bytes = bytes.fromhex(body.yubikey_response)
        except ValueError:
            raise HTTPException(400, "YubiKey response must be hex-encoded")
        if len(response_bytes) != 20:
            raise HTTPException(400, "YubiKey response must be 20 bytes")

        # Check against all registered YubiKeys (secrets encrypted in DB)
        result = await db.execute(
            text("SELECT serial, hmac_secret FROM vault_yubikeys")
        )
        for row in result.fetchall():
            secret = await _decrypt_2fa_secret(bytes(row.hmac_secret), aesgcm)
            if verify_yubikey_response(secret, challenge_bytes, response_bytes):
                # HMAC valid -- consume challenge atomically
                await _consume_challenge(db, body.challenge, client_ip, purpose)
                return "yubikey"

        await log_action(
            db,
            actor="anonymous",
            action="unseal_failed",
            detail={"reason": "yubikey_invalid", "purpose": purpose},
            ip_address=client_ip,
        )
        await db.commit()
        raise HTTPException(401, "YubiKey verification failed")

    # Try TOTP
    if has_totp and mode in ("totp", "any"):
        result = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'totp_secret'")
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(400, "TOTP not configured")

        totp_secret = (await _decrypt_2fa_secret(row.value, aesgcm)).decode()

        if not await verify_and_consume_totp(db, totp_secret, body.totp_code):
            await log_action(
                db,
                actor="anonymous",
                action="unseal_failed",
                detail={"reason": "totp_invalid", "purpose": purpose},
                ip_address=client_ip,
            )
            await db.commit()
            raise HTTPException(401, "Invalid TOTP code")
        return "totp"

    # Factor provided doesn't match mode
    raise HTTPException(400, f"Provided factor not accepted in mode '{mode}'")


# -- Challenge ---------------------------------------------------------------


# Allowlisted challenge purposes. Adding a purpose value MUST be paired
# with the consumer endpoint passing the same purpose to
# `_check_challenge_exists` / `_consume_challenge` ; otherwise the
# purpose isolation guarantee breaks down. unseal is the original use
# case ; namespace_mutation guards the namespace mutations on
# /vault/namespaces/*.
_ALLOWED_CHALLENGE_PURPOSES = {
    "unseal",
    "namespace_mutation",
    "delete_protected_secret",
    "delete_namespace",
}


@router.post("/challenge", response_model=ChallengeResponse)
async def create_challenge(
    purpose: str = "unseal",
    db: AsyncSession = Depends(get_db),
):
    """Generate a random challenge for YubiKey HMAC-SHA1 (slot 2).

    Send this to your YubiKey, get the HMAC response, then POST to the
    consumer endpoint (`/unseal`, namespace mutations...)
    with `yubikey_response` + `challenge`. Short-lived and stored in DB
    for cross-worker safety.

    `purpose` (query param) tags the challenge to its consumer flow -
    a `purpose=unseal` challenge cannot be consumed by a namespace
    mutation and vice versa. Default is `unseal` for
    backward compat with existing CLI/API clients.
    """
    if purpose not in _ALLOWED_CHALLENGE_PURPOSES:
        raise HTTPException(400, f"Unknown challenge purpose: {purpose}")

    # Purge expired challenges
    await db.execute(text("DELETE FROM vault_challenges WHERE expires_at < NOW()"))

    challenge_hex = os.urandom(CHALLENGE_BYTES).hex()
    await db.execute(
        text("""
            INSERT INTO vault_challenges (challenge, expires_at, purpose)
            VALUES (:ch, NOW() + make_interval(secs => :ttl), :purpose)
        """),
        {"ch": challenge_hex, "ttl": CHALLENGE_TTL, "purpose": purpose},
    )
    await db.commit()

    return ChallengeResponse(challenge=challenge_hex)


# -- Unseal ------------------------------------------------------------------


@router.post("/unseal")
async def unseal(
    body: UnsealRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _transition_guard: None = Depends(_master_transition_guard),
):
    from .. import metrics as _m
    from ..custody import is_rust_custody_api

    rust_custody = is_rust_custody_api()

    if not vault.sealed:
        return UnsealResponse(status="already_unsealed")

    client_ip = get_client_ip(request)
    await check_rate_limit(db, client_ip)

    shamir_on, shamir_threshold, shamir_total = await _get_shamir_config(db)

    # -- Shamir mode ------------------------------------------------------
    # `shares=[...]` reconstructs atomically inside one request and is the
    # reliable path behind a multi-worker listener (successive HTTP requests
    # are not guaranteed to land on the same uvicorn process). `share=...`
    # remains as a bounded, five-minute compatibility accumulator.
    if shamir_on and (body.share is not None or body.shares is not None):
        if body.share is not None and body.shares is not None:
            raise HTTPException(400, "Provide either 'share' or 'shares', not both")

        atomic = body.shares is not None
        submitted = (
            [value.get_secret_value() for value in body.shares]
            if body.shares is not None
            else [body.share.get_secret_value()]
        )
        if atomic:
            if len(submitted) < shamir_threshold:
                raise HTTPException(
                    400,
                    f"Atomic Shamir unseal requires at least {shamir_threshold} shares",
                )
            if len(submitted) > shamir_total:
                raise HTTPException(
                    400,
                    f"Atomic Shamir unseal accepts at most {shamir_total} shares",
                )
            vault.clear_shares()

        count = 0
        try:
            for raw_share in submitted:
                try:
                    share_buf = bytearray.fromhex(raw_share)
                except ValueError:
                    raise HTTPException(400, "Share must be hex-encoded")
                try:
                    count = vault.add_share(share_buf)
                except ValueError as exc:
                    raise HTTPException(400, str(exc))
                finally:
                    secure_zero(share_buf)
        except Exception:
            if atomic:
                vault.clear_shares()
            raise

        if atomic and count < shamir_threshold:
            vault.clear_shares()
            raise HTTPException(400, "Atomic Shamir shares contain duplicate indices")

        if count < shamir_threshold:
            return UnsealResponse(
                status="share_accepted",
                shamir_progress=count,
                shamir_threshold=shamir_threshold,
            )

        # Threshold reached, reconstruct key material (5x32 = 160 bytes)
        try:
            key_material = bytearray(shamir_combine(vault.pending_shares))
        except Exception:
            vault.clear_shares()
            await record_failure(db, client_ip)
            log_authfail(client_ip, "shamir_reconstruction_failed")
            raise HTTPException(401, "Shamir reconstruction failed - shares cleared")

        keys: dict[str, bytearray] = {}
        try:
            if len(key_material) != 160:
                await record_failure(db, client_ip)
                log_authfail(client_ip, "shamir_invalid_data")
                raise HTTPException(401, "Invalid share data")

            keys = {
                "hmac_key": key_material[:32],
                "dek_key": key_material[32:64],
                "audit_key": key_material[64:96],
                "ha_wrap_key": key_material[96:128],
                "pki_wrap_key": key_material[128:160],
            }

            # Verify master check
            result = await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'master_check'")
            )
            check_row = result.fetchone()
            if not check_row:
                log_authfail(client_ip, "shamir_master_check_missing")
                raise HTTPException(500, "Vault initialization state is inconsistent")
            computed = hmac_token(keys["hmac_key"], "master-check-value")
            if not _hmac.compare_digest(computed, check_row.value):
                await record_failure(db, client_ip)
                log_authfail(client_ip, "shamir_master_check_failed")
                raise HTTPException(401, "Invalid shares - master check failed")

            # PyO3's direct ``&[u8]`` arguments currently require ``bytes``.
            # Keep those unavoidable immutable copies scoped to this call;
            # the bytearrays we control are wiped in the finally block.
            vault.unseal({name: bytes(value) for name, value in keys.items()})
        finally:
            vault.clear_shares()
            secure_zero(key_material)
            for key in keys.values():
                secure_zero(key)
        try:
            # Operator shares can predate a dek-key rotation while retaining the
            # same valid hmac_key. Prove their dek_key matches current encrypted
            # data before assigning the database epoch.
            from ..key_epoch import resolve_reconstruct_epoch

            db_epoch = await get_key_epoch(db)
            reconstructed_epoch = await resolve_reconstruct_epoch(db, vault.aesgcm)
            if reconstructed_epoch != db_epoch:
                log_authfail(client_ip, "shamir_stale_generation")
                raise HTTPException(
                    409,
                    "Shamir shares are from an obsolete key generation; "
                    "unseal with the master password and initialize fresh shares",
                )
            vault.set_key_epoch(reconstructed_epoch)
            await clear_failures(db, client_ip)

            # Load previous hmac_key for lazy token migration
            prev_row = await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'prev_hmac_key'")
            )
            prev = prev_row.fetchone()
            if prev:
                try:
                    prev_hmac = _decrypt_2fa(prev.value, vault.aesgcm)
                    try:
                        vault.set_prev_hmac(prev_hmac)
                    finally:
                        del prev_hmac
                except Exception:
                    pass

            # Best-effort load of ha_password from vault_cluster_config.
            # Absent row = pre-cluster-init state, normal.
            from ..ha_password import load_ha_password_into_ram

            try:
                await load_ha_password_into_ram(db)
            except Exception:
                pass

            from ..cluster import WorkerState as _ClusterState
            from ..cluster import update_worker_state as _cluster_update_worker_state
            from ..cluster_setup import start_master_services_or_rollback

            await _cluster_update_worker_state(db, _ClusterState.MASTER)
            await start_master_services_or_rollback(db, vault)

            # S6: provision + certify the per-node Ed25519 audit identity so new
            # entries sign asymmetrically (verifiable while sealed, rotation-
            # independent). Best-effort -- a failure keeps the legacy hmac chain
            # rather than blocking unseal. Runs before the unseal entry below so
            # that entry is the first ed25519-signed row (cutover boundary).
            try:
                from ..audit_identity import ensure_audit_chain_identity

                await ensure_audit_chain_identity(db)
            except Exception:
                import logging

                logging.getLogger("rhorizon.audit_identity").warning(
                    "audit identity bootstrap failed at unseal; chain stays hmac",
                    exc_info=True,
                )

            await log_action(
                db,
                actor="operator",
                action="unseal",
                detail={"method": "shamir", "shares_used": count},
                ip_address=client_ip,
            )
            await db.commit()
        except BaseException:
            import logging as _logging

            from ..cluster_setup import stop_master_services as _stop_master

            try:
                await _stop_master(vault, db=db, pid=os.getpid())
            except BaseException:
                _logging.getLogger("rhorizon.vault").debug(
                    "Shamir re-seal: stop_master_services raised",
                    exc_info=True,
                )
            finally:
                vault.seal()
            raise

        _m.unseal_attempts.labels(result="success").inc()
        _m.set_vault_sealed(False)
        return UnsealResponse(
            status="unsealed",
            shamir_progress=count,
            shamir_threshold=shamir_threshold,
        )

    # -- Password mode --
    if not body.password:
        if shamir_on:
            raise HTTPException(400, "Provide 'share' (Shamir) or 'password'")
        raise HTTPException(400, "Password required")

    # 1. Determine first-boot eligibility BEFORE any state mutation
    #    (triple lock prevents bootstrap via master_check deletion alone)
    first_boot_allowed = await _is_first_boot(db)

    # 2. Derive master key from password (dek_key uses the versioned info string)
    salt = await _get_salt(db)
    dek_version = await _get_dek_key_version(db)
    master_key = bytearray(
        await derive_master_key_async(body.password.get_secret_value().encode(), salt)
    )
    try:
        keys = derive_keys(master_key, dek_key_version=dek_version)
    finally:
        secure_zero(master_key)

    # 3. Verify master check (correct password?) or bootstrap
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'master_check'")
    )
    check_row = result.fetchone()

    first_boot = False
    if check_row:
        computed = hmac_token(keys["hmac_key"], "master-check-value")
        if not _hmac.compare_digest(computed, check_row.value):
            await log_action(
                db,
                actor="anonymous",
                action="unseal_failed",
                detail={"reason": "invalid_password"},
                ip_address=client_ip,
            )
            await record_failure(db, client_ip)
            log_authfail(client_ip, "invalid_password")
            _m.unseal_attempts.labels(result="invalid_password").inc()
            raise HTTPException(401, "Invalid password")
    elif first_boot_allowed:
        # First-time setup, create master_check + vault_initialized atomically
        from datetime import datetime, timezone

        check_value = hmac_token(keys["hmac_key"], "master-check-value")
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES ('master_check', :check)"
            ),
            {"check": check_value},
        )
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('vault_initialized', :ts)"
            ),
            {"ts": datetime.now(timezone.utc).isoformat()},
        )
        first_boot = True
    else:
        # Bootstrap blocked, vault already initialized but master_check is missing.
        # Indicates corruption or tampering. Refuse to mint a new master.
        await log_action(
            db,
            actor="anonymous",
            action="unseal_failed",
            detail={"reason": "bootstrap_blocked_state_inconsistent"},
            ip_address=client_ip,
        )
        await record_failure(db, client_ip)
        log_authfail(client_ip, "bootstrap_blocked")
        raise HTTPException(401, "Bootstrap not allowed - vault is already initialized")

    # 3. Verify 2FA (now we have dek_key to decrypt 2FA secrets)
    mode = await _get_2fa_mode(db)
    aesgcm_tmp = AESGCM(keys["dek_key"])
    try:
        factor_used = await _verify_2fa(db, mode, body, client_ip, aesgcm_tmp)
    except HTTPException:
        await record_failure(db, client_ip)
        log_authfail(client_ip, "2fa_failed")
        _m.unseal_attempts.labels(result="invalid_2fa").inc()
        raise
    finally:
        del aesgcm_tmp

    try:
        vault.unseal(keys)
    finally:
        keys.wipe()
        del keys
    # record the generation these keys belong to so the fence loop
    # can tell whether another host has since rotated past us.
    #
    # Invariant from here on: this worker is unsealed in-RAM. If ANY step of
    # the critical section below fails, we must re-seal before propagating the
    # error. A worker left unsealed-in-RAM but without published master
    # services answers the next /unseal with "already_unsealed" (the
    # short-circuit near the top of this handler) while no crypto socket is
    # ever bound -- which silently wedges cluster formation (the operator sees
    # a 200/sealed:false but every follower times out attaching to a master
    # socket that does not exist).
    try:
        vault.set_key_epoch(await get_key_epoch(db))
        await clear_failures(db, client_ip)

        # Load previous hmac_key for lazy token migration (if password rotated)
        prev_row = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'prev_hmac_key'")
        )
        prev = prev_row.fetchone()
        if prev:
            try:
                prev_hmac = _decrypt_2fa(prev.value, vault.aesgcm)
                try:
                    vault.set_prev_hmac(prev_hmac)
                finally:
                    del prev_hmac
            except Exception:
                pass  # corrupted or wrong key - ignore

        # Best-effort load of ha_password from vault_cluster_config.
        # Absent row = pre-cluster-init state, normal.
        from ..ha_password import load_ha_password_into_ram

        try:
            await load_ha_password_into_ram(db)
        except Exception:
            pass

        # Bootstrap root token on first boot OR right after a backup/restore.
        # Restore overwrites every token_hash with values from the backup
        # (hashed under the OLD hmac_key) and the OLD plaintexts were shown
        # once at creation, so the operator has no usable plaintext anymore.
        # The restore endpoint sets the pending_restore_bootstrap flag for us;
        # we consume it here under the same transaction as the token mint.
        root_token = None
        bootstrap_kind: str | None = None
        if first_boot:
            bootstrap_kind = "bootstrap"
        else:
            flag_row = await db.execute(
                text(
                    "SELECT value FROM vault_config "
                    "WHERE key = 'pending_restore_bootstrap' "
                    "FOR UPDATE"
                )
            )
            if flag_row.fetchone():
                bootstrap_kind = "restore-recovery"

        recovery_token_expires_at = None
        if bootstrap_kind is not None:
            from datetime import datetime, timedelta, timezone

            from ..config import settings as _settings
            from ..crypto import generate_token as _gen_token

            root_token = _gen_token()
            root_hash = await vault.hmac_sha512_hex(root_token)
            if bootstrap_kind == "restore-recovery":
                token_name = (
                    f"root-restore-{int(datetime.now(timezone.utc).timestamp())}"
                )
                recovery_token_expires_at = datetime.now(timezone.utc) + timedelta(
                    days=_settings.recovery_token_ttl_days
                )
            else:
                token_name = "root"
            # Idempotent mint: a residual *active* token of the same name is
            # debris from an aborted prior bootstrap (the triple-lock was
            # cleared to re-bootstrap but vault_tokens was not). It can no
            # longer authenticate anyway -- it was hashed under the previous,
            # now-gone hmac_key -- so supersede it in place rather than
            # colliding on uq_vault_tokens_active_name. Without this, the
            # INSERT raises UniqueViolation *after* vault.unseal() flipped this
            # worker to unsealed-in-RAM, wedging cluster formation as described
            # in the invariant comment above.
            await db.execute(
                text("""
                    INSERT INTO vault_tokens
                        (name, token_hash, permissions, active, created_by,
                         expires_at)
                    VALUES
                        (:name, :hash, CAST(:perms AS jsonb), true, :actor,
                         :expires_at)
                    ON CONFLICT (name) WHERE active
                    DO UPDATE SET token_hash = EXCLUDED.token_hash,
                                  permissions = EXCLUDED.permissions,
                                  created_by = EXCLUDED.created_by,
                                  expires_at = EXCLUDED.expires_at,
                                  created_at = NOW(),
                                  last_used_at = NULL,
                                  allowed_ips = NULL,
                                  is_honey = false,
                                  rotated_at = NULL,
                                  revoked_at = NULL
                """),
                {
                    "name": token_name,
                    "hash": root_hash,
                    "perms": '{"admin": "rw"}',
                    "actor": bootstrap_kind,
                    "expires_at": recovery_token_expires_at,
                },
            )
            if bootstrap_kind == "restore-recovery":
                await db.execute(
                    text(
                        "DELETE FROM vault_config "
                        "WHERE key = 'pending_restore_bootstrap'"
                    )
                )

        if not rust_custody:
            from ..cluster import WorkerState as _ClusterState
            from ..cluster import update_worker_state as _cluster_update_worker_state
            from ..cluster_setup import start_master_services_or_rollback

            await _cluster_update_worker_state(db, _ClusterState.MASTER)
            await start_master_services_or_rollback(db, vault)

        # S6: provision + certify the per-node Ed25519 audit identity (see the
        # shamir path above). Best-effort; runs before the unseal entry so that
        # entry is the first ed25519-signed row.
        try:
            from ..audit_identity import ensure_audit_chain_identity

            await ensure_audit_chain_identity(db)
        except Exception:
            import logging

            logging.getLogger("rhorizon.audit_identity").warning(
                "audit identity bootstrap failed at unseal; chain stays hmac",
                exc_info=True,
            )

        await log_action(
            db,
            actor="operator",
            action="unseal",
            detail={"method": "password", "second_factor": factor_used},
            ip_address=client_ip,
        )
        await db.commit()
        if rust_custody:
            from ..rust_custody_backend import (
                activate_rust_custody_from_local,
                configured_rust_custody_pool,
            )

            local_key_epoch = vault.key_epoch
            if local_key_epoch is None:
                raise RuntimeError("verified local generation has no key epoch")
            await activate_rust_custody_from_local(
                configured_rust_custody_pool(),
                vault,
                key_epoch=local_key_epoch,
                threshold=settings.rust_custodian_threshold,
                slots=settings.rust_custodian_slots,
            )
    except BaseException:
        # Critical section failed -- re-seal so a retry re-derives cleanly
        # instead of short-circuiting on a phantom-unsealed worker.
        # start_master_services_or_rollback already tears down master services
        # on its own failure; this guard also covers every earlier step.
        import logging as _logging

        from ..cluster_setup import stop_master_services as _stop_master

        try:
            await _stop_master(vault, db=db, pid=os.getpid())
        except BaseException:
            _logging.getLogger("rhorizon.vault").debug(
                "re-seal: stop_master_services raised", exc_info=True
            )
        finally:
            vault.seal()
        raise

    _m.unseal_attempts.labels(result="success").inc()
    _m.set_vault_sealed(False)

    resp = UnsealResponse(status="unsealed", second_factor=factor_used)
    # Include root token in response on first setup or right after a
    # backup/restore (the bootstrap_kind tells which warning to show).
    if root_token:
        if bootstrap_kind == "restore-recovery":
            warning = (
                "Recovery root token - TEMPORARY, shown once only. Save it "
                "now; use it to rotate the stubs in Quasar > Pending "
                "rotations and mint a permanent root token. It expires "
                "automatically and is revoked when you dismiss the "
                "post-restore review."
            )
        else:
            warning = "Root token - shown once only. Save it now."
        body_out = {
            **resp.model_dump(),
            "root_token": root_token,
            "warning": warning,
            "bootstrap_kind": bootstrap_kind,
        }
        if recovery_token_expires_at is not None:
            body_out["recovery_token_expires_at"] = (
                recovery_token_expires_at.isoformat()
            )
        return body_out
    return resp


# -- Rotate master password --------------------------------------------------


class RotatePasswordRequest(BaseModel):
    current_password: SecretStr
    new_password: SecretStr
    emergency: bool = False  # True = invalidate ALL tokens (compromise scenario)
    force: bool = False  # override the in-window second-rotation guard (see handler)


@router.post("/rotate-password")
async def rotate_password(
    body: RotatePasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Change the master password. Re-derives all keys and re-encrypts DEKs
    and 2FA secrets. Token handling depends on the mode. Vault stays unsealed.

    Two operational modes:
      - emergency=false (default, ADMIN OPS): existing tokens keep working
        via lazy migration (prev_hmac_key stored, valid up to 15 days).
        Use case: routine password rotation, no suspicion of compromise.
      - emergency=true (SEC OPS): no prev_hmac_key stored - every existing
        token (including the caller's) is invalidated immediately. A fresh
        admin root token is returned once and must be saved by the operator.
        Use case: master password or token compromise.
    """
    vault.require_unsealed()
    client_ip = get_client_ip(request)

    # Cluster-wide singleton: only one host may rotate at a time.
    # The lock is xact-scoped: held until commit at the end, or released on
    # crash via TCP teardown + rollback (DB state then unchanged).
    lock_acquired = await db.execute(
        text(
            "SELECT pg_try_advisory_xact_lock("
            "hashtext('rhorizon:cluster:rotate_password'))"
        )
    )
    if not lock_acquired.scalar():
        raise HTTPException(
            status_code=409,
            detail="another host is already rotating the master password",
        )
    key_rotation_lock = await db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
        {"lock_name": KEY_ROTATION_LOCK},
    )
    if not key_rotation_lock.scalar():
        raise HTTPException(
            status_code=409,
            detail="another host is already performing a key rotation",
        )
    rust_rotation = (
        settings.custody_mode == "separated" and settings.custody_backend == "rust"
    )
    if rust_rotation:
        from ..custody_generation import CUSTODY_ORCHESTRATION_LOCK

        custody_lock = await db.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
            {"lock_name": CUSTODY_ORCHESTRATION_LOCK},
        )
        if not custody_lock.scalar():
            raise HTTPException(
                status_code=409,
                detail="another Rust custody operation is in progress",
            )

        # Same reason as rotate-dek-key: the staging below drives the pool, so
        # a worker that is not attached yet must attach rather than turn a
        # recoverable condition into a failed password rotation.
        from ..custody_routing import ensure_control_plane
        from ..rust_custody_backend import configured_rust_custody_pool

        await ensure_control_plane(configured_rust_custody_pool(), vault)

    # In-window second-rotation guard. Only ONE prev_hmac generation is kept,
    # so a second non-emergency rotation inside the migration window silently
    # strands every token minted before the FIRST rotation (their hmac_key is
    # evicted from current+prev). Refuse it unless force=true, turning a silent
    # token wipe into a loud, opt-in decision. Emergency rotations are exempt:
    # they intentionally invalidate everything regardless. force=true callers
    # must accept the blast radius (and re-mint long-lived tokens themselves).
    if not body.emergency and not body.force:
        prev_row = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'prev_hmac_rotated_at'")
        )
        prev_ts = prev_row.fetchone()
        if prev_ts:
            from datetime import datetime, timedelta, timezone

            from ..config import settings as _settings

            rotated_at = datetime.fromisoformat(prev_ts.value)
            window = timedelta(days=_settings.token_migration_window_days)
            if datetime.now(timezone.utc) < rotated_at + window:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "A non-emergency master password rotation already "
                        f"happened at {rotated_at.isoformat()}; a second rotation "
                        f"within the {_settings.token_migration_window_days}-day "
                        "migration window would invalidate every token minted "
                        "before it (only one prev_hmac generation is kept). "
                        "Re-mint long-lived tokens and wait out the window, or "
                        "retry with force=true to proceed anyway (this WILL "
                        "invalidate those tokens)."
                    ),
                )

    # 1. Verify current password (using the current dek_key version)
    salt = await _get_salt(db)
    dek_version = await _get_dek_key_version(db)
    old_mk = bytearray(
        await derive_master_key_async(
            body.current_password.get_secret_value().encode(), salt
        )
    )
    try:
        old_keys = derive_keys(old_mk, dek_key_version=dek_version)
    finally:
        secure_zero(old_mk)

    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'master_check'")
    )
    check_row = result.fetchone()
    if not check_row:
        raise HTTPException(500, "No master_check in vault_config")
    computed = hmac_token(old_keys["hmac_key"], "master-check-value")
    if not _hmac.compare_digest(computed, check_row.value):
        raise HTTPException(401, "Current password is incorrect")

    # 2. Derive new keys, same dek_key_version (password rotation doesn't bump it)
    new_salt = generate_salt()
    new_mk = bytearray(
        await derive_master_key_async(
            body.new_password.get_secret_value().encode(), new_salt
        )
    )
    try:
        new_keys = derive_keys(new_mk, dek_key_version=dek_version)
    finally:
        secure_zero(new_mk)

    new_aesgcm = DekCipher(new_keys["dek_key"])
    # Decrypt the DEKs with the key matching the CURRENT DB generation, derived
    # above from the live dek_key_version -- NOT vault.aesgcm. On a host whose
    # in-RAM keys lag a peer's dek-key rotation (key_epoch behind the DB), the
    # cached aesgcm holds the old dek_key while the rows are already re-wrapped
    # under the new one; using it tag-fails every DEK -> unhandled 500 (S4 C1).
    # old_keys["dek_key"] tracks the DB, so a behind host rotates correctly and
    # self-heals to the new generation at the vault.unseal() below.
    old_aesgcm = DekCipher(old_keys["dek_key"])

    # 3. Re-encrypt all DEKs (old dek_key -> new dek_key, AAD bound to row id)
    dek_rows = await db.execute(text("SELECT id, encrypted_key, nonce FROM vault_dek"))
    dek_count = 0
    for row in dek_rows.fetchall():
        aad = dek_aad(str(row.id))
        wrapped = bytes(row.nonce) + bytes(row.encrypted_key)
        rewrapped = bytes(old_aesgcm.rewrap_to(new_aesgcm, wrapped, aad))
        await db.execute(
            text("""
                UPDATE vault_dek
                SET encrypted_key = :ekey, nonce = :nonce
                WHERE id = CAST(:id AS uuid)
            """),
            {
                "ekey": rewrapped[12:],
                "nonce": rewrapped[:12],
                "id": str(row.id),
            },
        )
        dek_count += 1

    # 4. Token migration policy depends on rotation mode.
    #    emergency=false : preserve old hmac_key for lazy migration -
    #                      existing tokens keep working ~15 days.
    #    emergency=true  : drop prev_hmac_key entirely, every token
    #                      (caller included) becomes invalid as soon as
    #                      we flip vault.hmac_key.
    if not body.emergency:
        old_hmac_hex = _encrypt_2fa(old_keys["hmac_key"], new_aesgcm)
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('prev_hmac_key', :val)
                ON CONFLICT (key) DO UPDATE SET value = :val
            """),
            {"val": old_hmac_hex},
        )
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('prev_hmac_rotated_at', NOW()::text)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """)
        )
        # Authentication uses last_used_at IS NULL as the durable marker for
        # tokens that may still carry the previous HMAC. Reset every active
        # token in the same rotation transaction; otherwise tokens used before
        # rotation retain a timestamp and the first lazy migration can
        # incorrectly conclude that all tokens have migrated.
        await db.execute(
            text("UPDATE vault_tokens SET last_used_at = NULL WHERE active = true")
        )
    else:
        # Wipe any prev_hmac_key from a previous lazy rotation, emergency
        # mode means we explicitly do not want lazy migration paths to exist.
        await db.execute(
            text(
                "DELETE FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
            )
        )

    token_result = await db.execute(
        text("SELECT count(*) FROM vault_tokens WHERE active = true")
    )
    active_tokens = token_result.scalar()

    # 5. Re-encrypt 2FA secrets (TOTP + YubiKeys) -- shared with rotate_dek_key,
    #    the other route that derives a new dek_key.
    await rewrap_dek_encrypted_2fa(db, old_aesgcm, new_aesgcm)

    # 5b. Re-wrap ha_password under the new ha_wrap_key.
    #     The OLD ha_wrap_key cannot decrypt the row after the master flips,
    #     and a silent loss is worse than a failed rotation (cluster JOIN
    #     would 401 the next time around with no actionable error).
    from ..ha_password import rewrap_for_master_rotation

    await rewrap_for_master_rotation(
        db, old_keys["ha_wrap_key"], new_keys["ha_wrap_key"]
    )

    # 5c. Re-wrap the HA cluster CA key under the new ha_wrap_key (no-op if no
    #     HA cluster CA exists yet). This is separate from ha_password even
    #     though both use ha_wrap_key: losing this row strands /cluster/join,
    #     /cluster/refresh-cert and /cluster/rotate-ca after password rotation.
    from ..cluster_ca import rewrap_for_master_rotation as rewrap_cluster_ca

    await rewrap_cluster_ca(db, old_keys["ha_wrap_key"], new_keys["ha_wrap_key"])

    # 5d. Re-wrap the PKI-engine CA key under the new pki_wrap_key (no-op if no
    #     CA initialised). Same rationale as 5b: the OLD pki_wrap_key cannot
    #     decrypt the at-rest CA key after the master flips.
    from ..pki_ca import rewrap_for_master_rotation as rewrap_pki_ca

    await rewrap_pki_ca(db, old_keys["pki_wrap_key"], new_keys["pki_wrap_key"])

    # 6. Update salt + master_check
    await db.execute(
        text("UPDATE vault_config SET value = :val WHERE key = 'argon2_salt'"),
        {"val": new_salt.hex()},
    )
    new_check = hmac_token(new_keys["hmac_key"], "master-check-value")
    await db.execute(
        text("UPDATE vault_config SET value = :val WHERE key = 'master_check'"),
        {"val": new_check},
    )

    # 7. Audit + commit FIRST -- only mutate process state if DB persisted.
    #    If commit fails or the process crashes between vault.unseal(new_keys)
    #    and db.commit(), peers would receive new keys while the DB still holds
    #    DEKs under the old dek_key -- every secret read AES-GCM tag-fails until
    #    a manual seal+restart.
    # Emergency rotation invalidates every token -- the caller's included, and
    # the stored root token -- and a re-unseal of an already-initialised vault
    # mints nothing (bootstrap_kind stays None). So mint a fresh admin:rw root
    # token HERE, hashed under the NEW hmac_key, atomically in this transaction,
    # and return it ONCE below. Without it, emergency rotation is a one-way
    # lockout needing a restore-from-backup. (Non-emergency keeps prev_hmac, so
    # the caller's own token survives via lazy migration -- no mint needed.)
    emergency_root_token = None
    emergency_root_name = None
    if body.emergency:
        from datetime import datetime, timezone

        from ..crypto import generate_token as _gen_token

        emergency_root_token = _gen_token()
        emergency_root_name = (
            f"root-emergency-{int(datetime.now(timezone.utc).timestamp())}"
        )
        await db.execute(
            text("""
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, active, created_by)
                VALUES
                    (:name, :hash, CAST(:perms AS jsonb), true, :actor)
            """),
            {
                "name": emergency_root_name,
                "hash": hmac_token(new_keys["hmac_key"], emergency_root_token),
                "perms": '{"admin": "rw"}',
                "actor": "rotate_password_emergency",
            },
        )

    # audit half: archive the retiring audit_key under the current
    # (old) epoch and re-wrap the rest of the archive under the new dek_key, so
    # /audit/verify can still check pre-rotation entries. The OLD audit_key
    # exists only here -- after the unseal below it is gone.
    old_epoch = await get_key_epoch(db)
    await rotate_audit_keyring(
        db,
        retiring_epoch=old_epoch,
        retiring_audit_key=old_keys["audit_key"],
        old_aesgcm=old_aesgcm,
        new_aesgcm=new_aesgcm,
    )
    new_epoch = old_epoch + 1

    # S7: the dek_key changes with the master password, so re-wrap the at-rest
    # Ed25519 audit identity seed old->new dek in this same txn. Without it the
    # next unseal cannot decrypt the seed and the chain silently falls back to
    # hmac. The live signer is unaffected (vault.unseal below keeps it).
    from ..audit_identity import rewrap_seed_for_rotation

    await rewrap_seed_for_rotation(db, old_aesgcm, new_aesgcm)
    del old_aesgcm
    del new_aesgcm

    migration_mode = "emergency_invalidate" if body.emergency else "lazy"
    # Logged BEFORE the epoch bump: this entry is signed with the old audit_key,
    # so it must be tagged with the old epoch (log_action reads get_key_epoch).
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rotate_password_emergency" if body.emergency else "rotate_password",
        detail={
            "deks_rotated": dek_count,
            "active_tokens": active_tokens,
            "token_migration": migration_mode,
            "key_epoch": new_epoch,
            **(
                {"emergency_root_minted": emergency_root_name}
                if emergency_root_name
                else {}
            ),
        },
        ip_address=client_ip,
        # emergency rotation = sec-ops, immediate token invalidation,
        # operator-alertable. Routine rotation stays at default severity.
        critical=bool(body.emergency),
    )
    rust_pool = None
    rust_target = None
    rust_previous = None
    if rust_rotation:
        from ..custody_reshare import stage_local_bundle_for_rust_rotation
        from ..rust_custody_backend import configured_rust_custody_pool

        rust_pool = configured_rust_custody_pool()
        rotation_bundle = bytearray()
        try:
            for key_name in (
                "hmac_key",
                "dek_key",
                "audit_key",
                "ha_wrap_key",
                "pki_wrap_key",
            ):
                rotation_bundle.extend(new_keys[key_name])
            rust_target, rust_previous = await stage_local_bundle_for_rust_rotation(
                rotation_bundle,
                rust_pool,
                threshold=settings.rust_custodian_threshold,
                slots=settings.rust_custodian_slots,
            )
        except BaseException:
            # Staging restores the previous generation itself, but the seal it
            # went through dropped the ancillary envelopes and detached nothing.
            from ..rust_custody_backend import resync_rust_custody_attachment

            await resync_rust_custody_attachment(rust_pool, vault, key_epoch=old_epoch)
            raise
        finally:
            secure_zero(rotation_bundle)

    # bump the unified key generation in the SAME transaction as the
    # re-wrapped DEKs. Every other host's keys now lag this epoch; their fence
    # loop quarantines them out of /readiness until an operator re-unseals.
    try:
        if rust_target is not None:
            from ..custody_generation import choose_custody_generation

            await choose_custody_generation(db, rust_target)
        await bump_key_epoch(db)
        await db.commit()
    except Exception:
        await db.rollback()
        if rust_target is not None:
            assert rust_pool is not None and rust_previous is not None
            from ..rust_custody_backend import abort_rust_custody_key_rotation

            await abort_rust_custody_key_rotation(
                rust_pool,
                vault,
                target=rust_target,
                previous=rust_previous,
                key_epoch=old_epoch,
            )
        raise
    master_password_rotated.labels(
        mode="sec_ops" if body.emergency else "admin_ops"
    ).inc()

    # 8. DB persisted, now safe to flip in-memory state and broadcast to peers.
    if rust_target is not None:
        assert rust_pool is not None
        from ..rust_custody_backend import finish_rust_custody_key_rotation

        await finish_rust_custody_key_rotation(
            rust_pool,
            vault,
            target=rust_target,
            key_epoch=new_epoch,
        )
    else:
        vault.unseal(new_keys)
        # This worker is now on the new generation; record it so its own fence
        # loop does not quarantine the host that just rotated.
        vault.set_key_epoch(new_epoch)
        if not body.emergency:
            vault.set_prev_hmac(old_keys["hmac_key"])
        else:
            # Make sure no stale prev_hmac lingers in this worker's RAM.
            vault.clear_prev_hmac()
    old_keys.wipe()
    del old_keys

    # publish the signed rekey envelope so live-but-stale peers
    # roll forward to this generation automatically. NON-emergency only --
    # emergency severs the old->new link on purpose (peers quarantine and need
    # an operator re-unseal). Follow-up txn after the rotation commit : a
    # publish failure degrades to the fence backstop, never rolls back the
    # rotation that already committed.
    try:
        if not body.emergency:
            from ..cluster_rekey import publish_envelope

            bundle = bytearray()
            try:
                for key_name in (
                    "hmac_key",
                    "dek_key",
                    "audit_key",
                    "ha_wrap_key",
                    "pki_wrap_key",
                ):
                    bundle.extend(new_keys[key_name])
                # The rotation ran in whatever worker the routing mesh picked.
                # If that was a FOLLOWER, the host's master process still holds
                # the pre-rotation sub-keys (vault.unseal above only refreshed the
                # RPC listener when THIS worker owns it). Keep the host in the
                # envelope's recipient set so its master rolls forward instead of
                # stranding.
                await publish_envelope(
                    db, bundle, new_epoch, rotator_is_master=vault.is_master
                )
            finally:
                secure_zero(bundle)
                del bundle
    finally:
        new_keys.wipe()
        del new_keys

    if body.emergency:
        token_msg = (
            "All tokens invalidated. A fresh admin:rw root token was minted and "
            "is returned as root_token below - shown ONCE, save it now. Use it "
            "to re-provision your agents/scripts."
        )
    else:
        token_msg = "Existing tokens will be migrated on next use."

    resp_body = {
        "status": "password_rotated",
        "mode": "emergency" if body.emergency else "admin",
        "deks_rotated": dek_count,
        "active_tokens": active_tokens,
        "token_migration": token_msg,
    }
    if emergency_root_token:
        resp_body["root_token"] = emergency_root_token
        resp_body["root_token_name"] = emergency_root_name
        resp_body["warning"] = "Root token - shown once only. Save it now."
    return resp_body


# -- Seal --------------------------------------------------------------------


@router.post("/seal")
async def seal(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
    _transition_guard: None = Depends(_master_transition_guard),
):
    if vault.sealed:
        return {"status": "already_sealed"}

    # Log BEFORE sealing (audit_key still available for signing)
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="seal",
        ip_address=get_client_ip(request),
    )
    await db.commit()

    from .. import metrics as _m
    from ..custody import is_rust_custody_api

    if is_rust_custody_api():
        from ..rust_custody_backend import (
            configured_rust_custody_pool,
            deactivate_rust_custody,
        )

        await deactivate_rust_custody(
            configured_rust_custody_pool(),
            vault,
            local_transition_locked=True,
        )
        _m.seal_events.labels(trigger="manual").inc()
        _m.set_vault_sealed(True)
        return {"status": "sealed"}

    from ..cluster_setup import stop_master_services

    try:
        await stop_master_services(vault, db)
    finally:
        vault.seal()
    _m.seal_events.labels(trigger="manual").inc()
    _m.set_vault_sealed(True)
    return {"status": "sealed"}


# -- Status ------------------------------------------------------------------


@router.get("/status", response_model=StatusResponse)
async def status(db: AsyncSession = Depends(get_db)):
    mode, yk_count, totp_on, wa_count = await _get_2fa_status(db)
    shamir_on, shamir_threshold, shamir_total = await _get_shamir_config(db)

    review_row = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'pending_restore_review'")
    )
    pending_review = bool(review_row.fetchone())
    pending_count = 0
    recovery_expires_at = None
    custodian_workers_live = 0
    custodian_master_present = False
    custodian_quorum_threshold = 0
    if settings.custody_mode == "separated" and settings.custody_backend == "rust":
        from ..rust_custody_backend import configured_rust_custody_pool

        observed = await configured_rust_custody_pool().availability_statuses()
        live_statuses = [value for value in observed.values() if value is not None]
        custodian_workers_live = len(live_statuses)
        custodian_master_present = (
            sum(status.get("state") == "unsealed" for status in live_statuses) == 1
        )
        custodian_quorum_threshold = settings.rust_custodian_threshold
    elif settings.custody_mode == "separated":
        from ..cluster import MASTER_TIMEOUT_SECS, get_hostname

        custody_rows = await db.execute(
            text("""
                SELECT COUNT(*) AS live,
                       COUNT(*) FILTER (WHERE worker_state = 'master') AS masters
                FROM vault_workers
                WHERE hostname = :hostname
                  AND last_heartbeat >
                      NOW() - make_interval(secs => :timeout)
            """),
            {"hostname": get_hostname(), "timeout": MASTER_TIMEOUT_SECS},
        )
        custody_row = custody_rows.fetchone()
        custodian_workers_live = int(custody_row.live or 0)
        custodian_master_present = int(custody_row.masters or 0) == 1
        custodian_quorum_threshold = settings.cluster_shamir_threshold or max(
            2, settings.custodian_workers // 2 + 1
        )
    if pending_review:
        cnt_row = await db.execute(
            text("SELECT COUNT(*) FROM vault_pending_token_rotations")
        )
        pending_count = int(cnt_row.scalar() or 0)
        exp_row = await db.execute(
            text(
                "SELECT expires_at FROM vault_tokens "
                "WHERE created_by = 'restore-recovery' AND active "
                "ORDER BY created_at DESC LIMIT 1"
            )
        )
        exp = exp_row.fetchone()
        if exp and exp.expires_at:
            recovery_expires_at = exp.expires_at.isoformat()

    return StatusResponse(
        sealed=vault.sealed,
        uptime=vault.uptime,
        version=settings.version,
        second_factor=mode,
        yubikeys_registered=yk_count,
        totp_enabled=totp_on,
        webauthn_registered=wa_count,
        shamir_enabled=shamir_on,
        shamir_threshold=shamir_threshold,
        shamir_total=shamir_total,
        shamir_progress=vault.shamir_progress,
        memory_protection=vault.memory_protection,
        process_memory_protection=vault.process_memory_protection,
        swap_protection=vault.swap_protection,
        custody_mode=settings.custody_mode,
        custody_backend=settings.custody_backend,
        custodian_workers_expected=(
            (
                settings.rust_custodian_slots
                if settings.custody_backend == "rust"
                else settings.custodian_workers
            )
            if settings.custody_mode == "separated"
            else 0
        ),
        custodian_workers_live=custodian_workers_live,
        custodian_quorum_threshold=custodian_quorum_threshold,
        custodian_master_present=custodian_master_present,
        pending_restore_review=pending_review,
        pending_token_rotations_count=pending_count,
        recovery_token_expires_at=recovery_expires_at,
        token_migration_window_days=settings.token_migration_window_days,
        secret_grace_seconds=settings.secret_grace_seconds,
    )


# -- Post-restore review dismiss --------------------------------------------


@router.post("/post-restore-review/dismiss")
async def dismiss_post_restore_review(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Clear the post-restore review flag and revoke recovery root tokens.

    The recovery root token minted at the unseal-post-restore step is meant as a
    one-shot break-glass - once the admin has rotated the pending tokens
    and rebuilt a normal root token, dismissing the review panel auto-
    revokes the recovery root token. If the caller is using the recovery root token
    itself, their token is revoked too (warning returned).
    """
    replacement = await db.execute(
        text("""
            SELECT id
              FROM vault_tokens
             WHERE active
               AND created_by <> 'restore-recovery'
               AND is_honey = false
               AND POSITION(
                       'w' IN COALESCE(permissions ->> 'admin', '')
                   ) > 0
               AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY expires_at NULLS FIRST
             LIMIT 1
             FOR SHARE
        """)
    )
    if replacement.fetchone() is None:
        raise HTTPException(
            409,
            "Mint a separate active admin:w token before dismissing recovery review",
        )

    caller_token_id = token_info.get("id")

    await db.execute(
        text("DELETE FROM vault_config WHERE key = 'pending_restore_review'")
    )
    revoke = await db.execute(
        text("""
            UPDATE vault_tokens
               SET active = false, revoked_at = NOW()
             WHERE created_by = 'restore-recovery' AND active
            RETURNING id
        """)
    )
    revoked_ids = [str(r.id) for r in revoke.fetchall()]
    caller_revoked = caller_token_id and str(caller_token_id) in revoked_ids

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="post_restore_review_dismissed",
        detail={"revoked_recovery_tokens": len(revoked_ids)},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    body = {
        "status": "dismissed",
        "revoked_recovery_tokens": len(revoked_ids),
    }
    if caller_revoked:
        body["warning"] = (
            "Your current token has been revoked. Re-authenticate with a "
            "root token before issuing further requests."
        )
    return body


# -- Shamir init -------------------------------------------------------------


@router.post("/shamir/init", response_model=ShamirInitResponse)
async def shamir_init(
    body: ShamirInitRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Split the current master key into Shamir shares.

    Vault must be unsealed. Shares are shown ONCE - store them securely.
    After this, unseal accepts 'share' instead of 'password'.
    Password unseal remains available as fallback.
    """
    vault.require_unsealed()

    if body.threshold < 2:
        raise HTTPException(400, "Threshold must be >= 2")
    if body.total < body.threshold:
        raise HTTPException(400, "Total must be >= threshold")
    if body.total > 255:
        raise HTTPException(400, "Maximum 255 shares")

    await require_generation_current(db, vault)
    salt = await _get_salt(db)
    dek_version = await _get_dek_key_version(db)
    master_key = bytearray(
        await derive_master_key_async(
            body.current_password.get_secret_value().encode(), salt
        )
    )
    try:
        verification_keys = derive_keys(master_key, dek_key_version=dek_version)
    finally:
        secure_zero(master_key)
    try:
        check_result = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'master_check'")
        )
        check_row = check_result.fetchone()
        if check_row is None:
            raise HTTPException(500, "No master_check in vault_config")
        computed = hmac_token(verification_keys["hmac_key"], "master-check-value")
        if not _hmac.compare_digest(computed, check_row.value):
            raise HTTPException(401, "Current password is incorrect")
    finally:
        verification_keys.wipe()
        del verification_keys

    # Shamir split needs plaintext sub-keys in bytes form; export returns a
    # bytearray we zeroize right after.
    key_material = vault.export_subkeys_for_shamir()
    try:
        shares = shamir_split(bytes(key_material), body.threshold, body.total)
    finally:
        secure_zero(key_material)
    hex_shares = [s.hex() for s in shares]

    for key, value in [
        ("shamir_enabled", "true"),
        ("shamir_threshold", str(body.threshold)),
        ("shamir_total", str(body.total)),
    ]:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES (:key, :val) "
                "ON CONFLICT (key) DO UPDATE SET value = :val"
            ),
            {"key": key, "val": value},
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="shamir_init",
        detail={"threshold": body.threshold, "total": body.total},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return ShamirInitResponse(
        shares=hex_shares,
        threshold=body.threshold,
        total=body.total,
    )


@router.delete("/shamir")
async def shamir_disable(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Disable Shamir - revert to password-only unseal."""
    for key in ("shamir_enabled", "shamir_threshold", "shamir_total"):
        await db.execute(
            text("DELETE FROM vault_config WHERE key = :key"), {"key": key}
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="shamir_disabled",
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.clear_shares()
    return {"status": "shamir_disabled"}


# -- 2FA mode ----------------------------------------------------------------


@router.put("/2fa")
async def set_2fa_mode(
    mode: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Set 2FA mode: none, yubikey, totp, any."""
    if mode not in ("none", "yubikey", "totp", "any"):
        raise HTTPException(400, "Mode must be: none, yubikey, totp, any")

    await _lock_2fa_config(db)
    # Anti-lockout: refuse a mode whose factor isn't registered yet
    if mode in ("yubikey", "any"):
        yk = await _yubikey_count(db)
        wa = await _webauthn_count(db)
        if yk == 0 and wa == 0:
            raise HTTPException(
                400, "Register at least one YubiKey or WebAuthn credential first"
            )
    if mode in ("totp", "any"):
        if not await _totp_enabled(db):
            raise HTTPException(400, "Set up TOTP first")

    await _set_2fa_mode(db, mode)

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="set_2fa_mode",
        detail={"mode": mode},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"second_factor": mode}


# -- YubiKey management -----------------------------------------------------


@router.post("/yubikey")
async def register_yubikey(
    body: YubikeyRegister,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Register a YubiKey with its HMAC-SHA1 secret (slot 2).

    The same 20-byte secret must be programmed into the YubiKey
    (via ykpersonalize -2 -ochal-resp -ohmac-sha1).
    """
    vault.require_unsealed()
    secret_hex = body.hmac_secret.get_secret_value()
    if len(secret_hex) != 40:
        raise HTTPException(400, "HMAC secret must be 20 bytes (40 hex)")

    await _lock_2fa_config(db)
    await require_generation_current(db, vault)
    try:
        secret_buf = bytearray.fromhex(secret_hex)
    except ValueError:
        raise HTTPException(400, "HMAC secret must be hex-encoded")
    try:
        encrypted = bytes.fromhex(await _encrypt_2fa_current(bytes(secret_buf)))
    finally:
        secure_zero(secret_buf)
        del secret_buf

    await db.execute(
        text("""
            INSERT INTO vault_yubikeys
                (serial, name, hmac_secret, registered_by)
            VALUES (:serial, :name, :secret, :actor)
            ON CONFLICT (serial) DO UPDATE
                SET name = :name, hmac_secret = :secret,
                    registered_by = :actor, registered_at = NOW()
        """),
        {
            "serial": body.serial,
            "name": body.name,
            "secret": encrypted,
            "actor": token_info["name"],
        },
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="register_yubikey",
        target=body.serial,
        detail={"name": body.name},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.invalidate_2fa_cache()
    return {"status": "registered", "serial": body.serial}


@router.get("/yubikey")
async def list_yubikeys(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    result = await db.execute(
        text("""
            SELECT id, serial, name, registered_at, registered_by
            FROM vault_yubikeys ORDER BY registered_at
        """)
    )
    items = [
        {
            "id": str(r.id),
            "serial": r.serial,
            "name": r.name,
            "registered_at": r.registered_at.isoformat(),
            "registered_by": r.registered_by,
        }
        for r in result.fetchall()
    ]
    return {"items": items}


@router.delete("/yubikey/{serial}")
async def remove_yubikey(
    serial: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    await _lock_2fa_config(db)
    result = await db.execute(
        text("DELETE FROM vault_yubikeys WHERE serial = :serial RETURNING id"),
        {"serial": serial},
    )
    if not result.fetchone():
        raise HTTPException(404, "YubiKey not found")

    # Fall back if removing this YubiKey left the mode unsatisfiable.
    yk_count = await _yubikey_count(db)
    new_mode = await _downgrade_2fa_if_unsatisfiable(db)
    if new_mode is not None:
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="2fa_fallback",
            detail={
                "reason": "last_yubikey_removed",
                "new_mode": new_mode,
            },
            ip_address=get_client_ip(request),
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="remove_yubikey",
        target=serial,
        detail={"remaining": yk_count},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.invalidate_2fa_cache()
    return {"status": "removed", "serial": serial, "remaining": yk_count}


# -- TOTP management --------------------------------------------------------


@router.post("/totp/setup", response_model=TotpSetupResponse)
async def totp_setup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Generate TOTP secret. Scan the URI as QR code in your auth app.
    Then POST /totp/enable with a valid code to activate.
    """
    await _lock_2fa_config(db)
    if await _totp_enabled(db):
        raise HTTPException(
            409, "TOTP already configured - delete first to reconfigure"
        )

    vault.require_unsealed()
    await require_generation_current(db, vault)
    secret = generate_totp_secret()
    uri = get_totp_uri(secret)
    encrypted = await _encrypt_2fa_current(secret.encode())
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('totp_pending', :secret) "
            "ON CONFLICT (key) DO UPDATE SET value = :secret"
        ),
        {"secret": encrypted},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="totp_setup",
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return TotpSetupResponse(secret=secret, uri=uri)


@router.post("/totp/enable")
async def totp_enable(
    body: TotpVerify,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Verify a TOTP code to confirm setup and activate TOTP."""
    vault.require_unsealed()
    await _lock_2fa_config(db)
    await require_generation_current(db, vault)
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'totp_pending'")
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(400, "No pending TOTP setup - call /totp/setup first")

    totp_buf = bytearray(await _decrypt_2fa_secret(row.value))
    try:
        totp_valid = verify_totp(totp_buf.decode(), body.code)
    finally:
        secure_zero(totp_buf)
        del totp_buf
    if not totp_valid:
        raise HTTPException(401, "Invalid TOTP code - check your app")

    # Move from pending to active (stays encrypted)
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('totp_secret', :secret) "
            "ON CONFLICT (key) DO UPDATE SET value = :secret"
        ),
        {"secret": row.value},
    )
    await db.execute(text("DELETE FROM vault_config WHERE key = 'totp_pending'"))
    await db.execute(text("DELETE FROM vault_config WHERE key = 'totp_last_counter'"))

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="totp_enabled",
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.invalidate_2fa_cache()
    return {"status": "totp_enabled"}


@router.delete("/totp")
async def totp_disable(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Disable TOTP. Falls back to other 2FA or none."""
    await _lock_2fa_config(db)
    await db.execute(
        text(
            "DELETE FROM vault_config WHERE key IN "
            "('totp_secret', 'totp_pending', 'totp_last_counter')"
        )
    )

    # Fall back if removing TOTP left the mode unsatisfiable (anti-lockout).
    new_mode = await _downgrade_2fa_if_unsatisfiable(db)
    if new_mode is not None:
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="2fa_fallback",
            detail={"reason": "totp_disabled", "new_mode": new_mode},
            ip_address=get_client_ip(request),
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="totp_disabled",
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.invalidate_2fa_cache()
    return {"status": "totp_disabled"}


# -- Rate limit management (admin) -------------------------------------------


@router.get("/rate-limits")
async def list_rate_limits(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
    limit: int = 200,
    offset: int = 0,
):
    """List a bounded page of rate-limited IPs and lockout status."""
    vault.require_unsealed()
    if not 1 <= limit <= 1000:
        raise HTTPException(400, "limit must be between 1 and 1000")
    if offset < 0:
        raise HTTPException(400, "offset must be >= 0")

    result = await db.execute(
        text("""
            SELECT ip_address, fail_count, locked_until, updated_at,
                   locked_until > NOW() AS locked
            FROM vault_rate_limits
            ORDER BY updated_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {"limit": limit, "offset": offset},
    )
    rows = result.fetchall()

    items = []
    for r in rows:
        items.append(
            {
                "ip_address": r.ip_address,
                "fail_count": r.fail_count,
                "locked_until": r.locked_until.isoformat() if r.locked_until else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                "locked": bool(r.locked),
            }
        )

    return {"items": items, "count": len(items), "limit": limit, "offset": offset}


@router.delete("/rate-limits/{ip}")
async def unblock_ip(
    ip: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Unblock a rate-limited IP. Admin only."""
    vault.require_unsealed()

    result = await db.execute(
        text(
            "DELETE FROM vault_rate_limits WHERE ip_address = :ip RETURNING ip_address"
        ),
        {"ip": ip},
    )
    deleted = result.fetchone()
    if not deleted:
        raise HTTPException(404, f"No rate limit entry for {ip}")

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rate_limit_unblock",
        target=ip,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "unblocked", "ip": ip}


# -- dek_key rotation (hierarchical) -----------------------------------------


class RotateDekKeyRequest(BaseModel):
    current_password: SecretStr  # re-authenticate the operator


@router.post("/admin/rotate-dek-key")
async def rotate_dek_key(
    body: RotateDekKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Rotate dek_key without changing the master password.

    Bumps dek_key_version, derives a fresh dek_key from the same master key
    under the new HKDF info string, re-wraps every vault_dek entry under
    the new dek_key, and flips vault.aesgcm. Secrets stay encrypted under
    their own DEKs (no per-secret decrypt-encrypt cycle) - O(N_DEKs) with
    a small constant, vs. O(N_secrets) for the legacy per-secret loop.

    Requires the current master password as a re-auth check (this is a
    sensitive operation; we don't want a leaked root token to be enough).
    """
    vault.require_unsealed()
    client_ip = get_client_ip(request)

    # Cluster-wide exclusive lock: serializes password and DEK-key rotations
    # against each other and against shared key-material writers, preventing
    # missed rows or wraps under a retiring generation.
    lock_acquired = await db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
        {"lock_name": KEY_ROTATION_LOCK},
    )
    if not lock_acquired.scalar():
        raise HTTPException(
            status_code=409,
            detail="another host is already performing a key rotation",
        )
    rust_rotation = (
        settings.custody_mode == "separated" and settings.custody_backend == "rust"
    )
    if rust_rotation:
        from ..custody_generation import CUSTODY_ORCHESTRATION_LOCK

        custody_lock = await db.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
            {"lock_name": CUSTODY_ORCHESTRATION_LOCK},
        )
        if not custody_lock.scalar():
            raise HTTPException(
                status_code=409,
                detail="another Rust custody operation is in progress",
            )

        # Attach before re-wrapping anything. A disposable API worker that
        # restarted -- which under IO pressure is exactly when it did -- can
        # reach here holding no coordinator, and every DEK re-wrap below runs
        # through the pool. Failing the rotation for "not attached yet" is
        # reporting a recoverable condition as a broken quorum.
        from ..custody_routing import ensure_control_plane
        from ..rust_custody_backend import configured_rust_custody_pool

        await ensure_control_plane(configured_rust_custody_pool(), vault)

    # 1. Re-derive master_key from password and verify
    salt = await _get_salt(db)
    old_version = await _get_dek_key_version(db)
    new_version = old_version + 1

    mk = bytearray(
        await derive_master_key_async(
            body.current_password.get_secret_value().encode(), salt
        )
    )
    try:
        old_keys = derive_keys(mk, dek_key_version=old_version)
        new_keys = derive_keys(mk, dek_key_version=new_version)
    finally:
        secure_zero(mk)

    check_r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'master_check'")
    )
    check_row = check_r.fetchone()
    if not check_row:
        raise HTTPException(500, "No master_check in vault_config")
    if not _hmac.compare_digest(
        hmac_token(old_keys["hmac_key"], "master-check-value"), check_row.value
    ):
        raise HTTPException(401, "Current password is incorrect")

    # 2. Re-wrap every DEK: decrypt with old dek_key, encrypt with new dek_key.
    #    AAD is dek_aad(dek_id), unchanged across rotation.
    old_aesgcm = DekCipher(old_keys["dek_key"])
    new_aesgcm = DekCipher(new_keys["dek_key"])

    deks_r = await db.execute(text("SELECT id, encrypted_key, nonce FROM vault_dek"))
    rows = deks_r.fetchall()
    rewrapped = 0
    for row in rows:
        try:
            aad = dek_aad(str(row.id))
            wrapped = bytes(row.nonce) + bytes(row.encrypted_key)
            new_wrapped = bytes(old_aesgcm.rewrap_to(new_aesgcm, wrapped, aad))
        except Exception:
            log_authfail(client_ip, f"rotate_dek_key_unwrap_failed_{row.id}")
            await db.rollback()
            raise HTTPException(
                500,
                f"DEK key rotation aborted: DEK {row.id} failed to unwrap",
            )
        await db.execute(
            text(
                "UPDATE vault_dek SET encrypted_key = :ekey, nonce = :nonce "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {
                "ekey": new_wrapped[12:],
                "nonce": new_wrapped[:12],
                "id": str(row.id),
            },
        )
        rewrapped += 1

    # 3. Update version + rotated-at marker in config
    await db.execute(
        text("""
            INSERT INTO vault_config (key, value)
            VALUES ('dek_key_version', :v)
            ON CONFLICT (key) DO UPDATE SET value = :v
        """),
        {"v": str(new_version)},
    )
    await db.execute(
        text("""
            INSERT INTO vault_config (key, value)
            VALUES ('dek_key_rotated_at', NOW()::text)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """)
    )

    # 3b. audit half: the dek_key changes, so re-wrap the whole audit
    #     key archive under the new dek_key and archive the (unchanged) current
    #     audit_key at the old epoch -- keeps every epoch's key readable and
    #     keeps /audit/verify intact across the dek rotation.
    old_epoch = await get_key_epoch(db)
    await rotate_audit_keyring(
        db,
        retiring_epoch=old_epoch,
        retiring_audit_key=old_keys["audit_key"],
        old_aesgcm=old_aesgcm,
        new_aesgcm=new_aesgcm,
    )
    new_epoch = old_epoch + 1

    # 3c. S7: dek_key rotation also re-keys the at-rest Ed25519 audit identity
    #     seed (wrapped under dek_key). Re-wrap old->new in this txn so the next
    #     unseal can still load the identity; without it the chain silently
    #     reverts to hmac. The live signer is untouched by the rotation.
    from ..audit_identity import rewrap_seed_for_rotation

    await rewrap_seed_for_rotation(db, old_aesgcm, new_aesgcm)

    # 3d. The 2FA secrets are wrapped under dek_key too, and the second-factor
    #     gate decrypts them with the dek_key derived from the password at
    #     unseal. Leaving them behind is an unseal lockout at the next restart.
    rewrapped_2fa = await rewrap_dek_encrypted_2fa(db, old_aesgcm, new_aesgcm)

    # 3e. prev_hmac_key rides dek_key as well; orphaning it silently ends the
    #     lazy token-migration window (auth swallows the decrypt failure and
    #     every pre-rotation token starts getting rejected). rotate_password
    #     writes a fresh one instead, so only this route re-wraps in place.
    #     An already-unreadable row is dropped, not fatal: it is dead weight a
    #     previous rotation orphaned, and failing here would wedge the route.
    prev_row = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'prev_hmac_key'")
    )
    prev = prev_row.fetchone()
    prev_hmac_outcome = "absent"
    if prev:
        try:
            new_prev = bytes(
                old_aesgcm.rewrap_to(new_aesgcm, bytes.fromhex(prev.value))
            )
        except Exception:
            await db.execute(
                text(
                    "DELETE FROM vault_config "
                    "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                )
            )
            prev_hmac_outcome = "dropped_unreadable"
        else:
            await db.execute(
                text(
                    "UPDATE vault_config SET value = :val WHERE key = 'prev_hmac_key'"
                ),
                {"val": new_prev.hex()},
            )
            prev_hmac_outcome = "rewrapped"

    del old_aesgcm
    del new_aesgcm

    # 4. Audit + commit BEFORE flipping in-memory state.
    #    Logged before the epoch bump so the entry is tagged with the old epoch
    #    (the audit_key is unchanged here, but the tagging rule stays uniform).
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rotate_dek_key",
        detail={
            "old_version": old_version,
            "new_version": new_version,
            "deks_rewrapped": rewrapped,
            "key_epoch": new_epoch,
            "rewrapped_2fa": rewrapped_2fa,
            "prev_hmac_key": prev_hmac_outcome,
        },
        ip_address=client_ip,
    )

    # 5. Flip vault state: replace dek_key in encrypted RAM + AESGCM cache.
    #    hmac_key + audit_key + ha_wrap_key unchanged (constant HKDF info);
    #    we re-unseal with the same dict + new dek_key.
    rotated_keys = {
        "hmac_key": old_keys["hmac_key"],
        "dek_key": new_keys["dek_key"],
        "audit_key": old_keys["audit_key"],
        "ha_wrap_key": old_keys["ha_wrap_key"],
        "pki_wrap_key": old_keys["pki_wrap_key"],
    }

    # 5a. Rust custody staging. Only dek_key differs from the live bundle, so
    #     the staged generation is exactly what the local rewrap assumed.
    #     Staging seals the pool, so it must run AFTER the audit entry above
    #     (signing needs the custodians unsealed) and BEFORE the commit: a
    #     crash while the durable phase is preparing can only roll back.
    rust_pool = None
    rust_target = None
    rust_previous = None
    if rust_rotation:
        from ..custody_reshare import stage_local_bundle_for_rust_rotation
        from ..rust_custody_backend import configured_rust_custody_pool

        rust_pool = configured_rust_custody_pool()
        rotation_bundle = bytearray()
        try:
            for key_name in (
                "hmac_key",
                "dek_key",
                "audit_key",
                "ha_wrap_key",
                "pki_wrap_key",
            ):
                rotation_bundle.extend(rotated_keys[key_name])
            rust_target, rust_previous = await stage_local_bundle_for_rust_rotation(
                rotation_bundle,
                rust_pool,
                threshold=settings.rust_custodian_threshold,
                slots=settings.rust_custodian_slots,
            )
        except BaseException:
            from ..rust_custody_backend import resync_rust_custody_attachment

            await resync_rust_custody_attachment(rust_pool, vault, key_epoch=old_epoch)
            raise
        finally:
            secure_zero(rotation_bundle)

    # dek_key rotation also changes the in-RAM keys, so it bumps the
    # same unified generation marker. Peers that keep the old dek_key can no
    # longer unwrap the re-wrapped DEKs -> the fence quarantines them.
    # The custody roll-forward decision commits with the re-wrapped rows and
    # the epoch bump: one transaction decides both, or neither.
    try:
        if rust_target is not None:
            from ..custody_generation import choose_custody_generation

            await choose_custody_generation(db, rust_target)
        await bump_key_epoch(db)
        await db.commit()
    except Exception:
        await db.rollback()
        if rust_target is not None:
            assert rust_pool is not None and rust_previous is not None
            from ..rust_custody_backend import abort_rust_custody_key_rotation

            # Pre-decision failure: the staged generation holds the new
            # dek_key, but the rolled-back rows are still wrapped under the
            # old one. Only the old generation can read them.
            await abort_rust_custody_key_rotation(
                rust_pool,
                vault,
                target=rust_target,
                previous=rust_previous,
                key_epoch=old_epoch,
            )
        raise

    if rust_target is not None:
        assert rust_pool is not None
        from ..rust_custody_backend import finish_rust_custody_key_rotation

        # Post-decision: roll forward only. Reinstalling the ancillary
        # envelopes here is what re-fingerprints the prev_hmac_key row this
        # route re-wrapped at 3e -- a later compare-and-clear presenting the
        # committed envelope would otherwise return stale and never clear it.
        await finish_rust_custody_key_rotation(
            rust_pool,
            vault,
            target=rust_target,
            key_epoch=new_epoch,
        )
    else:
        vault.unseal(rotated_keys)
        vault.set_key_epoch(new_epoch)

    # publish the signed rekey envelope so live-but-stale peers
    # roll forward to this generation automatically. dek_key rotation has no
    # emergency mode (it is always a hygiene op), so always publish. Follow-up
    # txn after the rotation commit -- a publish failure leaves peers to the
    # fence backstop, never rolls back the rotation.
    from ..cluster_rekey import publish_envelope

    bundle = bytearray()
    try:
        for key_name in (
            "hmac_key",
            "dek_key",
            "audit_key",
            "ha_wrap_key",
            "pki_wrap_key",
        ):
            bundle.extend(rotated_keys[key_name])
        # Same caveat as rotate_password: if this ran on a follower the host
        # master still holds the old dek_key, so keep the host in the envelope
        # recipient set (see publish_envelope / rotator_is_master).
        await publish_envelope(db, bundle, new_epoch, rotator_is_master=vault.is_master)
    finally:
        secure_zero(bundle)
        del bundle
        del rotated_keys
        old_keys.wipe()
        new_keys.wipe()
        del old_keys
        del new_keys

    return {
        "status": "rotated",
        "old_version": old_version,
        "new_version": new_version,
        "deks_rewrapped": rewrapped,
    }
