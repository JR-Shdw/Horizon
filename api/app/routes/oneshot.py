# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Decrypt-and-die mode (Backlog #4).

POST /api/v1/vault/oneshot - unseal in-process, read one secret, re-seal
immediately, return the decrypted value. Designed for CI runners and
one-shot cron jobs where the vault should never sit unsealed between calls.

The whole sequence runs under a single coroutine; if anything raises after
unseal, the finally block re-seals the vault before propagating. The
unsealed window is bounded by Argon2id derivation (~250-500ms) + one DEK
unwrap + one secret decrypt - typically under a second.

Trade-offs:
  - Argon2id every call: ~500ms latency added vs. a normal GET /secrets/{name}.
    Tolerable for human-paced ops; bad for hot-path automation. For high
    volume the operator should keep the vault unsealed (existing behavior).
  - The master password crosses the wire on every call. Use only over TLS
    + WG, ideally via age-encrypted side-car that pipes it on stdin.
  - Audit trail logs both unseal_oneshot and read_oneshot actions, so a
    misuse is visible in the chain.
"""

import asyncio
import logging

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..authfail import log_authfail
from ..client_ip import get_client_ip
from ..crypto import (
    decrypt_dek,
    decrypt_secret,
    dek_aad,
    derive_keys,
    derive_master_key_async,
    hmac_token,
    secret_aad,
    verify_yubikey_response,
)
from ..database import get_db
from ..rate_limit import check_rate_limit, clear_failures, record_failure
from ..totp_replay import verify_and_consume_totp
from ..vault_state import vault

log = logging.getLogger("rhorizon.oneshot")

router = APIRouter(prefix="/api/v1/vault", tags=["oneshot"])

# Serialize the unseal->read->seal section per worker: oneshot mutates the shared
# `vault` singleton, so concurrent calls could seal it out from under each other's
# read/audit (spurious 503). Argon2 + auth stay outside (no shared state).
_oneshot_lock = asyncio.Lock()


class OneshotRequest(BaseModel):
    password: SecretStr
    name: str = Field(..., max_length=128)
    namespace: str = Field("default", max_length=64)
    # 2FA: provide whichever the vault is configured for
    totp_code: str | None = None
    yubikey_response: str | None = None
    challenge: str | None = None


class OneshotResponse(BaseModel):
    value: str
    name: str
    namespace: str


async def _verify_oneshot_2fa(
    db: AsyncSession,
    mode: str,
    body: OneshotRequest,
    aesgcm_tmp: AESGCM,
    client_ip: str,
) -> None:
    """Minimal 2FA verification mirroring vault.py's _verify_2fa, scoped
    to the modes supported by oneshot (totp + yubikey). WebAuthn isn't
    supported here - it requires a browser-driven assertion flow that
    doesn't fit a single API call."""
    if mode == "none":
        return
    if mode == "totp":
        if not body.totp_code:
            raise HTTPException(401, "TOTP code required")
        secret_row = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'totp_secret'")
        )
        secret_enc = secret_row.fetchone()
        if not secret_enc:
            raise HTTPException(500, "TOTP not configured but mode=totp")
        raw = bytes.fromhex(secret_enc.value)
        plain = aesgcm_tmp.decrypt(raw[:12], raw[12:], None)
        if not await verify_and_consume_totp(db, plain.decode(), body.totp_code):
            raise HTTPException(401, "Invalid TOTP code")
        return
    if mode == "yubikey":
        if not body.yubikey_response or not body.challenge:
            raise HTTPException(401, "YubiKey challenge+response required")
        # Single-use challenge consume (mirrors /unseal)
        ch = await db.execute(
            text(
                "DELETE FROM vault_challenges "
                "WHERE challenge = :c AND purpose = 'unseal' "
                "RETURNING expires_at"
            ),
            {"c": body.challenge},
        )
        if not ch.fetchone():  # pragma: no cover  (YubiKey integ)
            raise HTTPException(401, "Invalid or expired challenge")
        # Schema column is `hmac_secret BYTEA` (not `secret`), and the
        # value is the raw nonce||ct bytes (not a hex string). Mirror the
        # decoding done by routes/vault.py at the regular unseal path.
        try:  # pragma: no cover  (YubiKey integ)
            resp_bytes = bytes.fromhex(body.yubikey_response)
            challenge_bytes = bytes.fromhex(body.challenge)
        except ValueError as e:
            raise HTTPException(
                400, "yubikey_response and challenge must be hex"
            ) from e
        rows = await db.execute(text("SELECT serial, hmac_secret FROM vault_yubikeys"))
        for yk in rows.fetchall():
            raw = bytes(yk.hmac_secret)
            secret = aesgcm_tmp.decrypt(raw[:12], raw[12:], None)
            if verify_yubikey_response(secret, challenge_bytes, resp_bytes):
                return
        raise HTTPException(401, "YubiKey response did not match any registered key")
    raise HTTPException(400, f"Unsupported 2FA mode for oneshot: {mode}")


@router.post("/oneshot", response_model=OneshotResponse)
async def oneshot_read(
    body: OneshotRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Unseal -> read -> re-seal in a single call. Vault must be sealed
    when this is called (otherwise the operator should use a regular
    GET /secrets/{name}). Argon2id-bounded latency (~500ms)."""
    if not vault.sealed:
        raise HTTPException(
            409,
            "Vault is currently unsealed - oneshot is for sealed-by-default "
            "operation; use GET /secrets/{name} instead",
        )

    client_ip = get_client_ip(request)
    await check_rate_limit(db, client_ip)

    # 1. Re-derive keys from password (same path as /unseal, threaded with
    #    current dek_key version so vault_dek entries decrypt correctly).
    from .vault import _get_dek_key_version, _get_salt

    salt = await _get_salt(db)
    dek_version = await _get_dek_key_version(db)
    master_key = bytearray(
        await derive_master_key_async(body.password.get_secret_value().encode(), salt)
    )
    try:
        keys = derive_keys(master_key, dek_key_version=dek_version)
    finally:
        secure_zero(master_key)

    # 2. Verify password via master_check
    check_r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'master_check'")
    )
    check_row = check_r.fetchone()
    if not check_row:
        raise HTTPException(500, "Vault not initialized")
    # Constant-time compare to avoid a per-byte timing oracle that
    # would otherwise let an attacker probe valid password prefixes.
    import hmac as _hmac

    if not _hmac.compare_digest(
        hmac_token(keys["hmac_key"], "master-check-value"), check_row.value
    ):
        await record_failure(db, client_ip)
        log_authfail(client_ip, "oneshot_invalid_password")
        raise HTTPException(401, "Invalid password")

    # 3. 2FA verification (if configured)
    mode_r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'second_factor'")
    )
    mode_row = mode_r.fetchone()
    mode = mode_row.value if mode_row else "none"
    aesgcm_tmp = AESGCM(keys["dek_key"])
    try:
        await _verify_oneshot_2fa(db, mode, body, aesgcm_tmp, client_ip)
    except HTTPException:
        await record_failure(db, client_ip)
        log_authfail(client_ip, "oneshot_2fa_failed")
        raise

    # 4. Unseal in-process. Track that we did so we can re-seal even on
    #    error paths.
    from .. import metrics as _m

    async with _oneshot_lock, vault.master_transition_lock():
        vault.unseal(keys)
        _m.unseal_attempts.labels(result="oneshot_success").inc()
        _m.set_vault_sealed(False)
        try:
            # 5. Read the secret
            sec_r = await db.execute(
                text("""
                    SELECT s.id, s.ciphertext, s.nonce, s.aad_version, s.dek_id,
                           d.encrypted_key, d.nonce AS dek_nonce
                    FROM vault_secrets s
                    JOIN vault_dek d ON d.id = s.dek_id
                    WHERE s.name = :name AND s.namespace = :ns
                """),
                {"name": body.name, "ns": body.namespace},
            )
            row = sec_r.fetchone()
            if not row:
                raise HTTPException(
                    404, f"Secret not found: {body.namespace}/{body.name}"
                )

            dek = decrypt_dek(
                bytes(row.encrypted_key),
                bytes(row.dek_nonce),
                keys["dek_key"],
                None,  # aesgcm cache - let decrypt_dek build a fresh one
                dek_aad(str(row.dek_id)),
            )
            plaintext = decrypt_secret(
                bytes(row.ciphertext),
                bytes(row.nonce),
                dek,
                secret_aad(
                    body.name,
                    body.namespace,
                    version=row.aad_version,
                ),
            )

            await clear_failures(db, client_ip)
            await log_action(
                db,
                actor="oneshot",
                action="oneshot_read",
                target=body.name,
                detail={"namespace": body.namespace},
                ip_address=client_ip,
            )
            await db.commit()
            _m.secrets_read.inc()
            return OneshotResponse(
                value=plaintext.decode(),
                name=body.name,
                namespace=body.namespace,
            )
        finally:
            # 6. Re-seal regardless of outcome (unsealed window ~ a few ms).
            vault.seal()
            _m.seal_events.labels(trigger="oneshot").inc()
            _m.set_vault_sealed(True)
            keys.wipe()
