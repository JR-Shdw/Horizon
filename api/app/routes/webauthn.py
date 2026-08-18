# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""WebAuthn/FIDO2 - browser-native security key registration and management."""

import base64
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_client_ip
from ..config import settings
from ..database import get_db
from ..rate_limit import check_rate_limit
from ..vault_state import vault

router = APIRouter(prefix="/api/v1/vault/webauthn", tags=["webauthn"])

CHALLENGE_TTL = 60


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Decode base64url string to bytes."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


_fido2_server = None


def _get_fido2_server():  # pragma: no cover  (FIDO2 E2E only)
    """Lazily create and cache the Fido2Server instance."""
    global _fido2_server
    if _fido2_server is None:
        from fido2.server import Fido2Server
        from fido2.webauthn import PublicKeyCredentialRpEntity

        rp = PublicKeyCredentialRpEntity(
            id=settings.webauthn_rp_id, name=settings.webauthn_rp_name
        )
        _fido2_server = Fido2Server(rp)
    return _fido2_server


class RegisterBeginRequest(BaseModel):
    name: str = "Security Key"


class RegisterCompleteRequest(BaseModel):
    challenge_id: str  # hex challenge for state lookup
    name: str = "Security Key"
    id: str  # base64url credential id
    rawId: str  # base64url
    type: str = "public-key"
    response: dict  # {clientDataJSON, attestationObject}


@router.post("/register/begin")
async def register_begin(
    body: RegisterBeginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Start WebAuthn registration.

    Returns options for navigator.credentials.create().
    """
    vault.require_unsealed()

    challenge = os.urandom(32)
    challenge_hex = challenge.hex()

    await db.execute(text("DELETE FROM vault_challenges WHERE expires_at < NOW()"))
    await db.execute(
        text("""
            INSERT INTO vault_challenges (challenge, expires_at, purpose)
            VALUES (:ch, NOW() + make_interval(secs => :ttl), 'register')
        """),
        {"ch": challenge_hex, "ttl": CHALLENGE_TTL},
    )
    await db.commit()

    # Exclude already-registered credentials
    result = await db.execute(text("SELECT credential_id FROM vault_webauthn"))
    exclude = [
        {"type": "public-key", "id": _b64url_encode(bytes(r.credential_id))}
        for r in result.fetchall()
    ]

    return {
        "publicKey": {
            "rp": {"id": settings.webauthn_rp_id, "name": settings.webauthn_rp_name},
            "user": {
                "id": _b64url_encode(b"rhorizon-admin"),
                "name": "admin",
                "displayName": "rhorizon Admin",
            },
            "challenge": _b64url_encode(challenge),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257},  # RS256
            ],
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "userVerification": "discouraged",
                "residentKey": "discouraged",
            },
            "timeout": 60000,
            "attestation": "none",
        },
        "challenge_id": challenge_hex,
    }


@router.post("/register/complete")
async def register_complete(
    body: RegisterCompleteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Complete WebAuthn registration with credential from browser."""
    vault.require_unsealed()
    from .vault import _lock_2fa_config

    await _lock_2fa_config(db)

    from fido2.webauthn import AttestationObject, CollectedClientData

    # Consume challenge (atomic single-use, register-purpose only)
    result = await db.execute(
        text("""
            DELETE FROM vault_challenges
            WHERE challenge = :ch AND purpose = 'register' AND expires_at > NOW()
            RETURNING challenge
        """),
        {"ch": body.challenge_id},
    )
    if not result.fetchone():
        raise HTTPException(400, "Invalid or expired challenge")

    try:
        client_data = CollectedClientData(
            _b64url_decode(body.response["clientDataJSON"])
        )
        att_obj = AttestationObject(_b64url_decode(body.response["attestationObject"]))
        server = _get_fido2_server()
        state = {"challenge": bytes.fromhex(body.challenge_id)}
        auth_data = server.register_complete(state, client_data, att_obj)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"WebAuthn registration failed: {e}")

    cred_data = auth_data.credential_data
    if cred_data is None:
        raise HTTPException(400, "No credential data in response")

    credential_id = cred_data.credential_id
    credential_data_bytes = bytes(cred_data)

    await db.execute(
        text("""
            INSERT INTO vault_webauthn
                (credential_id, credential_data, sign_count, name, registered_by)
            VALUES (:cid, :cdata, 0, :name, :actor)
            ON CONFLICT (credential_id) DO UPDATE
                SET credential_data = :cdata, name = :name, registered_by = :actor
        """),
        {
            "cid": credential_id,
            "cdata": credential_data_bytes,
            "name": body.name,
            "actor": token_info["name"],
        },
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="register_webauthn",
        target=body.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.invalidate_2fa_cache()
    return {"status": "registered", "name": body.name}


@router.post("/auth/begin")
async def auth_begin(request: Request, db: AsyncSession = Depends(get_db)):
    """Start WebAuthn authentication for unseal. No auth required (vault is sealed).

    Rate-limited: unauthenticated DB-write surface - without
    this check, an on-VPN attacker could spam-create challenges and grow
    vault_challenges unboundedly.
    """
    client_ip = get_client_ip(request)
    await check_rate_limit(db, client_ip)

    challenge = os.urandom(32)
    challenge_hex = challenge.hex()

    await db.execute(text("DELETE FROM vault_challenges WHERE expires_at < NOW()"))
    await db.execute(
        text("""
            INSERT INTO vault_challenges (challenge, expires_at, purpose)
            VALUES (:ch, NOW() + make_interval(secs => :ttl), 'unseal')
        """),
        {"ch": challenge_hex, "ttl": CHALLENGE_TTL},
    )
    await db.commit()

    result = await db.execute(text("SELECT credential_id FROM vault_webauthn"))
    allow = [
        {"type": "public-key", "id": _b64url_encode(bytes(r.credential_id))}
        for r in result.fetchall()
    ]

    if not allow:
        raise HTTPException(400, "No WebAuthn credentials registered")

    return {
        "publicKey": {
            "challenge": _b64url_encode(challenge),
            "allowCredentials": allow,
            "rpId": settings.webauthn_rp_id,
            "timeout": 60000,
            "userVerification": "discouraged",
        },
        "challenge_id": challenge_hex,
    }


@router.get("/")
async def list_webauthn(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """List registered WebAuthn credentials."""
    result = await db.execute(
        text("""
            SELECT id, credential_id, sign_count, name, registered_at, registered_by
            FROM vault_webauthn ORDER BY registered_at
        """)
    )
    items = [
        {
            "id": str(r.id),
            "credential_id_short": _b64url_encode(bytes(r.credential_id))[:16] + "...",
            "sign_count": r.sign_count,
            "name": r.name,
            "registered_at": r.registered_at.isoformat(),
            "registered_by": r.registered_by,
        }
        for r in result.fetchall()
    ]
    return {"items": items}


@router.delete("/{credential_uuid}")
async def delete_webauthn(
    credential_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Delete a WebAuthn credential."""
    from .vault import _lock_2fa_config

    await _lock_2fa_config(db)
    result = await db.execute(
        text("DELETE FROM vault_webauthn WHERE id = CAST(:id AS uuid) RETURNING name"),
        {"id": credential_uuid},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "WebAuthn credential not found")

    # Fall back if removing this credential left the mode unsatisfiable (shared
    # helper with delete_yubikey + totp_disable -- the copies all missed 'any').
    from .vault import _downgrade_2fa_if_unsatisfiable

    new_mode = await _downgrade_2fa_if_unsatisfiable(db)
    if new_mode is not None:
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="2fa_fallback",
            detail={
                "reason": "last_security_key_removed",
                "new_mode": new_mode,
            },
            ip_address=get_client_ip(request),
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="remove_webauthn",
        target=row.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    vault.invalidate_2fa_cache()
    return {"status": "removed", "name": row.name}
