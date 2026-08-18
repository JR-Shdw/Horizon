# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""PKI secrets engine routes: init / issue / revoke / rotate / list / ca.

Init/revoke/rotate are admin:w; issue is secrets:w (namespace-checked); list +
ca are secrets:r. The CA private key never leaves the master (wrapped under
pki_wrap_key); leaf private keys are returned ONCE on issue and never stored.
"""

from __future__ import annotations

import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .. import pki_ca
from ..audit import log_action
from ..auth import actor_display_name, check_namespace, require_permission
from ..client_ip import get_client_ip
from ..database import get_db
from ..vault_state import vault

log = logging.getLogger("rhorizon")
router = APIRouter(prefix="/api/v1/vault/pki", tags=["pki"])


class PkiInit(BaseModel):
    # ANSSI/BSI composite hybrid (classical ed25519 + PQ ml-dsa-65) is the
    # default; callers can still pick "ml-dsa-65" (pure PQ) or "ed25519".
    algorithm: str = Field("ed25519-mldsa65")
    common_name: str = Field("rhorizon-pki", max_length=64)
    validity_days: int = Field(3650, ge=1, le=365 * 20)
    namespace: str = Field("default", max_length=64)


class PkiIssue(BaseModel):
    common_name: str = Field(..., min_length=1, max_length=253)
    san_ips: list[str] = Field(default_factory=list)
    san_dns: list[str] = Field(default_factory=list)
    # Capped at 398d (public-PKI norm): revocation is record-only (no CRL/OCSP),
    # so a short lifetime is the only real control over a compromised leaf.
    ttl_days: int = Field(30, ge=1, le=398)
    eku_client: bool = True
    eku_server: bool = True
    namespace: str = Field("default", max_length=64)

    @field_validator("san_dns")
    @classmethod
    def _dns_not_ip(cls, v: list[str]) -> list[str]:
        # An IP literal in a dNSName is malformed (validators ignore it) -- it
        # belongs in san_ips. Reject so the mistake is caught, not silently dropped.
        for name in v:
            try:
                ipaddress.ip_address(name.strip())
            except ValueError:
                continue  # not an IP -> a hostname, good
            raise ValueError(f"SAN DNS entry {name!r} is an IP address; use san_ips")
        return v

    @field_validator("san_ips")
    @classmethod
    def _ips_valid(cls, v: list[str]) -> list[str]:
        for ip in v:
            try:
                ipaddress.ip_address(ip.strip())
            except ValueError:
                raise ValueError(f"SAN IP entry {ip!r} is not a valid IP address")
        return v


class PkiKemIssue(BaseModel):
    common_name: str = Field(..., min_length=1, max_length=253)
    san_ips: list[str] = Field(default_factory=list)
    san_dns: list[str] = Field(default_factory=list)
    # KEM certs are for key establishment, not TLS auth -- same 398d public-PKI
    # cap applies (revocation is record-only, short lifetime is the real control).
    ttl_days: int = Field(30, ge=1, le=398)
    # ML-KEM parameter set for the subject key. Only ml-kem-768 (NIST cat 3,
    # matching the TLS X25519MLKEM768 handshake) is wired in this build.
    kem_algorithm: str = Field("ml-kem-768")
    # Construction: 'ml-kem' (pure PQ) or 'x25519-ml-kem' (hybrid classical+PQ,
    # the ANSSI/BSI-required combination). Default stays pure for back-compat.
    kem_mode: str = Field("ml-kem")
    namespace: str = Field("default", max_length=64)

    @field_validator("kem_mode")
    @classmethod
    def _mode_known(cls, v: str) -> str:
        if v not in ("ml-kem", "x25519-ml-kem"):
            raise ValueError(f"unknown kem_mode {v!r}; use ml-kem or x25519-ml-kem")
        return v

    @field_validator("san_dns")
    @classmethod
    def _dns_not_ip(cls, v: list[str]) -> list[str]:
        for name in v:
            try:
                ipaddress.ip_address(name.strip())
            except ValueError:
                continue
            raise ValueError(f"SAN DNS entry {name!r} is an IP address; use san_ips")
        return v


class PkiRevoke(BaseModel):
    serial: str = Field(..., max_length=64)
    reason: str = Field("unspecified", max_length=128)


class PkiRotate(BaseModel):
    validity_days: int = Field(3650, ge=1, le=365 * 20)
    namespace: str = Field("default", max_length=64)


def _allowed_namespaces(token_info: dict) -> list[str] | None:
    allowed = token_info.get("permissions", {}).get("namespaces")
    return list(allowed) if allowed else None


@router.post("/init", status_code=201)
async def init_ca(
    body: PkiInit,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    check_namespace(token_info, body.namespace)
    if body.algorithm not in pki_ca.ALGORITHMS:
        raise HTTPException(
            400, f"algorithm must be one of: {', '.join(pki_ca.ALGORITHMS)}"
        )
    if await pki_ca.is_initialised(db, body.namespace):
        raise HTTPException(
            409, f"PKI already initialised for namespace {body.namespace}"
        )
    cert_pem, key_blob, pub_hex, fpr = pki_ca.mint_pki_ca(
        body.algorithm, body.common_name, body.validity_days
    )
    await pki_ca.set_pki_ca(
        db,
        body.namespace,
        cert_pem,
        key_blob,
        pub_hex,
        body.algorithm,
        body.common_name,
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="pki_init",
        target=body.common_name,
        detail={
            "algorithm": body.algorithm,
            "fingerprint": fpr,
            "namespace": body.namespace,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "algorithm": body.algorithm,
        "common_name": body.common_name,
        "namespace": body.namespace,
        "fingerprint": fpr,
        "certificate": cert_pem.decode(),
    }


@router.get("/cas")
async def list_cas(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    """Namespaces that have an initialised CA, filtered to the token's scope."""
    vault.require_unsealed()
    allowed = _allowed_namespaces(token_info)
    names = await pki_ca.list_ca_namespaces(db)
    if allowed is not None:
        names = [n for n in names if n in allowed]
    return {"namespaces": names}


@router.get("/ca")
async def get_ca(
    namespace: str = "default",
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()
    check_namespace(token_info, namespace)
    ca = await pki_ca.load_pki_ca(db, namespace)
    if ca is None:
        raise HTTPException(404, f"PKI not initialised for namespace {namespace}")
    cert_pem, _key, _pub, algorithm, cn = ca
    secure_zero(_key)
    out = {
        "algorithm": algorithm,
        "common_name": cn,
        "namespace": namespace,
        "certificate": cert_pem.decode(),
        "fingerprint": pki_ca.compute_fingerprint(cert_pem),
    }
    prev = await pki_ca.load_pki_ca_prev_cert(db, namespace)
    if prev:
        out["previous_certificate"] = prev.decode()
    return out


@router.post("/issue", status_code=201)
async def issue_cert(
    body: PkiIssue,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    vault.require_unsealed()
    check_namespace(token_info, body.namespace)
    ca = await pki_ca.load_pki_ca(db, body.namespace)
    if ca is None:
        raise HTTPException(404, f"PKI not initialised for namespace {body.namespace}")
    cert_pem, key_blob, pub_hex, algorithm, cn = ca
    try:
        leaf_cert, leaf_key, serial, not_after = pki_ca.sign_leaf_cert(
            cert_pem,
            key_blob,
            pub_hex,
            algorithm,
            cn,
            common_name=body.common_name,
            san_ips=body.san_ips,
            san_dns=body.san_dns,
            validity_days=body.ttl_days,
            eku_client=body.eku_client,
            eku_server=body.eku_server,
        )
    except (pki_ca.PkiError, ValueError) as exc:
        raise HTTPException(400, f"cert issuance failed: {exc}")
    finally:
        secure_zero(key_blob)

    serial_hex = format(serial, "x")
    fpr = pki_ca.compute_fingerprint(leaf_cert)
    await db.execute(
        text(
            "INSERT INTO vault_pki_certs (serial_number, subject_cn, san_ips, "
            "san_dns, cert_pem, fingerprint, algorithm, namespace, not_before, "
            "not_after, issued_by) VALUES (:serial, :cn, :ips, :dns, :cert, :fpr, "
            ":alg, :ns, NOW(), :na, :by)"
        ),
        {
            "serial": serial_hex,
            "cn": body.common_name,
            "ips": body.san_ips or None,
            "dns": body.san_dns or None,
            "cert": leaf_cert.decode(),
            "fpr": fpr,
            "alg": algorithm,
            "ns": body.namespace,
            "na": not_after,
            "by": actor_display_name(token_info),
        },
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="pki_issue",
        target=body.common_name,
        detail={
            "serial": serial_hex,
            "namespace": body.namespace,
            "algorithm": algorithm,
            "fingerprint": fpr,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    # The leaf private key is shown ONCE here and never persisted.
    return {
        "serial": serial_hex,
        "certificate": leaf_cert.decode(),
        "private_key": leaf_key.decode(),
        "ca_chain": cert_pem.decode(),
        "fingerprint": fpr,
        "algorithm": algorithm,
        "not_after": not_after.isoformat(),
    }


@router.post("/kem/issue", status_code=201)
async def issue_kem_cert(
    body: PkiKemIssue,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Issue a KEM certificate: an ML-KEM subject key signed by the namespace CA.

    Subject key = KEM encaps key (KeyUsage=keyEncipherment, no EKU); signed by the
    CA under its own signature algorithm. The decapsulation (secret) key is
    returned ONCE and never stored. `algorithm` records the CA signature algo;
    `subject_algorithm` the KEM set ('ml-kem-768' or 'x25519-ml-kem-768');
    `kem_mode` the construction ('ml-kem' pure, or 'x25519-ml-kem' hybrid).
    """
    vault.require_unsealed()
    check_namespace(token_info, body.namespace)
    ca = await pki_ca.load_pki_ca(db, body.namespace)
    if ca is None:
        raise HTTPException(404, f"PKI not initialised for namespace {body.namespace}")
    cert_pem, key_blob, pub_hex, algorithm, cn = ca
    try:
        leaf_cert, leaf_key, serial, not_after, kem_alg = pki_ca.sign_kem_leaf_cert(
            cert_pem,
            key_blob,
            pub_hex,
            algorithm,
            cn,
            common_name=body.common_name,
            kem_algorithm=body.kem_algorithm,
            kem_mode=body.kem_mode,
            san_ips=body.san_ips,
            san_dns=body.san_dns,
            validity_days=body.ttl_days,
        )
    except (pki_ca.PkiError, ValueError) as exc:
        raise HTTPException(400, f"KEM cert issuance failed: {exc}")
    finally:
        secure_zero(key_blob)

    kem_mode = body.kem_mode  # 'ml-kem' (pure) or 'x25519-ml-kem' (hybrid)
    serial_hex = format(serial, "x")
    fpr = pki_ca.compute_fingerprint(leaf_cert)
    await db.execute(
        text(
            "INSERT INTO vault_pki_certs (serial_number, subject_cn, san_ips, "
            "san_dns, cert_pem, fingerprint, algorithm, subject_algorithm, "
            "kem_mode, namespace, not_before, not_after, issued_by) VALUES "
            "(:serial, :cn, :ips, :dns, :cert, :fpr, :alg, :salg, :kmode, :ns, "
            "NOW(), :na, :by)"
        ),
        {
            "serial": serial_hex,
            "cn": body.common_name,
            "ips": body.san_ips or None,
            "dns": body.san_dns or None,
            "cert": leaf_cert.decode(),
            "fpr": fpr,
            "alg": algorithm,
            "salg": kem_alg,
            "kmode": kem_mode,
            "ns": body.namespace,
            "na": not_after,
            "by": actor_display_name(token_info),
        },
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="pki_kem_issue",
        target=body.common_name,
        detail={
            "serial": serial_hex,
            "namespace": body.namespace,
            "algorithm": algorithm,
            "subject_algorithm": kem_alg,
            "kem_mode": kem_mode,
            "fingerprint": fpr,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    # The decapsulation (secret) key is shown ONCE here and never persisted.
    return {
        "serial": serial_hex,
        "certificate": leaf_cert.decode(),
        "private_key": leaf_key.decode(),
        "ca_chain": cert_pem.decode(),
        "fingerprint": fpr,
        "algorithm": algorithm,
        "subject_algorithm": kem_alg,
        "kem_mode": kem_mode,
        "not_after": not_after.isoformat(),
    }


@router.post("/revoke")
async def revoke_cert(
    body: PkiRevoke,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    row = (
        await db.execute(
            text(
                "SELECT subject_cn, namespace FROM vault_pki_certs "
                "WHERE serial_number = :serial AND revoked_at IS NULL"
            ),
            {"serial": body.serial},
        )
    ).fetchone()
    if row is None:
        raise HTTPException(404, "cert not found or already revoked")
    check_namespace(token_info, row.namespace)
    await db.execute(
        text(
            "UPDATE vault_pki_certs SET revoked_at = NOW(), revocation_reason = "
            ":reason WHERE serial_number = :serial"
        ),
        {"reason": body.reason, "serial": body.serial},
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="pki_revoke",
        target=row.subject_cn,
        detail={
            "serial": body.serial,
            "reason": body.reason,
            "namespace": row.namespace,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    # advisory: record-only. No CRL/OCSP, so relying parties must rely on the
    # short cert lifetime (ttl_days <= 398) rather than on this flag.
    return {"serial": body.serial, "revoked": True, "advisory": True}


@router.post("/rotate")
async def rotate_ca(
    body: PkiRotate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    check_namespace(token_info, body.namespace)
    try:
        cert_pem, fpr = await pki_ca.rotate_pki_ca(
            db, body.namespace, body.validity_days
        )
    except pki_ca.PkiError as exc:
        raise HTTPException(409, str(exc))
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="pki_rotate",
        target=body.namespace,
        detail={"fingerprint": fpr, "namespace": body.namespace},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "fingerprint": fpr,
        "namespace": body.namespace,
        "certificate": cert_pem.decode(),
    }


@router.get("/certs")
async def list_certs(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()
    allowed = _allowed_namespaces(token_info)
    sql = (
        "SELECT serial_number, subject_cn, san_ips, san_dns, fingerprint, "
        "algorithm, subject_algorithm, kem_mode, namespace, not_before, "
        "not_after, issued_at, issued_by, revoked_at, revocation_reason "
        "FROM vault_pki_certs {where} ORDER BY issued_at DESC"
    )
    if allowed is None:
        result = await db.execute(text(sql.format(where="")))
    else:
        result = await db.execute(
            text(sql.format(where="WHERE namespace = ANY(:ns)")), {"ns": allowed}
        )
    return {
        "items": [
            {
                "serial": r.serial_number,
                "subject_cn": r.subject_cn,
                "san_ips": r.san_ips or [],
                "san_dns": r.san_dns or [],
                "fingerprint": r.fingerprint,
                "algorithm": r.algorithm,
                "subject_algorithm": r.subject_algorithm,
                "kem_mode": r.kem_mode,
                "namespace": r.namespace,
                "not_before": r.not_before.isoformat(),
                "not_after": r.not_after.isoformat(),
                "issued_at": r.issued_at.isoformat() if r.issued_at else None,
                "issued_by": r.issued_by,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                "revocation_reason": r.revocation_reason,
            }
            for r in result.fetchall()
        ]
    }
