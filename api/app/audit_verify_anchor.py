# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Signed starting points for incremental audit evidence verification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .audit_identity import resolve_signer_fpr
from .crypto import verify_audit_ed25519
from .vault_state import vault

ANCHOR_SCHEMA = "rhorizon.audit_verification_anchor.v1"
LEGACY_ADOPTION_SCHEMA = "rhorizon.audit_legacy_adoption.v1"
MAX_LEGACY_ADOPTED_ROWS = 1024


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_anchor_payload(payload: dict[str, Any]) -> str:
    """Canonical, domain-separated bytes covered by the anchor signature."""
    if payload.get("schema") != ANCHOR_SCHEMA:
        raise ValueError("unsupported audit verification anchor schema")
    return (
        ANCHOR_SCHEMA
        + "\0"
        + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    )


def legacy_unsigned_row_commitment(row: Any) -> dict[str, str]:
    """Commit every stored field of one unsigned historical main-chain row."""
    timestamp = _utc_iso(row.timestamp)
    payload = {
        "id": str(row.id),
        "timestamp": timestamp,
        "actor": str(row.actor),
        "action": str(row.action),
        "target": row.target,
        "detail": row.detail,
        "ip_address": str(row.ip_address) if row.ip_address is not None else None,
        "signature": str(row.signature),
        "key_epoch": int(row.key_epoch),
        "sig_alg": str(row.sig_alg),
        "signer_fpr": row.signer_fpr,
        "payload_version": int(row.payload_version),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    digest = hashlib.sha256(b"rhorizon:audit_legacy_row:v1\0" + canonical).hexdigest()
    return {
        "id": payload["id"],
        "timestamp": timestamp,
        "action": payload["action"],
        "digest": "sha256:" + digest,
    }


def validate_legacy_adoption(adoption: Any) -> list[dict[str, str]]:
    """Return normalized adopted rows or reject malformed signed metadata."""
    if (
        not isinstance(adoption, dict)
        or adoption.get("schema") != LEGACY_ADOPTION_SCHEMA
    ):
        raise ValueError("invalid legacy adoption schema")
    rows = adoption.get("unsigned_rows")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_LEGACY_ADOPTED_ROWS:
        raise ValueError("invalid legacy adoption row count")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid legacy adoption row")
        row_id = str(UUID(str(row["id"])))
        timestamp = _utc_iso(
            datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
        )
        action = str(row["action"])
        digest = str(row["digest"])
        if row_id in seen or action != "audit_lite_checkpoint":
            raise ValueError("legacy adoption contains an unsupported row")
        if len(digest) != 71 or not digest.startswith("sha256:"):
            raise ValueError("invalid legacy adoption digest")
        try:
            bytes.fromhex(digest[7:])
        except ValueError as error:
            raise ValueError("invalid legacy adoption digest") from error
        seen.add(row_id)
        normalized.append(
            {
                "id": row_id,
                "timestamp": timestamp,
                "action": action,
                "digest": digest,
            }
        )
    return sorted(normalized, key=lambda row: (row["timestamp"], row["id"]))


def build_anchor_payload(
    *,
    anchor_id: UUID,
    completed_at: datetime,
    signer_fpr: str,
    result: dict[str, Any],
    legacy_adoption: dict[str, Any] | None = None,
    verification_mode: str = "full",
) -> dict[str, Any]:
    """Select only security-relevant, JSON-stable fields from a full result."""
    if result.get("verification_scope") != "full":
        raise ValueError("verification anchor requires a full verification")
    if verification_mode not in {"full", "legacy_candidate"}:
        raise ValueError("unsupported verification anchor mode")
    if result.get("evidence_intact") is not True and legacy_adoption is None:
        raise ValueError("verification anchor requires intact evidence")
    if result.get("snapshot_stable") is not True:
        raise ValueError("verification anchor requires a stable snapshot")

    if legacy_adoption is not None:
        adopted_rows = validate_legacy_adoption(legacy_adoption)
        if result.get("chain_intact") is not True:
            raise ValueError("legacy adoption requires an intact signed chain")
        if result.get("evidence_incomplete_reasons") != ["unsigned_main_chain_entries"]:
            raise ValueError("legacy adoption requires unsigned rows as sole gap")
        if int(result.get("unsigned_entries") or 0) != len(adopted_rows):
            raise ValueError("legacy adoption row count does not match full result")
        legacy_adoption = {**legacy_adoption, "unsigned_rows": adopted_rows}
    if verification_mode == "legacy_candidate" and legacy_adoption is None:
        raise ValueError("legacy candidate requires unsigned-row commitments")
    if verification_mode == "full" and legacy_adoption is not None:
        verification_mode = "legacy_adopted"

    payload = {
        "schema": ANCHOR_SCHEMA,
        "id": str(anchor_id),
        "completed_at": _utc_iso(completed_at),
        "signer_fpr": signer_fpr,
        "verification_mode": verification_mode,
        "verifier_version": 1,
        "main": {
            "row_count": int(result["total_entries"]),
            "highwater_timestamp": result.get("main_highwater_timestamp"),
            "highwater_id": result.get("main_highwater_id"),
            "highwater_stored_signature": result.get(
                "main_highwater_stored_signature",
                result.get("main_head_signature"),
            ),
            "head_signature": result.get("main_head_signature"),
            "anchored_at_day": result.get("chain_anchored_at_day"),
            "pruned_rows": int(result.get("chain_pruned_rows") or 0),
        },
        "lite": {
            "row_count": int(result.get("audit_lite_total_rows") or 0),
            "checkpoint_count": int(result.get("audit_lite_checkpoints") or 0),
            "checkpointed_rows": int(result.get("audit_lite_checkpointed_rows") or 0),
            "head_checkpoint_id": result.get("audit_lite_head_checkpoint_id"),
            "highwater_timestamp": result.get("audit_lite_head_timestamp"),
            "highwater_id": result.get("audit_lite_head_id"),
            "head_root": result.get("audit_lite_head_root"),
            "archived_rows": int(result.get("audit_lite_archived_rows") or 0),
        },
        "archive": {
            "seal_count": int(result.get("archive_seals") or 0),
            "head_day": result.get("archive_head_day"),
            "head_digest": result.get("archive_head_digest"),
        },
    }
    if legacy_adoption is not None:
        payload["legacy_adoption"] = legacy_adoption
    return payload


async def create_verification_anchor(
    db: AsyncSession,
    result: dict[str, Any],
    *,
    legacy_adoption: dict[str, Any] | None = None,
    verification_mode: str = "full",
) -> dict[str, Any]:
    """Sign and persist a receipt for one clean, stable full verification."""
    signer_fpr = await resolve_signer_fpr(db)
    if signer_fpr is None:
        raise RuntimeError("audit Ed25519 identity is not provisioned")

    anchor_id = uuid4()
    completed_at = datetime.now(timezone.utc)
    payload = build_anchor_payload(
        anchor_id=anchor_id,
        completed_at=completed_at,
        signer_fpr=signer_fpr,
        result=result,
        legacy_adoption=legacy_adoption,
        verification_mode=verification_mode,
    )
    return await _persist_verification_anchor(db, payload)


async def _persist_verification_anchor(
    db: AsyncSession, payload: dict[str, Any]
) -> dict[str, Any]:
    """Sign and persist a fully constructed anchor payload."""
    anchor_id = UUID(str(payload["id"]))
    completed_at = datetime.fromisoformat(
        str(payload["completed_at"]).replace("Z", "+00:00")
    )
    signer_fpr = str(payload["signer_fpr"])
    signature = await vault.audit_sign_identity(canonical_anchor_payload(payload), "")
    await db.execute(
        text("""
            INSERT INTO vault_audit_verification_anchors
                (id, completed_at, payload, signature, signer_fpr)
            VALUES
                (CAST(:id AS uuid), :completed_at, CAST(:payload AS jsonb),
                 :signature, :signer_fpr)
        """),
        {
            "id": str(anchor_id),
            "completed_at": completed_at,
            "payload": json.dumps(payload, separators=(",", ":")),
            "signature": signature,
            "signer_fpr": signer_fpr,
        },
    )
    return {
        "id": str(anchor_id),
        "completed_at": _utc_iso(completed_at),
        "signer_fpr": signer_fpr,
        "signature": signature,
        "payload": payload,
    }


async def adopt_verification_candidate(
    db: AsyncSession,
    candidate: dict[str, Any],
    *,
    source_job_id: UUID,
    operator: str,
) -> dict[str, Any]:
    """Promote an authenticated legacy candidate into a trusted anchor."""
    if candidate.get("valid") is not True:
        raise ValueError("legacy candidate signature is invalid")
    candidate_payload = candidate.get("payload")
    if not isinstance(candidate_payload, dict):
        raise ValueError("legacy candidate payload is invalid")
    if candidate_payload.get("verification_mode") != "legacy_candidate":
        raise ValueError("verification anchor is not a legacy candidate")
    rows = validate_legacy_adoption(candidate_payload.get("legacy_adoption"))
    signer_fpr = await resolve_signer_fpr(db)
    if signer_fpr is None:
        raise RuntimeError("audit Ed25519 identity is not provisioned")
    anchor_id = uuid4()
    completed_at = datetime.now(timezone.utc)
    payload = {
        "schema": ANCHOR_SCHEMA,
        "id": str(anchor_id),
        "completed_at": _utc_iso(completed_at),
        "signer_fpr": signer_fpr,
        "verification_mode": "legacy_adopted",
        "verifier_version": 1,
        "main": candidate_payload["main"],
        "lite": candidate_payload["lite"],
        "archive": candidate_payload["archive"],
        "legacy_adoption": {
            "schema": LEGACY_ADOPTION_SCHEMA,
            "source_job_id": str(source_job_id),
            "source_candidate_id": str(candidate_payload["id"]),
            "operator": operator,
            "unsigned_rows": rows,
        },
    }
    return await _persist_verification_anchor(db, payload)


def _authenticated_anchor(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    payload = row.payload
    if not isinstance(payload, dict):
        return {"valid": False, "reason": "payload_not_object"}
    try:
        metadata_matches = (
            payload.get("id") == str(row.id)
            and payload.get("completed_at") == _utc_iso(row.completed_at)
            and payload.get("signer_fpr") == row.signer_fpr
        )
        signed = row.public_key is not None and verify_audit_ed25519(
            bytes(row.public_key),
            canonical_anchor_payload(payload),
            "",
            row.signature,
        )
    except (TypeError, ValueError):
        metadata_matches = False
        signed = False
    valid = bool(metadata_matches and signed)
    return {
        "valid": valid,
        "reason": None if valid else "metadata_or_signature_invalid",
        "id": str(row.id),
        "completed_at": _utc_iso(row.completed_at),
        "signer_fpr": row.signer_fpr,
        "signature": row.signature,
        "payload": payload,
    }


async def latest_verification_anchor(db: AsyncSession) -> dict[str, Any] | None:
    """Load and independently authenticate the newest full-verification anchor."""
    row = (
        await db.execute(
            text("""
                SELECT a.id, a.completed_at, a.payload, a.signature,
                       a.signer_fpr, c.public_key
                FROM vault_audit_verification_anchors AS a
                LEFT JOIN vault_audit_signer_certs AS c
                  ON c.fingerprint = a.signer_fpr
                WHERE COALESCE(a.payload->>'verification_mode', 'full')
                      IN ('full', 'legacy_adopted')
                ORDER BY a.completed_at DESC, a.id DESC
                LIMIT 1
            """)
        )
    ).fetchone()
    return _authenticated_anchor(row)


async def verification_anchor_by_id(
    db: AsyncSession, anchor_id: UUID
) -> dict[str, Any] | None:
    """Load and authenticate one anchor, including a legacy candidate."""
    row = (
        await db.execute(
            text("""
                SELECT a.id, a.completed_at, a.payload, a.signature,
                       a.signer_fpr, c.public_key
                FROM vault_audit_verification_anchors AS a
                LEFT JOIN vault_audit_signer_certs AS c
                  ON c.fingerprint = a.signer_fpr
                WHERE a.id = CAST(:id AS uuid)
            """),
            {"id": str(anchor_id)},
        )
    ).fetchone()
    return _authenticated_anchor(row)
