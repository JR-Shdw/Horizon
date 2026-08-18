# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Versioned canonical payloads for the signed mutation audit chain."""

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

AUDIT_PAYLOAD_V1 = 1
AUDIT_PAYLOAD_V2 = 2
CURRENT_AUDIT_PAYLOAD_VERSION = AUDIT_PAYLOAD_V2
_V2_SCHEMA = "rhorizon.audit.row.v2"


def canonical_audit_detail(detail: Any) -> str:
    """Encode an audit detail object without lossy type coercion."""
    if not isinstance(detail, dict):
        raise ValueError("audit detail must be a JSON object")
    return json.dumps(
        detail,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _canonical_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("audit timestamp must be timezone-aware")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def audit_payload_v1(
    *, actor: str, action: str, target: str | None, detail: Any
) -> str:
    """Historical payload. Kept byte-for-byte for existing rows."""
    legacy_detail = detail if isinstance(detail, dict) else {}
    return (
        f"{actor}|{action}|{target or ''}|{json.dumps(legacy_detail, sort_keys=True)}"
    )


def audit_payload_v2(
    *,
    row_id: UUID | str,
    timestamp: datetime,
    actor: str,
    action: str,
    target: str | None,
    detail: Any,
    ip_address: str | None,
    key_epoch: int,
    sig_alg: str,
    signer_fpr: str | None,
) -> str:
    """Canonical, domain-separated representation of every signed row field."""
    row_uuid = UUID(str(row_id))
    detail_json = canonical_audit_detail(detail)
    envelope = {
        "action": action,
        "actor": actor,
        "detail": json.loads(detail_json),
        "id": str(row_uuid),
        "ip_address": ip_address,
        "key_epoch": int(key_epoch),
        "payload_version": AUDIT_PAYLOAD_V2,
        "schema": _V2_SCHEMA,
        "sig_alg": sig_alg,
        "signer_fpr": signer_fpr,
        "target": target,
        "timestamp": _canonical_timestamp(timestamp),
    }
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def audit_row_payload(row: Any) -> str:
    """Dispatch a stored row to its historical or current payload format."""
    version = int(getattr(row, "payload_version", AUDIT_PAYLOAD_V1) or 1)
    if version == AUDIT_PAYLOAD_V1:
        return audit_payload_v1(
            actor=row.actor,
            action=row.action,
            target=row.target,
            detail=row.detail,
        )
    if version == AUDIT_PAYLOAD_V2:
        return audit_payload_v2(
            row_id=row.id,
            timestamp=row.timestamp,
            actor=row.actor,
            action=row.action,
            target=row.target,
            detail=row.detail,
            ip_address=row.ip_address,
            key_epoch=row.key_epoch,
            sig_alg=row.sig_alg,
            signer_fpr=row.signer_fpr,
        )
    raise ValueError(f"unsupported audit payload version {version}")
