# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Signed, immutable archives for checkpointed audit-lite prefixes."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

SEAL_ACTION = "audit_lite_archive_seal"
SEAL_SCHEMA = "rhorizon.audit_lite_archive_seal.v1"
PRUNE_ANCHOR_SCHEMA = "rhorizon.audit_lite_prune_anchor.v2"
_DIGEST_PREFIX = b"rhorizon:audit_lite_archive:v1\0"
_SEAL_PREFIX = b"rhorizon:audit_lite_archive_seal:v1\0"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FILE_RE = re.compile(r"^audit-lite-[0-9a-f-]{36}\.jsonl\.gz$")


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def archive_digest(lines: list[str]) -> str:
    digest = hashlib.sha256(_DIGEST_PREFIX)
    for line in lines:
        raw = line.encode("utf-8")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return "sha256:" + digest.hexdigest()


def seal_digest(detail: dict[str, Any]) -> str:
    payload = {"schema": SEAL_SCHEMA}
    for key in (
        "id",
        "file_name",
        "entry_count",
        "content_digest",
        "merkle_root",
        "first_timestamp",
        "first_id",
        "last_timestamp",
        "last_id",
        "previous_seal_digest",
    ):
        payload[key] = detail[key]
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(_SEAL_PREFIX + canonical).hexdigest()


def archive_path(audit_dir: Path, file_name: str) -> Path:
    if not _FILE_RE.fullmatch(file_name):
        raise ValueError("invalid audit-lite archive name")
    return audit_dir / file_name


def read_archive_lines(audit_dir: Path, file_name: str) -> list[str] | None:
    try:
        path = archive_path(audit_dir, file_name)
    except ValueError:
        return None
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle if line.strip()]
    except (OSError, UnicodeError):
        return None


def inspect_archive(audit_dir: Path, file_name: str) -> dict[str, Any] | None:
    """Validate canonical rows and compute count, digest and Merkle root boundedly."""
    from .audit_mtree import _MerkleFrontier, audit_lite_leaf_hash, canonical_lite_row

    try:
        path = archive_path(audit_dir, file_name)
        digest = hashlib.sha256(_DIGEST_PREFIX)
        frontier = _MerkleFrontier()
        first: SimpleNamespace | None = None
        last: SimpleNamespace | None = None
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\n")
                value = json.loads(line)
                value["timestamp"] = datetime.fromisoformat(
                    str(value["timestamp"]).replace("Z", "+00:00")
                )
                row = SimpleNamespace(**value)
                canonical = canonical_lite_row(row).decode("utf-8")
                if canonical != line:
                    return None
                encoded = line.encode("utf-8")
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
                frontier.add(audit_lite_leaf_hash(row))
                first = first or row
                last = row
        if first is None or last is None:
            return None
        return {
            "entry_count": frontier.count,
            "content_digest": "sha256:" + digest.hexdigest(),
            "merkle_root": frontier.root(),
            "first_timestamp": _utc_iso(first.timestamp),
            "first_id": str(first.id),
            "last_timestamp": _utc_iso(last.timestamp),
            "last_id": str(last.id),
        }
    except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
        return None


def parse_prune_anchor(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("schema") != PRUNE_ANCHOR_SCHEMA:
        return None
    try:
        parsed = {
            "last_checkpoint_id": str(UUID(str(value["last_checkpoint_id"]))),
            "to_timestamp": datetime.fromisoformat(
                str(value["to_timestamp"]).replace("Z", "+00:00")
            ),
            "to_id": str(UUID(str(value["to_id"]))),
            "checkpoint_count": int(value["checkpoint_count"]),
            "checkpointed_row_count": int(value["checkpointed_row_count"]),
            "archive_seal_count": int(value["archive_seal_count"]),
            "archive_head_digest": str(value["archive_head_digest"]),
            "head_root": str(value["head_root"]),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if (
        parsed["checkpoint_count"] < 1
        or parsed["checkpointed_row_count"] < 1
        or parsed["archive_seal_count"] < 1
        or not _DIGEST_RE.match(parsed["archive_head_digest"])
        or not _DIGEST_RE.match(parsed["head_root"])
    ):
        return None
    return parsed


async def _sealed(db: AsyncSession) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            text("""
                SELECT id, file_name, entry_count, content_digest, seal_digest,
                       merkle_root,
                       first_timestamp, first_id, last_timestamp, last_id,
                       previous_seal_digest, attested_by_audit_id
                FROM vault_audit_lite_archive_seals
                ORDER BY created_at ASC, id ASC
            """)
        )
    ).fetchall()
    return [
        {
            "id": str(row.id),
            "file_name": row.file_name,
            "entry_count": int(row.entry_count),
            "content_digest": row.content_digest,
            "seal_digest": row.seal_digest,
            "merkle_root": row.merkle_root,
            "first_timestamp": _utc_iso(row.first_timestamp),
            "first_id": str(row.first_id),
            "last_timestamp": _utc_iso(row.last_timestamp),
            "last_id": str(row.last_id),
            "previous_seal_digest": row.previous_seal_digest,
            "attested_by_audit_id": str(row.attested_by_audit_id)
            if row.attested_by_audit_id
            else None,
        }
        for row in rows
    ]


def _seal_matches(entry: dict[str, Any], detail: Any) -> bool:
    if not isinstance(detail, dict) or detail.get("schema") != SEAL_SCHEMA:
        return False
    return all(
        detail.get(key) == entry[key] for key in entry if key != "attested_by_audit_id"
    )


async def verify_lite_archives(
    db: AsyncSession, *, audit_dir: Path, prune_anchor: dict[str, Any] | None
) -> dict[str, Any]:
    """Re-hash every lite archive and authenticate its signed seal lineage."""
    sealed = await _sealed(db)
    signed_rows = (
        await db.execute(
            text("SELECT id, detail FROM vault_audit WHERE action=:action"),
            {"action": SEAL_ACTION},
        )
    ).fetchall()
    signed = {str(row.id): row.detail for row in signed_rows}
    problems: list[str] = []
    previous: str | None = None
    total = 0
    for index, entry in enumerate(sealed):
        if entry["previous_seal_digest"] != previous:
            problems.append("previous_seal_digest_mismatch")
        if seal_digest(entry) != entry["seal_digest"]:
            problems.append("seal_digest_mismatch")
        anchored = (
            prune_anchor is not None and index < prune_anchor["archive_seal_count"]
        )
        if not anchored and not _seal_matches(
            entry, signed.get(entry["attested_by_audit_id"])
        ):
            problems.append("signed_seal_attestation_mismatch")
        inspected = inspect_archive(audit_dir, entry["file_name"])
        if inspected is None:
            problems.append("archive_file_missing")
        elif inspected["entry_count"] != entry["entry_count"]:
            problems.append("entry_count_mismatch")
        elif inspected["content_digest"] != entry["content_digest"]:
            problems.append("content_digest_mismatch")
        elif inspected["merkle_root"] != entry["merkle_root"]:
            problems.append("merkle_root_mismatch")
        total += entry["entry_count"]
        previous = entry["seal_digest"]
    if prune_anchor is not None and (
        prune_anchor["archive_seal_count"] != len(sealed)
        or not sealed
        or prune_anchor["archive_head_digest"] != sealed[-1]["seal_digest"]
        or prune_anchor["checkpointed_row_count"] != total
    ):
        problems.append("prune_anchor_mismatch")
    return {
        "intact": not problems,
        "problems": sorted(set(problems)),
        "rows": total,
        "seal_count": len(sealed),
        "head_digest": sealed[-1]["seal_digest"] if sealed else None,
    }


async def archive_lite_prefix(
    db: AsyncSession,
    *,
    audit_dir: Path,
    last_checkpoint_id: str,
    to_timestamp: datetime,
    to_id: str,
    checkpoint_count: int,
    head_root: str,
    previous_anchor: dict[str, Any] | None,
    actor: str,
) -> dict[str, Any]:
    """Export, attest and delete one fully checkpointed live prefix."""
    from .audit import log_action
    from .audit_mtree import _MerkleFrontier, audit_lite_leaf_hash, canonical_lite_row

    after_ts = previous_anchor["to_timestamp"] if previous_anchor else None
    after_id = previous_anchor["to_id"] if previous_anchor else None
    where_after = ""
    params: dict[str, Any] = {"to_ts": to_timestamp, "to_id": to_id}
    if after_ts is not None:
        where_after = "AND (timestamp,id) > (:after_ts,CAST(:after_id AS uuid))"
        params.update({"after_ts": after_ts, "after_id": after_id})
    rows = await db.stream(
        text(f"""
                SELECT id,timestamp,actor,action,target,detail,ip_address
                FROM vault_audit_lite
                WHERE (timestamp,id) <= (:to_ts,CAST(:to_id AS uuid)) {where_after}
                ORDER BY timestamp,id
            """).execution_options(yield_per=512),
        params,
    )
    seal_id = uuid4()
    file_name = f"audit-lite-{seal_id}.jsonl.gz"
    audit_dir.mkdir(parents=True, exist_ok=True)
    final = archive_path(audit_dir, file_name)
    temporary = final.with_suffix(final.suffix + ".tmp")
    digest_state = hashlib.sha256(_DIGEST_PREFIX)
    frontier = _MerkleFrontier()
    first = None
    last = None
    try:
        with gzip.open(temporary, "wt", encoding="utf-8") as handle:
            async for row in rows:
                line = canonical_lite_row(row).decode("utf-8")
                raw = line.encode("utf-8")
                digest_state.update(len(raw).to_bytes(8, "big"))
                digest_state.update(raw)
                frontier.add(audit_lite_leaf_hash(row))
                first = first or row
                last = row
                handle.write(line + "\n")
    finally:
        await rows.close()
    if first is None or last is None:
        raise RuntimeError("no checkpointed audit-lite rows to archive")
    os.replace(temporary, final)
    os.chmod(final, 0o600)
    file_fd = os.open(final, os.O_RDONLY)
    try:
        os.fsync(file_fd)
    finally:
        os.close(file_fd)
    directory_fd = os.open(audit_dir, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    inspected = inspect_archive(audit_dir, file_name)
    digest = "sha256:" + digest_state.hexdigest()
    if (
        inspected is None
        or inspected["entry_count"] != frontier.count
        or inspected["content_digest"] != digest
        or inspected["merkle_root"] != frontier.root()
    ):
        raise RuntimeError("audit-lite archive write verification failed")
    previous_seals = await _sealed(db)
    detail = {
        "schema": SEAL_SCHEMA,
        "id": str(seal_id),
        "file_name": file_name,
        "entry_count": frontier.count,
        "content_digest": digest,
        "merkle_root": frontier.root(),
        "first_timestamp": _utc_iso(first.timestamp),
        "first_id": str(first.id),
        "last_timestamp": _utc_iso(last.timestamp),
        "last_id": str(last.id),
        "previous_seal_digest": previous_seals[-1]["seal_digest"]
        if previous_seals
        else None,
    }
    detail["seal_digest"] = seal_digest(detail)
    audit_id = await log_action(
        db,
        actor=actor,
        action=SEAL_ACTION,
        target=file_name,
        detail=detail,
    )
    await db.execute(
        text("""
            INSERT INTO vault_audit_lite_archive_seals
              (id,file_name,entry_count,content_digest,seal_digest,merkle_root,
               first_timestamp,first_id,last_timestamp,last_id,
               previous_seal_digest,attested_by_audit_id)
            VALUES (CAST(:id AS uuid),:file_name,:entry_count,:content_digest,
                    :seal_digest,:merkle_root,:first_timestamp,CAST(:first_id AS uuid),
                    :last_timestamp,CAST(:last_id AS uuid),:previous_seal_digest,
                    CAST(:audit_id AS uuid))
        """),
        {
            **detail,
            "first_timestamp": first.timestamp,
            "last_timestamp": last.timestamp,
            "audit_id": audit_id,
        },
    )
    archived_before = (
        previous_anchor["checkpointed_row_count"] if previous_anchor else 0
    )
    seal_count_before = previous_anchor["archive_seal_count"] if previous_anchor else 0
    anchor = {
        "schema": PRUNE_ANCHOR_SCHEMA,
        "last_checkpoint_id": last_checkpoint_id,
        "to_timestamp": _utc_iso(to_timestamp),
        "to_id": to_id,
        "checkpoint_count": checkpoint_count,
        "checkpointed_row_count": archived_before + frontier.count,
        "archive_seal_count": seal_count_before + 1,
        "archive_head_digest": detail["seal_digest"],
        "head_root": head_root,
    }
    await db.execute(
        text(
            "DELETE FROM vault_audit_lite WHERE (timestamp,id) <= "
            "(:to_ts,CAST(:to_id AS uuid))"
        ),
        {"to_ts": to_timestamp, "to_id": to_id},
    )
    return anchor
