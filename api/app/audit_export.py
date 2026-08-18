# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Portable, signed evidence bundles for the mutation and read audit logs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .audit_archive import archive_file_paths, latest_prune_anchor
from .audit_identity import resolve_signer_fpr
from .audit_lite_archive import archive_path as lite_archive_path
from .audit_mtree import canonical_lite_row
from .vault_state import vault

EXPORT_SCHEMA = "rhorizon.audit_evidence_export.v1"
_MANIFEST_PREFIX = EXPORT_SCHEMA + "\0"
_BATCH_SIZE = 512


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_export_manifest(manifest: dict[str, Any]) -> str:
    """Canonical, domain-separated payload covered by the export signature."""
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    if unsigned.get("schema") != EXPORT_SCHEMA:
        raise ValueError("unsupported audit export schema")
    return _MANIFEST_PREFIX + json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _main_row(row: Any) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "timestamp": _utc_iso(row.timestamp),
        "actor": row.actor,
        "action": row.action,
        "target": row.target,
        "detail": row.detail if isinstance(row.detail, dict) else {},
        "ip_address": row.ip_address,
        "signature": row.signature,
        "key_epoch": int(row.key_epoch),
        "sig_alg": row.sig_alg,
        "signer_fpr": row.signer_fpr,
        "payload_version": int(row.payload_version),
    }


async def _write_query_jsonl(
    db: AsyncSession,
    path: Path,
    *,
    query: str,
    params: dict[str, Any],
    canonical_lite: bool = False,
) -> int:
    count = 0
    stream = await db.stream(
        text(query).execution_options(yield_per=_BATCH_SIZE), params
    )
    try:
        with path.open("wb") as handle:
            os.chmod(path, 0o600)
            async for row in stream:
                if canonical_lite:
                    handle.write(canonical_lite_row(row) + b"\n")
                else:
                    handle.write(_json_bytes(_main_row(row)))
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        await stream.close()
    return count


def _write_json(path: Path, value: Any) -> None:
    with path.open("wb") as handle:
        os.chmod(path, 0o600)
        handle.write(_json_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return "sha256:" + digest.hexdigest(), size


def _regular_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode)


def _copy_member(source: Path, destination: Path) -> None:
    if not _regular_file(source):
        raise RuntimeError(
            f"audit archive is missing or not a regular file: {source.name}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("wb") as dst:
        os.chmod(destination, 0o600)
        shutil.copyfileobj(src, dst, length=1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())


def _overlaps(
    first: datetime, last: datetime, since: datetime | None, until: datetime
) -> bool:
    lower = since or datetime.min.replace(tzinfo=timezone.utc)
    return last >= lower and first < until


def _day_overlaps(day: date, since: datetime | None, until: datetime) -> bool:
    start = datetime.combine(day, time.min, tzinfo=timezone.utc)
    end = datetime.combine(day, time.max, tzinfo=timezone.utc)
    return _overlaps(start, end, since, until)


async def _proof_documents(db: AsyncSession) -> dict[str, Any]:
    signer_rows = (
        await db.execute(
            text("""
                SELECT fingerprint, public_key, cert_pem, node_uuid, first_seen
                FROM vault_audit_signer_certs ORDER BY first_seen, fingerprint
            """)
        )
    ).fetchall()
    anchor_rows = (
        await db.execute(
            text("""
                SELECT id, completed_at, payload, signature, signer_fpr
                FROM vault_audit_verification_anchors
                ORDER BY completed_at, id
            """)
        )
    ).fetchall()
    main_seals = (
        await db.execute(
            text("""
                SELECT day, file_name, entry_count, content_digest,
                       first_signature, last_signature, previous_seal_digest,
                       attested_by_audit_id, created_at
                FROM vault_audit_archive_seals ORDER BY day
            """)
        )
    ).fetchall()
    lite_seals = (
        await db.execute(
            text("""
                SELECT id, file_name, entry_count, content_digest, seal_digest,
                       merkle_root, first_timestamp, first_id, last_timestamp,
                       last_id, previous_seal_digest, attested_by_audit_id,
                       created_at
                FROM vault_audit_lite_archive_seals
                ORDER BY first_timestamp, first_id
            """)
        )
    ).fetchall()
    return {
        "signers": [
            {
                "fingerprint": row.fingerprint,
                "public_key": bytes(row.public_key).hex(),
                "cert_pem": row.cert_pem,
                "node_uuid": row.node_uuid,
                "first_seen": _utc_iso(row.first_seen),
            }
            for row in signer_rows
        ],
        "anchors": [
            {
                "id": str(row.id),
                "completed_at": _utc_iso(row.completed_at),
                "payload": row.payload,
                "signature": row.signature,
                "signer_fpr": row.signer_fpr,
            }
            for row in anchor_rows
        ],
        "main_seals": [
            {
                "day": row.day.isoformat(),
                "file_name": row.file_name,
                "entry_count": int(row.entry_count),
                "content_digest": row.content_digest,
                "first_signature": row.first_signature,
                "last_signature": row.last_signature,
                "previous_seal_digest": row.previous_seal_digest,
                "attested_by_audit_id": str(row.attested_by_audit_id)
                if row.attested_by_audit_id
                else None,
                "created_at": _utc_iso(row.created_at),
            }
            for row in main_seals
        ],
        "lite_seals": [
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
                "created_at": _utc_iso(row.created_at),
            }
            for row in lite_seals
        ],
    }


def _build_tar(bundle_path: Path, root: Path, member_paths: list[str]) -> None:
    with tarfile.open(bundle_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for member_path in sorted(member_paths):
            source = root / member_path
            info = archive.gettarinfo(str(source), arcname=member_path)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mode = 0o600
            with source.open("rb") as handle:
                archive.addfile(info, handle)
    os.chmod(bundle_path, 0o600)


async def create_evidence_bundle(
    db: AsyncSession,
    *,
    audit_dir: Path,
    requested_by: str,
    since: datetime | None,
    until: datetime,
    verification: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    """Create one signed, bounded-memory tar.gz bundle under ``audit_dir``."""
    if since is not None and since >= until:
        raise ValueError("since must be earlier than until")
    signer_fpr = await resolve_signer_fpr(db)
    if signer_fpr is None:
        raise RuntimeError("audit Ed25519 identity is not provisioned")

    audit_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".audit-export-", dir=audit_dir))
    os.chmod(work, 0o700)
    bundle_fd, bundle_name = tempfile.mkstemp(
        prefix="audit-evidence-", suffix=".tar.gz", dir=audit_dir
    )
    os.close(bundle_fd)
    bundle_path = Path(bundle_name)
    try:
        params: dict[str, Any] = {"until": until}
        where = "timestamp < :until"
        if since is not None:
            params["since"] = since
            where += " AND timestamp >= :since"

        main_path = work / "audit/main.jsonl"
        lite_path = work / "audit/lite.jsonl"
        main_path.parent.mkdir(parents=True, exist_ok=True)
        main_count = await _write_query_jsonl(
            db,
            main_path,
            query=f"""
                SELECT id, timestamp, actor, action, target, detail, ip_address,
                       signature, key_epoch, sig_alg, signer_fpr, payload_version
                FROM vault_audit WHERE {where}
                ORDER BY timestamp, id
            """,
            params=params,
        )
        lite_count = await _write_query_jsonl(
            db,
            lite_path,
            query=f"""
                SELECT id, timestamp, actor, action, target, detail, ip_address
                FROM vault_audit_lite WHERE {where}
                ORDER BY timestamp, id
            """,
            params=params,
            canonical_lite=True,
        )

        proofs = await _proof_documents(db)
        proof_files = {
            "proofs/signers.json": proofs["signers"],
            "proofs/verification-anchors.json": proofs["anchors"],
            "proofs/main-archive-seals.json": proofs["main_seals"],
            "proofs/lite-archive-seals.json": proofs["lite_seals"],
        }
        for relative, value in proof_files.items():
            path = work / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_json(path, value)

        if not any(s["fingerprint"] == signer_fpr for s in proofs["signers"]):
            raise RuntimeError("audit export signer is absent from public registry")

        archived_main = 0
        prune_anchor = await latest_prune_anchor(db)
        pruned_day = (
            date.fromisoformat(str(prune_anchor["pruned_through_day"]))
            if prune_anchor
            else None
        )
        for seal in proofs["main_seals"]:
            seal_day = date.fromisoformat(seal["day"])
            if pruned_day is None or seal_day > pruned_day:
                continue
            if not _day_overlaps(seal_day, since, until):
                continue
            plain, compressed = archive_file_paths(audit_dir, seal_day)
            source = plain if _regular_file(plain) else compressed
            relative = f"archives/main/{source.name}"
            _copy_member(source, work / relative)
            archived_main += int(seal["entry_count"])

        archived_lite = 0
        for seal in proofs["lite_seals"]:
            first = datetime.fromisoformat(
                seal["first_timestamp"].replace("Z", "+00:00")
            )
            last = datetime.fromisoformat(seal["last_timestamp"].replace("Z", "+00:00"))
            if not _overlaps(first, last, since, until):
                continue
            # The database is evidence, not an authority for filesystem paths.
            # Reuse the archive writer's strict basename grammar so a forged seal
            # cannot make an export disclose an unrelated server file.
            source = lite_archive_path(audit_dir, seal["file_name"])
            relative = f"archives/lite/{source.name}"
            _copy_member(source, work / relative)
            archived_lite += int(seal["entry_count"])

        members = []
        member_paths = [
            str(path.relative_to(work))
            for path in work.rglob("*")
            if _regular_file(path)
        ]
        for relative in sorted(member_paths):
            digest, size = _sha256_file(work / relative)
            members.append({"path": relative, "size": size, "sha256": digest})

        created_at = datetime.now(timezone.utc)
        manifest: dict[str, Any] = {
            "schema": EXPORT_SCHEMA,
            "created_at": _utc_iso(created_at),
            "requested_by": requested_by,
            "range": {
                "since": _utc_iso(since) if since is not None else None,
                "until": _utc_iso(until),
                "until_exclusive": True,
            },
            "counts": {
                "main_live_rows": main_count,
                "main_archived_rows": archived_main,
                "lite_live_rows": lite_count,
                "lite_archived_rows": archived_lite,
            },
            "source_verification": verification,
            "members": members,
            "signature": {
                "algorithm": "ed25519",
                "signer_fpr": signer_fpr,
                "value": "",
            },
        }
        manifest["signature"]["value"] = await vault.audit_sign_identity(
            canonical_export_manifest(manifest), ""
        )
        manifest_path = work / "manifest.json"
        _write_json(manifest_path, manifest)
        member_paths.append("manifest.json")
        await asyncio.to_thread(_build_tar, bundle_path, work, member_paths)
        return bundle_path, manifest
    except Exception:
        bundle_path.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
