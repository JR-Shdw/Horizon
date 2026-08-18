# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Signed seals over the daily audit archive files.

Every audit entry is written twice: a signed row in ``vault_audit`` and a line
in ``audit-YYYY-MM-DD.jsonl``. Each archived line already carries its own chain
signature, so MODIFYING a line or deleting one from the middle is detectable --
the signature fails, or the chain breaks at the seam.

Two things are not detectable that way, and they are the two that matter once
the database is pruned:

  * truncating the tail of a file leaves a shorter, perfectly valid chain --
    nothing in a valid prefix says how long the log was supposed to be;
  * deleting a whole day's file leaves no trace at all.

So a completed file is SEALED: its logical content is hashed, its entries
counted, its first and last chain signatures recorded, and that record is
written back into ``vault_audit`` through the ordinary signed-and-chained
``log_action`` path. The seal is therefore protected by the same chain it
attests, exactly like ``audit_mtree``'s lite checkpoints, and seals link to
their predecessor so the SEQUENCE of days cannot be truncated either.

The digest covers the file's logical bytes, not its stored bytes: the reaper
gzips files older than ``audit_compress_days``, and a seal must survive that.

Sealing cross-checks the file against the database rows for the same window
while those rows still exist. That is the only moment both copies are present,
and it is what makes an incomplete archive loud instead of silent -- file
writes are best effort by design (a full disk must not fail a vault
operation), so a seal that simply trusted the file could certify a gap. A
window that disagrees is refused, which also means it can never become
prunable.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("rhorizon.audit_archive")

SEAL_ACTION = "audit_archive_seal"
SEAL_SCHEMA = "rhorizon.audit_archive_seal.v1"
ARCHIVE_PRUNE_ANCHOR_SCHEMA = "rhorizon.audit_archive_prune_anchor.v1"
DIGEST_ALG = "sha256-jsonl-logical-v1"

# Domain separator so an archive digest can never be confused with a lite
# Merkle leaf or any other sha256 the product computes.
_DIGEST_PREFIX = b"rhorizon:audit_archive:v1\0"
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ArchiveSealError(RuntimeError):
    """The archive and the database disagree, or a sealed file changed."""


def archive_file_paths(audit_dir: Path, day: date) -> tuple[Path, Path]:
    """Both storage forms of one day's archive: plain and gzipped."""
    stem = f"audit-{day.isoformat()}.jsonl"
    return audit_dir / stem, audit_dir / f"{stem}.gz"


def read_archive_lines(audit_dir: Path, day: date) -> list[str] | None:
    """Logical lines of one day's archive, whichever form it is stored in.

    Returns None when neither form exists. Compression is transparent: the
    seal is over content, so gzipping a sealed file must not invalidate it.
    """
    plain, compressed = archive_file_paths(audit_dir, day)
    if plain.exists():
        raw = plain.read_text()
    elif compressed.exists():
        with gzip.open(compressed, "rt") as handle:
            raw = handle.read()
    else:
        return None
    return [line for line in raw.splitlines() if line.strip()]


def archive_digest(lines: list[str]) -> str:
    """Digest of the logical content, independent of storage form.

    Each line is length-prefixed before hashing so that moving a newline
    between two adjacent entries cannot produce the same digest.
    """
    digest = hashlib.sha256()
    digest.update(_DIGEST_PREFIX)
    for line in lines:
        payload = line.encode()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def _entry_signature(line: str) -> str:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ArchiveSealError("archive line is not valid JSON") from exc
    signature = value.get("signature")
    if not isinstance(signature, str) or not signature:
        raise ArchiveSealError("archive line carries no signature")
    return signature


def seal_detail(
    day: date,
    lines: list[str],
    *,
    previous_seal_digest: str | None,
) -> dict[str, Any]:
    """The signed statement about one completed archive file.

    ``entry_count`` plus ``last_signature`` are what make truncation
    detectable; ``previous_seal_digest`` chains the seals to each other, so
    the SEQUENCE of days is pinned too -- removing one day's seal leaves the
    next seal referring to a digest nothing produces. The digest remains the
    lineage value across database pruning; the attesting audit row id is also
    stored for direct lookup while that row survives.
    """
    if not lines:
        raise ValueError("cannot seal an empty archive file")
    return {
        "schema": SEAL_SCHEMA,
        "digest_alg": DIGEST_ALG,
        "day": day.isoformat(),
        "file_name": f"audit-{day.isoformat()}.jsonl",
        "entry_count": len(lines),
        "content_digest": archive_digest(lines),
        "first_signature": _entry_signature(lines[0]),
        "last_signature": _entry_signature(lines[-1]),
        "previous_seal_digest": previous_seal_digest,
    }


def parse_seal_detail(detail: Any) -> dict[str, Any] | None:
    if not isinstance(detail, dict) or detail.get("schema") != SEAL_SCHEMA:
        return None
    try:
        return {
            "day": date.fromisoformat(str(detail["day"])),
            "file_name": str(detail["file_name"]),
            "entry_count": int(detail["entry_count"]),
            "content_digest": str(detail["content_digest"]),
            "first_signature": str(detail["first_signature"]),
            "last_signature": str(detail["last_signature"]),
            "previous_seal_digest": detail.get("previous_seal_digest"),
        }
    except (KeyError, TypeError, ValueError):
        return None


def parse_archive_prune_anchor(detail: Any) -> dict[str, Any] | None:
    if (
        not isinstance(detail, dict)
        or detail.get("schema") != ARCHIVE_PRUNE_ANCHOR_SCHEMA
    ):
        return None
    try:
        parsed = {
            "seal_count": int(detail["seal_count"]),
            "head_day": date.fromisoformat(str(detail["head_day"])),
            "head_digest": str(detail["head_digest"]),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if parsed["seal_count"] < 1 or not _SHA256_DIGEST_RE.match(parsed["head_digest"]):
        return None
    return parsed


def _seal_detail_matches(entry: dict[str, Any], detail: dict[str, Any]) -> bool:
    return all(
        entry[field] == detail[field]
        for field in (
            "day",
            "file_name",
            "entry_count",
            "content_digest",
            "first_signature",
            "last_signature",
            "previous_seal_digest",
        )
    )


async def sealed_days(db: AsyncSession) -> list[dict[str, Any]]:
    """Seals from the durable table -- these outlive a prune.

    The chain rows are the attestation; this table is the record. Reading the
    table is what lets an archive file from beyond the database window still be
    verified.
    """
    rows = (
        await db.execute(
            text("""
                SELECT day, file_name, entry_count, content_digest,
                       first_signature, last_signature, previous_seal_digest,
                       attested_by_audit_id
                FROM vault_audit_archive_seals
                ORDER BY day ASC
            """)
        )
    ).fetchall()
    return [
        {
            "day": row.day,
            "file_name": row.file_name,
            "entry_count": int(row.entry_count),
            "content_digest": row.content_digest,
            "first_signature": row.first_signature,
            "last_signature": row.last_signature,
            "previous_seal_digest": row.previous_seal_digest,
            "attested_by_audit_id": str(row.attested_by_audit_id)
            if getattr(row, "attested_by_audit_id", None) is not None
            else None,
        }
        for row in rows
    ]


async def _sealed_days(db: AsyncSession) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            text("""
                SELECT id, timestamp, detail
                FROM vault_audit
                WHERE action = :action
                ORDER BY timestamp ASC, id ASC
            """),
            {"action": SEAL_ACTION},
        )
    ).fetchall()
    sealed = []
    for row in rows:
        parsed = parse_seal_detail(row.detail)
        if parsed is not None:
            parsed["audit_id"] = str(row.id)
            sealed.append(parsed)
    return sealed


async def _database_window(db: AsyncSession, day: date) -> list[str]:
    """Chain signatures the DATABASE holds for one UTC day, in chain order."""
    start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    rows = (
        await db.execute(
            text("""
                SELECT signature
                FROM vault_audit
                WHERE timestamp >= :start AND timestamp < :end
                ORDER BY timestamp ASC, id ASC
            """),
            {"start": start, "end": start + timedelta(days=1)},
        )
    ).fetchall()
    return [row.signature for row in rows]


def _cross_check(day: date, lines: list[str], db_signatures: list[str]) -> None:
    """Refuse to seal an archive that does not match the database.

    File writes are deliberately best effort -- a full disk must not fail a
    vault operation -- so this is the check that stops a gap becoming a signed
    claim of completeness. It runs while both copies still exist, which is the
    only moment the comparison is possible at all.
    """
    file_signatures = [_entry_signature(line) for line in lines]
    if len(file_signatures) != len(db_signatures):
        raise ArchiveSealError(
            f"archive for {day.isoformat()} holds {len(file_signatures)} entries "
            f"but the database holds {len(db_signatures)}; refusing to seal an "
            "incomplete archive"
        )
    for index, (from_file, from_db) in enumerate(zip(file_signatures, db_signatures)):
        if from_file != from_db:
            raise ArchiveSealError(
                f"archive for {day.isoformat()} diverges from the database at "
                f"entry {index}; refusing to seal"
            )


async def seal_completed_archives(
    db: AsyncSession,
    *,
    audit_dir: Path,
    today: date | None = None,
    actor: str = "reaper",
    max_days: int = 7,
) -> dict[str, Any]:
    """Seal every completed archive day that is not sealed yet.

    Today's file is never sealed: it is still being appended to. The caller
    owns commit/rollback.
    """
    from .audit import log_action

    current = today or datetime.now(timezone.utc).date()
    sealed = await sealed_days(db)
    already = {entry["day"] for entry in sealed}
    previous_seal_digest = sealed[-1]["content_digest"] if sealed else None

    candidates = sorted(
        {
            day
            for day in (
                _day_of(path)
                for path in audit_dir.glob("audit-*.jsonl*")
                if not path.name.endswith(".tmp")
            )
            if day is not None and day < current and day not in already
        }
    )[:max_days]

    created: list[str] = []
    refused: list[dict[str, str]] = []
    for day in candidates:
        lines = read_archive_lines(audit_dir, day)
        if not lines:
            continue
        try:
            _cross_check(day, lines, await _database_window(db, day))
        except ArchiveSealError as error:
            # Loud, and NOT sealed: an unsealed day can never become prunable,
            # so a lost archive entry costs visibility rather than evidence.
            log.error("audit archive seal refused: %s", error)
            try:
                from .metrics import audit_archive_seal_refusals

                audit_archive_seal_refusals.inc()
            except Exception:
                pass
            refused.append({"day": day.isoformat(), "reason": str(error)})
            continue
        detail = seal_detail(day, lines, previous_seal_digest=previous_seal_digest)
        attested_by_audit_id = await log_action(
            db,
            actor=actor,
            action=SEAL_ACTION,
            target=detail["file_name"],
            detail=detail,
            critical=False,
        )
        # ALSO persisted outside the chain. The chain event proves the seal was
        # not fabricated after the fact; this row is what survives a prune,
        # because the chain can only be pruned contiguously and would take the
        # seal with the rows it attests.
        await db.execute(
            text("""
                INSERT INTO vault_audit_archive_seals
                    (day, file_name, entry_count, content_digest,
                     first_signature, last_signature, previous_seal_digest,
                     attested_by_audit_id)
                VALUES (:day, :file_name, :entry_count, :content_digest,
                        :first_signature, :last_signature, :previous_seal_digest,
                        CAST(:attested_by_audit_id AS uuid))
                ON CONFLICT (day) DO NOTHING
            """),
            {
                "day": day,
                "file_name": detail["file_name"],
                "entry_count": detail["entry_count"],
                "content_digest": detail["content_digest"],
                "first_signature": detail["first_signature"],
                "last_signature": detail["last_signature"],
                "previous_seal_digest": detail["previous_seal_digest"],
                "attested_by_audit_id": attested_by_audit_id,
            },
        )
        previous_seal_digest = detail["content_digest"]
        created.append(day.isoformat())

    return {"sealed_days": created, "refused": refused}


def _day_of(path: Path) -> date | None:
    name = path.name
    if not name.startswith("audit-"):
        return None
    stem = name[len("audit-") :].split(".")[0]
    try:
        return date.fromisoformat(stem)
    except ValueError:
        return None


async def verify_archive_seals(db: AsyncSession, *, audit_dir: Path) -> dict[str, Any]:
    """Recompute every seal against the file it attests.

    Detects the three things per-entry signatures cannot: a truncated tail (the
    count and digest move), a modified file (the digest moves), and a deleted
    day (the seal exists with no file). Seals are chained, so removing an
    entire seal ROW breaks the chain that protects it.
    """
    sealed = await sealed_days(db)
    intact = 0
    problems: list[dict[str, str]] = []
    legacy_anchor_incomplete = False

    # The durable seal table is useful only if its rows remain tied to a
    # signed mutation event. Before pruning, compare every seal to its
    # surviving signed detail. After pruning, the signed prune row carries a
    # cumulative seal high-water mark for the deleted attestations.
    signed_rows = (
        await db.execute(
            text("""
                SELECT id, detail
                FROM vault_audit
                WHERE action = :action
                ORDER BY timestamp ASC, id ASC
            """),
            {"action": SEAL_ACTION},
        )
    ).fetchall()
    signed_by_day: dict[date, dict[str, Any]] = {}
    for row in signed_rows:
        parsed = parse_seal_detail(row.detail)
        if parsed is None:
            problems.append(
                {"day": "unknown", "problem": "malformed_signed_seal_detail"}
            )
            continue
        if parsed["day"] in signed_by_day:
            problems.append(
                {
                    "day": parsed["day"].isoformat(),
                    "problem": "duplicate_signed_seal_attestation",
                }
            )
            continue
        signed_by_day[parsed["day"]] = parsed

    prune_anchor = await latest_prune_anchor(db)
    pruned_through = (
        date.fromisoformat(str(prune_anchor["pruned_through_day"]))
        if prune_anchor and prune_anchor.get("pruned_through_day")
        else None
    )
    raw_archive_anchor = (
        prune_anchor.get("archive_seal_anchor") if prune_anchor else None
    )
    archive_anchor = parse_archive_prune_anchor(raw_archive_anchor)
    anchored_seals = (
        [entry for entry in sealed if entry["day"] <= pruned_through]
        if pruned_through is not None
        else []
    )
    if anchored_seals:
        if raw_archive_anchor is None:
            # A legacy prune did not commit the durable seal prefix. Files can
            # still be checked, but their database claims are not independently
            # tied to the surviving signed chain.
            legacy_anchor_incomplete = True
            problems.append(
                {
                    "day": pruned_through.isoformat(),
                    "problem": "legacy_prune_has_no_archive_seal_anchor",
                }
            )
        elif archive_anchor is None:
            problems.append(
                {
                    "day": pruned_through.isoformat(),
                    "problem": "malformed_archive_prune_anchor",
                }
            )
        elif (
            archive_anchor["seal_count"] != len(anchored_seals)
            or archive_anchor["head_day"] != anchored_seals[-1]["day"]
            or archive_anchor["head_digest"] != anchored_seals[-1]["content_digest"]
        ):
            problems.append(
                {
                    "day": pruned_through.isoformat(),
                    "problem": "archive_prune_anchor_mismatch",
                }
            )

    for entry in sealed:
        if pruned_through is not None and entry["day"] <= pruned_through:
            continue
        signed = signed_by_day.get(entry["day"])
        if signed is None or not _seal_detail_matches(entry, signed):
            problems.append(
                {
                    "day": entry["day"].isoformat(),
                    "problem": "signed_seal_attestation_mismatch",
                }
            )

    previous_digest: str | None = None
    for entry in sealed:
        if entry["previous_seal_digest"] != previous_digest:
            problems.append(
                {
                    "day": entry["day"].isoformat(),
                    "problem": "previous_seal_digest_mismatch",
                    "expected": previous_digest or "",
                    "found": entry["previous_seal_digest"] or "",
                }
            )
            previous_digest = entry["content_digest"]
            continue
        lines = read_archive_lines(audit_dir, entry["day"])
        if lines is None:
            problems.append(
                {"day": entry["day"].isoformat(), "problem": "archive_file_missing"}
            )
            previous_digest = entry["content_digest"]
            continue
        if len(lines) != entry["entry_count"]:
            problems.append(
                {
                    "day": entry["day"].isoformat(),
                    "problem": "entry_count_mismatch",
                    "sealed": str(entry["entry_count"]),
                    "found": str(len(lines)),
                }
            )
            previous_digest = entry["content_digest"]
            continue
        if archive_digest(lines) != entry["content_digest"]:
            problems.append(
                {"day": entry["day"].isoformat(), "problem": "content_digest_mismatch"}
            )
            previous_digest = entry["content_digest"]
            continue
        intact += 1
        previous_digest = entry["content_digest"]
    return {
        "archive_seals": len(sealed),
        "archive_intact": False
        if any(
            problem["problem"] != "legacy_prune_has_no_archive_seal_anchor"
            for problem in problems
        )
        else None
        if legacy_anchor_incomplete
        else True,
        "archive_verified_days": intact,
        "archive_problems": problems,
        "archive_head_day": sealed[-1]["day"].isoformat() if sealed else None,
        "archive_head_digest": sealed[-1]["content_digest"] if sealed else None,
    }


# --- pruning the chain without breaking verification ------------------------

PRUNE_ANCHOR_ACTION = "audit_chain_prune"
PRUNE_SCHEMA = "rhorizon.audit_chain_prune.v1"


async def latest_prune_anchor(db: AsyncSession) -> dict[str, Any] | None:
    """Where a chain walk must START, given everything pruned so far.

    ``None`` means nothing was ever pruned and verification begins at "" as it
    always has.
    """
    row = (
        await db.execute(
            text("""
                SELECT detail
                FROM vault_audit
                WHERE action = :action
                ORDER BY timestamp DESC, id DESC
                LIMIT 1
            """),
            {"action": PRUNE_ANCHOR_ACTION},
        )
    ).fetchone()
    if row is None or not isinstance(row.detail, dict):
        return None
    detail = row.detail
    if detail.get("schema") != PRUNE_SCHEMA:
        return None
    signature = detail.get("pruned_through_signature")
    if not isinstance(signature, str) or not signature:
        return None
    return {
        "pruned_through_signature": signature,
        "pruned_through_day": detail.get("pruned_through_day"),
        "pruned_row_count": detail.get("pruned_row_count"),
        "audit_lite_anchor": detail.get("audit_lite_anchor"),
        "archive_seal_anchor": detail.get("archive_seal_anchor"),
    }


def select_prunable_days(
    seals: dict[date, dict[str, Any]],
    *,
    audit_dir: Path,
    cutoff: date,
    already_pruned: date | None,
) -> list[date]:
    """Which days may leave the database, in order, stopping at the first that
    may not.

    Stopping rather than skipping is the whole safety property. The chain is
    order-dependent, so pruning around a gap would leave a hole that no anchor
    can describe -- verification would resume at the anchor and immediately
    meet a row that chains to something already deleted.

    A day qualifies only if it is past the retention cutoff, its archive file
    is present, and its seal still verifies against that file. The last two are
    what stop a truncated or edited archive being traded for the rows it was
    supposed to preserve.

    Pure apart from reading the archive, so the decision that governs
    irreversible deletion is testable without a database.
    """
    prunable: list[date] = []
    for day in sorted(seals):
        if already_pruned is not None and day <= already_pruned:
            continue
        if day >= cutoff:
            break
        lines = read_archive_lines(audit_dir, day)
        if lines is None:
            log.warning("prune stops at %s: archive file missing", day)
            break
        entry = seals[day]
        if len(lines) != entry["entry_count"]:
            log.error(
                "prune stops at %s: archive holds %d entries, seal says %d",
                day,
                len(lines),
                entry["entry_count"],
            )
            break
        if archive_digest(lines) != entry["content_digest"]:
            log.error("prune stops at %s: archive content digest changed", day)
            break
        prunable.append(day)
    return prunable


async def prune_archived_audit_rows(
    db: AsyncSession,
    *,
    audit_dir: Path,
    retention_days: int,
    today: date | None = None,
    actor: str = "reaper",
) -> dict[str, Any]:
    """Delete chain rows whose archive day is sealed, verified, and expired.

    Three conditions, all required, and each removes a distinct way to destroy
    evidence:

      * older than ``retention_days`` -- policy;
      * the day is SEALED -- the archive provably held every row when both
        copies still existed;
      * the seal VERIFIES right now -- the archive still holds them, so the
        file was not truncated or edited in the meantime.

    Before deleting anything, an anchor is written into the chain recording the
    signature of the last pruned row. Verification then starts from that
    signature instead of "", which is what keeps the surviving chain
    verifiable. The anchor excuses exactly what it names and nothing more: if
    rows beyond it are also deleted, the first surviving row no longer chains
    to the anchor and the break is reported, so a prune cannot be used to hide
    a deletion.

    Days must be prunable CONTIGUOUSLY from the oldest -- the chain is
    order-dependent, so a hole in the middle is not something an anchor can
    describe.

    The caller owns commit/rollback.
    """
    from .audit import log_action

    current = today or datetime.now(timezone.utc).date()
    cutoff = current - timedelta(days=max(1, retention_days))
    seals = {entry["day"]: entry for entry in await sealed_days(db)}
    if not seals:
        return {"pruned_rows": 0, "pruned_through_day": None, "reason": "no_seals"}

    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext('rhorizon:audit_retention'))")
    )

    anchor = await latest_prune_anchor(db)
    already_pruned = (
        date.fromisoformat(anchor["pruned_through_day"])
        if anchor and anchor.get("pruned_through_day")
        else None
    )

    prunable = select_prunable_days(
        seals, audit_dir=audit_dir, cutoff=cutoff, already_pruned=already_pruned
    )

    if not prunable:
        return {"pruned_rows": 0, "pruned_through_day": None, "reason": "nothing_due"}

    last_day = prunable[-1]
    boundary = datetime.combine(
        last_day + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc
    )
    last_signature = seals[last_day]["last_signature"]
    sealed_prefix = [seals[day] for day in sorted(seals) if day <= last_day]
    archive_seal_anchor = {
        "schema": ARCHIVE_PRUNE_ANCHOR_SCHEMA,
        "seal_count": len(sealed_prefix),
        "head_day": sealed_prefix[-1]["day"].isoformat(),
        "head_digest": sealed_prefix[-1]["content_digest"],
    }

    from .audit_mtree import build_lite_prune_anchor

    try:
        lite_anchor = await build_lite_prune_anchor(db, boundary=boundary)
    except RuntimeError as error:
        log.error("prune refused: %s", error)
        return {
            "pruned_rows": 0,
            "pruned_through_day": None,
            "reason": "audit_lite_not_intact",
        }

    doomed = (
        await db.execute(
            text("SELECT count(*) AS n FROM vault_audit WHERE timestamp < :boundary"),
            {"boundary": boundary},
        )
    ).fetchone()
    doomed_count = int(doomed.n) if doomed else 0
    if doomed_count == 0:
        return {"pruned_rows": 0, "pruned_through_day": None, "reason": "nothing_due"}

    # The DELETE is a contiguous timestamp prefix, so the archive proof must
    # cover exactly that same number of rows. Merely iterating the seals would
    # miss a database day for which no archive file/seal exists and could then
    # delete its only copy as collateral between two sealed days.
    archived_row_count = sum(int(seals[day]["entry_count"]) for day in prunable)
    if doomed_count != archived_row_count:
        log.error(
            "prune refused: database prefix has %d row(s), selected archive "
            "days attest %d",
            doomed_count,
            archived_row_count,
        )
        return {
            "pruned_rows": 0,
            "pruned_through_day": None,
            "reason": "archive_row_count_mismatch",
            "database_rows": doomed_count,
            "archive_rows": archived_row_count,
        }

    integrity = await _verify_prunable_prefix(
        db,
        boundary=boundary,
        start_signature=(
            anchor["pruned_through_signature"] if anchor is not None else ""
        ),
        expected_last_signature=last_signature,
    )
    if integrity["intact"] is not True:
        log.error(
            "prune refused: archived database prefix is not intact: %s", integrity
        )
        return {
            "pruned_rows": 0,
            "pruned_through_day": None,
            "reason": "audit_prefix_not_intact",
            "integrity": integrity,
        }

    previous_lite = None
    if lite_anchor is not None:
        from .audit_lite_archive import archive_lite_prefix, parse_prune_anchor

        previous_lite = parse_prune_anchor(
            anchor.get("audit_lite_anchor") if anchor else None
        )
        # A v1 anchor still has its raw rows in PostgreSQL. The first v2 export
        # therefore includes that prefix and replaces it with an archive seal.
        lite_anchor = await archive_lite_prefix(
            db,
            audit_dir=audit_dir,
            last_checkpoint_id=lite_anchor["last_checkpoint_id"],
            to_timestamp=datetime.fromisoformat(
                str(lite_anchor["to_timestamp"]).replace("Z", "+00:00")
            ),
            to_id=lite_anchor["to_id"],
            checkpoint_count=int(lite_anchor["checkpoint_count"]),
            head_root=str(lite_anchor["head_root"]),
            previous_anchor=previous_lite,
            actor=actor,
        )

    # Anchor FIRST, in the same transaction as the delete. Written after the
    # rows it describes, so it survives the delete below (its own timestamp is
    # now), and a crash between the two leaves either both or neither.
    new_anchor_id = await log_action(
        db,
        actor=actor,
        action=PRUNE_ANCHOR_ACTION,
        target="vault_audit",
        detail={
            "schema": PRUNE_SCHEMA,
            "pruned_through_day": last_day.isoformat(),
            "pruned_through_signature": last_signature,
            "pruned_row_count": doomed_count,
            "pruned_days": [day.isoformat() for day in prunable],
            "retention_days": retention_days,
            "audit_lite_anchor": lite_anchor,
            "archive_seal_anchor": archive_seal_anchor,
        },
        critical=False,
    )
    # Preserve exactly the anchor created by this transaction. Older prune
    # anchors inside the newly archived prefix must be deleted with that
    # prefix: the new anchor already commits their signatures through
    # `last_signature`. Keeping an old anchor would make a later verifier
    # consume it twice -- once through the new starting signature and once as
    # a surviving row -- and report a false chain break. Selecting by id also
    # protects the new row under clock skew or deliberately future-dated tests.
    await db.execute(
        text(
            "DELETE FROM vault_audit "
            "WHERE timestamp < :boundary AND id <> CAST(:new_anchor_id AS uuid)"
        ),
        {"boundary": boundary, "new_anchor_id": new_anchor_id},
    )
    log.info(
        "Pruned %d audit chain row(s) through %s; verification now anchors at "
        "the sealed archive",
        doomed_count,
        last_day.isoformat(),
    )
    return {
        "pruned_rows": doomed_count,
        "pruned_lite_rows": (
            lite_anchor["checkpointed_row_count"]
            - (previous_lite["checkpointed_row_count"] if previous_lite else 0)
        )
        if lite_anchor is not None
        else 0,
        "pruned_through_day": last_day.isoformat(),
        "pruned_through_signature": last_signature,
        "pruned_days": [day.isoformat() for day in prunable],
    }


async def _verify_prunable_prefix(
    db: AsyncSession,
    *,
    boundary: datetime,
    start_signature: str,
    expected_last_signature: str,
) -> dict[str, Any]:
    """Verify every signed row before its database copy may be deleted.

    Archive seals prove completeness and pin file bytes. This pass proves that
    those bytes originate from the authenticated mutation chain rather than a
    modified database prefix that happened to be sealed before a full verify.
    It runs only in the background retention path and streams rows, so request
    latency and worker memory remain bounded.
    """
    from .key_epoch import get_key_epoch
    from .routes.audit import (
        _load_audit_keyring_via_vault,
        _load_signer_pubs,
        _row_verified,
    )
    from .vault_state import vault

    if vault.sealed:
        return {"intact": None, "reason": "vault_sealed", "verified_rows": 0}

    signer_pubs = await _load_signer_pubs(db)
    keyring = await _load_audit_keyring_via_vault(db)
    current_epoch = await get_key_epoch(db)
    rows = await db.stream(
        text("""
            SELECT id, timestamp, actor, action, target, detail,
                   ip_address, signature, key_epoch, sig_alg, signer_fpr,
                   payload_version
            FROM vault_audit
            WHERE timestamp < :boundary
            ORDER BY timestamp ASC, id ASC
        """).execution_options(yield_per=512),
        {"boundary": boundary},
    )
    previous = start_signature
    verified_rows = 0
    try:
        async for row in rows:
            if row.signature == "unsigned":
                return {
                    "intact": False,
                    "reason": "unsigned_row",
                    "broken_id": str(row.id),
                    "verified_rows": verified_rows,
                }
            if not await _row_verified(
                row,
                previous,
                sealed=False,
                current_epoch=current_epoch,
                keyring=keyring,
                signer_pubs=signer_pubs,
            ):
                return {
                    "intact": False,
                    "reason": "signature_mismatch",
                    "broken_id": str(row.id),
                    "verified_rows": verified_rows,
                }
            previous = row.signature
            verified_rows += 1
            if verified_rows % 256 == 0:
                await asyncio.sleep(0)
    finally:
        await rows.close()

    if previous != expected_last_signature:
        return {
            "intact": False,
            "reason": "archive_boundary_signature_mismatch",
            "expected_last_signature": expected_last_signature,
            "actual_last_signature": previous,
            "verified_rows": verified_rows,
        }
    return {"intact": True, "reason": None, "verified_rows": verified_rows}
