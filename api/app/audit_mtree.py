# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Merkle checkpoints for the high-volume read audit table.

`vault_audit_lite` deliberately has no per-row signature so read paths do not
serialize on the mutation audit chain. This module periodically hashes ordered
windows of read rows and writes one signed `vault_audit` checkpoint, giving
operators tamper-evidence for historical reads without changing the lite table.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings

CHECKPOINT_ACTION = "audit_lite_checkpoint"
CHECKPOINT_SCHEMA = "rhorizon.audit_lite_checkpoint.v1"
ROOT_ALG = "sha256-merkle-v1"
LEAF_ALG = "sha256-canonical-json-v1"
LITE_PRUNE_ANCHOR_SCHEMA = "rhorizon.audit_lite_prune_anchor.v1"

_LEAF_PREFIX = b"rhorizon:audit_lite:leaf:v1\0"
_NODE_PREFIX = b"rhorizon:audit_lite:node:v1\0"
_EMPTY_PREFIX = b"rhorizon:audit_lite:empty:v1\0"
_ROOT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_LITE_COLUMNS = "id, timestamp, actor, action, target, detail, ip_address"


def _utc_iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_iso(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _uuid_text(value: Any) -> str:
    return str(UUID(str(value)))


def _json_detail(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("audit-lite detail must be a JSON object")
    return value


def canonical_lite_row(row: Any) -> bytes:
    """Return the stable byte representation covered by a read-audit leaf."""
    payload = {
        "id": str(row.id),
        "timestamp": _utc_iso(row.timestamp),
        "actor": row.actor,
        "action": row.action,
        "target": row.target,
        "detail": _json_detail(row.detail),
        "ip_address": row.ip_address,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def audit_lite_leaf_hash(row: Any) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + canonical_lite_row(row)).digest()


def audit_lite_merkle_root(rows: list[Any]) -> str:
    """Compute a deterministic SHA-256 Merkle root for ordered read rows.

    Odd levels duplicate the final node. Leaves and internal nodes use distinct
    domain prefixes so a leaf hash cannot be replayed as an internal node.
    """
    if not rows:
        return "sha256:" + hashlib.sha256(_EMPTY_PREFIX).hexdigest()

    level = [audit_lite_leaf_hash(row) for row in rows]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(_NODE_PREFIX + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return "sha256:" + level[0].hex()


class _MerkleFrontier:
    """Streaming equivalent of :func:`audit_lite_merkle_root`."""

    def __init__(self) -> None:
        self._levels: list[bytes | None] = []
        self.count = 0

    def add(self, leaf: bytes) -> None:
        node = leaf
        level = 0
        self.count += 1
        while True:
            if level == len(self._levels):
                self._levels.append(node)
                return
            left = self._levels[level]
            if left is None:
                self._levels[level] = node
                return
            self._levels[level] = None
            node = hashlib.sha256(_NODE_PREFIX + left + node).digest()
            level += 1

    def root(self) -> str:
        if self.count == 0:
            return "sha256:" + hashlib.sha256(_EMPTY_PREFIX).hexdigest()
        right: bytes | None = None
        right_level = 0
        for level, left in enumerate(self._levels):
            if left is None:
                continue
            if right is None:
                right = left
                right_level = level
                continue
            while right_level < level:
                right = hashlib.sha256(_NODE_PREFIX + right + right).digest()
                right_level += 1
            right = hashlib.sha256(_NODE_PREFIX + left + right).digest()
            right_level = level + 1
        assert right is not None
        return "sha256:" + right.hex()


def checkpoint_detail(
    rows: list[Any],
    *,
    previous_checkpoint_id: str | None,
) -> dict[str, Any]:
    if not rows:
        raise ValueError("cannot checkpoint an empty audit-lite window")
    first = rows[0]
    last = rows[-1]
    return {
        "schema": CHECKPOINT_SCHEMA,
        "root_alg": ROOT_ALG,
        "leaf_alg": LEAF_ALG,
        "row_order": "timestamp_asc_id_asc",
        "from_timestamp": _utc_iso(first.timestamp),
        "from_id": str(first.id),
        "to_timestamp": _utc_iso(last.timestamp),
        "to_id": str(last.id),
        "row_count": len(rows),
        "merkle_root": audit_lite_merkle_root(rows),
        "previous_checkpoint_id": previous_checkpoint_id,
    }


def parse_checkpoint_detail(detail: Any) -> dict[str, Any] | None:
    if not isinstance(detail, dict) or detail.get("schema") != CHECKPOINT_SCHEMA:
        return None
    try:
        row_count = int(detail["row_count"])
        root = str(detail["merkle_root"])
        previous = detail.get("previous_checkpoint_id")
        parsed = {
            "from_timestamp": _parse_utc_iso(str(detail["from_timestamp"])),
            "from_id": _uuid_text(detail["from_id"]),
            "to_timestamp": _parse_utc_iso(str(detail["to_timestamp"])),
            "to_id": _uuid_text(detail["to_id"]),
            "row_count": row_count,
            "merkle_root": root,
            "previous_checkpoint_id": None
            if previous is None
            else _uuid_text(previous),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if row_count < 1 or not _ROOT_RE.match(root):
        return None
    return parsed


async def _last_checkpoint(db: AsyncSession) -> dict[str, Any] | None:
    result = await db.execute(
        text("""
            SELECT id, detail
            FROM vault_audit
            WHERE action = :action
            ORDER BY timestamp DESC, id DESC
            LIMIT 50
        """),
        {"action": CHECKPOINT_ACTION},
    )
    for row in result.fetchall():
        detail = parse_checkpoint_detail(row.detail)
        if detail is not None:
            return {"audit_id": str(row.id), "detail": detail}
    # Main-chain pruning removes old checkpoint rows. The signed prune anchor
    # carries their last id and high-water mark so the next checkpoint must
    # continue that lineage rather than silently starting a second genesis.
    from .audit_archive import latest_prune_anchor

    prune_anchor = await latest_prune_anchor(db)
    raw = prune_anchor.get("audit_lite_anchor") if prune_anchor else None
    if raw is None:
        return None
    anchor = parse_lite_prune_anchor(raw)
    if anchor is None:
        raise RuntimeError("stored audit-lite prune anchor is malformed")
    return {
        "audit_id": anchor["last_checkpoint_id"],
        "detail": {
            "to_timestamp": anchor["to_timestamp"],
            "to_id": anchor["to_id"],
        },
    }


async def _fetch_lite_after(
    db: AsyncSession,
    *,
    after: dict[str, Any] | None,
    limit: int,
) -> list[Any]:
    params: dict[str, Any] = {"limit": limit}
    where = ""
    if after is not None:
        where = "WHERE (timestamp, id) > (:after_ts, CAST(:after_id AS uuid))"
        params.update(
            {
                "after_ts": after["to_timestamp"],
                "after_id": after["to_id"],
            }
        )
    result = await db.execute(
        text(f"""
            SELECT {_LITE_COLUMNS}
            FROM vault_audit_lite
            {where}
            ORDER BY timestamp ASC, id ASC
            LIMIT :limit
        """),
        params,
    )
    return list(result.fetchall())


async def _fetch_lite_window(
    db: AsyncSession,
    *,
    from_ts: datetime,
    from_id: str,
    to_ts: datetime,
    to_id: str,
) -> list[Any]:
    result = await db.execute(
        text(f"""
            SELECT {_LITE_COLUMNS}
            FROM vault_audit_lite
            WHERE (timestamp, id) >= (:from_ts, CAST(:from_id AS uuid))
              AND (timestamp, id) <= (:to_ts, CAST(:to_id AS uuid))
            ORDER BY timestamp ASC, id ASC
        """),
        {
            "from_ts": from_ts,
            "from_id": from_id,
            "to_ts": to_ts,
            "to_id": to_id,
        },
    )
    return list(result.fetchall())


async def _count_lite(db: AsyncSession) -> int:
    result = await db.execute(text("SELECT count(*) FROM vault_audit_lite"))
    return int(result.scalar() or 0)


async def _count_lite_through(
    db: AsyncSession,
    *,
    to_ts: datetime,
    to_id: str,
) -> int:
    result = await db.execute(
        text("""
            SELECT count(*)
            FROM vault_audit_lite
            WHERE (timestamp, id) <= (:to_ts, CAST(:to_id AS uuid))
        """),
        {"to_ts": to_ts, "to_id": to_id},
    )
    return int(result.scalar() or 0)


async def _count_lite_after(
    db: AsyncSession,
    *,
    to_ts: datetime,
    to_id: str,
) -> int:
    result = await db.execute(
        text("""
            SELECT count(*)
            FROM vault_audit_lite
            WHERE (timestamp, id) > (:to_ts, CAST(:to_id AS uuid))
        """),
        {"to_ts": to_ts, "to_id": to_id},
    )
    return int(result.scalar() or 0)


async def _lite_prefix_commitment(
    db: AsyncSession,
    *,
    to_ts: datetime,
    to_id: str,
) -> tuple[int, str]:
    """Stream and commit every retained lite row through a high-water mark."""
    rows = await db.stream(
        text(f"""
            SELECT {_LITE_COLUMNS}
            FROM vault_audit_lite
            WHERE (timestamp, id) <= (:to_ts, CAST(:to_id AS uuid))
            ORDER BY timestamp ASC, id ASC
        """).execution_options(yield_per=512),
        {"to_ts": to_ts, "to_id": to_id},
    )
    frontier = _MerkleFrontier()
    try:
        async for row in rows:
            frontier.add(audit_lite_leaf_hash(row))
            if frontier.count % 2048 == 0:
                import asyncio

                await asyncio.sleep(0)
    finally:
        await rows.close()
    return frontier.count, frontier.root()


def parse_lite_prune_anchor(detail: Any) -> dict[str, Any] | None:
    if isinstance(detail, dict) and detail.get("schema") == (
        "rhorizon.audit_lite_prune_anchor.v2"
    ):
        from .audit_lite_archive import parse_prune_anchor

        return parse_prune_anchor(detail)
    if not isinstance(detail, dict) or detail.get("schema") != LITE_PRUNE_ANCHOR_SCHEMA:
        return None
    try:
        parsed = {
            "last_checkpoint_id": _uuid_text(detail["last_checkpoint_id"]),
            "to_timestamp": _parse_utc_iso(str(detail["to_timestamp"])),
            "to_id": _uuid_text(detail["to_id"]),
            "checkpoint_count": int(detail["checkpoint_count"]),
            "checkpointed_row_count": int(detail["checkpointed_row_count"]),
            "cumulative_merkle_root": str(detail["cumulative_merkle_root"]),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if (
        parsed["checkpoint_count"] < 1
        or parsed["checkpointed_row_count"] < 1
        or not _ROOT_RE.match(parsed["cumulative_merkle_root"])
    ):
        return None
    return parsed


async def build_lite_prune_anchor(
    db: AsyncSession,
    *,
    boundary: datetime,
) -> dict[str, Any] | None:
    """Commit checkpoint ancestry that the main-chain prune will delete."""
    from .audit_archive import latest_prune_anchor

    previous = await latest_prune_anchor(db)
    previous_raw = previous.get("audit_lite_anchor") if previous else None
    previous_lite = parse_lite_prune_anchor(previous_raw)
    if previous_raw is not None and previous_lite is None:
        raise RuntimeError("existing audit-lite prune anchor is malformed")

    doomed = (
        await db.execute(
            text("""
                SELECT id, detail
                FROM vault_audit
                WHERE action = :action AND timestamp < :boundary
                ORDER BY timestamp ASC, id ASC
            """),
            {"action": CHECKPOINT_ACTION, "boundary": boundary},
        )
    ).fetchall()
    if not doomed:
        # The new main-chain anchor supersedes the previous one. Carry the
        # cumulative lite commitment forward even when this retention interval
        # contains no newly pruned checkpoint, otherwise the latest anchor
        # would silently forget all previously anchored read evidence.
        return previous_raw

    status = await verify_audit_lite_checkpoints(db)
    if status.get("audit_lite_intact") is not True:
        raise RuntimeError(
            "audit-lite checkpoints are not intact; refusing to anchor their prune"
        )

    last = doomed[-1]
    last_detail = parse_checkpoint_detail(last.detail)
    if last_detail is None:
        raise RuntimeError("latest pruned audit-lite checkpoint is malformed")
    previous_checkpoints = previous_lite["checkpoint_count"] if previous_lite else 0
    if previous_lite is not None and "archive_seal_count" in previous_lite:
        live_rows = await _count_lite_through(
            db,
            to_ts=last_detail["to_timestamp"],
            to_id=last_detail["to_id"],
        )
        return {
            **previous_raw,
            "last_checkpoint_id": str(last.id),
            "to_timestamp": _utc_iso(last_detail["to_timestamp"]),
            "to_id": last_detail["to_id"],
            "checkpoint_count": previous_checkpoints + len(doomed),
            "checkpointed_row_count": (
                previous_lite["checkpointed_row_count"] + live_rows
            ),
            "head_root": last_detail["merkle_root"],
        }

    row_count, root = await _lite_prefix_commitment(
        db,
        to_ts=last_detail["to_timestamp"],
        to_id=last_detail["to_id"],
    )
    return {
        "schema": LITE_PRUNE_ANCHOR_SCHEMA,
        "last_checkpoint_id": str(last.id),
        "to_timestamp": _utc_iso(last_detail["to_timestamp"]),
        "to_id": last_detail["to_id"],
        "checkpoint_count": previous_checkpoints + len(doomed),
        "checkpointed_row_count": row_count,
        "cumulative_merkle_root": root,
        "head_root": last_detail["merkle_root"],
    }


async def create_audit_lite_checkpoint(
    db: AsyncSession,
    *,
    actor: str = "audit-mtree",
    max_rows: int | None = None,
) -> dict[str, Any]:
    """Create one signed checkpoint for the next audit-lite window.

    The caller owns commit/rollback. Returns a small status dict so background
    loops and tests can distinguish "nothing to checkpoint" from a write.
    """
    from .audit import log_action

    limit = int(max_rows or settings.audit_lite_checkpoint_max_rows)
    if limit < 1:
        return {"created": False, "row_count": 0}

    # Freeze the append-only table before choosing the closed checkpoint
    # window. INSERT holds ROW EXCLUSIVE until commit; SHARE waits for every
    # in-flight insert and prevents a new one from receiving its default
    # clock_timestamp() until this transaction commits. Without this barrier,
    # an uncommitted row can already have timestamp T while a later row at
    # T+1 commits and is checkpointed. When the first row finally commits it
    # lands inside the signed window and causes a false row_count_mismatch.
    #
    # SHARE remains compatible with readers, and checkpointing is already a
    # cluster-wide singleton, so the only pause is a short INSERT pause while
    # at most `limit` rows are hashed and the checkpoint is signed.
    await db.execute(text("LOCK TABLE vault_audit_lite IN SHARE MODE"))

    last = await _last_checkpoint(db)
    after = last["detail"] if last else None
    rows = await _fetch_lite_after(db, after=after, limit=limit)
    if not rows:
        return {"created": False, "row_count": 0}

    detail = checkpoint_detail(
        rows,
        previous_checkpoint_id=last["audit_id"] if last else None,
    )
    await log_action(
        db,
        actor=actor,
        action=CHECKPOINT_ACTION,
        target="vault_audit_lite",
        detail=detail,
        critical=False,
    )
    return {
        "created": True,
        "row_count": len(rows),
        "from_id": detail["from_id"],
        "to_id": detail["to_id"],
        "merkle_root": detail["merkle_root"],
    }


def _lite_status(
    *,
    intact: bool | None,
    checkpoints: int,
    checkpointed_rows: int,
    uncheckpointed_rows: int | None,
    broken_checkpoint_id: str | None = None,
    reason: str | None = None,
    detail: dict[str, Any] | None = None,
    anchored_checkpoints: int = 0,
    anchored_rows: int = 0,
    total_rows: int | None = None,
    head_checkpoint_id: str | None = None,
    head_timestamp: str | None = None,
    head_id: str | None = None,
    head_root: str | None = None,
    new_checkpoints_verified: int | None = None,
    new_rows_verified: int | None = None,
    historical_rows_not_reread: int | None = None,
    archived_rows: int = 0,
) -> dict[str, Any]:
    return {
        "audit_lite_intact": intact,
        "audit_lite_checkpoints": checkpoints,
        "audit_lite_checkpointed_rows": checkpointed_rows,
        "audit_lite_uncheckpointed_rows": uncheckpointed_rows,
        "audit_lite_broken_checkpoint_id": broken_checkpoint_id,
        "audit_lite_broken_reason": reason,
        "audit_lite_broken_detail": detail or {},
        "audit_lite_anchored_checkpoints": anchored_checkpoints,
        "audit_lite_anchored_rows": anchored_rows,
        "audit_lite_total_rows": total_rows,
        "audit_lite_head_checkpoint_id": head_checkpoint_id,
        "audit_lite_head_timestamp": head_timestamp,
        "audit_lite_head_id": head_id,
        "audit_lite_head_root": head_root,
        "audit_lite_new_checkpoints_verified": new_checkpoints_verified,
        "audit_lite_new_rows_verified": new_rows_verified,
        "audit_lite_historical_rows_not_reread": historical_rows_not_reread,
        "audit_lite_archived_rows": archived_rows,
    }


async def verify_audit_lite_checkpoints(db: AsyncSession) -> dict[str, Any]:
    """Recompute all signed read-audit checkpoints.

    This must be called only after the surrounding `vault_audit` chain has been
    verified, because checkpoint details are trusted through that chain.
    """
    checkpoint_rows = (
        await db.execute(
            text("""
                SELECT id, timestamp, detail
                FROM vault_audit
                WHERE action = :action
                ORDER BY timestamp ASC, id ASC
            """),
            {"action": CHECKPOINT_ACTION},
        )
    ).fetchall()

    from .audit_archive import latest_prune_anchor

    prune_anchor = await latest_prune_anchor(db)
    raw_lite_anchor = prune_anchor.get("audit_lite_anchor") if prune_anchor else None
    lite_anchor = parse_lite_prune_anchor(raw_lite_anchor)
    if raw_lite_anchor is not None and lite_anchor is None:
        return _lite_status(
            intact=False,
            checkpoints=len(checkpoint_rows),
            checkpointed_rows=0,
            uncheckpointed_rows=None,
            reason="malformed_lite_prune_anchor",
        )

    live_lite_rows = await _count_lite(db)
    total_lite_rows = live_lite_rows
    if not checkpoint_rows and lite_anchor is None:
        return _lite_status(
            intact=True,
            checkpoints=0,
            checkpointed_rows=0,
            uncheckpointed_rows=total_lite_rows,
            total_rows=total_lite_rows,
        )

    checkpointed_rows = 0
    previous_checkpoint_id: str | None = None
    last_detail: dict[str, Any] | None = None
    anchored_checkpoints = 0
    anchored_rows = 0
    archived_anchored_rows = 0
    if lite_anchor is not None:
        anchored_checkpoints = lite_anchor["checkpoint_count"]
        if "archive_seal_count" in lite_anchor:
            from .audit import _audit_dir
            from .audit_lite_archive import verify_lite_archives

            archived = await verify_lite_archives(
                db, audit_dir=_audit_dir(), prune_anchor=lite_anchor
            )
            if archived["intact"] is not True:
                return _lite_status(
                    intact=False,
                    checkpoints=anchored_checkpoints + len(checkpoint_rows),
                    checkpointed_rows=0,
                    uncheckpointed_rows=None,
                    reason="audit_lite_archive_broken",
                    detail={"problems": archived["problems"]},
                    anchored_checkpoints=anchored_checkpoints,
                )
            anchored_rows = int(archived["rows"])
            archived_anchored_rows = anchored_rows
            anchored_root = None
            total_lite_rows += anchored_rows
        else:
            try:
                anchored_rows, anchored_root = await _lite_prefix_commitment(
                    db,
                    to_ts=lite_anchor["to_timestamp"],
                    to_id=lite_anchor["to_id"],
                )
            except ValueError as error:
                return _lite_status(
                    intact=False,
                    checkpoints=anchored_checkpoints + len(checkpoint_rows),
                    checkpointed_rows=0,
                    uncheckpointed_rows=None,
                    reason="invalid_lite_detail",
                    detail={"error": str(error)},
                    anchored_checkpoints=anchored_checkpoints,
                )
        if anchored_rows != lite_anchor["checkpointed_row_count"]:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_rows,
                uncheckpointed_rows=None,
                reason="lite_prune_anchor_row_count_mismatch",
                detail={
                    "expected_rows": lite_anchor["checkpointed_row_count"],
                    "actual_rows": anchored_rows,
                },
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )
        if (
            "cumulative_merkle_root" in lite_anchor
            and anchored_root != lite_anchor["cumulative_merkle_root"]
        ):
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_rows,
                uncheckpointed_rows=None,
                reason="lite_prune_anchor_root_mismatch",
                detail={
                    "expected_merkle_root": lite_anchor["cumulative_merkle_root"],
                    "actual_merkle_root": anchored_root,
                },
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )
        checkpointed_rows = anchored_rows
        previous_checkpoint_id = lite_anchor["last_checkpoint_id"]
        last_detail = {
            "to_timestamp": lite_anchor["to_timestamp"],
            "to_id": lite_anchor["to_id"],
            "merkle_root": lite_anchor.get(
                "head_root", lite_anchor.get("cumulative_merkle_root")
            ),
        }

    for idx, row in enumerate(checkpoint_rows, start=1):
        checkpoint_id = str(row.id)
        detail = parse_checkpoint_detail(row.detail)
        if detail is None:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=checkpointed_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="malformed_checkpoint_detail",
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )
        if detail["previous_checkpoint_id"] != previous_checkpoint_id:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=checkpointed_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="previous_checkpoint_mismatch",
                detail={
                    "expected_previous_checkpoint_id": previous_checkpoint_id,
                    "actual_previous_checkpoint_id": detail["previous_checkpoint_id"],
                },
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )

        rows = await _fetch_lite_window(
            db,
            from_ts=detail["from_timestamp"],
            from_id=detail["from_id"],
            to_ts=detail["to_timestamp"],
            to_id=detail["to_id"],
        )
        if len(rows) != detail["row_count"]:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=checkpointed_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="row_count_mismatch",
                detail={
                    "checkpoint_index": idx,
                    "expected_rows": detail["row_count"],
                    "actual_rows": len(rows),
                },
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )

        try:
            root = audit_lite_merkle_root(rows)
        except ValueError as error:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=checkpointed_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="invalid_lite_detail",
                detail={"checkpoint_index": idx, "error": str(error)},
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )
        if root != detail["merkle_root"]:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=checkpointed_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="merkle_root_mismatch",
                detail={
                    "checkpoint_index": idx,
                    "expected_merkle_root": detail["merkle_root"],
                    "actual_merkle_root": root,
                },
                anchored_checkpoints=anchored_checkpoints,
                anchored_rows=anchored_rows,
            )

        checkpointed_rows += len(rows)
        previous_checkpoint_id = checkpoint_id
        last_detail = detail

    assert last_detail is not None
    covered_rows = await _count_lite_through(
        db,
        to_ts=last_detail["to_timestamp"],
        to_id=last_detail["to_id"],
    )
    if covered_rows + archived_anchored_rows != checkpointed_rows:
        return _lite_status(
            intact=False,
            checkpoints=anchored_checkpoints + len(checkpoint_rows),
            checkpointed_rows=checkpointed_rows,
            uncheckpointed_rows=None,
            broken_checkpoint_id=previous_checkpoint_id,
            reason="checkpoint_gap_or_backdated_row",
            detail={
                "checkpointed_rows": checkpointed_rows,
                "rows_through_last_checkpoint": (covered_rows + archived_anchored_rows),
            },
            anchored_checkpoints=anchored_checkpoints,
            anchored_rows=anchored_rows,
        )

    uncheckpointed_rows = await _count_lite_after(
        db,
        to_ts=last_detail["to_timestamp"],
        to_id=last_detail["to_id"],
    )
    return _lite_status(
        intact=True,
        checkpoints=anchored_checkpoints + len(checkpoint_rows),
        checkpointed_rows=checkpointed_rows,
        uncheckpointed_rows=uncheckpointed_rows,
        anchored_checkpoints=anchored_checkpoints,
        anchored_rows=anchored_rows,
        total_rows=total_lite_rows,
        head_checkpoint_id=previous_checkpoint_id,
        head_timestamp=_utc_iso(last_detail["to_timestamp"]),
        head_id=last_detail["to_id"],
        head_root=last_detail["merkle_root"],
        archived_rows=archived_anchored_rows,
    )


async def verify_audit_lite_incremental(
    db: AsyncSession,
    *,
    anchor_lite: dict[str, Any],
    main_highwater_timestamp: datetime | None,
    main_highwater_id: str | None,
) -> dict[str, Any]:
    """Verify only checkpoint windows created after a signed full anchor.

    The anchor attests the historical prefix. Counts are still reconciled so a
    post-anchor insert/delete on the old side of the high-water mark cannot be
    hidden merely by leaving the new suffix untouched. A same-cardinality edit
    inside the historical prefix requires the scheduled full verifier, which
    is why callers must label this result incremental.
    """
    try:
        anchored_total = int(anchor_lite["row_count"])
        anchored_checkpointed = int(anchor_lite["checkpointed_rows"])
        anchored_checkpoints = int(anchor_lite["checkpoint_count"])
        previous_checkpoint_id = anchor_lite.get("head_checkpoint_id")
        previous_timestamp = (
            _parse_utc_iso(anchor_lite["highwater_timestamp"])
            if anchor_lite.get("highwater_timestamp") is not None
            else None
        )
        previous_id = (
            _uuid_text(anchor_lite["highwater_id"])
            if anchor_lite.get("highwater_id") is not None
            else None
        )
        head_root = anchor_lite.get("head_root")
        archived_rows = int(anchor_lite.get("archived_rows") or 0)
    except (KeyError, TypeError, ValueError):
        return _lite_status(
            intact=False,
            checkpoints=0,
            checkpointed_rows=0,
            uncheckpointed_rows=None,
            reason="invalid_verification_anchor_lite_state",
        )
    if (
        anchored_total < 0
        or anchored_checkpointed != anchored_total
        or anchored_checkpoints < 0
        or (previous_timestamp is None) != (previous_id is None)
        or (previous_checkpoint_id is None) != (previous_timestamp is None)
        or (head_root is None) != (previous_timestamp is None)
        or (head_root is not None and not _ROOT_RE.match(str(head_root)))
    ):
        return _lite_status(
            intact=False,
            checkpoints=anchored_checkpoints,
            checkpointed_rows=anchored_checkpointed,
            uncheckpointed_rows=None,
            reason="invalid_verification_anchor_lite_state",
        )

    if main_highwater_timestamp is None:
        checkpoint_where = ""
        params: dict[str, Any] = {"action": CHECKPOINT_ACTION}
    else:
        checkpoint_where = "AND (timestamp, id) > (:main_ts, CAST(:main_id AS uuid))"
        params = {
            "action": CHECKPOINT_ACTION,
            "main_ts": main_highwater_timestamp,
            "main_id": main_highwater_id,
        }
    checkpoint_rows = (
        await db.execute(
            text(f"""
                SELECT id, timestamp, detail
                FROM vault_audit
                WHERE action = :action {checkpoint_where}
                ORDER BY timestamp ASC, id ASC
            """),
            params,
        )
    ).fetchall()

    new_rows = 0
    for index, row in enumerate(checkpoint_rows, start=1):
        checkpoint_id = str(row.id)
        detail = parse_checkpoint_detail(row.detail)
        if detail is None:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_checkpointed + new_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="malformed_checkpoint_detail",
            )
        if detail["previous_checkpoint_id"] != previous_checkpoint_id:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_checkpointed + new_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="previous_checkpoint_mismatch",
                detail={
                    "checkpoint_index": index,
                    "expected_previous_checkpoint_id": previous_checkpoint_id,
                    "actual_previous_checkpoint_id": detail["previous_checkpoint_id"],
                },
            )
        if previous_timestamp is not None and (
            detail["from_timestamp"],
            detail["from_id"],
        ) <= (previous_timestamp, previous_id):
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_checkpointed + new_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="checkpoint_overlaps_verification_anchor",
            )
        rows = await _fetch_lite_window(
            db,
            from_ts=detail["from_timestamp"],
            from_id=detail["from_id"],
            to_ts=detail["to_timestamp"],
            to_id=detail["to_id"],
        )
        if len(rows) != detail["row_count"]:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_checkpointed + new_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="row_count_mismatch",
                detail={
                    "checkpoint_index": index,
                    "expected_rows": detail["row_count"],
                    "actual_rows": len(rows),
                },
            )
        try:
            root = audit_lite_merkle_root(rows)
        except ValueError as error:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_checkpointed + new_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="invalid_lite_detail",
                detail={"checkpoint_index": index, "error": str(error)},
            )
        if root != detail["merkle_root"]:
            return _lite_status(
                intact=False,
                checkpoints=anchored_checkpoints + len(checkpoint_rows),
                checkpointed_rows=anchored_checkpointed + new_rows,
                uncheckpointed_rows=None,
                broken_checkpoint_id=checkpoint_id,
                reason="merkle_root_mismatch",
                detail={
                    "checkpoint_index": index,
                    "expected_merkle_root": detail["merkle_root"],
                    "actual_merkle_root": root,
                },
            )
        new_rows += len(rows)
        previous_checkpoint_id = checkpoint_id
        previous_timestamp = detail["to_timestamp"]
        previous_id = detail["to_id"]
        head_root = detail["merkle_root"]

    total_rows = await _count_lite(db) + archived_rows
    if previous_timestamp is None:
        covered_rows = 0
        uncheckpointed_rows = total_rows
    else:
        covered_rows = await _count_lite_through(
            db, to_ts=previous_timestamp, to_id=previous_id
        )
        uncheckpointed_rows = await _count_lite_after(
            db, to_ts=previous_timestamp, to_id=previous_id
        )
    expected_covered = anchored_checkpointed + new_rows
    if (
        covered_rows + archived_rows != expected_covered
        or total_rows != covered_rows + uncheckpointed_rows
    ):
        return _lite_status(
            intact=False,
            checkpoints=anchored_checkpoints + len(checkpoint_rows),
            checkpointed_rows=expected_covered,
            uncheckpointed_rows=None,
            broken_checkpoint_id=previous_checkpoint_id,
            reason="historical_row_count_changed",
            detail={
                "anchored_rows": anchored_total,
                "expected_covered_rows": expected_covered,
                "actual_covered_rows": covered_rows,
                "total_rows": total_rows,
            },
        )

    return _lite_status(
        intact=True,
        checkpoints=anchored_checkpoints + len(checkpoint_rows),
        checkpointed_rows=expected_covered,
        uncheckpointed_rows=uncheckpointed_rows,
        anchored_checkpoints=anchored_checkpoints,
        anchored_rows=anchored_checkpointed,
        total_rows=total_rows,
        head_checkpoint_id=previous_checkpoint_id,
        head_timestamp=_utc_iso(previous_timestamp) if previous_timestamp else None,
        head_id=previous_id,
        head_root=head_root,
        new_checkpoints_verified=len(checkpoint_rows),
        new_rows_verified=new_rows,
        historical_rows_not_reread=anchored_total,
        archived_rows=archived_rows,
    )
