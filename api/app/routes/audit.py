# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Audit log - read-only, chained signature verification, file management."""

import asyncio
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from ..audit import _audit_dir, log_action, log_mcp_action
from ..audit_archive import latest_prune_anchor
from ..audit_keyring import load_audit_keyring
from ..audit_mtree import (
    verify_audit_lite_checkpoints,
    verify_audit_lite_incremental,
)
from ..audit_payload import audit_row_payload
from ..audit_verify_anchor import (
    LEGACY_ADOPTION_SCHEMA,
    legacy_unsigned_row_commitment,
    validate_legacy_adoption,
)
from ..auth import actor_display_name, require_permission, require_vault_token
from ..client_ip import get_client_ip
from ..cluster import get_hostname
from ..config import settings
from ..crypto import sign_audit, verify_audit_ed25519
from ..database import async_session, get_db
from ..key_epoch import get_key_epoch
from ..metrics import (
    audit_chain_breaks,
    audit_chain_length,
    audit_lite_checkpoint_breaks,
    audit_lite_length,
    audit_lite_uncheckpointed,
    audit_verify_duration,
    audit_verify_phase_duration,
)
from ..vault_state import vault

router = APIRouter(prefix="/api/v1/vault/audit", tags=["audit"])

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_VERIFY_STREAM_BATCH = 512


def _verified_by_worker() -> dict[str, object]:
    return {"host": get_hostname(), "pid": os.getpid()}


def _evidence_verdict(
    *,
    chain_intact: bool,
    unsigned_entries: int,
    unverifiable_while_sealed: int,
    audit_lite_intact: bool | None,
    audit_lite_uncheckpointed_rows: int | None,
    archive_intact: bool | None,
    snapshot_stable: bool = True,
) -> tuple[bool, str, list[str]]:
    """Summarise what a green chain result actually proves.

    ``chain_intact`` is deliberately kept compatible: legacy HMAC rows that
    cannot be checked while sealed still thread through their stored
    signatures. ``evidence_intact`` is stricter and is true only when every
    evidence class was both protected and verified, including the audit-lite
    tail after the newest signed checkpoint.
    """
    broken: list[str] = []
    incomplete: list[str] = []
    if not chain_intact:
        broken.append("main_chain_broken")
    if audit_lite_intact is False:
        broken.append("audit_lite_checkpoint_broken")
    if archive_intact is False:
        broken.append("archive_seal_broken")
    if broken:
        return False, "broken", broken

    if unsigned_entries:
        incomplete.append("unsigned_main_chain_entries")
    if unverifiable_while_sealed:
        incomplete.append("legacy_hmac_entries_unverifiable_while_sealed")
    if audit_lite_intact is None:
        incomplete.append("audit_lite_not_verified")
    if audit_lite_uncheckpointed_rows is None:
        incomplete.append("audit_lite_tail_unknown")
    elif audit_lite_uncheckpointed_rows:
        incomplete.append("audit_lite_tail_not_checkpointed")
    if archive_intact is None:
        incomplete.append("archive_seals_not_verified")
    if not snapshot_stable:
        incomplete.append("evidence_advanced_during_verify")
    if incomplete:
        return False, "incomplete", incomplete
    return True, "intact", []


async def _current_audit_state(db: AsyncSession) -> dict[str, object]:
    """Cheap high-water marks used to reject a mixed verification snapshot."""
    row = (
        await db.execute(
            text("""
                SELECT
                    (SELECT count(*) FROM vault_audit) AS main_count,
                    (SELECT id FROM vault_audit
                     ORDER BY timestamp DESC, id DESC LIMIT 1) AS main_id,
                    (SELECT timestamp FROM vault_audit
                     ORDER BY timestamp DESC, id DESC LIMIT 1) AS main_timestamp,
                    (SELECT signature FROM vault_audit
                     ORDER BY timestamp DESC, id DESC LIMIT 1) AS main_signature,
                    ((SELECT count(*) FROM vault_audit_lite) +
                     (SELECT COALESCE(sum(entry_count), 0)
                      FROM vault_audit_lite_archive_seals)) AS lite_count,
                    (SELECT count(*) FROM vault_audit_archive_seals)
                        AS archive_count,
                    (SELECT day FROM vault_audit_archive_seals
                     ORDER BY day DESC LIMIT 1) AS archive_head_day,
                    (SELECT content_digest FROM vault_audit_archive_seals
                     ORDER BY day DESC LIMIT 1) AS archive_head_digest
            """)
        )
    ).one()
    return {
        "main_count": int(row.main_count),
        "main_id": str(row.main_id) if row.main_id is not None else None,
        "main_timestamp": row.main_timestamp,
        "main_signature": row.main_signature,
        "lite_count": int(row.lite_count),
        "archive_count": int(row.archive_count),
        "archive_head_day": row.archive_head_day.isoformat()
        if row.archive_head_day is not None
        else None,
        "archive_head_digest": row.archive_head_digest,
    }


async def _unsigned_commitments_through(
    db: AsyncSession,
    *,
    highwater_timestamp: datetime,
    highwater_id: str,
) -> list[dict[str, str]]:
    rows = (
        await db.execute(
            text("""
                SELECT id, timestamp, actor, action, target, detail,
                       ip_address, signature, key_epoch, sig_alg, signer_fpr,
                       payload_version
                FROM vault_audit
                WHERE signature = 'unsigned'
                  AND (timestamp, id) <= (:highwater_timestamp,
                                          CAST(:highwater_id AS uuid))
                ORDER BY timestamp ASC, id ASC
            """),
            {
                "highwater_timestamp": highwater_timestamp,
                "highwater_id": highwater_id,
            },
        )
    ).fetchall()
    return [legacy_unsigned_row_commitment(row) for row in rows]


def _audit_snapshot_stable(
    *,
    total_entries: int,
    main_highwater_id: str | None,
    main_highwater_timestamp: datetime | None,
    main_highwater_signature: str | None,
    lite_status: dict[str, object],
    archive_status: dict[str, object],
    current_state: dict[str, object],
) -> bool:
    """Whether later evidence phases observed the same append-only heads."""
    return bool(
        current_state["main_count"] == total_entries
        and current_state["main_id"] == main_highwater_id
        and current_state["main_timestamp"] == main_highwater_timestamp
        and current_state["main_signature"] == main_highwater_signature
        and lite_status.get("audit_lite_total_rows") is not None
        and current_state["lite_count"] == lite_status["audit_lite_total_rows"]
        and current_state["archive_count"] == archive_status.get("archive_seals")
        and current_state["archive_head_day"] == archive_status.get("archive_head_day")
        and current_state["archive_head_digest"]
        == archive_status.get("archive_head_digest")
    )


async def _load_audit_keyring_via_vault(db: AsyncSession) -> dict[int, bytes]:
    async def decrypt_blob(blob: bytes) -> bytes:
        raw = bytes(blob)
        return await vault.aesgcm_decrypt(raw[12:], raw[:12], b"")

    return await load_audit_keyring(db, decrypt_blob=decrypt_blob)


async def _expected_sigs(
    entry_epoch: int,
    current_epoch: int,
    keyring: dict[int, bytes],
    payload: str,
    prev_sig: str,
) -> tuple[str, str]:
    """Expected (chained, legacy-unsigned-prev) signatures for one audit entry.

    An entry is verified with the audit_key of the generation that
    SIGNED it. The current epoch's key lives only in Rust (use vault.audit_sign);
    retired epochs are decrypted into ``keyring``. An entry tagged with an epoch
    that is neither current nor archived (e.g. a corrupt/purged archive row)
    falls back to the in-RAM key -- best effort, and verify surfaces the break
    if it genuinely cannot match.
    """
    if entry_epoch == current_epoch or entry_epoch not in keyring:
        chained = await vault.audit_sign(payload, prev_sig)
        legacy = await vault.audit_sign(payload, "unsigned")
    else:
        k = keyring[entry_epoch]
        chained = sign_audit(k, payload, prev_sig)
        legacy = sign_audit(k, payload, "unsigned")
    return chained, legacy


def _row_payload(r) -> str:
    """Versioned signed payload for a stored mutation audit row."""
    return audit_row_payload(r)


def _row_payload_mcp(r) -> str:
    """The signed payload for a vault_audit_mcp row (must match log_mcp_action)."""
    detail = r.detail if isinstance(r.detail, dict) else {}
    return (
        f"{r.actor}|{r.hub or ''}|{r.backend}|{r.tool}|{r.target or ''}|"
        f"{r.decision}|{json.dumps(detail, sort_keys=True)}"
    )


async def _load_signer_pubs(db: AsyncSession) -> dict[str, bytes]:
    """Map {signer_fpr: ed25519 public key} from the public signer registry.

    Public material only -- no dek_key, so this works while the vault is SEALED.
    """
    rows = await db.execute(
        text("SELECT fingerprint, public_key FROM vault_audit_signer_certs")
    )
    return {row.fingerprint: bytes(row.public_key) for row in rows.fetchall()}


async def _row_verified(
    r,
    prev_sig: str,
    *,
    sealed: bool,
    current_epoch: int,
    keyring: dict[int, bytes],
    signer_pubs: dict[str, bytes],
    payload: str | None = None,
) -> bool | None:
    """Verify one audit row against the chain.

    Dispatches on ``sig_alg``: ``ed25519`` rows verify with the signer's PUBLIC
    key (deterministic, host-independent, works sealed); ``hmac`` rows use the
    per-epoch keyring (needs the in-RAM key). Returns True/False, or None for an
    hmac row that cannot be checked because the vault is sealed (not a break --
    the chain still threads through its known signature). ``payload`` overrides the
    default vault_audit payload (used by the MCP chain, which has its own layout).
    """
    try:
        payload = payload if payload is not None else _row_payload(r)
    except (AttributeError, TypeError, ValueError):
        return False
    if (r.sig_alg or "hmac") == "ed25519":
        pub = signer_pubs.get(r.signer_fpr)
        if pub is None:
            return False
        if verify_audit_ed25519(pub, payload, prev_sig, r.signature):
            return True
        # Fallback: a preceding sealed (unsigned) entry chained as "unsigned".
        return verify_audit_ed25519(pub, payload, "unsigned", r.signature)
    if sealed:
        return None  # symmetric chain needs the audit_key, which a sealed vault lacks
    expected, legacy = await _expected_sigs(
        r.key_epoch, current_epoch, keyring, payload, prev_sig
    )
    return hmac.compare_digest(expected, r.signature) or hmac.compare_digest(
        legacy, r.signature
    )


@router.get("/")
async def list_audit(
    actor: str | None = Query(None),
    action: str | None = Query(None),
    since: datetime | None = Query(None, description="ISO timestamp, inclusive"),
    until: datetime | None = Query(None, description="ISO timestamp, exclusive"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("audit", "r")),
):
    vault.require_unsealed()

    params: dict = {"limit": limit, "offset": offset}
    where_parts: list[str] = []

    if actor:
        params["actor"] = actor
        where_parts.append("actor = :actor")
    if action:
        params["action"] = action
        where_parts.append("action = :action")
    if since is not None:
        params["since"] = since
        where_parts.append("timestamp >= :since")
    if until is not None:
        params["until"] = until
        where_parts.append("timestamp < :until")

    base = """
        SELECT id, timestamp, actor, action, target, detail,
               ip_address, signature, key_epoch, sig_alg, signer_fpr,
               payload_version
        FROM vault_audit
    """
    if where_parts:
        base += " WHERE " + " AND ".join(where_parts)
    # Mirror of the writer's ORDER BY (timestamp DESC, id DESC), keep the
    # tiebreaker in sync so the chain remains stable when timestamps collide.
    base += " ORDER BY timestamp ASC, id ASC LIMIT :limit OFFSET :offset"

    result = await db.execute(text(base), params)
    rows = result.fetchall()

    # Chain verification is only meaningful over a CONTIGUOUS slice of the
    # total order. An actor/action filter returns a non-contiguous subset, so
    # prev_sig can never thread, report verified=None / chain_intact=None and
    # point callers at /verify for the authoritative full-chain check.
    content_filtered = bool(actor or action)

    # per-epoch keys (hmac rows) + public signer keys (ed25519 rows).
    # Skipped for a content-filtered query (no verification -> no key material).
    if content_filtered:
        keyring, current_epoch, signer_pubs = {}, 0, {}
    else:
        keyring = await _load_audit_keyring_via_vault(db)
        current_epoch = await get_key_epoch(db)
        signer_pubs = await _load_signer_pubs(db)

    items = []
    prev_sig = ""
    chain_intact: bool | None = None if content_filtered else True

    # Seed prev_sig from the signed row immediately BEFORE the first returned
    # row (by (timestamp, id), the chain order). This makes both since-windows
    # and offset>0 pages verify correctly, without it the first row of any
    # window/page would be checked against "" and spuriously fail.
    if not content_filtered and rows:
        seed_row = (
            await db.execute(
                text(
                    "SELECT signature FROM vault_audit "
                    "WHERE signature != 'unsigned' "
                    "AND (timestamp, id) < (:ts0, CAST(:id0 AS uuid)) "
                    "ORDER BY timestamp DESC, id DESC LIMIT 1"
                ),
                {"ts0": rows[0].timestamp, "id0": str(rows[0].id)},
            )
        ).fetchone()
        if seed_row:
            prev_sig = seed_row.signature
        else:
            # No predecessor row: either genuinely the first entry ever, or the
            # oldest SURVIVING entry after a prune. The anchor distinguishes
            # them; without this the first page after a prune reports a
            # spurious break.
            listing_anchor = await latest_prune_anchor(db)
            if listing_anchor:
                prev_sig = listing_anchor["pruned_through_signature"]

    for r in rows:
        # Skip unsigned entries (written while sealed), they are out-of-chain
        if r.signature == "unsigned":
            items.append(
                {
                    "id": str(r.id),
                    "timestamp": r.timestamp.isoformat(),
                    "actor": r.actor,
                    "action": r.action,
                    "target": r.target,
                    "detail": r.detail if isinstance(r.detail, dict) else {},
                    "ip_address": r.ip_address,
                    "payload_version": r.payload_version,
                    "verified": False,
                    "unsigned": True,
                }
            )
            continue

        # Verify with the entry's own scheme: ed25519 (public key) or hmac
        # (per-epoch keyring). list_audit requires an unsealed vault, so the
        # hmac path always has its keys (sealed=False -> never None). Skipped
        # entirely for a content-filtered (non-contiguous) result.
        if content_filtered:
            verified = None
        else:
            verified = await _row_verified(
                r,
                prev_sig,
                sealed=False,
                current_epoch=current_epoch,
                keyring=keyring,
                signer_pubs=signer_pubs,
            )
            if not verified:
                chain_intact = False
            prev_sig = r.signature

        items.append(
            {
                "id": str(r.id),
                "timestamp": r.timestamp.isoformat(),
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "detail": r.detail if isinstance(r.detail, dict) else {},
                "ip_address": r.ip_address,
                "payload_version": r.payload_version,
                "verified": verified,
            }
        )

    return {
        "items": items,
        "count": len(items),
        "chain_intact": chain_intact,
    }


@router.get("/lite")
async def list_audit_lite(
    actor: str | None = Query(None),
    action: str | None = Query(None),
    since: datetime | None = Query(None, description="ISO timestamp, inclusive"),
    until: datetime | None = Query(None, description="ISO timestamp, exclusive"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("audit", "r")),
):
    """List the access log (`vault_audit_lite`) - read events.

    Companion endpoint to `GET /audit/` which lists the chained
    `vault_audit`. This one returns the append-only access log
    populated by `log_read` (typically `read_secret`,
    `read_secret_version`, ...) - same column layout minus the
    `signature` field, so no chain verification, no `chain_intact`
    field in the response.

    Filtering and pagination semantics match the chained list.
    """
    vault.require_unsealed()

    params: dict = {"limit": limit, "offset": offset}
    where_parts: list[str] = []

    if actor:
        params["actor"] = actor
        where_parts.append("actor = :actor")
    if action:
        params["action"] = action
        where_parts.append("action = :action")
    if since is not None:
        params["since"] = since
        where_parts.append("timestamp >= :since")
    if until is not None:
        params["until"] = until
        where_parts.append("timestamp < :until")

    base = """
        SELECT id, timestamp, actor, action, target, detail, ip_address
        FROM vault_audit_lite
    """
    if where_parts:
        base += " WHERE " + " AND ".join(where_parts)
    # Newest first, opposite order from the chained list because there is
    # no chain verification to perform left-to-right ; UI users care about
    # recent reads, paginate older as needed.
    base += " ORDER BY timestamp DESC, id DESC LIMIT :limit OFFSET :offset"

    result = await db.execute(text(base), params)
    rows = result.fetchall()
    items = [
        {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "detail": r.detail if isinstance(r.detail, dict) else {},
            "ip_address": r.ip_address,
        }
        for r in rows
    ]
    return {"items": items, "count": len(items)}


@router.get("/stream")
async def stream_audit(
    interval_secs: float = Query(2.0, ge=0.5, le=60),
    db_dep: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("audit", "r")),
):
    """Server-Sent Events stream of new audit entries.

    Polls the DB every `interval_secs` seconds, emits any new rows as
    SSE events. Each event is a JSON document of the entry. The stream
    survives DB hiccups (logs + retries on the next tick).

    The connection lives until the client disconnects. Useful for SIEM
    integration (Wazuh, Grafana log panel) or live tailing from a CLI.
    """
    import asyncio

    from fastapi.responses import StreamingResponse

    from ..database import async_session

    vault.require_unsealed()

    def _evt(row) -> str:
        return "data: " + json.dumps(
            {
                "id": str(row.id),
                "timestamp": row.timestamp.isoformat(),
                "actor": row.actor,
                "action": row.action,
                "target": row.target,
                "detail": row.detail if isinstance(row.detail, dict) else {},
                "ip_address": row.ip_address,
            }
        )

    async def event_gen():
        # Cursor is a (timestamp, id) tuple, not id alone: `timestamp >` would
        # drop a row sharing the last emitted row's microsecond. The id
        # tiebreaker matches the chain order (ORDER BY timestamp, id).
        cursor: tuple | None = None
        # Bootstrap: send the most recent 20 entries so a fresh subscriber
        # has context.
        async with async_session() as boot_db:
            r = await boot_db.execute(
                text(
                    "SELECT id, timestamp, actor, action, target, detail, "
                    "ip_address FROM vault_audit "
                    "ORDER BY timestamp DESC, id DESC LIMIT 20"
                )
            )
            rows = list(reversed(r.fetchall()))
        for row in rows:
            yield f"{_evt(row)}\n\n"
            cursor = (row.timestamp, str(row.id))

        # Live tail loop
        while True:  # pragma: no cover  (SSE long-poll, integ)
            await asyncio.sleep(interval_secs)
            try:
                async with async_session() as poll_db:
                    if cursor is not None:
                        r = await poll_db.execute(
                            text(
                                "SELECT id, timestamp, actor, action, target, "
                                "detail, ip_address FROM vault_audit "
                                "WHERE (timestamp, id) > (:lts, CAST(:lid AS uuid)) "
                                "ORDER BY timestamp ASC, id ASC LIMIT 100"
                            ),
                            {"lts": cursor[0], "lid": cursor[1]},
                        )
                    else:
                        r = await poll_db.execute(
                            text(
                                "SELECT id, timestamp, actor, action, target, "
                                "detail, ip_address FROM vault_audit "
                                "ORDER BY timestamp ASC, id ASC LIMIT 100"
                            )
                        )
                    rows = r.fetchall()
                for row in rows:
                    yield f"{_evt(row)}\n\n"
                    cursor = (row.timestamp, str(row.id))
                # Heartbeat comment so middleware proxies don't drop idle
                # connections
                yield ": heartbeat\n\n"
            except asyncio.CancelledError:
                return
            except Exception:
                # Continue on transient DB errors, the stream stays alive
                yield ": db-error-retrying\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


def _sealed_verify_ip_allowed(request: Request) -> bool:
    """Perimeter gate for sealed /verify: the DIRECT peer IP must fall in
    settings.audit_verify_allowed_cidrs. X-Forwarded-For is ignored on purpose
    (same trust model as /metrics - the anchor is the network, not headers).
    Parsed per call so an operator (or a test) can flip the setting at runtime.
    """
    raw = settings.audit_verify_allowed_cidrs or ""
    nets = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    if not nets:
        return False
    direct = request.client.host if request.client else None
    if not direct:
        return False
    try:
        ip = ipaddress.ip_address(direct)
    except ValueError:
        return False
    return any(ip in net for net in nets)


async def _verify_auth(
    request: Request,
    authorization: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
) -> dict | None:
    """Dual-mode auth for /verify.

    Unsealed: normal audit:r bearer token (strong auth). Sealed: bearer is
    impossible (the hmac_key is gone), so fall back to the perimeter CIDR gate
    and verify only the ed25519 portion. Sealed verify is opt-in and OFF by
    default (empty audit_verify_allowed_cidrs -> 503).
    """
    if vault.sealed:
        if not _sealed_verify_ip_allowed(request):
            raise HTTPException(
                503,
                "Vault sealed; /verify requires a source IP in "
                "audit_verify_allowed_cidrs",
            )
        return None
    token_info = await require_vault_token(request, authorization or "", db)
    perms = token_info.get("permissions", {})
    granted = set(perms.get("audit", "")) | set(perms.get("admin", ""))
    if "r" not in granted:
        from .. import metrics as _m

        _m.record_auth_failure("scope")
        raise HTTPException(403, "Missing scope: audit")
    return token_info


@router.get("/verify")
async def verify_chain(
    db: AsyncSession = Depends(get_db),
    token_info: dict | None = Depends(_verify_auth),
):
    """Full chain verification - returns first broken link if any.

    Asymmetric (ed25519) entries verify with the public signer key, so this
    works while the vault is SEALED -- reachable then via the perimeter CIDR gate
    (audit_verify_allowed_cidrs), since bearer auth needs the in-RAM hmac_key.
    A sealed vault cannot check legacy hmac entries -- those are reported as
    ``unverifiable_while_sealed`` rather than broken, and the chain still threads
    through their stored signatures. Unsealed, it requires an audit:r bearer.
    """
    verify_started = time.perf_counter()
    sealed = vault.sealed

    # Public signer keys (ed25519) -- no secret, works sealed. Per-epoch hmac
    # keyring only when unsealed (a sealed vault has no dek_key to decrypt it).
    signer_pubs = await _load_signer_pubs(db)
    keyring = {} if sealed else await _load_audit_keyring_via_vault(db)
    current_epoch = await get_key_epoch(db)

    try:
        lite_count = await db.execute(text("SELECT count(*) FROM vault_audit_lite"))
        audit_lite_length.set(lite_count.scalar() or 0)
    except Exception:
        # vault_audit_lite may not exist on older deployments. Don't fail
        # verify on a missing table. Clear PostgreSQL's aborted read
        # transaction before opening the audit stream.
        await db.rollback()

    # Never materialize the full chain in a Python worker. A weekend K7 run
    # grew one verifier to 3.4 GiB anonymous RSS through fetchall(), triggered
    # the host OOM killer, and systemd then stopped the whole API cgroup. A
    # server-side cursor keeps Python memory bounded to this batch size.
    # count(*) OVER () gives every streamed row the same snapshot total, so a
    # concurrent append cannot make total_entries disagree with the chain walk.
    main_started = time.perf_counter()
    setup_seconds = main_started - verify_started
    audit_verify_phase_duration.labels(phase="setup").observe(setup_seconds)
    rows = await db.stream(
        text("""
            SELECT id, timestamp, actor, action, target, detail,
                   ip_address, signature, key_epoch, sig_alg, signer_fpr,
                   payload_version,
                   count(*) OVER () AS verify_total
            FROM vault_audit
            ORDER BY timestamp ASC, id ASC
        """).execution_options(yield_per=_VERIFY_STREAM_BATCH)
    )

    # Where the walk STARTS. "" is correct only while nothing was ever pruned:
    # after a prune the oldest surviving row's signature was computed over a row
    # that no longer exists, and starting at "" would report a broken chain at
    # the seam. The anchor is a signed row IN this chain naming the last pruned
    # signature, so forging one needs the audit key -- and it excuses exactly
    # what it names. Delete anything beyond it and the first surviving row no
    # longer chains to the anchor, which is reported as a break, so a prune
    # cannot be used to hide a deletion.
    prune_anchor = await latest_prune_anchor(db)
    prev_sig = prune_anchor["pruned_through_signature"] if prune_anchor else ""
    unsigned_count = 0
    unsigned_commitments: list[dict[str, str]] = []
    unverifiable_while_sealed = 0
    total_entries = 0
    main_highwater_id: str | None = None
    main_highwater_timestamp: datetime | None = None
    main_highwater_signature: str | None = None
    i = -1
    try:
        with audit_verify_duration.time():
            async for r in rows:
                i += 1
                main_highwater_id = str(r.id)
                main_highwater_timestamp = r.timestamp
                main_highwater_signature = r.signature
                if total_entries == 0:
                    total_entries = int(r.verify_total)
                    audit_chain_length.set(total_entries)
                # Ed25519 verification is CPU work. Yield without weakening or
                # skipping any check so normal requests and cluster RPC stay
                # responsive during a multi-million-row verification.
                if i and i % 256 == 0:
                    await asyncio.sleep(0)
                # Skip unsigned entries (written while sealed)
                if r.signature == "unsigned":
                    unsigned_count += 1
                    unsigned_commitments.append(legacy_unsigned_row_commitment(r))
                    continue

                verified = await _row_verified(
                    r,
                    prev_sig,
                    sealed=sealed,
                    current_epoch=current_epoch,
                    keyring=keyring,
                    signer_pubs=signer_pubs,
                )
                # hmac row we cannot check while sealed: not a break -- chain
                # through its stored signature.
                if verified is None:
                    unverifiable_while_sealed += 1
                    prev_sig = r.signature
                    continue
                if not verified:
                    # Tamper-evident break. Alert operators via the notification
                    # fan-out (Matrix/webhook/email) + a counter -- but do NOT
                    # write an audit_chain_broken row into the chain being
                    # verified.
                    audit_chain_breaks.inc()
                    try:
                        from ..audit import _dispatch_critical_event

                        await _dispatch_critical_event(
                            f"[critical] audit chain broken at #{i} id={r.id} "
                            f"ts={r.timestamp.isoformat()}"
                        )
                    except Exception:
                        pass
                    main_seconds = time.perf_counter() - main_started
                    total_seconds = time.perf_counter() - verify_started
                    audit_verify_phase_duration.labels(phase="main_chain").observe(
                        main_seconds
                    )
                    audit_verify_phase_duration.labels(phase="total").observe(
                        total_seconds
                    )
                    return {
                        "verified_by": _verified_by_worker(),
                        "chain_intact": False,
                        "evidence_intact": False,
                        "total_entries": total_entries,
                        "broken_at": i,
                        "broken_id": str(r.id),
                        "broken_timestamp": r.timestamp.isoformat(),
                        "unsigned_entries": unsigned_count,
                        "unverifiable_while_sealed": unverifiable_while_sealed,
                        "audit_lite_intact": None,
                        "evidence_status": "broken",
                        "evidence_incomplete_reasons": ["main_chain_broken"],
                        "verification_scope": "full",
                        "verification_duration_seconds": {
                            "setup": setup_seconds,
                            "main_chain": main_seconds,
                            "total": total_seconds,
                        },
                    }
                prev_sig = r.signature
    finally:
        await rows.close()
        # End the read-only cursor transaction and return its connection to the
        # pool before the independent audit-lite verification.
        await db.rollback()

    if total_entries == 0:
        audit_chain_length.set(0)
    main_seconds = time.perf_counter() - main_started
    audit_verify_phase_duration.labels(phase="main_chain").observe(main_seconds)

    # Use a fresh session for the audit-lite phase rather than reusing the
    # connection released before the CPU-heavy signature walk.
    lite_started = time.perf_counter()
    async with async_session() as lite_db:
        lite_status = await verify_audit_lite_checkpoints(lite_db)
    lite_seconds = time.perf_counter() - lite_started
    audit_verify_phase_duration.labels(phase="audit_lite").observe(lite_seconds)
    if lite_status.get("audit_lite_uncheckpointed_rows") is not None:
        audit_lite_uncheckpointed.set(lite_status["audit_lite_uncheckpointed_rows"])

    if lite_status.get("audit_lite_intact") is False:
        audit_lite_checkpoint_breaks.inc()
        try:
            from ..audit import _dispatch_critical_event

            await _dispatch_critical_event(
                "[critical] audit-lite Merkle checkpoint broken "
                f"id={lite_status.get('audit_lite_broken_checkpoint_id')} "
                f"reason={lite_status.get('audit_lite_broken_reason')}"
            )
        except Exception:
            pass

    # Archive seals: the only check that catches a TRUNCATED archive file or a
    # deleted day. Per-entry signatures cannot -- a truncated file is a shorter,
    # perfectly valid chain. Reported here because this is where operators
    # already look, and because a database prune is only safe while these are
    # green. A failure to read the archive is reported, never fatal: the chain
    # verdict above stands on its own.
    from ..audit import _audit_dir
    from ..audit_archive import verify_archive_seals

    archive_started = time.perf_counter()
    try:
        async with async_session() as archive_db:
            archive_status = await verify_archive_seals(
                archive_db, audit_dir=_audit_dir()
            )
    except Exception:
        import logging

        logging.getLogger("rhorizon.audit_archive").warning(
            "archive seal verification failed", exc_info=True
        )
        archive_status = {"archive_intact": None, "archive_seals": None}
    archive_seconds = time.perf_counter() - archive_started
    audit_verify_phase_duration.labels(phase="archive").observe(archive_seconds)

    if archive_status.get("archive_intact") is False:
        try:
            from ..audit import _dispatch_critical_event

            await _dispatch_critical_event(
                "[critical] audit archive seal broken: "
                f"{archive_status.get('archive_problems')}"
            )
        except Exception:
            pass

    # The three evidence classes are intentionally checked in separate, short
    # transactions so the O(N) verifier never pins one PostgreSQL snapshot for
    # tens of seconds. That creates one trust-boundary requirement: a green
    # full result must not combine an old main-chain snapshot with a newly
    # arrived audit-lite checkpoint. Re-read only the high-water marks now and
    # mark the result incomplete if either append-only table advanced.
    async with async_session() as state_db:
        current_state = await _current_audit_state(state_db)
    snapshot_stable = _audit_snapshot_stable(
        total_entries=total_entries,
        main_highwater_id=main_highwater_id,
        main_highwater_timestamp=main_highwater_timestamp,
        main_highwater_signature=main_highwater_signature,
        lite_status=lite_status,
        archive_status=archive_status,
        current_state=current_state,
    )

    evidence_intact, evidence_status, evidence_reasons = _evidence_verdict(
        chain_intact=True,
        unsigned_entries=unsigned_count,
        unverifiable_while_sealed=unverifiable_while_sealed,
        audit_lite_intact=lite_status.get("audit_lite_intact"),
        audit_lite_uncheckpointed_rows=lite_status.get(
            "audit_lite_uncheckpointed_rows"
        ),
        archive_intact=archive_status.get("archive_intact"),
        snapshot_stable=snapshot_stable,
    )
    total_seconds = time.perf_counter() - verify_started
    audit_verify_phase_duration.labels(phase="total").observe(total_seconds)

    result = {
        "verified_by": _verified_by_worker(),
        "chain_intact": True,
        "evidence_intact": evidence_intact,
        "evidence_status": evidence_status,
        "evidence_incomplete_reasons": evidence_reasons,
        "verification_scope": "full",
        "snapshot_stable": snapshot_stable,
        "audit_lite_tail_protected": (
            lite_status.get("audit_lite_uncheckpointed_rows") == 0
        ),
        "verification_duration_seconds": {
            "setup": setup_seconds,
            "main_chain": main_seconds,
            "audit_lite": lite_seconds,
            "archive": archive_seconds,
            "total": total_seconds,
        },
        "total_entries": total_entries,
        "unsigned_entries": unsigned_count,
        "unsigned_entry_commitments": unsigned_commitments,
        "unverifiable_while_sealed": unverifiable_while_sealed,
        "main_highwater_timestamp": (
            main_highwater_timestamp.isoformat()
            if main_highwater_timestamp is not None
            else None
        ),
        "main_highwater_id": main_highwater_id,
        "main_highwater_stored_signature": main_highwater_signature,
        "main_head_signature": prev_sig or None,
        # A green verdict over a PRUNED chain means something different from a
        # green verdict over a whole one -- the walk began at an anchor rather
        # than at genesis -- so the result says which it was.
        "chain_anchored_at_day": prune_anchor["pruned_through_day"]
        if prune_anchor
        else None,
        "chain_pruned_rows": prune_anchor["pruned_row_count"] if prune_anchor else 0,
        **lite_status,
        **archive_status,
    }

    # Only a clean, stable, unsealed full walk may become a starting point for
    # future incremental verification. Signing is independent of the audit
    # chain itself: a fast verifier will authenticate this receipt before it
    # trusts the recorded heads. A failure to issue the optimisation receipt
    # does not rewrite the authoritative full-verification verdict.
    result["verification_anchor"] = None
    result["legacy_adoption_candidate"] = None
    if evidence_intact and not sealed:
        try:
            from ..audit_verify_anchor import create_verification_anchor

            async with async_session() as anchor_db:
                anchor = await create_verification_anchor(anchor_db, result)
                await anchor_db.commit()
            result["verification_anchor"] = {
                "id": anchor["id"],
                "completed_at": anchor["completed_at"],
                "signer_fpr": anchor["signer_fpr"],
                "signature": anchor["signature"],
            }
        except Exception as error:
            import logging

            logging.getLogger("rhorizon.audit_verify_anchor").warning(
                "full verification passed but signed anchor was not issued: %s",
                error,
                exc_info=True,
            )
            result["verification_anchor_error"] = type(error).__name__
    elif (
        not sealed
        and snapshot_stable
        and evidence_reasons == ["unsigned_main_chain_entries"]
        and unsigned_commitments
    ):
        try:
            from ..audit_verify_anchor import create_verification_anchor

            candidate_adoption = {
                "schema": LEGACY_ADOPTION_SCHEMA,
                "unsigned_rows": unsigned_commitments,
            }
            async with async_session() as anchor_db:
                candidate = await create_verification_anchor(
                    anchor_db,
                    result,
                    legacy_adoption=candidate_adoption,
                    verification_mode="legacy_candidate",
                )
                await anchor_db.commit()
            result["legacy_adoption_candidate"] = {
                "id": candidate["id"],
                "completed_at": candidate["completed_at"],
                "signer_fpr": candidate["signer_fpr"],
                "signature": candidate["signature"],
            }
        except Exception as error:
            import logging

            logging.getLogger("rhorizon.audit_verify_anchor").warning(
                "legacy adoption candidate was not issued: %s",
                error,
                exc_info=True,
            )
            result["verification_anchor_error"] = type(error).__name__
    elif sealed:
        result["verification_anchor_error"] = "vault_sealed"
    elif not snapshot_stable:
        result["verification_anchor_error"] = "snapshot_advanced"

    return result


@router.get("/verify/incremental")
async def verify_chain_incremental(
    db: AsyncSession = Depends(get_db),
    token_info: dict | None = Depends(_verify_auth),
):
    """Authenticate the latest full anchor and verify only evidence after it.

    This is the bounded routine-health path. It never claims to have re-read
    the historical prefix; ``verification_scope`` remains ``incremental``.
    Scheduled/full-job verification is still the authoritative deep scan.
    """
    from ..audit_archive import verify_archive_seals
    from ..audit_verify_anchor import latest_verification_anchor

    started = time.perf_counter()
    anchor = await latest_verification_anchor(db)
    if anchor is None:
        return {
            "chain_intact": None,
            "evidence_intact": False,
            "evidence_status": "incomplete",
            "evidence_incomplete_reasons": ["full_verification_anchor_missing"],
            "verification_scope": "incremental",
            "full_verification_required": True,
        }
    if anchor.get("valid") is not True:
        audit_chain_breaks.inc()
        return {
            "chain_intact": None,
            "evidence_intact": False,
            "evidence_status": "broken",
            "evidence_incomplete_reasons": ["verification_anchor_invalid"],
            "verification_scope": "incremental",
            "full_verification_required": True,
            "verification_anchor": {
                "id": anchor.get("id"),
                "completed_at": anchor.get("completed_at"),
                "valid": False,
            },
        }

    try:
        payload = anchor["payload"]
        anchor_main = payload["main"]
        anchor_lite = payload["lite"]
        anchor_archive = payload["archive"]
        anchor_completed_at = datetime.fromisoformat(
            str(payload["completed_at"]).replace("Z", "+00:00")
        )
        if anchor_completed_at.tzinfo is None:
            anchor_completed_at = anchor_completed_at.replace(tzinfo=timezone.utc)
        anchor_main_count = int(anchor_main["row_count"])
        anchor_main_id = anchor_main.get("highwater_id")
        anchor_main_timestamp = (
            datetime.fromisoformat(
                str(anchor_main["highwater_timestamp"]).replace("Z", "+00:00")
            )
            if anchor_main.get("highwater_timestamp") is not None
            else None
        )
        anchor_head_signature = anchor_main.get("head_signature") or ""
        anchor_archive_count = int(anchor_archive["seal_count"])
        anchor_archive_day = (
            date.fromisoformat(str(anchor_archive["head_day"]))
            if anchor_archive.get("head_day") is not None
            else None
        )
        anchor_archive_digest = anchor_archive.get("head_digest")
        if anchor_main_count < 0 or (anchor_main_timestamp is None) != (
            anchor_main_id is None
        ):
            raise ValueError("inconsistent main high-water mark")
        if anchor_archive_count < 0 or (anchor_archive_day is None) != (
            anchor_archive_digest is None
        ):
            raise ValueError("inconsistent archive high-water mark")
    except (KeyError, TypeError, ValueError):
        return {
            "chain_intact": None,
            "evidence_intact": False,
            "evidence_status": "broken",
            "evidence_incomplete_reasons": ["verification_anchor_state_invalid"],
            "verification_scope": "incremental",
            "full_verification_required": True,
        }

    adopted_unsigned_rows: list[dict[str, str]] = []
    raw_legacy_adoption = payload.get("legacy_adoption")
    if raw_legacy_adoption is not None:
        try:
            adopted_unsigned_rows = validate_legacy_adoption(raw_legacy_adoption)
            if anchor_main_timestamp is None or anchor_main_id is None:
                raise ValueError("legacy adoption requires a main high-water mark")
            actual_unsigned_rows = await _unsigned_commitments_through(
                db,
                highwater_timestamp=anchor_main_timestamp,
                highwater_id=anchor_main_id,
            )
        except (KeyError, TypeError, ValueError):
            return {
                "chain_intact": None,
                "evidence_intact": False,
                "evidence_status": "broken",
                "evidence_incomplete_reasons": [
                    "verification_anchor_legacy_adoption_invalid"
                ],
                "verification_scope": "incremental",
                "full_verification_required": True,
            }
        if actual_unsigned_rows != adopted_unsigned_rows:
            audit_chain_breaks.inc()
            return {
                "chain_intact": False,
                "evidence_intact": False,
                "evidence_status": "broken",
                "evidence_incomplete_reasons": ["legacy_adopted_row_changed"],
                "verification_scope": "incremental",
                "full_verification_required": True,
            }

    now = datetime.now(timezone.utc)
    raw_anchor_age_seconds = (
        now - anchor_completed_at.astimezone(timezone.utc)
    ).total_seconds()
    anchor_age_seconds = max(0.0, raw_anchor_age_seconds)
    anchor_clock_valid = raw_anchor_age_seconds >= -300
    anchor_fresh = (
        anchor_clock_valid
        and anchor_age_seconds <= settings.audit_verify_anchor_max_age_seconds
    )
    sealed = vault.sealed
    signer_pubs = await _load_signer_pubs(db)
    keyring = {} if sealed else await _load_audit_keyring_via_vault(db)
    current_epoch = await get_key_epoch(db)
    state_before = await _current_audit_state(db)
    await db.rollback()

    params: dict[str, object] = {}
    if anchor_main_timestamp is None:
        suffix_where = ""
    else:
        suffix_where = "WHERE (timestamp, id) > (:anchor_ts, CAST(:anchor_id AS uuid))"
        params = {"anchor_ts": anchor_main_timestamp, "anchor_id": anchor_main_id}
    rows = await db.stream(
        text(f"""
            SELECT id, timestamp, actor, action, target, detail,
                   ip_address, signature, key_epoch, sig_alg, signer_fpr,
                   payload_version
            FROM vault_audit
            {suffix_where}
            ORDER BY timestamp ASC, id ASC
        """).execution_options(yield_per=_VERIFY_STREAM_BATCH),
        params,
    )
    prev_sig = anchor_head_signature
    suffix_entries = 0
    unsigned_count = 0
    unverifiable_while_sealed = 0
    prune_in_suffix = False
    suffix_highwater_id = anchor_main_id
    suffix_highwater_timestamp = anchor_main_timestamp
    try:
        async for row in rows:
            suffix_entries += 1
            suffix_highwater_id = str(row.id)
            suffix_highwater_timestamp = row.timestamp
            prune_in_suffix = prune_in_suffix or row.action == "audit_chain_prune"
            if row.signature == "unsigned":
                unsigned_count += 1
                continue
            verified = await _row_verified(
                row,
                prev_sig,
                sealed=sealed,
                current_epoch=current_epoch,
                keyring=keyring,
                signer_pubs=signer_pubs,
            )
            if verified is None:
                unverifiable_while_sealed += 1
                prev_sig = row.signature
                continue
            if not verified:
                audit_chain_breaks.inc()
                return {
                    "chain_intact": False,
                    "evidence_intact": False,
                    "evidence_status": "broken",
                    "evidence_incomplete_reasons": ["main_chain_suffix_broken"],
                    "verification_scope": "incremental",
                    "broken_id": str(row.id),
                    "full_verification_required": True,
                }
            prev_sig = row.signature
            if suffix_entries % 256 == 0:
                await asyncio.sleep(0)
    finally:
        await rows.close()
        await db.rollback()

    lite_started = time.perf_counter()
    async with async_session() as lite_db:
        lite_status = await verify_audit_lite_incremental(
            lite_db,
            anchor_lite=anchor_lite,
            main_highwater_timestamp=anchor_main_timestamp,
            main_highwater_id=anchor_main_id,
        )
    lite_seconds = time.perf_counter() - lite_started

    archive_started = time.perf_counter()
    archive_anchor_state_intact: bool | None = None
    try:
        async with async_session() as archive_db:
            archive_status = await verify_archive_seals(
                archive_db, audit_dir=_audit_dir()
            )
            if anchor_archive_day is None:
                archive_anchor_state_intact = anchor_archive_count == 0
            else:
                anchored_seal = (
                    await archive_db.execute(
                        text("""
                            SELECT content_digest
                            FROM vault_audit_archive_seals
                            WHERE day = CAST(:day AS date)
                        """),
                        {"day": anchor_archive_day},
                    )
                ).fetchone()
                archive_anchor_state_intact = bool(
                    anchored_seal is not None
                    and anchored_seal.content_digest == anchor_archive_digest
                    and int(archive_status.get("archive_seals") or 0)
                    >= anchor_archive_count
                )
    except Exception:
        import logging

        logging.getLogger("rhorizon.audit_verify_anchor").warning(
            "incremental archive verification failed", exc_info=True
        )
        archive_status = {"archive_intact": None, "archive_seals": None}
    archive_seconds = time.perf_counter() - archive_started

    async with async_session() as state_db:
        state_after = await _current_audit_state(state_db)
    snapshot_stable = state_before == state_after
    historical_main_count_stable = (
        state_after["main_count"] == anchor_main_count + suffix_entries
    )

    broken_reasons: list[str] = []
    incomplete_reasons: list[str] = []
    if not historical_main_count_stable and not prune_in_suffix:
        broken_reasons.append("historical_main_row_count_changed")
    if lite_status.get("audit_lite_intact") is False:
        broken_reasons.append("audit_lite_checkpoint_broken")
    if archive_status.get("archive_intact") is False:
        broken_reasons.append("archive_seal_broken")
    if archive_anchor_state_intact is False:
        broken_reasons.append("historical_archive_anchor_changed")
    if unsigned_count:
        incomplete_reasons.append("unsigned_main_chain_entries")
    if unverifiable_while_sealed:
        incomplete_reasons.append("legacy_hmac_entries_unverifiable_while_sealed")
    if lite_status.get("audit_lite_uncheckpointed_rows") is None:
        incomplete_reasons.append("audit_lite_tail_unknown")
    elif lite_status.get("audit_lite_uncheckpointed_rows"):
        incomplete_reasons.append("audit_lite_tail_not_checkpointed")
    if archive_status.get("archive_intact") is None:
        incomplete_reasons.append("archive_seals_not_verified")
    if not snapshot_stable:
        incomplete_reasons.append("evidence_advanced_during_verify")
    if anchor_clock_valid and not anchor_fresh:
        incomplete_reasons.append("full_verification_anchor_stale")
    if not anchor_clock_valid:
        incomplete_reasons.append("verification_anchor_timestamp_in_future")
    if prune_in_suffix:
        incomplete_reasons.append("prune_requires_new_full_verification")
    if not historical_main_count_stable and prune_in_suffix:
        incomplete_reasons.append("main_row_count_changed_by_prune")

    evidence_intact = not broken_reasons and not incomplete_reasons
    evidence_status = (
        "broken" if broken_reasons else "incomplete" if incomplete_reasons else "intact"
    )
    total_seconds = time.perf_counter() - started
    return {
        "verified_by": _verified_by_worker(),
        "chain_intact": True,
        "evidence_intact": evidence_intact,
        "evidence_status": evidence_status,
        "evidence_incomplete_reasons": broken_reasons + incomplete_reasons,
        "verification_scope": "incremental",
        "full_verification_required": bool(
            broken_reasons
            or not anchor_fresh
            or prune_in_suffix
            or not historical_main_count_stable
        ),
        "snapshot_stable": snapshot_stable,
        "verification_anchor": {
            "id": anchor["id"],
            "completed_at": anchor["completed_at"],
            "valid": True,
            "fresh": anchor_fresh,
            "age_seconds": anchor_age_seconds,
            "max_age_seconds": settings.audit_verify_anchor_max_age_seconds,
        },
        "total_entries": state_after["main_count"],
        "historical_entries_not_reread": anchor_main_count,
        "suffix_entries_verified": suffix_entries,
        "unsigned_entries": unsigned_count,
        "legacy_adopted_unsigned_entries": len(adopted_unsigned_rows),
        "unverifiable_while_sealed": unverifiable_while_sealed,
        "main_highwater_timestamp": suffix_highwater_timestamp.isoformat()
        if suffix_highwater_timestamp is not None
        else None,
        "main_highwater_id": suffix_highwater_id,
        "main_head_signature": prev_sig or None,
        "audit_lite_tail_protected": (
            lite_status.get("audit_lite_uncheckpointed_rows") == 0
        ),
        "archive_anchor_state_intact": archive_anchor_state_intact,
        "verification_duration_seconds": {
            "audit_lite": lite_seconds,
            "archive": archive_seconds,
            "total": total_seconds,
        },
        **lite_status,
        **archive_status,
    }


@router.post("/verify/jobs", status_code=202)
async def create_verify_job(
    token_info: dict | None = Depends(_verify_auth),
):
    """Queue an authoritative full verification outside the HTTP timeout path."""
    from ..audit_verify_jobs import enqueue_audit_verify

    requested_by = actor_display_name(token_info) if token_info is not None else "cidr"
    job, created = await enqueue_audit_verify(requested_by)
    return {**job, "created": created}


class LegacyAuditAdoptionRequest(BaseModel):
    job_id: UUID
    unsigned_row_ids: list[UUID] = Field(..., min_length=1, max_length=1024)
    confirmation: str = Field(..., max_length=64)


@router.post("/verify/legacy-adopt", status_code=201)
async def adopt_legacy_audit_baseline(
    body: LegacyAuditAdoptionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Explicitly sign a fully recomputed legacy unsigned-checkpoint baseline."""
    vault.require_unsealed()
    if body.confirmation != "ADOPT LEGACY AUDIT BASELINE":
        raise HTTPException(400, "confirmation must be ADOPT LEGACY AUDIT BASELINE")

    from ..audit_verify_anchor import (
        adopt_verification_candidate,
        verification_anchor_by_id,
    )
    from ..audit_verify_jobs import get_audit_verify_job

    job = await get_audit_verify_job(body.job_id)
    actor = actor_display_name(token_info)
    if job is None:
        raise HTTPException(404, "Audit verification job not found")
    if job.get("status") != "succeeded" or not isinstance(job.get("result"), dict):
        raise HTTPException(409, "Audit verification job has no successful result")
    if job.get("requested_by") != actor:
        raise HTTPException(403, "Only the operator who requested the job may adopt it")

    result = job["result"]
    candidate_metadata = result.get("legacy_adoption_candidate")
    if not isinstance(candidate_metadata, dict) or not candidate_metadata.get("id"):
        raise HTTPException(409, "Full result has no signed legacy candidate")
    try:
        candidate = await verification_anchor_by_id(
            db, UUID(str(candidate_metadata["id"]))
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(409, "Full result has an invalid candidate ID") from error
    if candidate is None or candidate.get("valid") is not True:
        raise HTTPException(
            409, "Legacy candidate is missing or has an invalid signature"
        )
    candidate_payload = candidate.get("payload")
    if (
        not isinstance(candidate_payload, dict)
        or candidate_payload.get("verification_mode") != "legacy_candidate"
    ):
        raise HTTPException(409, "Signed anchor is not a legacy candidate")
    try:
        commitments = validate_legacy_adoption(candidate_payload.get("legacy_adoption"))
        candidate_main = candidate_payload["main"]
        candidate_lite = candidate_payload["lite"]
        candidate_archive = candidate_payload["archive"]
        highwater_timestamp = datetime.fromisoformat(
            str(candidate_main["highwater_timestamp"]).replace("Z", "+00:00")
        )
        highwater_id = str(UUID(str(candidate_main["highwater_id"])))
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(409, "Signed legacy candidate state is invalid") from error
    expected_ids = sorted(str(row_id) for row_id in body.unsigned_row_ids)
    found_ids = sorted(
        str(row.get("id")) for row in commitments if isinstance(row, dict)
    )
    if expected_ids != found_ids or len(found_ids) != len(commitments):
        raise HTTPException(
            409, "Confirmed unsigned row IDs do not match the full result"
        )

    current_state = await _current_audit_state(db)
    candidate_still_current = bool(
        current_state["main_count"] == int(candidate_main["row_count"])
        and current_state["main_id"] == highwater_id
        and current_state["main_timestamp"] == highwater_timestamp
        and current_state["main_signature"]
        == candidate_main.get("highwater_stored_signature")
        and current_state["lite_count"] == int(candidate_lite["row_count"])
        and current_state["archive_count"] == int(candidate_archive["seal_count"])
        and current_state["archive_head_day"] == candidate_archive.get("head_day")
        and current_state["archive_head_digest"] == candidate_archive.get("head_digest")
    )
    if not candidate_still_current:
        raise HTTPException(409, "Audit evidence advanced since the full verification")

    current_commitments = await _unsigned_commitments_through(
        db,
        highwater_timestamp=highwater_timestamp,
        highwater_id=highwater_id,
    )
    if current_commitments != commitments:
        raise HTTPException(409, "Unsigned audit rows changed since full verification")

    try:
        anchor = await adopt_verification_candidate(
            db,
            candidate,
            source_job_id=body.job_id,
            operator=actor,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(409, str(error)) from error
    await log_action(
        db,
        actor=actor,
        action="audit_legacy_baseline_adopted",
        target=anchor["id"],
        detail={
            "source_job_id": str(body.job_id),
            "unsigned_row_ids": found_ids,
            "anchor_signer_fpr": anchor["signer_fpr"],
        },
        ip_address=get_client_ip(request),
        critical=True,
    )
    await db.commit()
    return {
        "status": "adopted",
        "verification_anchor": {
            "id": anchor["id"],
            "completed_at": anchor["completed_at"],
            "signer_fpr": anchor["signer_fpr"],
        },
        "legacy_adopted_unsigned_entries": len(commitments),
        "unsigned_row_ids": found_ids,
    }


@router.post("/verify/preflight")
async def audit_verify_preflight(
    db: AsyncSession = Depends(get_db),
    token_info: dict | None = Depends(_verify_auth),
):
    """Bounded preflight: close the lite tail, then verify from a full anchor.

    When no usable fresh anchor exists, this queues (or joins) the durable full
    job and reports its id. It never holds the request open for the deep scan.
    """
    checkpoint: dict[str, object] = {"created": False, "row_count": 0}
    if not vault.sealed:
        from ..audit_mtree import create_audit_lite_checkpoint

        checkpoint = await create_audit_lite_checkpoint(
            db,
            actor=actor_display_name(token_info)
            if token_info is not None
            else "audit-preflight",
        )
        await db.commit()

    result = await verify_chain_incremental(db=db, token_info=token_info)
    response: dict[str, object] = {
        **result,
        "preflight_ready": result.get("evidence_intact") is True,
        "tail_checkpoint": checkpoint,
        "full_verification_job": None,
    }
    if response["preflight_ready"] is not True and result.get(
        "full_verification_required"
    ):
        from ..audit_verify_jobs import enqueue_audit_verify

        requested_by = (
            actor_display_name(token_info) if token_info is not None else "cidr"
        )
        job, created = await enqueue_audit_verify(requested_by)
        response["full_verification_job"] = {**job, "created": created}
    return response


@router.get("/verify/jobs/{job_id}")
async def read_verify_job(
    job_id: UUID,
    token_info: dict | None = Depends(_verify_auth),
):
    """Return durable status and, when complete, the full verification result."""
    from ..audit_verify_jobs import get_audit_verify_job

    job = await get_audit_verify_job(job_id)
    if job is None:
        raise HTTPException(404, "Audit verification job not found")
    return job


# --- MCP hub audit chain (OPTIONAL feature; vault_audit_mcp) -----------------
# Ingest + list + verify for the dedicated MCP tool-call chain. Emitted only by
# the opt-in MCP hub; these endpoints add nothing to the standalone stdio server.


class McpAuditEvent(BaseModel):
    backend: str = Field(..., max_length=64)
    tool: str = Field(..., max_length=128)
    target: str | None = Field(None, max_length=512)
    decision: str = Field(..., max_length=32)  # allowed | policy_denied | error
    hub: str | None = Field(None, max_length=64)  # self-declared source hub name
    detail: dict = Field(default_factory=dict)


@router.post("/mcp", status_code=201)
async def ingest_mcp_audit(
    body: McpAuditEvent,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_vault_token),
):
    """Append one MCP tool-call event to the chained MCP audit log.

    Auth = the calling AGENT's own bearer (any valid token; the authoritative ACL
    is that token's scope). ``actor`` and ``agent_token_id`` are derived from the
    AUTHENTICATED token, never from the body -- an agent cannot forge another's
    attribution. ``ip_address`` is the hub host as seen by the vault.
    """
    if body.decision not in ("allowed", "policy_denied", "error"):
        raise HTTPException(400, "decision must be allowed|policy_denied|error")
    await log_mcp_action(
        db,
        agent_token_id=token_info["id"],
        actor=actor_display_name(token_info),
        backend=body.backend,
        tool=body.tool,
        hub=body.hub,
        target=body.target,
        decision=body.decision,
        detail=body.detail,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "recorded"}


@router.get("/mcp")
async def list_mcp_audit(
    agent: str | None = Query(None, description="agent_token_id (uuid)"),
    backend: str | None = Query(None),
    decision: str | None = Query(None),
    hub: str | None = Query(None, description="originating hub name"),
    since: datetime | None = Query(None, description="ISO timestamp, inclusive"),
    until: datetime | None = Query(None, description="ISO timestamp, exclusive"),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("audit", "r")),
):
    """List MCP audit rows (chained, per-agent). Mirrors :func:`list_audit`."""
    vault.require_unsealed()

    params: dict = {"limit": limit, "offset": offset}
    where_parts: list[str] = []
    if agent:
        params["agent"] = agent
        where_parts.append("agent_token_id = CAST(:agent AS uuid)")
    if backend:
        params["backend"] = backend
        where_parts.append("backend = :backend")
    if decision:
        params["decision"] = decision
        where_parts.append("decision = :decision")
    if hub:
        params["hub"] = hub
        where_parts.append("hub = :hub")
    if since is not None:
        params["since"] = since
        where_parts.append("timestamp >= :since")
    if until is not None:
        params["until"] = until
        where_parts.append("timestamp < :until")

    base = """
        SELECT id, timestamp, agent_token_id, actor, hub, backend, tool, target,
               decision, detail, ip_address, signature, key_epoch, sig_alg,
               signer_fpr
        FROM vault_audit_mcp
    """
    if where_parts:
        base += " WHERE " + " AND ".join(where_parts)
    base += " ORDER BY timestamp ASC, id ASC LIMIT :limit OFFSET :offset"

    rows = (await db.execute(text(base), params)).fetchall()
    content_filtered = bool(agent or backend or decision or hub)

    if content_filtered:
        keyring, current_epoch, signer_pubs = {}, 0, {}
    else:
        keyring = await _load_audit_keyring_via_vault(db)
        current_epoch = await get_key_epoch(db)
        signer_pubs = await _load_signer_pubs(db)

    items = []
    prev_sig = ""
    chain_intact: bool | None = None if content_filtered else True

    if not content_filtered and rows:
        seed_row = (
            await db.execute(
                text(
                    "SELECT signature FROM vault_audit_mcp "
                    "WHERE signature != 'unsigned' "
                    "AND (timestamp, id) < (:ts0, CAST(:id0 AS uuid)) "
                    "ORDER BY timestamp DESC, id DESC LIMIT 1"
                ),
                {"ts0": rows[0].timestamp, "id0": str(rows[0].id)},
            )
        ).fetchone()
        if seed_row:
            prev_sig = seed_row.signature
        else:
            # No predecessor row: either genuinely the first entry ever, or the
            # oldest SURVIVING entry after a prune. The anchor distinguishes
            # them; without this the first page after a prune reports a
            # spurious break.
            listing_anchor = await latest_prune_anchor(db)
            if listing_anchor:
                prev_sig = listing_anchor["pruned_through_signature"]

    for r in rows:
        base_item = {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "agent_token_id": str(r.agent_token_id) if r.agent_token_id else None,
            "actor": r.actor,
            "hub": r.hub,
            "backend": r.backend,
            "tool": r.tool,
            "target": r.target,
            "decision": r.decision,
            "detail": r.detail if isinstance(r.detail, dict) else {},
            "ip_address": r.ip_address,
        }
        if r.signature == "unsigned":
            items.append({**base_item, "verified": False, "unsigned": True})
            continue
        if content_filtered:
            verified = None
        else:
            verified = await _row_verified(
                r,
                prev_sig,
                sealed=False,
                current_epoch=current_epoch,
                keyring=keyring,
                signer_pubs=signer_pubs,
                payload=_row_payload_mcp(r),
            )
            if not verified:
                chain_intact = False
            prev_sig = r.signature
        items.append({**base_item, "verified": verified})

    return {"items": items, "count": len(items), "chain_intact": chain_intact}


@router.get("/mcp/verify")
async def verify_mcp_chain(
    db: AsyncSession = Depends(get_db),
    token_info: dict | None = Depends(_verify_auth),
):
    """Full verification of the MCP audit chain. Mirrors :func:`verify_chain`."""
    sealed = vault.sealed
    with audit_verify_duration.time():
        rows = (
            await db.execute(
                text("""
                    SELECT id, timestamp, actor, hub, backend, tool, target,
                           decision, detail, signature, key_epoch, sig_alg,
                           signer_fpr
                    FROM vault_audit_mcp
                    ORDER BY timestamp ASC, id ASC
                """)
            )
        ).fetchall()

    signer_pubs = await _load_signer_pubs(db)
    keyring = {} if sealed else await _load_audit_keyring_via_vault(db)
    current_epoch = await get_key_epoch(db)
    await db.invalidate()

    prev_sig = ""
    unsigned_count = 0
    unverifiable_while_sealed = 0
    for i, r in enumerate(rows):
        if r.signature == "unsigned":
            unsigned_count += 1
            continue
        verified = await _row_verified(
            r,
            prev_sig,
            sealed=sealed,
            current_epoch=current_epoch,
            keyring=keyring,
            signer_pubs=signer_pubs,
            payload=_row_payload_mcp(r),
        )
        if verified is None:
            unverifiable_while_sealed += 1
            prev_sig = r.signature
            continue
        if not verified:
            try:
                from ..audit import _dispatch_critical_event

                await _dispatch_critical_event(
                    f"[critical] MCP audit chain broken at #{i} id={r.id} "
                    f"ts={r.timestamp.isoformat()}"
                )
            except Exception:
                pass
            return {
                "verified_by": _verified_by_worker(),
                "chain_intact": False,
                "total_entries": len(rows),
                "broken_at": i,
                "broken_id": str(r.id),
                "broken_timestamp": r.timestamp.isoformat(),
                "unsigned_entries": unsigned_count,
                "unverifiable_while_sealed": unverifiable_while_sealed,
            }
        prev_sig = r.signature

    return {
        "verified_by": _verified_by_worker(),
        "chain_intact": True,
        "total_entries": len(rows),
        "unsigned_entries": unsigned_count,
        "unverifiable_while_sealed": unverifiable_while_sealed,
    }


# File-based audit logs


class AuditEvidenceExportRequest(BaseModel):
    since: datetime | None = None
    until: datetime | None = None


def _export_timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _remove_export(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        logging.getLogger("rhorizon.audit_export").warning(
            "failed to remove temporary export %s", Path(path).name, exc_info=True
        )


@router.post("/export", response_class=FileResponse)
async def export_audit_evidence(
    body: AuditEvidenceExportRequest,
    request: Request,
    token_info: dict = Depends(require_permission("audit", "r")),
):
    """Build one signed tar.gz containing live and archived audit evidence."""
    vault.require_unsealed()
    now = datetime.now(timezone.utc)
    since = _export_timestamp(body.since)
    requested_until = _export_timestamp(body.until)
    until = min(requested_until, now) if requested_until is not None else now
    if since is not None and since >= until:
        raise HTTPException(400, "since must be earlier than the effective until")

    from ..audit_export import canonical_export_manifest, create_evidence_bundle

    actor = actor_display_name(token_info)
    async with async_session() as preflight_db:
        preflight = await audit_verify_preflight(db=preflight_db, token_info=token_info)
    if preflight.get("preflight_ready") is not True:
        job = preflight.get("full_verification_job")
        job_id = job.get("job_id") if isinstance(job, dict) else None
        suffix = f"; full verification job {job_id} was queued" if job_id else ""
        raise HTTPException(
            409,
            "Audit evidence is not currently verified"
            f" ({preflight.get('evidence_status', 'incomplete')}){suffix}; "
            "retry the export after verification completes",
        )
    verification_receipt = {
        "verification_scope": preflight.get("verification_scope"),
        "evidence_intact": preflight.get("evidence_intact"),
        "snapshot_stable": preflight.get("snapshot_stable"),
        "verification_anchor": preflight.get("verification_anchor"),
        "main_highwater_timestamp": preflight.get("main_highwater_timestamp"),
        "main_highwater_id": preflight.get("main_highwater_id"),
        "main_head_signature": preflight.get("main_head_signature"),
        "audit_lite_head_checkpoint_id": preflight.get("audit_lite_head_checkpoint_id"),
        "audit_lite_head_root": preflight.get("audit_lite_head_root"),
        "archive_head_digest": preflight.get("archive_head_digest"),
    }
    path: Path | None = None
    try:
        async with async_session() as export_db:
            # A repeatable snapshot plus the retention lock prevents rows from
            # moving from PostgreSQL into an archive halfway through export.
            # Normal audit inserts remain concurrent.
            await export_db.execute(
                text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            )
            export_lock = (
                await export_db.execute(
                    text(
                        "SELECT pg_try_advisory_xact_lock("
                        "hashtext('rhorizon:audit_export')) AS acquired"
                    )
                )
            ).one()
            if export_lock.acquired is not True:
                raise HTTPException(409, "Another audit evidence export is running")
            await export_db.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtext('rhorizon:audit_retention'))"
                )
            )
            path, manifest = await create_evidence_bundle(
                export_db,
                audit_dir=_audit_dir(),
                requested_by=actor,
                since=since,
                until=until,
                verification=verification_receipt,
            )
            await export_db.commit()

        manifest_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_export_manifest(manifest).encode("ascii")
            ).hexdigest()
        )
        async with async_session() as audit_db:
            await log_action(
                audit_db,
                actor=actor,
                action="audit_evidence_export",
                target=path.name,
                detail={
                    "schema": manifest["schema"],
                    "manifest_digest": manifest_digest,
                    "signer_fpr": manifest["signature"]["signer_fpr"],
                    "since": manifest["range"]["since"],
                    "until": manifest["range"]["until"],
                    "counts": manifest["counts"],
                },
                ip_address=get_client_ip(request),
            )
            await audit_db.commit()
    except asyncio.CancelledError:
        if path is not None:
            _remove_export(str(path))
        raise
    except HTTPException:
        if path is not None:
            _remove_export(str(path))
        raise
    except Exception as error:
        if path is not None:
            _remove_export(str(path))
        logging.getLogger("rhorizon.audit_export").exception(
            "audit evidence export failed"
        )
        raise HTTPException(
            503, "Audit evidence export failed; check protected server logs"
        ) from error

    stamp = until.strftime("%Y%m%dT%H%M%SZ")
    filename = f"rhorizon-audit-evidence-{stamp}.tar.gz"
    return FileResponse(
        path,
        media_type="application/gzip",
        filename=filename,
        headers={
            "X-Rhorizon-Audit-Signer": manifest["signature"]["signer_fpr"],
            "Cache-Control": "no-store",
        },
        background=BackgroundTask(_remove_export, str(path)),
    )


@router.get("/files")
async def list_audit_files(
    token_info: dict = Depends(require_permission("audit", "r")),
):
    """List audit log files with date, size, and compressed status."""
    vault.require_unsealed()

    audit_path = _audit_dir()
    files = []

    for f in sorted(audit_path.glob("audit-*.jsonl*")):
        name = f.name
        compressed = name.endswith(".gz")
        # Extract date from filename
        date_part = (
            name.replace("audit-", "").replace(".jsonl.gz", "").replace(".jsonl", "")
        )
        files.append(
            {
                "date": date_part,
                "filename": name,
                "size_bytes": f.stat().st_size,
                "compressed": compressed,
            }
        )

    return {"files": files, "retention_days": settings.audit_retention_days}


@router.get("/files/{date}")
async def read_audit_file(
    date: str,
    token_info: dict = Depends(require_permission("audit", "r")),
):
    """Read a specific day's audit log. Returns JSONL content."""
    vault.require_unsealed()

    if not _DATE_RE.match(date):
        raise HTTPException(400, "Date format: YYYY-MM-DD")

    audit_path = _audit_dir()

    # Try uncompressed first, then compressed
    plain = audit_path / f"audit-{date}.jsonl"
    compressed = audit_path / f"audit-{date}.jsonl.gz"

    if plain.exists():
        content = plain.read_text()
    elif compressed.exists():
        with gzip.open(compressed, "rt") as f:
            content = f.read()
    else:
        raise HTTPException(404, f"No audit log for {date}")

    # Parse JSONL to return structured data
    entries = []
    for line in content.strip().split("\n"):
        if line.strip():
            entries.append(json.loads(line))

    return {"date": date, "entries": entries, "count": len(entries)}


@router.delete("/files/{date}")
async def delete_audit_file(
    date: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Delete an audit log file. Admin only, must be older than retention period.

    Destroying audit evidence is itself a security-relevant action, so it is
    recorded in the chained audit log (the DB chain is untouched by the file
    delete - only this JSONL copy is removed).
    """
    vault.require_unsealed()

    if not _DATE_RE.match(date):
        raise HTTPException(400, "Date format: YYYY-MM-DD")

    # Check retention
    try:
        file_date = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(400, "Invalid date")

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)
    if file_date >= cutoff:
        days_left = (file_date - cutoff).days + 1
        raise HTTPException(
            403,
            f"Cannot delete: file is within {settings.audit_retention_days}-day "
            f"retention period ({days_left} day(s) remaining)",
        )

    audit_path = _audit_dir()
    deleted = False
    for suffix in (".jsonl", ".jsonl.gz"):
        path = audit_path / f"audit-{date}{suffix}"
        if path.exists():
            path.unlink()
            deleted = True

    if not deleted:
        raise HTTPException(404, f"No audit log for {date}")

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="delete_audit_file",
        target=date,
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"status": "deleted", "date": date}


def compress_old_files():
    """Compress audit files older than audit_compress_days. Called by reaper.

    Atomic-rename pattern (`gzip -> .gz.tmp -> rename -> .gz`) so a crash
    mid-compression leaves either the original .jsonl intact OR the final
    .gz, never a half-written .gz. Orphan .gz.tmp files from previous
    crashes are cleaned up at the start of the run.
    """
    audit_path = _audit_dir()
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_compress_days)

    # Cleanup orphan .gz.tmp files from previous crashes (best-effort)
    for tmp in audit_path.glob("audit-*.jsonl.gz.tmp"):
        try:
            tmp.unlink()
        except OSError:
            pass

    compressed = 0
    for f in audit_path.glob("audit-*.jsonl"):
        # Extract date
        date_str = f.name.replace("audit-", "").replace(".jsonl", "")
        try:
            file_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue

        if file_date < cutoff:
            gz_path = f.with_suffix(".jsonl.gz")
            tmp_path = f.with_suffix(".jsonl.gz.tmp")
            try:
                with open(f, "rb") as fin, gzip.open(tmp_path, "wb") as fout:
                    fout.writelines(fin)
                # Atomic on POSIX, either the rename succeeds and .gz is
                # the new file, or it fails and .gz.tmp is left for cleanup
                # on the next run.
                tmp_path.rename(gz_path)
                f.unlink()
                compressed += 1
            except OSError:
                # Clean up partial output on error; don't crash the loop
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    return compressed
