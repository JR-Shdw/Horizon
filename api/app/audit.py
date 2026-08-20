# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Audit logging with versioned Ed25519/HMAC chained signatures.

Author: shdw <horizon@resurgamus.com>
Project: Resurgamus Horizon - minimal AGPL-3.0 vault for infra automation.
License: AGPL-3.0-or-later - closed-source relicensing prohibited.
AI training: not authorized. TDM reservation per EU DSM directive (art. 4).
See: NOTICE, LICENSE-AI.md, /.well-known/tdmrep.json

Module identity (rhorizon _RH_TAG_1​):
build references kept stable across releases for chain correlation.

New mutation entries sign a canonical v2 representation of every immutable
stored field, prefixed by the previous signature. Historical v1 entries keep
their original actor/action/target/detail payload for compatibility.

Previous signature is ALWAYS read from DB - the audit chain is a
security invariant that must never depend on in-memory cache.
The cost is one indexed SELECT per log_action() (~0.1ms), which is
negligible compared to the crypto operations in the same request.

File logging: each entry is also appended to a daily JSONL file
in RHORIZON_AUDIT_DIR. Files are compressed (gzip) after 7 days
and read-only. Admin can only delete files older than 30 days.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .audit_identity import resolve_signer_fpr
from .audit_payload import (
    CURRENT_AUDIT_PAYLOAD_VERSION,
    audit_payload_v2,
    canonical_audit_detail,
)
from .config import settings
from .key_epoch import get_key_epoch
from .metrics import audit_sign_path, record_audit_event, seal_events
from .vault_state import vault

_log = logging.getLogger("rhorizon.audit")

_AUDIT_BUILD_ID = "34d23b63-2a67-4c01-a5f4-06726f59bf96"
_BUF_G6BPFNY4GPDK = 4096


def _audit_dir() -> Path:
    p = Path(settings.audit_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_file(entry: dict):
    """Append audit entry to daily JSONL file.

    Deliberately non-fatal: the database row is the authoritative copy and a
    full disk must not fail a vault operation. But NOT silent -- this used to
    log at debug, so a read-only mount or an exhausted filesystem dropped
    archive entries with nothing an operator would ever see, and the archive
    is what audit_archive seals and what survives a future database prune.
    Logged at error and counted, so the gap is visible while both copies still
    exist; audit_archive._cross_check then refuses to seal that day, which is
    what stops an incomplete archive being certified as complete.
    """
    try:
        # Day comes from the entry's own timestamp, which is the database
        # clock (chain_timestamp), NOT from this host's clock. Reading a
        # second, different clock here put a row written at 23:59:59.9
        # database-time into tomorrow's file whenever the API host ran
        # slightly ahead -- and _cross_check compares this file against the
        # database rows for that day, so the mismatch surfaced as a day that
        # could never be sealed.
        stamp = entry.get("timestamp")
        if not isinstance(stamp, datetime):
            stamp = datetime.now(timezone.utc)
        day = stamp.astimezone(timezone.utc).strftime("%Y-%m-%d")
        path = _audit_dir() / f"audit-{day}.jsonl"
        with open(path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        _log.error(
            "audit archive write FAILED; this entry is in the database but not "
            "in the archive, and its day cannot be sealed until reconciled",
            exc_info=True,
        )
        try:
            from .metrics import audit_archive_write_failures

            audit_archive_write_failures.inc()
        except Exception:
            pass


async def chain_timestamp(db: AsyncSession) -> datetime:
    """Wall-clock for one audit row, read from PostgreSQL.

    The database is the single clock for the chain, and that is deliberate:
    read order must reproduce write order, and the ordering key is this
    column (schema.sql documents clock_timestamp() as chosen for exactly
    that). Reading datetime.now() here instead made every API node its own
    clock. Single-node deployments never noticed; under HA three NTP-synced
    hosts still disagree by microseconds, so two correctly serialized writes
    could land with inverted timestamps and the verifier reported a false
    chain break. Measured on the 24h chaos run: 284us of inversion.

    Asking the database keeps ONE clock however many nodes write, and still
    yields the value before signing, which is what a v2 payload needs to
    bind the complete stored row.

    This function is the ONLY clock seam in the chain. Tests that place rows
    on a historical day (retention, prune, archive) monkeypatch it, because
    v2 binds the timestamp into the signature: a row cannot be backdated
    with an UPDATE afterwards without invalidating it.
    """
    value = (await db.execute(text("SELECT clock_timestamp()"))).scalar_one()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


async def log_action(
    db: AsyncSession,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
    critical: bool = False,
) -> str:
    """Write a chained, signed audit log entry (DB + file).

    Serializes concurrent writers cluster-wide via an advisory xact lock on
    `rhorizon:cluster:audit_chain`: without it, two hosts reading the same
    prev_signature and inserting in parallel fork the chain into divergent
    branches and `audit verify` flags it broken. The lock is xact-scoped
    (released on commit/rollback/crash); contention is negligible since audit
    writes are rare (token/secret CRUD + unseal, never reads).

    critical=True injects ``_critical: true`` into the detail JSON (inside the
    HMAC payload, so tamper-evident) and schedules a fire-and-forget
    notification fan-out (event "critical") to subscribed channels. Use for
    security-relevant actions worth same-second alerting (recovery-handle
    write, chain break, emergency rotation, emergency root-token mint).
    """
    if critical:
        # Inject before serialising so the marker is part of the
        # HMAC chain. Attacker who flips this bit post-hoc breaks
        # verify -- the lie is tamper-evident.
        detail = dict(detail or {})
        detail["_critical"] = True
    if detail is None:
        detail = {}
    if not isinstance(detail, dict):
        raise ValueError("audit detail must be a JSON object")
    detail_json = canonical_audit_detail(detail)

    # prev_sig is ALWAYS read from DB (never cached), chain integrity is
    # non-negotiable. Skip "unsigned" entries (written while sealed) so the
    # signed chain stays contiguous.
    prev_sig = ""
    signed = not vault.sealed
    if signed:
        # Advisory lock on the chain for this xact: serializes all writers
        # across all hosts, preventing chain forks.
        await db.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('rhorizon:cluster:audit_chain'))"
            )
        )
        # ORDER BY (timestamp DESC, id DESC), id is a deterministic tiebreaker
        # when two entries share the same NOW() (transaction_timestamp is
        # constant within a tx, so back-to-back inserts can collide at the
        # microsecond). Verify uses the mirror order (timestamp ASC, id ASC),
        # so writer and verifier agree on "previous entry" in every case.
        result = await db.execute(
            text(
                "SELECT signature FROM vault_audit "
                "WHERE signature != 'unsigned' "
                "ORDER BY timestamp DESC, id DESC LIMIT 1"
            )
        )
        row = result.fetchone()
        if row:
            prev_sig = row.signature

    # Generate immutable database fields before signing, then insert those exact
    # values. Letting PostgreSQL generate either value after signing would make
    # it impossible for v2 to bind the complete stored row.
    row_id = uuid4()
    row_timestamp = await chain_timestamp(db)
    key_epoch_val = await get_key_epoch(db)

    def payload_for(algorithm: str, fingerprint: str | None) -> str:
        return audit_payload_v2(
            row_id=row_id,
            timestamp=row_timestamp,
            actor=actor,
            action=action,
            target=target,
            detail=detail,
            ip_address=ip_address,
            key_epoch=key_epoch_val,
            sig_alg=algorithm,
            signer_fpr=fingerprint,
        )

    # Asymmetric (Ed25519) chain whenever the cluster has an audit identity,
    # else the legacy symmetric HMAC chain. sig_alg tags each row so
    # /audit/verify dispatches per entry (public-key verify for ed25519, the
    # per-epoch keyring for hmac). The master signs locally; a follower
    # delegates to the master over RPC and tags the row with the shared cluster
    # fpr, so the whole cluster writes ed25519 (a follower writing hmac would
    # reintroduce the per-epoch cross-host fragility ed25519 kills). The
    # audit_key / Ed25519 seed stay inside Rust.
    if not signed:
        signature, sig_alg, signer_fpr = "unsigned", "hmac", None
        audit_sign_path.labels(path="unsigned").inc()
    else:
        ed_fpr = await resolve_signer_fpr(db)
        if ed_fpr is not None:
            try:
                payload = payload_for("ed25519", ed_fpr)
                signature = await vault.audit_sign_identity(payload, prev_sig)
                sig_alg, signer_fpr = "ed25519", ed_fpr
                audit_sign_path.labels(
                    path="ed25519_local"
                    if vault.has_audit_identity
                    else "ed25519_delegated"
                ).inc()
            except Exception:
                # An identity exists but signing failed -- typically a master
                # mid-failover that has not reloaded the signer yet. Keep the
                # chain WRITABLE with hmac for this one entry rather than 500;
                # the hmac_fallback metric makes the (transient) mixing visible.
                _log.warning(
                    "audit_sign_identity failed; hmac fallback for one entry "
                    "(action=%s)",
                    action,
                    exc_info=True,
                )
                sig_alg, signer_fpr = "hmac", None
                signature = await vault.audit_sign(
                    payload_for(sig_alg, signer_fpr), prev_sig
                )
                audit_sign_path.labels(path="hmac_fallback").inc()
        else:
            sig_alg, signer_fpr = "hmac", None
            signature = await vault.audit_sign(
                payload_for(sig_alg, signer_fpr), prev_sig
            )
            audit_sign_path.labels(path="hmac").inc()

    try:
        await db.execute(
            text("""
                INSERT INTO vault_audit
                    (id, timestamp, actor, action, target, detail, ip_address,
                     signature, key_epoch, sig_alg, signer_fpr, payload_version)
                VALUES
                    (CAST(:id AS uuid), :timestamp, :actor, :action, :target,
                     CAST(:detail AS jsonb), :ip, :sig, :key_epoch, :sig_alg,
                     :signer_fpr, :payload_version)
            """),
            {
                "id": str(row_id),
                "timestamp": row_timestamp,
                "actor": actor,
                "action": action,
                "target": target,
                "detail": detail_json,
                "ip": ip_address,
                "sig": signature,
                "key_epoch": key_epoch_val,
                "sig_alg": sig_alg,
                "signer_fpr": signer_fpr,
                "payload_version": CURRENT_AUDIT_PAYLOAD_VERSION,
            },
        )
    except Exception:
        record_audit_event(action, success=False)
        raise

    # Append to daily file
    _write_file(
        {
            "id": str(row_id),
            "timestamp": row_timestamp.isoformat(),
            "actor": actor,
            "action": action,
            "target": target,
            "detail": detail or {},
            "ip_address": ip_address,
            "signature": signature,
            "sig_alg": sig_alg,
            "signer_fpr": signer_fpr,
            "key_epoch": key_epoch_val,
            "payload_version": CURRENT_AUDIT_PAYLOAD_VERSION,
        }
    )

    record_audit_event(action, success=True)

    if critical:
        # Fire-and-forget background dispatch : opens its own DB
        # session so it survives the calling request's transaction
        # lifecycle. If the outer transaction rolls back AFTER this
        # point the notification was already scheduled, surfacing a
        # spurious alert ; operators inspecting the audit chain will
        # find no matching row and discount it. The reverse race
        # (commit succeeds but notification dispatch fails) is logged
        # inside the dispatcher itself and never raises.
        try:
            import asyncio as _asyncio

            message = f"[critical] action={action} actor={actor}" + (
                f" target={target}" if target else ""
            )
            _asyncio.create_task(_dispatch_critical_event(message))
        except Exception:
            _log.warning(
                "critical notification dispatch could not be scheduled",
                exc_info=True,
            )
    return str(row_id)


async def log_mcp_action(
    db: AsyncSession,
    *,
    agent_token_id: str | None,
    actor: str,
    backend: str,
    tool: str,
    decision: str,
    hub: str | None = None,
    target: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Write a chained, signed row to the DEDICATED MCP audit chain (vault_audit_mcp).

    Same keyed signing as :func:`log_action` (ed25519-first, hmac fallback,
    key_epoch) so ``/audit/mcp/verify`` works while sealed and survives key
    rotation, but on a SEPARATE advisory-lock lineage
    (``rhorizon:cluster:audit_mcp_chain``) so high-volume MCP traffic never
    serializes behind secret/token CRUD. DB-only (no JSONL file), like
    vault_audit_lite. Emitted by the OPTIONAL MCP hub for every tool call
    (``allowed`` / ``policy_denied`` / ``error``). ``actor`` and ``agent_token_id``
    MUST come from the authenticated bearer, never client-supplied (anti-spoofing).
    ``hub`` is a self-declared source label (like backend/tool): signed for
    tamper-evidence, but not a trusted identity -- the bearer is.
    """
    detail_json = json.dumps(detail or {}, sort_keys=True)

    prev_sig = ""
    signed = not vault.sealed
    if signed:
        await db.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('rhorizon:cluster:audit_mcp_chain'))"
            )
        )
        result = await db.execute(
            text(
                "SELECT signature FROM vault_audit_mcp "
                "WHERE signature != 'unsigned' "
                "ORDER BY timestamp DESC, id DESC LIMIT 1"
            )
        )
        row = result.fetchone()
        if row:
            prev_sig = row.signature

    payload = (
        f"{actor}|{hub or ''}|{backend}|{tool}|{target or ''}|{decision}|{detail_json}"
    )
    if not signed:
        signature, sig_alg, signer_fpr = "unsigned", "hmac", None
        audit_sign_path.labels(path="unsigned").inc()
    else:
        ed_fpr = await resolve_signer_fpr(db)
        if ed_fpr is not None:
            try:
                signature = await vault.audit_sign_identity(payload, prev_sig)
                sig_alg, signer_fpr = "ed25519", ed_fpr
                audit_sign_path.labels(
                    path="ed25519_local"
                    if vault.has_audit_identity
                    else "ed25519_delegated"
                ).inc()
            except Exception:
                _log.warning(
                    "audit_sign_identity failed; hmac fallback for one MCP entry "
                    "(tool=%s)",
                    tool,
                    exc_info=True,
                )
                signature = await vault.audit_sign(payload, prev_sig)
                sig_alg, signer_fpr = "hmac", None
                audit_sign_path.labels(path="hmac_fallback").inc()
        else:
            signature = await vault.audit_sign(payload, prev_sig)
            sig_alg, signer_fpr = "hmac", None
            audit_sign_path.labels(path="hmac").inc()

    key_epoch_val = await get_key_epoch(db)

    await db.execute(
        text("""
            INSERT INTO vault_audit_mcp
                (agent_token_id, actor, hub, backend, tool, target, decision,
                 detail, ip_address, signature, key_epoch, sig_alg, signer_fpr)
            VALUES
                (CAST(:agent AS uuid), :actor, :hub, :backend, :tool, :target,
                 :decision, CAST(:detail AS jsonb), :ip, :sig, :key_epoch,
                 :sig_alg, :signer_fpr)
        """),
        {
            "agent": agent_token_id,
            "actor": actor,
            "hub": hub,
            "backend": backend,
            "tool": tool,
            "target": target,
            "decision": decision,
            "detail": detail_json,
            "ip": ip_address,
            "sig": signature,
            "key_epoch": key_epoch_val,
            "sig_alg": sig_alg,
            "signer_fpr": signer_fpr,
        },
    )


async def _dispatch_critical_event(message: str) -> None:
    """Open a fresh session for the bg notification dispatch so it survives the
    calling request's transaction lifecycle. Swallows all exceptions: /audit
    emission is the trail of record; a missed Matrix/email is recoverable from
    the chain itself.
    """
    try:
        from .database import async_session
        from .routes.notifications import dispatch_event

        async with async_session() as bg_db:
            await dispatch_event(bg_db, "critical", message)
    except Exception:
        _log.warning(
            "critical notification dispatch failed for: %s", message, exc_info=True
        )


def record_seal(trigger: str, *, notify: bool = True) -> None:
    """Instrument a seal transition.

    Bumps ``rhorizon_seal_events_total{trigger}`` and, when ``notify`` is
    set, fires a best-effort critical notification (Matrix/webhook/email).

    A sealing node is the expected fail-safe under overload/attack, but it
    must be SURFACED. Two complementary signals (see
    docs/howto/observability-alerts.md):

    - The ``rhorizon_vault_sealed`` gauge is the RELIABLE external alert --
      Prometheus scrapes it, so it fires even when the node crash-seals or is
      too busy to report itself.
    - This best-effort in-app notification is the cheap early ping on a
      *deliberate* defensive seal. It may be dropped if the node is sealing
      under enough distress to lose the dispatch -- that is acceptable; the
      gauge backstops it. "Trying costs nothing."

    Only pass ``notify=True`` for seals where the node STAYS sealed
    unexpectedly (e.g. a master-start rollback). Do NOT use it for the
    transient ``seal()->unseal()`` re-key pairs (failover promote, rekey
    roll-forward, detach/re-attach) -- those never leave the vault
    observably sealed and would be false alarms.
    """
    try:
        seal_events.labels(trigger=trigger).inc()
    except Exception:
        pass
    if not notify:
        return
    try:
        import asyncio as _asyncio

        _asyncio.create_task(
            _dispatch_critical_event(
                f"[critical] node sealed unexpectedly (trigger={trigger}). "
                "Expected fail-safe under overload/attack, but investigate why "
                "(load knee? brute-force? crash?) and re-unseal."
            )
        )
    except Exception:
        _log.warning("seal notification could not be scheduled", exc_info=True)


async def log_read(
    db: AsyncSession,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
):
    """Append-only access log for read operations (no chain, no lock).

    Companion to `log_action`. Use for high-frequency read paths
    (`get_secret`, `list_secrets`, `whoami`, ...) where chain integrity
    is not required on the request path. Periodic Merkle checkpoints commit
    completed windows into the signed mutation chain; only the current tail is
    awaiting integrity protection.

    Differences vs `log_action` :
      - writes to `vault_audit_lite` instead of `vault_audit`
      - no `pg_advisory_xact_lock('rhorizon:cluster:audit_chain')` -
        inserts run in parallel cluster-wide
      - no `SELECT prev_signature` round-trip to PG
      - no `audit_sign` master RPC call
      - no daily JSONL file write (file IO would re-introduce a
        serialisation point; reads land in PG only)
      - no `signature` column

    Net effect: ~5-10x throughput on read paths vs the chained `log_action`
    (the cluster-wide advisory lock was the bottleneck on read_secret).
    """
    if detail is None:
        detail = {}
    if not isinstance(detail, dict):
        raise ValueError("audit-lite detail must be a JSON object")
    detail_json = json.dumps(detail, sort_keys=True)
    try:
        await db.execute(
            text("""
                INSERT INTO vault_audit_lite
                    (actor, action, target, detail, ip_address)
                VALUES
                    (:actor, :action, :target, CAST(:detail AS jsonb), :ip)
            """),
            {
                "actor": actor,
                "action": action,
                "target": target,
                "detail": detail_json,
                "ip": ip_address,
            },
        )
    except Exception:
        record_audit_event(action, success=False)
        raise
    record_audit_event(action, success=True)
