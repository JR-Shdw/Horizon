# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""The whole retention path, end to end, against a real chain.

Everything else about pruning is unit-tested in pieces: which days are
eligible, what a seal pins, that the anchor model resumes a walk. None of that
proves the thing that actually matters -- that after real rows are written,
sealed and DELETED, `/audit/verify` still returns a verified chain.

That is the claim retention rests on, and it is the one that destroys evidence
if it is wrong, so it is worth proving against the real endpoint rather than a
model.
"""

import gzip
import json
from datetime import date, datetime, timedelta, timezone

import pytest
from api.app import audit_archive
from api.app.audit import log_action, log_read
from api.app.audit_mtree import create_audit_lite_checkpoint
from api.app.database import async_session
from sqlalchemy import text


class _AuditClock:
    """Monotonic UTC clock used to model retention without editing signatures."""

    current = datetime.now(timezone.utc)

    @classmethod
    def set_day(cls, day: date) -> None:
        cls.current = datetime.combine(
            day, datetime.min.time(), tzinfo=timezone.utc
        ) + timedelta(hours=12)

    @classmethod
    def now(cls, tz=None):
        value = cls.current
        cls.current += timedelta(microseconds=1)
        if tz is None:
            return value.replace(tzinfo=None)
        return value.astimezone(tz)


async def _write_chain_rows(count: int, *, actor: str = "prune-e2e") -> None:
    async with async_session() as db:
        for index in range(count):
            await log_action(
                db,
                actor=actor,
                action="read_secret",
                target=f"prune-e2e/{index}",
                detail={"n": index},
            )
        await db.commit()


async def _write_lite_checkpoint(prefix: str, count: int = 2) -> dict:
    async with async_session() as db:
        for index in range(count):
            await log_read(
                db,
                actor="prune-lite",
                action="read_secret",
                target=f"{prefix}/{index}",
                detail={"n": index},
            )
        result = await create_audit_lite_checkpoint(
            db, actor="prune-lite-checkpoint", max_rows=1000
        )
        await db.commit()
    return result


async def _reset_archive_state() -> None:
    """Clear seals and prune anchors so a rerun starts from a known state.

    ALL seals, not just this day's: prune selection stops at the first day it
    cannot verify rather than skipping it (a gap is not something an anchor
    can describe), so one stale seal for a day whose archive is absent halts
    the prune entirely and this test would silently assert nothing.

    The seal table is DURABLE by design -- that is what lets it outlive a
    prune -- so a rerun otherwise finds the day already sealed and seals
    nothing.
    """
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_archive_seals"))
        await db.execute(text("DELETE FROM vault_audit_lite_archive_seals"))
        await db.execute(
            text("DELETE FROM vault_audit WHERE action IN (:seal, :anchor)"),
            {
                "seal": audit_archive.SEAL_ACTION,
                "anchor": audit_archive.PRUNE_ANCHOR_ACTION,
            },
        )
        await db.commit()


async def _chain_rows() -> list[tuple[str, str]]:
    async with async_session() as db:
        rows = (
            await db.execute(
                text(
                    "SELECT actor, signature FROM vault_audit "
                    "ORDER BY timestamp ASC, id ASC"
                )
            )
        ).fetchall()
    return [(r.actor, r.signature) for r in rows]


async def _write_database_day_archive(tmp_path, archive_day: date) -> int:
    """Materialize one test archive from the rows currently assigned to a day."""
    async with async_session() as db:
        start = datetime.combine(archive_day, datetime.min.time(), tzinfo=timezone.utc)
        rows = (
            await db.execute(
                text("""
                    SELECT id, actor, action, target, detail, ip_address,
                           signature, key_epoch, sig_alg, signer_fpr,
                           payload_version, timestamp
                    FROM vault_audit
                    WHERE timestamp >= :start AND timestamp < :end
                    ORDER BY timestamp ASC, id ASC
                """),
                {"start": start, "end": start + timedelta(days=1)},
            )
        ).fetchall()
    plain, _ = audit_archive.archive_file_paths(tmp_path, archive_day)
    plain.write_text(
        "".join(
            json.dumps(
                {
                    "id": str(row.id),
                    "timestamp": row.timestamp.isoformat(),
                    "actor": row.actor,
                    "action": row.action,
                    "target": row.target,
                    "detail": row.detail if isinstance(row.detail, dict) else {},
                    "ip_address": row.ip_address,
                    "signature": row.signature,
                    "key_epoch": row.key_epoch,
                    "sig_alg": row.sig_alg,
                    "signer_fpr": row.signer_fpr,
                    "payload_version": row.payload_version,
                }
            )
            + "\n"
            for row in rows
        )
    )
    return len(rows)


async def _verify(client, token: str) -> dict:
    response = await client.get(
        "/api/v1/vault/audit/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_a_pruned_chain_still_verifies(
    client, master_password, admin_token, tmp_path, monkeypatch
):
    """Write two days of chain, seal and prune the older one, then verify.

    The seam is the whole point: after the delete, the oldest surviving row
    signed over a signature that no longer exists. Without the anchor that
    reports a broken chain, which would make retention unusable.

    Two days matter. Pruning the ONLY day would also delete every row between
    the anchor point and the anchor itself, which is degenerate -- in a real
    deployment the pruned day is past the retention window and later days
    survive to chain onto.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_archive_state()
    async with async_session() as db:
        await db.execute(text("TRUNCATE vault_audit, vault_audit_lite"))
        await db.commit()

    from api.app import audit as audit_module
    from api.app.config import settings

    monkeypatch.setattr(audit_module, "datetime", _AuditClock)
    monkeypatch.setattr(settings, "audit_dir", str(tmp_path))
    old_day = date.today() - timedelta(days=400)
    second_old_day = date.today() - timedelta(days=200)

    _AuditClock.set_day(old_day)
    first_lite = await _write_lite_checkpoint("old-lite")
    assert first_lite["created"] is True

    baseline = await _verify(client, admin_token)
    assert baseline["chain_intact"] is True
    assert baseline["audit_lite_intact"] is True
    assert baseline["audit_lite_checkpoints"] == 1

    # The second generation is written with its original historical timestamp,
    # so payload-v2 remains valid; the test never rewrites a signed field.
    _AuditClock.set_day(second_old_day)
    await _write_chain_rows(4, actor="prune-recent")
    second_lite = await _write_lite_checkpoint("recent-lite")
    assert second_lite["created"] is True

    # Build the archive from the database, so the seal cross-check gets
    # exactly what it demands: the file holding every row of that day.
    assert await _write_database_day_archive(tmp_path, old_day) > 0

    async with async_session() as db:
        sealed = await audit_archive.seal_completed_archives(
            db, audit_dir=tmp_path, today=second_old_day, actor="prune-seal"
        )
        await db.commit()
    assert sealed["sealed_days"] == [old_day.isoformat()], sealed
    assert not sealed["refused"], sealed

    before = await _chain_rows()

    async with async_session() as db:
        pruned = await audit_archive.prune_archived_audit_rows(
            db,
            audit_dir=tmp_path,
            retention_days=30,
            today=second_old_day,
            actor="prune-anchor",
        )
        await db.commit()
    assert pruned["pruned_rows"] > 0, pruned
    assert pruned["pruned_lite_rows"] == 2, pruned
    assert pruned["pruned_through_day"] == old_day.isoformat()

    # Count rows still inside the pruned day rather than the total: the prune
    # ADDS an anchor as it removes rows, so the totals can coincide.
    async with async_session() as db:
        left = (
            await db.execute(
                text(
                    "SELECT count(*) AS n FROM vault_audit "
                    "WHERE timestamp < :boundary AND action <> :anchor"
                ),
                {
                    "boundary": datetime.combine(
                        old_day + timedelta(days=1),
                        datetime.min.time(),
                        tzinfo=timezone.utc,
                    ),
                    "anchor": audit_archive.PRUNE_ANCHOR_ACTION,
                },
            )
        ).fetchone()
    assert left[0] == 0, f"{left[0]} rows survived inside the pruned day"

    after = await _chain_rows()
    assert len(before) > 0
    assert any(actor == "prune-anchor" for actor, _ in after)
    assert any(actor == "prune-recent" for actor, _ in after), (
        "rows inside the retention window must be untouched"
    )

    # THE assertion: the surviving chain still verifies, from the anchor.
    verified = await _verify(client, admin_token)
    assert verified["chain_intact"] is True, verified
    assert verified["chain_anchored_at_day"] == old_day.isoformat(), verified
    assert verified["audit_lite_intact"] is True, verified
    assert verified["audit_lite_checkpoints"] == 2, verified
    assert verified["audit_lite_anchored_checkpoints"] == 1, verified
    assert verified["audit_lite_anchored_rows"] == 2, verified
    assert verified["audit_lite_checkpointed_rows"] == 4, verified
    assert verified["audit_lite_uncheckpointed_rows"] == 0, verified
    async with async_session() as db:
        live_lite = (
            await db.execute(text("SELECT count(*) FROM vault_audit_lite"))
        ).scalar()
    assert live_lite == 2

    # Repeat the complete operation across a later retention boundary. The
    # first prune anchor is now part of the newly archived prefix. The second
    # anchor must supersede it instead of leaving that old row live and making
    # verification consume the same signed history twice.
    _AuditClock.set_day(date.today())
    await _write_chain_rows(3, actor="prune-second-recent")
    third_lite = await _write_lite_checkpoint("second-recent-lite")
    assert third_lite["created"] is True
    assert await _write_database_day_archive(tmp_path, second_old_day) > 0

    async with async_session() as db:
        sealed_again = await audit_archive.seal_completed_archives(
            db, audit_dir=tmp_path, today=date.today(), actor="prune-seal-2"
        )
        await db.commit()
    assert sealed_again["sealed_days"] == [second_old_day.isoformat()], sealed_again
    assert not sealed_again["refused"], sealed_again

    async with async_session() as db:
        pruned_again = await audit_archive.prune_archived_audit_rows(
            db,
            audit_dir=tmp_path,
            retention_days=30,
            today=date.today(),
            actor="prune-anchor-2",
        )
        await db.commit()
    assert pruned_again["pruned_rows"] > 0, pruned_again
    assert pruned_again["pruned_lite_rows"] == 2, pruned_again
    assert pruned_again["pruned_through_day"] == second_old_day.isoformat()

    async with async_session() as db:
        anchors = (
            await db.execute(
                text(
                    "SELECT actor FROM vault_audit WHERE action = :action "
                    "ORDER BY timestamp, id"
                ),
                {"action": audit_archive.PRUNE_ANCHOR_ACTION},
            )
        ).fetchall()
    assert [row.actor for row in anchors] == ["prune-anchor-2"]

    verified_again = await _verify(client, admin_token)
    assert verified_again["chain_intact"] is True, verified_again
    assert verified_again["chain_anchored_at_day"] == second_old_day.isoformat(), (
        verified_again
    )
    assert verified_again["audit_lite_intact"] is True, verified_again
    assert verified_again["audit_lite_checkpoints"] == 3, verified_again
    assert verified_again["audit_lite_anchored_checkpoints"] == 2, verified_again
    assert verified_again["audit_lite_anchored_rows"] == 4, verified_again
    assert verified_again["audit_lite_checkpointed_rows"] == 6, verified_again
    assert verified_again["audit_lite_uncheckpointed_rows"] == 0, verified_again
    async with async_session() as db:
        live_lite = (
            await db.execute(text("SELECT count(*) FROM vault_audit_lite"))
        ).scalar()
    assert live_lite == 2

    # The HTTP endpoint uses the configured process archive directory; this
    # test intentionally uses tmp_path. Verify those files through the same
    # production archive verifier with the test directory supplied explicitly.
    async with async_session() as db:
        archive_again = await audit_archive.verify_archive_seals(db, audit_dir=tmp_path)
    assert archive_again["archive_intact"] is True, archive_again
    assert archive_again["archive_seals"] == 2, archive_again

    # The raw DB prefix is gone, so the archive is now the evidence. Editing
    # even one canonical row must make a full verification fail closed.
    lite_archives = sorted(tmp_path.glob("audit-lite-*.jsonl.gz"))
    assert len(lite_archives) == 2
    with gzip.open(lite_archives[0], "rt", encoding="utf-8") as handle:
        lines = handle.readlines()
    first = json.loads(lines[0])
    first["detail"] = {"tampered": True}
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":")) + "\n"
    with gzip.open(lite_archives[0], "wt", encoding="utf-8") as handle:
        handle.writelines(lines)
    tampered = await _verify(client, admin_token)
    assert tampered["audit_lite_intact"] is False, tampered
    assert tampered["audit_lite_broken_reason"] == "audit_lite_archive_broken"


@pytest.mark.asyncio
async def test_prune_refuses_a_signed_row_tampered_after_sealing(
    client, master_password, admin_token, tmp_path, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_archive_state()
    async with async_session() as db:
        await db.execute(text("TRUNCATE vault_audit, vault_audit_lite"))
        await db.commit()

    from api.app import audit as audit_module

    monkeypatch.setattr(audit_module, "datetime", _AuditClock)
    old_day = date.today() - timedelta(days=100)
    _AuditClock.set_day(old_day)
    await _write_chain_rows(1, actor="prune-tamper-victim")
    assert await _write_database_day_archive(tmp_path, old_day) == 1

    _AuditClock.set_day(date.today())
    async with async_session() as db:
        sealed = await audit_archive.seal_completed_archives(
            db, audit_dir=tmp_path, today=date.today(), actor="prune-seal"
        )
        await db.commit()
    assert sealed["sealed_days"] == [old_day.isoformat()]

    # IP is part of payload v2. The archive was legitimately sealed before the
    # edit, but retention must still re-authenticate the database prefix at the
    # irreversible deletion boundary.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit SET ip_address = '203.0.113.9' "
                "WHERE actor = 'prune-tamper-victim'"
            )
        )
        await db.commit()

    async with async_session() as db:
        refused = await audit_archive.prune_archived_audit_rows(
            db,
            audit_dir=tmp_path,
            retention_days=30,
            today=date.today(),
        )
        await db.commit()
    assert refused["pruned_rows"] == 0
    assert refused["reason"] == "audit_prefix_not_intact"
    assert refused["integrity"]["reason"] == "signature_mismatch"

    async with async_session() as db:
        remaining = (
            await db.execute(
                text(
                    "SELECT count(*) FROM vault_audit "
                    "WHERE actor = 'prune-tamper-victim'"
                )
            )
        ).scalar()
    assert remaining == 1


@pytest.mark.asyncio
async def test_prune_refuses_an_unsealed_day_inside_the_delete_prefix(
    client, master_password, admin_token, tmp_path, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_archive_state()
    async with async_session() as db:
        await db.execute(text("TRUNCATE vault_audit, vault_audit_lite"))
        await db.commit()

    from api.app import audit as audit_module

    monkeypatch.setattr(audit_module, "datetime", _AuditClock)
    missing_day = date.today() - timedelta(days=101)
    sealed_day = date.today() - timedelta(days=100)
    _AuditClock.set_day(missing_day)
    await _write_chain_rows(1, actor="unarchived-prefix-row")
    _AuditClock.set_day(sealed_day)
    await _write_chain_rows(1, actor="archived-prefix-row")
    assert await _write_database_day_archive(tmp_path, sealed_day) == 1

    _AuditClock.set_day(date.today())
    async with async_session() as db:
        sealed = await audit_archive.seal_completed_archives(
            db, audit_dir=tmp_path, today=date.today(), actor="prune-seal"
        )
        await db.commit()
    assert sealed["sealed_days"] == [sealed_day.isoformat()]

    async with async_session() as db:
        refused = await audit_archive.prune_archived_audit_rows(
            db,
            audit_dir=tmp_path,
            retention_days=30,
            today=date.today(),
        )
        await db.commit()
    assert refused["pruned_rows"] == 0
    assert refused["reason"] == "archive_row_count_mismatch"
    assert refused["database_rows"] == 2
    assert refused["archive_rows"] == 1


@pytest.mark.asyncio
async def test_deleting_from_the_middle_of_the_chain_is_detected(
    client, master_password, admin_token
):
    """Rows removed from the MIDDLE break the chain at the seam.

    Deliberately not the tail: a truncated tail leaves a shorter, perfectly
    valid chain and is undetectable by construction -- nothing in a valid
    prefix says how long the log was supposed to be. That is precisely why
    audit_archive seals record an entry COUNT, and why the prune anchor names
    the exact signature it excuses. This test pins the case the chain itself
    can catch.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _write_chain_rows(4, actor="prune-victim")
    # Rows AFTER the victims, so the victims are interior to the chain.
    await _write_chain_rows(3, actor="prune-survivor")

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_audit WHERE actor = :actor"),
            {"actor": "prune-victim"},
        )
        await db.commit()

    response = await client.get(
        "/api/v1/vault/audit/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["chain_intact"] is False, (
        "rows deleted from the middle with no anchor MUST be reported as a break"
    )


@pytest.mark.asyncio
async def test_a_truncated_tail_is_why_seals_record_a_count(
    client, master_password, admin_token
):
    """Documents the limit honestly: tail truncation is NOT detectable here.

    Kept as a test rather than a comment because it is the reason the archive
    seal stores entry_count and the prune anchor stores pruned_row_count. If
    this ever starts failing, the chain gained a property it did not have and
    those counters may be reconsidered.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _write_chain_rows(3, actor="prune-tail")

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_audit WHERE actor = :actor"),
            {"actor": "prune-tail"},
        )
        await db.commit()

    response = await client.get(
        "/api/v1/vault/audit/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    body = response.json()
    assert body["chain_intact"] is True, (
        "a truncated tail leaves a valid shorter chain -- if this fails, the "
        "chain now detects truncation and the seal counters can be revisited"
    )
