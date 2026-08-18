import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from api.app import audit_mtree
from api.app.audit import log_action, log_read
from api.app.audit_archive import PRUNE_ANCHOR_ACTION, PRUNE_SCHEMA
from api.app.audit_identity import ensure_audit_identity
from api.app.audit_mtree import (
    CHECKPOINT_ACTION,
    audit_lite_merkle_root,
    canonical_lite_row,
    create_audit_lite_checkpoint,
)
from api.app.database import async_session
from sqlalchemy import text


def _unit_row(**overrides):
    base = {
        "id": uuid4(),
        "timestamp": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "actor": "test-admin",
        "action": "read_secret",
        "target": "unit-secret",
        "detail": {"a": 1, "b": 2},
        "ip_address": "127.0.0.1",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


async def _read_secret(client, token: str, name: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    created = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": name, "value": "v"},
        headers=headers,
    )
    assert created.status_code in (200, 201), created.text
    read = await client.get(f"/api/v1/vault/secrets/{name}", headers=headers)
    assert read.status_code == 200, read.text


async def _checkpoint_once() -> dict:
    async with async_session() as db:
        result = await create_audit_lite_checkpoint(
            db,
            actor="test-mtree",
            max_rows=1000,
        )
        await db.commit()
    return result


async def log_lite_rows_for_anchor(count: int, *, prefix: str = "before-prune"):
    async with async_session() as db:
        for index in range(count):
            await log_read(
                db,
                actor="test-mtree",
                action="read_secret",
                target=f"{prefix}/{index}",
                detail={"n": index},
            )
        await db.commit()


async def _verify(client, token: str) -> dict:
    response = await client.get(
        "/api/v1/vault/audit/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert isinstance(body["verified_by"]["host"], str)
    assert isinstance(body["verified_by"]["pid"], int)
    return body


def test_lite_row_canonicalization_sorts_detail_keys():
    row_id = uuid4()
    r1 = _unit_row(id=row_id, detail={"b": 2, "a": 1})
    r2 = _unit_row(id=row_id, detail={"a": 1, "b": 2})
    r3 = _unit_row(id=row_id, detail={"a": 1, "b": 3})

    assert canonical_lite_row(r1) == canonical_lite_row(r2)
    assert audit_lite_merkle_root([r1]) == audit_lite_merkle_root([r2])
    assert audit_lite_merkle_root([r1]) != audit_lite_merkle_root([r3])
    with pytest.raises(ValueError, match="JSON object"):
        canonical_lite_row(_unit_row(detail=[]))


def test_mtree_time_merkle_and_parser_edge_cases():
    naive = datetime(2026, 1, 2, 3, 4, 5)
    assert audit_mtree._utc_iso(naive).endswith("Z")
    assert audit_mtree._parse_utc_iso("2026-01-02T03:04:05").tzinfo == timezone.utc
    assert audit_lite_merkle_root([]).startswith("sha256:")
    assert audit_lite_merkle_root([_unit_row(), _unit_row(), _unit_row()]).startswith(
        "sha256:"
    )
    with pytest.raises(ValueError, match="empty"):
        audit_mtree.checkpoint_detail([], previous_checkpoint_id=None)

    assert audit_mtree.parse_checkpoint_detail(None) is None
    assert audit_mtree.parse_checkpoint_detail({"schema": "wrong"}) is None
    assert (
        audit_mtree.parse_checkpoint_detail(
            {"schema": audit_mtree.CHECKPOINT_SCHEMA, "row_count": "bad"}
        )
        is None
    )
    row = _unit_row()
    detail = audit_mtree.checkpoint_detail([row], previous_checkpoint_id=None)
    assert audit_mtree.parse_checkpoint_detail({**detail, "row_count": 0}) is None
    assert audit_mtree.parse_checkpoint_detail({**detail, "merkle_root": "bad"}) is None


@pytest.mark.parametrize("row_count", range(0, 66))
def test_streaming_merkle_frontier_matches_batch_tree(row_count):
    rows = [_unit_row(target=f"row-{index}") for index in range(row_count)]
    frontier = audit_mtree._MerkleFrontier()
    for row in rows:
        frontier.add(audit_mtree.audit_lite_leaf_hash(row))
    assert frontier.count == row_count
    assert frontier.root() == audit_lite_merkle_root(rows)


class _UnitResult:
    def __init__(self, rows=(), scalar=None):
        self.rows = rows
        self.value = scalar

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def scalar(self):
        return self.value


class _UnitDb:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []

    async def execute(self, query, params=None):
        self.calls.append((str(query), params))
        return next(self.results)


@pytest.mark.asyncio
async def test_prune_without_new_checkpoint_carries_previous_lite_anchor(monkeypatch):
    previous_lite = {
        "schema": audit_mtree.LITE_PRUNE_ANCHOR_SCHEMA,
        "last_checkpoint_id": str(uuid4()),
        "to_timestamp": "2026-01-02T03:04:05Z",
        "to_id": str(uuid4()),
        "checkpoint_count": 2,
        "checkpointed_row_count": 9,
        "cumulative_merkle_root": "sha256:" + "a" * 64,
    }

    async def previous_anchor(_db):
        return {"audit_lite_anchor": previous_lite}

    monkeypatch.setattr("api.app.audit_archive.latest_prune_anchor", previous_anchor)
    db = _UnitDb([_UnitResult([])])
    carried = await audit_mtree.build_lite_prune_anchor(
        db, boundary=datetime(2026, 2, 1, tzinfo=timezone.utc)
    )
    assert carried == previous_lite


@pytest.mark.asyncio
async def test_prune_refuses_to_carry_malformed_previous_lite_anchor(monkeypatch):
    async def previous_anchor(_db):
        return {"audit_lite_anchor": {"schema": "wrong"}}

    monkeypatch.setattr("api.app.audit_archive.latest_prune_anchor", previous_anchor)
    with pytest.raises(RuntimeError, match="existing audit-lite prune anchor"):
        await audit_mtree.build_lite_prune_anchor(
            _UnitDb([]), boundary=datetime(2026, 2, 1, tzinfo=timezone.utc)
        )


@pytest.mark.asyncio
async def test_mtree_query_helpers_skip_invalid_checkpoint_and_apply_cursor():
    row = _unit_row()
    detail = audit_mtree.checkpoint_detail([row], previous_checkpoint_id=None)
    checkpoint_id = uuid4()
    db = _UnitDb(
        [
            _UnitResult(
                [
                    SimpleNamespace(id=uuid4(), detail={"invalid": True}),
                    SimpleNamespace(id=checkpoint_id, detail=detail),
                ]
            ),
            _UnitResult([row]),
        ]
    )
    last = await audit_mtree._last_checkpoint(db)
    assert last["audit_id"] == str(checkpoint_id)
    rows = await audit_mtree._fetch_lite_after(db, after=detail, limit=10)
    assert rows == [row]
    assert db.calls[1][1]["after_id"] == detail["to_id"]


@pytest.mark.asyncio
async def test_checkpoint_handles_disabled_limit_and_empty_window(monkeypatch):
    monkeypatch.setattr(audit_mtree.settings, "audit_lite_checkpoint_max_rows", 0)
    assert await audit_mtree.create_audit_lite_checkpoint(_UnitDb([])) == {
        "created": False,
        "row_count": 0,
    }

    async def no_checkpoint(_db):
        return None

    async def no_rows(_db, **_kwargs):
        return []

    monkeypatch.setattr(audit_mtree, "_last_checkpoint", no_checkpoint)
    monkeypatch.setattr(audit_mtree, "_fetch_lite_after", no_rows)
    monkeypatch.setattr(audit_mtree.settings, "audit_lite_checkpoint_max_rows", 10)
    db = _UnitDb([_UnitResult()])
    assert await audit_mtree.create_audit_lite_checkpoint(db) == {
        "created": False,
        "row_count": 0,
    }


@pytest.mark.asyncio
async def test_verify_mtree_reports_malformed_and_broken_link():
    malformed = SimpleNamespace(id=uuid4(), detail={"bad": True})
    db = _UnitDb([_UnitResult([malformed]), _UnitResult(), _UnitResult(scalar=1)])
    result = await audit_mtree.verify_audit_lite_checkpoints(db)
    assert result["audit_lite_broken_reason"] == "malformed_checkpoint_detail"

    row = _unit_row()
    detail = audit_mtree.checkpoint_detail([row], previous_checkpoint_id=str(uuid4()))
    broken = SimpleNamespace(id=uuid4(), detail=detail)
    db = _UnitDb([_UnitResult([broken]), _UnitResult(), _UnitResult(scalar=1)])
    result = await audit_mtree.verify_audit_lite_checkpoints(db)
    assert result["audit_lite_broken_reason"] == "previous_checkpoint_mismatch"


def _incremental_lite_anchor(**changes):
    anchor = {
        "row_count": 0,
        "checkpointed_rows": 0,
        "checkpoint_count": 0,
        "head_checkpoint_id": None,
        "highwater_timestamp": None,
        "highwater_id": None,
        "head_root": None,
    }
    anchor.update(changes)
    return anchor


@pytest.mark.asyncio
async def test_incremental_mtree_rejects_invalid_anchor_shapes():
    missing = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([]),
        anchor_lite={},
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert missing["audit_lite_broken_reason"] == (
        "invalid_verification_anchor_lite_state"
    )

    incoherent = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([]),
        anchor_lite=_incremental_lite_anchor(row_count=-1),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert incoherent["audit_lite_broken_reason"] == (
        "invalid_verification_anchor_lite_state"
    )


@pytest.mark.asyncio
async def test_incremental_mtree_reports_checkpoint_shape_failures(monkeypatch):
    row = _unit_row()
    checkpoint_id = uuid4()
    valid_detail = audit_mtree.checkpoint_detail([row], previous_checkpoint_id=None)

    malformed = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([_UnitResult([SimpleNamespace(id=checkpoint_id, detail={})])]),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert malformed["audit_lite_broken_reason"] == "malformed_checkpoint_detail"

    wrong_previous = {
        **valid_detail,
        "previous_checkpoint_id": str(uuid4()),
    }
    mismatch = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb(
            [_UnitResult([SimpleNamespace(id=checkpoint_id, detail=wrong_previous)])]
        ),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert mismatch["audit_lite_broken_reason"] == "previous_checkpoint_mismatch"

    anchor_checkpoint_id = str(uuid4())
    overlap_detail = {
        **valid_detail,
        "previous_checkpoint_id": anchor_checkpoint_id,
    }
    overlap = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb(
            [_UnitResult([SimpleNamespace(id=checkpoint_id, detail=overlap_detail)])]
        ),
        anchor_lite=_incremental_lite_anchor(
            row_count=1,
            checkpointed_rows=1,
            checkpoint_count=1,
            head_checkpoint_id=anchor_checkpoint_id,
            highwater_timestamp=audit_mtree._utc_iso(row.timestamp),
            highwater_id=str(row.id),
            head_root=audit_lite_merkle_root([row]),
        ),
        main_highwater_timestamp=row.timestamp,
        main_highwater_id=str(row.id),
    )
    assert overlap["audit_lite_broken_reason"] == (
        "checkpoint_overlaps_verification_anchor"
    )


@pytest.mark.asyncio
async def test_incremental_mtree_reports_window_and_root_failures(monkeypatch):
    row = _unit_row()
    checkpoint = SimpleNamespace(
        id=uuid4(),
        detail=audit_mtree.checkpoint_detail([row], previous_checkpoint_id=None),
    )

    async def no_rows(*_args, **_kwargs):
        return []

    monkeypatch.setattr(audit_mtree, "_fetch_lite_window", no_rows)
    count_mismatch = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([_UnitResult([checkpoint])]),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert count_mismatch["audit_lite_broken_reason"] == "row_count_mismatch"

    async def invalid_rows(*_args, **_kwargs):
        return [_unit_row(id=row.id, timestamp=row.timestamp, detail=[])]

    monkeypatch.setattr(audit_mtree, "_fetch_lite_window", invalid_rows)
    invalid = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([_UnitResult([checkpoint])]),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert invalid["audit_lite_broken_reason"] == "invalid_lite_detail"

    async def changed_rows(*_args, **_kwargs):
        return [_unit_row(id=row.id, timestamp=row.timestamp, detail={"changed": 1})]

    monkeypatch.setattr(audit_mtree, "_fetch_lite_window", changed_rows)
    changed = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([_UnitResult([checkpoint])]),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert changed["audit_lite_broken_reason"] == "merkle_root_mismatch"


@pytest.mark.asyncio
async def test_incremental_mtree_reconciles_counts_and_empty_tail(monkeypatch):
    async def count_three(_db):
        return 3

    monkeypatch.setattr(audit_mtree, "_count_lite", count_three)
    tail = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([_UnitResult([])]),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert tail["audit_lite_intact"] is True
    assert tail["audit_lite_uncheckpointed_rows"] == 3

    row = _unit_row()
    checkpoint = SimpleNamespace(
        id=uuid4(),
        detail=audit_mtree.checkpoint_detail([row], previous_checkpoint_id=None),
    )

    async def rows(*_args, **_kwargs):
        return [row]

    async def count_one(_db):
        return 1

    async def through(*_args, **_kwargs):
        return 0

    async def after(*_args, **_kwargs):
        return 1

    monkeypatch.setattr(audit_mtree, "_fetch_lite_window", rows)
    monkeypatch.setattr(audit_mtree, "_count_lite", count_one)
    monkeypatch.setattr(audit_mtree, "_count_lite_through", through)
    monkeypatch.setattr(audit_mtree, "_count_lite_after", after)
    changed = await audit_mtree.verify_audit_lite_incremental(
        _UnitDb([_UnitResult([checkpoint])]),
        anchor_lite=_incremental_lite_anchor(),
        main_highwater_timestamp=None,
        main_highwater_id=None,
    )
    assert changed["audit_lite_broken_reason"] == "historical_row_count_changed"


@pytest.mark.asyncio
async def test_audit_lite_checkpoint_is_signed_and_verified(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await ensure_audit_identity(db)
        await db.commit()
    await _read_secret(client, admin_token, f"mtree-ok-{uuid4().hex}")

    result = await _checkpoint_once()
    assert result["created"] is True
    assert result["row_count"] == 1
    assert result["merkle_root"].startswith("sha256:")

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT signature, detail FROM vault_audit "
                    "WHERE action = :action "
                    "ORDER BY timestamp DESC, id DESC LIMIT 1"
                ),
                {"action": CHECKPOINT_ACTION},
            )
        ).fetchone()
    assert row is not None
    assert row.signature != "unsigned"
    assert row.detail["row_count"] == 1

    body = await _verify(client, admin_token)
    assert body["chain_intact"] is True
    assert body["evidence_intact"] is True, (
        body["evidence_status"],
        body["evidence_incomplete_reasons"],
        body["audit_lite_broken_reason"],
        body["archive_problems"],
    )
    assert body["evidence_status"] == "intact"
    assert body["audit_lite_tail_protected"] is True
    assert body["audit_lite_intact"] is True
    assert body["audit_lite_checkpoints"] == 1
    assert body["audit_lite_checkpointed_rows"] == 1
    assert body["audit_lite_uncheckpointed_rows"] == 0
    assert body["snapshot_stable"] is True
    assert body["verification_anchor"] is not None

    # A new read after the anchor is visible immediately, but routine health is
    # honest about its uncheckpointed tail instead of treating the cached full
    # prefix as a blanket green verdict.
    await log_lite_rows_for_anchor(1, prefix="after-full-anchor")
    response = await client.get(
        "/api/v1/vault/audit/verify/incremental",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    incremental = response.json()
    assert incremental["chain_intact"] is True
    assert incremental["evidence_intact"] is False
    assert incremental["verification_scope"] == "incremental"
    assert (
        "audit_lite_tail_not_checkpointed" in incremental["evidence_incomplete_reasons"]
    )

    # Once that suffix is checkpointed, only the new row/window is re-hashed;
    # the signed historical prefix is not walked again.
    response = await client.post(
        "/api/v1/vault/audit/verify/preflight",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.text
    incremental = response.json()
    assert incremental["evidence_intact"] is True, incremental
    assert incremental["preflight_ready"] is True
    assert incremental["tail_checkpoint"]["created"] is True
    assert incremental["full_verification_job"] is None
    assert incremental["audit_lite_new_rows_verified"] == 1
    assert incremental["audit_lite_historical_rows_not_reread"] == 1


@pytest.mark.asyncio
async def test_checkpoint_waits_for_late_committing_read(
    client, master_password, admin_token
):
    """An older uncommitted insert cannot appear inside a signed window.

    The second insert commits first, reproducing the production interleaving
    that used to checkpoint around the first row and later report 928 rows for
    a window signed with 927. The checkpoint table lock must wait for the first
    transaction, then seal both rows in one stable window.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    async with async_session() as late_db:
        await log_read(
            late_db,
            actor="test-mtree",
            action="read_secret",
            target="late-commit",
        )

        async with async_session() as later_db:
            await log_read(
                later_db,
                actor="test-mtree",
                action="read_secret",
                target="later-commit",
            )
            await later_db.commit()

        checkpoint_started = asyncio.Event()

        async def checkpoint() -> dict:
            async with async_session() as checkpoint_db:
                checkpoint_started.set()
                result = await create_audit_lite_checkpoint(
                    checkpoint_db,
                    actor="test-mtree",
                    max_rows=1000,
                )
                await checkpoint_db.commit()
                return result

        task = asyncio.create_task(checkpoint())
        await checkpoint_started.wait()
        await asyncio.sleep(0.1)
        assert not task.done(), "checkpoint did not wait for the in-flight insert"

        await late_db.commit()
        result = await asyncio.wait_for(task, timeout=5)

    assert result["created"] is True
    assert result["row_count"] == 2

    body = await _verify(client, admin_token)
    assert body["chain_intact"] is True
    assert body["audit_lite_intact"] is True
    assert body["audit_lite_checkpointed_rows"] == 2
    assert body["audit_lite_uncheckpointed_rows"] == 0


@pytest.mark.asyncio
async def test_audit_lite_verify_detects_detail_tamper(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    name = f"mtree-tamper-{uuid4().hex}"
    await _read_secret(client, admin_token, name)
    assert (await _checkpoint_once())["created"] is True

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_lite "
                "SET detail = CAST(:detail AS jsonb) "
                "WHERE target = :target"
            ),
            {"target": name, "detail": '{"tampered": true}'},
        )
        await db.commit()

    body = await _verify(client, admin_token)
    assert body["chain_intact"] is True
    assert body["evidence_intact"] is False
    assert body["audit_lite_intact"] is False
    assert body["audit_lite_broken_reason"] == "merkle_root_mismatch"


@pytest.mark.asyncio
async def test_audit_lite_verify_detects_deleted_checkpointed_row(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    name = f"mtree-delete-{uuid4().hex}"
    await _read_secret(client, admin_token, name)
    assert (await _checkpoint_once())["created"] is True

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_audit_lite WHERE target = :target"),
            {"target": name},
        )
        await db.commit()

    body = await _verify(client, admin_token)
    assert body["chain_intact"] is True
    assert body["audit_lite_intact"] is False
    assert body["audit_lite_broken_reason"] == "row_count_mismatch"


@pytest.mark.asyncio
async def test_audit_lite_verify_detects_backdated_insert(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    name = f"mtree-backdate-{uuid4().hex}"
    await _read_secret(client, admin_token, name)
    assert (await _checkpoint_once())["created"] is True

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT timestamp FROM vault_audit_lite "
                    "WHERE target = :target LIMIT 1"
                ),
                {"target": name},
            )
        ).fetchone()
        await db.execute(
            text("""
                INSERT INTO vault_audit_lite
                    (id, timestamp, actor, action, target, detail, ip_address)
                VALUES
                    (CAST(:id AS uuid), :ts, 'attacker', 'read_secret',
                     'backdated', '{}'::jsonb, '127.0.0.1')
            """),
            {
                "id": str(uuid4()),
                "ts": row.timestamp - timedelta(seconds=1),
            },
        )
        await db.commit()

    body = await _verify(client, admin_token)
    assert body["chain_intact"] is True
    assert body["audit_lite_intact"] is False
    assert body["audit_lite_broken_reason"] == "checkpoint_gap_or_backdated_row"


@pytest.mark.asyncio
async def test_audit_lite_verify_reports_uncheckpointed_tail(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _read_secret(client, admin_token, f"mtree-tail-a-{uuid4().hex}")
    assert (await _checkpoint_once())["created"] is True

    await _read_secret(client, admin_token, f"mtree-tail-b-{uuid4().hex}")

    body = await _verify(client, admin_token)
    assert body["chain_intact"] is True
    assert body["evidence_intact"] is False
    assert body["evidence_status"] == "incomplete"
    assert "audit_lite_tail_not_checkpointed" in body["evidence_incomplete_reasons"]
    assert body["audit_lite_tail_protected"] is False
    assert body["audit_lite_intact"] is True
    assert body["audit_lite_checkpointed_rows"] == 1
    assert body["audit_lite_uncheckpointed_rows"] == 1


@pytest.mark.asyncio
async def test_all_pruned_checkpoints_continue_from_signed_lite_anchor(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await db.execute(text("TRUNCATE vault_audit, vault_audit_lite"))
        await db.commit()

    await log_lite_rows_for_anchor(2)
    first = await _checkpoint_once()
    assert first["created"] is True

    async with async_session() as db:
        lite_anchor = await audit_mtree.build_lite_prune_anchor(
            db, boundary=datetime.now(timezone.utc) + timedelta(days=1)
        )
        checkpoint = (
            await db.execute(
                text("SELECT id, signature FROM vault_audit WHERE action = :action"),
                {"action": CHECKPOINT_ACTION},
            )
        ).one()
        await log_action(
            db,
            actor="test-prune",
            action=PRUNE_ANCHOR_ACTION,
            target="vault_audit",
            detail={
                "schema": PRUNE_SCHEMA,
                "pruned_through_day": "2026-01-01",
                "pruned_through_signature": checkpoint.signature,
                "pruned_row_count": 1,
                "audit_lite_anchor": lite_anchor,
            },
        )
        await db.execute(
            text("DELETE FROM vault_audit WHERE id = :id"), {"id": checkpoint.id}
        )
        await db.commit()

    anchored = await _verify(client, admin_token)
    assert anchored["chain_intact"] is True, anchored
    assert anchored["audit_lite_intact"] is True, anchored
    assert anchored["audit_lite_checkpoints"] == 1
    assert anchored["audit_lite_anchored_checkpoints"] == 1
    assert anchored["audit_lite_checkpointed_rows"] == 2
    assert anchored["audit_lite_uncheckpointed_rows"] == 0

    async with async_session() as db:
        victim = (
            await db.execute(
                text(
                    "SELECT id, detail FROM vault_audit_lite "
                    "ORDER BY timestamp ASC, id ASC LIMIT 1"
                )
            )
        ).one()
        await db.execute(
            text(
                "UPDATE vault_audit_lite SET detail = CAST(:detail AS jsonb) "
                "WHERE id = :id"
            ),
            {"detail": '{"n":99}', "id": victim.id},
        )
        await db.commit()
    tampered = await _verify(client, admin_token)
    assert tampered["chain_intact"] is True
    assert tampered["audit_lite_intact"] is False
    assert tampered["audit_lite_broken_reason"] == "lite_prune_anchor_root_mismatch"
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_lite SET detail = CAST(:detail AS jsonb) "
                "WHERE id = :id"
            ),
            {"detail": '{"n":0}', "id": victim.id},
        )
        await db.commit()

    await log_lite_rows_for_anchor(1, prefix="after-prune")
    continued = await _checkpoint_once()
    assert continued["created"] is True
    final = await _verify(client, admin_token)
    assert final["chain_intact"] is True, final
    assert final["audit_lite_intact"] is True, final
    assert final["audit_lite_checkpoints"] == 2
    assert final["audit_lite_anchored_checkpoints"] == 1
    assert final["audit_lite_checkpointed_rows"] == 3
    assert final["audit_lite_uncheckpointed_rows"] == 0
