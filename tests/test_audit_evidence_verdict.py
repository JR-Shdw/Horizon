"""The combined audit verdict must not overstate incomplete verification."""

from datetime import datetime, timezone

import pytest
from api.app.routes.audit import _audit_snapshot_stable, _evidence_verdict


def _verdict(**overrides):
    values = {
        "chain_intact": True,
        "unsigned_entries": 0,
        "unverifiable_while_sealed": 0,
        "audit_lite_intact": True,
        "audit_lite_uncheckpointed_rows": 0,
        "archive_intact": True,
    }
    values.update(overrides)
    return _evidence_verdict(**values)


def test_complete_verified_evidence_is_intact():
    assert _verdict() == (True, "intact", [])


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"unsigned_entries": 1}, "unsigned_main_chain_entries"),
        (
            {"unverifiable_while_sealed": 1},
            "legacy_hmac_entries_unverifiable_while_sealed",
        ),
        ({"audit_lite_intact": None}, "audit_lite_not_verified"),
        ({"audit_lite_uncheckpointed_rows": None}, "audit_lite_tail_unknown"),
        (
            {"audit_lite_uncheckpointed_rows": 1},
            "audit_lite_tail_not_checkpointed",
        ),
        ({"archive_intact": None}, "archive_seals_not_verified"),
        ({"snapshot_stable": False}, "evidence_advanced_during_verify"),
    ],
)
def test_unverified_or_unprotected_evidence_is_incomplete(change, reason):
    assert _verdict(**change) == (False, "incomplete", [reason])


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"chain_intact": False}, "main_chain_broken"),
        ({"audit_lite_intact": False}, "audit_lite_checkpoint_broken"),
        ({"archive_intact": False}, "archive_seal_broken"),
    ],
)
def test_proven_tamper_is_broken(change, reason):
    assert _verdict(**change) == (False, "broken", [reason])


def _snapshot(**changes):
    timestamp = datetime(2026, 8, 16, tzinfo=timezone.utc)
    values = {
        "total_entries": 10,
        "main_highwater_id": "main-10",
        "main_highwater_timestamp": timestamp,
        "main_highwater_signature": "a" * 128,
        "lite_status": {"audit_lite_total_rows": 20},
        "archive_status": {
            "archive_seals": 1,
            "archive_head_day": "2026-08-15",
            "archive_head_digest": "sha256:" + "c" * 64,
        },
        "current_state": {
            "main_count": 10,
            "main_id": "main-10",
            "main_timestamp": timestamp,
            "main_signature": "a" * 128,
            "lite_count": 20,
            "archive_count": 1,
            "archive_head_day": "2026-08-15",
            "archive_head_digest": "sha256:" + "c" * 64,
        },
    }
    values.update(changes)
    return _audit_snapshot_stable(**values)


def test_snapshot_is_stable_only_when_both_heads_are_unchanged():
    assert _snapshot() is True


def test_snapshot_rejects_main_chain_append_between_phases():
    current = {
        "main_count": 11,
        "main_id": "new-checkpoint",
        "main_timestamp": datetime(2026, 8, 16, 0, 0, 1, tzinfo=timezone.utc),
        "main_signature": "b" * 128,
        "lite_count": 20,
        "archive_count": 1,
        "archive_head_day": "2026-08-15",
        "archive_head_digest": "sha256:" + "c" * 64,
    }
    assert _snapshot(current_state=current) is False


def test_snapshot_rejects_lite_append_after_checkpoint_verification():
    current = {
        "main_count": 10,
        "main_id": "main-10",
        "main_timestamp": datetime(2026, 8, 16, tzinfo=timezone.utc),
        "main_signature": "a" * 128,
        "lite_count": 21,
        "archive_count": 1,
        "archive_head_day": "2026-08-15",
        "archive_head_digest": "sha256:" + "c" * 64,
    }
    assert _snapshot(current_state=current) is False


def test_snapshot_rejects_archive_seal_append_after_file_verification():
    current = {
        "main_count": 10,
        "main_id": "main-10",
        "main_timestamp": datetime(2026, 8, 16, tzinfo=timezone.utc),
        "main_signature": "a" * 128,
        "lite_count": 20,
        "archive_count": 2,
        "archive_head_day": "2026-08-16",
        "archive_head_digest": "sha256:" + "d" * 64,
    }
    assert _snapshot(current_state=current) is False
