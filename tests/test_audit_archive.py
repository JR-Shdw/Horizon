# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Signed seals over the daily audit archive.

Per-entry chain signatures already catch a modified line and a line deleted
from the middle. They cannot catch a truncated tail -- a valid prefix says
nothing about how long the log was -- nor a deleted day. Those are exactly the
two that matter once the database is pruned and the archive becomes the only
copy, so they are what these tests pin.
"""

import gzip
import json
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
from api.app import audit_archive


def _entry(signature: str, action: str = "read_secret") -> str:
    return json.dumps(
        {
            "timestamp": "2026-08-01T10:00:00+00:00",
            "actor": "tester",
            "action": action,
            "target": "some/secret",
            "detail": {},
            "ip_address": "192.0.2.1",
            "signature": signature,
            "sig_alg": "ed25519",
            "signer_fpr": "ab" * 16,
        }
    )


def _write_archive(audit_dir, day: date, signatures: list[str], *, gz=False):
    plain, compressed = audit_archive.archive_file_paths(audit_dir, day)
    body = "".join(_entry(sig) + "\n" for sig in signatures)
    if gz:
        with gzip.open(compressed, "wt") as handle:
            handle.write(body)
    else:
        plain.write_text(body)


DAY = date(2026, 8, 1)


def test_a_seal_pins_content_count_and_endpoints(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1", "sig-2", "sig-3"])
    lines = audit_archive.read_archive_lines(tmp_path, DAY)
    detail = audit_archive.seal_detail(DAY, lines, previous_seal_digest=None)

    assert detail["entry_count"] == 3
    assert detail["first_signature"] == "sig-1"
    assert detail["last_signature"] == "sig-3"
    assert detail["content_digest"].startswith("sha256:")
    assert audit_archive.parse_seal_detail(detail)["day"] == DAY


def test_compression_does_not_break_a_seal(tmp_path):
    """The reaper gzips files past audit_compress_days. The seal is over
    LOGICAL content, so the storage form must not matter."""
    signatures = ["sig-1", "sig-2"]
    _write_archive(tmp_path, DAY, signatures)
    before = audit_archive.archive_digest(
        audit_archive.read_archive_lines(tmp_path, DAY)
    )

    audit_archive.archive_file_paths(tmp_path, DAY)[0].unlink()
    _write_archive(tmp_path, DAY, signatures, gz=True)
    after = audit_archive.archive_digest(
        audit_archive.read_archive_lines(tmp_path, DAY)
    )
    assert before == after


def test_a_truncated_tail_is_detected(tmp_path):
    """THE attack per-entry signatures cannot catch: what remains after
    truncation is a shorter, perfectly valid chain."""
    _write_archive(tmp_path, DAY, ["sig-1", "sig-2", "sig-3"])
    sealed = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )

    _write_archive(tmp_path, DAY, ["sig-1", "sig-2"])  # tail lopped off
    truncated = audit_archive.read_archive_lines(tmp_path, DAY)
    assert len(truncated) != sealed["entry_count"]
    assert audit_archive.archive_digest(truncated) != sealed["content_digest"]


def test_a_modified_line_is_detected(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1", "sig-2"])
    sealed = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    _write_archive(tmp_path, DAY, ["sig-1", "tampered"])
    assert (
        audit_archive.archive_digest(audit_archive.read_archive_lines(tmp_path, DAY))
        != sealed["content_digest"]
    )


def test_moving_a_newline_between_entries_changes_the_digest(tmp_path):
    """Length-prefixing each line: without it, concatenation is ambiguous and
    two different splittings could hash identically."""
    assert audit_archive.archive_digest(["ab", "c"]) != audit_archive.archive_digest(
        ["a", "bc"]
    )


def test_seals_chain_so_a_deleted_day_is_detected(tmp_path):
    """Deleting a whole day leaves no trace in per-entry signatures. Chaining
    each seal to its predecessor's digest pins the SEQUENCE of days."""
    _write_archive(tmp_path, DAY, ["sig-1"])
    first = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    day_two = date(2026, 8, 2)
    _write_archive(tmp_path, day_two, ["sig-2"])
    second = audit_archive.seal_detail(
        day_two,
        audit_archive.read_archive_lines(tmp_path, day_two),
        previous_seal_digest=first["content_digest"],
    )
    assert second["previous_seal_digest"] == first["content_digest"]
    assert first["previous_seal_digest"] is None


def test_durable_seal_must_match_its_signed_audit_detail(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1"])
    signed = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    signed_parsed = audit_archive.parse_seal_detail(signed)
    durable = dict(signed_parsed)
    assert audit_archive._seal_detail_matches(durable, signed_parsed) is True
    durable["content_digest"] = "sha256:" + "0" * 64
    assert audit_archive._seal_detail_matches(durable, signed_parsed) is False


@pytest.mark.asyncio
async def test_archive_verifier_rejects_a_broken_seal_sequence(tmp_path):
    day_two = DAY + timedelta(days=1)
    _write_archive(tmp_path, DAY, ["sig-1"])
    _write_archive(tmp_path, day_two, ["sig-2"])
    first = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    second = audit_archive.seal_detail(
        day_two,
        audit_archive.read_archive_lines(tmp_path, day_two),
        previous_seal_digest="sha256:" + "0" * 64,
    )

    class _Result:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

    class _Db:
        async def execute(self, query, params=None):
            sql = str(query)
            if "FROM vault_audit_archive_seals" in sql:
                return _Result(
                    [
                        SimpleNamespace(**{**first, "day": DAY}),
                        SimpleNamespace(**{**second, "day": day_two}),
                    ]
                )
            if params == {"action": audit_archive.SEAL_ACTION}:
                return _Result(
                    [
                        SimpleNamespace(id="seal-1", detail=first),
                        SimpleNamespace(id="seal-2", detail=second),
                    ]
                )
            return _Result([])

    status = await audit_archive.verify_archive_seals(_Db(), audit_dir=tmp_path)
    assert status["archive_intact"] is False
    assert status["archive_problems"] == [
        {
            "day": day_two.isoformat(),
            "problem": "previous_seal_digest_mismatch",
            "expected": first["content_digest"],
            "found": second["previous_seal_digest"],
        }
    ]


class _ArchiveVerifyResult:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class _ArchiveVerifyDb:
    def __init__(self, seals, signed_details=(), prune_detail=None):
        self.seals = seals
        self.signed_details = signed_details
        self.prune_detail = prune_detail

    async def execute(self, query, params=None):
        if "FROM vault_audit_archive_seals" in str(query):
            return _ArchiveVerifyResult(self.seals)
        if params == {"action": audit_archive.SEAL_ACTION}:
            return _ArchiveVerifyResult(
                [
                    SimpleNamespace(id=f"signed-{index}", detail=detail)
                    for index, detail in enumerate(self.signed_details)
                ]
            )
        if params == {"action": audit_archive.PRUNE_ANCHOR_ACTION}:
            rows = (
                [SimpleNamespace(detail=self.prune_detail)]
                if self.prune_detail is not None
                else []
            )
            return _ArchiveVerifyResult(rows)
        raise AssertionError((str(query), params))


def _durable_seal_row(detail, day=DAY):
    return SimpleNamespace(
        **{
            **detail,
            "day": day,
            "attested_by_audit_id": None,
        }
    )


@pytest.mark.asyncio
async def test_archive_verifier_requires_signed_attestation_before_prune(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1"])
    detail = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    status = await audit_archive.verify_archive_seals(
        _ArchiveVerifyDb([_durable_seal_row(detail)]), audit_dir=tmp_path
    )
    assert status["archive_intact"] is False
    assert status["archive_problems"] == [
        {
            "day": DAY.isoformat(),
            "problem": "signed_seal_attestation_mismatch",
        }
    ]


@pytest.mark.asyncio
async def test_archive_verifier_marks_legacy_pruned_attestation_incomplete(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1"])
    detail = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    legacy_prune = {
        "schema": audit_archive.PRUNE_SCHEMA,
        "pruned_through_signature": "sig-1",
        "pruned_through_day": DAY.isoformat(),
        "pruned_row_count": 1,
    }
    status = await audit_archive.verify_archive_seals(
        _ArchiveVerifyDb([_durable_seal_row(detail)], prune_detail=legacy_prune),
        audit_dir=tmp_path,
    )
    assert status["archive_intact"] is None
    assert status["archive_problems"][0]["problem"] == (
        "legacy_prune_has_no_archive_seal_anchor"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("archive_anchor", "problem"),
    [
        ({"schema": "wrong"}, "malformed_archive_prune_anchor"),
        (
            {
                "schema": audit_archive.ARCHIVE_PRUNE_ANCHOR_SCHEMA,
                "seal_count": 2,
                "head_day": DAY.isoformat(),
                "head_digest": "sha256:" + "0" * 64,
            },
            "archive_prune_anchor_mismatch",
        ),
    ],
)
async def test_archive_verifier_rejects_bad_prune_attestation(
    tmp_path, archive_anchor, problem
):
    _write_archive(tmp_path, DAY, ["sig-1"])
    detail = audit_archive.seal_detail(
        DAY, audit_archive.read_archive_lines(tmp_path, DAY), previous_seal_digest=None
    )
    prune = {
        "schema": audit_archive.PRUNE_SCHEMA,
        "pruned_through_signature": "sig-1",
        "pruned_through_day": DAY.isoformat(),
        "pruned_row_count": 1,
        "archive_seal_anchor": archive_anchor,
    }
    status = await audit_archive.verify_archive_seals(
        _ArchiveVerifyDb([_durable_seal_row(detail)], prune_detail=prune),
        audit_dir=tmp_path,
    )
    assert status["archive_intact"] is False
    assert status["archive_problems"][0]["problem"] == problem


def test_an_archive_missing_entries_is_refused_not_sealed(tmp_path):
    """File writes are best effort, so the archive can be short. Sealing it
    anyway would certify a gap as complete -- and that day would then become
    prunable, destroying the only remaining copy."""
    _write_archive(tmp_path, DAY, ["sig-1", "sig-3"])  # sig-2 never reached disk
    lines = audit_archive.read_archive_lines(tmp_path, DAY)
    with pytest.raises(audit_archive.ArchiveSealError, match="refusing to seal"):
        audit_archive._cross_check(DAY, lines, ["sig-1", "sig-2", "sig-3"])


def test_an_archive_that_diverges_from_the_database_is_refused(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1", "wrong"])
    lines = audit_archive.read_archive_lines(tmp_path, DAY)
    with pytest.raises(audit_archive.ArchiveSealError, match="diverges"):
        audit_archive._cross_check(DAY, lines, ["sig-1", "sig-2"])


def test_a_matching_archive_passes_the_cross_check(tmp_path):
    _write_archive(tmp_path, DAY, ["sig-1", "sig-2"])
    lines = audit_archive.read_archive_lines(tmp_path, DAY)
    audit_archive._cross_check(DAY, lines, ["sig-1", "sig-2"])


def test_an_empty_archive_cannot_be_sealed(tmp_path):
    with pytest.raises(ValueError, match="empty archive"):
        audit_archive.seal_detail(DAY, [], previous_seal_digest=None)


def test_a_line_without_a_signature_is_refused(tmp_path):
    plain, _ = audit_archive.archive_file_paths(tmp_path, DAY)
    plain.write_text(json.dumps({"actor": "x", "action": "y"}) + "\n")
    with pytest.raises(audit_archive.ArchiveSealError, match="no signature"):
        audit_archive.seal_detail(
            DAY,
            audit_archive.read_archive_lines(tmp_path, DAY),
            previous_seal_digest=None,
        )


def test_a_missing_archive_reads_as_none(tmp_path):
    assert audit_archive.read_archive_lines(tmp_path, DAY) is None


# --- pruning without breaking verification ---------------------------------


def test_the_anchor_is_what_lets_a_pruned_chain_verify():
    """Chain rows sign over their PREDECESSOR's signature. Delete the oldest
    rows and the first survivor references a signature that no longer exists,
    so a walk starting at "" reports a break at the seam. The anchor names that
    missing signature, so the walk resumes exactly where the data went.
    """

    # Model the walk: each row's "signature" is derived from the previous one.
    def chain(previous: str, payload: str) -> str:
        return f"sig({previous}|{payload})"

    whole = []
    previous = ""
    for entry in ("a", "b", "c", "d"):
        previous = chain(previous, entry)
        whole.append((entry, previous))

    # Prune the first two. The survivor 'c' signs over b's signature.
    survivors = whole[2:]
    anchor = whole[1][1]

    # Starting from "" fails at the seam...
    walked = ""
    assert chain(walked, survivors[0][0]) != survivors[0][1]

    # ...and starting from the anchor succeeds, for every survivor.
    walked = anchor
    for payload, expected in survivors:
        walked = chain(walked, payload)
        assert walked == expected


def test_deleting_beyond_the_anchor_is_still_detected():
    """The anchor excuses exactly what it names. If it did not, a prune would
    be a way to erase rows undetectably -- which is the whole risk."""

    def chain(previous: str, payload: str) -> str:
        return f"sig({previous}|{payload})"

    whole = []
    previous = ""
    for entry in ("a", "b", "c", "d"):
        previous = chain(previous, entry)
        whole.append((entry, previous))

    anchor = whole[1][1]  # claims: pruned through 'b'
    # ...but 'c' was ALSO deleted, which the anchor does not cover.
    survivors = whole[3:]
    assert chain(anchor, survivors[0][0]) != survivors[0][1]


@pytest.mark.asyncio
async def test_prune_refuses_when_nothing_is_sealed(tmp_path):
    """No seal means no proof the archive holds the rows, so nothing may go."""

    class _NoSeals:
        async def execute(self, *_a, **_kw):
            raise AssertionError("must not touch the chain with no seals")

    from api.app import audit_archive as archive

    async def no_seals(_db):
        return []

    original = archive.sealed_days
    archive.sealed_days = no_seals
    try:
        result = await archive.prune_archived_audit_rows(
            _NoSeals(), audit_dir=tmp_path, retention_days=30
        )
    finally:
        archive.sealed_days = original
    assert result["pruned_rows"] == 0
    assert result["reason"] == "no_seals"


def _seal_for(tmp_path, day, signatures):
    from api.app import audit_archive as archive

    _write_archive(tmp_path, day, signatures)
    lines = archive.read_archive_lines(tmp_path, day)
    return {
        "day": day,
        "entry_count": len(lines),
        "content_digest": archive.archive_digest(lines),
        "last_signature": signatures[-1],
    }


def test_prune_stops_at_a_day_whose_seal_no_longer_verifies(tmp_path):
    """A truncated or edited archive HALTS the prune rather than being skipped.

    Skipping would leave a hole no anchor can describe: verification would
    resume at the anchor and immediately meet a row chaining to something
    already deleted.
    """
    from api.app import audit_archive as archive

    day_one, day_two, day_three = date(2026, 1, 1), date(2026, 1, 2), date(2026, 1, 3)
    seals = {
        day_one: _seal_for(tmp_path, day_one, ["sig-1"]),
        day_two: _seal_for(tmp_path, day_two, ["sig-2"]),
        day_three: _seal_for(tmp_path, day_three, ["sig-3"]),
    }
    # Day two's archive is truncated AFTER sealing.
    _write_archive(tmp_path, day_two, [])
    archive.archive_file_paths(tmp_path, day_two)[0].write_text("")

    chosen = archive.select_prunable_days(
        seals, audit_dir=tmp_path, cutoff=date(2026, 6, 1), already_pruned=None
    )
    assert chosen == [day_one], "must stop at the bad day, not skip past it"


def test_prune_never_reaches_days_inside_the_retention_window(tmp_path):
    from api.app import audit_archive as archive

    old_day, recent = date(2026, 1, 1), date(2026, 5, 30)
    seals = {
        old_day: _seal_for(tmp_path, old_day, ["sig-1"]),
        recent: _seal_for(tmp_path, recent, ["sig-2"]),
    }
    chosen = archive.select_prunable_days(
        seals, audit_dir=tmp_path, cutoff=date(2026, 5, 2), already_pruned=None
    )
    assert chosen == [old_day]


def test_prune_skips_days_already_pruned(tmp_path):
    from api.app import audit_archive as archive

    day_one, day_two = date(2026, 1, 1), date(2026, 1, 2)
    seals = {
        day_one: _seal_for(tmp_path, day_one, ["sig-1"]),
        day_two: _seal_for(tmp_path, day_two, ["sig-2"]),
    }
    chosen = archive.select_prunable_days(
        seals, audit_dir=tmp_path, cutoff=date(2026, 6, 1), already_pruned=day_one
    )
    assert chosen == [day_two]


def test_a_missing_archive_file_halts_the_prune(tmp_path):
    """No file means no proof the rows survive anywhere. Deleting them would
    destroy the only remaining copy."""
    from api.app import audit_archive as archive

    day_one, day_two = date(2026, 1, 1), date(2026, 1, 2)
    seals = {
        day_one: _seal_for(tmp_path, day_one, ["sig-1"]),
        day_two: _seal_for(tmp_path, day_two, ["sig-2"]),
    }
    archive.archive_file_paths(tmp_path, day_two)[0].unlink()
    chosen = archive.select_prunable_days(
        seals, audit_dir=tmp_path, cutoff=date(2026, 6, 1), already_pruned=None
    )
    assert chosen == [day_one]


def test_retention_window_is_itself_the_observation_period(tmp_path):
    """A day cannot be pruned until it is past the window AND sealed AND its
    seal still verifies. Nothing recent is ever at risk, which is what makes
    enabling the feature survivable on a live vault."""
    from api.app import audit_archive as archive

    yesterday = date(2026, 5, 31)
    seals = {yesterday: _seal_for(tmp_path, yesterday, ["sig-1"])}
    # 30-day window: yesterday is nowhere near eligible.
    chosen = archive.select_prunable_days(
        seals,
        audit_dir=tmp_path,
        cutoff=date(2026, 6, 1) - timedelta(days=30),
        already_pruned=None,
    )
    assert chosen == []
