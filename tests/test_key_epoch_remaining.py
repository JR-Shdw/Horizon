# SPDX-License-Identifier: AGPL-3.0-or-later
"""Focused recovery-path coverage for the key-generation fence."""

from types import SimpleNamespace

import pytest
from api.app import key_epoch
from fastapi import HTTPException


class _Result:
    def __init__(self, *, row=None, scalar=None):
        self._row = row
        self._scalar = scalar

    def fetchone(self):
        return self._row

    def scalar(self):
        return self._scalar


class _Db:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []
        self.commits = 0

    async def execute(self, query, params=None):
        self.calls.append((str(query), params))
        return next(self.results)

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_raw_epoch_rejects_boolean_database_value():
    db = _Db([_Result(row=SimpleNamespace(value=True))])
    with pytest.raises(key_epoch.KeyEpochCorrupt):
        await key_epoch._read_key_epoch_raw(db)


@pytest.mark.asyncio
@pytest.mark.parametrize("require_sample", [False, True])
async def test_key_probe_empty_table_respects_required_sample(require_sample):
    db = _Db([_Result(row=None)])
    assert await key_epoch.keys_match_current_data(
        db, object(), require_sample=require_sample
    ) is (not require_sample)


@pytest.mark.asyncio
async def test_key_probe_reports_decrypt_success_and_failure(monkeypatch):
    row = SimpleNamespace(id="id", encrypted_key=b"cipher", nonce=b"nonce")
    calls = []
    monkeypatch.setattr(
        key_epoch,
        "decrypt_dek",
        lambda *args: calls.append(args),
    )
    assert await key_epoch.keys_match_current_data(_Db([_Result(row=row)]), "aes")
    assert calls[0][2:] == (None, "aes", key_epoch.dek_aad("id"))

    monkeypatch.setattr(
        key_epoch,
        "decrypt_dek",
        lambda *_args: (_ for _ in ()).throw(ValueError("wrong key")),
    )
    assert not await key_epoch.keys_match_current_data(_Db([_Result(row=row)]), "aes")


@pytest.mark.asyncio
@pytest.mark.parametrize("commit", [False, True])
async def test_stamp_node_generation_commit_control(commit):
    db = _Db([_Result()])
    await key_epoch.stamp_node_generation(db, "node", 7, commit=commit)
    assert db.calls[0][1] == {"e": 7, "u": "node"}
    assert db.commits == int(commit)


@pytest.mark.asyncio
async def test_rotation_lock_contention_is_retryable():
    db = _Db([_Result(scalar=False)])
    with pytest.raises(HTTPException) as exc:
        await key_epoch.require_generation_current(db, object())
    assert exc.value.status_code == 503
    assert exc.value.headers == {"Retry-After": "1"}
    assert "rotation in progress" in exc.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize(("matches", "expected"), [(True, 8), (False, 7)])
async def test_resolve_reconstruct_epoch_current_or_stale(
    monkeypatch, matches, expected
):
    async def current(_db):
        return 8

    async def probe(_db, _aes, **_kwargs):
        return matches

    monkeypatch.setattr(key_epoch, "get_key_epoch", current)
    monkeypatch.setattr(key_epoch, "keys_match_current_data", probe)
    assert await key_epoch.resolve_reconstruct_epoch(object(), object()) == expected


@pytest.mark.asyncio
async def test_resolve_reconstruct_epoch_before_first_rotation(monkeypatch):
    async def fresh(_db):
        return 0

    monkeypatch.setattr(key_epoch, "get_key_epoch", fresh)
    assert await key_epoch.resolve_reconstruct_epoch(object(), object()) == 0
