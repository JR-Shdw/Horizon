# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail-safe edge coverage for the HA rekey envelope."""

from types import SimpleNamespace

import pytest
from api.app import cluster_rekey, key_epoch


class _Result:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class _Db:
    def __init__(self, rows=(), rollback_fails=False):
        self.rows = iter(rows)
        self.rollback_fails = rollback_fails
        self.rollbacks = 0

    async def execute(self, *_args, **_kwargs):
        return _Result(next(self.rows, None))

    async def rollback(self):
        self.rollbacks += 1
        if self.rollback_fails:
            raise RuntimeError("rollback failed")


@pytest.mark.asyncio
async def test_publish_rejects_wrong_bundle_size_and_missing_certificate(monkeypatch):
    short = bytearray(b"short")
    assert await cluster_rekey.publish_envelope(_Db(), short, 1) == 0
    assert short == bytearray(len(short))

    async def cluster_id(_db, _table, _key):
        return "cluster"

    monkeypatch.setattr(cluster_rekey, "_read_config", cluster_id)
    monkeypatch.setattr(
        cluster_rekey.cluster_cert, "load_cluster_cert", lambda *_a: None
    )
    bundle = bytearray(cluster_rekey.BUNDLE_LEN)
    assert await cluster_rekey.publish_envelope(_Db(), bundle, 1) == 0
    assert bundle == bytearray(cluster_rekey.BUNDLE_LEN)


@pytest.mark.asyncio
async def test_publish_failure_rolls_back_but_never_masks_rotation(monkeypatch):
    async def failed(*_args):
        raise RuntimeError("database")

    monkeypatch.setattr(cluster_rekey, "_read_config", failed)
    db = _Db(rollback_fails=True)
    bundle = bytearray(cluster_rekey.BUNDLE_LEN)
    assert await cluster_rekey.publish_envelope(db, bundle, 2) == 0
    assert db.rollbacks == 1
    assert bundle == bytearray(cluster_rekey.BUNDLE_LEN)


@pytest.mark.asyncio
async def test_consume_rejects_missing_cluster_verification_material(monkeypatch):
    async def epoch(_db):
        return 2

    values = iter(["cluster", None])

    async def config(*_args):
        return next(values)

    monkeypatch.setattr(key_epoch, "get_key_epoch", epoch)
    monkeypatch.setattr(cluster_rekey, "_read_config", config)
    monkeypatch.setattr(cluster_rekey, "vault", SimpleNamespace(key_epoch=1))
    shared = SimpleNamespace(blob=b"blob", sig=b"sig", signer_cert="cert")
    mine = SimpleNamespace(wrapped_k=b"wrapped")
    assert await cluster_rekey.consume_envelope(_Db([shared, mine]), "node") is None
