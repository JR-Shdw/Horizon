# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Bloc G - multi-worker invariants of the dual-context restore.

Closes three gaps left by tests/test_legacy_backup.py (single-worker
crypto), as raised by the operator 2026-05-20 evening :

  - test_restore_seal_disconnects_follower_then_reunseal_redistributes_share
        Simulates the cluster endgame of restore_backup : master
        stop_master_services + vault.seal() must tear down the RPC
        socket. A follower with an RPC client attached must fail-closed
        on the next call. The subsequent re-unseal must start a fresh
        master_rpc_server, KeyServer and redistribute a Shamir share
        to an attaching follower.

  - test_post_restore_unseal_mints_exactly_one_root_token
        The pending_restore_bootstrap flag set by restore_backup must
        trigger exactly ONE mint of a root-restore-<ts> token, and the
        flag must be DELETEd in the same transaction so a subsequent
        seal + unseal cycle does not duplicate the recovery root token.

The first test uses the real cluster wiring (cluster_real marker,
which disables the conftest IPC bypass). The second test goes through
the API and inspects vault_tokens + vault_config directly.
"""

import os

import pytest
from api.app.cluster import (
    WorkerState,
    register_worker,
    update_worker_state,
)
from api.app.cluster_setup import (
    attach_to_master,
    detach_from_master,
    start_master_services,
    stop_master_services,
)
from api.app.database import async_session
from api.app.vault_state import VaultState
from sqlalchemy import text


def _gen_keys():
    return {
        "hmac_key": os.urandom(32),
        "dek_key": os.urandom(32),
        "audit_key": os.urandom(32),
        "ha_wrap_key": os.urandom(32),
        "pki_wrap_key": os.urandom(32),
    }


@pytest.fixture(autouse=True)
async def _wipe_workers(setup_db):
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()


@pytest.mark.cluster_real
@pytest.mark.asyncio
async def test_restore_seal_disconnects_follower_then_reunseal_redistributes_share(
    monkeypatch,
):
    """Cluster endgame of restore_backup : master tears down RPC server,
    follower fails closed, next unseal restarts services and redistributes
    a Shamir share to a fresh attaching follower.
    """
    monkeypatch.setenv("HOSTNAME", "post-restore-host")
    master_pid = os.getpid()
    follower_pid_pre = 92001
    follower_pid_post = 92002

    # -- master + follower running --
    master = VaultState()
    master.unseal(_gen_keys())
    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=follower_pid_pre)

    follower_pre = VaultState()
    try:
        ok = await attach_to_master(async_session, follower_pre, pid=follower_pid_pre)
        assert ok is True
        assert follower_pre._rpc_client is not None
        assert follower_pre._cluster_share is not None

        sig_pre = await follower_pre.hmac_sha512_hex("pre-restore")
        assert sig_pre

        # -- simulate restore_backup endgame on master --
        async with async_session() as db:
            await stop_master_services(master, db, pid=master_pid)
        master.seal()

        # The master_rpc_server is torn down ; the follower's RPC client
        # still points at a now-dead socket. Any crypto-op must fail.
        with pytest.raises(Exception):
            await follower_pre.hmac_sha512_hex("post-seal-should-fail")
    finally:
        await detach_from_master(follower_pre)

    # -- simulate post-restore unseal, fresh master services --
    master.unseal(_gen_keys())
    async with async_session() as db:
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=follower_pid_post)

    follower_post = VaultState()
    try:
        ok = await attach_to_master(async_session, follower_post, pid=follower_pid_post)
        assert ok is True, "follower failed to re-attach to restarted master"
        assert follower_post._rpc_client is not None
        assert follower_post._cluster_share is not None, (
            "fresh follower did not receive a Shamir share after master restart"
        )

        sig_post = await follower_post.hmac_sha512_hex("post-restore")
        assert sig_post
        assert sig_post != sig_pre, (
            "post-restart hmac_key happens to equal pre-restart - test premise broken"
        )
    finally:
        await detach_from_master(follower_post)
        async with async_session() as db:
            await stop_master_services(master, db, pid=master_pid)
        master.seal()


@pytest.mark.asyncio
async def test_post_restore_unseal_mints_exactly_one_root_token(
    client, master_password
):
    """pending_restore_bootstrap must drive a single mint of root-restore-<ts>.
    The flag is DELETEd in the same transaction; a subsequent unseal cycle
    must NOT produce a second recovery root token.
    """
    from api.app.vault_state import vault

    if not vault.sealed:
        vault.seal()

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_tokens WHERE name LIKE 'root-restore-%'")
        )
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('pending_restore_bootstrap', 'true') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 200, r.text
    body1 = r.json()
    assert body1.get("bootstrap_kind") == "restore-recovery", body1
    assert body1.get("root_token"), body1

    async with async_session() as db:
        rr = await db.execute(
            text(
                "SELECT COUNT(*) FROM vault_config "
                "WHERE key = 'pending_restore_bootstrap'"
            )
        )
        assert rr.scalar_one() == 0, "pending_restore_bootstrap flag was not consumed"

        rr = await db.execute(
            text(
                "SELECT COUNT(*) FROM vault_tokens "
                "WHERE name LIKE 'root-restore-%' AND active"
            )
        )
        assert rr.scalar_one() == 1, "expected exactly one active root-restore-* token"

    vault.seal()
    r2 = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2.get("bootstrap_kind") != "restore-recovery", body2
    assert body2.get("root_token") is None, body2

    async with async_session() as db:
        rr = await db.execute(
            text(
                "SELECT COUNT(*) FROM vault_tokens "
                "WHERE name LIKE 'root-restore-%' AND active"
            )
        )
        assert rr.scalar_one() == 1, (
            "second unseal duplicated the recovery root token - "
            "single-mint invariant broken"
        )
