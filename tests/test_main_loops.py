"""Tests for the asyncio lifespan loops of api/app/main.py.

Targets: _reaper_loop, _shutdown_cluster, request-body middleware,
global lifespan, _init_cluster.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
from api.app import main as main_mod
from api.app.database import async_session
from api.app.vault_state import VaultSealedError
from api.app.vault_state import vault as vs
from sqlalchemy import text
from starlette.requests import Request


def test_sealed_rejection_log_is_sampled_and_escaped(monkeypatch, caplog):
    monkeypatch.setattr(main_mod, "_sealed_rejection_last_log_at", None)
    monkeypatch.setattr(main_mod, "_sealed_rejection_suppressed", 0)
    caplog.set_level(logging.WARNING, logger="rhorizon")

    assert main_mod._log_sealed_rejection(
        "GET", "/secret\nforged", "192.0.2.1", now=0.0
    )
    assert not main_mod._log_sealed_rejection("GET", "/second", "192.0.2.2", now=1.0)
    assert not main_mod._log_sealed_rejection("POST", "/third", "192.0.2.3", now=2.0)
    assert main_mod._log_sealed_rejection("HEAD", "/fourth", "192.0.2.4", now=10.0)

    messages = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("sealed: rejected")
    ]
    assert len(messages) == 2
    assert "\\n" in messages[0]
    assert len(messages[0].splitlines()) == 1
    assert "suppressed_since_previous=2" in messages[1]


@pytest.mark.asyncio
async def test_sealed_handler_classifies_head_as_read(monkeypatch):
    from api.app.metrics import sealed_op_attempts

    monkeypatch.setattr(main_mod, "_sealed_rejection_last_log_at", None)
    monkeypatch.setattr(main_mod, "_sealed_rejection_suppressed", 0)
    read_counter = sealed_op_attempts.labels(op="read")
    before = read_counter._value.get()
    request = Request(
        {
            "type": "http",
            "method": "HEAD",
            "path": "/api/v1/vault/status",
            "raw_path": b"/api/v1/vault/status",
            "query_string": b"",
            "headers": [],
            "client": ("192.0.2.10", 12345),
            "server": ("test", 80),
            "scheme": "http",
        }
    )

    response = await main_mod.sealed_handler(request, VaultSealedError())

    assert response.status_code == 503
    assert read_counter._value.get() - before == 1


async def _run_one_reaper_cycle(monkeypatch):
    """Run one cleanup body, then cancel at the next five-minute tick."""
    real_sleep = asyncio.sleep
    ticks = 0

    async def fast_sleep(delay):
        nonlocal ticks
        if delay == 300:
            ticks += 1
            if ticks > 1:
                raise asyncio.CancelledError
            return
        await real_sleep(0)

    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_sleep)
    task = asyncio.create_task(main_mod._reaper_loop())
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# _reaper_loop : exercises the reaper body via 1 cycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reaper_loop_purges_expired_tokens(monkeypatch, master_password):
    """Insert an expired token, run 1 reaper cycle, verify purge."""
    # Vault must be unsealed for the reaper (vs.sealed check)
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        salt_row = r.fetchone()
        if not salt_row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(salt_row.value)

    if vs.sealed:
        mk = derive_master_key(master_password.encode(), salt)
        vs.unseal(derive_keys(mk))

    # Insert an expired token
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, expires_at, created_by)
                VALUES (:n, :h, '{}'::jsonb,
                        NOW() - INTERVAL '1 hour', 'test')
                ON CONFLICT (name) WHERE active DO UPDATE
                    SET expires_at = NOW() - INTERVAL '1 hour'
            """),
            {"n": "expired-test-token", "h": "deadbeef" * 16},
        )
        await db.commit()

    # Patch sleep to make the loop fast (1st sleep=300s before 1st iter)
    real_sleep = asyncio.sleep

    async def fast_sleep(d):
        if d == 300:
            await real_sleep(0.05)
        else:
            await real_sleep(d)

    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_sleep)

    task = asyncio.create_task(main_mod._reaper_loop())
    await real_sleep(0.3)  # 1 cycle
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Verify the expired token was deleted
    async with async_session() as db:
        r = await db.execute(
            text("SELECT name FROM vault_tokens WHERE name = :n"),
            {"n": "expired-test-token"},
        )
        assert r.fetchone() is None


@pytest.mark.asyncio
async def test_reaper_purges_stale_workers(monkeypatch, master_password):
    """Reaper deletes stale vault_workers (> 5 min without heartbeat)."""
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        row = r.fetchone()
        if not row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(row.value)
    if vs.sealed:
        vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, last_heartbeat)
                VALUES ('reaper-test', 99999, 'sealed',
                        NOW() - INTERVAL '10 minutes')
                ON CONFLICT (hostname, pid) DO UPDATE
                    SET last_heartbeat = NOW() - INTERVAL '10 minutes'
            """)
        )
        await db.commit()

    real_sleep = asyncio.sleep

    async def fast_sleep(d):
        if d == 300:
            await real_sleep(0.05)
        else:
            await real_sleep(d)

    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_sleep)

    task = asyncio.create_task(main_mod._reaper_loop())
    await real_sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    async with async_session() as db:
        r = await db.execute(text("SELECT pid FROM vault_workers WHERE pid = 99999"))
        assert r.fetchone() is None  # stale worker reaped


@pytest.mark.asyncio
async def test_reaper_commits_soft_deleted_secret_purge(
    monkeypatch, client, master_password, admin_token
):
    """A secret-only cleanup must commit without another reaper event."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "reaper-only-secret", "value": "version-one"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    updated = await client.put(
        "/api/v1/vault/secrets/reaper-only-secret",
        json={"value": "version-two"},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text

    async with async_session() as db:
        secret_row = (
            await db.execute(
                text(
                    "UPDATE vault_secrets "
                    "SET deleted_at = NOW() - INTERVAL '2 days', "
                    "    purge_after = NOW() - INTERVAL '1 day' "
                    "WHERE name = 'reaper-only-secret' "
                    "RETURNING id, dek_id"
                )
            )
        ).one()
        version_dek_ids = (
            await db.execute(
                text(
                    "SELECT dek_id FROM vault_secret_versions "
                    "WHERE secret_id = CAST(:id AS uuid)"
                ),
                {"id": str(secret_row.id)},
            )
        ).scalars()
        candidate_dek_ids = {
            str(secret_row.dek_id),
            *(str(dek_id) for dek_id in version_dek_ids),
        }
        assert len(candidate_dek_ids) >= 2
        await db.commit()

    await _run_one_reaper_cycle(monkeypatch)

    async with async_session() as db:
        assert (
            await db.execute(
                text("SELECT 1 FROM vault_secrets WHERE name = 'reaper-only-secret'")
            )
        ).fetchone() is None
        assert (
            await db.execute(
                text("SELECT 1 FROM vault_dek WHERE id::text = ANY(:ids)"),
                {"ids": list(candidate_dek_ids)},
            )
        ).fetchall() == []


@pytest.mark.asyncio
async def test_reaper_commits_join_idempotency_purge(
    monkeypatch, client, master_password
):
    """A join-cache-only cleanup must commit without another reaper event."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_join_idempotency
                    (nonce, node_uuid, source_ip, response_json, expires_at)
                VALUES
                    ('reaper-expired-join', 'reaper-node', '192.0.2.10',
                     '{}', NOW() - INTERVAL '1 minute')
            """)
        )
        await db.commit()

    await _run_one_reaper_cycle(monkeypatch)

    async with async_session() as db:
        assert (
            await db.execute(
                text(
                    "SELECT 1 FROM vault_join_idempotency "
                    "WHERE nonce = 'reaper-expired-join'"
                )
            )
        ).fetchone() is None


@pytest.mark.asyncio
async def test_reaper_expires_prev_hmac_after_window(monkeypatch, master_password):
    """An out-of-window previous HMAC is deleted and cleared from memory."""
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        row = r.fetchone()
        if not row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(row.value)
    if vs.sealed:
        vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))

    # Setup: an active prev_hmac + a timestamp > 15 days
    vs.set_prev_hmac(b"\x00" * 32)
    old = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('prev_hmac_rotated_at', :v),
                       ('prev_hmac_key', 'dummy-encrypted-value')
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """),
            {"v": old},
        )
        await db.commit()

    await _run_one_reaper_cycle(monkeypatch)

    # Verify prev_hmac_rotated_at + prev_hmac_key are deleted
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT key FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
            )
        )
        assert r.fetchall() == []
        audit = await db.execute(
            text(
                "SELECT action FROM vault_audit "
                "WHERE action = 'prev_hmac_expired' "
                "ORDER BY timestamp DESC, id DESC LIMIT 1"
            )
        )
        assert audit.scalar_one() == "prev_hmac_expired"
    assert vs.has_prev_hmac is False


@pytest.mark.asyncio
async def test_reaper_prev_hmac_missing_timestamp_fails_closed(
    monkeypatch, master_password
):
    """Incomplete migration metadata is audited, deleted, and cleared."""
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        row = r.fetchone()
        if not row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(row.value)
    if vs.sealed:
        vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))

    vs.set_prev_hmac(b"\x00" * 32)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('prev_hmac_key', 'dummy-encrypted-value') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        )
        await db.execute(
            text("DELETE FROM vault_config WHERE key = 'prev_hmac_rotated_at'")
        )
        await db.commit()

    await _run_one_reaper_cycle(monkeypatch)

    async with async_session() as db:
        remaining = await db.execute(
            text(
                "SELECT key FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
            )
        )
        assert remaining.fetchall() == []
        audit = await db.execute(
            text(
                "SELECT action FROM vault_audit "
                "WHERE action = 'prev_hmac_corrupt' "
                "ORDER BY timestamp DESC, id DESC LIMIT 1"
            )
        )
        assert audit.scalar_one() == "prev_hmac_corrupt"
    assert vs.has_prev_hmac is False


@pytest.mark.asyncio
async def test_reaper_dek_key_staleness_metric(monkeypatch, master_password):
    """If dek_key_rotated_at is very old, the reaper logs a warning
    and the dek_key_stale metric is set to 1."""
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        row = r.fetchone()
        if not row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(row.value)
    if vs.sealed:
        vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))

    monkeypatch.setattr(main_mod.settings, "dek_key_lazy_check", True)
    monkeypatch.setattr(main_mod.settings, "dek_key_max_age_days", 1)  # 1 day

    # Insert a very old dek_key_rotated_at (10 days)
    old = datetime.now(timezone.utc) - timedelta(days=10)
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('dek_key_rotated_at', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": old.isoformat()},
        )
        await db.commit()

    real_sleep = asyncio.sleep

    async def fast_sleep(d):
        if d == 300:
            await real_sleep(0.05)
        else:
            await real_sleep(d)

    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_sleep)

    task = asyncio.create_task(main_mod._reaper_loop())
    await real_sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Cleanup
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_config WHERE key = 'dek_key_rotated_at'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_reaper_dek_key_staleness_handles_bad_timestamp(
    monkeypatch, master_password, caplog
):
    """A non-ISO marker alerts fail-closed without crashing the reaper."""
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        row = r.fetchone()
        if not row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(row.value)
    if vs.sealed:
        vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))

    monkeypatch.setattr(main_mod.settings, "dek_key_lazy_check", True)

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('dek_key_rotated_at', 'not-an-iso-date')
                ON CONFLICT (key) DO UPDATE SET value = 'not-an-iso-date'
            """)
        )
        await db.commit()

    real_sleep = asyncio.sleep

    async def fast_sleep(d):
        if d == 300:
            await real_sleep(0.05)
        else:
            await real_sleep(d)

    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_sleep)

    with caplog.at_level("WARNING", logger="rhorizon"):
        task = asyncio.create_task(main_mod._reaper_loop())
        await real_sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    from api.app import metrics as _m

    assert _m.dek_key_stale._value.get() == 1
    assert _m.dek_key_age_seconds._value.get() == -1
    assert "rotation timestamp is malformed" in caplog.text

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_config WHERE key = 'dek_key_rotated_at'")
        )
        await db.commit()


@pytest.mark.parametrize(
    ("raw_value", "expected_reason"),
    [
        (None, "missing"),
        ("2026-07-27T12:00:00", "timezone_missing"),
        ("not-an-iso-date", "malformed"),
        ("2026-07-27T12:10:01+00:00", "future"),
    ],
)
def test_observe_dek_key_age_invalid_metadata_fails_closed(
    monkeypatch, caplog, raw_value, expected_reason
):
    from api.app import metrics as _m

    _m.dek_key_stale.set(0)
    _m.dek_key_age_seconds.set(123)
    now = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)

    with caplog.at_level("WARNING", logger="rhorizon"):
        main_mod._observe_dek_key_age(raw_value, now)

    assert _m.dek_key_stale._value.get() == 1
    assert _m.dek_key_age_seconds._value.get() == -1
    assert f"rotation timestamp is {expected_reason}" in caplog.text


def test_observe_dek_key_age_tolerates_small_clock_skew(monkeypatch):
    from api.app import metrics as _m

    monkeypatch.setattr(main_mod.settings, "dek_key_max_age_days", 1)
    now = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)

    main_mod._observe_dek_key_age("2026-07-27T12:04:59+00:00", now)

    assert _m.dek_key_stale._value.get() == 0
    assert _m.dek_key_age_seconds._value.get() == 0


@pytest.mark.asyncio
async def test_reaper_loop_skips_when_sealed(monkeypatch):
    """Vault sealed -> reaper continues (but skips the main body)."""
    if not vs.sealed:
        vs.seal()

    real_sleep = asyncio.sleep

    async def fast_sleep(d):
        if d == 300:
            await real_sleep(0.05)
        else:
            await real_sleep(d)

    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_sleep)

    task = asyncio.create_task(main_mod._reaper_loop())
    await real_sleep(0.2)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # No assertion, the test passes if there is no crash in sealed mode


# ---------------------------------------------------------------------------
# _shutdown_cluster : swallows DB errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shutdown_cluster_swallows_errors(monkeypatch, caplog):
    """If deregister_worker raises, _shutdown_cluster does not propagate."""
    from api.app import cluster as cluster_mod

    async def boom(db):
        raise RuntimeError("db down")

    monkeypatch.setattr(cluster_mod, "deregister_worker", boom)
    # Must not raise
    await main_mod._shutdown_cluster()
    assert "cluster shutdown deregister failed" in caplog.text


@pytest.mark.asyncio
async def test_cancel_background_tasks_awaits_cleanup():
    cleanup_finished = asyncio.Event()

    async def background():
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_finished.set()

    task = asyncio.create_task(background(), name="cleanup-test")
    await asyncio.sleep(0)
    await main_mod._cancel_background_tasks([task])

    assert cleanup_finished.is_set()
    assert task.cancelled()


@pytest.mark.asyncio
async def test_stop_local_cluster_services_detaches_follower(monkeypatch):
    from api.app import cluster_setup

    calls = []

    async def fake_stop(vault, db):
        calls.append((vault, db))

    detached = []
    monkeypatch.setattr(cluster_setup, "stop_master_services", fake_stop)
    monkeypatch.setattr(vs, "detach_rpc_client", lambda: detached.append(True))

    await main_mod._stop_local_cluster_services()

    assert calls == [(vs, None)]
    assert detached == [True]


@pytest.mark.asyncio
async def test_init_rust_api_custody_builds_attaches_and_monitors(monkeypatch):
    from api.app import custody_routing, rust_custody_backend, socket_paths

    pool = object()
    calls = []
    stopped = asyncio.Event()

    monkeypatch.setattr(socket_paths, "runtime_dir", lambda: "/run/test-rhorizon")
    monkeypatch.setattr(
        main_mod.settings,
        "custodian_token_file",
        "/run/test-rhorizon/token",
    )
    monkeypatch.setattr(main_mod.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(main_mod.settings, "rust_custodian_threshold", 2)
    monkeypatch.setattr(
        main_mod.settings, "rust_custody_maintenance_interval_secs", 7.0
    )

    def build(**kwargs):
        calls.append(("build", kwargs))
        return pool

    async def attach(candidate, vault, *, session_factory):
        calls.append(("attach", candidate, vault, session_factory))
        return True

    async def maintain(candidate, vault, *, session_factory, interval_seconds):
        calls.append(("maintain", candidate, vault, session_factory, interval_seconds))
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(rust_custody_backend, "build_rust_custodian_pool", build)
    monkeypatch.setattr(
        rust_custody_backend,
        "configure_rust_custody_pool",
        lambda value: calls.append(("configure", value)),
    )
    monkeypatch.setattr(
        rust_custody_backend,
        "wire_rust_custody_recovery",
        lambda *args, **kwargs: calls.append(("wire", args, kwargs)),
    )
    monkeypatch.setattr(rust_custody_backend, "attach_reconciled_rust_custody", attach)
    # The maintenance loop lives in custody_routing now: it is a ROUTING
    # decision (which worker on this node may reopen the pool), not a backend
    # detail. Patch it where main.py imports it from.
    monkeypatch.setattr(custody_routing, "run_custody_routing", maintain)

    tasks = await main_mod._init_rust_api_custody()
    await asyncio.sleep(0)
    await main_mod._cancel_background_tasks(tasks)

    assert stopped.is_set()
    assert calls[0] == (
        "build",
        {
            "runtime_directory": "/run/test-rhorizon",
            "control_token_file": "/run/test-rhorizon/token",
            "slots": 3,
            "threshold": 2,
        },
    )
    assert ("configure", pool) in calls
    assert any(call[0] == "attach" for call in calls)
    assert any(call[0] == "maintain" and call[-1] == 7.0 for call in calls)


# ---------------------------------------------------------------------------
# limit_request_body middleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_rejects_oversized_body(client):
    """POST with Content-Length > max_body_bytes -> 413."""
    huge = "x" * 100
    r = await client.post(
        "/api/v1/vault/secrets/",
        headers={
            "Authorization": "Bearer rh_invalid",
            "Content-Length": "999999999",  # > 1 MB default
        },
        content=huge,
    )
    assert r.status_code == 413
    assert "max_bytes" in r.json()


@pytest.mark.asyncio
async def test_middleware_rejects_streamed_oversized_body(monkeypatch):
    """POST without explicit Content-Length -> limit applied while reading chunks."""
    from api.app.config import settings
    from api.app.main import RequestBodyLimitMiddleware

    monkeypatch.setattr(settings, "max_body_bytes", 32)

    async def app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.request" and not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = iter(
        [
            {
                "type": "http.request",
                "body": b'{"password":"',
                "more_body": True,
            },
            {"type": "http.request", "body": b"x" * 64, "more_body": True},
            {"type": "http.request", "body": b'"}', "more_body": False},
        ]
    )
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(app)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/vault/unseal",
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
        send,
    )

    start = next(msg for msg in sent if msg["type"] == "http.response.start")
    body = next(msg for msg in sent if msg["type"] == "http.response.body")
    assert start["status"] == 413
    assert b'"max_bytes":32' in body["body"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "detail"),
    [
        (
            [(b"content-length", b"1"), (b"content-length", b"1")],
            b"duplicate Content-Length",
        ),
        ([(b"content-length", b"-1")], b"invalid Content-Length"),
        ([(b"content-length", b"+1")], b"invalid Content-Length"),
        ([(b"content-length", b"abc")], b"invalid Content-Length"),
        (
            [
                (b"content-length", b"1"),
                (b"transfer-encoding", b"chunked"),
            ],
            b"Content-Length conflicts with Transfer-Encoding",
        ),
    ],
)
async def test_middleware_rejects_ambiguous_body_framing(headers, detail):
    from api.app.main import RequestBodyLimitMiddleware

    app_called = False

    async def app(scope, receive, send):
        nonlocal app_called
        app_called = True

    sent = []

    async def receive():
        pytest.fail("invalid framing reached the body reader")

    async def send(message):
        sent.append(message)

    await RequestBodyLimitMiddleware(app)(
        {
            "type": "http",
            "method": "DELETE",
            "path": "/unknown",
            "headers": headers,
        },
        receive,
        send,
    )

    start = next(msg for msg in sent if msg["type"] == "http.response.start")
    body = next(msg for msg in sent if msg["type"] == "http.response.body")
    assert start["status"] == 400
    assert detail in body["body"]
    assert app_called is False


@pytest.mark.asyncio
async def test_middleware_limits_declared_body_on_get():
    from api.app.main import RequestBodyLimitMiddleware

    app_called = False

    async def app(scope, receive, send):
        nonlocal app_called
        app_called = True

    sent = []

    async def receive():
        pytest.fail("oversized GET reached the body reader")

    async def send(message):
        sent.append(message)

    await RequestBodyLimitMiddleware(app)(
        {
            "type": "http",
            "method": "GET",
            "path": "/unknown",
            "headers": [(b"content-length", b"9" * 10_000)],
        },
        receive,
        send,
    )

    start = next(msg for msg in sent if msg["type"] == "http.response.start")
    assert start["status"] == 413
    assert app_called is False


@pytest.mark.asyncio
async def test_middleware_backup_route_has_higher_limit(client):
    """Only POST /backup/restore receives the larger backup limit."""
    oversized_headers = {
        "Authorization": "Bearer rh_invalid",
        "Content-Length": "5000000",  # 5MB > 1MB default but < 100MB
    }
    r = await client.post(
        "/api/v1/vault/backup/restore",
        headers=oversized_headers,
        content=b"x" * 100,
    )
    assert r.status_code != 413

    # Unknown backup subpaths and other methods keep the normal API limit.
    unknown = await client.post(
        "/api/v1/vault/backup/anything",
        headers=oversized_headers,
        content=b"x" * 100,
    )
    assert unknown.status_code == 413

    wrong_method = await client.put(
        "/api/v1/vault/backup/restore",
        headers=oversized_headers,
        content=b"x" * 100,
    )
    assert wrong_method.status_code == 413


# ---------------------------------------------------------------------------
# Full lifespan via app.router.lifespan_context
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lifespan_full_boot_and_shutdown(monkeypatch):
    """Start the full lifespan, verify the background tasks are created
    and cleaned up without leaving warnings."""

    async def fake_init():
        return []

    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)
    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)

    from api.app.main import app

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_lifespan_seeds_trusted_proxies_from_db(monkeypatch):
    """If vault_config has a 'proxy_config' row, the lifespan loads it."""

    async def fake_init():
        return []

    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)
    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)

    # Insert a proxy config in the DB
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('proxy_config', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": json.dumps({"trusted_ips": "192.0.2.0/24"})},
        )
        await db.commit()

    set_proxies_calls = []

    def fake_set(ips, **kwargs):
        set_proxies_calls.append(ips)

    from api.app import client_ip as client_ip_mod

    monkeypatch.setattr(client_ip_mod, "set_trusted_proxies", fake_set)

    from api.app.main import app

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.1)

    assert "192.0.2.0/24" in set_proxies_calls

    # Cleanup: delete the proxy_config row
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'proxy_config'"))
        await db.commit()


@pytest.mark.asyncio
async def test_lifespan_proxy_seed_errors_fail_closed(monkeypatch, caplog):
    """A malformed DB override clears trust and emits an operator warning."""

    async def fake_init():
        return []

    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)
    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)

    # Insert a malformed proxy config (broken JSON)
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('proxy_config', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": "{not valid json"},
        )
        await db.commit()

    from api.app import client_ip as client_ip_mod
    from api.app.main import app

    set_proxies_calls = []
    original_set_proxies = client_ip_mod.set_trusted_proxies

    def recording_set_proxies(ips, **kwargs):
        set_proxies_calls.append((ips, kwargs))
        return original_set_proxies(ips, **kwargs)

    monkeypatch.setattr(client_ip_mod, "set_trusted_proxies", recording_set_proxies)

    # Must not raise
    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.05)

    assert set_proxies_calls[-1] == ("", {})
    assert "identity proxies cleared" in caplog.text

    # Cleanup
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'proxy_config'"))
        await db.commit()


@pytest.mark.asyncio
async def test_lifespan_refuses_enabled_proxy_auth_without_trusted_ips(monkeypatch):
    async def fake_init():
        return []

    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)
    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)
    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", False)
    monkeypatch.setattr(main_mod.settings, "proxy_auth_enabled", False)

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('proxy_config', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": json.dumps({"enabled": True, "trusted_ips": ""})},
        )
        await db.commit()

    from api.app.main import app

    try:
        with pytest.raises(RuntimeError, match="trusted proxy IPs are required"):
            async with app.router.lifespan_context(app):
                pass
    finally:
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = 'proxy_config'")
            )
            await db.commit()


@pytest.mark.asyncio
async def test_lifespan_warns_for_broad_proxy_without_ha_or_sso(monkeypatch, caplog):
    """A broad XFF trust boundary matters even without identity forwarding."""

    async def fake_init():
        return []

    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)
    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)
    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", False)
    monkeypatch.setattr(main_mod.settings, "proxy_auth_enabled", False)

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value)
                VALUES ('proxy_config', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": json.dumps({"enabled": False, "trusted_ips": "10.0.0.0/8"})},
        )
        await db.commit()

    from api.app.main import app

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.05)

    assert "token IP ACLs, rate limiting and audit" in caplog.text

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'proxy_config'"))
        await db.commit()


@pytest.mark.asyncio
async def test_lifespan_init_cluster_failure_refuses_startup(monkeypatch, caplog):
    """A worker without cluster supervision must never enter service."""
    init_calls = []

    async def fake_init():
        init_calls.append(1)
        raise RuntimeError("simulated cluster init failure")

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)

    # Patch _shutdown_cluster to avoid a DB dependency on deregister
    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)

    from api.app.main import app

    with pytest.raises(RuntimeError, match="simulated cluster init failure"):
        async with app.router.lifespan_context(app):
            pytest.fail("lifespan yielded after cluster init failure")

    assert len(init_calls) == 1
    assert "refusing worker startup" in caplog.text


# ---------------------------------------------------------------------------
# _init_cluster: startup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_cluster_acquires_role_and_spawns_tasks(monkeypatch):
    """Happy path: acquire master or stay sealed, spawn 3 tasks
    (heartbeat/watch/boot). Followers are unbounded - there is no
    'no role available' branch any more."""
    from api.app import cluster as cluster_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState

    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "d" * 32)

    async def fake_register(
        db, socket_name=None, pid=None, hostname=None, node_uuid=None
    ):
        return None

    async def fake_acquire(db, pid=None):
        return WorkerState.SEALED

    # Prevent the loops from doing real work (the tasks will be cancelled)
    async def noop_loop(*a, **kw):
        await asyncio.sleep(60)

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", noop_loop)

    # Patch attach_to_master for the follower_boot, return False quickly
    from api.app import cluster_setup as cs_mod

    async def fake_attach(session_factory, vault, expect_master=True):
        return False  # never attached

    monkeypatch.setattr(cs_mod, "attach_to_master", fake_attach)

    tasks = await main_mod._init_cluster()

    # Must have 3 tasks: heartbeat + master_watch + _follower_boot
    assert len(tasks) == 3

    # Cancel for cleanup
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_init_cluster_on_master_lost_no_share_returns_early(monkeypatch):
    """Capture the on_master_lost callback from _init_cluster and invoke it
    when vs._cluster_share is None -> early return (log debug, no election)."""
    from api.app import cluster as cluster_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState

    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "e" * 32)

    async def fake_register(
        db, socket_name=None, pid=None, hostname=None, node_uuid=None
    ):
        return None

    async def fake_acquire(db, pid=None):
        return WorkerState.SEALED

    captured = []

    async def capture_master_watch(session_factory, on_master_lost, **kw):
        captured.append(on_master_lost)
        await asyncio.sleep(60)

    async def noop_loop(*a, **kw):
        await asyncio.sleep(60)

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", capture_master_watch)

    from api.app import cluster_setup as cs_mod

    async def fake_attach(*a, **kw):
        return False

    monkeypatch.setattr(cs_mod, "attach_to_master", fake_attach)

    # Force _cluster_share = None (initial sealed state)
    vs._cluster_share = None

    tasks = await main_mod._init_cluster()
    await asyncio.sleep(0.05)  # let capture_master_watch capture

    assert len(captured) == 1
    on_lost = captured[0]

    # Invoke the callback, must return early (cluster_share is None)
    await on_lost()  # must not raise nor start an election

    # Cleanup
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_init_cluster_stale_db_heartbeat_keeps_healthy_rpc_master(monkeypatch):
    """A delayed SQL heartbeat under load must not trigger an election when
    the follower's already-attached master RPC channel is still healthy."""
    from api.app import cluster as cluster_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState

    class HealthyClient:
        def __init__(self):
            self.calls = 0

        async def call(self, method, params):
            self.calls += 1
            return {"ok": True}

    class FakeVault:
        def __init__(self):
            self._cluster_share = object()
            self._rpc_client = HealthyClient()
            self.sealed = False
            self.recovery_hook = None
            self.transition_lock = asyncio.Lock()

        @property
        def is_master(self):
            return False

        def set_rpc_recovery_hook(self, hook):
            self.recovery_hook = hook

        def master_transition_lock(self):
            return self.transition_lock

    fake_vault = FakeVault()
    monkeypatch.setattr(main_mod, "vs", fake_vault)
    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "a" * 32)

    async def fake_register(
        db, socket_name=None, pid=None, hostname=None, node_uuid=None
    ):
        return None

    async def fake_acquire(db, pid=None):
        return WorkerState.SEALED

    async def noop_loop(*a, **kw):
        await asyncio.sleep(60)

    captured = []

    async def capture_master_watch(session_factory, on_master_lost, **kw):
        captured.append(on_master_lost)
        await asyncio.sleep(60)

    election_calls = []

    async def fake_election(*a, **kw):
        election_calls.append(True)
        return True

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", capture_master_watch)
    monkeypatch.setattr(cluster_mod, "run_election", fake_election)

    tasks = await main_mod._init_cluster()
    await asyncio.sleep(0.05)
    await captured[0]()

    assert fake_vault._rpc_client.calls == 1
    assert election_calls == []

    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_init_cluster_unseal_winning_election_race_is_not_rolled_back(
    monkeypatch,
):
    """If /unseal makes this process master while its election delay is in
    flight, the callback must not reconstruct, detach, or seal that master."""
    from api.app import cluster as cluster_mod
    from api.app import cluster_setup as cluster_setup_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState
    from api.app.cluster_rpc import MasterUnreachable

    class DeadClient:
        async def call(self, method, params):
            raise MasterUnreachable("stale test client")

    class FakeVault:
        def __init__(self):
            self._cluster_share = object()
            self._rpc_client = DeadClient()
            self.sealed = False
            self.master = False
            self.recovery_hook = None
            self.transition_lock = asyncio.Lock()

        @property
        def is_master(self):
            return self.master

        def set_rpc_recovery_hook(self, hook):
            self.recovery_hook = hook

        def master_transition_lock(self):
            return self.transition_lock

    fake_vault = FakeVault()
    monkeypatch.setattr(main_mod, "vs", fake_vault)
    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "b" * 32)

    async def fake_register(
        db, socket_name=None, pid=None, hostname=None, node_uuid=None
    ):
        return None

    async def fake_acquire(db, pid=None):
        return WorkerState.SEALED

    async def noop_loop(*a, **kw):
        await asyncio.sleep(60)

    captured = []

    async def capture_master_watch(session_factory, on_master_lost, **kw):
        captured.append(on_master_lost)
        await asyncio.sleep(60)

    async def fake_election(*a, **kw):
        fake_vault._rpc_client = None
        fake_vault.master = True
        return True

    reconstruct_calls = []
    detach_calls = []

    async def fake_reconstruct(*a, **kw):
        reconstruct_calls.append(True)
        return False

    async def fake_detach(*a, **kw):
        detach_calls.append(True)

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", capture_master_watch)
    monkeypatch.setattr(cluster_mod, "run_election", fake_election)
    monkeypatch.setattr(
        cluster_setup_mod, "reconstruct_and_become_master", fake_reconstruct
    )
    monkeypatch.setattr(cluster_setup_mod, "detach_from_master", fake_detach)

    tasks = await main_mod._init_cluster()
    await asyncio.sleep(0.05)
    await captured[0]()

    assert fake_vault.is_master is True
    assert reconstruct_calls == []
    assert detach_calls == []

    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_init_cluster_failed_election_checks_registration_before_detach(
    monkeypatch,
):
    """A reaped candidate row prevents a destructive local rollback."""
    from api.app import cluster as cluster_mod
    from api.app import cluster_setup as cluster_setup_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState
    from api.app.cluster_rpc import MasterUnreachable

    monkeypatch.setenv("HOSTNAME", "rollback-row-missing-test")
    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "f" * 32)

    class DeadClient:
        async def call(self, _method, _params):
            raise MasterUnreachable("stale test client")

    class FakeVault:
        def __init__(self):
            self._cluster_share = object()
            self._rpc_client = DeadClient()
            self.sealed = False
            self.recovery_hook = None
            self.transition_lock = asyncio.Lock()

        @property
        def is_master(self):
            return False

        def set_rpc_recovery_hook(self, hook):
            self.recovery_hook = hook

        def master_transition_lock(self):
            return self.transition_lock

    fake_vault = FakeVault()
    monkeypatch.setattr(main_mod, "vs", fake_vault)

    async def fake_register(*_args, **_kwargs):
        # Deliberately leave no row: simulates the five-minute reaper winning.
        return None

    async def fake_acquire(*_args, **_kwargs):
        return WorkerState.SEALED

    async def noop_loop(*_args, **_kwargs):
        await asyncio.sleep(60)

    captured = []

    async def capture_master_watch(_factory, callback, **_kwargs):
        captured.append(callback)
        await asyncio.sleep(60)

    async def fake_election(*_args, **_kwargs):
        return True

    reconstruction_locked = []

    async def fake_reconstruct(*_args, **_kwargs):
        reconstruction_locked.append(fake_vault.transition_lock.locked())
        return False

    detach_calls = []

    async def fake_detach(*_args, **_kwargs):
        detach_calls.append(True)

    async def fake_attach(*_args, **_kwargs):
        return False

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", capture_master_watch)
    monkeypatch.setattr(cluster_mod, "run_election", fake_election)
    monkeypatch.setattr(
        cluster_setup_mod, "reconstruct_and_become_master", fake_reconstruct
    )
    monkeypatch.setattr(cluster_setup_mod, "detach_from_master", fake_detach)
    monkeypatch.setattr(cluster_setup_mod, "attach_to_master", fake_attach)

    tasks = await main_mod._init_cluster()
    await asyncio.sleep(0.05)
    await captured[0]()

    assert reconstruction_locked == [True]
    assert detach_calls == []

    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_init_cluster_follower_boot_attaches_when_master_appears(
    monkeypatch,
):
    """The persistent follower reconciler marks an attached worker FOLLOWER
    and remains alive to repair a later detach/seal transition."""
    from api.app import cluster as cluster_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState

    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "c" * 32)

    async def fake_register(
        db, socket_name=None, pid=None, hostname=None, node_uuid=None
    ):
        return None

    async def fake_acquire(db, pid=None):
        return WorkerState.SEALED

    async def noop_loop(*a, **kw):
        await asyncio.sleep(60)

    attach_call_count = [0]

    from api.app import cluster_setup as cs_mod

    async def fake_attach(session_factory, vault, expect_master=True):
        attach_call_count[0] += 1
        return True  # success on the 1st call

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", noop_loop)
    monkeypatch.setattr(cs_mod, "attach_to_master", fake_attach)

    tasks = await main_mod._init_cluster()

    # Let _follower_boot run (1st attempt -> success -> return)
    await asyncio.sleep(0.1)

    # attach_to_master owns both local RPC attachment and FOLLOWER publication.
    assert attach_call_count[0] >= 1
    assert tasks[2].done() is False

    # Cleanup
    for t in tasks:
        t.cancel()
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_init_cluster_follower_reconciler_retries_after_exception(
    monkeypatch, caplog
):
    """One unexpected attach error must not kill the persistent reconciler."""
    from api.app import cluster as cluster_mod
    from api.app import cluster_setup as cs_mod
    from api.app import node_uuid as node_uuid_mod
    from api.app.cluster import WorkerState

    monkeypatch.setattr(node_uuid_mod, "get_node_uuid", lambda: "9" * 32)

    class FakeVault:
        is_master = False
        _rpc_client = None
        sealed = True

        def set_rpc_recovery_hook(self, _hook):
            return None

    monkeypatch.setattr(main_mod, "vs", FakeVault())

    async def fake_register(*_args, **_kwargs):
        return None

    async def fake_acquire(*_args, **_kwargs):
        return WorkerState.SEALED

    real_sleep = asyncio.sleep

    async def fast_reconcile_sleep(delay):
        if delay == 2.0:
            await real_sleep(0)
            return
        await real_sleep(delay)

    async def noop_loop(*_args, **_kwargs):
        await real_sleep(60)

    attach_calls = 0

    async def flaky_attach(*_args, **_kwargs):
        nonlocal attach_calls
        attach_calls += 1
        if attach_calls == 1:
            raise RuntimeError("transient attach bug")
        return False

    monkeypatch.setattr(cluster_mod, "register_worker", fake_register)
    monkeypatch.setattr(cluster_mod, "acquire_master_or_follower", fake_acquire)
    monkeypatch.setattr(cluster_mod, "heartbeat_loop", noop_loop)
    monkeypatch.setattr(cluster_mod, "master_watch_loop", noop_loop)
    monkeypatch.setattr(cs_mod, "attach_to_master", flaky_attach)
    monkeypatch.setattr(main_mod.asyncio, "sleep", fast_reconcile_sleep)

    with caplog.at_level("WARNING", logger="rhorizon"):
        tasks = await main_mod._init_cluster()
        for _ in range(20):
            if attach_calls >= 2:
                break
            await real_sleep(0)

    assert attach_calls >= 2
    assert tasks[2].done() is False
    assert "follower reconciliation failed; retrying" in caplog.text

    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, BaseException):
            pass


@pytest.mark.asyncio
async def test_lifespan_seals_vault_on_shutdown_if_unsealed(
    monkeypatch, master_password
):
    """The lifespan shutdown calls vs.seal() if not already sealed."""

    async def fake_init():
        return []

    async def fake_shutdown():
        return None

    monkeypatch.setattr(main_mod, "_init_cluster", fake_init)
    monkeypatch.setattr(main_mod, "_shutdown_cluster", fake_shutdown)

    # Force vault unsealed
    from api.app.crypto import derive_keys, derive_master_key

    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
        )
        salt_row = r.fetchone()
        if not salt_row:
            pytest.skip("Vault not initialized")
        salt = bytes.fromhex(salt_row.value)

    if vs.sealed:
        mk = derive_master_key(master_password.encode(), salt)
        vs.unseal(derive_keys(mk))

    from api.app.main import app

    async with app.router.lifespan_context(app):
        if vs.sealed:
            vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))
        await asyncio.sleep(0.05)

    assert vs.sealed is True

    # Restore
    vs.unseal(derive_keys(derive_master_key(master_password.encode(), salt)))


@pytest.mark.asyncio
async def test_rust_custody_startup_serves_sealed_when_no_quorum_is_reachable(
    monkeypatch,
):
    """An empty pool must come up SEALED, never refuse to start.

    Shares are not persisted, so after a restart no slot holds the durable
    generation and attach_reconciled_rust_custody raises. Exiting there leaves
    no path back: the API is the only thing that can serve the /unseal that
    re-derives from the master password and re-splits the pool. This took the
    whole HA lab down the first time persistence was turned off.
    """
    from api.app import custody_routing, rust_custody_backend, socket_paths
    from api.app.cluster_rpc import CustodianPoolUnavailable

    monkeypatch.setattr(socket_paths, "runtime_dir", lambda: "/run/test-rhorizon")
    monkeypatch.setattr(
        main_mod.settings, "custodian_token_file", "/run/test-rhorizon/token"
    )
    monkeypatch.setattr(main_mod.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(main_mod.settings, "rust_custodian_threshold", 2)
    monkeypatch.setattr(
        main_mod.settings, "rust_custody_maintenance_interval_secs", 7.0
    )

    async def attach_raises(*_args, **_kwargs):
        raise CustodianPoolUnavailable(
            "custodian quorum unavailable: donor slot 2: "
            "requested custodian share generation is not installed"
        )

    async def maintain(*_args, **_kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(
        rust_custody_backend, "build_rust_custodian_pool", lambda **_kw: object()
    )
    monkeypatch.setattr(
        rust_custody_backend, "configure_rust_custody_pool", lambda _value: None
    )
    monkeypatch.setattr(
        rust_custody_backend,
        "wire_rust_custody_recovery",
        lambda *_a, **_kw: None,
    )
    monkeypatch.setattr(
        rust_custody_backend, "attach_reconciled_rust_custody", attach_raises
    )
    monkeypatch.setattr(custody_routing, "run_custody_routing", maintain)

    # Must not raise: startup completes and the maintenance loop is running.
    tasks = await main_mod._init_rust_api_custody()
    try:
        assert tasks, "startup must still schedule the maintenance loop"
    finally:
        await main_mod._cancel_background_tasks(tasks)
