# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Admission control / load shedding middleware (MaxConcurrencyMiddleware).

Bounds in-flight requests per worker so congestion collapse can't starve the
event loop / cluster coordination loops into a defensive seal. PG-free: the
middleware is exercised directly over ASGI with a stub app.
"""

import asyncio

import pytest
from api.app import metrics
from api.app.config import settings
from api.app.main import MaxConcurrencyMiddleware


def _http_scope(path="/api/v1/vault/secrets/x", method="GET"):
    return {"type": "http", "path": path, "method": method, "headers": []}


async def _drain(mw, scope):
    """Run one request through the middleware; return the response status."""
    status = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            status["code"] = msg["status"]

    await mw(scope, receive, send)
    return status.get("code")


@pytest.mark.asyncio
async def test_sheds_above_cap_then_recovers(monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_requests", 2)
    gate = asyncio.Event()
    admitted = metrics.requests_by_transport.labels(transport="http")
    shed = metrics.requests_shed.labels(reason="request_concurrency_limit")
    admitted_before = admitted._value.get()
    shed_before = shed._value.get()

    async def slow_app(scope, receive, send):
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = MaxConcurrencyMiddleware(slow_app)

    # Two requests occupy the cap (blocked on the gate)...
    t1 = asyncio.create_task(_drain(mw, _http_scope()))
    t2 = asyncio.create_task(_drain(mw, _http_scope()))
    await asyncio.sleep(0.05)  # let both enter slow_app

    # ...the third is shed immediately with 429 (no wait on the gate). 429
    # (transient backpressure), NOT 503 : a passive LB ejects on 5xx, so a
    # busy node must not look unavailable. See _load_shed_response in main.py
    # + tests/test_admission_429.py for the full contract.
    third = await asyncio.wait_for(_drain(mw, _http_scope()), timeout=1.0)
    assert third == 429

    # Release the in-flight pair; they complete 200 and free the slots.
    gate.set()
    assert await asyncio.wait_for(t1, timeout=1.0) == 200
    assert await asyncio.wait_for(t2, timeout=1.0) == 200

    # Capacity restored: a new request is admitted (200).
    assert await asyncio.wait_for(_drain(mw, _http_scope()), timeout=1.0) == 200
    assert admitted._value.get() - admitted_before == 3
    assert shed._value.get() - shed_before == 1


@pytest.mark.asyncio
async def test_exempt_paths_bypass_cap(monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_requests", 1)
    gate = asyncio.Event()
    exempt = {"/readiness"}

    async def app(scope, receive, send):
        # Non-exempt requests block on the gate (to hold the single slot);
        # exempt requests answer immediately.
        if scope["path"] not in exempt:
            await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = MaxConcurrencyMiddleware(app)

    # Occupy the single slot with a non-exempt request.
    t1 = asyncio.create_task(_drain(mw, _http_scope()))
    await asyncio.sleep(0.05)

    # Probes must not be shed even at cap.
    for path in exempt:
        code = await asyncio.wait_for(_drain(mw, _http_scope(path)), timeout=1.0)
        assert code == 200, f"{path} should be exempt, got {code}"

    # /status performs DB work and must remain under the normal cap.
    status = await asyncio.wait_for(
        _drain(mw, _http_scope("/api/v1/vault/status")),
        timeout=1.0,
    )
    assert status == 429

    wrong_method = await asyncio.wait_for(
        _drain(mw, _http_scope("/api/v1/vault/unseal", method="GET")),
        timeout=1.0,
    )
    assert wrong_method == 429

    gate.set()
    assert await asyncio.wait_for(t1, timeout=1.0) == 200


@pytest.mark.asyncio
async def test_unseal_has_one_reserved_slot(monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_requests", 1)
    normal_gate = asyncio.Event()
    unseal_gate = asyncio.Event()
    unseal_shed = metrics.requests_shed.labels(reason="unseal_concurrency_limit")
    shed_before = unseal_shed._value.get()

    async def app(scope, receive, send):
        if scope["path"] == "/api/v1/vault/unseal":
            await unseal_gate.wait()
        else:
            await normal_gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = MaxConcurrencyMiddleware(app)

    # Saturate normal traffic. The reserved recovery slot still admits unseal.
    normal = asyncio.create_task(_drain(mw, _http_scope()))
    await asyncio.sleep(0)
    first_unseal = asyncio.create_task(
        _drain(mw, _http_scope("/api/v1/vault/unseal", method="POST"))
    )
    await asyncio.sleep(0)

    # A second attempt cannot queue behind the first transition/Argon2 call.
    second = await asyncio.wait_for(
        _drain(mw, _http_scope("/api/v1/vault/unseal", method="POST")),
        timeout=1.0,
    )
    assert second == 429
    assert unseal_shed._value.get() - shed_before == 1

    unseal_gate.set()
    assert await asyncio.wait_for(first_unseal, timeout=1.0) == 200
    normal_gate.set()
    assert await asyncio.wait_for(normal, timeout=1.0) == 200


@pytest.mark.asyncio
async def test_disabled_when_cap_zero(monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_requests", 0)
    gate = asyncio.Event()

    async def slow_app(scope, receive, send):
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = MaxConcurrencyMiddleware(slow_app)
    # Many concurrent requests, cap disabled -> none shed.
    tasks = [asyncio.create_task(_drain(mw, _http_scope())) for _ in range(5)]
    await asyncio.sleep(0.05)
    gate.set()
    codes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=2.0)
    assert all(c == 200 for c in codes)
