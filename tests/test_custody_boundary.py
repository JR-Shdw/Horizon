"""ASGI contracts for the local separated-custody boundary."""

import httpx
import pytest
from api.app import custody


def test_only_key_generation_routes_enter_custodian_control_plane():
    assert custody.is_custody_route("POST", "/api/v1/vault/unseal")
    assert custody.is_custody_route("POST", "/api/v1/vault/rotate-password")
    assert custody.is_custody_route("POST", "/api/v1/vault/admin/rotate-dek-key")
    assert custody.is_custody_route("POST", "/api/v1/vault/seal")
    assert custody.is_custody_route("POST", "/api/v1/vault/backup/restore")
    assert not custody.is_custody_route("GET", "/api/v1/vault/secrets/example")
    assert not custody.is_custody_route("POST", "/api/v1/vault/secrets/")
    assert not custody.is_custody_route("GET", "/readiness")
    assert ("POST", "/api/v1/vault/seal") in custody._MASTER_ONLY_ROUTES
    assert ("POST", "/api/v1/vault/unseal") not in custody._MASTER_ONLY_ROUTES


@pytest.mark.asyncio
async def test_rust_canary_blocks_unsupported_routes_but_allows_lifecycle_parity(
    monkeypatch,
):
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    called = []

    async def downstream(scope, _receive, _send):
        called.append(scope["path"])

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    messages = []

    async def send(message):
        messages.append(message)

    middleware = custody.CustodyBoundaryMiddleware(downstream)
    base = {"type": "http", "method": "POST", "headers": []}
    # Shamir administration still needs its own maintenance protocol: a
    # topology or threshold change is not an ordinary same-topology repair.
    await middleware({**base, "path": "/api/v1/vault/shamir/init"}, receive, send)
    await middleware({**base, "path": "/api/v1/vault/rotate-password"}, receive, send)
    await middleware(
        {**base, "path": "/api/v1/vault/admin/rotate-dek-key"}, receive, send
    )
    await middleware({**base, "path": "/api/v1/vault/unseal"}, receive, send)
    await middleware({**base, "path": "/api/v1/vault/seal"}, receive, send)
    await middleware({**base, "path": "/api/v1/vault/backup/restore"}, receive, send)

    assert messages[0]["status"] == 503
    assert called == [
        "/api/v1/vault/rotate-password",
        "/api/v1/vault/admin/rotate-dek-key",
        "/api/v1/vault/unseal",
        "/api/v1/vault/seal",
        "/api/v1/vault/backup/restore",
    ]


@pytest.mark.asyncio
async def test_rust_canary_password_unseal_enters_opaque_activation(
    client, master_password, monkeypatch
):
    from api.app import rust_custody_backend
    from api.app.vault_state import vault

    pool = object()
    calls = []
    vault.seal()
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(custody.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(custody.settings, "rust_custodian_threshold", 2)
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", pool)

    async def activate(candidate, candidate_vault, **kwargs):
        assert candidate_vault is vault
        assert not vault.sealed
        calls.append((candidate, kwargs))

    monkeypatch.setattr(
        rust_custody_backend, "activate_rust_custody_from_local", activate
    )

    response = await client.post(
        "/api/v1/vault/unseal", json={"password": master_password}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "unsealed"
    assert calls[0][0] is pool
    assert calls[0][1]["threshold"] == 2
    assert calls[0][1]["slots"] == 3


@pytest.mark.asyncio
async def test_rust_canary_manual_seal_uses_durable_backend_path(
    client, admin_token, monkeypatch
):
    from api.app import rust_custody_backend
    from api.app.vault_state import vault

    pool = object()
    calls = []
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", pool)

    async def deactivate(candidate, candidate_vault, **kwargs):
        calls.append((candidate, candidate_vault))
        assert kwargs == {"local_transition_locked": True}
        candidate_vault.seal()

    monkeypatch.setattr(rust_custody_backend, "deactivate_rust_custody", deactivate)

    response = await client.post(
        "/api/v1/vault/seal",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "sealed"}
    assert calls == [(pool, vault)]
    assert vault.sealed


@pytest.mark.asyncio
async def test_rust_canary_status_reports_native_slot_availability(client, monkeypatch):
    from api.app import rust_custody_backend

    class Pool:
        async def availability_statuses(self):
            return {
                1: {"state": "unsealed", "generation": 2},
                2: {"state": "sealed", "generation": None},
                3: None,
            }

    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(custody.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(custody.settings, "rust_custodian_threshold", 2)
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", Pool())

    response = await client.get("/api/v1/vault/status")

    assert response.status_code == 200
    status = response.json()
    assert status["custody_backend"] == "rust"
    assert status["custodian_workers_expected"] == 3
    assert status["custodian_workers_live"] == 2
    assert status["custodian_quorum_threshold"] == 2
    assert status["custodian_master_present"] is True


def test_control_token_rejects_weak_and_overexposed_files(tmp_path, monkeypatch):
    token = tmp_path / "control.token"
    monkeypatch.setattr(custody.settings, "custodian_token_file", str(token))

    token.write_bytes(b"short")
    token.chmod(0o600)
    with pytest.raises(RuntimeError, match="32..256"):
        custody._read_control_token()

    token.write_bytes(b"a" * 32)
    token.chmod(0o640)
    with pytest.raises(RuntimeError, match="group/world"):
        custody._read_control_token()

    token.chmod(0o600)
    assert custody._read_control_token() == b"a" * 32


@pytest.mark.asyncio
async def test_custodian_rejects_request_without_control_capability(
    monkeypatch, tmp_path
):
    token = tmp_path / "control.token"
    token.write_bytes(b"b" * 32)
    token.chmod(0o600)
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "process_role", "custodian")
    monkeypatch.setattr(custody.settings, "custodian_token_file", str(token))
    called = False
    messages = []

    async def downstream(_scope, _receive, _send):
        nonlocal called
        called = True

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    middleware = custody.CustodyBoundaryMiddleware(downstream)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/vault/unseal",
            "headers": [],
        },
        receive,
        send,
    )
    assert called is False
    assert messages[0]["status"] == 403


@pytest.mark.asyncio
async def test_custodian_accepts_capability_and_restores_client_ip(
    monkeypatch, tmp_path
):
    token = tmp_path / "control.token"
    token.write_bytes(b"c" * 32)
    token.chmod(0o600)
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "process_role", "custodian")
    monkeypatch.setattr(custody.settings, "custodian_token_file", str(token))
    observed = {}

    async def downstream(scope, _receive, _send):
        observed.update(scope)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message):
        return None

    middleware = custody.CustodyBoundaryMiddleware(downstream)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/vault/unseal",
            "headers": [
                (b"x-rhorizon-custody-token", b"c" * 32),
                (b"x-rhorizon-custody-client-ip", b"192.0.2.7"),
            ],
        },
        receive,
        send,
    )
    assert observed["client"] == ("192.0.2.7", 0)
    assert not any(
        key.startswith(b"x-rhorizon-custody") for key, _ in observed["headers"]
    )


@pytest.mark.asyncio
async def test_custodian_follower_rejects_master_only_route_before_dispatch(
    monkeypatch, tmp_path
):
    token = tmp_path / "control.token"
    token.write_bytes(b"d" * 32)
    token.chmod(0o600)
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "process_role", "custodian")
    monkeypatch.setattr(custody.settings, "custodian_token_file", str(token))
    called = False
    messages = []

    async def downstream(_scope, _receive, _send):
        nonlocal called
        called = True

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    middleware = custody.CustodyBoundaryMiddleware(downstream)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/vault/seal",
            "headers": [(b"x-rhorizon-custody-token", b"d" * 32)],
        },
        receive,
        send,
    )
    assert called is False
    assert messages[0]["status"] == 409
    assert (custody._MASTER_RETRY_HEADER, b"1") in messages[0]["headers"]


@pytest.mark.asyncio
async def test_api_proxies_key_lifecycle_request_over_uds(monkeypatch, tmp_path):
    token = tmp_path / "control.token"
    token.write_bytes(b"e" * 32)
    token.chmod(0o600)
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(custody.settings, "custodian_token_file", str(token))
    monkeypatch.setattr(
        custody.settings, "custodian_uds_path", "/tmp/rhorizon-custodian.sock"
    )
    observed = {}
    messages = []

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def request(self, method, url, *, headers, content):
            streamed = bytearray()
            async for chunk in content:
                streamed.extend(chunk)
            observed.update(
                method=method,
                url=url,
                headers=dict(headers),
                content=bytes(streamed),
            )
            return httpx.Response(200, json={"status": "unsealed"})

    monkeypatch.setattr(custody.httpx, "AsyncHTTPTransport", lambda **_kwargs: object())
    monkeypatch.setattr(custody.httpx, "AsyncClient", _Client)

    async def downstream(_scope, _receive, _send):
        raise AssertionError("custody route must not reach public API app")

    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {
            "type": "http.request",
            "body": b'{"password":"secret"}',
            "more_body": False,
        }

    async def send(message):
        messages.append(message)

    middleware = custody.CustodyBoundaryMiddleware(downstream)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/vault/unseal",
            "query_string": b"",
            "client": ("192.0.2.9", 50000),
            "headers": [(b"content-type", b"application/json")],
        },
        receive,
        send,
    )
    assert observed["method"] == "POST"
    assert observed["url"].endswith("/api/v1/vault/unseal")
    assert observed["content"] == b'{"password":"secret"}'
    assert observed["headers"][custody._TOKEN_HEADER] == b"e" * 32
    assert observed["headers"][custody._CLIENT_IP_HEADER] == b"192.0.2.9"
    assert messages[0]["status"] == 200
