"""Backlog #2: Prometheus metrics module - exposition + CIDR allow-list."""

import json
from types import SimpleNamespace

import pytest
from api.app import metrics as _m
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text


class _Request:
    def __init__(self, host=None):
        self.client = None if host is None else SimpleNamespace(host=host)


def test_parse_cidrs_and_direct_peer_validation(monkeypatch):
    nets = _m._parse_cidrs(" ,127.0.0.1/32,invalid,10.0.0.7/24")
    assert [str(net) for net in nets] == ["127.0.0.1/32", "10.0.0.0/24"]

    monkeypatch.setattr(_m, "_ALLOWED_CIDRS", [])
    assert _m._client_ip_in_allowed(_Request("127.0.0.1")) is False
    monkeypatch.setattr(_m, "_ALLOWED_CIDRS", nets)
    assert _m._client_ip_in_allowed(_Request()) is False
    assert _m._client_ip_in_allowed(_Request("not-an-ip")) is False
    assert _m._client_ip_in_allowed(_Request("10.0.0.42")) is True
    assert _m._client_ip_in_allowed(_Request("192.0.2.1")) is False


@pytest.mark.parametrize(
    ("buckets", "expected"),
    [
        ({}, 0.0),
        ({"bad": 4}, 0.0),
        ({"0.1": 0, "+Inf": 0}, 0.0),
        ({"0.1": 95, "0.2": 100}, 100.0),
        ({"0.1": 90, "0.2": 100}, 150.0),
        ({"0.1": 90, "+Inf": 100}, 100.0),
    ],
)
def test_p95_histogram_interpolation(buckets, expected):
    assert _m._p95_ms(buckets) == pytest.approx(expected)


def test_observability_snapshot_collects_all_supported_samples(monkeypatch):
    samples = [
        SimpleNamespace(name="rhorizon_secrets_read_total", labels={}, value=4.0),
        SimpleNamespace(name="rhorizon_secrets_write_total", labels={}, value=3.0),
        SimpleNamespace(
            name="rhorizon_http_requests_total",
            labels={"transport": "http"},
            value=7.0,
        ),
        SimpleNamespace(
            name="rhorizon_http_requests_total",
            labels={"transport": "https"},
            value=11.0,
        ),
        SimpleNamespace(name="rhorizon_auth_failures_total", labels={}, value=2.0),
        SimpleNamespace(name="rhorizon_active_tokens", labels={}, value=5.0),
        SimpleNamespace(name="rhorizon_requests_inflight", labels={}, value=6.0),
        SimpleNamespace(
            name="rhorizon_custody_master_retries_total", labels={}, value=8.0
        ),
        SimpleNamespace(
            name="rhorizon_custody_control_requests_total",
            labels={"result": "success"},
            value=9.0,
        ),
        SimpleNamespace(
            name="rhorizon_custody_control_requests_total",
            labels={"result": "transport_error"},
            value=1.0,
        ),
        SimpleNamespace(
            name="rhorizon_secret_decrypt_duration_seconds_bucket",
            labels={"le": "0.1"},
            value=95.0,
        ),
        SimpleNamespace(
            name="rhorizon_secret_decrypt_duration_seconds_bucket",
            labels={"le": "+Inf"},
            value=100.0,
        ),
    ]
    registry = SimpleNamespace(
        collect=lambda: [
            SimpleNamespace(samples=samples[:4]),
            SimpleNamespace(samples=samples[4:]),
        ]
    )
    monkeypatch.setattr(_m, "_MULTIPROC", False)
    monkeypatch.setattr(_m, "REGISTRY", registry)

    assert _m.observability_snapshot() == {
        "reads_total": 4.0,
        "writes_total": 3.0,
        "http_total": 18.0,
        "http_https": 11.0,
        "auth_failures_total": 2.0,
        "active_tokens": 5,
        "active_connections": 6,
        "decrypt_p95_ms": 100.0,
        "custody_master_retries_total": 8.0,
        "custody_control_failures_total": 1.0,
    }


def test_observability_snapshot_builds_multiprocess_registry(monkeypatch):
    registry = SimpleNamespace(collect=lambda: [])
    calls = []
    monkeypatch.setattr(_m, "_MULTIPROC", True)
    monkeypatch.setattr(_m, "CollectorRegistry", lambda: registry)
    monkeypatch.setattr(
        _m.multiprocess,
        "MultiProcessCollector",
        lambda value: calls.append(value),
    )
    snapshot = _m.observability_snapshot()
    assert calls == [registry]
    assert snapshot["reads_total"] == 0


@pytest.mark.asyncio
async def test_metrics_multiprocess_registry_path(monkeypatch):
    registry = object()
    calls = []
    monkeypatch.setattr(_m.settings, "metrics_enabled", True)
    monkeypatch.setattr(_m, "_client_ip_in_allowed", lambda _request: True)
    monkeypatch.setattr(_m, "_MULTIPROC", True)
    monkeypatch.setattr(_m, "CollectorRegistry", lambda: registry)
    monkeypatch.setattr(
        _m.multiprocess,
        "MultiProcessCollector",
        lambda value: calls.append(value),
    )
    monkeypatch.setattr(_m, "generate_latest", lambda value: b"metric 1\n")

    response = await _m.metrics(_Request("127.0.0.1"))
    assert calls == [registry]
    assert response.body == b"metric 1\n"


def test_record_auth_failure_bounds_label_cardinality():
    before = _m.auth_failures.labels(reason="other")._value.get()
    _m.record_auth_failure("attacker-controlled-reason")
    assert _m.auth_failures.labels(reason="other")._value.get() == before + 1


@pytest.mark.asyncio
async def test_metrics_endpoint_rejects_disallowed_ip(
    client, master_password, monkeypatch
):
    """A client whose direct peer IP is not in the allow-list gets 403."""
    monkeypatch.setattr(_m, "_ALLOWED_CIDRS", _m._parse_cidrs("192.0.2.99/32"))
    r = await client.get("/metrics")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_metrics_endpoint_allows_loopback(client, master_password, monkeypatch):
    """If we widen the allow-list to include the test client IP, the
    endpoint returns the prometheus text body."""
    # Force the allow-list to include any 0.0.0.0/0 + the testclient pseudo-IP
    # path. ASGITransport sets request.client.host to "testclient" (a string,
    # not a real IP), so we monkey-patch _client_ip_in_allowed to bypass.
    monkeypatch.setattr(_m, "_client_ip_in_allowed", lambda req: True)

    r = await client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    # Standard prometheus_client metadata lines
    assert "# HELP rhorizon_unseal_attempts_total" in body
    assert "# TYPE rhorizon_unseal_attempts_total counter" in body
    # Our counters appear (at minimum, the metric name)
    assert "rhorizon_secrets_read_total" in body
    assert "rhorizon_tokens_created_total" in body
    assert "rhorizon_vault_sealed" in body


@pytest.mark.asyncio
async def test_metrics_disabled_returns_404(client, monkeypatch):
    """metrics_enabled=false -> endpoint hidden as if not registered."""
    from api.app.config import settings

    monkeypatch.setattr(settings, "metrics_enabled", False)
    monkeypatch.setattr(_m, "_client_ip_in_allowed", lambda req: True)
    r = await client.get("/metrics")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_unseal_counter_increments(client, master_password, monkeypatch):
    """A failed unseal bumps the invalid_password counter."""
    monkeypatch.setattr(_m, "_client_ip_in_allowed", lambda req: True)

    # Snapshot before
    before_fail = _m.unseal_attempts.labels(result="invalid_password")._value.get()

    # Trigger a failure: vault is unsealed already, force it sealed first by
    # creating a fresh state... actually simplest: call /unseal with a wrong
    # password while vault is sealed. Need to seal first.
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # Make an root token to call /seal
    raw = generate_token()
    h = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'metrics-admin'"))
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, created_by) "
                "VALUES ('metrics-admin', :h, CAST(:p AS jsonb), 'test')"
            ),
            {"h": h, "p": json.dumps({"admin": "rw"})},
        )
        await db.commit()

    seal_r = await client.post(
        "/api/v1/vault/seal", headers={"Authorization": f"Bearer {raw}"}
    )
    assert seal_r.status_code == 200

    # Now try unseal with wrong password
    bad_r = await client.post(
        "/api/v1/vault/unseal", json={"password": "wrong-password-xxxxx"}
    )
    assert bad_r.status_code == 401

    after_fail = _m.unseal_attempts.labels(result="invalid_password")._value.get()
    assert after_fail >= before_fail + 1

    # Re-unseal for downstream tests
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_secrets_read_counter_increments(
    client, master_password, admin_token, monkeypatch
):
    """A successful GET /secrets/{name} bumps secrets_read_total."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a secret
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "metrics-test-secret", "value": "hello"},
    )

    before = _m.secrets_read._value.get()
    r = await client.get(
        "/api/v1/vault/secrets/metrics-test-secret",
        headers=headers,
    )
    assert r.status_code == 200
    after = _m.secrets_read._value.get()
    assert after == before + 1


def _hist_count(hist) -> float:
    """Total observations on a Histogram, read from its exposed _count sample."""
    for metric in hist.collect():
        for s in metric.samples:
            if s.name.endswith("_count"):
                return s.value
    return 0.0


@pytest.mark.asyncio
async def test_secret_read_observes_decrypt_histogram(
    client, master_password, admin_token
):
    """GET /secrets/{name} observes secret_decrypt_duration (was a dead metric)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "decrypt-hist-secret", "value": "hello"},
    )

    before = _hist_count(_m.secret_decrypt_duration)
    r = await client.get("/api/v1/vault/secrets/decrypt-hist-secret", headers=headers)
    assert r.status_code == 200
    after = _hist_count(_m.secret_decrypt_duration)
    assert after == before + 1


@pytest.mark.asyncio
async def test_derived_gauges_refresh_from_db(client, master_password, admin_token):
    """active_tokens/locked_ips were dead gauges; _refresh_derived_gauges sets
    them from a DB COUNT(*)."""
    from api.app.main import _refresh_derived_gauges

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    async with async_session() as db:
        row = await db.execute(
            text(
                "SELECT COUNT(*) AS n FROM vault_tokens WHERE active = true "
                "AND (expires_at IS NULL OR expires_at > NOW())"
            )
        )
        expected = row.fetchone().n
    assert expected > 0  # at least the admin token exists

    await _refresh_derived_gauges()
    assert _m.active_tokens._value.get() == expected
    assert _m.locked_ips._value.get() >= 0
