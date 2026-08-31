# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stable-contract tests for the HA preflight shared by every client."""

from datetime import datetime, timedelta, timezone

import pytest
from api.app import cluster_preflight
from api.app.routes import cluster_read


def _by_id(checks):
    return {check["id"]: check for check in checks}


def test_static_checks_explain_complete_and_incomplete_configuration(monkeypatch):
    values = {
        "cluster_ha_enabled": True,
        "tls_enabled": True,
        "proxy_trusted_ips": "10.0.0.8/32",
        "cluster_identity_persistent": True,
        "cluster_advertise_ip": "10.0.0.11",
        "ha_primary_url": "https://vault.internal:8443",
        "max_concurrent_requests": 64,
    }
    for name, value in values.items():
        monkeypatch.setattr(cluster_preflight.settings, name, value)
    passing = _by_id(cluster_preflight._static_checks())
    assert all(check["status"] == "pass" for check in passing.values())

    for name, value in {
        "cluster_ha_enabled": False,
        "tls_enabled": False,
        "proxy_trusted_ips": "",
        "cluster_identity_persistent": False,
        "cluster_advertise_ip": "",
        "ha_primary_url": "http://vault.internal",
        "max_concurrent_requests": 0,
    }.items():
        monkeypatch.setattr(cluster_preflight.settings, name, value)
    failing = _by_id(cluster_preflight._static_checks())
    assert all(check["status"] == "fail" for check in failing.values())
    assert all(check["remediation"] for check in failing.values())

    monkeypatch.setattr(cluster_preflight.settings, "cluster_advertise_ip", "127.0.0.1")
    assert (
        _by_id(cluster_preflight._static_checks())["advertised_address"]["status"]
        == "fail"
    )


def test_identity_checks_validate_persistent_uuid_and_certificate(
    tmp_path, monkeypatch
):
    uuid_path = tmp_path / "node-uuid"
    cert_path = tmp_path / "cluster-cert.pem"
    key_path = tmp_path / "cluster-cert.key"
    uuid_path.write_text("node-a")
    cert_path.write_text("certificate")
    key_path.write_text("private key")
    key_path.chmod(0o400)
    monkeypatch.setattr(cluster_preflight.settings, "node_uuid_path", str(uuid_path))
    monkeypatch.setattr(cluster_preflight.settings, "cluster_cert_path", str(cert_path))
    monkeypatch.setattr(
        cluster_preflight.settings, "cluster_cert_key_path", str(key_path)
    )
    monkeypatch.setattr(
        cluster_preflight.cluster_cert, "validate_perms", lambda *_: None
    )
    monkeypatch.setattr(
        cluster_preflight.cluster_cert,
        "load_cluster_cert",
        lambda *_: (b"cert", b"key"),
    )
    monkeypatch.setattr(
        cluster_preflight.cluster_cert,
        "cert_not_after",
        lambda _: datetime.now(timezone.utc) + timedelta(days=30),
    )

    checks = _by_id(cluster_preflight._identity_checks())
    assert checks["node_identity"]["status"] == "pass"
    assert checks["node_certificate"]["status"] == "pass"
    assert checks["node_certificate"]["evidence"]["key_mode"] == "0o400"

    monkeypatch.setattr(
        cluster_preflight.cluster_cert,
        "cert_not_after",
        lambda _: datetime.now(timezone.utc) + timedelta(days=1),
    )
    assert (
        _by_id(cluster_preflight._identity_checks())["node_certificate"]["status"]
        == "fail"
    )

    uuid_path.unlink()
    monkeypatch.setattr(
        cluster_preflight.cluster_cert,
        "validate_perms",
        lambda *_: (_ for _ in ()).throw(ValueError("mode must be 0400")),
    )
    checks = _by_id(cluster_preflight._identity_checks())
    assert checks["node_identity"]["status"] == "fail"
    assert checks["node_certificate"]["status"] == "fail"
    assert "0400" in checks["node_certificate"]["reason"]


def test_health_and_worker_checks_are_strict():
    health = {
        "components": {
            "database": {"state": "green", "reason": "writable"},
            "node": {"state": "orange", "reason": "forming"},
        }
    }
    checks = _by_id(cluster_preflight._health_checks(health))
    assert checks["health_database"]["status"] == "pass"
    assert checks["health_node"]["status"] == "fail"
    assert checks["health_cluster"]["evidence"] == {"state": "grey"}

    converged = cluster_preflight._worker_check(
        {"hosts": {"a": {"master": {"age_sec": 0.4}}}}
    )
    assert converged["status"] == "pass"
    depleted = cluster_preflight._worker_check(
        {
            "hosts": {
                "a": {"master": None},
                "b": {"master": {"age_sec": 9}},
            }
        }
    )
    assert depleted["status"] == "fail"
    assert depleted["evidence"]["missing_masters"] == ["a"]
    assert depleted["evidence"]["stale_masters"] == ["b"]


@pytest.mark.asyncio
async def test_audit_anchor_requires_valid_and_fresh_signature(monkeypatch):
    now = datetime.now(timezone.utc)

    async def fresh(_db):
        return {"valid": True, "completed_at": now.isoformat(), "payload": {}}

    monkeypatch.setattr(cluster_preflight, "latest_verification_anchor", fresh)
    monkeypatch.setattr(
        cluster_preflight.settings, "audit_verify_anchor_max_age_seconds", 60
    )
    assert (await cluster_preflight._audit_anchor_check(object()))["status"] == "pass"

    async def stale(_db):
        return {
            "valid": True,
            "completed_at": (now - timedelta(hours=1)).isoformat(),
            "payload": {},
        }

    monkeypatch.setattr(cluster_preflight, "latest_verification_anchor", stale)
    assert (await cluster_preflight._audit_anchor_check(object()))["status"] == "fail"

    async def malformed(_db):
        return {"valid": False, "completed_at": "not-a-date", "payload": {}}

    monkeypatch.setattr(cluster_preflight, "latest_verification_anchor", malformed)
    malformed_check = await cluster_preflight._audit_anchor_check(object())
    assert malformed_check["status"] == "fail"
    assert malformed_check["evidence"]["age_seconds"] is None

    async def absent(_db):
        return None

    monkeypatch.setattr(cluster_preflight, "latest_verification_anchor", absent)
    assert (await cluster_preflight._audit_anchor_check(object()))["status"] == "fail"


@pytest.mark.asyncio
async def test_live_mtls_probe_uses_node_certificate(monkeypatch):
    monkeypatch.setattr(
        cluster_preflight.settings,
        "ha_primary_url",
        "https://vault.internal:8443/",
    )
    monkeypatch.setattr(cluster_preflight.settings, "cluster_cert_path", "/cert.pem")
    monkeypatch.setattr(
        cluster_preflight.settings, "cluster_cert_key_path", "/cert.key"
    )
    loaded = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"authenticated": True, "node_uuid": "node-a"}

    class Client:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url):
            assert url.endswith("/api/v1/vault/cluster/mtls-self")
            return Response()

    context = object()
    monkeypatch.setattr(
        cluster_preflight.cluster_tls,
        "server_context",
        lambda **kwargs: loaded.append(kwargs) or context,
    )
    monkeypatch.setattr(cluster_preflight.httpx, "AsyncClient", Client)
    check = await cluster_preflight._live_mtls_check()
    assert check["status"] == "pass"
    assert loaded == [{"client_cert": "/cert.pem", "client_key": "/cert.key"}]

    monkeypatch.setattr(cluster_preflight.settings, "ha_primary_url", "http://bad")
    assert (await cluster_preflight._live_mtls_check())["status"] == "fail"

    monkeypatch.setattr(
        cluster_preflight.settings, "ha_primary_url", "https://vault.internal"
    )
    monkeypatch.setattr(
        cluster_preflight.cluster_tls,
        "server_context",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("missing CA")),
    )
    failed = await cluster_preflight._live_mtls_check()
    assert failed["status"] == "fail"
    assert "missing CA" in failed["reason"]


@pytest.mark.asyncio
async def test_build_and_mcp_projection_keep_one_stable_contract(monkeypatch):
    passed = cluster_preflight._item("static", "Static", "pass", "ok")

    monkeypatch.setattr(cluster_preflight, "_static_checks", lambda: [passed])
    monkeypatch.setattr(cluster_preflight, "_identity_checks", lambda: [])
    monkeypatch.setattr(cluster_preflight, "_health_checks", lambda _health: [])
    monkeypatch.setattr(
        cluster_preflight,
        "_worker_check",
        lambda _topology: cluster_preflight._item(
            "workers", "Workers", "pass", "converged"
        ),
    )

    async def anchor(_db):
        return cluster_preflight._item("audit_anchor", "Audit", "pass", "fresh")

    monkeypatch.setattr(cluster_preflight, "_audit_anchor_check", anchor)

    async def skew(_db):
        return cluster_preflight._item("clock_skew", "Clock", "pass", "aligned")

    async def peers(_db):
        return cluster_preflight._item("peer_state", "Peers", "pass", "one primary")

    monkeypatch.setattr(cluster_preflight, "_clock_skew_check", skew)
    monkeypatch.setattr(cluster_preflight, "_peer_state_check", peers)
    result = await cluster_preflight.build_preflight(
        object(), health={}, topology={}, live=False
    )
    assert result["ready"] is True
    assert result["overall"] == "warn"
    assert result["warning_checks"] == ["mtls_live"]

    projected = cluster_preflight.project_preflight(result)
    assert projected["ready"] is True
    assert projected["live_mtls_requested"] is False
    assert all("evidence" not in check for check in projected["checks"])


@pytest.mark.asyncio
async def test_read_routes_share_status_and_preflight_contract(monkeypatch):
    health = {
        "overall": "green",
        "ready": True,
        "components": {
            "database": {
                "state": "green",
                "reason": "writable",
                "internal_detail": "not in summary",
            }
        },
    }
    topology = {"hosts": {"node-a": {"master": {"age_sec": 0.1}}}}

    async def health_snapshot(_db, _vault):
        return health

    async def topology_snapshot(_db):
        return topology

    async def build(_db, **kwargs):
        assert kwargs == {"health": health, "topology": topology, "live": False}
        return {
            "schema_version": 1,
            "ready": True,
            "overall": "pass",
            "failed_checks": [],
            "warning_checks": [],
            "checks": [],
        }

    monkeypatch.setattr(cluster_read.cluster_status, "health_snapshot", health_snapshot)
    monkeypatch.setattr(
        cluster_read.cluster_status, "topology_snapshot", topology_snapshot
    )
    monkeypatch.setattr(cluster_read.cluster_preflight, "build_preflight", build)

    assert await cluster_read.cluster_topology(db=object()) == topology
    assert (
        await cluster_read.cluster_health_endpoint(summary=False, db=object()) == health
    )
    summary = await cluster_read.cluster_health_endpoint(summary=True, db=object())
    assert summary["components"] == {
        "database": {"state": "green", "reason": "writable"}
    }
    preflight = await cluster_read.cluster_preflight_endpoint(
        live=False, summary=True, db=object()
    )
    assert preflight == {
        "schema_version": 1,
        "ready": True,
        "overall": "pass",
        "live_mtls_requested": False,
        "failed_checks": [],
        "warning_checks": [],
        "checks": [],
    }


@pytest.mark.asyncio
async def test_mtls_self_returns_only_authenticated_identity():
    identity = type(
        "Identity",
        (),
        {"node_uuid": "node-a", "cert_fingerprint": "sha256:abc"},
    )()
    assert await cluster_read.cluster_mtls_self(identity) == {
        "authenticated": True,
        "node_uuid": "node-a",
        "cert_fingerprint": "sha256:abc",
    }


@pytest.mark.asyncio
async def test_clock_skew_fails_past_a_quarter_of_the_lease(monkeypatch):
    """Leases are stamped with the database clock, so drift is a real hazard."""

    async def drifted(_db):
        far = datetime.now(timezone.utc) - timedelta(
            seconds=cluster_preflight.settings.cluster_primary_lease_ttl_secs
        )
        return (None, None, far, None)

    monkeypatch.setattr(
        cluster_preflight.cluster_membership, "read_canonical_primary", drifted
    )
    check = await cluster_preflight._clock_skew_check(object())
    assert check["status"] == "fail"
    assert check["blocking"] is True
    assert check["evidence"]["skew_seconds"] > check["evidence"]["limit_seconds"]


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _FakeDb:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, _stmt):
        return _Rows(self._rows)


class _Node:
    def __init__(self, uuid, state, not_after):
        self.node_uuid = uuid
        self.ha_state = state
        self.cert_not_after = not_after


@pytest.mark.asyncio
async def test_peer_state_rejects_two_primaries():
    far = datetime.now(timezone.utc) + timedelta(days=365)
    db = _FakeDb([_Node("a", "primary", far), _Node("b", "primary", far)])
    check = await cluster_preflight._peer_state_check(db)
    assert check["status"] == "fail"
    assert check["evidence"]["primaries"] == ["a", "b"]


@pytest.mark.asyncio
async def test_peer_state_rejects_a_peer_certificate_about_to_lapse():
    far = datetime.now(timezone.utc) + timedelta(days=365)
    soon = datetime.now(timezone.utc) + timedelta(days=1)
    db = _FakeDb([_Node("a", "primary", far), _Node("b", "secondary", soon)])
    check = await cluster_preflight._peer_state_check(db)
    assert check["status"] == "fail"
    assert check["evidence"]["earliest_cert_days"] < 2
