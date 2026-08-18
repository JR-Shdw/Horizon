# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Auto-JOIN reconciliation of a stale on-disk cluster cert.

Regression for the "node holds a cert but is absent from membership" trap:
an evicted node (e.g. its cluster-cert nginx reload failed and the primary
dropped it over mTLS), a half-joined node (cert persisted, membership row
never committed), or a node carrying a cert from a previous cluster after a
DB wipe would all be parked forever by the cert-on-disk auto-JOIN gate. The
task now skips that gate at boot, verifies membership post-unseal, and clears
a stale cert so it can re-JOIN.
"""

from unittest.mock import patch

import httpx
import pytest
from api.app import cluster_auto_join, cluster_cert
from api.app.config import settings


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _write_cert(tmp_path, monkeypatch):
    """Drop a real cert+key on disk and point settings at them."""
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cert_p.write_bytes(
        b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"
    )
    key_p.write_bytes(b"-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n")
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.example:8443")
    return cert_p, key_p


# --- _should_attempt(check_cert=...) -------------------------------------


def test_should_attempt_check_cert_false_ignores_cert_on_disk(tmp_path, monkeypatch):
    """With check_cert=False, a cert on disk no longer gates the task off."""
    _write_cert(tmp_path, monkeypatch)
    pw = tmp_path / "ha-password"
    pw.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_password_file", str(pw))

    ok_skip, reason = cluster_auto_join._should_attempt(check_cert=True)
    assert ok_skip is False and "cluster-cert already on disk" in reason

    ok_go, _ = cluster_auto_join._should_attempt(check_cert=False)
    assert ok_go is True


# --- _reconcile_stale_cert ------------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_removes_cert_when_not_a_member(tmp_path, monkeypatch):
    """404 from membership (evicted/unknown) -> stale cert removed."""
    cert_p, key_p = _write_cert(tmp_path, monkeypatch)

    async def _get(self, url, *a, **k):
        return _Resp(404)

    with patch("httpx.AsyncClient.get", _get):
        await cluster_auto_join._reconcile_stale_cert("node-uuid-evicted")

    assert not cluster_cert.has_cluster_cert(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_reconcile_keeps_cert_when_member(tmp_path, monkeypatch):
    """200 from membership (genuine member) -> cert preserved."""
    cert_p, key_p = _write_cert(tmp_path, monkeypatch)

    async def _get(self, url, *a, **k):
        return _Resp(200, {"node_uuid": "n", "ha_state": "secondary"})

    with patch("httpx.AsyncClient.get", _get):
        await cluster_auto_join._reconcile_stale_cert("node-uuid-member")

    assert cluster_cert.has_cluster_cert(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_reconcile_keeps_cert_on_transient_lookup_error(tmp_path, monkeypatch):
    """A non-404/200 (transient) must NOT discard a cert we can't prove stale."""
    cert_p, key_p = _write_cert(tmp_path, monkeypatch)

    async def _get(self, url, *a, **k):
        return _Resp(503, text="primary busy")

    with patch("httpx.AsyncClient.get", _get):
        await cluster_auto_join._reconcile_stale_cert("node-uuid-x")

    assert cluster_cert.has_cluster_cert(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_reconcile_keeps_cert_on_transport_error(tmp_path, monkeypatch):
    """A dial failure is transient -> keep the cert (fail-safe)."""
    cert_p, key_p = _write_cert(tmp_path, monkeypatch)

    async def _boom(self, url, *a, **k):
        raise httpx.ConnectError("simulated dial failure")

    with patch("httpx.AsyncClient.get", _boom):
        await cluster_auto_join._reconcile_stale_cert("node-uuid-x")

    assert cluster_cert.has_cluster_cert(str(cert_p), str(key_p))


@pytest.mark.asyncio
async def test_reconcile_noop_when_no_cert(tmp_path, monkeypatch):
    """No cert on disk -> nothing to reconcile, no membership call made."""
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "absent.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "absent.key"))
    called = False

    async def _get(self, url, *a, **k):
        nonlocal called
        called = True
        return _Resp(404)

    with patch("httpx.AsyncClient.get", _get):
        await cluster_auto_join._reconcile_stale_cert("node-uuid-x")

    assert called is False
