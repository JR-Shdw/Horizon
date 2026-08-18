# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""coverage push on the auto-JOIN module.

Targets the residual gaps in :mod:`api.app.cluster_auto_join` not
covered by :file:`test_ha_cluster_auto_join_bug_c.py` :

- ``_should_attempt_file`` empty path branch.
- ``_read_ha_password`` trailing-newline strip + too-short raise.
- ``_post_challenge`` transport error + unexpected status.
- ``_post_join`` transport error + permanent + unexpected-status branches.
- ``_get_membership`` transport error branch.
- ``_attempt_join_once`` age_vault dispatch (happy + recoverable + permanent).
- ``_attempt_join_once`` missing-observed-source-ip / missing-cluster-id raises.
- ``_attempt_join_once`` server-cert wrap + nginx reload.
- ``cluster_auto_join_task`` lifespan branches : gating-false, unseal wait,
  success, permanent error, transient retry, exhaust attempts.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from api.app import (
    cluster_auto_join,
    cluster_cert,
    ha_bootstrap,
    ha_password,
    nginx_reload,
)
from api.app.config import settings

# --- helpers ---------------------------------------------------------------


class _Resp:
    """Minimal httpx-like response stub (matches bug_c test fixture)."""

    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def _challenge_payload(**overrides) -> dict:
    base = {
        "nonce": "deadbeef" * 4,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": datetime.now(timezone.utc).isoformat(),
        "cluster_version": settings.version,
        "cluster_min_compatible_version": settings.cluster_min_compatible_version,
        "observed_source_ip": "192.0.2.42",
        "cluster_id": "test-cluster-id",
    }
    base.update(overrides)
    return base


# --- _should_attempt_file gating ------------------------------------------


def test_should_attempt_file_empty_path_returns_reason(monkeypatch):
    """``ha_password_file`` unset surfaces a typed reason."""
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_password_file", "")
    ok, reason = cluster_auto_join._should_attempt_file()
    assert ok is False
    assert "ha_password_file not set" in reason


def test_should_attempt_file_missing_file_returns_reason(tmp_path, monkeypatch):
    """Path configured but the file is absent -> typed reason for the operator."""
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_password_file", str(tmp_path / "absent"))
    ok, reason = cluster_auto_join._should_attempt_file()
    assert ok is False
    assert "not present" in reason


def test_should_attempt_file_happy_path_returns_true(tmp_path, monkeypatch):
    """Path configured + file exists -> gate opens."""
    p = tmp_path / "pw"
    p.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_password_file", str(p))
    ok, reason = cluster_auto_join._should_attempt_file()
    assert ok is True
    assert reason == ""


def test_should_attempt_age_vault_missing_age_path_returns_reason(monkeypatch):
    """Empty ``ha_password_age_path`` surfaces a typed reason."""
    monkeypatch.setattr(settings, "ha_password_age_path", "")
    ok, reason = cluster_auto_join._should_attempt_age_vault()
    assert ok is False
    assert "ha_password_age_path not set" in reason


def test_should_attempt_age_vault_missing_age_file_returns_reason(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "ha_password_age_path", str(tmp_path / "absent.age"))
    monkeypatch.setattr(settings, "ha_bootstrap_token_file", str(tmp_path / "token"))
    ok, reason = cluster_auto_join._should_attempt_age_vault()
    assert ok is False
    assert "not present" in reason


def test_should_attempt_age_vault_missing_token_path_returns_reason(
    tmp_path, monkeypatch
):
    p = tmp_path / "ciphertext.age"
    p.write_bytes(b"age-ciphertext-bytes")
    monkeypatch.setattr(settings, "ha_password_age_path", str(p))
    monkeypatch.setattr(settings, "ha_bootstrap_token_file", "")
    ok, reason = cluster_auto_join._should_attempt_age_vault()
    assert ok is False
    assert "ha_bootstrap_token_file not set" in reason


def test_should_attempt_age_vault_missing_token_file_returns_reason(
    tmp_path, monkeypatch
):
    p = tmp_path / "ciphertext.age"
    p.write_bytes(b"age-ciphertext-bytes")
    monkeypatch.setattr(settings, "ha_password_age_path", str(p))
    monkeypatch.setattr(
        settings, "ha_bootstrap_token_file", str(tmp_path / "absent-token")
    )
    ok, reason = cluster_auto_join._should_attempt_age_vault()
    assert ok is False
    assert "not present" in reason


def test_should_attempt_age_vault_happy_path_returns_true(tmp_path, monkeypatch):
    age_p = tmp_path / "ciphertext.age"
    age_p.write_bytes(b"age-ciphertext-bytes")
    token_p = tmp_path / "token"
    token_p.write_bytes(b"rh_xxxx")
    monkeypatch.setattr(settings, "ha_password_age_path", str(age_p))
    monkeypatch.setattr(settings, "ha_bootstrap_token_file", str(token_p))
    ok, reason = cluster_auto_join._should_attempt_age_vault()
    assert ok is True
    assert reason == ""


# --- _should_attempt top-level dispatch -----------------------------------


def test_should_attempt_cluster_ha_disabled(monkeypatch):
    monkeypatch.setattr(settings, "cluster_ha_enabled", False)
    ok, reason = cluster_auto_join._should_attempt()
    assert ok is False
    assert "cluster_ha_enabled" in reason


def test_should_attempt_auto_join_disabled(monkeypatch):
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", False)
    ok, reason = cluster_auto_join._should_attempt()
    assert ok is False
    assert "ha_auto_join" in reason


def test_should_attempt_no_primary_url(monkeypatch):
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "")
    ok, reason = cluster_auto_join._should_attempt()
    assert ok is False
    assert "ha_primary_url" in reason


def test_should_attempt_dispatches_age_vault_path(tmp_path, monkeypatch):
    """Storage = age_vault -> age-vault gating is the one that surfaces."""
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://p.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "age_vault")
    monkeypatch.setattr(settings, "ha_password_age_path", "")
    ok, reason = cluster_auto_join._should_attempt()
    assert ok is False
    assert "ha_password_age_path" in reason


def test_should_attempt_cert_already_on_disk_blocks(tmp_path, monkeypatch):
    """Both storage artifacts present + cluster-cert on disk -> REJOIN
    will use it ; the auto-JOIN stays out of the way."""
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://p.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    pw = tmp_path / "pw"
    pw.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "ha_password_file", str(pw))
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    cert_p.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n")
    key_p.write_bytes(b"-----BEGIN PRIVATE KEY-----\nstub\n")
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    ok, reason = cluster_auto_join._should_attempt()
    assert ok is False
    assert "cluster-cert already on disk" in reason


def test_should_attempt_happy_path_returns_true(tmp_path, monkeypatch):
    """All gates clear -> the auto-JOIN task can proceed."""
    monkeypatch.setattr(settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(settings, "ha_auto_join", True)
    monkeypatch.setattr(settings, "ha_primary_url", "https://p.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    pw = tmp_path / "pw"
    pw.write_bytes(b"x" * 32)
    monkeypatch.setattr(settings, "ha_password_file", str(pw))
    # No cluster-cert paths -> default settings point at /etc/... which
    # is absent under the test process -> has_cluster_cert returns False.
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "absent.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "absent.key"))
    ok, reason = cluster_auto_join._should_attempt()
    assert ok is True
    assert reason == ""


# --- _post_challenge permanent statuses ----------------------------------


@pytest.mark.asyncio
async def test_post_challenge_403_raises_permanent_error(monkeypatch):
    """403 (uuid revoked) -> permanent ; operator must unrevoke + restart."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_post(self, url, json=None):
        return _Resp(403, text="node_uuid revoked")

    with patch("httpx.AsyncClient.post", _fake_post):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinPermanentError,
                match=r"challenge rejected \(403\)",
            ):
                await cluster_auto_join._post_challenge(client, "uuid" * 8)


# --- _read_ha_password edge cases -----------------------------------------


def test_read_ha_password_strips_trailing_newline(tmp_path, monkeypatch):
    """``echo "..." > file`` adds a newline ; the wire format is raw bytes."""
    payload = b"x" * 32
    p = tmp_path / "pw"
    p.write_bytes(payload + b"\n")
    monkeypatch.setattr(settings, "ha_password_file", str(p))
    assert cluster_auto_join._read_ha_password() == payload


def test_read_ha_password_too_short_raises_permanent(tmp_path, monkeypatch):
    """Below ``ha_password_min_length`` -> permanent error, no retry."""
    p = tmp_path / "pw"
    p.write_bytes(b"short")
    monkeypatch.setattr(settings, "ha_password_file", str(p))
    monkeypatch.setattr(settings, "ha_password_min_length", 32)
    with pytest.raises(cluster_auto_join.AutoJoinPermanentError, match="too short"):
        cluster_auto_join._read_ha_password()


# --- _post_challenge branches ---------------------------------------------


@pytest.mark.asyncio
async def test_post_challenge_transport_error_raises_autojoin_error(monkeypatch):
    """``httpx.HTTPError`` -> recoverable AutoJoinError (retry path)."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _boom(self, url, json=None):
        raise httpx.ConnectError("simulated dial failure")

    with patch("httpx.AsyncClient.post", _boom):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinError, match="challenge transport error"
            ) as exc_info:
                await cluster_auto_join._post_challenge(client, "uuid" * 8)
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)


@pytest.mark.asyncio
async def test_post_challenge_500_raises_autojoin_error(monkeypatch):
    """Server-side 500 is unexpected -> recoverable AutoJoinError."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_post(self, url, json=None):
        return _Resp(500, text="internal server error")

    with patch("httpx.AsyncClient.post", _fake_post):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinError, match=r"challenge unexpected 500"
            ):
                await cluster_auto_join._post_challenge(client, "uuid" * 8)


# --- _post_join branches ---------------------------------------------------


@pytest.mark.asyncio
async def test_post_join_transport_error_raises_autojoin_error(monkeypatch):
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _boom(self, url, json=None):
        raise httpx.ReadTimeout("simulated read timeout")

    with patch("httpx.AsyncClient.post", _boom):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinError, match="join transport error"
            ) as exc_info:
                await cluster_auto_join._post_join(client, {"node_uuid": "x"})
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)


@pytest.mark.asyncio
async def test_post_join_401_raises_permanent_error(monkeypatch):
    """Bad ha_password -> permanent ; operator must rotate + redeploy."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_post(self, url, json=None):
        return _Resp(401, text="ha_password proof invalid")

    with patch("httpx.AsyncClient.post", _fake_post):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinPermanentError, match=r"join rejected \(401\)"
            ):
                await cluster_auto_join._post_join(client, {"node_uuid": "x"})


@pytest.mark.asyncio
async def test_post_join_500_raises_autojoin_error(monkeypatch):
    """Server hiccup -> recoverable, the surrounding loop retries."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _fake_post(self, url, json=None):
        return _Resp(500, text="boom")

    with patch("httpx.AsyncClient.post", _fake_post):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinError, match=r"join unexpected 500"
            ) as exc_info:
                await cluster_auto_join._post_join(client, {"node_uuid": "x"})
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)


# --- _get_membership branch ------------------------------------------------


@pytest.mark.asyncio
async def test_get_membership_transport_error_raises_autojoin_error(monkeypatch):
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _boom(self, url):
        raise httpx.ConnectError("simulated dial failure")

    with patch("httpx.AsyncClient.get", _boom):
        async with httpx.AsyncClient() as client:
            with pytest.raises(
                cluster_auto_join.AutoJoinError,
                match="membership lookup transport error",
            ) as exc_info:
                await cluster_auto_join._get_membership(client, "uuid" * 8)
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)


# --- _attempt_join_once challenge response edge cases ----------------------


@pytest.mark.asyncio
async def test_attempt_join_missing_observed_source_ip_raises_permanent(
    monkeypatch, tmp_path
):
    """A legacy primary omits ``observed_source_ip`` ; the proof
    cannot be computed -> permanent failure with the wire hint."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    pw = tmp_path / "pw"
    pw.write_bytes(b"y" * 32)
    monkeypatch.setattr(settings, "ha_password_file", str(pw))

    async def _fake_post(self, url, json=None):
        return _Resp(200, payload=_challenge_payload(observed_source_ip=None))

    with patch("httpx.AsyncClient.post", _fake_post):
        with pytest.raises(
            cluster_auto_join.AutoJoinPermanentError,
            match="observed_source_ip",
        ):
            await cluster_auto_join._attempt_join_once("uuid" * 8)


@pytest.mark.asyncio
async def test_attempt_join_missing_cluster_id_raises_permanent(monkeypatch, tmp_path):
    """Challenge response misses ``cluster_id`` and the joiner has no
    ``ha_cluster_id`` env fallback -> permanent."""
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_cluster_id", "")
    pw = tmp_path / "pw"
    pw.write_bytes(b"z" * 32)
    monkeypatch.setattr(settings, "ha_password_file", str(pw))

    async def _fake_post(self, url, json=None):
        return _Resp(200, payload=_challenge_payload(cluster_id=None))

    with patch("httpx.AsyncClient.post", _fake_post):
        with pytest.raises(
            cluster_auto_join.AutoJoinPermanentError,
            match="cluster_id",
        ):
            await cluster_auto_join._attempt_join_once("uuid" * 8)


# --- _attempt_join_once age_vault dispatch --------------------------------


@pytest.mark.asyncio
async def test_attempt_join_age_vault_permanent_error_propagates(monkeypatch):
    """``HaBootstrapPermanentError`` from the age-vault fetch maps to
    :class:`AutoJoinPermanentError` so the surrounding loop exits."""
    monkeypatch.setattr(settings, "ha_password_storage", "age_vault")
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _boom(client):
        raise ha_bootstrap.HaBootstrapPermanentError("bootstrap token revoked")

    monkeypatch.setattr(ha_bootstrap, "read_ha_password_from_vault", _boom)
    with pytest.raises(
        cluster_auto_join.AutoJoinPermanentError, match="bootstrap token revoked"
    ):
        await cluster_auto_join._attempt_join_once("uuid" * 8)


@pytest.mark.asyncio
async def test_attempt_join_age_vault_recoverable_error_propagates(monkeypatch):
    """``HaBootstrapError`` (non-permanent) maps to :class:`AutoJoinError`."""
    monkeypatch.setattr(settings, "ha_password_storage", "age_vault")
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")

    async def _boom(client):
        raise ha_bootstrap.HaBootstrapError("transient vault hiccup")

    monkeypatch.setattr(ha_bootstrap, "read_ha_password_from_vault", _boom)
    with pytest.raises(cluster_auto_join.AutoJoinError) as exc_info:
        await cluster_auto_join._attempt_join_once("uuid" * 8)
    assert not isinstance(exc_info.value, cluster_auto_join.AutoJoinPermanentError)


# --- _attempt_join_once happy path with server cert -----------------------


@pytest.mark.asyncio
async def test_attempt_join_happy_path_persists_server_cert_and_reloads_nginx(
    monkeypatch, tmp_path
):
    """Primary ships a server cert pair -> joiner unwraps it, atomic-writes
    both files, and triggers nginx reload. Cleanup is also fired
    when ``ha_password_storage == 'age_vault'``."""
    monkeypatch.setattr(settings, "ha_password_storage", "age_vault")
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    monkeypatch.setattr(settings, "ha_cluster_id", "")  # use wire value

    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    server_cert_p = tmp_path / "server.crt"
    server_key_p = tmp_path / "server.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    monkeypatch.setattr(settings, "cluster_server_cert_path", str(server_cert_p))
    monkeypatch.setattr(settings, "cluster_server_cert_key_path", str(server_key_p))
    monkeypatch.setattr(settings, "cluster_nginx_reload_cmd", "/bin/true")

    async def _fetch_password(client):
        return b"q" * 32

    monkeypatch.setattr(ha_bootstrap, "read_ha_password_from_vault", _fetch_password)

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _Resp(200, payload=_challenge_payload())
        # /join : minimal happy payload + server cert pair.
        return _Resp(
            200,
            payload={
                "node_cert_pem": "stub-cert",
                "node_cert_key_wrapped_hex": "ab" * 16,
                "server_cert_pem": "stub-server-cert",
                "server_cert_key_wrapped_hex": "cd" * 16,
                "ha_state": "secondary",
                "primary_uuid": "primary" * 4,
            },
        )

    with patch("httpx.AsyncClient.post", _fake_post):
        # Short-circuit the wrap-key unwrap : we are testing the
        # persistence + nginx reload, not the crypto.
        node_calls: list[tuple] = []
        server_calls: list[tuple] = []

        def _unwrap_node(wrapped, pw, uuid):
            node_calls.append((wrapped, bytes(pw), uuid))
            return b"-----BEGIN PRIVATE KEY-----\nnode-key\n-----END PRIVATE KEY-----\n"

        def _unwrap_server(wrapped, pw, uuid):
            server_calls.append((wrapped, bytes(pw), uuid))
            return b"-----BEGIN PRIVATE KEY-----\nsrv-key\n-----END PRIVATE KEY-----\n"

        save_node: list[tuple] = []
        save_server: list[tuple] = []
        reload_calls: list[str] = []
        cleanup_calls: list[None] = []

        def _save_cluster(cert, key, cp, kp):
            save_node.append((cert, key, cp, kp))

        def _save_server(cert, key, cp, kp):
            save_server.append((cert, key, cp, kp))

        def _reload(cmd):
            reload_calls.append(cmd)
            return True

        def _cleanup():
            cleanup_calls.append(None)

        monkeypatch.setattr(ha_password, "unwrap_node_key_for_joiner", _unwrap_node)
        monkeypatch.setattr(ha_password, "unwrap_server_key_for_joiner", _unwrap_server)
        monkeypatch.setattr(cluster_cert, "save_cluster_cert", _save_cluster)
        monkeypatch.setattr(nginx_reload, "save_server_cert", _save_server)
        monkeypatch.setattr(nginx_reload, "reload_nginx", _reload)
        monkeypatch.setattr(ha_bootstrap, "cleanup_on_join_success", _cleanup)

        ok = await cluster_auto_join._attempt_join_once("uuid" * 8)
    assert ok is True
    assert len(node_calls) == 1 and len(server_calls) == 1
    assert len(save_node) == 1 and len(save_server) == 1
    assert reload_calls == ["/bin/true"]
    assert cleanup_calls == [None]  # age_vault cleanup fired


@pytest.mark.asyncio
async def test_attempt_join_happy_path_pre_slice_11d_skips_server_cert(
    monkeypatch, tmp_path
):
    """A legacy primary omits the server cert fields ; the joiner
    logs + persists only the node cert. The renewal loop will pick up
    the server cert at the next refresh-cert tick."""
    monkeypatch.setattr(settings, "ha_password_storage", "file")
    monkeypatch.setattr(settings, "ha_primary_url", "https://primary.invalid")
    monkeypatch.setattr(settings, "ha_cluster_id", "test-cluster-id")
    pw = tmp_path / "pw"
    pw.write_bytes(b"k" * 32)
    monkeypatch.setattr(settings, "ha_password_file", str(pw))
    cert_p = tmp_path / "node.pem"
    key_p = tmp_path / "node.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))

    async def _fake_post(self, url, json=None):
        if "/challenge" in url:
            return _Resp(200, payload=_challenge_payload())
        return _Resp(
            200,
            payload={
                "node_cert_pem": "stub-cert",
                "node_cert_key_wrapped_hex": "ef" * 16,
                "ha_state": "secondary",
            },
        )

    server_calls: list = []

    monkeypatch.setattr(
        ha_password,
        "unwrap_node_key_for_joiner",
        lambda w, p, u: b"-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n",
    )
    monkeypatch.setattr(
        ha_password,
        "unwrap_server_key_for_joiner",
        lambda *a, **k: server_calls.append(a) or b"",
    )
    monkeypatch.setattr(cluster_cert, "save_cluster_cert", lambda *a, **k: None)
    monkeypatch.setattr(nginx_reload, "save_server_cert", lambda *a, **k: None)
    monkeypatch.setattr(nginx_reload, "reload_nginx", lambda cmd: True)

    with patch("httpx.AsyncClient.post", _fake_post):
        ok = await cluster_auto_join._attempt_join_once("uuid" * 8)
    assert ok is True
    # Server-key unwrap must NOT have been called.
    assert server_calls == []


# --- cluster_auto_join_task lifespan branches -----------------------------


@pytest.mark.asyncio
async def test_lifespan_task_returns_early_when_gating_false(monkeypatch):
    """``_should_attempt`` returning False -> log + exit, no unseal wait."""
    monkeypatch.setattr(
        cluster_auto_join,
        "_should_attempt",
        lambda check_cert=True: (False, "cluster_ha_enabled=false"),
    )
    # No vault.sealed access expected -- assert by completing immediately.
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)


@pytest.mark.asyncio
async def test_lifespan_task_returns_after_unseal_post_gate_false(monkeypatch):
    """Pre-unseal gate True but post-unseal gate False -> cancel cleanly."""
    calls = {"n": 0}

    def _gate(check_cert=True):
        calls["n"] += 1
        # First call (pre-unseal) -> True ; second (post-unseal) -> False.
        if calls["n"] == 1:
            return True, ""
        return False, "cert appeared during unseal wait"

    monkeypatch.setattr(cluster_auto_join, "_should_attempt", _gate)
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    # No cert on disk -> _reconcile_stale_cert is a no-op between the two gates.
    monkeypatch.setattr(
        cluster_auto_join.cluster_cert, "has_cluster_cert", lambda *a, **k: False
    )

    class _FakeVault:
        sealed = False  # skip the unseal poll entirely

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_lifespan_task_success_returns_on_first_attempt(monkeypatch):
    """One successful ``_attempt_join_once`` -> task exits after attempt 1."""
    monkeypatch.setattr(
        cluster_auto_join, "_should_attempt", lambda check_cert=True: (True, "")
    )

    class _FakeVault:
        sealed = False

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 3)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)

    attempt = AsyncMock(return_value=True)
    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    attempt.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_task_permanent_error_exits_without_retry(monkeypatch):
    """``AutoJoinPermanentError`` exits the loop on the first attempt --
    no further calls, no sleep."""
    monkeypatch.setattr(
        cluster_auto_join, "_should_attempt", lambda check_cert=True: (True, "")
    )

    class _FakeVault:
        sealed = False

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 5)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)

    attempt = AsyncMock(
        side_effect=cluster_auto_join.AutoJoinPermanentError("operator R1 required")
    )
    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    assert attempt.await_count == 1


@pytest.mark.asyncio
async def test_lifespan_task_recoverable_error_retries_then_succeeds(monkeypatch):
    """Two AutoJoinError + one success -> 3 attempts total."""
    monkeypatch.setattr(
        cluster_auto_join, "_should_attempt", lambda check_cert=True: (True, "")
    )

    class _FakeVault:
        sealed = False

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 5)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)

    attempt = AsyncMock(
        side_effect=[
            cluster_auto_join.AutoJoinError("transient 1"),
            cluster_auto_join.AutoJoinError("transient 2"),
            True,
        ]
    )
    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    assert attempt.await_count == 3


@pytest.mark.asyncio
async def test_lifespan_task_unexpected_crash_retries(monkeypatch):
    """A generic Exception is logged and the loop retries."""
    monkeypatch.setattr(
        cluster_auto_join, "_should_attempt", lambda check_cert=True: (True, "")
    )

    class _FakeVault:
        sealed = False

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 2)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)

    attempt = AsyncMock(side_effect=[RuntimeError("unexpected"), True])
    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    assert attempt.await_count == 2


@pytest.mark.asyncio
async def test_lifespan_task_exhausts_attempts_and_logs_error(monkeypatch):
    """All attempts fail with transient errors -> loop exits silently
    after the final attempt + the ``exhausted`` log line."""
    monkeypatch.setattr(
        cluster_auto_join, "_should_attempt", lambda check_cert=True: (True, "")
    )

    class _FakeVault:
        sealed = False

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 3)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)

    attempt = AsyncMock(side_effect=cluster_auto_join.AutoJoinError("never recovers"))
    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    assert attempt.await_count == 3


@pytest.mark.asyncio
async def test_lifespan_task_waits_for_unseal_then_proceeds(monkeypatch):
    """Initially sealed -> poll loop yields ; once flipped, the gate
    re-fires and the attempt runs."""
    monkeypatch.setattr(
        cluster_auto_join, "_should_attempt", lambda check_cert=True: (True, "")
    )

    class _FakeVault:
        def __init__(self):
            self._poll_count = 0
            self.sealed = True

        def __getattribute__(self, name):
            # Flip on the third read so the while-loop spins twice.
            if name == "sealed":
                object.__setattr__(
                    self,
                    "_poll_count",
                    object.__getattribute__(self, "_poll_count") + 1,
                )
                return object.__getattribute__(self, "_poll_count") < 3
            return object.__getattribute__(self, name)

    monkeypatch.setattr(cluster_auto_join, "vault", _FakeVault())
    monkeypatch.setattr(cluster_auto_join, "get_node_uuid", lambda: "uuid" * 8)
    monkeypatch.setattr(settings, "ha_auto_join_max_attempts", 1)
    monkeypatch.setattr(settings, "ha_auto_join_retry_secs", 0)

    # Speed up the 5s unseal poll.
    real_sleep = asyncio.sleep

    async def _fast_sleep(delay):
        await real_sleep(0)

    monkeypatch.setattr(cluster_auto_join.asyncio, "sleep", _fast_sleep)

    attempt = AsyncMock(return_value=True)
    monkeypatch.setattr(cluster_auto_join, "_attempt_join_once", attempt)
    await asyncio.wait_for(cluster_auto_join.cluster_auto_join_task(), timeout=2.0)
    attempt.assert_awaited_once()


def test_a_password_whose_last_byte_is_a_newline_survives(tmp_path, monkeypatch):
    """1-in-256 permanent join failure: the secret IS raw token_bytes(32).

    An unconditional strip ate a real secret byte, left 31, tripped the floor
    and raised AutoJoinPermanentError -- so that node could never join. The
    automated path (ansible add-joiner.yml) writes exactly these raw bytes
    with no terminator, so the strip was corrupting the real case.
    """
    payload = b"x" * 31 + b"\n"
    assert len(payload) == 32
    p = tmp_path / "pw"
    p.write_bytes(payload)
    monkeypatch.setattr(settings, "ha_password_file", str(p))
    monkeypatch.setattr(settings, "ha_password_min_length", 32)
    assert cluster_auto_join._read_ha_password() == payload


def test_an_operator_echo_newline_is_still_stripped(tmp_path, monkeypatch):
    """The convenience the strip existed for keeps working: a genuine `echo`
    file is one byte LONGER than the password, so dropping its newline still
    satisfies the floor."""
    payload = b"y" * 32
    p = tmp_path / "pw"
    p.write_bytes(payload + b"\n")
    monkeypatch.setattr(settings, "ha_password_file", str(p))
    monkeypatch.setattr(settings, "ha_password_min_length", 32)
    assert cluster_auto_join._read_ha_password() == payload


def test_a_genuinely_short_password_is_still_refused(tmp_path, monkeypatch):
    """The floor must not be weakened by the conditional strip."""
    p = tmp_path / "pw"
    p.write_bytes(b"z" * 20 + b"\n")
    monkeypatch.setattr(settings, "ha_password_file", str(p))
    monkeypatch.setattr(settings, "ha_password_min_length", 32)
    with pytest.raises(cluster_auto_join.AutoJoinPermanentError, match="too short"):
        cluster_auto_join._read_ha_password()
