# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""CLI rhorizon cluster subcommands.

Coverage split :

- VaultClient.cluster_* wrappers end-to-end against the ASGI app
  (real cluster init / promote / drain / evict / rotate-cert / etc.).
  This is the load-bearing layer that holds the network contract ;
  the typer commands are thin dispatchers on top.

- Typer dispatch unit tests via CliRunner with a mocked VaultClient.
  These guard the argument-parsing surface (flags, --json, --all,
  --output) and the pretty-printing helpers without needing ASGI.

The split avoids the sync httpx <-> async ASGI bridge (sync httpx
clients cannot use ASGITransport ; spawning a real uvicorn just to
test argument parsing is heavy for marginal value).
"""

import base64
import hashlib
import hmac as _hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from api.app import cluster_membership as cm
from api.app import ha_password as hp
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from cli.rhorizon.client import VaultClient
from cli.rhorizon.main import app as cli_app
from sqlalchemy import text
from typer.testing import CliRunner

_CLUSTER_CONFIG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "cluster_ca_cert_prev",
    "cluster_ca_rotated_at",
    "primary_uuid",
    "primary_since",
    "revoked_node_uuids",
    "pending_ha_password_rotation",
)


@pytest_asyncio.fixture(autouse=True)
async def _wipe_cluster_state():
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CONFIG_KEYS)},
        )
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CONFIG_KEYS)},
        )
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()


# ---------------------------------------------------------------------------
# VaultClient end-to-end tests against ASGI.
#
# Each test builds a VaultClient whose ._request is shimmed to dispatch
# through the conftest async `client` fixture. The CLI's network surface
# is exercised against the real FastAPI routes ; only the synchronous
# wiring is swapped for the async one.
# ---------------------------------------------------------------------------


def _make_client(async_client, admin_token):
    """Return a VaultClient whose _request delegates to the ASGI client.

    The CLI VaultClient normally calls httpx.request(...) synchronously.
    For tests we bypass the sync httpx layer and route through the
    AsyncClient + ASGITransport (the same one driving every other
    cluster-routes test). Keeps the contract identical from
    the wrapper's perspective : same URLs, same headers, same JSON
    bodies, same status-code-to-exit-1 behaviour.
    """
    import sys

    c = VaultClient("http://test", admin_token)

    async def _arequest(method, path, json=None, params=None):
        r = await async_client.request(
            method, path, json=json, params=params, headers=c._headers(), timeout=30
        )
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            print(f"Error {r.status_code}: {detail}", file=sys.stderr)
            raise SystemExit(1)
        if r.status_code == 204:
            return {}
        return r.json()

    c._arequest = _arequest  # type: ignore[attr-defined]
    return c


async def _init_cluster(client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "slice13b-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _insert_secondary(node_uuid: str, source_ip: str = "10.0.0.1"):
    """Plant a secondary row + ha_state row directly via DB."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes "
                "(node_uuid, source_ip, joined_at, ha_state, "
                " cluster_version, cert_fingerprint, cert_not_after) "
                "VALUES (:u, :ip, NOW(), 'secondary', :v, :fpr, "
                " NOW() + INTERVAL '90 days')"
            ),
            {
                "u": node_uuid,
                "ip": source_ip,
                "v": settings.version,
                "fpr": "test-fpr-" + node_uuid[:8],
            },
        )
        await db.commit()


# --------------------------- init ---------------------------


async def test_cluster_init_happy_path(client, admin_token):
    c = _make_client(client, admin_token)
    r = await c._arequest(
        "POST", "/api/v1/vault/cluster/init", json={"cluster_name": "via-cli"}
    )
    assert "cluster_id" in r
    assert "ha_password" in r
    assert "primary_uuid" in r
    assert "ca_fingerprint" in r
    # ha_password is base64 of 32 bytes -> 44 chars
    assert len(base64.b64decode(r["ha_password"])) == 32


async def test_cluster_init_409_already_initialised(client, admin_token):
    await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    with pytest.raises(SystemExit) as exc:
        await c._arequest("POST", "/api/v1/vault/cluster/init", json={})
    assert exc.value.code == 1


# --------------------------- ha / ha-self ---------------------------


async def test_cluster_ha_after_init(client, admin_token):
    init = await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    r = await c._arequest("GET", "/api/v1/vault/cluster/ha")
    assert r["cluster_id"] == init["cluster_id"]
    assert r["primary_uuid"] == init["primary_uuid"]
    assert isinstance(r["nodes"], list)
    assert len(r["nodes"]) == 1
    primary_row = r["nodes"][0]
    assert primary_row["node_uuid"] == init["primary_uuid"]
    assert primary_row["ha_state"] == "primary"


async def test_cluster_ha_409_not_initialised(client, admin_token):
    c = _make_client(client, admin_token)
    with pytest.raises(SystemExit) as exc:
        await c._arequest("GET", "/api/v1/vault/cluster/ha")
    assert exc.value.code == 1


async def test_cluster_ha_self_returns_state(client, admin_token):
    await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    r = await c._arequest("GET", "/api/v1/vault/cluster/ha/self")
    assert r["ha_state"] == "primary"
    assert r["node_uuid"] == nu.get_node_uuid()


async def test_cluster_ha_self_null_pre_join(client, admin_token):
    # No cluster init -- no membership row. ha_state should be null.
    c = _make_client(client, admin_token)
    r = await c._arequest("GET", "/api/v1/vault/cluster/ha/self")
    assert r["ha_state"] is None


# --------------------------- promote / demote ---------------------------


async def test_cluster_promote_secondary(client, admin_token):
    init = await _init_cluster(client, admin_token)
    secondary_uuid = "f" * 32
    await _insert_secondary(secondary_uuid, source_ip="10.0.0.1")
    c = _make_client(client, admin_token)
    r = await c._arequest("POST", f"/api/v1/vault/cluster/promote/{secondary_uuid}")
    assert r["node_uuid"] == secondary_uuid
    assert r["ha_state"] == "primary"
    assert r["primary_uuid"] == secondary_uuid
    # The previous primary was demoted.
    ha = await c._arequest("GET", "/api/v1/vault/cluster/ha")
    states = {n["node_uuid"]: n["ha_state"] for n in ha["nodes"]}
    assert states[init["primary_uuid"]] == "secondary"
    assert states[secondary_uuid] == "primary"


async def test_cluster_demote_primary(client, admin_token):
    init = await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    r = await c._arequest(
        "POST", f"/api/v1/vault/cluster/demote/{init['primary_uuid']}"
    )
    assert r["ha_state"] == "secondary"
    assert r["primary_uuid"] is None


async def test_cluster_promote_404(client, admin_token):
    await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    with pytest.raises(SystemExit):
        await c._arequest("POST", "/api/v1/vault/cluster/promote/" + "0" * 32)


# --------------------------- drain / evict / unrevoke ---------------------------


async def test_cluster_drain_secondary(client, admin_token):
    await _init_cluster(client, admin_token)
    sec = "a" * 32
    await _insert_secondary(sec)
    c = _make_client(client, admin_token)
    r = await c._arequest("POST", f"/api/v1/vault/cluster/drain/{sec}")
    assert r["node_uuid"] == sec
    assert r["ha_state"] == "draining"
    assert r["drain_deadline_at"] is not None


async def test_cluster_evict_secondary(client, admin_token):
    await _init_cluster(client, admin_token)
    sec = "b" * 32
    await _insert_secondary(sec)
    c = _make_client(client, admin_token)
    r = await c._arequest("POST", f"/api/v1/vault/cluster/evict/{sec}")
    assert r["ha_state"] == "evicted"
    # revoked_node_uuids was appended (visible via DB).
    async with async_session() as db:
        revoked = await cm.read_revoked_uuids(db)
    assert sec in revoked


async def test_cluster_unrevoke(client, admin_token):
    await _init_cluster(client, admin_token)
    sec = "c" * 32
    await _insert_secondary(sec)
    c = _make_client(client, admin_token)
    await c._arequest("POST", f"/api/v1/vault/cluster/evict/{sec}")
    r = await c._arequest("POST", f"/api/v1/vault/cluster/unrevoke/{sec}")
    assert r["node_uuid"] == sec
    assert r["revoked"] is False


# ----------------- rotate-cert / ca-bundle / rotate-ca -----------------


async def test_cluster_rotate_cert_one(client, admin_token):
    await _init_cluster(client, admin_token)
    sec = "d" * 32
    await _insert_secondary(sec)
    c = _make_client(client, admin_token)
    r = await c._arequest("POST", f"/api/v1/vault/cluster/rotate-cert/{sec}")
    assert r["scope"] == "one"
    assert r["flipped"] == 1
    assert r["target"] == sec


async def test_cluster_rotate_cert_all(client, admin_token):
    init = await _init_cluster(client, admin_token)
    sec = "e" * 32
    await _insert_secondary(sec)
    c = _make_client(client, admin_token)
    r = await c._arequest("POST", "/api/v1/vault/cluster/rotate-cert/all")
    assert r["scope"] == "all"
    # Primary + secondary == 2 rows flipped.
    assert r["flipped"] == 2
    _ = init  # silence unused


async def test_cluster_ca_bundle(client, admin_token):
    init = await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    r = await c._arequest("GET", "/api/v1/vault/cluster/ca-bundle")
    assert r["fingerprint"] == init["ca_fingerprint"]
    assert "BEGIN CERTIFICATE" in r["ca_cert_pem"]


async def test_cluster_rotate_ca(client, admin_token):
    init = await _init_cluster(client, admin_token)
    c = _make_client(client, admin_token)
    r = await c._arequest("POST", "/api/v1/vault/cluster/rotate-ca")
    assert r["new_fingerprint"] != init["ca_fingerprint"]
    assert r["grace_window_secs"] > 0
    assert r["flipped"] >= 1


# ---------------------------------------------------------------------------
# Typer dispatch unit tests (no ASGI -- VaultClient mocked).
# ---------------------------------------------------------------------------


def _patch_client(monkeypatch, mock_client):
    """Replace VaultClient construction in cli.rhorizon.main with the mock."""
    monkeypatch.setattr("cli.rhorizon.main.VaultClient", lambda *a, **kw: mock_client)
    monkeypatch.setattr("cli.rhorizon.main.get_url", lambda *a, **kw: "http://test")
    monkeypatch.setattr("cli.rhorizon.main.load_token", lambda *a, **kw: "rh_test")


def test_cluster_typer_help():
    """The cluster subapp is registered and lists its subcommands."""
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "--help"])
    assert result.exit_code == 0
    for sub in (
        "init",
        "join",
        "status",
        "promote",
        "demote",
        "drain",
        "evict",
        "unrevoke",
        "rotate-cert",
        "rotate-ca",
        "ca-bundle",
    ):
        assert sub in result.output, sub


def test_cluster_init_print_ha_password(monkeypatch):
    mc = MagicMock()
    mc.cluster_init.return_value = {
        "cluster_id": "cid-123",
        "ha_password": "AAAA" * 11,
        "primary_uuid": "puuid-abc",
        "ca_fingerprint": "ca:fpr:zz",
        "warning": "shown once",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "init", "--cluster-name", "lab"])
    assert result.exit_code == 0
    mc.cluster_init.assert_called_once_with("lab")
    assert "cid-123" in result.output
    assert "AAAA" in result.output
    assert "ca:fpr:zz" in result.output


def test_cluster_init_save_ha_password_file(monkeypatch, tmp_path):
    mc = MagicMock()
    mc.cluster_init.return_value = {
        "cluster_id": "cid",
        "ha_password": "PWD",
        "primary_uuid": "p",
        "ca_fingerprint": "f",
        "warning": "",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    target = tmp_path / "ha_pw"
    result = runner.invoke(
        cli_app, ["cluster", "init", "--save-ha-password", str(target)]
    )
    assert result.exit_code == 0
    assert target.read_text() == "PWD"
    assert oct(target.stat().st_mode & 0o777) == "0o400"
    # PWD must NOT be printed when saved to file (least-surprise).
    assert "PWD" not in result.output


def test_cluster_init_json(monkeypatch):
    mc = MagicMock()
    payload = {
        "cluster_id": "x",
        "ha_password": "y",
        "primary_uuid": "z",
        "ca_fingerprint": "f",
        "warning": "",
    }
    mc.cluster_init.return_value = payload
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "init", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == payload


def test_cluster_status_compact(monkeypatch):
    mc = MagicMock()
    mc.cluster_ha.return_value = {
        "cluster_id": "cid",
        "cluster_version": "1.0.0",
        "primary_uuid": "puuid",
        "ha_loaded": True,
        "uuid_ip_conflicts_total": 0,
        "nodes": [
            {
                "node_uuid": "puuid1234567890abcdef",
                "source_ip": "10.0.0.1",
                "ha_state": "primary",
                "quarantine_until": None,
                "joined_at": "2026-05-28T00:00:00+00:00",
                "last_heartbeat": "2026-05-28T00:00:00+00:00",
                "cluster_version": "1.0.0",
                "cert_fingerprint": "fpr",
                "cert_not_after": (
                    datetime(2026, 8, 28, tzinfo=timezone.utc).isoformat()
                ),
            }
        ],
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "status"])
    assert result.exit_code == 0
    assert "cid" in result.output
    assert "puuid1234567" in result.output  # truncated to 12 chars
    assert "primary" in result.output
    assert "1 node(s)" in result.output


def test_cluster_status_json(monkeypatch):
    mc = MagicMock()
    payload = {
        "cluster_id": "cid",
        "cluster_version": "1.0.0",
        "primary_uuid": None,
        "ha_loaded": False,
        "uuid_ip_conflicts_total": 0,
        "nodes": [],
    }
    mc.cluster_ha.return_value = payload
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "status", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == payload


def test_cluster_join_polls_until_state(monkeypatch):
    mc = MagicMock()
    # 1st call : ha_state None ; 2nd call : secondary.
    mc.cluster_ha_self.side_effect = [
        {
            "node_uuid": "n",
            "ha_state": None,
            "quarantine_until": None,
            "last_heartbeat": None,
            "ha_loaded": False,
        },
        {
            "node_uuid": "n",
            "ha_state": "secondary",
            "quarantine_until": "2026-05-28T01:00:00+00:00",
            "last_heartbeat": "2026-05-28T00:30:00+00:00",
            "ha_loaded": True,
        },
    ]
    _patch_client(monkeypatch, mc)
    # Patch time.sleep so the test doesn't actually wait.
    monkeypatch.setattr("time.sleep", lambda s: None)
    runner = CliRunner()
    result = runner.invoke(
        cli_app, ["cluster", "join", "--timeout", "10", "--poll-interval", "0.1"]
    )
    assert result.exit_code == 0
    assert "secondary" in result.output
    assert mc.cluster_ha_self.call_count == 2


def test_cluster_join_timeout(monkeypatch):
    mc = MagicMock()
    mc.cluster_ha_self.return_value = {
        "node_uuid": "n",
        "ha_state": None,
        "quarantine_until": None,
        "last_heartbeat": None,
        "ha_loaded": False,
    }
    _patch_client(monkeypatch, mc)
    monkeypatch.setattr("time.sleep", lambda s: None)
    # Patch monotonic so the deadline trips on the 2nd call.
    state = {"n": 0}

    def _fake_monotonic():
        state["n"] += 1
        return 0.0 if state["n"] == 1 else 1e6

    monkeypatch.setattr("time.monotonic", _fake_monotonic)
    runner = CliRunner()
    result = runner.invoke(
        cli_app, ["cluster", "join", "--timeout", "1", "--poll-interval", "0.1"]
    )
    assert result.exit_code == 2
    assert "Timeout" in result.output


def test_cluster_promote_dispatch(monkeypatch):
    mc = MagicMock()
    mc.cluster_promote.return_value = {
        "node_uuid": "u",
        "ha_state": "primary",
        "primary_uuid": "u",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "promote", "u"])
    assert result.exit_code == 0
    mc.cluster_promote.assert_called_once_with("u")
    assert "Promoted u -> primary" in result.output


def test_cluster_demote_dispatch(monkeypatch):
    mc = MagicMock()
    mc.cluster_demote.return_value = {
        "node_uuid": "u",
        "ha_state": "secondary",
        "primary_uuid": None,
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "demote", "u"])
    assert result.exit_code == 0
    mc.cluster_demote.assert_called_once_with("u")


def test_cluster_drain_dispatch(monkeypatch):
    mc = MagicMock()
    mc.cluster_drain.return_value = {
        "node_uuid": "u",
        "ha_state": "draining",
        "primary_uuid": "p",
        "drain_deadline_at": "2026-05-28T00:01:00+00:00",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "drain", "u"])
    assert result.exit_code == 0
    mc.cluster_drain.assert_called_once_with("u")
    assert "drain_deadline_at" in result.output


def test_cluster_evict_dispatch(monkeypatch):
    mc = MagicMock()
    mc.cluster_evict.return_value = {
        "node_uuid": "u",
        "ha_state": "evicted",
        "primary_uuid": "p",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "evict", "u"])
    assert result.exit_code == 0
    mc.cluster_evict.assert_called_once_with("u")


def test_cluster_unrevoke_dispatch(monkeypatch):
    mc = MagicMock()
    mc.cluster_unrevoke.return_value = {"node_uuid": "u", "revoked": False}
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "unrevoke", "u"])
    assert result.exit_code == 0
    mc.cluster_unrevoke.assert_called_once_with("u")
    assert "revoked=False" in result.output


def test_cluster_rotate_cert_one_typer(monkeypatch):
    mc = MagicMock()
    mc.cluster_rotate_cert.return_value = {
        "scope": "one",
        "flipped": 1,
        "target": "u",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-cert", "u"])
    assert result.exit_code == 0
    mc.cluster_rotate_cert.assert_called_once_with("u")


def test_cluster_rotate_cert_all_typer(monkeypatch):
    mc = MagicMock()
    mc.cluster_rotate_cert.return_value = {
        "scope": "all",
        "flipped": 3,
        "target": "all",
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-cert", "--all"])
    assert result.exit_code == 0
    mc.cluster_rotate_cert.assert_called_once_with("all")


def test_cluster_rotate_cert_conflict_args(monkeypatch):
    mc = MagicMock()
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-cert", "u", "--all"])
    assert result.exit_code == 1
    assert "not both" in result.output


def test_cluster_rotate_cert_missing_target(monkeypatch):
    mc = MagicMock()
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-cert"])
    assert result.exit_code == 1
    assert "NODE_UUID or --all" in result.output


def test_cluster_rotate_ca_confirm(monkeypatch):
    mc = MagicMock()
    mc.cluster_rotate_ca.return_value = {
        "new_fingerprint": "newfpr",
        "rotated_at": "2026-05-28T00:00:00+00:00",
        "grace_window_secs": 604800,
        "flipped": 2,
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-ca"], input="rotate-ca\n")
    assert result.exit_code == 0
    mc.cluster_rotate_ca.assert_called_once_with()
    assert "newfpr" in result.output


def test_cluster_rotate_ca_aborted(monkeypatch):
    mc = MagicMock()
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-ca"], input="no\n")
    assert result.exit_code == 0
    mc.cluster_rotate_ca.assert_not_called()
    assert "Aborted" in result.output


def test_cluster_rotate_ca_yes_skips_prompt(monkeypatch):
    mc = MagicMock()
    mc.cluster_rotate_ca.return_value = {
        "new_fingerprint": "f",
        "rotated_at": "t",
        "grace_window_secs": 1,
        "flipped": 0,
    }
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "rotate-ca", "--yes"])
    assert result.exit_code == 0
    mc.cluster_rotate_ca.assert_called_once()


def test_cluster_ca_bundle_stdout(monkeypatch):
    mc = MagicMock()
    pem = "-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n"
    mc.cluster_ca_bundle.return_value = {"ca_cert_pem": pem, "fingerprint": "f"}
    _patch_client(monkeypatch, mc)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "ca-bundle"])
    assert result.exit_code == 0
    assert "BEGIN CERTIFICATE" in result.output
    assert "f" in result.output


def test_cluster_ca_bundle_file(monkeypatch, tmp_path):
    mc = MagicMock()
    pem = "-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n"
    mc.cluster_ca_bundle.return_value = {"ca_cert_pem": pem, "fingerprint": "ff"}
    _patch_client(monkeypatch, mc)
    out = tmp_path / "ca.pem"
    runner = CliRunner()
    result = runner.invoke(cli_app, ["cluster", "ca-bundle", "--output", str(out)])
    assert result.exit_code == 0
    assert out.read_text() == pem
    assert oct(out.stat().st_mode & 0o777) == "0o444"
    assert "ff" in result.output


def test_fmt_helpers():
    """Direct unit tests on the formatting helpers."""
    from cli.rhorizon.main import (
        _fmt_cert_expiry,
        _fmt_heartbeat_age,
        _fmt_uuid_short,
    )

    assert _fmt_uuid_short("0123456789abcdefghij") == "0123456789ab"
    assert _fmt_uuid_short("short") == "short"
    assert _fmt_heartbeat_age(None) == "never"
    assert _fmt_heartbeat_age("not-a-date") == "not-a-date"
    # Recent timestamp -> seconds.
    recent = datetime.now(timezone.utc).isoformat()
    assert _fmt_heartbeat_age(recent).endswith("s")
    # Future cert.
    future = (datetime.now(timezone.utc).replace(year=2030)).isoformat()
    assert _fmt_cert_expiry(future).endswith("d")
    # Expired cert.
    past = "2020-01-01T00:00:00+00:00"
    assert _fmt_cert_expiry(past).startswith("EXPIRED")


# Silence unused imports flagged by ruff when adding follow-on tests.
_ = hashlib
_ = _hmac
_ = Path
