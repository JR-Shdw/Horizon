"""Tests for tools/matrix-notify.

Subprocess-driven - invokes the helper script the way an operator would
and verifies the resulting Matrix API call. A fake homeserver and a fake
vault are stood up on ephemeral ports; the helper is given a temp config
dir pointing at them.

Same pattern as test_git_credential_helper.py - pure stdlib, no third-
party HTTP mocking, no live network.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
HELPER = REPO_ROOT / "tools" / "matrix-notify"


# ---------------------------------------------------------------------------
# Helpers: fake vault + fake Matrix homeserver
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _FakeVaultHandler(http.server.BaseHTTPRequestHandler):
    secrets: dict[str, str] = {}
    expected_token: str | None = None

    def log_message(self, *_):  # silence
        pass

    def do_GET(self):  # noqa: N802 - stdlib API
        prefix = "/api/v1/vault/secrets/"
        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        if self.expected_token:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {self.expected_token}":
                self.send_error(401)
                return
        name = self.path[len(prefix) :].split("?")[0]
        if name not in self.secrets:
            self.send_error(404)
            return
        body = json.dumps({"value": self.secrets[name]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _FakeMatrixHandler(http.server.BaseHTTPRequestHandler):
    """Captures the room/event PUT and stores it on the class."""

    captured: list[dict] = []
    expected_token: str | None = None
    fail_status: int | None = None  # set to e.g. 403 to simulate failure

    def log_message(self, *_):
        pass

    def do_PUT(self):  # noqa: N802
        if self.fail_status:
            self.send_error(self.fail_status, "simulated")
            return
        # Path: /_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}
        if "/rooms/" not in self.path:
            self.send_error(404)
            return
        if self.expected_token:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {self.expected_token}":
                self.send_error(401)
                return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw)
        except ValueError:
            self.send_error(400)
            return
        # Extract room ID from path
        # /_matrix/client/v3/rooms/<URL-encoded-room>/send/...
        from urllib.parse import unquote

        parts = self.path.split("/")
        room = unquote(parts[parts.index("rooms") + 1])
        txn = parts[-1]
        self.captured.append(
            {
                "room": room,
                "txn": txn,
                "payload": payload,
                "auth": self.headers.get("Authorization", ""),
            }
        )
        body = json.dumps({"event_id": f"$evt-{len(self.captured)}"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_vault() -> Iterator[tuple[str, type[_FakeVaultHandler]]]:
    """Fresh handler class per test (mutable class state would leak)."""

    class H(_FakeVaultHandler):
        secrets: dict[str, str] = {}
        expected_token: str | None = None

    port = _free_port()
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), H)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}", H
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def fake_matrix() -> Iterator[tuple[str, type[_FakeMatrixHandler]]]:
    class H(_FakeMatrixHandler):
        captured: list[dict] = []
        expected_token: str | None = None
        fail_status: int | None = None

    port = _free_port()
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), H)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}", H
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def helper_env(tmp_path) -> dict[str, str]:
    """Isolated config dir per test - doesn't touch ~/.config/rhorizon."""
    cfg = tmp_path / "rhorizon"
    cfg.mkdir()
    (cfg / "token").write_text("rh_test_bootstrap_token\n")
    (cfg / "token").chmod(0o600)
    return {**os.environ, "RHORIZON_CONFIG_DIR": str(cfg)}


def _run(
    env: dict[str, str], *args: str, stdin: str | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(HELPER), *args],
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=10,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_helper_is_executable():
    assert HELPER.is_file(), f"missing {HELPER}"
    assert os.access(HELPER, os.X_OK), f"{HELPER} not executable"


def test_argv_message_resolves_via_vault(fake_vault, fake_matrix, helper_env, tmp_path):
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {
        "matrix-token": "syt_TESTtokenABCD",
        "matrix-room": "!testroom:example.org",
    }
    vault.expected_token = "rh_test_bootstrap_token"
    matrix.expected_token = "syt_TESTtokenABCD"

    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )

    r = _run(helper_env, "hello from test")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().startswith("$evt-"), r.stdout
    assert len(matrix.captured) == 1
    sent = matrix.captured[0]
    assert sent["room"] == "!testroom:example.org"
    assert sent["payload"]["msgtype"] == "m.text"
    assert sent["payload"]["body"] == "hello from test"
    assert sent["auth"] == "Bearer syt_TESTtokenABCD"


def test_stdin_message(fake_vault, fake_matrix, helper_env):
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {
        "matrix-token": "syt_TESTtokenABCD",
        "matrix-room": "!testroom:example.org",
    }
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )
    r = _run(helper_env, "--stdin", stdin="line1\nline2\nline3\n")
    assert r.returncode == 0, r.stderr
    body = matrix.captured[0]["payload"]["body"]
    assert body == "line1\nline2\nline3"


def test_html_format_adds_formatted_body(fake_vault, fake_matrix, helper_env):
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {
        "matrix-token": "t",
        "matrix-room": "!r:s",
    }
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )
    r = _run(helper_env, "--format", "html", "<b>bold</b>")
    assert r.returncode == 0
    payload = matrix.captured[0]["payload"]
    assert payload["format"] == "org.matrix.custom.html"
    assert payload["formatted_body"] == "<b>bold</b>"


def test_cli_overrides_skip_vault(fake_matrix, helper_env, tmp_path):
    """--token + --room together skip the vault entirely (test-mode)."""
    matrix_url, matrix = fake_matrix
    matrix.expected_token = "direct_token"
    # No vault URL configured, would 500 if vault were used
    r = _run(
        helper_env,
        "--homeserver",
        matrix_url,
        "--token",
        "direct_token",
        "--room",
        "!direct:s",
        "msg without vault",
    )
    assert r.returncode == 0, r.stderr
    sent = matrix.captured[0]
    assert sent["room"] == "!direct:s"
    assert sent["payload"]["body"] == "msg without vault"


def test_missing_token_file_exits_2(helper_env):
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "token").unlink()
    r = _run(helper_env, "msg")
    assert r.returncode == 2
    assert "no vault token" in r.stderr.lower()


def test_world_readable_token_refused(helper_env):
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "token").chmod(0o644)
    r = _run(helper_env, "msg")
    assert r.returncode == 2
    assert "permissions" in r.stderr.lower()


def test_vault_404_exits_3(fake_vault, fake_matrix, helper_env):
    vault_url, vault = fake_vault
    matrix_url, _ = fake_matrix
    vault.secrets = {}  # empty - every lookup is 404
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\ntoken_secret = nope\nroom_secret = nope\n"
    )
    r = _run(helper_env, "msg")
    assert r.returncode == 3
    assert "404" in r.stderr or "vault" in r.stderr.lower()


def test_matrix_403_exits_4(fake_vault, fake_matrix, helper_env):
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {"matrix-token": "wrong", "matrix-room": "!r:s"}
    matrix.expected_token = "right"  # mismatch -> 401
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )
    r = _run(helper_env, "msg")
    assert r.returncode == 4
    assert "matrix" in r.stderr.lower()


def test_quiet_suppresses_event_id_print(fake_vault, fake_matrix, helper_env):
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {"matrix-token": "t", "matrix-room": "!r:s"}
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )
    r = _run(helper_env, "--quiet", "msg")
    assert r.returncode == 0
    assert r.stdout == ""


def test_room_id_url_encoded(fake_vault, fake_matrix, helper_env):
    """Matrix room IDs start with '!' which is reserved in URLs - must be encoded."""
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {
        "matrix-token": "t",
        "matrix-room": "!sensitive:room.example.com",
    }
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )
    r = _run(helper_env, "msg")
    assert r.returncode == 0, r.stderr
    # The handler decoded the room, proves it was sent encoded
    assert matrix.captured[0]["room"] == "!sensitive:room.example.com"


def test_env_vars_override_conf(fake_vault, fake_matrix, helper_env):
    vault_url, vault = fake_vault
    matrix_url, matrix = fake_matrix
    vault.secrets = {
        "alt-token-secret": "syt_alt",
        "alt-room-secret": "!alt:s",
    }
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "url").write_text(vault_url + "\n")
    # matrix.conf points at "wrong" secret names; env overrides it
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = wrong-token\n"
        "room_secret = wrong-room\n"
    )
    env = {
        **helper_env,
        "MATRIX_TOKEN_SECRET": "alt-token-secret",
        "MATRIX_ROOM_SECRET": "alt-room-secret",
    }
    r = _run(env, "msg")
    assert r.returncode == 0, r.stderr
    assert matrix.captured[0]["room"] == "!alt:s"
    assert matrix.captured[0]["auth"] == "Bearer syt_alt"
