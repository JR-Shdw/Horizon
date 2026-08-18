"""Backlog #5: git-credential-rhorizon helper.

Subprocess-driven tests - invoke the script the way git would, with stdin
key=value pairs and argv operation. Mocks the vault via a tmp HTTP server.
"""

import http.server
import json as _json
import os
import socket
import subprocess
import threading
from pathlib import Path

import pytest

HELPER = Path(__file__).parent.parent / "tools" / "git-credential-rhorizon"


class _FakeVaultHandler(http.server.BaseHTTPRequestHandler):
    """Serves a single `/api/v1/vault/secrets/{name}` endpoint that
    returns whatever the test fixture set on the class-level dict."""

    secrets: dict[str, str] = {}
    expected_token: str | None = None

    def do_GET(self):  # noqa: N802 - required by stdlib API
        import urllib.parse as _up

        prefix = "/api/v1/vault/secrets/"
        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        if self.expected_token:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {self.expected_token}":
                self.send_error(401, "auth mismatch")
                return
        parsed = _up.urlparse(self.path)
        name = parsed.path[len(prefix) :]
        namespace = _up.parse_qs(parsed.query).get("namespace", [None])[0]
        key = f"{namespace}/{name}" if namespace else name
        if key not in self.secrets:
            self.send_error(404, "secret not found")
            return
        body = _json.dumps({"value": self.secrets[key]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):  # silence
        pass


@pytest.fixture
def fake_vault():
    """Spin up a stdlib HTTP server on a random port, yield (url, handler_cls)."""
    # Reset class-level state per test
    _FakeVaultHandler.secrets = {}
    _FakeVaultHandler.expected_token = None

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = http.server.HTTPServer(("127.0.0.1", port), _FakeVaultHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _FakeVaultHandler
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.fixture
def helper_config(tmp_path, fake_vault):
    """Build a RHORIZON_CONFIG_DIR pointing at tmp_path with token+url
    set up. Returns (env_dict, vault_url, handler_cls)."""
    url, handler = fake_vault
    cfg = tmp_path / "rhorizon"
    cfg.mkdir()
    (cfg / "token").write_text("rh_test_token_123")
    (cfg / "token").chmod(0o600)
    (cfg / "url").write_text(url)
    handler.expected_token = "rh_test_token_123"
    env = {**os.environ, "RHORIZON_CONFIG_DIR": str(cfg)}
    return env, url, handler


def _run_helper(env: dict, op: str, stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(HELPER), op],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def test_get_returns_credentials_for_known_host(helper_config):
    env, _url, handler = helper_config
    handler.secrets = {"git/gitea-c0re-me-api-token": "the-secret-token-value"}

    result = _run_helper(
        env,
        "get",
        "protocol=https\nhost=gitea.example.com\n\n",
    )
    assert result.returncode == 0, result.stderr
    out = dict(line.split("=", 1) for line in result.stdout.strip().split("\n"))
    assert out["host"] == "gitea.example.com"
    assert out["password"] == "the-secret-token-value"
    assert out["protocol"] == "https"


def test_get_uses_custom_mapping(tmp_path, fake_vault):
    """git-map file overrides the default host -> secret name."""
    url, handler = fake_vault
    cfg = tmp_path / "rhorizon"
    cfg.mkdir()
    (cfg / "token").write_text("rh_test_token_123")
    (cfg / "token").chmod(0o600)
    (cfg / "url").write_text(url)
    (cfg / "git-map").write_text(
        "# overrides\ngitea.example.com = git/custom-secret-name\ngithub.com = git/gh-pat\n"
    )
    handler.expected_token = "rh_test_token_123"
    handler.secrets = {"git/custom-secret-name": "mapped-secret"}

    env = {**os.environ, "RHORIZON_CONFIG_DIR": str(cfg)}
    result = _run_helper(env, "get", "protocol=https\nhost=gitea.example.com\n\n")
    assert result.returncode == 0, result.stderr
    out = dict(line.split("=", 1) for line in result.stdout.strip().split("\n"))
    assert out["password"] == "mapped-secret"


def test_get_fails_when_token_missing(tmp_path, fake_vault):
    """No token file -> exit code 2."""
    url, _ = fake_vault
    cfg = tmp_path / "rhorizon"
    cfg.mkdir()
    (cfg / "url").write_text(url)
    # NO token file

    env = {**os.environ, "RHORIZON_CONFIG_DIR": str(cfg)}
    result = _run_helper(env, "get", "protocol=https\nhost=any.example\n\n")
    assert result.returncode == 2


def test_get_fails_when_token_too_open(tmp_path, fake_vault):
    """Mode 0644 token -> refuse to use it."""
    url, _ = fake_vault
    cfg = tmp_path / "rhorizon"
    cfg.mkdir()
    (cfg / "token").write_text("rh_test_token_123")
    (cfg / "token").chmod(0o644)
    (cfg / "url").write_text(url)

    env = {**os.environ, "RHORIZON_CONFIG_DIR": str(cfg)}
    result = _run_helper(env, "get", "protocol=https\nhost=any.example\n\n")
    assert result.returncode == 2


def test_get_fails_when_secret_not_in_vault(helper_config):
    """Vault returns 404 -> exit code 3."""
    env, _url, handler = helper_config
    handler.secrets = {}  # nothing
    result = _run_helper(env, "get", "protocol=https\nhost=unknown.example\n\n")
    assert result.returncode == 3


def test_store_and_erase_are_noops(helper_config):
    """git asking us to store/erase -> exit 0, drain stdin, no output."""
    env, _url, _handler = helper_config
    for op in ("store", "erase"):
        result = _run_helper(
            env, op, "protocol=https\nhost=any\nusername=u\npassword=p\n\n"
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""
