"""Tests for tools/matrix-read.

Same shape as test_matrix_notify.py: subprocess invocation against a
fake Matrix homeserver and a fake vault. The fake homeserver here serves
GET /_matrix/client/v3/sync and /messages instead of PUTting events.
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
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).parent.parent
HELPER = REPO_ROOT / "tools" / "matrix-read"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _FakeVaultHandler(http.server.BaseHTTPRequestHandler):
    secrets: dict[str, str] = {}

    def log_message(self, *_):
        pass

    def do_GET(self):  # noqa: N802
        prefix = "/api/v1/vault/secrets/"
        if not self.path.startswith(prefix):
            self.send_error(404)
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
    """Simulates /sync (GET) + /messages (GET)."""

    # Programmable per test
    sync_responses: list[dict] = []  # popped left to right per call
    messages_chunk: list[dict] = []
    sync_calls: list[dict] = []  # captures since= and timeout= per call
    expected_token: str | None = None

    def log_message(self, *_):
        pass

    def _check_auth(self) -> bool:
        if self.expected_token is None:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {self.expected_token}"

    def do_GET(self):  # noqa: N802
        if not self._check_auth():
            self.send_error(401)
            return
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        if url.path == "/_matrix/client/v3/sync":
            self.sync_calls.append(
                {
                    "since": (qs.get("since") or [None])[0],
                    "timeout": (qs.get("timeout") or [None])[0],
                }
            )
            if self.sync_responses:
                payload = self.sync_responses.pop(0)
            else:
                payload = {"next_batch": "EMPTY", "rooms": {"join": {}}}
            self._json(200, payload)
            return
        if "/messages" in url.path:
            payload = {
                "chunk": self.messages_chunk,
                "start": "s_test",
                "end": "e_test",
            }
            self._json(200, payload)
            return
        self.send_error(404)

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_vault() -> Iterator[tuple[str, type[_FakeVaultHandler]]]:
    class H(_FakeVaultHandler):
        secrets: dict[str, str] = {}

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
        sync_responses: list[dict] = []
        messages_chunk: list[dict] = []
        sync_calls: list[dict] = []
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
def helper_env(tmp_path, fake_vault, fake_matrix) -> dict[str, str]:
    vault_url, vault = fake_vault
    matrix_url, _ = fake_matrix
    vault.secrets = {
        "matrix-token": "syt_TEST",
        "matrix-room": "!testroom:example.org",
    }
    cfg = tmp_path / "rhorizon"
    cfg.mkdir()
    (cfg / "token").write_text("rh_test\n")
    (cfg / "token").chmod(0o600)
    (cfg / "url").write_text(vault_url + "\n")
    (cfg / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )
    return {**os.environ, "RHORIZON_CONFIG_DIR": str(cfg)}


def _run(
    env: dict[str, str], *args: str, timeout: int = 10
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(HELPER), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _msg_event(sender: str, body: str, ts_ms: int = 1714478000000) -> dict:
    return {
        "type": "m.room.message",
        "sender": sender,
        "origin_server_ts": ts_ms,
        "event_id": f"$evt-{ts_ms}",
        "content": {"msgtype": "m.text", "body": body},
    }


def _sync_with(events: list[dict], next_batch: str, room: str) -> dict:
    return {
        "next_batch": next_batch,
        "rooms": {"join": {room: {"timeline": {"events": events}}}},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_helper_is_executable():
    assert HELPER.is_file(), f"missing {HELPER}"
    assert os.access(HELPER, os.X_OK)


def test_one_shot_initial_sync_no_messages(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.append(_sync_with([], "BATCH_1", "!testroom:example.org"))
    r = _run(helper_env)
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""  # no events, no output
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    assert (cfg / "matrix.state").read_text().strip() == "BATCH_1"
    # First call has no `since=` (initial sync)
    assert matrix.sync_calls[0]["since"] is None


def test_one_shot_emits_events_text(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.append(
        _sync_with(
            [
                _msg_event("@alice:s", "hello", 1714478000000),
                _msg_event("@bob:s", "hi alice", 1714478060000),
            ],
            "BATCH_2",
            "!testroom:example.org",
        )
    )
    r = _run(helper_env)
    assert r.returncode == 0, r.stderr
    lines = [ln for ln in r.stdout.splitlines() if ln]
    assert len(lines) == 2
    assert "@alice:s: hello" in lines[0]
    assert "@bob:s: hi alice" in lines[1]
    # Timestamp formatting includes "T" and "+00:00"
    assert "T" in lines[0] and "+00:00" in lines[0]


def test_one_shot_json_format(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.append(
        _sync_with(
            [_msg_event("@alice:s", "json please")],
            "BATCH_J",
            "!testroom:example.org",
        )
    )
    r = _run(helper_env, "--format", "json")
    assert r.returncode == 0, r.stderr
    line = r.stdout.strip().splitlines()[0]
    parsed = json.loads(line)
    assert parsed["sender"] == "@alice:s"
    assert parsed["content"]["body"] == "json please"


def test_subsequent_call_uses_saved_cursor(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.extend(
        [
            _sync_with([], "CURSOR_AFTER_FIRST", "!testroom:example.org"),
            _sync_with(
                [_msg_event("@alice:s", "after cursor")],
                "CURSOR_AFTER_SECOND",
                "!testroom:example.org",
            ),
        ]
    )
    # First run, stores CURSOR_AFTER_FIRST
    r1 = _run(helper_env)
    assert r1.returncode == 0
    # Second run, should send since=CURSOR_AFTER_FIRST and emit the new event
    r2 = _run(helper_env)
    assert r2.returncode == 0
    assert "@alice:s: after cursor" in r2.stdout
    # Verify the second sync had the cursor from the first run
    assert matrix.sync_calls[1]["since"] == "CURSOR_AFTER_FIRST"
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    assert (cfg / "matrix.state").read_text().strip() == "CURSOR_AFTER_SECOND"


def test_reset_discards_cursor(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.extend(
        [
            _sync_with([], "STORED", "!testroom:example.org"),
            _sync_with([], "RESET_BATCH", "!testroom:example.org"),
        ]
    )
    _run(helper_env)  # stores STORED
    r = _run(helper_env, "--reset")
    assert r.returncode == 0, r.stderr
    # Second call did NOT pass since=
    assert matrix.sync_calls[1]["since"] is None


def test_backfill_uses_messages_endpoint(fake_matrix, helper_env):
    _, matrix = fake_matrix
    # /messages returns events newest-first; helper should reverse them
    matrix.messages_chunk = [
        _msg_event("@new:s", "newest", 1714478200000),
        _msg_event("@mid:s", "middle", 1714478100000),
        _msg_event("@old:s", "oldest", 1714478000000),
    ]
    r = _run(helper_env, "--backfill", "3")
    assert r.returncode == 0, r.stderr
    lines = [ln for ln in r.stdout.splitlines() if ln]
    # Output is oldest -> newest after the helper's reverse
    assert "@old:s: oldest" in lines[0]
    assert "@new:s: newest" in lines[-1]
    # Sync was NOT called for backfill mode
    assert matrix.sync_calls == []


def test_backfill_does_not_write_state(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.messages_chunk = [_msg_event("@a:s", "x")]
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    assert not (cfg / "matrix.state").exists()
    r = _run(helper_env, "--backfill", "1")
    assert r.returncode == 0
    assert not (cfg / "matrix.state").exists()


def test_backfill_range_validation(helper_env):
    r = _run(helper_env, "--backfill", "0")
    assert r.returncode == 1
    r = _run(helper_env, "--backfill", "1001")
    assert r.returncode == 1


def test_state_file_mode_0600(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.append(_sync_with([], "S1", "!testroom:example.org"))
    _run(helper_env)
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    state = cfg / "matrix.state"
    mode = state.stat().st_mode & 0o777
    assert mode == 0o600, f"state file mode {oct(mode)} (must be 0o600)"


def test_world_readable_token_refused(helper_env):
    cfg = Path(helper_env["RHORIZON_CONFIG_DIR"])
    (cfg / "token").chmod(0o644)
    r = _run(helper_env)
    assert r.returncode == 2
    assert "permissions" in r.stderr.lower()


def test_newlines_in_body_inlined(fake_matrix, helper_env):
    _, matrix = fake_matrix
    matrix.sync_responses.append(
        _sync_with(
            [_msg_event("@a:s", "line1\nline2\nline3")],
            "B",
            "!testroom:example.org",
        )
    )
    r = _run(helper_env)
    assert r.returncode == 0
    # Newlines should be replaced with the visible-arrow marker
    assert "line1 ⏎ line2 ⏎ line3" in r.stdout
    # And there's only one output line
    assert len([ln for ln in r.stdout.splitlines() if ln]) == 1


def test_only_target_room_events_returned(fake_matrix, helper_env):
    """Even though the server filter scopes /sync, defensive behavior:
    events from other rooms in the response are ignored."""
    _, matrix = fake_matrix
    matrix.sync_responses.append(
        {
            "next_batch": "B",
            "rooms": {
                "join": {
                    "!testroom:example.org": {
                        "timeline": {"events": [_msg_event("@a:s", "in target")]}
                    },
                    "!other:example.org": {
                        "timeline": {"events": [_msg_event("@b:s", "in other room")]}
                    },
                }
            },
        }
    )
    r = _run(helper_env)
    assert r.returncode == 0
    assert "@a:s: in target" in r.stdout
    assert "in other room" not in r.stdout


def test_cli_overrides_skip_vault(fake_matrix, helper_env, tmp_path):
    """--token + --room together skip the vault entirely (test-mode)."""
    matrix_url, matrix = fake_matrix
    matrix.sync_responses.append(_sync_with([], "DIRECT_BATCH", "!direct:s"))
    # Wipe the vault token to prove we don't talk to the vault
    (Path(helper_env["RHORIZON_CONFIG_DIR"]) / "token").unlink()
    r = _run(
        helper_env,
        "--homeserver",
        matrix_url,
        "--token",
        "direct",
        "--room",
        "!direct:s",
    )
    assert r.returncode == 0, r.stderr
