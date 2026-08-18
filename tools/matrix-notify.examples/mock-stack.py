#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""mock-stack.py - runnable demo: fake rhorizon vault + fake Matrix homeserver.

For prospective adopters who want to watch matrix-notify and matrix-read
work end-to-end without standing up a real vault or a real Matrix
homeserver. Single stdlib script, two HTTP servers in threads, every
interaction logged to stdout.

QUICK DEMO
----------
Terminal 1 - start the mock:

    ./mock-stack.py
    # Picks two free ports, prints the env block to copy-paste.

Terminal 2 - copy-paste the env block, then send + read:

    export RHORIZON_CONFIG_DIR=/tmp/mock-rhorizon
    # ... (the script writes a temp config dir for you, banner shows the env)

    matrix-notify "first demo message"
    matrix-notify --format html "<strong>second</strong>"
    matrix-read --backfill 10
    matrix-read --watch     # Ctrl-C to stop

Every request lands in terminal 1 with timestamp, route, payload - so
you can see exactly what the helper sent over the wire.

WHAT IT MOCKS
-------------
Vault side (rhorizon):
    GET /api/v1/vault/secrets/matrix-token  -> returns "mock_matrix_token"
    GET /api/v1/vault/secrets/matrix-room   -> returns "!mockroom:demo.local"
    GET /api/v1/vault/secrets/<other>       -> 404 (so error paths are testable)

Matrix side:
    PUT /_matrix/client/v3/rooms/.../send/m.room.message/<txn>
        -> appends to the in-memory timeline, returns event_id, wakes up
          any /sync long-poll waiters.
    GET /_matrix/client/v3/sync?since=...&timeout=...
        -> if there are events past `since`, returns them immediately.
          Otherwise blocks up to `timeout` ms (long-poll) for a new
          message, then returns whatever arrived.
    GET /_matrix/client/v3/rooms/.../messages?dir=b&limit=N
        -> returns the last N events newest-first (matrix-read reverses).

WHAT IT DOES NOT MOCK
---------------------
- Authentication: any Bearer token is accepted on both sides. Adopters
  who want to test auth failures can use the test fixtures in
  tests/test_matrix_notify.py / test_matrix_read.py instead.
- E2EE, federation, room state events. Just m.room.message.

Tip: this same script doubles as the simplest possible reference for
how the rhorizon GET-secret endpoint and the Matrix Client-Server API
look on the wire.
"""

from __future__ import annotations

import argparse
import http.server
import json
import socket
import socketserver
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

# ---------------------------------------------------------------------------
# Shared state, single in-memory "room"
# ---------------------------------------------------------------------------


class Timeline:
    """Tiny event store. Thread-safe append + slice-since."""

    def __init__(self):
        self._events: list[dict] = []
        self._batch = 0  # monotonic; the "next_batch" cursor is its string form
        self._cond = threading.Condition()

    @property
    def cursor(self) -> str:
        return str(self._batch)

    def append(self, sender: str, body: str, msgtype: str = "m.text") -> dict:
        with self._cond:
            self._batch += 1
            event = {
                "type": "m.room.message",
                "sender": sender,
                "origin_server_ts": int(time.time() * 1000),
                "event_id": f"$mock-{self._batch}",
                "content": {"msgtype": msgtype, "body": body},
            }
            self._events.append(event)
            self._cond.notify_all()
            return event

    def since(self, cursor: str | None, timeout_ms: int) -> tuple[list[dict], str]:
        """Return events with batch > cursor, blocking up to timeout_ms.

        The first /sync (no cursor) returns the current snapshot
        immediately so matrix-read --reset starts at "now".
        """
        try:
            since = int(cursor) if cursor else 0
        except ValueError:
            since = 0
        with self._cond:
            if cursor is None:
                # Initial sync, snapshot, no wait
                return list(self._events), self.cursor
            deadline = time.monotonic() + (timeout_ms / 1000)
            while self._batch <= since:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(timeout=remaining)
            new = self._events[since:] if self._batch > since else []
            return new, self.cursor

    def last(self, n: int) -> list[dict]:
        with self._cond:
            return list(self._events[-n:])


TIMELINE = Timeline()
SECRETS = {
    "matrix-token": "mock_matrix_token_for_demo",
    "matrix-room": "!mockroom:demo.local",
}


# ---------------------------------------------------------------------------
# Logging: uniform across both servers
# ---------------------------------------------------------------------------


_log_lock = threading.Lock()


def stamp(label: str, *parts: object) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"[{now}] {label:<10} " + " ".join(str(p) for p in parts)
    with _log_lock:
        print(line, flush=True)


# ---------------------------------------------------------------------------
# Vault HTTP handler
# ---------------------------------------------------------------------------


def _vault_handler():
    class VaultHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Use our own stamp() instead

        def _json(self, code: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            prefix = "/api/v1/vault/secrets/"
            if not url.path.startswith(prefix):
                stamp("VAULT", self.command, self.path, "-> 404 (no route)")
                self._json(404, {"error": "not found"})
                return
            name = url.path[len(prefix) :]
            if name not in SECRETS:
                stamp("VAULT", "GET", name, "-> 404 (no such secret)")
                self._json(404, {"error": "secret not found"})
                return
            stamp("VAULT", "GET", name, "-> 200 (value len:", len(SECRETS[name]), ")")
            self._json(
                200,
                {
                    "name": name,
                    "value": SECRETS[name],
                    "namespace": "demo",
                    "version": 1,
                },
            )

    return VaultHandler


# ---------------------------------------------------------------------------
# Matrix HTTP handler
# ---------------------------------------------------------------------------


def _matrix_handler():
    class MatrixHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # for keep-alive on long-polls

        def log_message(self, *_):
            pass

        def _json(self, code: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            try:
                return json.loads(raw or b"{}")
            except ValueError:
                return {}

        def do_PUT(self):  # noqa: N802
            url = urlparse(self.path)
            # /_matrix/client/v3/rooms/<room>/send/m.room.message/<txn>
            parts = url.path.split("/")
            if "rooms" not in parts or "send" not in parts:
                self._json(404, {"errcode": "M_NOT_FOUND"})
                return
            room = unquote(parts[parts.index("rooms") + 1])
            txn = parts[-1]
            payload = self._read_body()
            body = payload.get("body", "")
            sender_token = self.headers.get("Authorization", "Bearer anon")[7:]
            event = TIMELINE.append(sender=f"@mock:{sender_token[:8]}", body=body)
            stamp(
                "MATRIX",
                "PUT",
                f"room={room}",
                f"txn={txn}",
                f"body={body[:60]!r}",
                f"-> {event['event_id']}",
            )
            self._json(200, {"event_id": event["event_id"]})

        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            qs = parse_qs(url.query)
            if url.path == "/_matrix/client/v3/sync":
                since = (qs.get("since") or [None])[0]
                timeout = int((qs.get("timeout") or ["0"])[0])
                events, next_batch = TIMELINE.since(since, timeout)
                # Echo the room from the filter, for this mock we always
                # emit into the single mock room.
                room_id = SECRETS["matrix-room"]
                stamp(
                    "MATRIX",
                    "GET /sync",
                    f"since={since}",
                    f"timeout={timeout}ms",
                    f"-> {len(events)} new event(s), cursor={next_batch}",
                )
                self._json(
                    200,
                    {
                        "next_batch": next_batch,
                        "rooms": {"join": {room_id: {"timeline": {"events": events}}}},
                    },
                )
                return
            if "/messages" in url.path:
                limit = int((qs.get("limit") or ["50"])[0])
                # /messages dir=b returns newest-first
                events = list(reversed(TIMELINE.last(limit)))
                stamp(
                    "MATRIX",
                    "GET /messages",
                    f"limit={limit}",
                    f"-> {len(events)} event(s)",
                )
                self._json(200, {"chunk": events, "start": "s_mock", "end": "e_mock"})
                return
            self._json(404, {"errcode": "M_NOT_FOUND"})

    return MatrixHandler


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(handler_factory, host: str, port: int) -> _ThreadingServer:
    srv = _ThreadingServer((host, port), handler_factory)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _write_demo_config(config_dir: Path, vault_url: str, matrix_url: str) -> None:
    """Drop a self-contained ~/.config/rhorizon look-alike in a temp dir.

    Lets the user run `RHORIZON_CONFIG_DIR=<tmp> matrix-notify "..."`
    without touching their real config.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    config_dir.chmod(0o700)
    (config_dir / "token").write_text("rh_mock_bootstrap\n")
    (config_dir / "token").chmod(0o600)
    (config_dir / "url").write_text(vault_url + "\n")
    (config_dir / "matrix.conf").write_text(
        f"homeserver = {matrix_url}\n"
        "token_secret = matrix-token\n"
        "room_secret = matrix-room\n"
    )


def _print_banner(
    vault_url: str, matrix_url: str, config_dir: Path, seeded: int
) -> None:
    print(
        f"""
================================================================
  rhorizon + Matrix mock stack - running in this terminal
================================================================

  Fake vault   : {vault_url}
                 secrets: matrix-token + matrix-room
  Fake Matrix  : {matrix_url}
                 single room "{SECRETS["matrix-room"]}"
                 {seeded} pre-seeded message(s) in the timeline

  A demo rhorizon config dir has been written to:
      {config_dir}

  In another terminal, paste:

      export RHORIZON_CONFIG_DIR={config_dir}

  Then try:

      matrix-notify "hello from the demo"
      matrix-notify --format html "<strong>bold</strong>"
      matrix-read --backfill 10
      matrix-read --watch                  # blocks until a new message
      matrix-read --reset && matrix-read   # cursor demo

  Every interaction prints below with a [VAULT] or [MATRIX] tag.
  Ctrl-C to stop.
================================================================
""",
        flush=True,
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--vault-port",
        type=int,
        default=0,
        help="Port for the fake vault (0 = pick a free one).",
    )
    p.add_argument(
        "--matrix-port",
        type=int,
        default=0,
        help="Port for the fake Matrix homeserver (0 = pick a free one).",
    )
    p.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help=(
            "Where to drop the demo config. Default: a fresh tempdir, "
            "printed in the banner."
        ),
    )
    p.add_argument(
        "--seed",
        type=int,
        default=2,
        help="Number of pre-seeded messages to put in the room (default 2).",
    )
    args = p.parse_args()

    vault_port = args.vault_port or _free_port()
    matrix_port = args.matrix_port or _free_port()
    config_dir = args.config_dir or Path(tempfile.mkdtemp(prefix="mock-rhorizon-"))

    vault_srv = _start(_vault_handler(), "127.0.0.1", vault_port)
    matrix_srv = _start(_matrix_handler(), "127.0.0.1", matrix_port)
    vault_url = f"http://127.0.0.1:{vault_port}"
    matrix_url = f"http://127.0.0.1:{matrix_port}"

    # Seed the timeline so --backfill returns something on first try.
    for i in range(args.seed):
        TIMELINE.append(
            sender="@seed:demo.local",
            body=f"pre-seeded message #{i + 1}",
        )

    _write_demo_config(config_dir, vault_url, matrix_url)
    _print_banner(vault_url, matrix_url, config_dir, args.seed)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nshutting down...", flush=True)
    finally:
        vault_srv.shutdown()
        matrix_srv.shutdown()
        vault_srv.server_close()
        matrix_srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
