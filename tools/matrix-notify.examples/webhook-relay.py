#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""matrix-webhook-relay - receive HTTP webhooks, forward to Matrix.

A minimal stdlib HTTP server that accepts JSON or form payloads from
webhook-emitting tools (Grafana alertmanager, Woodpecker, GitHub
webhooks, Restic post-backup hooks, etc.) and forwards them as Matrix
messages. Credentials are pulled from rhorizon at startup, never
embedded in the relay's config or env.

The relay is intentionally feature-light - it's a pattern, not a
product. Copy it, adapt the message-formatting hook to your sender,
deploy it as a systemd unit or container.

USAGE
-----
    # Default: listen on 127.0.0.1:8765, forward to the room from
    # ~/.config/rhorizon/matrix.conf
    ./webhook-relay.py

    # Bind to all interfaces (e.g. inside a container)
    ./webhook-relay.py --host 0.0.0.0 --port 8765

    # Verify a shared secret in X-Webhook-Token header (defense-in-depth)
    ./webhook-relay.py --shared-secret-secret webhook-shared-secret

POST a webhook:

    curl -X POST http://127.0.0.1:8765/webhook \
        -H 'Content-Type: application/json' \
        -d '{"text": "Build failed on node-1"}'

ENDPOINTS
---------
  POST /webhook       - generic. JSON body. Looks at: text, message, body,
                        title (in that order). Falls back to whole JSON.
  POST /grafana       - Grafana alertmanager v4 payload. Renders to a
                        compact human-readable summary.
  POST /woodpecker    - Woodpecker post-step. Renders status + repo + URL.
  GET  /healthz       - liveness check, returns 200 OK.

Replace the *_format() functions to suit your senders.
"""

from __future__ import annotations

import argparse
import http.server
import json
import logging
import os
import secrets as _stdlib_secrets
import socketserver
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG_DIR = Path(
    os.environ.get("RHORIZON_CONFIG_DIR", "~/.config/rhorizon")
).expanduser()
TOKEN_PATH = CONFIG_DIR / "token"
URL_PATH = CONFIG_DIR / "url"
CONF_PATH = CONFIG_DIR / "matrix.conf"

log = logging.getLogger("matrix-webhook-relay")


# ---------------------------------------------------------------------------
# Vault + Matrix glue (mirrors matrix-notify; intentional duplication so this
# example file is self-contained, copy-paste-deploy)
# ---------------------------------------------------------------------------


def _vault_get(vault_url: str, vault_token: str, secret_name: str) -> str:
    url = f"{vault_url.rstrip('/')}/api/v1/vault/secrets/{secret_name}"
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {vault_token}"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)["value"]


def _read_conf() -> dict[str, str]:
    out = {
        "homeserver": "https://matrix.org",
        "token_secret": "matrix-token",
        "room_secret": "matrix-room",
    }
    if not CONF_PATH.exists():
        return out
    for raw in CONF_PATH.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def _matrix_send(
    homeserver: str, matrix_token: str, room_id: str, body: str, html: str | None
) -> str:
    txn = f"webhook-{_stdlib_secrets.token_urlsafe(12)}"
    safe_room = urllib.parse.quote(room_id, safe="")
    url = (
        f"{homeserver.rstrip('/')}/_matrix/client/v3/rooms/"
        f"{safe_room}/send/m.room.message/{txn}"
    )
    payload: dict[str, str] = {"msgtype": "m.text", "body": body}
    if html:
        payload["format"] = "org.matrix.custom.html"
        payload["formatted_body"] = html
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {matrix_token}",
            "Content-Type": "application/json",
        },
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp).get("event_id", "")


# ---------------------------------------------------------------------------
# Per-sender format hooks. Replace these to match your tooling.
# ---------------------------------------------------------------------------


def generic_format(payload: dict) -> tuple[str, str | None]:
    for key in ("text", "message", "body"):
        if key in payload and isinstance(payload[key], str):
            return payload[key], None
    return json.dumps(payload, indent=2, ensure_ascii=False), None


def grafana_format(payload: dict) -> tuple[str, str | None]:
    """Grafana alertmanager v4 payload - receiver/alerts/state."""
    state = payload.get("state", "?")
    title = payload.get("title", "Grafana alert")
    msg = payload.get("message", "").strip()
    rule = payload.get("ruleName", "")
    out = [f"[{state.upper()}] {title}"]
    if rule:
        out.append(f"rule: {rule}")
    if msg:
        out.append(msg)
    body = "\n".join(out)
    html = (
        f"<strong>[{state.upper()}]</strong> {title}"
        + (f"<br><em>rule: {rule}</em>" if rule else "")
        + (f"<br>{msg}" if msg else "")
    )
    return body, html


def woodpecker_format(payload: dict) -> tuple[str, str | None]:
    """Woodpecker post-pipeline notification."""
    repo = payload.get("repo", {}).get("full_name", "?")
    pipe = payload.get("pipeline", payload.get("build", {}))
    status = pipe.get("status", "?")
    branch = pipe.get("branch", "?")
    url = pipe.get("link", pipe.get("link_url", ""))
    icon = {"success": "OK", "failure": "FAIL", "error": "ERR"}.get(
        status, status.upper()
    )
    body = f"[{icon}] {repo} ({branch}) - {url}".strip()
    return body, None


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


def make_handler(
    homeserver: str,
    matrix_token: str,
    room_id: str,
    shared_secret: str | None,
):
    class WebhookHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.info("%s - %s", self.address_string(), fmt % args)

        def _read_json(self) -> dict | None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            ctype = self.headers.get("Content-Type", "")
            try:
                if "application/json" in ctype:
                    return json.loads(raw or b"{}")
                if "application/x-www-form-urlencoded" in ctype:
                    return dict(urllib.parse.parse_qsl(raw.decode()))
                # Best-effort JSON for unlabelled payloads
                return json.loads(raw or b"{}")
            except (ValueError, UnicodeDecodeError):
                return None

        def _check_secret(self) -> bool:
            if not shared_secret:
                return True
            given = self.headers.get("X-Webhook-Token", "")
            # Constant-time comparison
            return _stdlib_secrets.compare_digest(given, shared_secret)

        def _respond(self, code: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):  # noqa: N802 - stdlib API
            if self.path == "/healthz":
                self._respond(200, {"ok": True})
                return
            self._respond(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._check_secret():
                self._respond(401, {"error": "shared secret mismatch"})
                return
            payload = self._read_json()
            if payload is None or not isinstance(payload, dict):
                self._respond(400, {"error": "invalid payload"})
                return
            try:
                if self.path == "/webhook":
                    body, html = generic_format(payload)
                elif self.path == "/grafana":
                    body, html = grafana_format(payload)
                elif self.path == "/woodpecker":
                    body, html = woodpecker_format(payload)
                else:
                    self._respond(404, {"error": "unknown route"})
                    return
                event_id = _matrix_send(homeserver, matrix_token, room_id, body, html)
                self._respond(200, {"event_id": event_id})
            except urllib.error.HTTPError as e:
                err = e.read().decode(errors="replace")
                log.warning("matrix returned %d: %s", e.code, err)
                self._respond(502, {"error": f"matrix {e.code}", "detail": err})
            except urllib.error.URLError as e:
                log.warning("matrix unreachable: %s", e)
                self._respond(503, {"error": "matrix unreachable"})

    return WebhookHandler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--shared-secret-secret",
        help=(
            "Vault secret name holding a shared secret. Incoming webhooks "
            "must include it in the X-Webhook-Token header."
        ),
    )
    parser.add_argument(
        "--token-secret",
        help="Override matrix.conf token_secret.",
    )
    parser.add_argument("--room-secret", help="Override matrix.conf room_secret.")
    parser.add_argument("--homeserver", help="Override matrix.conf homeserver.")
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not TOKEN_PATH.exists():
        print(f"matrix-webhook-relay: no vault token at {TOKEN_PATH}", file=sys.stderr)
        return 2
    vault_token = TOKEN_PATH.read_text().strip()
    vault_url = URL_PATH.read_text().strip() if URL_PATH.exists() else "https://vault"
    conf = _read_conf()
    homeserver = args.homeserver or conf["homeserver"]
    token_name = args.token_secret or conf["token_secret"]
    room_name = args.room_secret or conf["room_secret"]

    matrix_token = _vault_get(vault_url, vault_token, token_name)
    room_id = _vault_get(vault_url, vault_token, room_name)
    shared = (
        _vault_get(vault_url, vault_token, args.shared_secret_secret)
        if args.shared_secret_secret
        else None
    )

    handler = make_handler(homeserver, matrix_token, room_id, shared)
    log.info("matrix-webhook-relay listening on http://%s:%d", args.host, args.port)
    log.info(
        "  matrix -> %s, room=%s, token-secret=%s, shared-secret=%s",
        homeserver,
        room_id,
        token_name,
        "ON" if shared else "OFF",
    )
    with socketserver.ThreadingTCPServer((args.host, args.port), handler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            log.info("shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
