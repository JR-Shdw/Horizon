# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""Thin stdlib client to the rh-mcp-gateway unix-socket sidecar.

The sidecar (agent/rust rh-mcp-gateway) is the only leg that speaks HTTP/2 + PQ
TLS 1.3 to the vault. Line-JSON protocol: send
``{"bearer","method","path","body"?}`` -> receive ``{"status","body"}`` or
``{"error"}``. One short-lived connection per call keeps this thread-safe and
simple; the sidecar owns the persistent vault connection pool. Zero third-party
deps (only used in the OPTIONAL hub daemon mode).
"""

from __future__ import annotations

import json
import socket


class SidecarError(RuntimeError):
    """The sidecar was unreachable or returned a transport-level error."""


class SidecarClient:
    def __init__(self, socket_path: str, timeout: float = 15.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def request(
        self,
        bearer: str,
        method: str,
        path: str,
        body: object | None = None,
        client_ip: str | None = None,
    ) -> tuple[int, object]:
        """Proxy one vault request through the sidecar with ``bearer``.

        ``client_ip``, when given, is forwarded to the Rust sidecar so it can
        set X-Forwarded-For on the vault call -- lets a per-token allowed_ips
        ACL bind to the real MCP agent's IP instead of this sidecar's own
        connecting address. The vault only honours the header from peers it
        has explicitly trusted (api/app/client_ip.py); passing it here is not
        itself a trust grant.

        Returns ``(http_status, parsed_body)``. Raises :class:`SidecarError` on a
        transport failure (sidecar down, bad framing) -- distinct from a normal
        4xx/5xx which comes back as ``(status, body)``.
        """
        req: dict = {"bearer": bearer, "method": method, "path": path}
        if body is not None:
            req["body"] = body
        if client_ip:
            req["client_ip"] = client_ip
        line = (json.dumps(req) + "\n").encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                s.sendall(line)
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise SidecarError(f"sidecar unreachable: {e}") from None
        raw = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
        try:
            resp = json.loads(raw)
        except json.JSONDecodeError:
            raise SidecarError("sidecar returned non-JSON") from None
        if "error" in resp:
            raise SidecarError(str(resp["error"]))
        return int(resp.get("status", 0)), resp.get("body")
