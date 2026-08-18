# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""Daemon-mode gateway for the OPTIONAL MCP hub.

Adds, on top of the stdio hub (which is unchanged):
  - BearerAuth: resolve a per-agent bearer -> {id, name} via the vault
    /tokens/whoami over the sidecar, with positive/negative caches + a rolling
    per-IP reject rate-limit (re-derives the mcp bearer-middleware hardening
    pattern, stdlib only);
  - VaultBackend: the 6 vault tools dispatched to the vault over the sidecar with
    the PER-REQUEST agent bearer (so the vault's own audit attributes to the real
    agent);
  - emit_mcp_audit: POST every tool call to the vault's chained /audit/mcp with the
    agent bearer (the server-side per-agent MCP audit chain);
  - serve_http: a loopback ThreadingHTTPServer serving Streamable MCP (POST /mcp).

The hub never holds a vault token: bearer validation and the vault leg both go
through the rh-mcp-gateway sidecar (HTTP/2 + PQ TLS 1.3). This module is only
imported/used in ``--daemon`` mode.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:  # package mode
    from .sidecar import SidecarClient, SidecarError
except ImportError:  # script mode (running directly / tests)
    from sidecar import SidecarClient, SidecarError

log = logging.getLogger("rhorizon-mcp-hub")

_POS_TTL = 30.0  # positive (validated) bearer cache
_NEG_TTL = 5.0  # negative (rejected) bearer cache
_RL_WINDOW = 60.0
_RL_MAX = 10  # rejects per window per IP -> 429

# Hard backstop against unbounded memory growth from many distinct bogus
# bearers or source IPs (each entry only expires lazily, on next lookup of
# that SAME key -- an attacker who never repeats a key would otherwise grow
# these dicts forever). Active pruning runs opportunistically on every
# resolve() call; this cap is the last-resort eviction if pruning alone
# can't keep up under sustained abuse. Sized generously for the loopback,
# admin-scale traffic this optional daemon mode expects -- not a public
# service.
_MAX_ENTRIES = 10_000


class RateLimited(Exception):
    """Too many rejected bearers from one source IP."""


class BearerAuth:
    def __init__(self, sidecar: SidecarClient) -> None:
        self._sidecar = sidecar
        self._pos: dict[str, tuple[float, dict]] = {}
        self._neg: dict[str, float] = {}
        self._rl: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune_locked(self, now: float) -> None:
        """Drop expired entries, then hard-cap by evicting the oldest.
        Caller must hold self._lock."""
        self._pos = {k: v for k, v in self._pos.items() if now - v[0] < _POS_TTL}
        self._neg = {k: t for k, t in self._neg.items() if now - t < _NEG_TTL}
        self._rl = {
            ip: hits
            for ip, raw in self._rl.items()
            if (hits := [t for t in raw if now - t < _RL_WINDOW])
        }
        for d, key_fn in (
            (self._pos, lambda item: item[1][0]),
            (self._neg, lambda item: item[1]),
            (self._rl, lambda item: max(item[1])),
        ):
            if len(d) > _MAX_ENTRIES:
                oldest = sorted(d.items(), key=key_fn)[: len(d) - _MAX_ENTRIES]
                for k, _ in oldest:
                    del d[k]

    def _rate_limited(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            hits = [t for t in self._rl.get(ip, []) if now - t < _RL_WINDOW]
            self._rl[ip] = hits
            return len(hits) >= _RL_MAX

    def _record_reject(self, ip: str) -> None:
        with self._lock:
            self._rl.setdefault(ip, []).append(time.monotonic())

    def resolve(self, bearer: str, ip: str) -> dict | None:
        """Return ``{id, name}`` for a valid bearer, else None. Raises
        :class:`RateLimited` if the source IP is throttling on rejects."""
        if not bearer:
            return None
        key = hashlib.sha256(bearer.encode()).hexdigest()
        now = time.monotonic()
        with self._lock:
            hit = self._pos.get(key)
            if hit and now - hit[0] < _POS_TTL:
                return hit[1]
            neg = self._neg.get(key)
            if neg and now - neg < _NEG_TTL:
                return None
        if self._rate_limited(ip):
            raise RateLimited()
        try:
            status, body = self._sidecar.request(
                bearer, "GET", "/api/v1/vault/tokens/whoami"
            )
        except SidecarError:
            # Sidecar/network error is NOT an invalid token: do not poison the
            # negative cache, let the caller surface a transient failure.
            return None
        if status == 200 and isinstance(body, dict) and body.get("id"):
            ident = {"id": str(body["id"]), "name": body.get("name") or ""}
            with self._lock:
                self._pos[key] = (now, ident)
            return ident
        self._record_reject(ip)
        with self._lock:
            self._neg[key] = now
        return None


def _mcp_result(data: object) -> dict:
    """Wrap a vault response as an MCP tools/call result (text content)."""
    return {"content": [{"type": "text", "text": json.dumps(data)}]}


# The vault tool catalog, mirrored from mcp/rhorizon_mcp/server.py. Kept as a copy
# (not a shared import) so the standalone stdio server stays independent.
# Canonical catalog, byte-identical to mcp/rhorizon_mcp/tools.json.
# The two packages install independently so neither may import the
# other; parity is enforced by tests/test_tool_catalog_parity.py.
VAULT_TOOLS: list[dict] = json.loads(
    (Path(__file__).parent / "tools.json").read_text(encoding="utf-8")
)["tools"]


class VaultBackend:
    """Hub-embedded vault backend, dispatched over the sidecar with the caller's
    own bearer (per-agent identity reaches the vault). Same interface as the stdio
    ``Backend`` (``.name``, ``.tools``, ``.destructive_requires_confirm``,
    ``.call(tool, args, ctx)``) so the hub routes to it uniformly."""

    def __init__(self, sidecar: SidecarClient, name: str = "rhorizon") -> None:
        self.name = name
        self._sidecar = sidecar
        self.tools = VAULT_TOOLS
        self.destructive_requires_confirm = False

    def _get(
        self,
        bearer: str,
        path: str,
        params: dict | None = None,
        client_ip: str | None = None,
    ) -> object:
        if params:
            path += "?" + urllib.parse.urlencode(params)
        status, body = self._sidecar.request(bearer, "GET", path, client_ip=client_ip)
        if status >= 400:
            raise RuntimeError(f"vault {status}: {str(body)[:200]}")
        return body

    def call(self, tool: str, arguments: dict, ctx: dict | None = None) -> dict:
        if not ctx or not ctx.get("bearer"):
            raise RuntimeError("vault backend requires a per-agent bearer (daemon)")
        b = ctx["bearer"]
        ip = ctx.get("client_ip")
        if tool == "vault_status":
            return _mcp_result(self._get(b, "/api/v1/vault/status", client_ip=ip))
        if tool == "vault_whoami":
            return _mcp_result(
                self._get(b, "/api/v1/vault/tokens/whoami", client_ip=ip)
            )
        if tool == "vault_list_namespaces":
            return _mcp_result(
                self._get(b, "/api/v1/vault/secrets/namespaces", client_ip=ip)
            )
        if tool == "vault_list_secrets":
            ns = arguments.get("namespace") or "default"
            return _mcp_result(
                self._get(b, "/api/v1/vault/secrets/", {"namespace": ns}, client_ip=ip)
            )
        if tool == "vault_get_secret":
            ns = arguments.get("namespace") or "default"
            name = arguments["name"]
            path = "/api/v1/vault/secrets/" + urllib.parse.quote(name, safe="")
            return _mcp_result(self._get(b, path, {"namespace": ns}, client_ip=ip))
        if tool == "vault_audit_tail":
            limit = max(1, min(100, int(arguments.get("limit", 10))))
            return _mcp_result(
                self._get(b, "/api/v1/vault/audit/", {"limit": limit}, client_ip=ip)
            )
        if tool == "vault_cluster_health":
            # summary=true: the server projects states + reasons only, so this
            # path and mcp/'s cannot drift (they already did once).
            return _mcp_result(
                self._get(
                    b,
                    "/api/v1/vault/cluster/health",
                    {"summary": "true"},
                    client_ip=ip,
                )
            )
        raise ValueError(f"unknown vault tool: {tool}")


def emit_mcp_audit(
    sidecar: SidecarClient,
    bearer: str,
    *,
    backend: str,
    tool: str,
    decision: str,
    hub: str | None = None,
    target: str | None = None,
    detail: dict | None = None,
    client_ip: str | None = None,
) -> None:
    """POST one event to the vault's chained /audit/mcp with the agent bearer.

    Best-effort: a failure here must not break the tool call. The vault derives
    actor + agent_token_id from the bearer, so nothing sensitive is trusted from
    the hub. ``hub`` is a self-declared source label (not a trusted identity).
    The local hash-chained JSONL remains the offline backstop. ``client_ip`` is
    forwarded the same way as VaultBackend's tool calls, so the audit row's
    recorded IP matches the real agent, not this sidecar.
    """
    try:
        sidecar.request(
            bearer,
            "POST",
            "/api/v1/vault/audit/mcp",
            body={
                "backend": backend,
                "tool": tool,
                "hub": hub,
                "target": target,
                "decision": decision,
                "detail": detail or {},
            },
            client_ip=client_ip,
        )
    except Exception as e:  # noqa: BLE001 - never let audit emit break a call
        log.warning("MCP audit emit failed (%s/%s): %s", backend, tool, e)


def serve_http(hub, auth: BearerAuth, bind: str, port: int) -> None:
    """Serve Streamable MCP over loopback HTTP. Each POST /mcp carries the agent
    bearer; the hub dispatches with a per-request identity context."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _json(self, code: int, obj: dict) -> None:
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _unauth(self) -> None:
            self._json(401, {"error": "unauthorized"})

        def log_message(self, *a):  # silence default stderr access log
            return

        def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
            if self.path.rstrip("/") != "/mcp":
                self._json(404, {"error": "not found"})
                return
            ip = self.client_address[0] if self.client_address else "?"
            authz = self.headers.get("Authorization", "")
            bearer = authz[7:].strip() if authz.startswith("Bearer ") else ""
            try:
                ident = auth.resolve(bearer, ip)
            except RateLimited:
                self._json(429, {"error": "too many requests"})
                return
            if ident is None:
                self._unauth()
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                msg = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"error": "bad request"})
                return
            ctx = {
                "bearer": bearer,
                "agent_id": ident["id"],
                "agent_name": ident["name"],
                "client_ip": ip,
            }
            resp = hub.handle(msg, ctx)
            self._json(
                200, resp if resp is not None else {"jsonrpc": "2.0", "result": {}}
            )

    httpd = ThreadingHTTPServer((bind, port), Handler)
    log.info("hub daemon: Streamable MCP on http://%s:%d/mcp", bind, port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
