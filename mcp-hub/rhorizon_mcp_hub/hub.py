# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""rhorizon-mcp-hub -- zero-dependency per-host MCP federation hub.

Fronts N local stdio MCP servers behind ONE local stdio MCP endpoint. Each
agent connects once (stdio) and sees the union of the backends' tools, prefixed
by backend name (`docker_ps`, `rhorizon_vault_get_secret`, ...). The hub spawns
each enabled backend as a subprocess, routes `tools/call` by prefix, enforces a
local policy (per-backend `enabled` + `destructive_requires_confirm`), and
appends every call to an audit log.

Pure Python standard library -- no third-party dependencies. MCP-over-stdio is
newline-delimited JSON-RPC 2.0; implemented directly here.

Topology (per host):

    agents --stdio--> rhorizon-mcp-hub --stdio--> backend servers
                                          (the rhorizon backend then talks
                                           QR-TLS to the central vault)

Config: TOML (see hub.toml.example). RHORIZON_HUB_CONFIG or --config selects it.
"""

from __future__ import annotations

import json
import logging
import os
import select
import subprocess
import sys
import time
import tomllib
from typing import Any

try:  # package mode (installed console script)
    from .audit import AuditChain
    from .audit import verify as audit_verify
    from .harden import append_only_status, harden_log
    from .sidecar import SidecarClient
except ImportError:  # script mode (running hub.py directly, e.g. tests)
    from audit import AuditChain
    from audit import verify as audit_verify
    from harden import append_only_status, harden_log
    from sidecar import SidecarClient


def _import_gateway():
    """Lazy dual-mode import of the daemon gateway (only needed in --daemon)."""
    try:
        from . import gateway
    except ImportError:  # script mode
        import gateway
    return gateway


log = logging.getLogger("rhorizon-mcp-hub")

PROTOCOL_VERSION = "2024-11-05"
__version__ = "0.1.0"
_STARTUP_TIMEOUT = 30.0
_CALL_TIMEOUT = 120.0


# ============================================================
# JSON-RPC helpers
# ============================================================
def _result(mid: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _tool_error(mid: Any, message: str) -> dict:
    # An in-band tool failure is a RESULT with isError=true (per MCP), not a
    # protocol-level error -- the agent sees the text and can react.
    return _result(
        mid, {"content": [{"type": "text", "text": message}], "isError": True}
    )


def _expand(p: str) -> str:
    return os.path.expanduser(p)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ============================================================
# Backend: one spawned stdio MCP server
# ============================================================
class Backend:
    def __init__(
        self,
        name: str,
        command: list[str],
        env: dict[str, str],
        destructive_requires_confirm: bool = False,
    ):
        self.name = name
        self.command = command
        self.env = env
        self.destructive_requires_confirm = destructive_requires_confirm
        self.proc: subprocess.Popen | None = None
        self.tools: list[dict] = []
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def start(self) -> None:
        full_env = {**os.environ, **self.env}
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # the backend's own logs stay on its stderr
            env=full_env,
            text=True,
            bufsize=1,
        )
        self._handshake()

    def _send(self, msg: dict) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _read_result(self, want_id: int, timeout: float) -> dict:
        """Read backend stdout until the response with want_id (skip the rest)."""
        assert self.proc and self.proc.stdout
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"backend {self.name} timed out (id {want_id})")
            r, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not r:
                raise TimeoutError(f"backend {self.name} timed out (id {want_id})")
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"backend {self.name} closed the pipe")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # a stray non-JSON line -- ignore
            if msg.get("id") == want_id:
                if "error" in msg:
                    raise RuntimeError(f"backend {self.name}: {msg['error']}")
                return msg.get("result", {})
            # notifications / unrelated ids -> ignore

    def _request(
        self, method: str, params: dict | None = None, timeout: float = _CALL_TIMEOUT
    ) -> dict:
        rid = self._next_id()
        self._send(
            {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        )
        return self._read_result(rid, timeout)

    def _notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _handshake(self) -> None:
        self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "rhorizon-mcp-hub", "version": __version__},
            },
            timeout=_STARTUP_TIMEOUT,
        )
        self._notify("notifications/initialized")
        result = self._request("tools/list", timeout=_STARTUP_TIMEOUT)
        self.tools = result.get("tools", [])

    def call(self, tool: str, arguments: dict, ctx: dict | None = None) -> dict:
        # ctx (per-agent identity) is unused by a stdio backend -- accepted so the
        # hub can call every backend (stdio or embedded VaultBackend) uniformly.
        return self._request("tools/call", {"name": tool, "arguments": arguments})

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


# ============================================================
# Hub: aggregate + route + policy + audit
# ============================================================
class Hub:
    def __init__(self, config: dict):
        hub_cfg = config.get("hub", {})
        self.name = hub_cfg.get("name", "rhorizon-mcp-hub")
        self.audit_path = _expand(
            hub_cfg.get("audit_log", "~/.local/state/rhorizon-mcp-hub/calls.jsonl")
        )
        self._config = config
        self.backends: dict = {}
        self.routes: dict[str, tuple] = {}  # prefixed -> (backend, orig)
        self.aggregated_tools: list[dict] = []
        self._audit_chain = AuditChain(self.audit_path)  # tamper-evident hash chain
        # Daemon mode only: the sidecar reaches the vault (PQ-TLS), and every tool
        # call is also emitted to the vault's chained /audit/mcp. Both are no-ops
        # in stdio mode / without a configured sidecar (additive, opt-in).
        sock = _expand(hub_cfg.get("sidecar_socket", "")) or None
        self._sidecar = SidecarClient(sock) if sock else None
        self._emit_audit = bool(hub_cfg.get("emit_server_audit", True))

    def _startup_audit_guard(self) -> None:
        # Warn loudly if the chain doesn't verify (tampering since last run),
        # then harden the log (tight perms + best-effort append-only per OS).
        ok, msg = audit_verify(self.audit_path)
        if ok:
            log.info("audit chain verified (%s)", msg)
        else:
            log.error(
                "AUDIT CHAIN BROKEN: %s -- possible tampering since last run", msg
            )
            self._audit(
                {
                    "event": "audit_alert",
                    "reason": "startup_verify_failed",
                    "detail": msg,
                }
            )
        h = harden_log(self.audit_path)
        if h["append_only"]:
            log.info("audit log hardened: 0600 + append-only via %s", h["method"])
        else:
            log.warning(
                "audit log NOT append-only (%s): %s -- tampering is only "
                "DETECTED, not PREVENTED, until this is set",
                h["os"],
                h["note"],
            )

    def start(self) -> None:
        self._startup_audit_guard()
        for bname, bcfg in self._config.get("backends", {}).items():
            if not bcfg.get("enabled", False):
                log.info("backend %s disabled -> skipped", bname)
                continue
            if bcfg.get("mode") == "sidecar":
                # Embedded vault backend: dispatched over the sidecar with each
                # agent's own bearer (per-agent identity to the vault). Needs a
                # configured [hub].sidecar_socket.
                if not self._sidecar:
                    log.error(
                        "backend %s mode=sidecar but no [hub].sidecar_socket set",
                        bname,
                    )
                    continue
                gw = _import_gateway()
                be = gw.VaultBackend(self._sidecar, name=bname)
                self.backends[bname] = be
                for tool in be.tools:
                    orig = tool["name"]
                    prefixed = f"{bname}_{orig}"
                    t = dict(tool)
                    t["name"] = prefixed
                    self.aggregated_tools.append(t)
                    self.routes[prefixed] = (be, orig)
                log.info("backend %s (sidecar vault): %d tools", bname, len(be.tools))
                continue
            be = Backend(
                name=bname,
                command=bcfg["command"],
                env=bcfg.get("env", {}),
                destructive_requires_confirm=bcfg.get(
                    "destructive_requires_confirm", False
                ),
            )
            try:
                be.start()
            except Exception as e:
                # One bad backend must not sink the hub; log and carry on.
                log.error("backend %s failed to start: %s", bname, e)
                continue
            self.backends[bname] = be
            for tool in be.tools:
                orig = tool["name"]
                prefixed = f"{bname}_{orig}"
                t = dict(tool)
                t["name"] = prefixed
                self.aggregated_tools.append(t)
                self.routes[prefixed] = (be, orig)
            log.info("backend %s: %d tools", bname, len(be.tools))

    def _audit(self, event: dict) -> None:
        event = {"ts": _now_iso(), "hub": self.name, **event}
        try:
            self._audit_chain.append(event)  # hash-chained, append-only
        except Exception as e:
            log.warning("audit write failed: %s", e)

    def _emit(
        self,
        ctx: dict | None,
        *,
        backend: str,
        tool: str,
        decision: str,
        target: str | None = None,
        detail: dict | None = None,
    ) -> None:
        """Emit one event to the vault's chained /audit/mcp (daemon mode only)."""
        bearer = ctx.get("bearer") if ctx else None
        if not (self._emit_audit and self._sidecar and bearer):
            return
        gw = _import_gateway()
        gw.emit_mcp_audit(
            self._sidecar,
            bearer,
            backend=backend,
            tool=tool,
            decision=decision,
            hub=self.name,
            target=target,
            detail=detail,
            client_ip=ctx.get("client_ip") if ctx else None,
        )

    def handle(self, msg: dict, ctx: dict | None = None) -> dict | None:
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            return _result(
                mid,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": __version__},
                },
            )
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return _result(mid, {})
        if method == "tools/list":
            return _result(mid, {"tools": self.aggregated_tools})
        if method == "tools/call":
            return self._call(mid, msg.get("params", {}) or {}, ctx)
        if mid is not None:
            return _error(mid, -32601, f"method not found: {method}")
        return None

    def _call(self, mid: Any, params: dict, ctx: dict | None = None) -> dict:
        name = params.get("name", "")
        arguments = dict(params.get("arguments", {}) or {})
        # Best-effort target for the audit (name never carries a secret value).
        target = arguments.get("name") or arguments.get("namespace")
        route = self.routes.get(name)
        if not route:
            self._audit({"event": "denied", "tool": name, "reason": "unknown_tool"})
            self._emit(
                ctx,
                backend="",
                tool=name,
                decision="policy_denied",
                target=target,
                detail={"reason": "unknown_tool"},
            )
            return _error(mid, -32602, f"unknown tool: {name}")
        be, orig = route
        # Local policy: a destructive tool needs an explicit _confirm on this host.
        if be.destructive_requires_confirm and not arguments.get("_confirm"):
            self._audit(
                {
                    "event": "blocked",
                    "backend": be.name,
                    "tool": orig,
                    "reason": "destructive_requires_confirm",
                }
            )
            self._emit(
                ctx,
                backend=be.name,
                tool=orig,
                decision="policy_denied",
                target=target,
                detail={"reason": "destructive_requires_confirm"},
            )
            return _tool_error(
                mid,
                f"'{name}' is marked destructive on this host. Re-call it with "
                'argument "_confirm": true to proceed.',
            )
        arguments.pop("_confirm", None)
        t0 = time.monotonic()
        try:
            result = be.call(orig, arguments, ctx)
        except Exception as e:
            self._audit(
                {
                    "event": "error",
                    "backend": be.name,
                    "tool": orig,
                    "error": str(e)[:200],
                }
            )
            self._emit(
                ctx,
                backend=be.name,
                tool=orig,
                decision="error",
                target=target,
                detail={"error": str(e)[:200]},
            )
            return _tool_error(mid, f"backend '{be.name}' error: {e}")
        self._audit(
            {
                "event": "call",
                "backend": be.name,
                "tool": orig,
                "ms": round((time.monotonic() - t0) * 1000),
            }
        )
        self._emit(ctx, backend=be.name, tool=orig, decision="allowed", target=target)
        return _result(mid, result)

    def serve(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp = self.handle(msg)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()

    def stop(self) -> None:
        for be in self.backends.values():
            if hasattr(be, "stop"):
                be.stop()  # stdio backends only; the embedded VaultBackend has none


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        stream=sys.stderr,  # stdout is the JSON-RPC channel
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    argv = sys.argv[1:]
    if "--version" in argv:
        print(__version__)
        return 0
    if "--verify-audit" in argv:
        i = argv.index("--verify-audit")
        path = (
            argv[i + 1]
            if i + 1 < len(argv)
            else "~/.local/state/rhorizon-mcp-hub/calls.jsonl"
        )
        ok, msg = audit_verify(path)
        print(("OK: " if ok else "TAMPERED: ") + msg)
        return 0 if ok else 2
    if "--harden-audit" in argv:
        i = argv.index("--harden-audit")
        path = (
            argv[i + 1]
            if i + 1 < len(argv)
            else "~/.local/state/rhorizon-mcp-hub/calls.jsonl"
        )
        rep = harden_log(path)
        print(json.dumps(rep, indent=2))
        print("current flags:", append_only_status(path))
        return 0 if rep["perms_0600"] else 1
    cfg_path = os.environ.get(
        "RHORIZON_HUB_CONFIG", "~/.config/rhorizon-mcp-hub/hub.toml"
    )
    for i, a in enumerate(argv):
        if a == "--config" and i + 1 < len(argv):
            cfg_path = argv[i + 1]
    cfg_path = _expand(cfg_path)
    try:
        with open(cfg_path, "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        log.error("no config at %s (set RHORIZON_HUB_CONFIG or --config)", cfg_path)
        return 1
    hub = Hub(config)
    hub.start()

    # --daemon: multi-agent loopback HTTP (Streamable MCP), per-agent bearer +
    # server-side chained audit. Default stays stdio (single agent, unchanged).
    if "--daemon" in argv:
        if not hub._sidecar:
            log.error("--daemon requires [hub].sidecar_socket (bearer auth path)")
            hub.stop()
            return 1
        hub_cfg = config.get("hub", {})
        bind = hub_cfg.get("bind", "127.0.0.1")
        port = int(hub_cfg.get("port", 9110))
        if bind not in ("127.0.0.1", "::1", "localhost") and (
            os.environ.get("RHORIZON_HUB_PUBLIC_BIND_OK") != "1"
        ):
            log.error(
                "refusing non-loopback bind %s without RHORIZON_HUB_PUBLIC_BIND_OK=1",
                bind,
            )
            hub.stop()
            return 1
        gw = _import_gateway()
        auth = gw.BearerAuth(hub._sidecar)
        log.info(
            "%s ready: %d backend(s), %d tool(s) (daemon http://%s:%d)",
            hub.name,
            len(hub.backends),
            len(hub.aggregated_tools),
            bind,
            port,
        )
        try:
            gw.serve_http(hub, auth, bind, port)
        finally:
            hub.stop()
        return 0

    log.info(
        "%s ready: %d backend(s), %d tool(s) (stdio)",
        hub.name,
        len(hub.backends),
        len(hub.aggregated_tools),
    )
    try:
        hub.serve()
    finally:
        hub.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
