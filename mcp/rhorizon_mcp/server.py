# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""rhorizon-mcp -- zero-dependency MCP stdio server for the rhorizon vault.

Exposes read-only, policy-gated vault operations to LLM agents (Claude Code,
Codex, Cursor, Cline, opencode, ...) over the Model Context Protocol.
MCP-over-stdio is just
newline-delimited JSON-RPC 2.0; this implements it directly with the Python
standard library -- NO third-party dependencies, nothing to hash-pin, minimal
supply-chain surface. The AI never sees the vault token: the server holds it
and filters every call against policy.toml (fail-closed).

stdout carries the JSON-RPC protocol; all logging goes to stderr.

Environment:
  RH_VAULT_URL        vault base URL (default http://127.0.0.1:8200)
  RH_TOKEN_FILE       path to a 0600 file holding the vault token (or RH_TOKEN)
  RH_VAULT_CAFILE     optional CA bundle for a private-CA HTTPS vault. TLS stays
                      VERIFIED; only the trust anchor changes. Never disabled.
  RH_MCP_POLICY       policy.toml path (default ~/.config/rhorizon-mcp/policy.toml).
                      RHORIZON_MCP_POLICY is a deprecated alias.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__
from .policy import Policy, load_policy

log = logging.getLogger("rhorizon-mcp")

PROTOCOL_VERSION = "2024-11-05"


# ============================================================
# Vault client (stdlib urllib; TLS verified by default)
# ============================================================
class VaultHTTPError(Exception):
    def __init__(self, code: int, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"HTTP {code}: {detail}")


# Post-quantum hybrid key-exchange groups (OpenSSL >= 3.5 names). The rhorizon
# vault serves PQ TLS (X25519MLKEM768); the connector must negotiate PQ, never
# silently fall back to classical ECDH.
_PQ_HYBRID_GROUPS = (
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "X448MLKEM1024",
    "SecP384r1MLKEM1024",
)
_CLASSIC_GROUPS = ("x25519", "secp256r1", "x448", "secp384r1")


def _build_ssl_context(cafile: str | None, pq_mode: str) -> ssl.SSLContext:
    """Build a TLS context that prefers/enforces post-quantum key exchange.

    pq_mode:
      require -- PQ-only groups; a classical-only vault fails the handshake.
      prefer  -- PQ first, classical fallback (default).

    Enforcement needs SSLContext.set_groups (Python 3.13+). Without it we rely
    on OpenSSL >= 3.5, where X25519MLKEM768 is a default group and gets
    negotiated automatically -- but PQ cannot be *pinned* from Python, so the
    hard guarantee must come from the vault requiring PQ server-side.
    """
    ctx = ssl.create_default_context(cafile=cafile)
    openssl_pq = ssl.OPENSSL_VERSION_INFO >= (3, 5)
    groups = (
        _PQ_HYBRID_GROUPS
        if pq_mode == "require"
        else _PQ_HYBRID_GROUPS + _CLASSIC_GROUPS
    )
    if hasattr(ctx, "set_groups"):
        try:
            ctx.set_groups(":".join(groups))  # type: ignore[attr-defined]
            log.info(
                "TLS: PQ key exchange %s (%s)",
                "ENFORCED" if pq_mode == "require" else "preferred",
                groups[0],
            )
        except (ssl.SSLError, ValueError, OSError) as e:
            if pq_mode == "require":
                raise SystemExit(f"Cannot enforce PQ TLS groups: {e}") from None
            log.warning("TLS: set_groups failed (%s); using OpenSSL defaults", e)
    elif not openssl_pq:
        # No set_groups AND OpenSSL < 3.5: this client cannot offer ML-KEM at
        # all -- the only genuine "cannot do PQ" case. require -> fail closed.
        if pq_mode == "require":
            raise SystemExit(
                f"RH_VAULT_PQ=require: local OpenSSL {ssl.OPENSSL_VERSION} has no "
                "ML-KEM groups; this client cannot do post-quantum TLS. Upgrade "
                "OpenSSL to >= 3.5."
            )
        log.warning(
            "TLS: OpenSSL %s < 3.5 has no ML-KEM -> classical KEX ONLY; "
            "vault TLS will NOT be quantum-resistant. Upgrade OpenSSL.",
            ssl.OPENSSL_VERSION,
        )
    else:
        log.info(
            "TLS: OpenSSL %s negotiates PQ by default (X25519MLKEM768 @default); "
            "require PQ server-side on the vault for a hard guarantee.",
            ssl.OPENSSL_VERSION,
        )
    return ctx


class VaultClient:
    """Minimal rhorizon vault client over stdlib urllib.

    HTTPS certificates are validated against the system trust store by default
    (same posture as httpx/certifi). A private-CA vault supplies its anchor via
    RH_VAULT_CAFILE -- verification is never turned off. Key exchange prefers
    post-quantum hybrids (RH_VAULT_PQ).
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        cafile: str | None = None,
        pq_mode: str = "prefer",
        timeout: float = 10.0,
    ) -> None:
        self.base = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self._ctx = _build_ssl_context(cafile, pq_mode)

    def _get(self, path: str, params: dict | None = None) -> Any:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self._ctx
            ) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            raise VaultHTTPError(e.code, detail) from None
        return json.loads(raw) if raw.strip() else {}

    def status(self) -> Any:
        return self._get("/api/v1/vault/status")

    def whoami(self) -> Any:
        return self._get("/api/v1/vault/tokens/whoami")

    def list_namespaces(self) -> Any:
        return self._get("/api/v1/vault/secrets/namespaces")

    def list_secrets(self, namespace: str) -> Any:
        return self._get("/api/v1/vault/secrets/", {"namespace": namespace})

    def get_secret(self, name: str, namespace: str) -> Any:
        # name goes in the path -> percent-encode (secret names may contain '!' etc.)
        return self._get(
            "/api/v1/vault/secrets/" + urllib.parse.quote(name, safe=""),
            {"namespace": namespace},
        )

    def audit_tail(self, limit: int = 10) -> Any:
        return self._get("/api/v1/vault/audit/", {"limit": limit})

    def cluster_health(self) -> Any:
        # summary=true: states + reasons only. The server does the projection
        # so this path and the hub's cannot drift (they already did once).
        return self._get("/api/v1/vault/cluster/health", {"summary": "true"})


# ============================================================
# Tool catalog (plain JSON Schema dicts -- no pydantic)
# ============================================================
# Canonical catalog, shared byte-for-byte with mcp-hub (see tools.json).
# Do NOT inline tool definitions here: the two paths drifted apart once
# already, and tool descriptions are prompt material the model reads.
TOOLS: list[dict] = json.loads(
    (Path(__file__).parent / "tools.json").read_text(encoding="utf-8")
)["tools"]


def _dispatch(name: str, args: dict, client: VaultClient, policy: Policy) -> Any:
    """Route a tool call to the vault, applying policy filters. Identical
    semantics to the SDK-based server it replaces."""
    if name == "vault_status":
        return client.status()
    if name == "vault_whoami":
        return client.whoami()
    if name == "vault_list_namespaces":
        return client.list_namespaces()
    if name == "vault_list_secrets":
        ns = args.get("namespace") or "default"
        raw = client.list_secrets(ns)
        items = raw.get("items", []) if isinstance(raw, dict) else []
        filtered = [it for it in items if policy.secret_allowed(ns, it.get("name", ""))]
        return {
            "namespace": ns,
            "items": filtered,
            "filtered_count": len(items) - len(filtered),
        }
    if name == "vault_get_secret":
        secret_name = args["name"]
        ns = args.get("namespace") or "default"
        if not policy.secret_allowed(ns, secret_name):
            return {
                "error": "policy_denied",
                "message": (
                    f"Secret '{ns}/{secret_name}' not allowed. Operator must add "
                    f"it to [secrets].whitelist (or [namespaces].allow) in policy.toml."
                ),
            }
        r = client.get_secret(secret_name, ns)
        log.info(
            "vault_get_secret: %s/%s served", ns, secret_name
        )  # name only, never value
        return r
    if name == "vault_audit_tail":
        limit = int(args.get("limit", 10))
        return client.audit_tail(limit=max(1, min(100, limit)))
    if name == "vault_cluster_health":
        return client.cluster_health()
    raise ValueError(f"Unknown tool: {name}")


# ============================================================
# MCP over stdio (newline-delimited JSON-RPC 2.0)
# ============================================================
def _result(mid: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _content_error(msg: str) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps({"error": msg}, indent=2)}],
        "isError": True,
    }


def _call_tool(name: str, args: dict, client: VaultClient, policy: Policy) -> dict:
    if not policy.tool_allowed(name):
        return _content_error(
            f"Tool '{name}' not allowed. Add it to [tools].allow in policy.toml."
        )
    try:
        result = _dispatch(name, args, client, policy)
    except VaultHTTPError as e:
        return _content_error(f"Vault returned HTTP {e.code}: {e.detail}")
    except Exception as e:  # noqa: BLE001 -- surface failure, do not crash
        log.exception("Tool %s failed", name)
        return _content_error(f"Tool error: {type(e).__name__}: {e}")
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


def handle(msg: dict, client: VaultClient, policy: Policy) -> dict | None:
    """Handle one JSON-RPC message; return a response dict, or None for
    notifications / messages that take no reply."""
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return _result(
            mid,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "rhorizon-mcp", "version": __version__},
            },
        )
    if method in (
        "notifications/initialized",
        "initialized",
        "notifications/cancelled",
    ):
        return None
    if method == "ping":
        return _result(mid, {})
    if method == "tools/list":
        return _result(
            mid, {"tools": [t for t in TOOLS if policy.tool_allowed(t["name"])]}
        )
    if method == "tools/call":
        params = msg.get("params") or {}
        return _result(
            mid,
            _call_tool(
                params.get("name", ""), params.get("arguments") or {}, client, policy
            ),
        )
    if mid is not None:
        return _error(mid, -32601, f"Method not found: {method}")
    return None  # unknown notification -> ignore


def serve_stdio(client: VaultClient, policy: Policy) -> None:
    """Read JSON-RPC lines from stdin, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            log.warning("dropping non-JSON line")
            continue
        try:
            resp = handle(msg, client, policy)
        except Exception:  # noqa: BLE001
            log.exception("handler crashed")
            mid = msg.get("id")
            resp = _error(mid, -32603, "internal error") if mid is not None else None
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


# ============================================================
# Bootstrap
# ============================================================
def _load_token() -> str:
    """Resolve the vault token from RH_TOKEN_FILE (0600 enforced) or RH_TOKEN.
    Refuses to start without one."""
    env_token = os.environ.get("RH_TOKEN")
    if env_token:
        return env_token
    token_file = os.environ.get("RH_TOKEN_FILE")
    if not token_file:
        raise SystemExit(
            "Set RH_TOKEN_FILE (recommended) or RH_TOKEN for the vault credentials."
        )
    p = Path(token_file).expanduser()
    if not p.exists():
        raise SystemExit(f"Token file not found: {p}")
    if p.stat().st_mode & 0o077:
        raise SystemExit(f"Token file {p} is too open -- chmod 0600")
    return p.read_text().strip()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        stream=sys.stderr,  # stdout is the JSON-RPC channel -- keep logs off it
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    argv = sys.argv[1:]
    if "--version" in argv:
        print(__version__)
        return 0
    if "--transport" in argv and "http" in argv:
        raise SystemExit(
            "The zero-dependency build ships stdio only. HTTP transport was "
            "dropped to keep the dependency surface empty."
        )
    vault_url = os.environ.get("RH_VAULT_URL", "http://127.0.0.1:8200")
    cafile = os.environ.get("RH_VAULT_CAFILE") or None
    pq_mode = os.environ.get("RH_VAULT_PQ", "prefer").lower()
    if pq_mode not in ("prefer", "require"):
        raise SystemExit("RH_VAULT_PQ must be 'prefer' or 'require'")
    policy = load_policy()
    if policy.deny_all:
        log.warning(
            "No usable policy (%s) -> DENY ALL. Configure before reads.",
            os.environ.get("RH_MCP_POLICY")
            or os.environ.get("RHORIZON_MCP_POLICY")
            or "~/.config/rhorizon-mcp/policy.toml",
        )
    token = _load_token()
    client = VaultClient(vault_url, token, cafile=cafile, pq_mode=pq_mode)
    log.info("rhorizon-mcp %s (stdio, zero-dep) -> %s", __version__, vault_url)
    serve_stdio(client, policy)
    return 0


if __name__ == "__main__":
    sys.exit(main())
