# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Policy whitelist - filter which secrets the LLM is allowed to ask for.

The vault token already restricts what's reachable (scope + namespaces).
Policy is an EXTRA layer on top: even if the token can read 100 secrets,
the LLM might only need 3 of them. By default the MCP server refuses
anything not explicitly whitelisted - fail-closed.

Two policy modes:

  - **whitelist** (default, recommended): explicit list of fully-qualified
    secret names. Anything not listed -> denied.

  - **namespace**: allow a whole namespace (e.g. `mcp/mail/*`). Coarser
    but useful when the agent legitimately needs everything in a slice.

Config file (TOML) at $RH_MCP_POLICY (deprecated alias:
$RHORIZON_MCP_POLICY) (default
~/.config/rhorizon-mcp/policy.toml):

    [secrets]
    whitelist = [
        "mcp/mail/imap-host",
        "mcp/mail/imap-user",
        "mcp/mail/imap-password",
    ]

    [namespaces]
    allow = ["mcp/demo"]      # all secrets in mcp/demo/*

    [tools]
    allow = ["vault_get_secret", "vault_list_secrets", "vault_whoami"]
    # Optional: defaults to all tools the server exposes minus
    # destructive ones. See server.py for the canonical tool list.

    [proxy.github-prod]        # optional, one table per credential
    namespace   = "mcp"
    allow_read  = false        # vault_get_secret refuses it -- the point
    allow_proxy = true
    base_url    = "https://api.github.com"
    methods     = ["GET"]
    inject      = { type = "header", name = "Authorization", format = "Bearer {value}" }

The whitelist says which secrets may be READ; a `[proxy]` binding says which may
be USED (`proxy.py`, docs/MCP.md 4.1). `allow_read = false` keeps the two
answers from contradicting each other for the same secret.
"""

from __future__ import annotations

import os
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_POLICY_PATH = Path(
    os.environ.get("RH_MCP_POLICY")
    or os.environ.get("RHORIZON_MCP_POLICY")  # deprecated alias
    or "~/.config/rhorizon-mcp/policy.toml"
).expanduser()

# Tools that read state vs. mutate it. Default-allow read, default-deny
# mutate: the operator must opt in explicitly.
READ_TOOLS = {
    "vault_get_secret",
    "vault_list_secrets",
    "vault_list_namespaces",
    "vault_whoami",
    "vault_audit_tail",
    "vault_status",
    "vault_cluster_health",
    "vault_cluster_preflight",
    "vault_call_api",  # inert until a [proxy] binding names a credential
}
MUTATE_TOOLS = {
    "vault_set_secret",
    "vault_delete_secret",
    "vault_create_ephemeral_token",
}


def same_authority(a: str, b: str) -> bool:
    """Whether two URLs name the same host:port, default ports filled in.

    Used to refuse proxying a credential back at the vault. The MCP server
    holds a vault token; an agent able to name the vault as a destination would
    be asking the server to make authenticated vault calls on its behalf, which
    rebuilds direct API access through a confused deputy. Not possessing the
    token stops mattering the moment you can borrow what holds it.

    Compares authority rather than the string: scheme, case, and an explicit
    default port are all ways of spelling the same endpoint. Returns False when
    either side cannot be parsed -- the caller's own allow-list is what decides
    then, and this must not become a second way to say yes.
    """

    def authority(url: str) -> tuple[str, int] | None:
        parts = urllib.parse.urlsplit(url)
        default = {"https": 443, "http": 80}.get(parts.scheme.lower())
        if default is None or not parts.hostname:
            return None
        if parts.username or parts.password:
            return None  # userinfo changes which host is really contacted
        try:
            port = parts.port or default
        except ValueError:
            return None
        return parts.hostname.lower(), port

    x, y = authority(a), authority(b)
    return x is not None and x == y


class ProxyDenied(ValueError):
    """A proxied call was refused before any credential was resolved."""


@dataclass
class ProxyBinding:
    """What a credential may be used FOR, as opposed to read.

    Everything deciding where the request goes and how the credential is
    attached lives here, never in the call arguments.
    """

    credential: str
    namespace: str = "default"
    allow_read: bool = False
    allow_proxy: bool = False
    base_url: str = ""
    methods: frozenset[str] = field(default_factory=lambda: frozenset({"GET"}))
    inject_type: str = "header"
    inject_name: str = "Authorization"
    inject_format: str = "Bearer {value}"
    timeout_secs: float = 15.0
    max_response_bytes: int = 262_144
    rate_limit_per_min: int = 30

    def url_allowed(self, url: str) -> bool:
        """Prefix match against the bound base URL.

        Requires https and a non-empty base, so a binding that forgot base_url
        permits nothing rather than everything.
        """
        if not self.base_url.startswith("https://"):
            return False
        base = self.base_url.rstrip("/") + "/"
        return (url.rstrip("/") + "/").startswith(base)

    def method_allowed(self, method: str) -> bool:
        return method.upper() in self.methods

    def methods_listed(self) -> str:
        return ", ".join(sorted(self.methods)) or "none"

    def validate_inject(self) -> None:
        """Refuse a malformed binding BEFORE the credential is read.

        Left until injection time, a typo in the operator's table would spend a
        vault read -- decrypting and auditing a credential for a call that was
        never going to happen -- and then report itself as whatever the read
        returned.
        """
        if self.inject_type != "header":
            raise ProxyDenied(
                f"this binding injects into {self.inject_type!r}; only "
                '"header" is supported'
            )
        if "{value}" not in self.inject_format:
            raise ProxyDenied(
                "this binding's inject format has no {value} placeholder, so "
                "the credential has nowhere to go"
            )

    def build_url(self, path: str, query: dict | None = None) -> str:
        """Join a caller-supplied path onto the bound base, or refuse.

        Anything that could move the host is refused rather than sanitised:
        ``//evil.test/x`` and ``@evil.test/`` re-authority the URL once
        concatenated (so the parsed host is compared against the base's), dot
        segments climb out of a base that pins a path prefix, and control
        characters split the request line.
        """
        if not self.base_url:
            raise ProxyDenied("this binding has no base_url; the operator must set one")
        if not self.base_url.startswith("https://"):
            raise ProxyDenied(
                f"base_url must be https, not {self.base_url.split(':', 1)[0]}"
            )
        if not path:
            raise ProxyDenied("path is required, e.g. /api/v1/user")
        if path.startswith("//"):
            raise ProxyDenied(
                "path must not start with '//': that would re-point the request "
                "at another host"
            )
        if not path.startswith("/"):
            raise ProxyDenied(f"path must start with '/', got {path[:40]!r}")
        if any(c.isspace() or ord(c) < 0x20 for c in path):
            raise ProxyDenied("path contains whitespace or control characters")
        if "#" in path:
            raise ProxyDenied("path must not carry a fragment")
        segments = path.split("?", 1)[0].split("/")
        if any(s in (".", "..") for s in segments) or "%2e" in path.lower():
            raise ProxyDenied("path must not contain dot segments")
        url = self.base_url.rstrip("/") + path
        if query:
            sep = "&" if "?" in path else "?"
            url += sep + urllib.parse.urlencode(query)
        base = urllib.parse.urlsplit(self.base_url)
        got = urllib.parse.urlsplit(url)
        if got.scheme != "https" or got.netloc.lower() != base.netloc.lower():
            raise ProxyDenied("path would move the request off the bound host")
        if not self.url_allowed(url):
            raise ProxyDenied("path is outside the bound base URL")
        return url


@dataclass
class Policy:
    """In-memory policy. Built from the TOML file at startup."""

    whitelist_secrets: set[str] = field(default_factory=set)
    allow_namespaces: set[str] = field(default_factory=set)
    allow_tools: set[str] = field(default_factory=lambda: set(READ_TOOLS))
    proxy: dict[str, ProxyBinding] = field(default_factory=dict)
    deny_all: bool = False  # set when the file exists but is empty/invalid

    def proxy_binding(self, credential: str) -> ProxyBinding | None:
        """The binding for a credential, or None when it may not be proxied."""
        if self.deny_all:
            return None
        b = self.proxy.get(credential.strip("/"))
        if b is None or not b.allow_proxy:
            return None
        return b

    def bound_credentials(self) -> str:
        """Names an agent may actually pass, so a refusal is self-correcting.
        Names only -- the same ones vault_list_secrets already shows."""
        usable = sorted(k for k, b in self.proxy.items() if b.allow_proxy)
        return ", ".join(usable) if usable else "none"

    def read_denied_by_proxy(self, namespace: str, name: str) -> bool:
        """True when a binding exists and withholds direct read.

        The point of the feature is ``allow_read = false, allow_proxy = true``.
        Without this, a credential listed in both the proxy table and the
        secrets whitelist would still be readable, and the two tools would
        disagree about the same secret.
        """
        b = self.proxy.get(name.strip("/"))
        if b is None:
            return False
        if b.namespace.strip("/") != namespace.strip("/"):
            return False
        return not b.allow_read

    def secret_allowed(self, namespace: str, name: str) -> bool:
        """Resolve a secret access request.

        - Fully qualified name in whitelist_secrets -> allowed
        - Bare name in whitelist_secrets where the entry equals "ns/name" -> allowed
        - Namespace in allow_namespaces -> all names allowed
        - Otherwise -> denied

        Tolerant of leading/trailing slashes in namespace and name.
        """
        if self.deny_all:
            return False
        if self.read_denied_by_proxy(namespace, name):
            return False
        ns = namespace.strip("/")
        nm = name.strip("/")
        full = f"{ns}/{nm}" if ns else nm
        if full in self.whitelist_secrets:
            return True
        if ns in self.allow_namespaces:
            return True
        return False

    def tool_allowed(self, tool_name: str) -> bool:
        if self.deny_all:
            return False
        return tool_name in self.allow_tools


def load_policy(path: Path | None = None) -> Policy:
    """Read the policy TOML. Missing file -> empty policy (deny everything).

    Returning an empty Policy with deny_all=True is the safe default -
    the operator MUST configure the policy explicitly before the agent
    can do anything. Better than implicitly granting access.
    """
    p = path or DEFAULT_POLICY_PATH
    if not p.exists():
        return Policy(deny_all=True)

    try:
        data = tomllib.loads(p.read_text())
    except (tomllib.TOMLDecodeError, OSError):
        return Policy(deny_all=True)

    proxy_cfg = data.get("proxy", {})
    bindings: dict[str, ProxyBinding] = {}
    for cred, raw in proxy_cfg.items():
        if not isinstance(raw, dict):
            continue
        inject = raw.get("inject") or {}
        bindings[cred] = ProxyBinding(
            credential=cred,
            namespace=str(raw.get("namespace", "default")),
            allow_read=bool(raw.get("allow_read", False)),
            allow_proxy=bool(raw.get("allow_proxy", False)),
            base_url=str(raw.get("base_url", "")),
            methods=frozenset(
                m.upper() for m in raw.get("methods", ["GET"]) if isinstance(m, str)
            ),
            inject_type=str(inject.get("type", "header")),
            inject_name=str(inject.get("name", "Authorization")),
            inject_format=str(inject.get("format", "Bearer {value}")),
            timeout_secs=float(raw.get("timeout_secs", 15.0)),
            max_response_bytes=int(raw.get("max_response_bytes", 262_144)),
            rate_limit_per_min=int(raw.get("rate_limit_per_min", 30)),
        )

    secrets_cfg = data.get("secrets", {})
    ns_cfg = data.get("namespaces", {})
    tools_cfg = data.get("tools", {})

    pol = Policy(
        whitelist_secrets=set(secrets_cfg.get("whitelist", [])),
        allow_namespaces=set(ns_cfg.get("allow", [])),
        allow_tools=set(tools_cfg.get("allow", READ_TOOLS)),
        proxy=bindings,
    )
    # Empty whitelist + no allowed namespaces + READ tools only = effectively
    # deny everything except metadata. That's a reasonable fallback -
    # don't flip deny_all here.
    return pol
