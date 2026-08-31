# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""Per-credential proxy bindings for the hub, read from hub.toml.

The one property: an agent may **use** a credential without being authorised to
**read** it. See docs/MCP.md 4.1.

Structure mirrors `mcp/rhorizon_mcp/policy.py` -- the two paths must agree about
the same credential, and a shared shape is what keeps them agreeing. The
packages install independently, so neither may import the other.

    [proxy.github-prod]
    namespace   = "mcp"
    allow_read  = false          # vault_get_secret refuses it on this hub too
    allow_proxy = true
    base_url    = "https://api.github.com"
    methods     = ["GET"]
    inject      = { type = "header", name = "Authorization", format = "Bearer {value}" }

Absent `[proxy]` table -> no bindings -> every proxied call refused. An old hub
reading a new file ignores the table; a new hub reading an old file gets an
empty set. Both directions fail closed.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field


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

    def url_allowed(self, url: str) -> bool:
        """Prefix match against the bound base URL, anchored on a trailing
        slash so ``api.example.com`` cannot permit ``api.example.com.evil``.
        Requires https and a non-empty base, so a binding that forgot base_url
        permits nothing rather than everything."""
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

    def as_inject(self) -> dict:
        """The injection spec as the sidecar expects it."""
        return {
            "type": self.inject_type,
            "name": self.inject_name,
            "format": self.inject_format,
        }


@dataclass
class ProxyPolicy:
    bindings: dict[str, ProxyBinding] = field(default_factory=dict)

    def bound_credentials(self) -> str:
        """Names an agent may actually pass, so a refusal is self-correcting."""
        usable = sorted(k for k, b in self.bindings.items() if b.allow_proxy)
        return ", ".join(usable) if usable else "none"

    def binding(self, credential: str) -> ProxyBinding | None:
        """The binding for a credential, or None when it may not be proxied."""
        b = self.bindings.get(credential.strip("/"))
        if b is None or not b.allow_proxy:
            return None
        return b

    def read_denied(self, namespace: str, name: str) -> bool:
        """True when a binding exists and withholds direct read, so
        ``vault_get_secret`` cannot serve what the proxy is meant to guard."""
        b = self.bindings.get(name.strip("/"))
        if b is None:
            return False
        if b.namespace.strip("/") != namespace.strip("/"):
            return False
        return not b.allow_read


def load_proxy_policy(config: dict) -> ProxyPolicy:
    """Build the policy from an already-parsed hub.toml."""
    bindings: dict[str, ProxyBinding] = {}
    for cred, raw in (config.get("proxy") or {}).items():
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
        )
    return ProxyPolicy(bindings=bindings)
