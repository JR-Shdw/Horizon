# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Credential proxy for the stdio server -- use a credential without reading it.

The server resolves the credential, makes the authenticated call itself and
returns only the upstream's answer. The caller chooses the path and the query;
the host, the credential format and the injection point come from the operator's
`[proxy]` binding (`policy.py`). See docs/MCP.md 4.1.

The value is a Python `str` here for the duration of the call, exactly as
`vault_get_secret` already leaves it: what this buys on the stdio path is that
it does not reach the model. The hub path keeps it out of Python entirely
(`rh-mcp-gateway`). Stdlib only.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request

from .policy import ProxyBinding, ProxyDenied

# Upstream trust anchors: the system store, plus RH_MCP_EGRESS_CAFILE when the
# API is internal and served by a private CA. Never RH_VAULT_CAFILE -- a
# separate variable, so the vault's CA cannot certify the API being called.
_upstream_ctx: ssl.SSLContext | None = None


def upstream_context(cafile: str | None = None) -> ssl.SSLContext:
    """System trust store, plus an optional extra anchor.

    Built by hand rather than ``create_default_context(cafile=...)``, which
    loads that file *instead of* the system store: an internal anchor would
    silently stop every public API from verifying.
    """
    global _upstream_ctx
    if _upstream_ctx is None:
        extra = cafile or os.environ.get("RH_MCP_EGRESS_CAFILE") or None
        ctx = ssl.create_default_context()
        if extra:
            ctx.load_verify_locations(cafile=extra)
        _upstream_ctx = ctx
    return _upstream_ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: a 302 elsewhere re-attaches the credential to
    whatever the upstream names. None makes urllib raise the 3xx as HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_opener: urllib.request.OpenerDirector | None = None


def _default_opener() -> urllib.request.OpenerDirector:
    global _opener
    if _opener is None:
        _opener = urllib.request.build_opener(
            _NoRedirect,
            urllib.request.HTTPSHandler(context=upstream_context()),
        )
    return _opener


class RateLimiter:
    """Per-credential sliding window, so the proxy cannot be used to hammer a
    third party from this host. In-process: the stdio server is one per agent."""

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, per_min: int) -> bool:
        if per_min <= 0:
            return False
        now = time.monotonic()
        hits = [t for t in self._hits.get(key, []) if now - t < 60.0]
        if len(hits) >= per_min:
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True


def call(
    binding: ProxyBinding,
    value: str,
    url: str,
    *,
    method: str = "GET",
    opener: urllib.request.OpenerDirector | None = None,
) -> dict:
    """Perform one proxied call and return `{status, body, truncated}`.

    `url` must come from `ProxyBinding.build_url`: that is where the destination
    is decided, not here.
    """
    if binding.inject_type != "header":
        raise ProxyDenied(f"unsupported injection type {binding.inject_type!r}")
    if "{value}" not in binding.inject_format:
        raise ProxyDenied("inject format has no {value} placeholder")
    if not url.startswith("https://"):
        raise ProxyDenied("proxied calls are https-only")
    header = binding.inject_format.replace("{value}", value)
    if any(c in header for c in "\r\n\0"):
        raise ProxyDenied("credential does not render to a legal header value")

    req = urllib.request.Request(url, method=method.upper())
    req.add_header(binding.inject_name, header)
    req.add_header("Accept", "application/json")
    send = opener or _default_opener()
    cap = binding.max_response_bytes
    try:
        with send.open(req, timeout=binding.timeout_secs) as resp:
            status = resp.status
            raw = resp.read(cap + 1)
    except urllib.error.HTTPError as e:
        # Error bodies repeat the rejected token; same scan as a success.
        status = e.code
        raw = e.read(cap + 1)
        if status in (301, 302, 303, 307, 308):
            raise ProxyDenied(f"upstream redirected ({status}); refused") from None
    except urllib.error.URLError as e:
        raise ProxyDenied(f"upstream request failed: {e.reason}") from None

    text = raw.decode("utf-8", "replace")
    if value and value in text:
        raise ProxyDenied("upstream echoed the credential; response withheld")
    truncated = len(raw) > cap
    if truncated:
        text = raw[:cap].decode("utf-8", "replace")
    try:
        body: object = json.loads(text)
    except json.JSONDecodeError:
        body = text
    return {"status": status, "body": body, "truncated": truncated}
