# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Resolve the client IP for audit + rate-limit identity, parsing
X-Forwarded-For when the request comes from a configured trusted proxy.

The effective trust list combines `settings.xff_trusted_ips`, used only for
client-IP forwarding, with identity proxies from `settings.proxy_trusted_ips`
or the DB-backed SSO configuration.

Without trusted proxies configured, returns request.client.host directly -
no XFF interpretation, so a non-proxied client cannot lie about its IP.

When trusted_proxies is set, walks XFF right-to-left, skipping hops that
are themselves trusted, returning the first untrusted hop. If all hops are
trusted, returns the leftmost (the original origin).

Note: do NOT use this helper for trust decisions like _is_trusted(client_ip)
in routes/auth_proxy.py - those must use the direct peer (request.client.host)
to prevent header smuggling.
"""

import ipaddress
import logging

from fastapi import Request

from .config import settings

log = logging.getLogger("rhorizon.client_ip")


def _parse_cidrs(csv: str, *, reject_invalid: bool = False) -> list:
    networks = []
    for token in (csv or "").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            if reject_invalid:
                raise
            continue  # malformed env entry: ignore it rather than trust it
    return networks


_XFF_TRUSTED_PROXIES = _parse_cidrs(settings.xff_trusted_ips)
_IDENTITY_TRUSTED_PROXIES = _parse_cidrs(settings.proxy_trusted_ips)


def _merge_trusted_proxies() -> list:
    merged = []
    for network in [*_XFF_TRUSTED_PROXIES, *_IDENTITY_TRUSTED_PROXIES]:
        if network not in merged:
            merged.append(network)
    return merged


_TRUSTED_PROXIES = _merge_trusted_proxies()


def set_trusted_proxies(csv: str | None, *, reject_invalid: bool = False) -> None:
    """Override identity proxies and refresh effective XFF trust.

    Called from `POST /auth/proxy/config` after a successful DB write,
    and from the lifespan handler on startup so a previously-saved DB
    config takes effect immediately on boot.

    Passing None or "" clears identity proxies but preserves the separately
    configured XFF-only proxies used by the bundled frontend.
    """
    global _IDENTITY_TRUSTED_PROXIES, _TRUSTED_PROXIES
    new_list = _parse_cidrs(csv or "", reject_invalid=reject_invalid)
    _IDENTITY_TRUSTED_PROXIES = new_list
    _TRUSTED_PROXIES = _merge_trusted_proxies()
    log.info(
        "identity proxies updated: %s",
        [str(n) for n in new_list] if new_list else "(none)",
    )


def get_trusted_proxies() -> list:
    """Read access for tests + the /cluster endpoint."""
    return list(_TRUSTED_PROXIES)


def get_identity_trusted_proxies() -> list:
    """Identity-proxy trust, excluding XFF-only frontend proxies."""
    return list(_IDENTITY_TRUSTED_PROXIES)


# Prefixes at or tighter than these are "host-group sized" ; anything broader
# trusts more hosts than a reverse proxy ever needs.
_BROAD_V4_PREFIX = 24
_BROAD_V6_PREFIX = 120


def overly_broad_proxies() -> list[str]:
    """Trusted-proxy networks broader than a /24 (v4) or /120 (v6).

    A wide trust list lets any host in range supply the client IP consumed by
    token ACLs, rate limiting and audit. Identity-forwarding features add
    further impact. Returns the entries that need a startup warning.
    """
    out = []
    for net in _TRUSTED_PROXIES:
        floor = _BROAD_V4_PREFIX if net.version == 4 else _BROAD_V6_PREFIX
        if net.prefixlen < floor:
            out.append(str(net))
    return out


def get_client_ip(request: Request) -> str:
    """Best-effort client IP for audit/rate-limit. Returns 'unknown' if absent."""
    direct = request.client.host if request.client else "unknown"
    if not _TRUSTED_PROXIES or direct == "unknown":
        return direct

    try:
        direct_ip = ipaddress.ip_address(direct)
    except ValueError:
        return direct

    if not any(direct_ip in net for net in _TRUSTED_PROXIES):
        return direct  # don't trust XFF from non-proxy peers

    xff = request.headers.get("x-forwarded-for", "")
    if not xff:
        return direct

    chain = [hop.strip() for hop in xff.split(",") if hop.strip()]
    for hop in reversed(chain):
        try:
            hop_ip = ipaddress.ip_address(hop)
        except ValueError:
            continue
        if not any(hop_ip in net for net in _TRUSTED_PROXIES):
            return hop

    # All hops were trusted -> the leftmost is the claimed origin. Only return
    # it if it is a real IP; otherwise fall back to the proxy peer. Never
    # return an unvalidated header value -- it flows into the audit log and
    # the fail2ban authfail log, where an embedded newline forges entries.
    if chain:
        try:
            ipaddress.ip_address(chain[0])
            return chain[0]
        except ValueError:
            return direct
    return direct
