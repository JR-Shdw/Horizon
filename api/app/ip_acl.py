# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Per-token IP allowlist parsing and matching.

Tokens may carry an `allowed_ips` field (TEXT, comma-separated) restricting
where they can be used. NULL or empty means no restriction (default).

Format: `10.0.0.0/8, 192.168.1.5, 2001:db8::/32, ::1`
- Bare IPs are treated as /32 (v4) or /128 (v6).
- IPv4 and IPv6 mix freely.
- Whitespace around entries is tolerated.
- An invalid entry raises ValueError with the offending token - fail-closed
  at creation time, never silently dropped.
"""

from __future__ import annotations

import ipaddress

CidrNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_allowed_ips(raw: str | None) -> list[CidrNet]:
    """Parse a comma-separated allowlist string into a list of networks.

    Returns [] for None / empty / whitespace-only input. Raises ValueError
    on the first invalid CIDR/IP - caller (token create endpoint) maps
    that to HTTP 400.
    """
    if not raw:
        return []
    nets: list[CidrNet] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        # ip_network accepts both "10.0.0.5" (-> /32) and "10.0.0.0/8"
        # when strict=False.
        nets.append(ipaddress.ip_network(entry, strict=False))
    return nets


def normalize_allowed_ips(raw: str | None) -> str | None:
    """Validate and canonicalize the allowlist for storage.

    Returns None if the input is empty (so the DB stores NULL = no
    restriction), otherwise a comma-separated string of canonical
    `network/prefix` forms. Raises ValueError on invalid entries.
    """
    nets = parse_allowed_ips(raw)
    if not nets:
        return None
    return ",".join(str(n) for n in nets)


def ip_in_allowlist(client_ip: str, allowed_ips: str | None) -> bool:
    """Return True iff `client_ip` matches any CIDR in `allowed_ips`.

    Empty/NULL allowlist means no restriction -> returns True.
    Malformed `client_ip` returns False (fail-closed).
    """
    if not allowed_ips:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    try:
        nets = parse_allowed_ips(allowed_ips)
    except ValueError:
        # DB content is corrupt, fail closed rather than open up access.
        return False
    return any(addr in n for n in nets)
