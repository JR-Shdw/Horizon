# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Authentication failure log - fail2ban-ready.

Appends one line per auth failure. Format:
    2026-04-13T14:23:45+0000 rhorizon AUTH_FAIL ip=10.0.0.1 type=invalid_token

POSIX guarantees atomic append for writes < PIPE_BUF (4096 bytes),
so concurrent workers can write safely without locking.

Ready-to-use fail2ban filter/jail ship in contrib/fail2ban/ (see
docs/FAIL2BAN.md). The line format is a stability contract: that filter's
failregex and any "or similar" log shipper depend on it.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

_log_path: Path | None = None

# Allowed chars for a field written to the log: IPv4/IPv6/CIDR literals and
# the fixed fail_type tokens. Anything else (newline, space, '=') is dropped,
# so a caller-supplied value can never forge a second line in the fail2ban
# log (which would let an attacker ban an arbitrary IP).
_UNSAFE_FIELD = re.compile(r"[^A-Za-z0-9._:/-]")


def _sanitize(value: str) -> str:
    return _UNSAFE_FIELD.sub("", str(value))[:64] or "unknown"


def _ensure_log() -> Path | None:
    """Lazy init: create parent dir if needed, return path."""
    global _log_path
    if _log_path is not None:
        return _log_path
    try:
        p = Path(settings.authfail_log)
        p.parent.mkdir(parents=True, exist_ok=True)
        _log_path = p
        return _log_path
    except OSError:
        return None


def log_authfail(ip: str, fail_type: str):
    """Append a single auth failure line. Never raises."""
    path = _ensure_log()
    if path is None:
        return
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
        safe_ip = _sanitize(ip)
        safe_type = _sanitize(fail_type)
        line = f"{ts} rhorizon AUTH_FAIL ip={safe_ip} type={safe_type}\n"
        with open(path, "a") as f:
            f.write(line)
    except OSError:
        pass
