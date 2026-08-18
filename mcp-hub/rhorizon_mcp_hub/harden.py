# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""Portable hardening for the tamper-evident audit log. Zero-dep.

Two protections:
  1. tight permissions  -- 0600 on the file, 0700 on its directory. The owner
     can always set these, on every POSIX OS.
  2. append-only flag   -- stops in-place rewrite/truncate of the hash chain.
     The mechanism and the privilege needed differ per OS:

       Linux    : chattr +a       (needs CAP_LINUX_IMMUTABLE == root; a DEPLOY
                                    step -- a non-root hub cannot self-set it)
       *BSD     : chflags uappnd   (the file OWNER sets it -- no root needed)
                  chflags sappnd   (stronger: root + securelevel > 0)
       macOS    : chflags uappnd

Where append-only cannot be set (e.g. non-root Linux, or an FS that lacks it),
we still enforce the perms and REPORT append_only=False with a note, so the
operator knows to set it at deploy. Nothing here silently pretends to be
protected when it isn't.
"""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as e:
        return False, str(e)


_BSD = ("FreeBSD", "OpenBSD", "NetBSD", "DragonFly", "Darwin")


def harden_log(path: str) -> dict:
    """chmod 0600 + 0700 dir, then best-effort append-only for the OS.

    Returns a report dict; never raises on the append-only step.
    """
    p = Path(os.path.expanduser(path))
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.touch()

    try:
        os.chmod(p, 0o600)
        os.chmod(p.parent, 0o700)
        perms = True
    except OSError:
        perms = False

    system = platform.system()
    method = None
    append_only = False
    note = ""

    if system == "Linux":
        method = "chattr +a"
        append_only, msg = _run(["chattr", "+a", str(p)])
        if not append_only:
            note = (
                f"{method} failed ({msg or 'needs root/CAP_LINUX_IMMUTABLE'}); "
                "set it once at deploy as root"
            )
    elif system in _BSD:
        method = "chflags uappnd"
        append_only, msg = _run(["chflags", "uappnd", str(p)])
        if append_only:
            note = "uappnd set (owner); sappnd (root+securelevel) is stronger"
        else:
            note = f"{method} failed ({msg}); check file ownership"
    else:
        note = f"append-only unsupported/unknown OS '{system}'; perms only"

    return {
        "path": str(p),
        "os": system,
        "perms_0600": perms,
        "append_only": append_only,
        "method": method,
        "note": note,
    }


def append_only_status(path: str) -> str:
    """Best-effort human-readable current flag state (lsattr / ls -lO)."""
    p = Path(os.path.expanduser(path))
    if platform.system() == "Linux":
        ok, msg = _run(["lsattr", str(p)])
    else:
        ok, msg = _run(["ls", "-lO", str(p)])  # BSD/macOS print file flags
    return msg if ok else "(flag state unavailable)"
