# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw
"""Tamper-evident append-only audit log (SHA-256 hash chain). Zero-dep.

Each record links to the previous one by hash, so any in-place edit, insertion,
reorder, or deletion breaks the chain and `verify()` catches it (and points at
the first broken line).

The chain proves *integrity relative to a trusted head*. To make it tamper-
evident against a compromised hub user (who could otherwise rewrite the whole
file and recompute every hash), deploy so the hub user can append but not
rewrite/truncate:

  - Linux : `chattr +a <logfile>`      (append-only; only root clears the attr)
  - *BSD  : `chflags sappnd <logfile>` (system append-only; needs securelevel)

and/or anchor the head hash off-host periodically (ship it to the vault's audit
chain or a remote append-only sink). The hash chain detects modification;
append-only prevents wholesale rewrite; together they are tamper-evident.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

GENESIS = "0" * 64


def _canon(payload: dict) -> str:
    # Deterministic serialization so the hash is reproducible on verify.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _entry_hash(payload: dict) -> str:
    # payload already contains `prev` (the previous record's hash), so the
    # chain is bound without prepending it separately.
    return hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()


class AuditChain:
    """Append-only hash-chained JSONL log."""

    def __init__(self, path: str):
        self.path = Path(os.path.expanduser(path))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._load_head()

    def _load_head(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = None
        with self.path.open("rb") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return 0, GENESIS
        rec = json.loads(last)
        return int(rec.get("seq", 0)), rec.get("hash", GENESIS)

    def append(self, event: dict) -> dict:
        seq = self._seq + 1
        payload = {"seq": seq, "prev": self._head, **event}
        rec = {**payload, "hash": _entry_hash(payload)}
        # append-only open; if the file is chattr +a / sappnd this still works,
        # but truncation/rewrite by the hub user does not.
        with self.path.open("a", encoding="utf-8") as f:
            f.write(_canon(rec) + "\n")
        self._seq, self._head = seq, rec["hash"]
        return rec


def verify(path: str) -> tuple[bool, str]:
    """Re-walk the chain. Returns (ok, message); message names the first break."""
    p = Path(os.path.expanduser(path))
    if not p.exists() or p.stat().st_size == 0:
        return True, "empty (no records)"
    prev = GENESIS
    seq = 0
    with p.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {lineno}: not valid JSON"
            seq += 1
            if rec.get("seq") != seq:
                return (
                    False,
                    f"line {lineno}: seq {rec.get('seq')} != {seq} (bad seq)",
                )
            if rec.get("prev") != prev:
                return False, f"line {lineno}: prev != previous hash (chain broken)"
            recorded = rec.get("hash")
            payload = {k: v for k, v in rec.items() if k != "hash"}
            if recorded != _entry_hash(payload):
                return False, f"line {lineno}: hash mismatch (record tampered)"
            prev = recorded
    return True, f"{seq} records, head {prev[:12]}..."
