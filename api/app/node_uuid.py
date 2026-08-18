# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Per-container node identity.

Each rhorizon container holds a stable `node_uuid` for its lifetime,
persisted on a docker volume (`/var/lib/rhorizon/node-uuid`, mode 0400,
owner uid 1500). The file is generated on first boot via `uuid4().hex`
and reused on subsequent boots. Destroying the volume yields a fresh
identity - the cluster JOIN protocol treats the node as new, not as a
returning one. See `docs/HA-CLUSTER.md` section 3.

Corruption (non-hex, wrong length, partial write left over from a crash)
raises `NodeUUIDError` at boot. The container refuses to start rather
than registering with an unreliable identity - operator inspects, then
either fixes the file or deletes the volume to restart fresh.
"""

import logging
import os
import re
import tempfile
import time
import uuid
from pathlib import Path

log = logging.getLogger("rhorizon.node_uuid")

_NODE_UUID: str | None = None

# uuid4().hex is exactly 32 lowercase hex characters.
_HEX_32_RE = re.compile(r"^[0-9a-f]{32}$")


class NodeUUIDError(RuntimeError):
    """Raised when the persisted node_uuid is unreadable or corrupted."""


def _validate(value: str) -> str:
    if not _HEX_32_RE.fullmatch(value):
        raise NodeUUIDError(
            "node-uuid file contents invalid (expected 32 lowercase hex chars, "
            f"got len={len(value)})"
        )
    return value


def load_or_create_node_uuid(path: str | Path) -> str:
    """Read the node_uuid from `path`, or generate and persist if absent.

    The write is atomic (tmp file + chmod 0400 + rename) so a crash
    cannot leave a half-written file. Parent dir is created mode 0700.
    """
    p = Path(path)
    if p.exists():
        if not p.is_file():
            raise NodeUUIDError(f"{p} exists but is not a regular file")
        try:
            contents = p.read_text(encoding="ascii").strip()
        except (UnicodeDecodeError, OSError) as exc:
            raise NodeUUIDError(f"cannot read {p}: {exc}") from exc
        validated = _validate(contents)
        log.info("node_uuid: loaded existing uuid from %s", p)
        return validated

    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fresh = uuid.uuid4().hex
    # Mint once across the N racing workers: link(2) is atomic and fails
    # EEXIST, so the loser adopts the winner's uuid instead of its own.
    fd, tmp_name = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        os.write(fd, fresh.encode("ascii"))
        os.fchmod(fd, 0o400)  # umask-proof: mkstemp creates 0600
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, p)
    except FileExistsError:
        return _adopt_existing(p)  # a peer won the race; take its uuid
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    log.warning("node_uuid: generated fresh uuid at %s (first boot)", p)
    return fresh


def _adopt_existing(p: Path) -> str:
    """Read the uuid a peer minted when we lost the link race.

    The peer fsyncs before linking, so `p` is complete once it exists;
    the short retry only guards exotic filesystems.
    """
    for _ in range(50):  # ~0.5s ceiling
        try:
            contents = p.read_text(encoding="ascii").strip()
        except (UnicodeDecodeError, OSError) as exc:
            raise NodeUUIDError(f"cannot read {p}: {exc}") from exc
        if contents:
            log.info("node_uuid: adopted uuid minted by a peer worker at %s", p)
            return _validate(contents)
        time.sleep(0.01)
    raise NodeUUIDError(f"{p} was created by a peer worker but stayed empty")


def init_node_uuid(path: str | Path) -> str:
    """Initialise and cache the module-level node_uuid for later consumers."""
    global _NODE_UUID
    _NODE_UUID = load_or_create_node_uuid(path)
    return _NODE_UUID


def get_node_uuid() -> str:
    """Return the cached node_uuid (init_node_uuid must run first)."""
    if _NODE_UUID is None:
        raise NodeUUIDError("node_uuid not initialised - call init_node_uuid() first")
    return _NODE_UUID


def _reset_for_tests() -> None:
    global _NODE_UUID
    _NODE_UUID = None
