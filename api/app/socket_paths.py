# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Filesystem-path Unix socket helpers - portable across Linux, macOS, BSD.

Replaces the Linux-only abstract namespace (\\0name) sockets used earlier.
The compartmentalisation contract is unchanged
(master holds sub-keys, followers attach via authenticated IPC) - only
the transport moves from kernel-only abstract namespace to a filesystem
path with strict 0700 permissions.

Lifecycle:
  Boot:   acquire_socket_path(p) checks for a stale socket file. If a
          live process is bound to it, refuses to start. If the file is
          orphaned (previous process died ungracefully), unlinks it.
  Bind:   socket(AF_UNIX) + bind(path) + chmod 0700 (defence in depth)
  Stop:   close fd + unlink path
  Crash:  file persists but next boot detects orphan via connect-probe

Design choices:
  - 0700 dir + 0700 socket: only owner UID can stat/connect. Combined
    with SO_PEERCRED/getpeereid UID check, fail-closed even if dir is
    misconfigured.
  - Connect-probe for staleness detection: simpler than flock/PID file,
    works across OSes, no extra fd to manage. Race window is tiny:
    if a peer connects between probe and our bind, our bind fails with
    EADDRINUSE - caller retries via the cleanup path.
  - Path resolution: env override > XDG_RUNTIME_DIR > /run/rhorizon
    > /tmp/rhorizon-{uid}. The fallback chain matches systemd best
    practice + dev/test ergonomics.
"""

import logging
import os
import socket
import sys
import tempfile
from pathlib import Path


def get_hostname() -> str:
    """Lazy re-export of cluster.get_hostname.

    Imported inside the call rather than at module scope so this module stays
    pure-stdlib to IMPORT. The custodian supervisor runs
    `python -m app.socket_paths` to decide whether a leftover socket is an
    orphan, and app.cluster pulls in SQLAlchemy; a module-level import would
    make that probe fail wherever the ORM is unavailable. Since the supervisor
    fails closed, such a failure would refuse to start the pool at all --
    turning a recoverable wedge into a node that never boots.
    """
    from .cluster import get_hostname as _get_hostname

    return _get_hostname()


log = logging.getLogger("rhorizon.socket_paths")

# Permissions
_DIR_MODE = 0o700
_SOCK_MODE = 0o700

# Probe timeout when checking for a stale socket file
_STALE_PROBE_TIMEOUT = 0.5


def runtime_dir() -> Path:
    """Resolve the rhorizon runtime directory.

    Preference order:
      1. $RH_RUNTIME_DIR, then legacy $RHORIZON_RUNTIME_DIR
      2. $XDG_RUNTIME_DIR/rhorizon (rootless containers, user services)
      3. /run/rhorizon (system service, systemd RuntimeDirectory)
      4. /tmp/rhorizon-{uid} (fallback for tests / unprivileged dev)

    The directory is created if missing, with strict 0700 mode and the
    current user as owner. Returns the resolved Path.
    """
    env = os.environ.get("RH_RUNTIME_DIR") or os.environ.get("RHORIZON_RUNTIME_DIR")
    if env:
        path = Path(env)
    else:
        xdg = os.environ.get("XDG_RUNTIME_DIR")
        if xdg and Path(xdg).exists():
            path = Path(xdg) / "rhorizon"
        elif Path("/run/rhorizon").exists() and os.access("/run/rhorizon", os.W_OK):
            # systemd RuntimeDirectory=rhorizon pre-created the dir with
            # the service user as owner -- the typical bare-metal case.
            # An unprivileged uid cannot os.access("/run", W_OK) but
            # /run/rhorizon itself is writable, so we MUST probe the
            # final target, not the parent.
            path = Path("/run/rhorizon")
        elif Path("/run").exists() and os.access("/run", os.W_OK):
            # Running as root (or another user with write on /run) :
            # we can mkdir /run/rhorizon ourselves.
            path = Path("/run/rhorizon")
        else:
            path = Path(tempfile.gettempdir()) / f"rhorizon-{os.getuid()}"
            # /tmp is world-writable: refuse a symlink or a pre-existing
            # dir we don't own (predictable-path pre-plant) rather than
            # dropping IPC sockets into an attacker-controlled directory.
            if path.is_symlink():
                raise RuntimeError(f"runtime dir {path} is a symlink -- refusing")
            if path.exists() and path.stat().st_uid != os.getuid():
                raise RuntimeError(
                    f"runtime dir {path} is owned by uid {path.stat().st_uid}, "
                    f"not {os.getuid()} -- refusing"
                )

    path.mkdir(mode=_DIR_MODE, exist_ok=True)
    # Defence in depth: enforce 0700 even if mkdir's mode was masked by umask
    try:
        os.chmod(path, _DIR_MODE)
    except OSError:
        log.debug("chmod 0700 on %s failed (umask?)", path)
    return path


def crypto_ops_socket_path(container_id: str | None = None) -> Path:
    """Master process's crypto-ops RPC socket. Followers connect here to
    delegate HMAC/AES-GCM ops without holding the sub-keys themselves."""
    if container_id is None:
        container_id = get_hostname()
    return runtime_dir() / f"crypto-ops-{container_id}.sock"


def keys_distribution_socket_path(container_id: str | None = None) -> Path:
    """Master's Shamir keys-distribution socket. Each follower fetches
    its share here at boot."""
    if container_id is None:
        container_id = get_hostname()
    return runtime_dir() / f"keys-{container_id}.sock"


def custodian_http_socket_path(
    slot: int,
    container_id: str | None = None,
) -> Path:
    """One HTTP socket per Python custodian, so it can be ADDRESSED.

    The pool historically shared a single listener, which is why the control
    plane reaches the elected custodian by rejection sampling: a shared socket
    cannot name a process, so the caller re-dials until the kernel happens to
    hand it the master. Measured cost of that on a three-custodian pool, same
    workload: 4, 5, 7 and 41 retries across four runs, each retry re-sending
    the whole request body -- which on unseal and rotate-password is the
    master password.

    A socket per slot makes the master directly addressable, which is the
    point of separated custody: the key holder must not be the thing every
    request queues behind.
    """
    if container_id is None:
        container_id = get_hostname()
    return runtime_dir() / f"custodian-{container_id}-{slot}.sock"


def follower_share_back_socket_path(
    pid: int | None = None,
    container_id: str | None = None,
) -> Path:
    """Per-follower share-back socket exposing this worker's Shamir share
    to a future new master at failover. Unique per pid."""
    if container_id is None:
        container_id = get_hostname()
    if pid is None:
        pid = os.getpid()
    return runtime_dir() / f"share-{container_id}-{pid}.sock"


def is_alive_socket(path: Path) -> bool:
    """Return True if `path` is a live socket actively bound by a process.

    Uses a connect-probe: if a peer accepts our connection, a live listener
    is bound and we return True. A ConnectionRefusedError or
    FileNotFoundError means no process is listening -- treat the inode as an
    orphan and return False.
    """
    if not path.exists():
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(_STALE_PROBE_TIMEOUT)
            probe.connect(str(path))
            # Connect succeeded, a listener is bound and accepting.
            return True
    except (ConnectionRefusedError, FileNotFoundError):
        # File exists but no listener (process died), orphan.
        return False
    except (OSError, socket.timeout):
        # Could be ENOTSOCK (file isn't a socket, definitely stale)
        # or timeout (peer is busy but alive, treat as alive, fail-closed).
        # We choose fail-closed on timeout to avoid clobbering a slow peer.
        try:
            st = path.stat()
            import stat as _stat

            if not _stat.S_ISSOCK(st.st_mode):
                return False  # not a socket file - orphan
        except OSError:
            return False
        return True


def sweep_orphan_share_sockets(container_id: str | None = None) -> int:
    """Unlink this host's share-back sockets whose listener is gone.

    The share-back path embeds the pid, so a replacement worker never reuses
    the name and acquire_socket_path -- which only probes its OWN path --
    never sees the old one. cleanup_socket runs at orderly shutdown, so every
    SIGKILL, OOM kill, container stop, and crash leaks exactly one inode, and
    systemd RuntimeDirectoryPreserve keeps them across restarts.

    Measured on the HA lab after ~1 month: 561, 632, and 616 orphans on the
    three nodes -- 1809 in total, every one owned by a dead pid. That is an
    availability bug, not a disclosure one (the inodes are 0700 and peer-UID
    checked): the runtime directory is a small tmpfs, so unbounded growth
    trends toward inode exhaustion, and past that point NO worker can bind its
    share socket at all.

    Only this host's prefix is swept, and liveness is decided by the same
    fail-closed connect-probe acquire_socket_path uses -- never a bare
    kill(0), which would unlink a live peer's socket whenever a pid was
    recycled. Returns the number removed.
    """
    if container_id is None:
        container_id = get_hostname()
    own = follower_share_back_socket_path(container_id=container_id)
    removed = 0
    try:
        candidates = sorted(runtime_dir().glob(f"share-{container_id}-*.sock"))
    except OSError as error:
        log.warning("sweep_orphan_share_sockets: cannot list runtime dir: %s", error)
        return 0
    for candidate in candidates:
        # Never touch the socket this process is about to bind, even though a
        # not-yet-bound path would probe as dead.
        if candidate == own or is_alive_socket(candidate):
            continue
        try:
            candidate.unlink()
        except FileNotFoundError:
            continue
        except OSError as error:
            log.debug("sweep_orphan_share_sockets: %s: %s", candidate, error)
            continue
        removed += 1
    if removed:
        log.info("sweep_orphan_share_sockets: removed %d orphaned sockets", removed)
    return removed


def acquire_socket_path(path: Path) -> Path:
    """Prepare `path` for bind(): clean an orphan if present, refuse if alive.

    Caller is expected to bind() the socket immediately after this returns.
    There is a tiny race window between our orphan-check unlink and the
    bind: if a peer slips in, bind fails with EADDRINUSE - caller should
    log and exit (a second master is a misconfiguration, not a recoverable
    state).

    Raises:
        RuntimeError: if the path is bound by an alive process.
    """
    path.parent.mkdir(mode=_DIR_MODE, exist_ok=True)
    pre_exists = path.exists()
    log.info(
        "acquire_socket_path: path=%s pre_exists=%s uid=%d pid=%d",
        path,
        pre_exists,
        os.getuid(),
        os.getpid(),
    )
    if is_alive_socket(path):
        log.warning(
            "acquire_socket_path: alive listener on %s -- refusing bind",
            path,
        )
        raise RuntimeError(
            f"socket {path} is already bound by an alive process - "
            "refusing to start a second instance"
        )
    if pre_exists:
        try:
            path.unlink()
            log.info("acquire_socket_path: removed stale socket %s", path)
        except OSError as e:
            raise RuntimeError(f"cannot remove stale socket {path}: {e}") from e
    else:
        log.debug("acquire_socket_path: path free, ready to bind")
    return path


def post_bind_chmod(path: Path) -> None:
    """Tighten the just-bound socket to 0700.

    bind() honours the process umask. Even if umask is 0077 (recommended),
    we re-chmod defensively to make the contract explicit and resilient
    to future umask changes upstream.
    """
    try:
        os.chmod(path, _SOCK_MODE)
    except OSError as e:
        log.warning("chmod 0700 on socket %s failed: %s", path, e)


def cleanup_socket(path: Path) -> None:
    """Best-effort unlink at shutdown / seal. Idempotent."""
    try:
        path.unlink()
        log.debug("cleanup_socket: removed %s", path)
    except FileNotFoundError:
        pass
    except OSError as e:
        log.debug("cleanup_socket: %s removal failed: %s", path, e)


def _acquire_paths_for_launcher(raw_paths: list[str]) -> int:
    """Apply acquire_socket_path to each path, for a shell supervisor.

    The custodian supervisor is /bin/sh and cannot run a connect-probe, so it
    used to treat "the socket file exists" as "a daemon owns it" and abort.
    That is wrong for the case that actually happens: the EXIT trap unlinks
    sockets only after waiting on every child, so a stop-timeout SIGKILL
    strands them, and the next start then refused a socket nobody was bound
    to -- wedging the pool below threshold and sealing the node for good.

    Deciding it here keeps ONE definition of liveness (the fail-closed
    connect-probe) instead of a second, cruder one in shell.

    Exit codes are the contract with the shell:
        0  every path is free (orphans unlinked, absent paths untouched)
        1  a path is bound by a LIVE process -- a second pool is running,
           which is a misconfiguration the supervisor must not paper over
        2  undetermined -- treated as refuse, so a probe that cannot answer
           never licenses an unlink
    """
    for raw in raw_paths:
        try:
            acquire_socket_path(Path(raw))
        except RuntimeError as error:
            print(f"[rhorizon] {error}", file=sys.stderr)
            return 1
        except OSError as error:
            print(
                f"[rhorizon] cannot check custodian socket {raw}: {error}",
                file=sys.stderr,
            )
            return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - launcher entry point
    sys.exit(_acquire_paths_for_launcher(sys.argv[1:]))
