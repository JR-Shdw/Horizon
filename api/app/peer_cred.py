# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Portable peer credentials shim for AF_UNIX sockets.

Returns the connected peer's UID across Linux, macOS and BSD families.
The UID is the only field rhorizon uses to authenticate IPC peers
(SO_PEERCRED check in cluster_rpc.py and key_share Rust); PID + GID are
not used in any security decision, just logged in debug.

Status per OS :
  - Linux        : validated (production target)
  - macOS        : implemented from `xucred` docs, NOT exercised on a real Mac
  - FreeBSD      : implemented via getpeereid(3) ctypes, NOT exercised
  - OpenBSD      : same as FreeBSD, NOT exercised
  - DragonFly BSD: same as FreeBSD, NOT exercised

Cluster IPC uses filesystem-path Unix sockets on every supported host.
Only peer-credential retrieval varies by platform in this module.

Caller is expected to fall closed: any return of None must be treated
as "untrusted peer" and the connection rejected.
"""

import ctypes
import ctypes.util
import logging
import platform
import socket
import struct

log = logging.getLogger("rhorizon.peer_cred")

_SYS = platform.system()

# Linux SO_PEERCRED: socket.h struct ucred = (pid_t, uid_t, gid_t).
# Prefer the values Python resolved for this arch (SO_PEERCRED is not 17
# everywhere -- mips/ppc/sparc differ); fall back to the generic-arch
# literals when the symbol is absent (non-Linux import).
_LINUX_SOL_SOCKET = getattr(socket, "SOL_SOCKET", 1)
_LINUX_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
_LINUX_UCRED_SIZE = struct.calcsize("iII")  # i32 + u32 + u32 = 12 bytes

# macOS SOL_LOCAL / LOCAL_PEERCRED: returns struct xucred. We only need
# the first 8 bytes (cr_version u32 + cr_uid u32) and ignore the rest
# (cr_ngroups + cr_groups[NGROUPS=16]). The full struct size is 76 bytes
# on modern macOS; we request that much but parse only the prefix.
_MACOS_SOL_LOCAL = 0
_MACOS_LOCAL_PEERCRED = 1
_MACOS_XUCRED_SIZE = 76
_MACOS_XUCRED_PREFIX = struct.calcsize("II")  # version + uid

# BSD getpeereid(3): int getpeereid(int s, uid_t *euid, gid_t *egid)
_BSD_FAMILIES = ("FreeBSD", "OpenBSD", "DragonFly", "NetBSD")
_libc = None
_getpeereid = None


def _load_libc_getpeereid():  # pragma: no cover  (BSD-only)
    """Lazily resolve libc.getpeereid on BSD. Returns the bound symbol or None."""
    global _libc, _getpeereid
    if _getpeereid is not None:
        return _getpeereid
    libname = ctypes.util.find_library("c")
    if not libname:
        return None
    try:
        _libc = ctypes.CDLL(libname, use_errno=True)
    except OSError:
        return None
    if not hasattr(_libc, "getpeereid"):
        return None
    fn = _libc.getpeereid
    fn.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    fn.restype = ctypes.c_int
    _getpeereid = fn
    return fn


def read_peer_uid(sock: socket.socket) -> int | None:
    """Return the UID of the connected peer on AF_UNIX socket `sock`.

    Returns None if:
      - the OS is not supported,
      - the syscall fails (errno set, sock is not AF_UNIX, peer disconnected),
      - the BSD getpeereid symbol cannot be resolved.

    Callers MUST treat None as "untrusted peer" (fail-closed).
    """
    try:
        if _SYS == "Linux":
            data = sock.getsockopt(
                _LINUX_SOL_SOCKET, _LINUX_SO_PEERCRED, _LINUX_UCRED_SIZE
            )
            _pid, uid, _gid = struct.unpack("iII", data)
            return int(uid)
        if _SYS == "Darwin":
            data = sock.getsockopt(
                _MACOS_SOL_LOCAL, _MACOS_LOCAL_PEERCRED, _MACOS_XUCRED_SIZE
            )
            if len(data) < _MACOS_XUCRED_PREFIX:
                return None
            _version, uid = struct.unpack("II", data[:_MACOS_XUCRED_PREFIX])
            return int(uid)
        if _SYS in _BSD_FAMILIES:
            fn = _load_libc_getpeereid()
            if fn is None:
                log.warning("getpeereid not available on %s libc", _SYS)
                return None
            uid = ctypes.c_uint32(0)
            gid = ctypes.c_uint32(0)
            ret = fn(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid))
            if ret != 0:
                return None
            return int(uid.value)
        log.warning("read_peer_uid: unsupported OS %s", _SYS)
        return None
    except OSError as e:
        log.debug("read_peer_uid OSError on %s: %s", _SYS, e)
        return None


def read_peer_cred(sock: socket.socket) -> tuple[int, int, int] | None:
    """Backward-compat wrapper for the (pid, uid, gid) tuple shape.

    On Linux: returns (pid, uid, gid) from SO_PEERCRED.
    On macOS / BSD: pid and gid are 0 placeholders since the underlying
    APIs don't expose them. Callers that read only the UID (cluster_rpc.py)
    are unaffected; callers that read the PID get 0 and should not rely on
    it for security decisions (which rhorizon doesn't).
    """
    try:
        if _SYS == "Linux":
            data = sock.getsockopt(
                _LINUX_SOL_SOCKET, _LINUX_SO_PEERCRED, _LINUX_UCRED_SIZE
            )
            return struct.unpack("iII", data)
    except OSError as e:
        log.debug("read_peer_cred (Linux) failed: %s", e)
        return None
    uid = read_peer_uid(sock)
    if uid is None:
        return None
    return (0, uid, 0)
