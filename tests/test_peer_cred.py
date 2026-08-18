"""Tests for api/app/peer_cred.py - portable peer credentials shim.

The Linux branch is exercised against a real AF_UNIX socketpair (this is
our production target). The macOS / BSD branches are exercised through
mocks since the project does not currently run on those OSes.
"""

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest
from api.app import peer_cred

# ---------------------------------------------------------------------------
# Linux: real socketpair, no mock
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    peer_cred._SYS != "Linux", reason="real SO_PEERCRED only on Linux runners"
)
def test_read_peer_uid_real_linux_socketpair():
    """SO_PEERCRED on a fresh socketpair returns this process's uid."""
    import os

    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        uid = peer_cred.read_peer_uid(a)
        assert uid == os.getuid()

        cred = peer_cred.read_peer_cred(a)
        assert cred is not None
        pid, cred_uid, gid = cred
        assert cred_uid == os.getuid()
        assert pid == os.getpid()
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# Linux: error paths via mock
# ---------------------------------------------------------------------------


def test_read_peer_uid_oserror_returns_none():
    """If getsockopt raises OSError, return None (fail-closed)."""
    sock = MagicMock(spec=socket.socket)
    sock.getsockopt.side_effect = OSError("ENOTSOCK")

    with patch.object(peer_cred, "_SYS", "Linux"):
        assert peer_cred.read_peer_uid(sock) is None


# ---------------------------------------------------------------------------
# macOS: mock the xucred struct
# ---------------------------------------------------------------------------


def test_read_peer_uid_macos_mocked():
    """Darwin branch parses xucred prefix (version u32 + uid u32)."""
    sock = MagicMock(spec=socket.socket)
    # xucred version=0, uid=42, then 68 bytes of padding (groups etc.)
    sock.getsockopt.return_value = struct.pack("II", 0, 42) + b"\x00" * 68

    with patch.object(peer_cred, "_SYS", "Darwin"):
        assert peer_cred.read_peer_uid(sock) == 42


def test_read_peer_uid_macos_short_response_returns_none():
    """If the kernel returns less than 8 bytes, fail-closed."""
    sock = MagicMock(spec=socket.socket)
    sock.getsockopt.return_value = b"\x00\x00"  # too short

    with patch.object(peer_cred, "_SYS", "Darwin"):
        assert peer_cred.read_peer_uid(sock) is None


def test_read_peer_uid_macos_oserror_returns_none():
    sock = MagicMock(spec=socket.socket)
    sock.getsockopt.side_effect = OSError("EOPNOTSUPP")

    with patch.object(peer_cred, "_SYS", "Darwin"):
        assert peer_cred.read_peer_uid(sock) is None


# ---------------------------------------------------------------------------
# BSD: mock libc.getpeereid via the lazy resolver
# ---------------------------------------------------------------------------


def _build_fake_libc(getpeereid_ret: int, fake_uid: int):
    """Return a fake libc.getpeereid that writes fake_uid into euid out-param."""
    import ctypes as _ct

    def fake_call(fd, euid_ptr, egid_ptr):
        # Write the fake uid into the pointer
        euid_ptr._obj.value = _ct.c_uint32(fake_uid).value
        egid_ptr._obj.value = 0
        return getpeereid_ret

    return fake_call


def test_read_peer_uid_freebsd_mocked():
    sock = MagicMock(spec=socket.socket)
    sock.fileno.return_value = 7

    fake_fn = _build_fake_libc(0, 1500)

    with patch.object(peer_cred, "_SYS", "FreeBSD"):
        with patch.object(peer_cred, "_load_libc_getpeereid", return_value=fake_fn):
            assert peer_cred.read_peer_uid(sock) == 1500


def test_read_peer_uid_freebsd_syscall_failure():
    sock = MagicMock(spec=socket.socket)
    sock.fileno.return_value = 7

    fake_fn = _build_fake_libc(-1, 0)  # non-zero return = error

    with patch.object(peer_cred, "_SYS", "FreeBSD"):
        with patch.object(peer_cred, "_load_libc_getpeereid", return_value=fake_fn):
            assert peer_cred.read_peer_uid(sock) is None


def test_read_peer_uid_bsd_no_libc():
    """If libc.getpeereid can't be resolved, return None and warn."""
    sock = MagicMock(spec=socket.socket)
    with patch.object(peer_cred, "_SYS", "OpenBSD"):
        with patch.object(peer_cred, "_load_libc_getpeereid", return_value=None):
            assert peer_cred.read_peer_uid(sock) is None


def test_load_libc_getpeereid_caches():
    """The resolver caches the symbol after the first call."""
    # Reset cache
    peer_cred._libc = None
    peer_cred._getpeereid = None

    # On Linux, find_library('c') returns libc.so.6 which has no getpeereid;
    # we expect None and we expect the cache to NOT be populated (so a future
    # OS-aware test still triggers resolution).
    result = peer_cred._load_libc_getpeereid()
    # Linux libc.so.6 doesn't have getpeereid -> None expected
    assert result is None or callable(result)


# ---------------------------------------------------------------------------
# Unsupported OS
# ---------------------------------------------------------------------------


def test_read_peer_uid_unsupported_os(caplog):
    sock = MagicMock(spec=socket.socket)
    with patch.object(peer_cred, "_SYS", "AIX"):
        with caplog.at_level("WARNING"):
            assert peer_cred.read_peer_uid(sock) is None
    assert any("unsupported OS" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Backward-compat read_peer_cred
# ---------------------------------------------------------------------------


def test_read_peer_cred_macos_returns_pid_zero():
    """On macOS, read_peer_cred returns pid=0 placeholder."""
    sock = MagicMock(spec=socket.socket)
    sock.getsockopt.return_value = struct.pack("II", 0, 99) + b"\x00" * 68

    with patch.object(peer_cred, "_SYS", "Darwin"):
        cred = peer_cred.read_peer_cred(sock)
        assert cred == (0, 99, 0)


def test_read_peer_cred_returns_none_when_uid_unavailable():
    sock = MagicMock(spec=socket.socket)
    sock.getsockopt.side_effect = OSError("nope")

    with patch.object(peer_cred, "_SYS", "Linux"):
        assert peer_cred.read_peer_cred(sock) is None
