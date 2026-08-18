# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Coverage targete sur api/app/socket_paths.py (60 % -> 95 %+).

Cible les paths actuellement non couverts apres le bump 2026-05-03 :
  - runtime_dir() XDG_RUNTIME_DIR branch (L66)
  - runtime_dir() /tmp fallback (L70)
  - runtime_dir() chmod failure (L76-77)
  - follower_share_back_socket_path default pid (L106)
  - is_alive_socket() : live / refused / timeout-keeps / stat fails (L120-141)
  - acquire_socket_path() : alive raises RuntimeError (L158), unlink raises (L163-167)
  - post_bind_chmod() : chmod failure log (L180-181)
  - cleanup_socket() : FileNotFoundError + OSError branches (L189-192)
"""

import os
import socket
import stat
from pathlib import Path
from unittest.mock import patch

import pytest
from api.app import socket_paths

# --- runtime_dir() -----------------------------------------------------------


def test_runtime_dir_explicit_env_override(tmp_path, monkeypatch):
    target = tmp_path / "explicit"
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(target))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    out = socket_paths.runtime_dir()
    assert out == target
    assert target.exists()
    assert oct(target.stat().st_mode & 0o777) == "0o700"


def test_runtime_dir_canonical_env_wins_over_legacy(tmp_path, monkeypatch):
    canonical = tmp_path / "canonical"
    legacy = tmp_path / "legacy"
    monkeypatch.setenv("RH_RUNTIME_DIR", str(canonical))
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(legacy))

    assert socket_paths.runtime_dir() == canonical


def test_runtime_dir_xdg_branch(tmp_path, monkeypatch):
    xdg_root = tmp_path / "xdg"
    xdg_root.mkdir()
    monkeypatch.delenv("RHORIZON_RUNTIME_DIR", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg_root))
    out = socket_paths.runtime_dir()
    assert out == xdg_root / "rhorizon"
    assert (xdg_root / "rhorizon").exists()


def test_runtime_dir_tmp_fallback(tmp_path, monkeypatch):
    # Force both overrides off + /run not writable from test perspective.
    monkeypatch.delenv("RHORIZON_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    # Make /run appear unwritable so the fallback to tmp triggers.
    with patch("api.app.socket_paths.os.access", return_value=False):
        with patch(
            "api.app.socket_paths.tempfile.gettempdir",
            return_value=str(tmp_path),
        ):
            out = socket_paths.runtime_dir()
            assert out == tmp_path / f"rhorizon-{os.getuid()}"
            assert out.exists()


def test_runtime_dir_tmp_fallback_rejects_foreign_owner(tmp_path, monkeypatch):
    """A pre-planted /tmp/rhorizon-{uid} owned by someone else must be
    refused, not adopted (predictable-path hijack on the world-writable
    /tmp fallback)."""
    monkeypatch.delenv("RHORIZON_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    other = os.getuid() + 1
    # Pre-create the path the code will resolve to (owned by us, the real
    # uid), then make the code believe it runs as `other` -- so the owner
    # check sees a mismatch.
    (tmp_path / f"rhorizon-{other}").mkdir()
    with patch("api.app.socket_paths.os.access", return_value=False):
        with patch(
            "api.app.socket_paths.tempfile.gettempdir", return_value=str(tmp_path)
        ):
            with patch("api.app.socket_paths.os.getuid", return_value=other):
                with pytest.raises(RuntimeError, match="owned by uid"):
                    socket_paths.runtime_dir()


def test_runtime_dir_tmp_fallback_rejects_symlink(tmp_path, monkeypatch):
    """A symlink at the predictable /tmp path must be refused."""
    monkeypatch.delenv("RHORIZON_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / f"rhorizon-{os.getuid()}").symlink_to(target)
    with patch("api.app.socket_paths.os.access", return_value=False):
        with patch(
            "api.app.socket_paths.tempfile.gettempdir", return_value=str(tmp_path)
        ):
            with pytest.raises(RuntimeError, match="symlink"):
                socket_paths.runtime_dir()


def test_runtime_dir_chmod_failure_logged(tmp_path, monkeypatch):
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path / "chmod-fail"))
    with patch("api.app.socket_paths.os.chmod", side_effect=OSError("denied")):
        # Must NOT raise, the chmod failure is logged + swallowed.
        out = socket_paths.runtime_dir()
        assert out.exists()


def test_runtime_dir_picks_run_rhorizon_when_parent_not_writable(monkeypatch):
    """F4 regression : systemd RuntimeDirectory=rhorizon pre-creates
    /run/rhorizon owned by the service uid. uid 1500 can write that
    target but cannot write the /run parent. The old check probed
    only /run and fell through to /tmp/rhorizon-{uid}, hiding sockets
    behind PrivateTmp= and breaking discoverability.
    """
    monkeypatch.delenv("RHORIZON_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)

    real_exists = Path.exists

    def fake_exists(self):
        if str(self) in ("/run", "/run/rhorizon"):
            return True
        return real_exists(self)

    def fake_access(p, _mode):
        if str(p) == "/run/rhorizon":
            return True
        if str(p) == "/run":
            return False
        return True

    with patch.object(Path, "exists", fake_exists):
        with patch("api.app.socket_paths.os.access", side_effect=fake_access):
            with patch.object(Path, "mkdir") as mock_mkdir:
                with patch("api.app.socket_paths.os.chmod"):
                    out = socket_paths.runtime_dir()
    assert out == Path("/run/rhorizon")
    mock_mkdir.assert_called_once_with(mode=0o700, exist_ok=True)


# --- follower_share_back_socket_path -----------------------------------------


def test_follower_share_back_default_pid(monkeypatch, tmp_path):
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "host42")
    path = socket_paths.follower_share_back_socket_path()
    assert f"share-host42-{os.getpid()}.sock" in str(path)


def test_follower_share_back_explicit_pid(monkeypatch, tmp_path):
    monkeypatch.setenv("RHORIZON_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("HOSTNAME", "host7")
    path = socket_paths.follower_share_back_socket_path(pid=12345)
    assert path.name == "share-host7-12345.sock"


# --- is_alive_socket ---------------------------------------------------------


def test_is_alive_socket_missing_file(tmp_path):
    assert socket_paths.is_alive_socket(tmp_path / "nope.sock") is False


def test_is_alive_socket_live_listener(tmp_path):
    sock_path = tmp_path / "live.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(str(sock_path))
        s.listen(1)
        assert socket_paths.is_alive_socket(sock_path) is True
    finally:
        s.close()
        if sock_path.exists():
            sock_path.unlink()


def test_is_alive_socket_refused_no_listener(tmp_path):
    # Create a plain regular file at the path -> not a socket, connect refused.
    bad = tmp_path / "regular_file.sock"
    bad.write_text("not a socket")
    # connect() on a non-socket raises ConnectionRefusedError or OSError.
    assert socket_paths.is_alive_socket(bad) is False


def test_is_alive_socket_oserror_path_is_socket(tmp_path):
    """When connect raises OSError but the inode IS a socket, treat as alive."""
    sock_path = tmp_path / "stat_socket.sock"
    # Create a real socket file (bound but immediately closed without listen).
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(sock_path))
    s.close()
    # The file persists as a socket inode. connect() will get ConnectionRefusedError
    # since no listener is on it, function returns False (orphan).
    # To exercise the OSError + S_ISSOCK True branch, we mock connect.
    with patch("socket.socket") as mock_socket:
        mock_probe = mock_socket.return_value.__enter__.return_value
        mock_probe.connect.side_effect = OSError("simulated transient error")
        mock_probe.settimeout = lambda *a, **k: None
        # path.stat returns a socket-type -> fail-closed treats as alive.
        result = socket_paths.is_alive_socket(sock_path)
        assert result is True
    if sock_path.exists():
        sock_path.unlink()


def test_is_alive_socket_oserror_path_not_socket(tmp_path):
    """OSError + not-a-socket inode -> orphan (False)."""
    bad = tmp_path / "regular.sock"
    bad.write_text("nope")
    with patch("socket.socket") as mock_socket:
        mock_probe = mock_socket.return_value.__enter__.return_value
        mock_probe.connect.side_effect = OSError("ENOTSOCK simulated")
        mock_probe.settimeout = lambda *a, **k: None
        assert socket_paths.is_alive_socket(bad) is False


def test_is_alive_socket_oserror_stat_fails(tmp_path):
    """OSError on connect + stat also raises -> orphan.

    Subtlety: pathlib.Path.exists() in Python 3.12 calls self.stat()
    internally. So we use a call-counter: the FIRST stat call (from
    exists()) is let through, only the SECOND (the explicit path.stat()
    in the except branch) raises. Without this, exists() would crash
    before we reach the code we want to test.
    """
    p = tmp_path / "vanished.sock"
    p.write_text("placeholder")
    original_stat = Path.stat
    call_count = {"n": 0}

    def stat_side(self, *args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] >= 2:
            raise OSError("stat denied on retry")
        return original_stat(self, *args, **kwargs)

    with patch("socket.socket") as mock_socket:
        mock_probe = mock_socket.return_value.__enter__.return_value
        mock_probe.connect.side_effect = OSError("connect failed")
        mock_probe.settimeout = lambda *a, **k: None
        with patch.object(Path, "stat", stat_side):
            assert socket_paths.is_alive_socket(p) is False


# --- acquire_socket_path -----------------------------------------------------


def test_acquire_socket_path_refuses_when_alive(tmp_path):
    sock_path = tmp_path / "occupied.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(str(sock_path))
        s.listen(1)
        with pytest.raises(RuntimeError, match="already bound by an alive"):
            socket_paths.acquire_socket_path(sock_path)
    finally:
        s.close()
        if sock_path.exists():
            sock_path.unlink()


def test_acquire_socket_path_cleans_orphan(tmp_path):
    sock_path = tmp_path / "stale.sock"
    # Regular file simulates an orphan that exists but isn't connectable.
    sock_path.write_text("stale data")
    out = socket_paths.acquire_socket_path(sock_path)
    assert out == sock_path
    assert not sock_path.exists()  # was unlinked


def test_acquire_socket_path_unlink_fails(tmp_path):
    sock_path = tmp_path / "wont_remove.sock"
    sock_path.write_text("blocked")
    with patch.object(Path, "unlink", side_effect=OSError("EACCES")):
        with pytest.raises(RuntimeError, match="cannot remove stale socket"):
            socket_paths.acquire_socket_path(sock_path)


# --- post_bind_chmod --------------------------------------------------------


def test_post_bind_chmod_success(tmp_path):
    sock_path = tmp_path / "chmod_ok.sock"
    sock_path.write_text("x")
    socket_paths.post_bind_chmod(sock_path)
    assert stat.S_IMODE(sock_path.stat().st_mode) == 0o700


def test_post_bind_chmod_failure_logged(tmp_path):
    sock_path = tmp_path / "chmod_fail.sock"
    sock_path.write_text("x")
    with patch("api.app.socket_paths.os.chmod", side_effect=OSError("denied")):
        # Must NOT raise, log only.
        socket_paths.post_bind_chmod(sock_path)


# --- cleanup_socket ---------------------------------------------------------


def test_cleanup_socket_success(tmp_path):
    sock_path = tmp_path / "cleanme.sock"
    sock_path.write_text("x")
    socket_paths.cleanup_socket(sock_path)
    assert not sock_path.exists()


def test_cleanup_socket_already_gone(tmp_path):
    # Idempotent : path missing must not raise.
    socket_paths.cleanup_socket(tmp_path / "never_existed.sock")


def test_cleanup_socket_oserror_swallowed(tmp_path):
    sock_path = tmp_path / "stuck.sock"
    sock_path.write_text("x")
    with patch.object(Path, "unlink", side_effect=OSError("EBUSY")):
        # Must NOT raise.
        socket_paths.cleanup_socket(sock_path)


def test_sweep_removes_dead_share_sockets_but_never_a_live_one(tmp_path, monkeypatch):
    """Unbounded /run growth: 1809 orphans across 3 lab nodes in a month.

    The share-back name embeds the pid, so a replacement worker never reclaims
    it and acquire_socket_path -- which probes only its OWN path -- never sees
    it. Every SIGKILL/OOM-kill/crash leaks one inode onto a small tmpfs, and
    inode exhaustion means NO worker can bind its share socket at all.
    """
    import socket as _socket

    from api.app import socket_paths

    monkeypatch.setattr(socket_paths, "runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(socket_paths, "get_hostname", lambda: "node-a")

    # Three dead inodes: a plain file, and two real sockets with no listener.
    dead = []
    for pid in (1001, 1002):
        path = tmp_path / f"share-node-a-{pid}.sock"
        server = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        server.bind(str(path))
        server.close()  # inode survives, listener does not
        dead.append(path)
    not_a_socket = tmp_path / "share-node-a-1003.sock"
    not_a_socket.write_bytes(b"")
    dead.append(not_a_socket)

    # A LIVE listener must survive: pids are recycled, so a bare kill(0) test
    # would unlink a healthy peer's socket.
    live = tmp_path / "share-node-a-2001.sock"
    listener = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    listener.bind(str(live))
    listener.listen(1)

    # Another host's socket is not ours to reap.
    foreign = tmp_path / "share-node-b-1004.sock"
    foreign.write_bytes(b"")

    try:
        removed = socket_paths.sweep_orphan_share_sockets()
    finally:
        listener.close()

    assert removed == 3
    assert all(not path.exists() for path in dead)
    assert live.exists(), "a live listener's socket must never be swept"
    assert foreign.exists(), "another host's socket must never be swept"


def test_sweep_never_removes_the_socket_this_worker_will_bind(tmp_path, monkeypatch):
    """The caller's own path is not yet bound, so it probes as dead."""
    import os

    from api.app import socket_paths

    monkeypatch.setattr(socket_paths, "runtime_dir", lambda: tmp_path)
    monkeypatch.setattr(socket_paths, "get_hostname", lambda: "node-a")
    own = tmp_path / f"share-node-a-{os.getpid()}.sock"
    own.write_bytes(b"")

    assert socket_paths.sweep_orphan_share_sockets() == 0
    assert own.exists()
