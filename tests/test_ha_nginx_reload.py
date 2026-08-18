# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""nginx_reload helpers.

Covers :
- save_server_cert : mkstemp+rename, cert mode 0640, key mode 0600, parent
  dir 0750, parent dir auto-created.
- save_server_cert rejects empty cert or key.
- atomic write does not wedge on a stale temp and survives concurrent writers.
- reload_nginx : empty command is a no-op returning True ; non-zero
  exit returns False ; missing binary returns False ; success returns
  True.
"""

import pytest
from api.app import nginx_reload


def test_save_server_cert_writes_with_expected_modes(tmp_path):
    cert_path = tmp_path / "subdir" / "server.crt"
    key_path = tmp_path / "subdir" / "server.key"
    nginx_reload.save_server_cert(
        b"-----BEGIN CERT-----\nfake\n-----END CERT-----\n",
        b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        str(cert_path),
        str(key_path),
    )
    assert cert_path.is_file()
    assert key_path.is_file()
    assert (cert_path.stat().st_mode & 0o777) == 0o640
    assert (key_path.stat().st_mode & 0o777) == 0o600
    # Parent dir created with 0o750 (umask-permitting).
    parent_mode = cert_path.parent.stat().st_mode & 0o777
    assert parent_mode == 0o750


def test_save_server_cert_overwrites_existing(tmp_path):
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    nginx_reload.save_server_cert(b"v1-cert", b"v1-key", str(cert_path), str(key_path))
    nginx_reload.save_server_cert(b"v2-cert", b"v2-key", str(cert_path), str(key_path))
    assert cert_path.read_bytes() == b"v2-cert"
    assert key_path.read_bytes() == b"v2-key"


def test_save_server_cert_leaves_no_temp(tmp_path):
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    nginx_reload.save_server_cert(b"cert", b"key", str(cert_path), str(key_path))
    assert not list(tmp_path.glob(".server.*.tmp"))


def test_save_server_cert_survives_stale_temp(tmp_path):
    """A leftover temp from a crashed write must not wedge future writes
    (the old fixed-name O_EXCL tmp raised FileExistsError forever)."""
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    (tmp_path / ".server.crt.deadbeef.tmp").write_text("stale", encoding="ascii")
    nginx_reload.save_server_cert(b"fresh", b"key", str(cert_path), str(key_path))
    assert cert_path.read_bytes() == b"fresh"


def test_save_server_cert_concurrent_writers(tmp_path):
    """N threads writing the same paths converge on one valid pair with
    no leftover temps -- mkstemp gives each its own temp, last rename wins."""
    import threading

    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def writer(n: int):
        try:
            barrier.wait()
            nginx_reload.save_server_cert(
                f"cert-{n}".encode(), f"key-{n}".encode(), str(cert_path), str(key_path)
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"writers crashed: {errors}"
    assert cert_path.read_bytes().startswith(b"cert-")
    assert (cert_path.stat().st_mode & 0o777) == 0o640
    assert not list(tmp_path.glob(".server.*.tmp"))


def test_save_server_cert_rejects_empty():
    with pytest.raises(ValueError):
        nginx_reload.save_server_cert(b"", b"key", "/tmp/a", "/tmp/b")
    with pytest.raises(ValueError):
        nginx_reload.save_server_cert(b"cert", b"", "/tmp/a", "/tmp/b")


def test_reload_nginx_empty_cmd_is_noop():
    assert nginx_reload.reload_nginx("") is True


def test_reload_nginx_success(tmp_path):
    flag = tmp_path / "ran"
    cmd = f"/bin/sh -c 'touch {flag}'"
    assert nginx_reload.reload_nginx(cmd) is True
    assert flag.is_file()


def test_reload_nginx_nonzero_exit_returns_false():
    # /bin/false always exits 1.
    assert nginx_reload.reload_nginx("/bin/false") is False


def test_reload_nginx_missing_binary_returns_false():
    assert nginx_reload.reload_nginx("/nonexistent/binary --arg") is False
