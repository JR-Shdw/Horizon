# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Atomic server cert persistence + nginx reload.

The cluster-CA-signed nginx server cert is dropped on disk by the
auto-JOIN flow and by the renewal loop. nginx must be told to re-read
the cert ; the canonical mechanism on Linux is ``systemctl reload
nginx`` (graceful, zero-downtime) or ``nginx -s reload`` (direct binary).

The API does not run as root. The deployer wires a sudoers NOPASSWD
entry for the rhorizon uid against the chosen reload command and sets
``RHORIZON_CLUSTER_NGINX_RELOAD_CMD`` in the API environment. An empty
value disables the reload step -- useful when the deployer signals
nginx out-of-band (file watcher, systemd path unit, separate sidecar).

The on-disk mode is 0640 for the cert (nginx group-readable) and 0600
for the key (only the owner). The owner is whatever uid the API
process runs as ; nginx's worker uid must be in the cert file's group
(deployer-side concern -- typically ``adm`` or a dedicated ``ssl-cert``
group).
"""

import logging
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger("rhorizon.nginx_reload")


def _atomic_write_mode(path: Path, data: bytes, mode: int) -> None:
    """mkstemp + fsync + atomic rename, with explicit final mode.

    Unique temp (not fixed-name) so concurrent writers / a crashed write
    never collide or wedge: last rename wins. Parent dir 0750 (nginx
    group traverses; cert is group-read, not 0400).
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        os.write(fd, data)
        os.fchmod(fd, mode)  # mkstemp creates 0600
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def save_server_cert(
    cert_pem: bytes,
    key_pem: bytes,
    cert_path: str,
    key_path: str,
) -> None:
    """Persist the nginx server cert + key atomically.

    Cert : mode 0640 (group-readable so nginx workers can read).
    Key  : mode 0600 (owner-only).

    Both written via tmp + fsync + rename. The two renames are not
    transactional together ; if the process dies between them, the cert
    lands but the key does not -- nginx reload will fail at next call
    and the deployer surfaces the mismatch via systemd status. The
    window is microseconds.
    """
    if not cert_pem or not key_pem:
        raise ValueError("cert_pem and key_pem must both be non-empty")
    _atomic_write_mode(Path(cert_path), cert_pem, 0o640)
    _atomic_write_mode(Path(key_path), key_pem, 0o600)
    log.info(
        "nginx_reload: persisted server cert (%d bytes) + key (%d bytes) to %s / %s",
        len(cert_pem),
        len(key_pem),
        cert_path,
        key_path,
    )


def reload_nginx(reload_cmd: str) -> bool:
    """Run the configured reload command. Returns True on exit code 0.

    ``reload_cmd`` is parsed via :func:`shlex.split` so a value like
    ``sudo /bin/systemctl reload nginx`` is interpreted as a 3-arg
    exec without shell injection surface. Empty string is a no-op
    (returns True -- deployer signals nginx elsewhere).

    Failure is logged at warning level ; the caller logs an outcome
    counter but does NOT raise -- a failed reload leaves nginx running
    on the previous cert, which is a degraded state but not a service
    outage. The operator surfaces the failure via journalctl and
    re-runs the reload by hand.
    """
    if not reload_cmd:
        log.debug("nginx_reload: reload_cmd empty, skipping")
        return True
    argv = shlex.split(reload_cmd)
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("nginx_reload: %s failed (%s)", reload_cmd, exc)
        return False
    if result.returncode != 0:
        log.warning(
            "nginx_reload: %s exited %d ; stderr=%s",
            reload_cmd,
            result.returncode,
            result.stderr.strip(),
        )
        return False
    log.info("nginx_reload: %s OK", reload_cmd)
    return True
