# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""On-disk persistence of the per-node cluster cert.

Each rhorizon container that is a cluster member persists its identity
cert + private key on a docker volume :

- ``/var/lib/rhorizon/cluster-cert.pem`` -- X.509 cert signed by the
  cluster CA (CN = ``node_uuid``, SAN = source IP, validity 90 days
  default). Public material, but kept under mode 0400 alongside the
  private key so the two move together.
- ``/var/lib/rhorizon/cluster-cert.key`` -- PEM-encoded PKCS8 private
  key, mode 0400 owned by uid 1500.

Both files are written atomically (mkstemp + fsync + rename, mode
0400). Destroying the volume forces a fresh JOIN (the cluster's
(uuid, ip) binding check at /cluster/join surfaces the duplication).

Functions :
- :func:`save_cluster_cert` -- atomic write at /cluster/init (primary
  self-cert) and after a successful auto-JOIN (joiner cert).
- :func:`load_cluster_cert` -- read at boot to fuel the mTLS REJOIN
  flow ; returns ``None`` if no cert on disk yet.
- :func:`has_cluster_cert` -- predicate used by the lifespan auto-JOIN
  task to decide whether to attempt a fresh JOIN.
- :func:`validate_perms` -- assert mode 0400 on existing files
  (ha_boot_check.py wires this at boot when ``cluster_ha_enabled`` is on).

The cert NotAfter is the source of truth for the renewal
loop -- :func:`cert_not_after` parses the on-disk PEM and returns the
expiry as a tz-aware datetime.
"""

import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path

from cryptography import x509

log = logging.getLogger("rhorizon.cluster_cert")


class ClusterCertError(RuntimeError):
    """Base error for cluster cert persistence failures."""


class ClusterCertPermError(ClusterCertError):
    """Raised when the on-disk cert files have wrong permissions or ownership."""


def _atomic_write(path: Path, data: bytes) -> None:
    """mkstemp + fsync + atomic rename, mode 0400.

    Unique temp (not fixed-name) so a crashed write / concurrent writer
    never collides or wedges: last rename wins. Parent dir 0700.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        os.write(fd, data)
        os.fchmod(fd, 0o400)  # mkstemp creates 0600
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def save_cluster_cert(
    cert_pem: bytes, key_pem: bytes, cert_path: str, key_path: str
) -> None:
    """Persist cert + key atomically. Overwrites any prior pair in place.

    Each file is written via mkstemp + fsync + rename. The two renames
    are not transactional together: a crash between them leaves the new
    cert with no key (first write) or with the stale key (overwrite) --
    either way a broken pair that fails mTLS, so REJOIN falls back to a
    fresh JOIN. The window is microseconds and the failure mode is
    conservative (a broken pair is rejected, never trusted).
    """
    cp = Path(cert_path)
    kp = Path(key_path)
    if not cert_pem or not key_pem:
        raise ClusterCertError("cert_pem and key_pem must both be non-empty")
    _atomic_write(cp, cert_pem)
    _atomic_write(kp, key_pem)
    log.info(
        "cluster_cert: persisted cert (%d bytes) + key (%d bytes) to %s / %s",
        len(cert_pem),
        len(key_pem),
        cp,
        kp,
    )


def has_cluster_cert(cert_path: str, key_path: str) -> bool:
    """True if BOTH files exist as regular files on disk."""
    cp = Path(cert_path)
    kp = Path(key_path)
    return cp.is_file() and kp.is_file()


def load_cluster_cert(cert_path: str, key_path: str) -> tuple[bytes, bytes] | None:
    """Read cert + key from disk. Returns ``None`` if either file is absent.

    A half-pair (only cert OR only key) is treated as ``None`` -- the
    cert + key must travel together for the membership identity to be
    usable. The half-pair case is logged at warning level so the
    operator can investigate the volume state.
    """
    cp = Path(cert_path)
    kp = Path(key_path)
    if not cp.is_file() and not kp.is_file():
        return None
    if not cp.is_file() or not kp.is_file():
        log.warning(
            "cluster_cert: half-pair on disk (cert=%s key=%s) -- treating as missing",
            cp.is_file(),
            kp.is_file(),
        )
        return None
    cert_pem = cp.read_bytes()
    key_pem = kp.read_bytes()
    return cert_pem, key_pem


def validate_perms(cert_path: str, key_path: str) -> None:
    """Assert both files are mode 0400. Raises :class:`ClusterCertPermError`.

    Boot-time invariant -- ha_boot_check.py wires this when
    ``cluster_ha_enabled`` is true. A loose mode (group/world readable)
    on the private key file is a security-relevant misconfiguration
    that must be surfaced rather than silently tolerated.
    """
    for path_str in (cert_path, key_path):
        p = Path(path_str)
        if not p.is_file():
            continue  # absent file is fine ; auto-JOIN will create it
        st = p.stat()
        mode = st.st_mode & 0o777
        if mode != 0o400:
            raise ClusterCertPermError(f"{p} has mode {oct(mode)} (expected 0o400)")


def cert_not_after(cert_pem: bytes) -> datetime:
    """Parse the cert PEM and return its NotAfter as a tz-aware datetime.

    The renewal loop polls this against
    ``cluster_cert_renewal_threshold_days`` to decide when to call
    /cluster/refresh-cert.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.not_valid_after_utc


def cert_is_self_signed(cert_pem: bytes) -> bool:
    """True when issuer == subject, i.e. the cert vouches only for itself.

    This distinguishes the boot-time placeholder cert (minted by the
    nginx-frontend role so the vhost can serve HTTPS before a cluster
    exists) from one signed by the cluster CA. Expiry alone cannot tell
    them apart: the placeholder is deliberately long-lived (10 years),
    so an expiry-only renewal check never fires on it and the node keeps
    a cert that chains to nothing, silently defeating cluster mTLS.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.issuer == cert.subject


def remove_cluster_cert(cert_path: str, key_path: str) -> None:
    """Delete both files. Used by /cluster/evict-self or operator wipe.

    Idempotent -- missing files do not raise.
    """
    for path_str in (cert_path, key_path):
        p = Path(path_str)
        try:
            p.unlink()
            log.info("cluster_cert: removed %s", p)
        except FileNotFoundError:
            pass
