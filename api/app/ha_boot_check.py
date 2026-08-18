# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""HA boot-time invariants -- fail-closed checks run at lifespan startup.

Two invariants, both refuse boot rather than serve a misconfigured node:

  1. ``cluster_ha_enabled=true`` AND ``tls_enabled=false`` => refuse.
     /cluster/{challenge,join} carry the JOIN proof's HMAC inputs and
     the wrapped node key; they must travel over TLS so a LAN adversary
     cannot snoop them.
  2. an on-disk cluster cert pair with mode != 0o400 => refuse.
     A group/world-readable private key is a security-relevant
     misconfiguration; absence of the pair is fine (auto-JOIN mints it).

Each check takes explicit args (not the Settings singleton) so it can be
unit-tested across every combination without spinning the app. main.py
calls them before any DB access or background loop.
"""

import logging

from . import cluster_cert

log = logging.getLogger("rhorizon.ha_boot_check")


class HaBootInvariantError(RuntimeError):
    """Raised when an HA boot-time invariant is violated.

    Lifespan catches nothing -- the exception propagates, uvicorn's
    worker exits non-zero, the orchestrator (systemd / Swarm / K8s)
    surfaces the failure in the standard way.
    """


def enforce_cluster_cert_perms_invariant(cert_path: str, key_path: str) -> None:
    """Refuse to boot if an on-disk cluster cert pair has wrong mode.

    When ``cluster-cert.{pem,key}`` are present on the volume (returning
    node or post-JOIN reboot), both files MUST be mode 0o400. A loose mode
    (key readable by other UIDs sharing the volume) is surfaced at boot
    rather than tolerated silently. Absence of the pair is fine -- the
    auto-JOIN task mints it on first JOIN.

    Wraps :func:`api.app.cluster_cert.validate_perms` to keep the
    ``HaBootInvariantError`` type consistent across both boot checks.
    """
    try:
        cluster_cert.validate_perms(cert_path, key_path)
    except cluster_cert.ClusterCertPermError as exc:
        msg = (
            f"HA boot invariant violated : {exc}. The cluster cert pair must "
            "be mode 0o400 owned by the rhorizon UID. Re-deploy the volume "
            "with the correct permissions or delete the files to trigger a "
            "fresh JOIN."
        )
        log.critical(msg)
        raise HaBootInvariantError(msg) from exc


def enforce_ha_tls_invariant(cluster_ha_enabled: bool, tls_enabled: bool) -> None:
    """Refuse to boot if ``cluster_ha_enabled`` is true without TLS.

    Parameters are passed explicitly (rather than reaching into
    ``api.app.config.settings``) so unit tests can stress every
    combination without touching the global Settings singleton.
    Raises :class:`HaBootInvariantError` on violation.
    """
    if cluster_ha_enabled and not tls_enabled:
        msg = (
            "HA boot invariant violated : RHORIZON_CLUSTER_HA_ENABLED is true "
            "but RHORIZON_TLS_ENABLED is false. /cluster/challenge + "
            "/cluster/join must travel over TLS so a LAN adversary cannot "
            "snoop the JOIN proof inputs or the wrapped node key. Either "
            "(a) set RHORIZON_TLS_ENABLED=true and terminate TLS at the "
            "API (nginx or uvicorn --ssl-keyfile) or (b) set "
            "RHORIZON_CLUSTER_HA_ENABLED=false if this container is not "
            "part of an HA cluster. See docs/HA-CLUSTER.md for "
            "the HA-over-TLS rationale."
        )
        log.critical(msg)
        raise HaBootInvariantError(msg)
    log.debug(
        "HA boot invariant OK : cluster_ha_enabled=%s tls_enabled=%s",
        cluster_ha_enabled,
        tls_enabled,
    )
