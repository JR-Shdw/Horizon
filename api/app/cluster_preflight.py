# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Production HA preflight shared by the API, CLI, UI and MCP surfaces.

Every check has a stable identifier and an operator-facing remediation. The
payload contains no secret and can be safely projected to an MCP agent. Static
checks are cheap; ``live=True`` additionally traverses the real HTTPS/mTLS
proxy path with this node's client certificate.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from . import cluster_cert, cluster_membership, cluster_tls
from .audit_verify_anchor import latest_verification_anchor
from .config import settings

_LIVE_TIMEOUT = httpx.Timeout(8.0, connect=3.0)


def _item(
    check_id: str,
    label: str,
    status: str,
    reason: str,
    remediation: str = "",
    *,
    blocking: bool = True,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "label": label,
        "status": status,
        "blocking": blocking,
        "reason": reason,
        "remediation": remediation,
        "evidence": evidence or {},
    }


def _file_mode(path: str) -> str | None:
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except OSError:
        return None


def _static_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.append(
        _item(
            "ha_enabled",
            "Application HA enabled",
            "pass" if settings.cluster_ha_enabled else "fail",
            "RH_CLUSTER_HA_ENABLED is enabled"
            if settings.cluster_ha_enabled
            else "this node is running in standalone mode",
            "Set RH_CLUSTER_HA_ENABLED=true on every HA member.",
        )
    )
    checks.append(
        _item(
            "tls_enabled",
            "TLS declared",
            "pass" if settings.tls_enabled else "fail",
            "the API is declared reachable through TLS"
            if settings.tls_enabled
            else "HA traffic is not declared TLS-protected",
            "Enable the bundled HTTPS frontend or an equivalent TLS proxy.",
        )
    )
    trusted = bool(settings.proxy_trusted_ips.strip())
    checks.append(
        _item(
            "trusted_proxy",
            "mTLS proxy trust boundary",
            "pass" if trusted else "fail",
            "forwarded client certificates are accepted only from configured peers"
            if trusted
            else "no proxy is authorized to forward X-Client-Cert",
            "Set RH_PROXY_TRUSTED_IPS to the exact nginx address or frontend Pod CIDR.",
        )
    )
    checks.append(
        _item(
            "persistent_identity",
            "Persistent node identity",
            "pass" if settings.cluster_identity_persistent else "fail",
            "/var/lib/rhorizon is declared persistent"
            if settings.cluster_identity_persistent
            else "the deployment has not declared persistent node identity",
            "Use a named volume/PVC for /var/lib/rhorizon and set "
            "RH_CLUSTER_IDENTITY_PERSISTENT=true.",
        )
    )
    advertised = settings.cluster_advertise_ip.strip()
    try:
        address = ipaddress.ip_address(advertised)
        advertised_ok = not (
            address.is_loopback or address.is_unspecified or address.is_link_local
        )
    except ValueError:
        advertised_ok = False
    checks.append(
        _item(
            "advertised_address",
            "Advertised member address",
            "pass" if advertised_ok else "fail",
            f"member address is {advertised}"
            if advertised_ok
            else "member address is missing, loopback, unspecified or link-local",
            "Set RH_CLUSTER_ADVERTISE_IP to the node LAN/VPN address; "
            "Kubernetes uses status.podIP.",
        )
    )
    primary_url = settings.ha_primary_url.strip()
    primary_ok = primary_url.startswith("https://")
    checks.append(
        _item(
            "primary_https_url",
            "Stable HTTPS cluster URL",
            "pass" if primary_ok else "fail",
            primary_url
            if primary_ok
            else "RH_HA_PRIMARY_URL is missing or is not HTTPS",
            "Set RH_HA_PRIMARY_URL to the stable HTTPS frontend used by every member.",
        )
    )
    admission = settings.max_concurrent_requests
    checks.append(
        _item(
            "admission_control",
            "Admission control",
            "pass" if admission > 0 else "fail",
            f"per-worker limit is {admission}"
            if admission > 0
            else "RH_MAX_CONCURRENT_REQUESTS is disabled",
            "Set a measured per-worker RH_MAX_CONCURRENT_REQUESTS limit "
            "before production.",
        )
    )
    return checks


def _identity_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    node_path = Path(settings.node_uuid_path)
    node_ok = node_path.is_file() and node_path.stat().st_size > 0
    checks.append(
        _item(
            "node_identity",
            "Node UUID present",
            "pass" if node_ok else "fail",
            "node UUID exists on persistent storage"
            if node_ok
            else "node UUID file is absent or empty",
            "Start the node once with writable /var/lib/rhorizon and preserve "
            "that volume.",
            evidence={"path": str(node_path), "mode": _file_mode(str(node_path))},
        )
    )

    cert_path = settings.cluster_cert_path
    key_path = settings.cluster_cert_key_path
    try:
        cluster_cert.validate_perms(cert_path, key_path)
        pair = cluster_cert.load_cluster_cert(cert_path, key_path)
        if pair is None:
            raise ValueError("cluster certificate pair is absent")
        not_after = cluster_cert.cert_not_after(pair[0])
        remaining = (not_after - datetime.now(timezone.utc)).total_seconds()
        status = "pass" if remaining > 7 * 86400 else "fail"
        reason = (
            f"node certificate valid until {not_after.isoformat()}"
            if status == "pass"
            else f"node certificate expires too soon ({not_after.isoformat()})"
        )
    except Exception as error:
        status = "fail"
        reason = f"cluster certificate unusable: {error}"
        not_after = None
    checks.append(
        _item(
            "node_certificate",
            "Node mTLS certificate",
            status,
            reason,
            "Complete JOIN, fix both files to mode 0400, or force certificate renewal.",
            evidence={
                "cert_path": cert_path,
                "cert_mode": _file_mode(cert_path),
                "key_mode": _file_mode(key_path),
                "not_after": not_after.isoformat() if not_after else None,
            },
        )
    )
    return checks


def _health_checks(health: dict[str, Any]) -> list[dict[str, Any]]:
    labels = {
        "database": "Database write path",
        "node": "Local node",
        "cluster": "Application membership",
        "database_ha": "Database HA supervision",
    }
    checks: list[dict[str, Any]] = []
    for name in ("database", "node", "cluster", "database_ha"):
        component = (health.get("components") or {}).get(name) or {}
        state = str(component.get("state") or "grey")
        checks.append(
            _item(
                f"health_{name}",
                labels[name],
                "pass" if state == "green" else "fail",
                str(component.get("reason") or f"component state is {state}"),
                "Resolve this component until /cluster/health reports green.",
                evidence={"state": state},
            )
        )
    return checks


def _worker_check(topology: dict[str, Any]) -> dict[str, Any]:
    hosts = topology.get("hosts") or {}
    missing = sorted(name for name, host in hosts.items() if not host.get("master"))
    stale = sorted(
        name
        for name, host in hosts.items()
        if float((host.get("master") or {}).get("age_sec", 0)) > 5
    )
    ok = bool(hosts) and not missing and not stale
    problems = []
    if not hosts:
        problems.append("no live worker host reported")
    if missing:
        problems.append("no local custody leader: " + ", ".join(missing))
    if stale:
        problems.append("stale local custody leader: " + ", ".join(stale))
    return _item(
        "worker_convergence",
        "Worker and custodian convergence",
        "pass" if ok else "fail",
        "every live host has a fresh local custody leader"
        if ok
        else "; ".join(problems),
        "Wait for convergence or inspect the custodian supervisor and worker "
        "heartbeats.",
        evidence={
            "hosts": len(hosts),
            "missing_masters": missing,
            "stale_masters": stale,
        },
    )


async def _audit_anchor_check(db: AsyncSession) -> dict[str, Any]:
    anchor = await latest_verification_anchor(db)
    if anchor is None:
        return _item(
            "audit_anchor",
            "Signed audit verification anchor",
            "fail",
            "no full-verification anchor exists",
            "Run POST /audit/verify/preflight and wait for its durable full job.",
        )
    payload = anchor.get("payload") or {}
    completed_raw = anchor.get("completed_at") or payload.get("completed_at")
    try:
        completed = datetime.fromisoformat(str(completed_raw).replace("Z", "+00:00"))
        if completed.tzinfo is None:
            completed = completed.replace(tzinfo=timezone.utc)
        age = max(0.0, (datetime.now(timezone.utc) - completed).total_seconds())
    except (TypeError, ValueError):
        age = float("inf")
    valid = anchor.get("valid") is True
    fresh = age <= settings.audit_verify_anchor_max_age_seconds
    ok = valid and fresh
    return _item(
        "audit_anchor",
        "Signed audit verification anchor",
        "pass" if ok else "fail",
        "latest signed full-verification anchor is valid and fresh"
        if ok
        else "latest full-verification anchor is invalid or stale",
        "Run POST /audit/verify/preflight and complete the returned durable job.",
        evidence={
            "valid": valid,
            "age_seconds": None if age == float("inf") else round(age, 3),
            "max_age_seconds": settings.audit_verify_anchor_max_age_seconds,
        },
    )


async def _clock_skew_check(db: AsyncSession) -> dict[str, Any]:
    """Local clock against the PostgreSQL clock.

    Leases and the FROZEN deadlines are stamped with the database clock. A node
    whose own clock has drifted misjudges how long its authority is still valid,
    which is exactly the condition the hard fence exists to bound.
    """
    _, _, db_now, _ = await cluster_membership.read_canonical_primary(db)
    if db_now.tzinfo is None:
        db_now = db_now.replace(tzinfo=timezone.utc)
    skew = abs((datetime.now(timezone.utc) - db_now).total_seconds())
    limit = float(settings.cluster_primary_lease_ttl_secs) / 4.0
    ok = skew <= limit
    return _item(
        "clock_skew",
        "Local clock against the database clock",
        "pass" if ok else "fail",
        f"local clock differs from PostgreSQL by {skew:.3f}s"
        if ok
        else f"local clock differs from PostgreSQL by {skew:.3f}s, over {limit:.3f}s",
        "Run an NTP client on this node; lease arithmetic uses the database clock.",
        evidence={"skew_seconds": round(skew, 3), "limit_seconds": round(limit, 3)},
    )


async def _peer_state_check(db: AsyncSession) -> dict[str, Any]:
    """Membership rows: exactly one primary, and no peer certificate expiring.

    The other checks read this node. A cluster with two primaries, or with a
    peer whose certificate lapses tomorrow, is not production ready however
    healthy this node looks from inside.
    """
    rows = (
        await db.execute(
            text(
                "SELECT node_uuid, ha_state, cert_not_after "
                "FROM vault_cluster_nodes "
                "WHERE ha_state NOT IN ('evicted', 'quarantined')"
            )
        )
    ).fetchall()
    if not rows:
        return _item(
            "peer_state",
            "Cluster membership",
            "fail",
            "no active node rows in vault_cluster_nodes",
            "Initialise the cluster, or let this node complete its JOIN.",
        )
    primaries = [r.node_uuid for r in rows if r.ha_state == "primary"]
    now = datetime.now(timezone.utc)
    soonest = min(
        (
            r.cert_not_after.replace(tzinfo=r.cert_not_after.tzinfo or timezone.utc)
            for r in rows
        ),
        default=None,
    )
    days_left = None if soonest is None else (soonest - now).total_seconds() / 86400.0
    renew_floor = float(settings.cluster_cert_renewal_threshold_days)
    cert_ok = days_left is not None and days_left > renew_floor
    one_primary = len(primaries) == 1
    ok = one_primary and cert_ok
    if not one_primary:
        reason = f"{len(primaries)} nodes claim the primary role"
    elif not cert_ok:
        reason = f"the earliest peer certificate expires in {days_left:.1f} days"
    else:
        reason = (
            f"{len(rows)} active nodes, one primary, "
            f"earliest certificate expires in {days_left:.1f} days"
        )
    return _item(
        "peer_state",
        "Cluster membership",
        "pass" if ok else "fail",
        reason,
        "Demote the extra primary, or rotate the expiring node certificate "
        "with POST /cluster/rotate-cert.",
        evidence={
            "active_nodes": len(rows),
            "primaries": primaries,
            "earliest_cert_days": None if days_left is None else round(days_left, 2),
            "renew_before_days": renew_floor,
        },
    )


async def _live_mtls_check() -> dict[str, Any]:
    base = settings.ha_primary_url.rstrip("/")
    cert_path = settings.cluster_cert_path
    key_path = settings.cluster_cert_key_path
    if not base.startswith("https://"):
        return _item(
            "mtls_live",
            "End-to-end mTLS path",
            "fail",
            "live probe cannot run without an HTTPS primary URL",
            "Set RH_HA_PRIMARY_URL and rerun the live preflight.",
        )
    try:
        ctx = cluster_tls.server_context(
            client_cert=cert_path,
            client_key=key_path,
        )
        async with httpx.AsyncClient(timeout=_LIVE_TIMEOUT, verify=ctx) as client:
            response = await client.get(base + "/api/v1/vault/cluster/mtls-self")
        response.raise_for_status()
        body = response.json()
        ok = body.get("authenticated") is True
        reason = (
            "mTLS authenticated node "
            f"{body.get('node_uuid', 'unknown')} through the HTTPS frontend"
            if ok
            else "mTLS endpoint returned an unexpected response"
        )
    except Exception as error:
        ok = False
        reason = f"end-to-end mTLS probe failed: {error}"
    return _item(
        "mtls_live",
        "End-to-end mTLS path",
        "pass" if ok else "fail",
        reason,
        "Check frontend RH_CLUSTER_MTLS, certificate trust, "
        "RH_PROXY_TRUSTED_IPS and X-Client-Cert forwarding.",
    )


async def build_preflight(
    db: AsyncSession,
    *,
    health: dict[str, Any],
    topology: dict[str, Any],
    live: bool,
) -> dict[str, Any]:
    checks = _static_checks() + _identity_checks() + _health_checks(health)
    checks.append(_worker_check(topology))
    for probe in (_clock_skew_check, _peer_state_check):
        try:
            checks.append(await probe(db))
        except Exception as error:
            checks.append(
                _item(
                    probe.__name__.strip("_").replace("_check", ""),
                    "Cluster state probe",
                    "fail",
                    f"probe failed: {error}",
                    "Repair database access and rerun the preflight.",
                )
            )
    try:
        checks.append(await _audit_anchor_check(db))
    except Exception as error:
        checks.append(
            _item(
                "audit_anchor",
                "Signed audit verification anchor",
                "fail",
                f"audit anchor state unavailable: {error}",
                "Repair database/audit access and run the audit preflight.",
            )
        )
    checks.append(
        await _live_mtls_check()
        if live
        else _item(
            "mtls_live",
            "End-to-end mTLS path",
            "warn",
            "live network verification was not requested",
            "Run `rhorizon cluster preflight` or request /cluster/preflight?live=true.",
            blocking=False,
        )
    )
    failed = [
        check["id"]
        for check in checks
        if check["blocking"] and check["status"] == "fail"
    ]
    warnings = [check["id"] for check in checks if check["status"] == "warn"]
    return {
        "schema_version": 1,
        "ready": not failed,
        "overall": "fail" if failed else ("warn" if warnings else "pass"),
        "live_mtls_requested": live,
        "failed_checks": failed,
        "warning_checks": warnings,
        "checks": checks,
    }


def project_preflight(result: dict[str, Any]) -> dict[str, Any]:
    """Topology-free projection used by MCP clients."""
    return {
        "schema_version": result.get("schema_version"),
        "ready": result.get("ready"),
        "overall": result.get("overall"),
        "live_mtls_requested": result.get("live_mtls_requested", False),
        "failed_checks": result.get("failed_checks", []),
        "warning_checks": result.get("warning_checks", []),
        "checks": [
            {
                "id": check.get("id"),
                "status": check.get("status"),
                "blocking": check.get("blocking"),
                "reason": check.get("reason"),
                "remediation": check.get("remediation"),
            }
            for check in result.get("checks", [])
        ],
    }
