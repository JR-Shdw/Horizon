# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Single source of truth for cluster readiness.

Every component is probed from live state on each call:
  green  verified OK        orange transitional (starting/forming)
  red    verified not OK    grey   cannot probe -- never treated as OK

overall = worst non-grey component, so a half-formed cluster never reports
ready. Pure reads, idempotent. Feeds /cluster/health, the CLI, the UI and the
rhorizon_cluster_component gauges.
"""

import asyncio
import logging
import time
from enum import Enum

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings

log = logging.getLogger("rhorizon.cluster_health")


class Health(str, Enum):
    GREEN = "green"  # verified OK
    ORANGE = "orange"  # transitional: starting / forming / degraded-but-recovering
    RED = "red"  # verified NOT OK
    GREY = "grey"  # unknown -- cannot probe ; NEVER treated as OK


# Gauge encoding. grey -> no sample (absence is honest about "unknown").
GAUGE_VALUE = {Health.GREEN: 1.0, Health.ORANGE: 0.5, Health.RED: 0.0}

# Severity for worst-of aggregation (grey excluded -- unknown must not mask a
# real red, nor downgrade a real green).
_RANK = {Health.RED: 3, Health.ORANGE: 2, Health.GREEN: 1}

# Monotonic timestamp of the first replica-lag breach in the current streak,
# keyed by provider ("patroni" / "pgha") so the two probes cannot clear each
# other's streak when the provider is "auto". Module-level: "has this cluster
# been lagging for a while" is a property of the cluster, not of who asked.
_lag_breach_since: dict[str, float] = {}


def _lag_breach_secs(provider: str, lagging: list) -> float:
    """Seconds the current replica-lag breach has persisted (0.0 if none).

    Deliberately time-based rather than a consecutive-sample count: callers
    poll at wildly different rates (a 2 s UI refresh, a chaos harness, a
    Prometheus scrape), so "3 samples in a row" would mean a different
    duration for each. Seconds mean the same thing to everyone.

    Observed motivation: a 14 h chaos run produced 6 criticals, all isolated
    single samples that were clean again by the next observation, while
    Patroni reported one leader and every member streaming throughout.
    """
    if not lagging:
        _lag_breach_since.pop(provider, None)
        return 0.0
    now = time.monotonic()
    since = _lag_breach_since.setdefault(provider, now)
    return now - since


async def probe_database(db: AsyncSession) -> tuple[Health, str]:
    """DB tier as the app sees it through the configured write endpoint/VIP."""
    try:
        rec = (await db.execute(text("SELECT pg_is_in_recovery() AS r"))).fetchone().r
    except Exception as e:
        return Health.RED, f"unreachable: {type(e).__name__}"
    if rec:
        return Health.ORANGE, "reachable but in recovery (VIP routed to a standby?)"
    return Health.GREEN, "reachable, writable primary"


def probe_node(vault, quarantined: bool) -> tuple[Health, str]:
    """This rhorizon process. Sealed = orange (startup, awaiting unseal)."""
    if vault.sealed:
        return Health.ORANGE, "sealed (awaiting unseal)"
    if quarantined:
        return Health.RED, "quarantined by key-epoch fence (stale keys)"
    return Health.GREEN, "unsealed and serving"


async def probe_cluster(db: AsyncSession) -> tuple[Health, str, dict]:
    """HA membership. Green ONLY when fully settled -- this is the false-green
    killer (ha_loaded alone is not enough; the primary can be "loaded" while
    joiners are stuck)."""
    if not settings.cluster_ha_enabled:
        return Health.GREY, "single-node (HA disabled)", {"members": 0}
    try:
        rows = (
            await db.execute(
                text(
                    "SELECT ha_state, COUNT(*) AS n FROM vault_cluster_nodes "
                    "GROUP BY ha_state"
                )
            )
        ).fetchall()
    except Exception as e:
        return Health.RED, f"membership query failed: {type(e).__name__}", {}
    by_state = {r.ha_state: r.n for r in rows}
    total = sum(by_state.values())
    primaries = by_state.get("primary", 0)
    secondaries = by_state.get("secondary", 0)
    transitional = by_state.get("joining", 0) + by_state.get("quarantined", 0)
    bad = by_state.get("evicted", 0) + by_state.get("draining", 0)
    detail = {"total": total, "by_state": by_state}
    if total == 0:
        return Health.RED, "no cluster members registered", detail
    if primaries != 1 or bad:
        return Health.RED, f"primaries={primaries} evicted/draining={bad}", detail
    if transitional:
        return Health.ORANGE, f"{transitional} member(s) joining/quarantined", detail
    return Health.GREEN, f"{primaries} primary + {secondaries} secondary", detail


def _csv_urls(value: str) -> list[str]:
    return [url.strip().rstrip("/") for url in (value or "").split(",") if url.strip()]


async def probe_patroni(urls: list[str] | None = None) -> tuple[Health, str, dict]:
    """Database-HA health via Patroni REST.

    A Patroni member's ``state=running`` only says that PostgreSQL is up. A
    replica may still be unable to consume WAL indefinitely, so green also
    requires bounded, known lag and the leader's current timeline.
    """
    if urls is None:
        urls = _csv_urls(settings.patroni_rest_urls or settings.database_ha_status_urls)
    if not urls:
        return (
            Health.GREY,
            "Patroni status endpoints not configured",
            {"provider": "patroni"},
        )
    cluster_members: list[dict] = []
    async with httpx.AsyncClient(timeout=3.0) as c:
        for url in urls:
            try:
                data = (await c.get(f"{url}/cluster")).json()
            except Exception:
                continue
            cluster_members = data.get("members", [])
            break  # one reachable endpoint reports the whole cluster

    members = len(cluster_members)
    leaders = [m for m in cluster_members if m.get("role") in ("leader", "primary")]
    running = sum(m.get("state") in ("running", "streaming") for m in cluster_members)
    leader_timeline = leaders[0].get("timeline") if len(leaders) == 1 else None
    threshold = settings.database_ha_max_replica_lag_bytes
    lagging: list[dict] = []
    unknown_lag: list[str] = []
    non_streaming: list[dict] = []
    timeline_mismatch: list[dict] = []
    replica_lags: dict[str, int | None] = {}

    for i, member in enumerate(cluster_members):
        if member in leaders:
            continue
        name = str(member.get("name") or f"member-{i}")
        state = str(member.get("state") or "unknown")
        # Patroni can report a replica as "running" when PostgreSQL is accepting
        # read-only traffic but its WAL receiver is stopped (for example because
        # a physical slot was invalidated). Only "streaming" proves attachment.
        if state != "streaming":
            non_streaming.append({"name": name, "state": state})
        lag = member.get("lag")
        # Patroni emits "unknown" when PostgreSQL is running but replication
        # progress cannot be established. bool is deliberately excluded even
        # though it is an int subclass.
        if isinstance(lag, bool) or not isinstance(lag, (int, float)):
            replica_lags[name] = None
            unknown_lag.append(name)
        else:
            lag_bytes = max(0, int(lag))
            replica_lags[name] = lag_bytes
            if lag_bytes > threshold:
                lagging.append({"name": name, "lag_bytes": lag_bytes})

        timeline = member.get("timeline")
        if (
            leader_timeline is not None
            and timeline is not None
            and timeline != leader_timeline
        ):
            timeline_mismatch.append({"name": name, "timeline": timeline})

    max_lag = max((lag for lag in replica_lags.values() if lag is not None), default=0)
    detail = {
        "provider": "patroni",
        "leaders": len(leaders),
        "running": running,
        "members": members,
        "leader_timeline": leader_timeline,
        "replica_lags": replica_lags,
        "max_replica_lag_bytes": max_lag,
        "lag_threshold_bytes": threshold,
        "lagging_members": lagging,
        "unknown_lag_members": unknown_lag,
        "non_streaming_replicas": non_streaming,
        "timeline_mismatch_members": timeline_mismatch,
    }
    if members == 0:
        return Health.RED, "patroni REST unreachable on all endpoints", detail
    if len(leaders) != 1:
        return Health.RED, f"leaders={len(leaders)} (no single leader)", detail
    if running < members:
        return Health.ORANGE, f"{running}/{members} members healthy", detail
    if non_streaming:
        summary = ", ".join(f"{m['name']}={m['state']}" for m in non_streaming)
        return Health.ORANGE, f"replica not streaming: {summary}", detail
    if unknown_lag:
        return Health.ORANGE, f"replica lag unknown: {', '.join(unknown_lag)}", detail
    breach_secs = _lag_breach_secs("patroni", lagging)
    detail["lag_breach_secs"] = int(breach_secs)
    if lagging and breach_secs >= settings.database_ha_lag_grace_secs:
        summary = ", ".join(f"{m['name']}={m['lag_bytes']}B" for m in lagging)
        return (
            Health.ORANGE,
            f"replica lag exceeds {threshold}B for {int(breach_secs)}s: {summary}",
            detail,
        )
    if timeline_mismatch:
        summary = ", ".join(f"{m['name']}={m['timeline']}" for m in timeline_mismatch)
        return Health.ORANGE, f"replica timeline differs from leader: {summary}", detail
    return Health.GREEN, f"leader + {running}/{members} healthy", detail


async def probe_pgha(urls: list[str] | None = None) -> tuple[Health, str, dict]:
    """Database-HA health via rhorizon-pgha's read-only status endpoints.

    Every configured agent must report a fresh control-loop observation. The
    reports must agree on quorum and one leader, exactly one primary must own
    the write VIP, and every standby must be actively streaming within budget.
    """
    if urls is None:
        urls = _csv_urls(settings.database_ha_status_urls)
    if not urls:
        return Health.GREY, "pgha status endpoints not configured", {"provider": "pgha"}

    async def fetch(client: httpx.AsyncClient, url: str) -> tuple[str, dict | None]:
        endpoint = url if url.endswith("/status") else f"{url}/status"
        try:
            data = (await client.get(endpoint)).json()
            return url, data if isinstance(data, dict) else None
        except Exception:
            return url, None

    async with httpx.AsyncClient(timeout=3.0) as client:
        fetched = await asyncio.gather(*(fetch(client, url) for url in urls))

    now = time.time()
    max_age = settings.database_ha_status_max_age_secs
    reports: dict[str, dict] = {}
    unreachable_endpoints: list[str] = []
    stale_agents: list[dict] = []
    duplicate_agents: list[str] = []
    status_ages: dict[str, float | None] = {}
    for url, report in fetched:
        if not report or report.get("provider") != "pgha":
            unreachable_endpoints.append(url)
            continue
        node = str(report.get("node") or "")
        if not node:
            unreachable_endpoints.append(url)
            continue
        if node in reports:
            duplicate_agents.append(node)
            continue
        observed_at = report.get("observed_at")
        if isinstance(observed_at, bool) or not isinstance(observed_at, (int, float)):
            age = None
        else:
            age = max(0.0, now - float(observed_at))
        status_ages[node] = age
        if age is None or age > max_age:
            stale_agents.append({"name": node, "age_seconds": age})
        reports[node] = report

    expected_endpoints = len(urls)
    detail: dict = {
        "provider": "pgha",
        "members": expected_endpoints,
        "agents_reporting": len(reports),
        "status_max_age_seconds": max_age,
        "status_age_seconds": status_ages,
        "unreachable_endpoints": unreachable_endpoints,
        "stale_agents": stale_agents,
        "duplicate_agents": duplicate_agents,
        "leaders": 0,
        "running": 0,
        "leader_timeline": None,
        "replica_lags": {},
        "max_replica_lag_bytes": 0,
        "lag_threshold_bytes": settings.database_ha_max_replica_lag_bytes,
        "lagging_members": [],
        "unknown_lag_members": [],
        "non_streaming_replicas": [],
        "timeline_mismatch_members": [],
    }
    if not reports:
        return Health.RED, "pgha status unreachable on all endpoints", detail
    if duplicate_agents:
        return (
            Health.RED,
            f"duplicate pgha agent reports: {', '.join(duplicate_agents)}",
            detail,
        )
    if stale_agents:
        return (
            Health.ORANGE,
            "pgha agent status is stale or missing a timestamp",
            detail,
        )

    no_quorum = sorted(
        node for node, report in reports.items() if report.get("quorum") is not True
    )
    if no_quorum:
        detail["quorum"] = False
        return Health.RED, f"pgha quorum absent: {', '.join(no_quorum)}", detail
    detail["quorum"] = True

    claimed_leaders = {
        str(report.get("leader")) for report in reports.values() if report.get("leader")
    }
    primary_reports = [
        report for report in reports.values() if report.get("role") == "primary"
    ]
    detail["leaders"] = len(primary_reports)
    if len(claimed_leaders) != 1:
        return Health.RED, f"pgha leader consensus={len(claimed_leaders)}", detail
    leader = next(iter(claimed_leaders))
    detail["leader"] = leader
    if len(primary_reports) != 1 or primary_reports[0].get("node") != leader:
        return (
            Health.RED,
            f"pgha primaries={len(primary_reports)} leader={leader}",
            detail,
        )

    vip_owners = sorted(
        node for node, report in reports.items() if report.get("vip_present") is True
    )
    detail["vip_owners"] = vip_owners
    if vip_owners != [leader]:
        return Health.RED, f"write VIP owners={vip_owners}, expected [{leader}]", detail

    primary_report = primary_reports[0]
    expected_members = primary_report.get("expected_members")
    if isinstance(expected_members, int) and not isinstance(expected_members, bool):
        detail["members"] = expected_members
    else:
        expected_members = expected_endpoints
    if expected_members < 3:
        return (
            Health.RED,
            f"pgha requires at least 3 members, got {expected_members}",
            detail,
        )
    if len(reports) < expected_members or unreachable_endpoints:
        return (
            Health.ORANGE,
            f"pgha agents reporting {len(reports)}/{expected_members}",
            detail,
        )

    member_states = primary_report.get("member_states")
    if not isinstance(member_states, dict):
        return Health.ORANGE, "pgha leader did not report member state", detail

    threshold = settings.database_ha_max_replica_lag_bytes
    replica_lags: dict[str, int | None] = {}
    non_streaming: list[dict] = []
    unknown_lag: list[str] = []
    lagging: list[dict] = []
    running = 0
    for name, member in member_states.items():
        if not isinstance(member, dict) or not member.get("reachable"):
            if name != leader:
                replica_lags[name] = None
                non_streaming.append({"name": name, "state": "unreachable"})
                unknown_lag.append(name)
            continue
        running += 1
        if name == leader:
            continue
        state = str(member.get("replication_state") or "unknown")
        if member.get("role") != "standby" or state != "streaming":
            non_streaming.append({"name": name, "state": state})
        lag = member.get("lag_bytes")
        if isinstance(lag, bool) or not isinstance(lag, (int, float)):
            replica_lags[name] = None
            unknown_lag.append(name)
        else:
            lag_bytes = max(0, int(lag))
            replica_lags[name] = lag_bytes
            if lag_bytes > threshold:
                lagging.append({"name": name, "lag_bytes": lag_bytes})

    max_lag = max((lag for lag in replica_lags.values() if lag is not None), default=0)
    detail.update(
        {
            "running": running,
            "replica_lags": replica_lags,
            "max_replica_lag_bytes": max_lag,
            "lagging_members": lagging,
            "unknown_lag_members": unknown_lag,
            "non_streaming_replicas": non_streaming,
        }
    )
    if running < expected_members:
        return (
            Health.ORANGE,
            f"{running}/{expected_members} database members reachable",
            detail,
        )
    if non_streaming:
        summary = ", ".join(f"{m['name']}={m['state']}" for m in non_streaming)
        return Health.ORANGE, f"replica not streaming: {summary}", detail
    if unknown_lag:
        return Health.ORANGE, f"replica lag unknown: {', '.join(unknown_lag)}", detail
    breach_secs = _lag_breach_secs("pgha", lagging)
    detail["lag_breach_secs"] = int(breach_secs)
    if lagging and breach_secs >= settings.database_ha_lag_grace_secs:
        summary = ", ".join(f"{m['name']}={m['lag_bytes']}B" for m in lagging)
        return (
            Health.ORANGE,
            f"replica lag exceeds {threshold}B for {int(breach_secs)}s: {summary}",
            detail,
        )
    return Health.GREEN, f"pgha leader + {running}/{expected_members} healthy", detail


async def probe_database_ha() -> tuple[Health, str, dict]:
    """Dispatch the provider-neutral database-HA component probe."""
    provider = settings.database_ha_provider
    generic_urls = _csv_urls(settings.database_ha_status_urls)
    patroni_urls = _csv_urls(settings.patroni_rest_urls)
    if provider == "auto":
        if generic_urls:
            provider = "pgha"
        elif patroni_urls:
            provider = "patroni"
        else:
            return (
                Health.GREY,
                "database HA provider not configured",
                {"provider": "unconfigured"},
            )
    if provider == "none":
        return Health.GREY, "database HA supervision disabled", {"provider": "none"}
    if provider == "patroni":
        return await probe_patroni(generic_urls or patroni_urls)
    return await probe_pgha(generic_urls)


async def cluster_health(db: AsyncSession, vault, quarantined: bool = False) -> dict:
    """Aggregate readout. overall = worst non-grey component ; ready iff green."""
    db_h, db_r = await probe_database(db)
    node_h, node_r = probe_node(vault, quarantined)
    cl_h, cl_r, cl_d = await probe_cluster(db)
    dbha_h, dbha_r, dbha_d = await probe_database_ha()

    components = {
        "database": {"state": db_h.value, "reason": db_r},
        "node": {"state": node_h.value, "reason": node_r},
        "cluster": {"state": cl_h.value, "reason": cl_r, **cl_d},
        "database_ha": {"state": dbha_h.value, "reason": dbha_r, **dbha_d},
    }
    # Refresh the per-component gauges from the same probe (grey -> no sample).
    from . import metrics as _m

    for name, h in (
        ("database", db_h),
        ("node", node_h),
        ("cluster", cl_h),
        ("database_ha", dbha_h),
    ):
        if h != Health.GREY:
            _m.cluster_component.labels(component=name).set(GAUGE_VALUE[h])

    graded = [h for h in (db_h, node_h, cl_h, dbha_h) if h != Health.GREY]
    overall = max(graded, key=lambda h: _RANK[h]) if graded else Health.GREY
    return {
        "overall": overall.value,
        "ready": overall == Health.GREEN,
        "components": components,
    }
