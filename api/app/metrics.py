# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Prometheus metrics - observability.

GET /metrics returns Prometheus exposition format. Access is restricted
by CIDR (settings.metrics_allowed_cidrs) - typically the monitoring host
on the management VLAN. Metrics leak timing/usage information about the
vault, so they must NOT be public.

Counters / histograms / gauges are defined here and incremented inline in
the hot paths (auth, secret CRUD, unseal/seal, DEK rotation, audit).
Keep cardinality low - labels with high cardinality (e.g. token name,
secret name) are deliberately avoided.
"""

import ipaddress
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)

from .config import settings

# Multiprocess registry mode is gated on PROMETHEUS_MULTIPROC_DIR. When the
# boot wrapper sets that var (uvicorn --workers > 1), every worker writes
# its samples to per-pid mmap files in the dir and /metrics aggregates them
# via MultiProcessCollector. Without it, the in-process registry is used
# (single-process dev / tests).
#
# Background-task counters (e.g. cluster_state_transitions, bumped only by
# the worker that wins the advisory lock) are invisible without this --
# only one worker ever increments and a scrape on any other worker returns
# zero.
_MULTIPROC = bool(os.environ.get("PROMETHEUS_MULTIPROC_DIR"))

log = logging.getLogger("rhorizon.metrics")

router = APIRouter(tags=["metrics"])


# -- Definitions -----------------------------------------------------------


# Authentication / unseal
unseal_attempts = Counter(
    "rhorizon_unseal_attempts_total",
    "Number of /unseal calls",
    ["result"],  # success | invalid_password | invalid_2fa | rate_limited | other
)
seal_events = Counter(
    "rhorizon_seal_events_total",
    "Number of seal events (manual + auto + shutdown)",
    ["trigger"],  # manual | shutdown | broadcast | failover
)

# Admission control / load shedding (per-worker concurrency cap).
# livesum so /metrics shows the cluster-wide in-flight sum across workers.
requests_inflight = Gauge(
    "rhorizon_requests_inflight",
    "HTTP requests currently being served (admission control gauge)",
    multiprocess_mode="livesum",
)
requests_shed = Counter(
    "rhorizon_requests_shed_total",
    "Requests rejected with 429 by the concurrency cap (admission control)",
    ["reason"],
)
# Request volume split by transport: http = direct API (machine clients on the
# plain port), https = via the nginx TLS frontend (X-Forwarded-Proto: https).
# Lets the dashboard show API vs HTTPS request rate. Health probes are excluded.
requests_by_transport = Counter(
    "rhorizon_http_requests_total",
    "HTTP requests admitted, by transport (http | https from X-Forwarded-Proto)",
    ["transport"],
)
custody_control_requests = Counter(
    "rhorizon_custody_control_requests_total",
    "Separated-custody control requests completed by the public API proxy",
    ["result"],  # success | master_unavailable | transport_error
)
custody_master_retries = Counter(
    "rhorizon_custody_master_retries_total",
    "Control connections rejected by a follower before reaching the custodian master",
)
custody_direct_routes = Counter(
    "rhorizon_custody_direct_routes_total",
    "Control requests addressed straight to the elected custodian's own socket",
)

# Secret CRUD
secrets_read = Counter(
    "rhorizon_secrets_read_total",
    "Successful secret reads",
)
secrets_write = Counter(
    "rhorizon_secrets_write_total",
    "Successful secret writes (create + update)",
    ["op"],  # create | update | delete
)
secret_decrypt_duration = Histogram(
    "rhorizon_secret_decrypt_duration_seconds",
    "Per-secret decrypt latency",
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5),
)

# Tokens
tokens_created = Counter(
    "rhorizon_tokens_created_total",
    "Tokens minted",
    ["kind"],  # standard | ephemeral
)
tokens_revoked = Counter(
    "rhorizon_tokens_revoked_total",
    "Tokens explicitly revoked (separate from natural expiry)",
)
tokens_rotated = Counter(
    "rhorizon_tokens_rotated_total",
    "Live tokens whose secret was re-minted in place (POST /tokens/{id}/rotate)",
)
auth_failures = Counter(
    "rhorizon_auth_failures_total",
    "Token auth rejections - bumps signal brute-force attempts",
    ["reason"],  # missing|invalid_token|revoked|scope|namespace|ip_not_allowed|other
)

audit_chain_breaks = Counter(
    "rhorizon_audit_chain_breaks_total",
    "Audit chain integrity failures detected during /audit/verify (should stay 0)",
)
audit_archive_write_failures = Counter(
    "rhorizon_audit_archive_write_failures_total",
    "Audit entries written to the database but NOT to the daily archive file "
    "(should stay 0; their day cannot be sealed and so cannot be pruned)",
)
audit_archive_seal_refusals = Counter(
    "rhorizon_audit_archive_seal_refusals_total",
    "Archive days refused a seal because the file and the database disagree",
)
audit_lite_checkpoint_breaks = Counter(
    "rhorizon_audit_lite_checkpoint_breaks_total",
    "Read-audit Merkle checkpoint integrity failures detected during /audit/verify",
)
audit_lite_checkpoints = Counter(
    "rhorizon_audit_lite_checkpoints_total",
    "Read-audit Merkle checkpoint loop outcomes",
    ["result"],  # success | empty | failure
)
audit_lite_checkpoint_rows = Counter(
    "rhorizon_audit_lite_checkpoint_rows_total",
    "vault_audit_lite rows covered by written Merkle checkpoints",
)
reaper_failures = Counter(
    "rhorizon_reaper_failures_total",
    "Background reaper cycles that failed and will be retried",
)

# Vault state gauges
# Gauge multiprocess_mode rationale (see prometheus_client.multiprocess docs) :
# - DB-derived gauges (sealed, stale, age, active_tokens, locked_ips,
#   audit_chain_length, audit_lite_length) are conceptually system-wide
#   values that any worker observes identically when fresh -- "livemax"
#   surfaces the most recent live-worker value (dead worker files dropped)
#   without summing identical samples N times.
# - master_rpc_inflight is per-process by design (only the master worker
#   serves crypto-ops RPC) -- "livesum" gives the system total.
vault_sealed = Gauge(
    "rhorizon_vault_sealed",
    "1 if the vault is sealed, 0 if unsealed",
    multiprocess_mode="livemax",
)
cluster_component = Gauge(
    "rhorizon_cluster_component",
    "Cluster health per component: 1=green, 0.5=orange, 0=red (grey omitted)",
    ["component"],
    multiprocess_mode="livemax",
)
dek_key_stale = Gauge(
    "rhorizon_dek_key_stale",
    "1 if dek_key age exceeds RHORIZON_DEK_KEY_MAX_AGE_DAYS or its rotation "
    "timestamp is invalid - operator action required",
    multiprocess_mode="livemax",
)
dek_key_age_seconds = Gauge(
    "rhorizon_dek_key_age_seconds",
    "Time since the dek_key was last rotated (or vault initialized); "
    "-1 means the timestamp is missing or invalid",
    multiprocess_mode="livemax",
)
active_tokens = Gauge(
    "rhorizon_active_tokens",
    "Tokens currently active (not revoked, not expired)",
    multiprocess_mode="livemax",
)
locked_ips = Gauge(
    "rhorizon_locked_ips",
    "Client IPs currently rate-limited",
    multiprocess_mode="livemax",
)

# master RPC saturation.
# Every encrypt/decrypt from a follower converges on the master process via
# Unix-socket RPC. These three series let an operator catch master-side
# saturation (the one bottleneck multi-worker scaling does NOT lift) before
# it shows up as p99 read latency on /secrets/{name}.
master_rpc_inflight = Gauge(
    "rhorizon_master_rpc_inflight",
    "Crypto-op RPC requests currently being served by the master",
    multiprocess_mode="livesum",
)
master_rpc_duration = Histogram(
    "rhorizon_master_rpc_duration_seconds",
    "Server-side latency of one crypto-op RPC, by op",
    ["op"],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)
master_rpc_errors = Counter(
    "rhorizon_master_rpc_errors_total",
    "Crypto-op RPC requests that returned an error to the follower",
    ["op"],
)

# Audit chain, security observability
#
# Every log_action / log_read call increments audit_events with a
# bucketed `category` label. The category set is closed (8 values) ;
# new actions get mapped to "other" so the cardinality stays bounded.
# `result` is success / failure (the audit row itself was written or
# the helper raised, the latter usually means DB unreachable).
audit_events = Counter(
    "rhorizon_audit_events_total",
    "Audit log entries written, by category. Wide categorisation is "
    "deliberate (cardinality bound) - drill into specific actions via "
    "the audit chain itself.",
    ["category", "result"],  # category: see _AUDIT_CATEGORY_MAP
)
# Which path signed each audit entry. ed25519_local = the master signed
# with its own loaded signer ; ed25519_delegated = a follower delegated to the
# master via RPC ; hmac = no audit identity provisioned ; hmac_fallback = an
# identity exists but signing failed (e.g. master mid-failover has not reloaded
# the signer) -- should be 0 in steady state, a non-zero rate means the chain
# is silently mixing schemes ; unsigned = written while sealed.
audit_sign_path = Counter(
    "rhorizon_audit_sign_path_total",
    "Audit entries written by signing path. hmac_fallback > 0 means an ed25519 "
    "identity exists but a node could not use it (cluster chain mixing - alert).",
    ["path"],  # ed25519_local | ed25519_delegated | hmac | hmac_fallback | unsigned
)
audit_verify_duration = Histogram(
    "rhorizon_audit_verify_duration_seconds",
    "Wall-clock time of a signed audit-chain verification pass. Scales "
    "linearly with chain length; audit-lite and archive phases are measured "
    "separately by rhorizon_audit_verify_phase_duration_seconds.",
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60),
)
audit_verify_phase_duration = Histogram(
    "rhorizon_audit_verify_phase_duration_seconds",
    "Wall-clock duration of each /audit/verify phase.",
    ["phase"],  # setup | main_chain | audit_lite | archive | total
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60),
)
audit_chain_length = Gauge(
    "rhorizon_audit_chain_length",
    "Total rows currently in vault_audit (chained, mutations). Updated on "
    "every successful log_action so /metrics scrapes don't pay a COUNT(*).",
    multiprocess_mode="livemax",
)
audit_lite_length = Gauge(
    "rhorizon_audit_lite_length",
    "Total rows currently in vault_audit_lite (read events, append-only).",
    multiprocess_mode="livemax",
)
audit_lite_uncheckpointed = Gauge(
    "rhorizon_audit_lite_uncheckpointed_rows",
    "Read-audit rows newer than the latest signed Merkle checkpoint.",
    multiprocess_mode="livemax",
)

# Honeytoken intrusion signal, ANY non-zero rate here is an alert.
# `kind` distinguishes a honey *secret* (decoy in vault_secrets) from
# a honey *token* (decoy in vault_tokens) so the responder knows which
# tripwire fired.
honey_access = Counter(
    "rhorizon_honey_access_total",
    "Honeytoken trips - a real attacker / automation has read a decoy. "
    "ALERT-WORTHY at any non-zero rate.",
    ["kind"],  # secret | token
)

# Sealed-state forbidden ops, calls that hit a CRUD endpoint while the
# vault is sealed. Steady non-zero = automation is broken (a consumer
# kept calling after seal). Bursts after a seal event are normal during
# the unseal window ; sustained > 1/min after unseal indicates a stale
# client config.
sealed_op_attempts = Counter(
    "rhorizon_sealed_op_attempts_total",
    "Requests rejected because the vault is sealed. Indicates automation "
    "still calling post-seal, or an active scan attempt.",
    ["op"],  # read | write | other
)

# Cluster failover, the most expensive and security-relevant event in
# normal operation : the master died and a follower had to reconstruct the
# unsealed state from Shamir shares.
cluster_failover = Counter(
    "rhorizon_cluster_failover_total",
    "Master failover events. result=success means a follower "
    "reconstructed the unsealed state and took over ; quorum_missing "
    "means M-of-N Shamir shares were not reachable and the cluster sealed.",
    ["result"],  # success | quorum_missing | failure
)

# Per-worker attempts to bind the master crypto-ops socket. Used to
# investigate the intermittent socket-already-bound symptom by surfacing
# which outcome dominates over time.
master_socket_acquire = Counter(
    "rhorizon_master_socket_acquire_attempts_total",
    "Attempts to bind the master crypto-ops Unix socket. "
    "outcome=ok : clean bind on a free path. "
    "stale_cleaned : an orphan file was present, unlinked, then bind succeeded. "
    "alive_refused : is_alive_socket returned True, bind aborted (the "
    "symptom that surfaces as 'socket already bound'). "
    "error : unexpected exception during the acquire path.",
    ["outcome"],
)

# Master password rotation, a high-impact security operation. Counter
# lets the operator audit "did anyone rotate the master password without
# leaving a paper trail elsewhere?", non-zero on /metrics without a
# corresponding ticket is itself a signal.
master_password_rotated = Counter(
    "rhorizon_master_password_rotated_total",
    "Master password rotations performed. mode=admin_ops is routine "
    "(prev_hmac_key kept, lazy migration). mode=sec_ops is emergency "
    "(prev_hmac_key wiped, all tokens immediately invalidated).",
    ["mode"],  # admin_ops | sec_ops
)

# inter-host HA cluster RPC observability + loops.
# cluster_rpc_latency : histogram of master/follower-boundary RPC ops issued by
#   cluster auth (notably ha_password_hmac for JOIN proof). Labelled by op only,
#   no worker_pid (cardinality discipline, mirrors master_rpc_duration).
# ha_password_load_failures : bumped only on a *failure* (decrypt errored on a
#   present row). A missing row = normal pre-cluster-init state, NOT counted
#   (would flood on every fresh deploy boot).
# cluster_state_transitions : bumped on each state-machine transition. Labelled
#   (from, to), bounded enum -- only ('joining','secondary') ships today.
# cluster_nodes_reaped : bumped per row removed by the joining-orphan reaper.
#   Labelled by reason ('joining_orphan' for now).
cluster_rpc_latency = Histogram(
    "rhorizon_cluster_rpc_latency_seconds",
    "Latency of cluster auth RPC ops dispatched across the "
    "master/follower boundary. Drives the slow-follower alert.",
    ["op"],
    buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
)
ha_password_load_failures = Counter(
    "rhorizon_ha_password_load_failures_total",
    "load_ha_password_into_ram() failure events. Non-zero rate after "
    "an unseal signals a corrupt vault_cluster_config row or a key "
    "mismatch -- HA is silently broken.",
    ["reason"],  # decrypt_fail | other
)
cluster_state_transitions = Counter(
    "rhorizon_cluster_state_transitions_total",
    "vault_cluster_nodes ha_state transitions performed by the "
    "background state-machine loop.",
    ["from_state", "to_state"],
)
cluster_nodes_reaped = Counter(
    "rhorizon_cluster_nodes_reaped_total",
    "vault_cluster_nodes rows purged by the reaper loop (stuck-joining orphans).",
    ["reason"],  # joining_orphan
)

# A peer successfully adopted a verified
# rekey envelope and rolled forward to the rotated generation with no operator
# action. A healthy non-emergency rotation in a 3-node cluster bumps this by 2.
cluster_node_rolled_forward = Counter(
    "rhorizon_cluster_node_rolled_forward_total",
    "Peers that adopted a verified rekey envelope and rolled forward to the "
    "new key generation.",
)

# Red-timing reconciler -- the primary re-sealed the CURRENT-epoch envelope for
# peers that quarantined behind because they published their rekey_pub only
# AFTER the one-shot post-rotation publish. A non-zero rate is normal right after
# a rotation where a peer was momentarily absent ; it should fall back to 0 once
# the cluster converges. Persistently climbing = a peer that never drains.
rekey_envelope_republished = Counter(
    "rhorizon_rekey_envelope_republished_total",
    "Times the primary re-sealed the current-epoch rekey envelope for late/"
    "behind peers (red-timing reconciler). Drives sub-30s convergence.",
)

# Live row count in vault_rekey_envelope, set by the reaper. At
# steady state (all members converged) this is 0. A persistently non-zero
# value means a rotation is stuck mid-propagation or a node is lagging and not
# draining its row -- alertable (the table is meant to be transient, and stale
# rows weaken the envelope's forward-secrecy property).
rekey_envelope_rows = Gauge(
    "rhorizon_rekey_envelope_rows",
    "Current number of rows in vault_rekey_envelope (transient ; 0 at steady "
    "state). Persistently non-zero = stuck rekey propagation / lagging node.",
)

# Envelope rows purged by the reaper backstop (unconsumed past the
# migration window : nodes that never came back, emergency rotations that left
# stragglers, partial publishes). Distinct from per-row consume teardown.
rekey_envelope_reaped = Counter(
    "rhorizon_rekey_envelope_reaped_total",
    "vault_rekey_envelope rows purged by the reaper after the migration window.",
)

# (uuid, ip) binding conflict counter.
# Bumped each time /cluster/join hits the source_ip-already-bound
# pre-flight check. Surfaced by GET /cluster/ha as a historical
# diagnostic without exposing row-level conflict detail (avoids growing
# a separate vault_cluster_conflicts table). A non-zero rate
# during operations review is the signal that an operator wiped a
# node's volume and tried to JOIN as a fresh identity from the same IP.
cluster_uuid_ip_conflicts = Counter(
    "rhorizon_cluster_uuid_ip_conflicts_total",
    "JOIN attempts rejected because source_ip is already bound to a "
    "different active node.",
)

# /cluster/join idempotency cache hit counter. Bumped
# each time a joiner replays a nonce within the TTL window and receives
# the cached payload (identical cert + wrapped key) instead of a fresh
# mint. Non-zero rate is expected during cold-bootstrap re-runs after a
# transient 503 ; sustained rate during steady-state signals a flaky
# network between joiner and primary.
cluster_join_idempotency_hits = Counter(
    "rhorizon_cluster_join_idempotency_hits_total",
    "Replays of a /cluster/join nonce served from the idempotency cache.",
)

# proactive RPC recovery on MasterUnreachable.
# Bumped each time a follower crypto op trips a stale master_rpc client
# (master_watch has not yet detected the loss via DB heartbeat). The
# `outcome` label distinguishes the resolution paths :
#   - success      : detach+reattach+retry returned a value
#   - promoted     : this follower became master during recovery
#   - timeout      : recovery did not complete within recover_budget_secs
#   - no_master    : recovery completed but no new master was reachable
#   - retry_failed : retry after reattach also raised MasterUnreachable
#   - unwired      : recovery hook not set on vault (defensive)
# Read with cluster_rpc_latency_seconds for end-to-end recovery impact.
cluster_rpc_recovery = Counter(
    "rhorizon_cluster_rpc_recovery_total",
    "Follower-side RPC recovery outcomes triggered by MasterUnreachable. "
    "Non-zero rate post-failover is normal; sustained "
    "rate signals a master that flaps.",
    ["outcome"],
)

# two-phase ha_password rotation outcomes.
# Bumped by the four exit paths of the rotate-ha-password flow :
#   - staged    : POST /cluster/rotate-ha-password/stage inserted a row
#   - confirmed : POST .../confirm minted a new password + applied it
#   - cancelled : POST .../cancel dropped the pending row before confirm
#   - expired   : reaper purged a pending row past its TTL
#   - corrupt   : reaper cancelled malformed intent metadata fail-closed
# Labelled by outcome only -- actor cardinality would explode and is
# already captured in the audit chain.
cluster_ha_password_rotations = Counter(
    "rhorizon_cluster_ha_password_rotations_total",
    "Two-phase ha_password rotation outcomes. Surfaces "
    "operator intent (staged) vs. completion (confirmed/cancelled) vs. "
    "forgotten or malformed rotations (expired/corrupt).",
    ["outcome"],  # staged | confirmed | cancelled | expired | corrupt
)

# per-node cert renewal outcomes. One increment
# per renewal tick that ran a refresh attempt (skipped ticks are not
# counted -- they fire on every poll cycle and would flood the counter).
# "success" / "fail" distinguish completed refreshes from errored ones.
cluster_cert_refreshes = Counter(
    "rhorizon_cluster_cert_refreshes_total",
    "Cert renewal outcomes performed by the per-node "
    "renewal loop. success = new cert persisted on disk + metadata updated. "
    "fail = transport or auth error ; next tick will retry.",
    ["outcome"],  # success | fail
)

# POST /cluster/rotate-cert admin-triggered
# force-renew broadcasts. Labelled by scope to distinguish a per-node
# rotate from the cluster-wide broadcast (CA rotation will
# fire scope=all).
cluster_cert_force_rotates = Counter(
    "rhorizon_cluster_cert_force_rotates_total",
    "Force-renew triggers issued by POST "
    "/cluster/rotate-cert. scope=one for a single node, scope=all for "
    "the cluster-wide broadcast.",
    ["scope"],  # one | all
)

# cluster CA rotation lifecycle.
# cluster_ca_rotations_total : one increment per successful
# POST /cluster/rotate-ca call (the 409 in-grace path does NOT bump).
# Unlabelled -- the audit chain captures actor + fingerprints, the
# metric is just a "how many times has this happened" counter.
cluster_ca_rotations = Counter(
    "rhorizon_cluster_ca_rotations_total",
    "Successful CA rotations performed by POST "
    "/cluster/rotate-ca. Excludes 409 in-grace refusals.",
)

# end of the rotation grace window. Labelled by
# the trigger that fired the drop : all_rotated (every active node
# refreshed its cert under the new CA) vs. grace_expired (the
# wall-clock window elapsed before all nodes rotated -- typically
# means some nodes were offline or stuck).
cluster_ca_grace_drops = Counter(
    "rhorizon_cluster_ca_grace_drops_total",
    "End-of-grace-window events. all_rotated = the "
    "reaper observed every active node had cleared its force_renew_at ; "
    "grace_expired = the wall-clock window elapsed without all nodes "
    "rotating.",
    ["reason"],  # all_rotated | grace_expired
)


# Bounded categorisation map for audit_events. New action names get
# mapped to "other" by record_audit_event(), keeps Prometheus
# cardinality predictable. Re-categorise an action by editing this map.
_AUDIT_CATEGORY_MAP: dict[str, str] = {
    # auth / 2FA / external auth
    "ldap_login": "auth",
    "proxy_login": "auth",
    "register_webauthn": "auth",
    "register_yubikey": "auth",
    "remove_webauthn": "auth",
    "remove_yubikey": "auth",
    "ldap_configure": "auth",
    "ldap_update_mappings": "auth",
    "proxy_configure": "auth",
    "proxy_update_mappings": "auth",
    "2fa_fallback": "auth",
    # secret CRUD + reads
    "create_secret": "secret",
    "delete_secret": "secret",
    "read_secret": "secret",
    "read_secret_version": "secret",
    "rotate_secret": "secret",
    "rollback_secret": "secret",
    "oneshot_read": "secret",
    "audit_lite_checkpoint": "audit",
    # token lifecycle
    "create_token": "token",
    "create_ephemeral_token": "token",
    "delete_token": "token",
    "revoke_token": "token",
    "renew_token": "token",
    "rotate_token": "token",
    # namespace / RBAC
    "create_namespace": "namespace",
    "archive_namespace": "namespace",
    "delete_namespace": "namespace",
    "update_namespace": "namespace",
    "namespace_rate_limit_exceeded": "namespace",
    "admin_bypass_namespace_rbac": "namespace",
    # group RBAC
    "create_group": "group",
    "delete_group": "group",
    "update_group": "group",
    "add_group_member": "group",
    "remove_group_member": "group",
    # dynamic secrets
    "create_dynamic_engine": "dynamic",
    "delete_dynamic_engine": "dynamic",
    "create_dynamic_role": "dynamic",
    "generate_credentials": "dynamic",
    "revoke_lease": "dynamic",
    # backup / export
    "create_backup": "backup",
    "restore_backup": "backup",
    # notifications
    "create_notification_channel": "notification",
    "delete_notification_channel": "notification",
    "update_notification_channel": "notification",
    # security signals
    "honey_access": "security",
    "rate_limit_unblock": "security",
    "rotate_password": "security",
    "rotate_dek_key": "security",
    "shamir_init": "security",
    "shamir_destroy": "security",
}


# -- CIDR allow list -------------------------------------------------------


def _parse_cidrs(csv: str) -> list:
    nets = []
    for token in csv.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return nets


_ALLOWED_CIDRS = _parse_cidrs(settings.metrics_allowed_cidrs)


def _client_ip_in_allowed(request: Request) -> bool:
    """Allow-list check using the direct peer IP, NOT the X-Forwarded-For.

    /metrics is meant to be called by the monitoring host on the management
    network. We deliberately ignore XFF here - accepting XFF would let any
    proxy claim a privileged source IP. The trust anchor is the network
    perimeter (firewall + VPN), not headers.
    """
    if not _ALLOWED_CIDRS:
        return False
    direct = request.client.host if request.client else None
    if not direct:
        return False
    try:
        ip = ipaddress.ip_address(direct)
    except ValueError:
        return False
    return any(ip in net for net in _ALLOWED_CIDRS)


# -- Endpoint --------------------------------------------------------------


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    if not settings.metrics_enabled:
        raise HTTPException(404, "Metrics disabled")
    if not _client_ip_in_allowed(request):
        log.warning(
            "metrics: rejected from %s (not in allowed CIDRs)",
            request.client.host if request.client else "?",
        )
        raise HTTPException(403, "Metrics access denied")
    if _MULTIPROC:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        payload = generate_latest(registry)
    else:
        payload = generate_latest()
    return PlainTextResponse(payload, media_type=CONTENT_TYPE_LATEST)


def _p95_ms(buckets: dict[str, float]) -> float:
    """95th percentile (ms) from cumulative histogram buckets, Prometheus-style
    linear interpolation. buckets maps the `le` label to its cumulative count."""
    items = []
    for le, count in buckets.items():
        try:
            items.append((float("inf") if le in ("+Inf", "Inf") else float(le), count))
        except ValueError:
            continue
    items.sort()
    if not items:
        return 0.0
    total = items[-1][1]
    if total <= 0:
        return 0.0
    target = 0.95 * total
    prev_le, prev_count = 0.0, 0.0
    for le, count in items:
        if count >= target:
            if le == float("inf"):
                return prev_le * 1000.0
            if count == prev_count:
                return le * 1000.0
            frac = (target - prev_count) / (count - prev_count)
            return (prev_le + (le - prev_le) * frac) * 1000.0
        prev_le, prev_count = le, count
    return items[-1][0] * 1000.0


def observability_snapshot() -> dict:
    """Current metric values as JSON for the in-app Nova view. Same source as
    /metrics (the multiprocess registry), shaped for a token-authed UI poll.
    Route-layer only: reads already-computed counters/gauges, never touches keys
    or crypto. Counters are monotonic totals; the client diffs successive polls
    to draw per-second rates."""
    if _MULTIPROC:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
    else:
        registry = REGISTRY
    reads = writes = http_total = http_https = auth_fail = 0.0
    tokens = conns = custody_retries = custody_failures = 0.0
    dbuckets: dict[str, float] = {}
    for mf in registry.collect():
        for s in mf.samples:
            name, labels, val = s.name, s.labels, s.value
            if name == "rhorizon_secrets_read_total":
                reads += val
            elif name == "rhorizon_secrets_write_total":
                writes += val
            elif name == "rhorizon_http_requests_total":
                http_total += val
                if labels.get("transport") == "https":
                    http_https += val
            elif name == "rhorizon_auth_failures_total":
                auth_fail += val
            elif name == "rhorizon_active_tokens":
                tokens = val
            elif name == "rhorizon_requests_inflight":
                conns = val
            elif name == "rhorizon_custody_master_retries_total":
                custody_retries += val
            elif (
                name == "rhorizon_custody_control_requests_total"
                and labels.get("result") != "success"
            ):
                custody_failures += val
            elif name == "rhorizon_secret_decrypt_duration_seconds_bucket":
                le = labels.get("le", "")
                dbuckets[le] = dbuckets.get(le, 0.0) + val
    return {
        "reads_total": reads,
        "writes_total": writes,
        "http_total": http_total,
        "http_https": http_https,
        "auth_failures_total": auth_fail,
        "active_tokens": int(tokens),
        "active_connections": int(conns),
        "decrypt_p95_ms": round(_p95_ms(dbuckets), 3),
        "custody_master_retries_total": custody_retries,
        "custody_control_failures_total": custody_failures,
    }


# -- Helpers for hot-path instrumentation ---------------------------------


def record_auth_failure(reason: str) -> None:
    """Convenience wrapper for auth-failure counter - keeps cardinality low
    by mapping arbitrary error strings to the 5 documented reasons.
    """
    if reason not in (
        "missing",
        "invalid_token",
        "revoked",
        "scope",
        "namespace",
        "ip_not_allowed",
    ):
        reason = "other"
    auth_failures.labels(reason=reason).inc()


def set_vault_sealed(sealed: bool) -> None:
    vault_sealed.set(1 if sealed else 0)


def record_audit_event(action: str, success: bool = True) -> None:
    """Bucket the action into a known category and bump the counter.

    Called from log_action() / log_read() ; new action names default to
    'other' to keep Prometheus cardinality bounded. To re-categorise,
    edit `_AUDIT_CATEGORY_MAP` above.
    """
    category = _AUDIT_CATEGORY_MAP.get(action, "other")
    audit_events.labels(
        category=category,
        result="success" if success else "failure",
    ).inc()
