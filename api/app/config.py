# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
import ipaddress
from pathlib import Path

from pydantic import ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, EnvSettingsSource


def _default_dynamic_modules_file() -> str:
    """Find the shipped INI beside either source or relocated application."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "dynamic-engines.ini"
        if candidate.is_file():
            return str(candidate)
    # Keep a deterministic error path when packaging omitted the file.
    return "/app/dynamic-engines.ini"


class Settings(BaseSettings):
    # PostgreSQL
    database_url: str = "postgresql+asyncpg://rhorizon:rhorizon@postgres:5432/rhorizon"
    # Postgres TLS mode (3-state; legacy bool via validator: true->require,
    # false->disable):
    #   disable      : plaintext, safe only same-host (unix socket / loopback).
    #   require      : encrypt, no cert verify -- same-host / loopback only.
    #   verify-full  : encrypt + verify against database_ca_cert (empty path ->
    #                  system trust store). Shipped compose pins a per-instance cert.
    database_ssl: str = "require"
    database_ca_cert: str = ""  # CA/cert bundle pinned under verify-full

    # Vault
    auto_seal_minutes: int = 0  # 0 = never auto-seal
    version: str = "0.9.0-beta"
    # Closed-catalog dynamic backend selection. This resolves to the repository
    # root in source and /app in the image, independent of process cwd.
    dynamic_modules_file: str = _default_dynamic_modules_file()
    secret_max_versions: int = 10  # 0 = unlimited
    # Rotation grace window. After a non-emergency value update, the immediately
    # prior version stays readable via GET /{name}?previous=true for this many
    # seconds (audited as read_secret_previous), so a consumer mid-cutover can
    # still fetch the old value. 0 = disabled (safe-by-default, opt-in). An
    # emergency update suppresses it (clears grace on all versions). Clamped to
    # [0, 86400].
    secret_grace_seconds: int = 0
    enable_docs: bool = False  # Enable /docs and /redoc (behind SSO in prod)
    # Uvicorn process count. One process is the explicit home mode; 2-4 cannot
    # form the supported per-worker Shamir quorum and are promoted to 5.
    workers: int = 5
    # Crypto custody placement. ``embedded`` is the existing compatibility
    # path: public API workers also form the local Shamir quorum. ``separated``
    # runs a fixed UDS-only custodian pool and makes public API workers
    # disposable RPC clients that never receive a share.
    custody_mode: str = "embedded"  # embedded | separated
    # Custody implementation. Rust remains explicit until every rollout gate
    # passes; selecting it never falls back to the Python share-bearing pool.
    custody_backend: str = "python"  # python | rust
    # Internal process role set by the launcher. Operators select
    # ``custody_mode``; they should not normally set this directly.
    process_role: str = "api"  # api | custodian
    custodian_workers: int = 5
    custodian_uds_path: str = "/run/rhorizon/custodian-http.sock"
    custodian_token_file: str = "/run/rhorizon/custodian-control.token"
    rust_custodian_slots: int = 3
    rust_custodian_threshold: int = 0  # 0 = majority
    # Where the launcher keeps per-slot transport keys and persisted share
    # state. The API never reads a share; it needs the path only to sweep what
    # a resolved topology change superseded. Must match the value
    # run-rust-custodians.sh was started with, hence the same env var.
    rust_custodian_key_dir: str = "/var/lib/rhorizon/custody"
    rust_custody_maintenance_interval_secs: float = 5.0
    # Failover timing. A master is declared lost after cluster_master_timeout_secs
    # without a heartbeat, and the surviving workers then reconstruct from Shamir
    # shares.
    #
    # The default was 5s, which is a bet that a silent master is a dead master.
    # Under the IO pressure separated custody exists for, that bet is wrong: a
    # worker starved on iowait stops heartbeating while still holding its
    # sub-keys, and a 5s deadline turns a recoverable stall into a full
    # reconstruction -- more load, on a box already collapsing. 120s waits for
    # the machine to come back instead.
    #
    # Raise it further on storage that stalls for minutes; lower it only where
    # a fast, clean failover matters more than surviving a stall.
    cluster_master_timeout_secs: float = 120.0
    # How often a follower checks whether the master is still alive. Kept at
    # half the timeout so detection latency stays bounded by it without adding
    # database load proportional to worker count.
    cluster_master_watch_interval_secs: float = 60.0
    # Per-call deadline on crypto-op RPC to the master. Must exceed the master
    # timeout, or a stalled-but-alive master fails every in-flight request
    # before the cluster has even decided whether it is gone.
    cluster_rpc_timeout_secs: float = 180.0
    memlock_all: bool = True  # mlockall() workers: keep secret pages out of swap
    # Rust secret-buffer policy. best-effort keeps zeroize-on-drop and warns if
    # mlock is unavailable; required preserves fail-closed startup/unseal.
    memory_lock_mode: str = "best-effort"
    disable_core_dumps: bool = True  # RLIMIT_CORE=0: no cleartext in a crash dump
    # Lazy token-migration window after a non-emergency master password
    # rotation. prev_hmac_key is kept this long (reaper purges it past the
    # window); a second non-emergency rotation inside the window is refused
    # unless force=true (only one prev_hmac generation is retained). Single
    # source for the reaper expiry (main.py) and the rotate-password guard
    # (routes/vault.py).
    token_migration_window_days: int = 15
    # Hierarchical rotation: the dek_key (HKDF sub-key wrapping each secret's
    # DEK) ages and is rotated as a whole -- vault_dek rows are re-wrapped
    # under the new dek_key, secrets stay encrypted under their own DEKs.
    # O(N_DEKs) instead of O(N_secrets * decrypt+encrypt).
    dek_key_max_age_days: int = 30
    dek_key_lazy_check: bool = True  # check age in reaper loop, trigger if stale
    ephemeral_max_ttl: int = 86400  # max TTL for ephemeral tokens (24h)
    namespace_mutation_rate_per_hour: int = 10  # cap per actor on namespace ops
    soft_delete_retention_days: int = 7  # 'soft' mode reaper window
    protected_delete_retention_days: int = (
        365  # 'protected' mode reaper window (no auto-purge if 0)
    )
    audit_dir: str = "/var/log/rhorizon"  # audit log directory
    audit_lite_checkpoint_enabled: bool = True
    audit_lite_checkpoint_interval_secs: int = 60
    audit_lite_checkpoint_max_rows: int = 10000
    # Per-container node identity. Mode 0400 on a persistent volume;
    # survives restart, lost with the volume (fresh identity = new node at JOIN).
    node_uuid_path: str = "/var/lib/rhorizon/node-uuid"
    # Minimum byte length for the cluster ha_password. 32B = 256 bits,
    # mirrors the master key entropy budget.
    ha_password_min_length: int = 32
    # /cluster/{challenge,join} knobs + HA gate.
    # cluster_ha_enabled : the operator declares this container part of an
    # HA cluster; combined with tls_enabled it drives the refuse-to-boot
    # invariant (see api/app/ha_boot_check.py).
    # cluster_challenge_ttl_secs : single-use nonce lifetime returned by
    # /cluster/challenge. Short on purpose -- a slow joiner re-issues
    # (harmless), a sniffed nonce expires before it can be replayed.
    # cluster_join_quarantine_secs : how long a freshly-joined node stays in
    # ha_state='joining' before the state-machine loop flips it to 'secondary'.
    # cluster_min_compatible_version : version floor a joiner must meet.
    # Bidirectional: the joiner also verifies the cluster_version returned
    # by /challenge against its own floor.
    # tls_enabled : the operator declares the API is reachable over TLS.
    # Two supported terminations: nginx in front (the container path, TLS_ENABLED
    # in docker-compose.yml) or uvicorn itself via --ssl-certfile/--ssl-keyfile
    # (the native path, which has no nginx). Read at boot by ha_boot_check.py to
    # refuse-to-start an HA-enabled node without TLS.
    cluster_ha_enabled: bool = False
    cluster_challenge_ttl_secs: int = 30
    cluster_join_quarantine_secs: int = 60
    # Provider-neutral database-HA health shown by /cluster/health. "auto"
    # selects Patroni when the legacy Patroni endpoints are configured, or pgha
    # when generic status endpoints are configured. "none" explicitly disables
    # orchestration probing (the database write-path probe still runs).
    database_ha_provider: str = "auto"  # auto | patroni | pgha | none
    database_ha_status_urls: str = ""
    # Shares minted beyond the worker count at unseal, so a worker that is
    # replaced can still obtain one. Shares are cut once and consumed
    # permanently; with no spares the pool empties as soon as every worker has
    # attached, and the live share count can then only fall until failover
    # quorum is unreachable and the node seals. Spares come from the same
    # polynomial, so they combine normally.
    cluster_shamir_spare_shares: int = 8
    # How stale a vault_workers row must be before the reaper deletes it.
    # Kept at the historical 5 minutes by default. Worth knowing the ratio it
    # implies: HEARTBEAT_INTERVAL_SECS is 1s, so this is 300 consecutive failed
    # heartbeats -- a very wide gap with no useful detection in between, and
    # 1 write/s/worker of permanent WAL traffic to sustain it.
    worker_reap_stale_secs: int = 300
    database_ha_max_replica_lag_bytes: int = 16 * 1024 * 1024
    database_ha_status_max_age_secs: int = 15
    # How long a replica-lag breach must persist before it is reported.
    # Write bursts push WAL past the threshold for a few seconds and then
    # catch up ; reporting each blip trains the operator to ignore the check.
    database_ha_lag_grace_secs: int = 60
    # Deprecated Patroni-specific aliases. Keep these for existing deployments;
    # new configurations should use RH_DATABASE_HA_*.
    patroni_rest_urls: str = ""
    patroni_max_replica_lag_bytes: int = 16 * 1024 * 1024
    cluster_min_compatible_version: str = "0.9.0-beta"
    tls_enabled: bool = False
    # Stable address advertised by this node in HA membership and encoded in
    # its node-certificate IP SAN.  HA installers should always set this to
    # the inventory/LAN address.  Empty keeps the TEST-NET compatibility
    # placeholder for local tests and manual single-host initialisation.
    cluster_advertise_ip: str = ""
    # Inter-host HA state-machine knobs.
    # cluster_heartbeat_interval_secs : how often a node writes its own
    #   vault_cluster_nodes.last_heartbeat. Dedicated asyncio task
    #   (cluster_ha_loops.py), decoupled from the state machine so a stuck
    #   machine still emits a liveness signal.
    # cluster_state_machine_interval_secs : poll period of the loop flipping
    #   'joining' rows to 'secondary' once quarantine_until elapses. Singleton
    #   (advisory lock 'cluster_ha_state_machine').
    # cluster_joining_orphan_ttl_secs : a row stuck 'joining' past this TTL
    #   (from joined_at) is reaped, so a crashed mid-JOIN does not leak forever.
    #   Singleton (lock 'cluster_ha_reaper'). MUST stay >= quarantine plus the
    #   slower of the state-machine and reaper intervals, else the reaper can
    #   race the joining->secondary flip and evict a healthy joiner.
    # cluster_reaper_interval_secs : poll period of that reaper (housekeeping,
    #   slower than the state machine).
    cluster_heartbeat_interval_secs: int = 3
    cluster_state_machine_interval_secs: int = 2
    cluster_joining_orphan_ttl_secs: int = 90
    cluster_reaper_interval_secs: int = 30
    # Auto-promote lease knobs.
    # cluster_primary_lease_ttl_secs : how far ahead the active primary's
    #   heartbeat pushes primary_lease_expires_at (vault_cluster_config). Each
    #   secondary reads it; if NOW() > expiry + skew (skew = ttl / 3) and
    #   primary_uuid != self, the eligible secondary takes PRIMARY_ELECTION_LOCK
    #   and promotes. Autonomous failover -- does NOT replace the manual /promote
    #   escape hatch. With the 20s default, expiry + skew + maximum jitter +
    #   one state-machine interval is about 32s. Range [5, 3600].
    # cluster_operator_weight : per-node bias on the random jitter before
    #   PRIMARY_ELECTION_LOCK. Higher = shorter jitter ceiling, so a preferred
    #   node claims first under contention. Local (each node knows only its own).
    #   1.0 = uniform; non-finite / non-positive fall back to 1.0.
    cluster_primary_lease_ttl_secs: int = 20
    cluster_operator_weight: float = 1.0
    # Auto-promote demotion cooldown (anti-thrash).
    # cluster_auto_promote_cooldown_secs : minimum dwell time a node must
    # spend in its current ha_state before _maybe_auto_promote considers it
    # an election candidate. role_changed_at is stamped on every transition;
    # a node that changed within the window is skipped even if the primary
    # lease is stale. Targets partition-heal thrash: a returning ex-primary
    # lands directly in 'secondary' (no quarantine) and must dwell before
    # re-claiming primary, so a flapping link cannot ping-pong the role.
    # Other healthy secondaries fail over immediately. The 20s default matches
    # one primary lease. 0 disables. Range [0, 3600]. NULL role_changed_at =
    # no cooldown.
    cluster_auto_promote_cooldown_secs: int = 20
    # cluster_frozen_max_secs : how long a node may stay FROZEN -- keys retained
    # in RAM, all authority suspended -- before the hard fence seals it and the
    # key material goes.
    #
    # The node stops being authoritative at cluster_primary_lease_ttl_secs; this
    # governs only how long it waits, holding its keys, for the database to come
    # back. That wait is the point: there is no auto-unseal, so sealing at the
    # TTL meant every PostgreSQL outage longer than it cost a manual /unseal on
    # the primary -- and a Patroni failover takes 10-30s against a 20s default.
    #
    # 300s covers a database failover comfortably while bounding how long a
    # possibly-stale node sits on key material.
    #
    # There is deliberately NO "never seal" value -- see
    # standalone_db_seal_secs. Range [30, 86400].
    cluster_frozen_max_secs: int = 300
    # -- standalone / embedded / custodian : seal on a dead local database --
    #
    # These apply ONLY when cluster_ha_enabled is false, and they are tuned the
    # opposite way to the HA knobs above, because the evidence is different.
    #
    # In HA, "cannot reach the database" is ambiguous: it may be this node's
    # NIC, a BGP/OSPF reconvergence, a VIP still settling, or load. A peer can
    # cover, so the node freezes and waits, and recovers by self-demoting.
    # Sealing on that signal would destroy keys over a transient network event.
    #
    # Standalone has no such excuse. The database is on this machine. There is
    # no partition to blame and no peer that could be serving, so sustained
    # unreachability IS evidence rather than ambiguity -- and the vault is
    # already serving nothing, since every read needs the database. Keys held
    # in RAM past that point are pure exposure. Data protection wins: freeze,
    # then seal.
    #
    # standalone_db_freeze_secs : unreachable this long -> stop being
    #   authoritative (FROZEN). Keys retained; a database that comes back
    #   restores service with no unseal.
    # standalone_db_seal_secs : frozen this long on top -> seal, dropping the
    #   key material. Long enough to ride a local postgres restart or package
    #   upgrade, short enough to bound the exposure.
    #
    #   There is deliberately NO "never seal" value. Ambiguity has to end in
    #   sealed rather than in active, and an operator switch that suspends that
    #   is an override on the one property the design exists to guarantee. The
    #   floor below is the shortest window that still rides a service restart.
    standalone_db_freeze_secs: int = 10
    standalone_db_seal_secs: int = 60
    # /cluster/join idempotency cache TTL: lifetime of the (nonce ->
    # response payload) row after a successful JOIN. A joiner that lost the
    # wire response can replay the same nonce and recover the *identical*
    # cert + wrapped key, instead of a divergent fresh cert or a
    # PermanentError once the membership row moved past 'joining'. Past the
    # TTL the joiner restarts from /cluster/challenge. Range [60, 3600]:
    # 60s floor covers a transient 503 retry, 1h ceiling caps stale cache.
    cluster_join_idempotency_ttl_secs: int = 300
    # Two-phase ha_password rotation TTL: how long a staged rotation may
    # sit before the operator confirms or cancels. The pending row is
    # metadata only (no plaintext persisted; new bytes are minted at
    # confirm time), so the TTL caps a stale "intent to rotate" in the
    # admin UI, not an at-rest exposure. The reaper purges expired rows +
    # emits audit/metric. Range [300, 86400].
    cluster_pending_ha_rotation_ttl_secs: int = 3600

    # cluster_drain_deadline_secs : how long POST /cluster/drain lets the
    # target node finish in-flight RPC ops before the reaper forces it to
    # 'evicted' and appends its node_uuid to revoked_node_uuids.
    # Materialised on the row as drain_deadline_at at drain time; no
    # per-request override. Range [5, 600] -- past 10 min an evict is the
    # right operation, not a drain.
    cluster_drain_deadline_secs: int = 30

    # Per-node cluster cert lifecycle.
    # cluster_node_cert_validity_days : NotAfter span for the per-node cert
    # minted by /cluster/init (primary self-cert) and /cluster/join (joiner
    # cert). LE-style 90-day baseline, auto-renewed by the renewal loop;
    # revocation (binary `node_uuid in revoked_node_uuids` check at mTLS
    # auth time) is the load-bearing control, not the validity cap.
    # cluster_cert_renewal_threshold_days : the renewal loop triggers
    # POST /cluster/refresh-cert when the node's own cert has less than
    # this many days remaining. Must stay strictly less than both node and
    # server validity, else the loop refreshes the shorter cert on every tick.
    # cluster_cert_renewal_poll_secs : how often the renewal loop checks
    # the local cert's NotAfter. 12h is enough against a 30-day threshold.
    # cluster_cert_path / cluster_cert_key_path : where the joiner persists
    # the cert + private key. Mode 0400 on a persistent volume, same volume
    # as node-uuid so the (uuid, ip, cert) triple stays consistent across
    # reboots; lost volume = fresh JOIN.
    cluster_node_cert_validity_days: int = 90
    cluster_cert_renewal_threshold_days: int = 30
    cluster_cert_renewal_poll_secs: int = 43200
    cluster_cert_path: str = "/var/lib/rhorizon/cluster-cert.pem"
    cluster_cert_key_path: str = "/var/lib/rhorizon/cluster-cert.key"

    # Cluster CA also signs the nginx server cert.
    # cluster_server_cert_validity_days : NotAfter span for the cluster-CA
    # signed nginx server cert minted by /cluster/issue-server-cert and
    # /cluster/join (auto-shipped to joiners). LE-style 90-day baseline,
    # rotated by the same renewal loop as the node identity cert.
    # cluster_server_cert_path / cluster_server_cert_key_path : where the
    # API persists the server cert + key. nginx reads from these paths
    # (host volume in Docker setups, write-then-reload native). 0640 cert /
    # 0600 key: nginx reads the cert via group; only the owner reads the key.
    # cluster_nginx_reload_cmd : command line parsed into an argument vector and
    # executed without a shell after persisting a fresh server cert. Empty
    # disables the reload (deployer signals nginx out-of-band -- file watcher,
    # systemd path unit, etc.). Typical:
    # "sudo /bin/systemctl reload nginx" with a NOPASSWD sudoers entry.
    cluster_server_cert_validity_days: int = 90
    cluster_server_cert_path: str = "/etc/nginx/ssl/server.crt"
    cluster_server_cert_key_path: str = "/etc/nginx/ssl/server.key"
    cluster_nginx_reload_cmd: str = ""

    # Cluster CA rotation grace window.
    # cluster_ca_grace_window_secs : how long the previous cluster CA cert
    # stays valid for mTLS verification after POST /cluster/rotate-ca has
    # minted a fresh CA. Node certs signed under the prev CA keep
    # authenticating inside the window; the reaper drops the prev once
    # every active node has re-certed under the new CA OR the window
    # elapses. Default 7d covers a cluster-wide weekend deploy. The floor
    # allows two renewal polls; the 30d ceiling limits how long a stale
    # previous CA remains an attack surface.
    cluster_ca_grace_window_secs: int = 604800

    # Auto-JOIN bootstrap.
    # ha_primary_url : base URL of an already-initialised cluster node
    # (primary or secondary -- /cluster/{challenge,join} run on any
    # member). When set together with a present RHORIZON_HA_PASSWORD_FILE
    # and no local cluster-cert.pem, the lifespan triggers an auto-JOIN
    # against this URL after vault unseal. Empty disables (manual ops only).
    # ha_password_file : tmpfs path (mode 0400) holding the cluster
    # ha_password plaintext at boot. Read once at JOIN time, then the
    # operator unlinks; subsequent reboots REJOIN with the on-disk cert.
    # ha_auto_join : master switch for the auto-JOIN background task.
    # Default true; flip false for a manual JOIN flow without unsetting
    # ha_primary_url.
    # ha_auto_join_max_attempts : retries before the task gives up and
    # requires operator action. Readiness stays 503 until membership is
    # confirmed. 20 x 30s = ~10 min window, outlasting bootstrap churn.
    # ha_auto_join_retry_secs : backoff between auto-JOIN attempts.
    ha_primary_url: str = ""
    ha_password_file: str = ""
    ha_cluster_id: str = ""
    ha_auto_join: bool = True
    ha_auto_join_max_attempts: int = 20
    ha_auto_join_retry_secs: int = 30

    # Portable ha_password delivery via age-encrypted file + vault-fetched key.
    # ha_password_storage : "file" (default, tmpfs) or "age_vault"
    # (ha_password_file ignored; ha_password_age_path +
    # ha_bootstrap_token_file used instead).
    # age_vault flow at joiner boot:
    #   1. read bootstrap bearer token from ha_bootstrap_token_file
    #   2. GET <ha_bootstrap_vault_url>/api/v1/vault/secrets/
    #      <ha_bootstrap_secret_name>?namespace=<ha_bootstrap_namespace>
    #   3. age-decrypt ha_password_age_path with the fetched key as
    #      passphrase (pyrage scrypt mode)
    #   4. continue the normal JOIN flow with the plaintext ha_password
    #   5. on success: unlink both files (cluster cert is now the JOIN
    #      credential; subsequent boots REJOIN-by-cert)
    # ha_bootstrap_vault_url defaults to ha_primary_url. Override only when
    # the bootstrap key lives on a different rhorizon.
    ha_password_storage: str = "file"
    ha_password_age_path: str = ""
    ha_bootstrap_token_file: str = ""
    ha_bootstrap_secret_name: str = "ha-bootstrap"
    ha_bootstrap_namespace: str = "cluster-ha"
    ha_bootstrap_vault_url: str = ""
    audit_retention_days: int = 365  # min retention before delete (1-10y)
    audit_compress_days: int = 1  # compress files older than N days
    # How long the audit chain and checkpointed audit-lite prefix stay in the
    # database. Distinct from
    # audit_retention_days, which is a compliance floor on the archive FILES
    # (1-10 years): the database holds a working set for querying and for
    # /audit/verify, and a year of it is neither walkable nor cheap. Rows past
    # this window are pruned only once their day is sealed and that seal still
    # verifies, so the archive provably holds what the database drops.
    #
    # Ceilinged at audit_retention_days below, for the same reason
    # audit_compress_days is: pruning a row whose archive file has already
    # been deleted would put a hole in the record that nothing detects.
    audit_db_retention_days: int = 30
    # Pruning DELETES chain rows from the database once the archive provably
    # holds them. ON by default: nothing is lost, because a day is pruned only
    # when it is past the window, SEALED (its archive cross-checked against the
    # database rows while both copies still existed), and its seal still
    # verifies against the file -- with an anchor written first, in the same
    # transaction, so the surviving chain stays verifiable and over-deletion
    # beyond the anchor is still reported as a break.
    #
    # Left as a switch rather than removed so an operator can keep the whole
    # chain in the database if they want it there; raising
    # audit_db_retention_days (up to audit_retention_days) says the same thing
    # with a window instead.
    audit_db_prune_enabled: bool = True

    # Critical audit + notification fan-out. Secrets matching any of these
    # comma-separated fnmatch globs have their write actions flagged
    # critical in the audit chain (detail._critical=true, inside the signed
    # payload so it is tamper-evident) and trigger a fan-out to all enabled
    # channels subscribed to event "critical". Defaults cover the recovery
    # handles minted by bootstrap.yml: an unexpected overwrite is a
    # tampering signal.
    audit_critical_secret_patterns: str = (
        "rhorizon-ha-root-token-primary,rhorizon-ha-password"
    )
    webauthn_rp_id: str = "localhost"  # Relying Party ID (domain)
    webauthn_rp_name: str = "rhorizon"  # human-readable RP name
    max_body_bytes: int = 1_048_576  # 1 MB default for API requests
    max_body_backup: int = 104_857_600  # 100 MB for backup restore
    rate_limit_whitelist: str = ""  # comma-separated IPs, never rate-limited
    # Sliding window (seconds) for rate-limit failure counting. A failing IP
    # that goes quiet longer than this has its counter RESET on its next failure
    # instead of incremented -- so an old burst can't permanently lock a
    # legitimate IP (the counter is cumulative and token auth never clears it on
    # success). Default = the top-tier lockout (RATE_LIMITS), so escalation only
    # accumulates within one window.
    rate_limit_findtime: int = 3600
    # Admission control / load shedding: per-worker cap on in-flight HTTP
    # requests; those above it get an immediate 429 + Retry-After instead
    # of queueing to the 10s timeout. Bounds the pile-up that, under
    # congestion collapse, starves the event loop and the cluster
    # coordination loops (heartbeat / master-RPC). 0 = disabled. ~2-4x the
    # DB pool is a sane start; small nodes want it low (e.g. 32).
    max_concurrent_requests: int = 0
    authfail_log: str = "/var/log/rhorizon/authfail.log"  # fail2ban-ready log

    # Proxies allowed to supply X-Forwarded-For for audit, rate limiting and
    # token IP ACLs. Private ranges keep the bundled nginx deployment working;
    # this list never authorizes identity headers.
    xff_trusted_ips: str = (
        "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
    )

    # SSO and mTLS identity proxies (Authelia / Authentik / Keycloak / nginx).
    proxy_auth_enabled: bool = False
    proxy_user_header: str = "Remote-User"
    proxy_groups_header: str = "Remote-Groups"
    # Identity trust stays empty by default. Enabling proxy auth or cluster HA
    # requires explicit addresses so a generic frontend proxy cannot
    # accidentally become an authentication authority.
    proxy_trusted_ips: str = ""
    proxy_session_ttl_hours: int = 8

    # Per-worker Shamir share distribution in multi-worker mode; see
    # docs/multiworker.md. Single-worker mode keeps keys in-process.
    # At 0 both auto-derive: total = max(5, workers), threshold = majority.
    cluster_shamir_total: int = 0
    cluster_shamir_threshold: int = 0

    # Prometheus metrics. When enabled, GET /metrics returns text-format
    # exposition, restricted to the CIDRs below (the monitoring host). An
    # empty list disables /metrics even when metrics_enabled=true (fail-closed).
    metrics_enabled: bool = True
    metrics_allowed_cidrs: str = "127.0.0.1/32"

    # GET /audit/verify while SEALED: bearer auth is impossible when sealed (the
    # hmac_key is gone), but the ed25519-signed portion of the chain can still be
    # verified with public keys. To allow that without a token, the caller must
    # come from one of these CIDRs (direct peer IP, X-Forwarded-For ignored --
    # trust = network perimeter, same model as /metrics). Empty (default) =
    # sealed verify is DISABLED (fail-closed); unsealed verify always needs an
    # audit:r bearer regardless of this list.
    audit_verify_allowed_cidrs: str = ""
    # Incremental evidence checks trust the historical prefix attested by the
    # newest independently signed full-verification anchor. Older anchors make
    # the result explicit `incomplete`; they never silently become permanent
    # cache entries. A full verification remains available through /verify/jobs.
    audit_verify_anchor_max_age_seconds: int = 86400

    # Backup/restore (see routes/backup.py, routes/tokens.py).
    # restore_rotation_grace_days : reaper purge window for pending token
    # stubs no admin has rotated yet. Past this the stub disappears
    # (equivalent to a late revocation).
    restore_rotation_grace_days: int = 30
    # recovery_token_ttl_days : auto-expiry of the root-restore-<ts> admin
    # token minted at the first unseal post-restore. The admin uses it to
    # rotate the pending stubs and rebuild a normal setup, then dismisses
    # the post-restore panel (auto-revokes the token) or lets it expire here.
    recovery_token_ttl_days: int = 7

    @field_validator("database_ssl", mode="before")
    @classmethod
    def _normalize_database_ssl(cls, v) -> str:
        # Accept the legacy bool/string forms and map to the 3-state enum.
        if isinstance(v, bool):
            return "require" if v else "disable"
        s = str(v).strip().lower()
        s = {
            "true": "require",
            "1": "require",
            "yes": "require",
            "on": "require",
            "false": "disable",
            "0": "disable",
            "no": "disable",
            "off": "disable",
            "": "require",
        }.get(s, s)
        if s not in {"disable", "require", "verify-full"}:
            raise ValueError(
                f"database_ssl must be disable|require|verify-full (got {v!r})"
            )
        return s

    @field_validator("secret_grace_seconds")
    @classmethod
    def clamp_secret_grace_seconds(cls, v: int) -> int:
        # 0 disables the rotation grace window; cap at 1 day so a stale value
        # can never linger readable longer than the master-password lazy window.
        return max(0, min(86400, v))

    @field_validator("xff_trusted_ips", "proxy_trusted_ips")
    @classmethod
    def validate_proxy_trusted_ips(cls, value: str) -> str:
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid trusted proxy IP/network: {entry}") from exc
        return value

    @field_validator("memory_lock_mode", mode="before")
    @classmethod
    def _validate_memory_lock_mode(cls, value: object) -> str:
        mode = str(value).strip().lower().replace("_", "-")
        if mode not in {"best-effort", "required"}:
            raise ValueError("memory_lock_mode must be best-effort or required")
        return mode

    @field_validator("workers")
    @classmethod
    def validate_workers(cls, v: int) -> int:
        if v < 1:
            return 1
        if v > 255:
            raise ValueError("workers cannot exceed the Shamir limit of 255")
        return v

    @field_validator("rate_limit_findtime")
    @classmethod
    def clamp_rate_limit_findtime(cls, v: int) -> int:
        # Floor at 60s: a sub-minute (or 0/negative) window would reset the
        # counter on nearly every failure, silently disabling lockout escalation.
        return max(60, v)

    @field_validator("audit_retention_days")
    @classmethod
    def clamp_audit_retention(cls, v: int) -> int:
        return max(365, min(3650, v))

    @field_validator("audit_compress_days")
    @classmethod
    def clamp_audit_compress(cls, v: int, info: ValidationInfo) -> int:
        # Floor 1 keeps today's still-open file safe from the reaper.
        # Ceiling = retention so files become eligible for compression no later
        # than they become eligible for deletion.
        retention = info.data.get("audit_retention_days", 365)
        return max(1, min(retention, v))

    @field_validator("audit_db_retention_days")
    @classmethod
    def clamp_audit_db_retention(cls, v: int, info: ValidationInfo) -> int:
        # Ceiling = file retention: the database may never outlive the archive
        # it will be pruned in favour of. Floor 1 keeps today's rows.
        retention = info.data.get("audit_retention_days", 365)
        return max(1, min(retention, v))

    @field_validator("audit_lite_checkpoint_interval_secs")
    @classmethod
    def clamp_audit_lite_checkpoint_interval(cls, v: int) -> int:
        # `audit_lite_checkpoint_enabled` disables the loop. Keep the interval
        # itself sane so zero or a typo cannot create a tight DB loop.
        return max(5, min(3600, v))

    @field_validator("audit_lite_checkpoint_max_rows")
    @classmethod
    def clamp_audit_lite_checkpoint_max_rows(cls, v: int) -> int:
        return max(1, min(100000, v))

    @field_validator("audit_verify_anchor_max_age_seconds")
    @classmethod
    def clamp_audit_verify_anchor_max_age(cls, v: int) -> int:
        return max(60, min(30 * 86400, v))

    @field_validator("restore_rotation_grace_days")
    @classmethod
    def clamp_restore_rotation_grace(cls, v: int) -> int:
        return max(7, min(90, v))

    @field_validator("recovery_token_ttl_days")
    @classmethod
    def clamp_recovery_token_ttl(cls, v: int) -> int:
        return max(1, min(30, v))

    @field_validator("cluster_challenge_ttl_secs")
    @classmethod
    def clamp_cluster_challenge_ttl(cls, v: int) -> int:
        # 5s floor avoids fat-fingered config nuking the JOIN flow ;
        # 5 min ceiling caps the replay window of a sniffed nonce.
        return max(5, min(300, v))

    @field_validator("cluster_advertise_ip")
    @classmethod
    def validate_cluster_advertise_ip(cls, v: str) -> str:
        value = v.strip()
        if not value:
            return ""
        # Store a canonical literal (including compressed IPv6), never a DNS
        # name whose resolution could change independently of membership.
        return str(ipaddress.ip_address(value))

    @field_validator("cluster_join_quarantine_secs")
    @classmethod
    def clamp_cluster_join_quarantine(cls, v: int) -> int:
        # 0 = no quarantine (joining -> secondary immediately) is
        # accepted ; ceiling 3600s = 1h to avoid an operator typo
        # leaving a node stranded forever.
        return max(0, min(3600, v))

    @field_validator("cluster_heartbeat_interval_secs")
    @classmethod
    def clamp_cluster_heartbeat_interval(cls, v: int) -> int:
        # 1s floor matches the worker heartbeat ; 60s ceiling
        # keeps the cluster failover window bounded.
        return max(1, min(60, v))

    @field_validator("cluster_state_machine_interval_secs")
    @classmethod
    def clamp_cluster_state_machine_interval(cls, v: int) -> int:
        # 1s floor avoids a busy loop ; 60s ceiling matches the
        # heartbeat ceiling.
        return max(1, min(60, v))

    @field_validator("cluster_joining_orphan_ttl_secs")
    @classmethod
    def clamp_cluster_joining_orphan_ttl(cls, v: int) -> int:
        # 10s floor avoids reaping nodes mid-JOIN. The 4200s ceiling covers
        # maximum quarantine plus the maximum loop interval.
        return max(10, min(4200, v))

    @field_validator("cluster_reaper_interval_secs")
    @classmethod
    def clamp_cluster_reaper_interval(cls, v: int) -> int:
        # 5s floor (reaping is cheap); 600s ceiling (10 min) bounds how
        # long an expired orphan remains visible before the next scan.
        return max(5, min(600, v))

    @field_validator("cluster_primary_lease_ttl_secs")
    @classmethod
    def clamp_cluster_primary_lease_ttl(cls, v: int, info: ValidationInfo) -> int:
        # Allow two missed renewal opportunities before the lease expires.
        # Reject an unsafe combination instead of silently increasing failover
        # convergence time.
        ttl = max(5, min(3600, v))
        heartbeat = info.data.get("cluster_heartbeat_interval_secs", 3)
        if ttl < 3 * heartbeat:
            raise ValueError(
                "cluster_primary_lease_ttl_secs must be at least three times "
                "cluster_heartbeat_interval_secs"
            )
        return ttl

    @model_validator(mode="after")
    def _keep_auto_promote_cooldown_coherent(self) -> "Settings":
        # Zero explicitly disables the anti-thrash dwell. Otherwise a returning
        # former primary must remain secondary for at least one full lease.
        if (
            self.cluster_auto_promote_cooldown_secs != 0
            and self.cluster_auto_promote_cooldown_secs
            < self.cluster_primary_lease_ttl_secs
        ):
            self.cluster_auto_promote_cooldown_secs = (
                self.cluster_primary_lease_ttl_secs
            )
        return self

    @field_validator("standalone_db_freeze_secs")
    @classmethod
    def clamp_standalone_db_freeze(cls, v: int) -> int:
        # 3s floor: the probe interval is derived as freeze // 3, so anything
        # lower would poll faster than once a second for no benefit.
        return max(3, min(3600, v))

    @field_validator("standalone_db_seal_secs")
    @classmethod
    def clamp_standalone_db_seal(cls, v: int) -> int:
        # No zero: "freeze but never seal" would waive the invariant that
        # ambiguity ends sealed. 15s floor still rides a systemd restart.
        return max(15, min(86400, v))

    @field_validator("cluster_frozen_max_secs")
    @classmethod
    def clamp_cluster_frozen_max(cls, v: int) -> int:
        # No zero: retaining keys indefinitely on an unresolved node waives the
        # invariant that ambiguity ends sealed. 30s floor gives a partition
        # room to heal; 86400 bounds the accidental "effectively forever".
        return max(30, min(86400, v))

    @field_validator("cluster_operator_weight")
    @classmethod
    def clamp_cluster_operator_weight(cls, v: float) -> float:
        # Strict positive ; zero/negative would either tie with every
        # other candidate or invert the bias. NaN check via self-
        # inequality (NaN != NaN by IEEE 754). +inf trapped explicitly
        # (would zero the jitter ceiling and break the randbelow call).
        # All rejected values default to 1.0 (uniform).
        if v != v or v == float("inf") or v <= 0:
            return 1.0
        return v

    @field_validator("cluster_auto_promote_cooldown_secs")
    @classmethod
    def clamp_cluster_auto_promote_cooldown(cls, v: int) -> int:
        # 0 = gate disabled (a node is promote-eligible the instant it
        # lands in 'secondary'). 3600s ceiling caps how long a healed
        # ex-primary can be held out of the election pool. Negatives
        # collapse to 0 (disabled) rather than inverting the comparison.
        return max(0, min(3600, v))

    @field_validator("cluster_join_idempotency_ttl_secs")
    @classmethod
    def clamp_cluster_join_idempotency_ttl(cls, v: int) -> int:
        # 60s floor covers transient-503 retry windows; 3600s ceiling
        # caps stale database retention vs. recovery flexibility.
        return max(60, min(3600, v))

    @field_validator("cluster_pending_ha_rotation_ttl_secs")
    @classmethod
    def clamp_cluster_pending_ha_rotation_ttl(cls, v: int) -> int:
        # 300s floor (5 min) avoids accidental immediate expiry on a
        # human-paced confirm ; 86400s ceiling (24h) caps a forgotten
        # intent. The pending row is metadata-only so the TTL does not
        # bound an at-rest plaintext window.
        return max(300, min(86400, v))

    @field_validator("cluster_drain_deadline_secs")
    @classmethod
    def clamp_cluster_drain_deadline(cls, v: int) -> int:
        return max(5, min(600, v))

    @field_validator(
        "database_ha_max_replica_lag_bytes", "patroni_max_replica_lag_bytes"
    )
    @classmethod
    def clamp_database_ha_max_replica_lag(cls, v: int) -> int:
        # 0 is a valid strict mode. The 1 TiB ceiling catches unit mistakes
        # without preventing deliberately large archive-backed deployments.
        return max(0, min(1 << 40, v))

    @field_validator("database_ha_status_max_age_secs")
    @classmethod
    def clamp_database_ha_status_max_age(cls, v: int) -> int:
        return max(3, min(300, v))

    @field_validator("cluster_shamir_spare_shares")
    @classmethod
    def clamp_cluster_shamir_spare_shares(cls, v: int) -> int:
        # 0 restores the old exhaust-on-startup behaviour. The ceiling keeps
        # quorum_base + spares under the 255-share GF(256) limit even with a
        # large worker count; _shamir_total_threshold clamps the sum as well.
        return max(0, min(200, v))

    @field_validator("custody_mode")
    @classmethod
    def normalize_custody_mode(cls, v: str) -> str:
        mode = v.strip().lower().replace("-", "_")
        if mode not in {"embedded", "separated"}:
            raise ValueError("must be embedded or separated")
        return mode

    @field_validator("custody_backend")
    @classmethod
    def normalize_custody_backend(cls, v: str) -> str:
        backend = v.strip().lower().replace("-", "_")
        if backend not in {"python", "rust"}:
            raise ValueError("must be python or rust")
        return backend

    @field_validator("rust_custodian_slots")
    @classmethod
    def validate_rust_custodian_slots(cls, v: int) -> int:
        if v not in {3, 5, 7, 9}:
            raise ValueError("must be one of 3, 5, 7, or 9")
        return v

    @field_validator("cluster_master_timeout_secs")
    @classmethod
    def validate_cluster_master_timeout(cls, v: float) -> float:
        if not 5.0 <= v <= 900.0:
            raise ValueError("must be between 5 and 900 seconds")
        return v

    @field_validator("cluster_master_watch_interval_secs")
    @classmethod
    def validate_cluster_master_watch_interval(cls, v: float) -> float:
        if not 1.0 <= v <= 450.0:
            raise ValueError("must be between 1 and 450 seconds")
        return v

    @field_validator("cluster_rpc_timeout_secs")
    @classmethod
    def validate_cluster_rpc_timeout(cls, v: float) -> float:
        if not 1.0 <= v <= 900.0:
            raise ValueError("must be between 1 and 900 seconds")
        return v

    @field_validator("rust_custody_maintenance_interval_secs")
    @classmethod
    def validate_rust_custody_maintenance_interval(cls, v: float) -> float:
        if not 1.0 <= v <= 300.0:
            raise ValueError("must be between 1 and 300 seconds")
        return v

    @field_validator("process_role")
    @classmethod
    def normalize_process_role(cls, v: str) -> str:
        role = v.strip().lower().replace("-", "_")
        if role not in {"api", "custodian"}:
            raise ValueError("must be api or custodian")
        return role

    @field_validator("custodian_workers")
    @classmethod
    def validate_custodian_workers(cls, v: int) -> int:
        # A majority quorum needs an odd fixed pool. Keep the initial surface
        # intentionally small; larger pools add share traffic without
        # improving the local process-failure model.
        if v not in {3, 5, 7, 9}:
            raise ValueError("must be one of 3, 5, 7, or 9")
        return v

    @field_validator("custodian_uds_path", "custodian_token_file")
    @classmethod
    def validate_custodian_runtime_path(cls, v: str) -> str:
        path = Path(v)
        if not path.is_absolute():
            raise ValueError("must be an absolute path")
        if path == Path("/"):
            raise ValueError("must not be the filesystem root")
        return str(path)

    @model_validator(mode="after")
    def _failover_timing_invariant(self) -> "Settings":
        """The three timeouts are only meaningful in relation to each other.

        Tuning one in isolation is how an operator lengthens the master
        timeout to survive an IO stall and then discovers every request still
        fails at the old RPC deadline, or shortens the RPC deadline and turns
        a healthy pause into a request storm. Checked here so a broken
        combination cannot start rather than being discovered under load.
        """
        if self.cluster_master_watch_interval_secs > self.cluster_master_timeout_secs:
            raise ValueError(
                "cluster_master_watch_interval_secs must not exceed "
                "cluster_master_timeout_secs, or master loss is detected a "
                "full poll after the deadline it is supposed to enforce"
            )
        if self.cluster_rpc_timeout_secs <= self.cluster_master_timeout_secs:
            raise ValueError(
                "cluster_rpc_timeout_secs must exceed cluster_master_timeout_secs, "
                "or a stalled-but-alive master fails every in-flight request "
                "before the cluster has decided whether it is gone"
            )
        return self

    @model_validator(mode="after")
    def _separated_custody_role_invariant(self) -> "Settings":
        if self.custody_backend == "rust":
            if self.custody_mode != "separated":
                raise ValueError("custody_backend=rust requires custody_mode=separated")
            if self.process_role != "api":
                raise ValueError("Rust custodians are standalone, not Python roles")
            threshold = self.rust_custodian_threshold
            if threshold == 0:
                threshold = self.rust_custodian_slots // 2 + 1
                object.__setattr__(self, "rust_custodian_threshold", threshold)
            if threshold < 2 or threshold > self.rust_custodian_slots:
                raise ValueError(
                    "rust_custodian_threshold must be between 2 and slot count"
                )
        if self.process_role == "custodian" and self.custody_mode != "separated":
            raise ValueError("process_role=custodian requires custody_mode=separated")
        # Only processes that actually hold Shamir shares need the historical
        # five-participant floor. Disposable separated API pools may use any
        # positive size; custodian pools have their own explicit odd-quorum
        # validator and the launcher sets ``workers`` to that value.
        if self.custody_mode == "embedded" and 1 < self.workers < 5:
            object.__setattr__(self, "workers", 5)
        if self.process_role == "custodian" and self.workers != self.custodian_workers:
            object.__setattr__(self, "workers", self.custodian_workers)
        return self

    @field_validator("worker_reap_stale_secs")
    @classmethod
    def clamp_worker_reap_stale(cls, v: int) -> int:
        # Floor well above HEARTBEAT_INTERVAL_SECS so a brief stall cannot
        # reap a live worker.
        return max(30, min(3600, v))

    @field_validator("database_ha_lag_grace_secs")
    @classmethod
    def clamp_database_ha_lag_grace(cls, v: int) -> int:
        # 0 restores the old fire-on-first-sample behaviour. The 1 h ceiling
        # keeps the grace window well under any sane alert-response time.
        return max(0, min(3600, v))

    @field_validator("database_ha_provider")
    @classmethod
    def normalize_database_ha_provider(cls, v: str) -> str:
        provider = v.strip().lower().replace("-", "_")
        provider = {"rhorizon_pgha": "pgha", "disabled": "none"}.get(provider, provider)
        if provider not in {"auto", "patroni", "pgha", "none"}:
            raise ValueError("must be auto, patroni, pgha, or none")
        return provider

    @field_validator("cluster_node_cert_validity_days")
    @classmethod
    def clamp_cluster_node_cert_validity(cls, v: int) -> int:
        # 7d floor avoids impractically short-lived membership certificates.
        # 366d ceiling: long-lived membership certs blunt the "revocable
        # instantly" property -- past a year the operator should rotate the
        # cluster CA instead.
        return max(7, min(366, v))

    @field_validator("cluster_server_cert_validity_days")
    @classmethod
    def clamp_cluster_server_cert_validity(cls, v: int) -> int:
        # Same bounds as the node cert (cluster_ca mints both). Without the
        # floor a 0/negative value would yield a server cert born expired
        # (NotAfter <= NotBefore) and break TLS / churn the renewal loop.
        return max(7, min(366, v))

    @field_validator("cluster_cert_renewal_threshold_days")
    @classmethod
    def clamp_cluster_cert_renewal_threshold(cls, v: int, info: ValidationInfo) -> int:
        # Threshold must be strictly less than validity, otherwise the
        # renewal loop refreshes on every tick.
        validity = info.data.get("cluster_node_cert_validity_days", 90)
        ceiling = max(1, validity - 1)
        return max(1, min(ceiling, v))

    @field_validator("cluster_cert_renewal_poll_secs")
    @classmethod
    def clamp_cluster_cert_renewal_poll(cls, v: int) -> int:
        # 1 min floor (no point polling faster than the renewal flow can
        # complete) ; 1 day ceiling (a 30-day threshold means a daily
        # poll is the slowest cadence that still catches renewals in time).
        return max(60, min(86400, v))

    @field_validator("cluster_ca_grace_window_secs")
    @classmethod
    def clamp_cluster_ca_grace_window(cls, v: int, info: ValidationInfo) -> int:
        # Allow two renewal polls so a node gets an initial attempt and one
        # retry before the previous CA stops authenticating it.
        renewal_poll = info.data.get("cluster_cert_renewal_poll_secs", 43200)
        floor = max(3600, 2 * renewal_poll)
        return max(floor, min(2592000, v))

    @field_validator("ha_auto_join_max_attempts")
    @classmethod
    def clamp_ha_auto_join_max_attempts(cls, v: int) -> int:
        return max(1, min(100, v))

    @field_validator("ha_auto_join_retry_secs")
    @classmethod
    def clamp_ha_auto_join_retry_secs(cls, v: int) -> int:
        # 5s floor avoids a tight retry loop on transient network errors ;
        # 600s ceiling caps the gap before the cluster section surfaces
        # the warning.
        return max(5, min(600, v))

    @model_validator(mode="after")
    def _keep_cert_renewal_threshold_below_validity(self) -> "Settings":
        ceiling = (
            min(
                self.cluster_node_cert_validity_days,
                self.cluster_server_cert_validity_days,
            )
            - 1
        )
        if self.cluster_cert_renewal_threshold_days > ceiling:
            object.__setattr__(
                self,
                "cluster_cert_renewal_threshold_days",
                ceiling,
            )
        return self

    @model_validator(mode="after")
    def _enforce_orphan_ttl_after_quarantine(self) -> "Settings":
        # Invariant: the joining-orphan reaper must not be able to purge a
        # healthy joiner before it has had a chance to flip to 'secondary'.
        # The flip becomes eligible at joined_at + cluster_join_quarantine_secs;
        # Give the state machine at least one poll after eligibility, while
        # preserving the reaper margin when it is slower. Bump (never lower)
        # the orphan TTL so operator overrides cannot recreate the race.
        margin = max(
            self.cluster_state_machine_interval_secs,
            self.cluster_reaper_interval_secs,
        )
        floor = self.cluster_join_quarantine_secs + margin
        if self.cluster_joining_orphan_ttl_secs < floor:
            object.__setattr__(self, "cluster_joining_orphan_ttl_secs", floor)
        # A deployment that only set the old Patroni lag knob keeps its exact
        # behavior while the API and metrics move to the provider-neutral name.
        fields_set = self.model_fields_set
        if (
            "database_ha_max_replica_lag_bytes" not in fields_set
            and "patroni_max_replica_lag_bytes" in fields_set
        ):
            object.__setattr__(
                self,
                "database_ha_max_replica_lag_bytes",
                self.patroni_max_replica_lag_bytes,
            )
        return self

    @model_validator(mode="after")
    def _require_trusted_proxy_for_forwarded_identity(self) -> "Settings":
        if (
            self.proxy_auth_enabled or self.cluster_ha_enabled
        ) and not self.proxy_trusted_ips.strip():
            raise ValueError(
                "proxy_trusted_ips is required when proxy authentication "
                "or cluster HA is enabled"
            )
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        # RH_* is the canonical env prefix product-wide (see env_prefix below).
        # Read the deprecated RHORIZON_* names too, at LOWER priority, so existing
        # deployments keep working; RH_* wins when both are set.
        legacy_env = EnvSettingsSource(settings_cls, env_prefix="RHORIZON_")
        return (
            init_settings,
            env_settings,
            legacy_env,
            dotenv_settings,
            file_secret_settings,
        )

    model_config = {"env_prefix": "RH_"}


settings = Settings()
