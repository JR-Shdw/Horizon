# Environment variables

The commonly-tuned `RH_*` knobs, plus the agent envs.

**`api/app/config.py` is the authoritative list** - 93 settings today, and it
carries the rationale for each in comments. This page is a curated subset; the
cluster/HA knobs live in [HA-CLUSTER.md](https://github.com/JR-Shdw/Horizon/blob/main/docs/HA-CLUSTER.md)
and the auth/proxy ones in [DEPLOYMENT.md](https://github.com/JR-Shdw/Horizon/blob/main/docs/DEPLOYMENT.md),
so they are not duplicated here. To enumerate everything:

```bash
grep -nE '^    [a-z][a-z0-9_]*\s*:' api/app/config.py
```

Any setting `foo_bar` is set as `RH_FOO_BAR`.

> **Prefix.** `RH_*` is canonical product-wide. The legacy `RHORIZON_*`
> prefix is a deprecated alias that still works (e.g. `RHORIZON_WORKERS`
> == `RH_WORKERS`); when both are set, `RH_*` wins. Use `RH_*` for new
> setups.

## API process

| Var | Default | Meaning |
|-----|---------|---------|
| `RH_DATABASE_URL` | `postgresql+asyncpg://rhorizon:rhorizon@postgres:5432/rhorizon` | asyncpg DSN (host `postgres` = the compose service name) |
| `RH_DATABASE_SSL` | `require` | PG TLS mode, 3-state: `disable` (plaintext, same-host only), `require` (encrypt, no cert verify), `verify-full` (encrypt + verify against `RH_DATABASE_CA_CERT`). Legacy booleans are coerced: `true`->`require`, `false`->`disable` |
| `RH_DATABASE_CA_CERT` | `""` | CA/cert bundle pinned under `verify-full`; empty = system trust store |
| `RH_WORKERS` | `5` | Public API workers. In `embedded` custody, `1` is the single-worker path and `2`-`4` are floored to 5. In `separated` custody, any value from 1 to 255 is valid. |
| `RH_CUSTODY_MODE` | `embedded` | `embedded` keeps the compatibility worker model. `separated` starts a fixed UDS-only custodian quorum beside the disposable API pool. Container launcher only in this release. |
| `RH_CUSTODY_BACKEND` | `python` | Custodian implementation in separated mode. `rust` is an explicit standalone canary with password activation, master-password rotation, and `dek_key` rotation; unsupported restore and Shamir routes fail closed. |
| `RH_CUSTODIAN_WORKERS` | `5` | Fixed custodian processes in separated mode: `3`, `5`, `7`, or `9`. Default threshold is the majority. |
| `RH_RUST_CUSTODIAN_SLOTS` | `3` | Fixed standalone Rust slots: `3`, `5`, `7`, or `9`. |
| `RH_RUST_CUSTODIAN_THRESHOLD` | `0` | Rust quorum threshold. `0` selects the majority. |
| `RH_RUST_CUSTODIAN_KEY_DIR` | `/var/lib/rhorizon/custody` | Per-slot transport keys and persisted share state. |
| `RH_RUST_CUSTODY_MAINTENANCE_INTERVAL_SECS` | `5` | Single-leader slot health and repair interval, from 1 to 300 seconds. |
| `RH_MEMORY_LOCK_MODE` | `best-effort` | Continue with reported degradation when locking fails, or use `required` to fail closed for buffer locks and for whole-process locking while swap is exposed |
| `RH_SWAP_PROTECTION` | auto-detect natively; `unknown` in containers | Host/node swap state: `protected`, `unencrypted`, or `unknown`. The Docker installer writes its host-side result. Read directly from the environment by `api/app/mem_hardening.py`, not a Pydantic setting |
| `RH_DYNAMIC_MODULES_FILE` | `dynamic-engines.ini` | Closed-catalog dynamic backend selection; restart every API worker after changes |
| `RH_CLUSTER_SHAMIR_TOTAL` | `0` | 0 = custody pool size plus `RH_CLUSTER_SHAMIR_SPARE_SHARES`; override only for an asymmetric quorum |
| `RH_CLUSTER_SHAMIR_THRESHOLD` | `0` | 0 = majority of the active custody pool; M-of-N quorum for failover |
| `RH_CLUSTER_SHAMIR_SPARE_SHARES` | `8` | Unassigned shares from the same polynomial, reserved for replacing failed custody processes without a manual unseal |
| `RH_DATABASE_HA_PROVIDER` | `auto` | Database-HA status provider: `patroni`, `pgha`, `auto`, or `none`; `auto` preserves legacy Patroni configuration and selects pgha for generic status URLs |
| `RH_DATABASE_HA_STATUS_URLS` | empty | Comma-separated provider status base URLs: Patroni REST (`:8008`) or pgha agent status (`:8010`) |
| `RH_DATABASE_HA_MAX_REPLICA_LAG_BYTES` | `16777216` | Maximum known replica lag allowed for a green `database_ha` component |
| `RH_DATABASE_HA_STATUS_MAX_AGE_SECS` | `15` | Maximum age of a pgha agent control-loop report before database HA becomes orange |
| `RH_DATABASE_HA_LAG_GRACE_SECS` | `60` | How long a replica-lag breach must persist before `database_ha` reports it. Write bursts cross the threshold for a few seconds and recover; reporting each blip trains operators to ignore the check. `0` restores fire-on-first-sample |
| `RH_PATRONI_REST_URLS` | empty | Deprecated compatibility alias for existing Patroni deployments |
| `RH_PATRONI_MAX_REPLICA_LAG_BYTES` | `16777216` | Deprecated compatibility alias for the database-HA lag budget |
| `RH_DEK_KEY_MAX_AGE_DAYS` | `30` | Stale alert threshold for `dek_key` |
| `RH_EPHEMERAL_MAX_TTL` | `86400` | Cap for ephemeral token TTL (24 h) |
| `RH_NAMESPACE_MUTATION_RATE_PER_HOUR` | `10` | Per-actor cap on namespace ops |
| `RH_SOFT_DELETE_RETENTION_DAYS` | `7` | Soft-mode reaper window |
| `RH_PROTECTED_DELETE_RETENTION_DAYS` | `365` | Protected-mode reaper window (0 = never) |
| `RH_AUDIT_DIR` | `/var/log/rhorizon` | JSONL audit files |
| `RH_AUDIT_RETENTION_DAYS` | `365` | Min before delete (range 365-3650) |
| `RH_AUDIT_DB_RETENTION_DAYS` | `30` | Database window for the audit chain and checkpointed audit-lite rows; older prefixes are dropped only after their sealed archives verify |
| `RH_AUDIT_DB_PRUNE_ENABLED` | `true` | Archive, seal and prune audit database prefixes after the database retention window |
| `RH_AUDIT_COMPRESS_DAYS` | `1` | gzip after N days (clamped to `[1, retention_days]`) |
| `RH_WEBAUTHN_RP_ID` | `localhost` | Relying Party ID |
| `RH_WEBAUTHN_RP_NAME` | `rhorizon` | RP operator name |
| `RH_MAX_BODY_BYTES` | `1048576` | 1 MB API body cap |
| `RH_MAX_BODY_BACKUP` | `104857600` | 100 MB cap on `/backup/restore` |
| `RH_RATE_LIMIT_WHITELIST` | `""` | CSV of IPs immune to rate limit |
| `RH_AUTHFAIL_LOG` | `/var/log/rhorizon/authfail.log` | fail2ban-ready log |
| `RH_XFF_TRUSTED_IPS` | loopback, RFC 1918 and IPv6 ULA | Proxies allowed to supply `X-Forwarded-For`; does not authorize identity headers |
| `RH_PROXY_TRUSTED_IPS` | `""` | SSO/mTLS identity proxy CIDRs; required when proxy auth or cluster HA is enabled |
| `RH_AUTO_SEAL_MINUTES` | `0` | Auto-seal after N minutes idle; `0` = never (the recommended posture) |
| `RH_MAX_CONCURRENT_REQUESTS` | `0` | Per-worker in-flight cap; above it, requests get `429 capacity_overloaded` + `Retry-After`. **`0` disables load shedding** - set it in production, ~2-4x the DB pool |
| `RH_SECRET_GRACE_SECONDS` | `0` | Rotation grace: prior secret value stays readable via `?previous=true` for this long. `0` = off (opt-in), clamped to 1 day |
| `RH_SECRET_MAX_VERSIONS` | see config | Version history retained per secret |
| `RH_TOKEN_MIGRATION_WINDOW_DAYS` | `15` | How long the previous `hmac_key` stays valid after a non-emergency master-password rotation, so live tokens re-hash on use |
| `RH_MEMLOCK_ALL` | `true` | `mlockall()` the whole worker address space |
| `RH_DISABLE_CORE_DUMPS` | `true` | `RLIMIT_CORE=0`, so a crash cannot spill plaintext to disk |
| `RH_ENABLE_DOCS` | `false` | Serve `/docs` and `/redoc` (put them behind SSO if enabled at all) |
| `RH_METRICS_ENABLED` | `true` | Serve `GET /metrics` |
| `RH_METRICS_ALLOWED_CIDRS` | `127.0.0.1/32` | CIDRs allowed to scrape `/metrics`. Empty disables the endpoint (fail-closed); ignores `X-Forwarded-For` by design |
| `RH_AUDIT_VERIFY_ALLOWED_CIDRS` | `""` | CIDRs permitted to call `/audit/verify` **while sealed** (bearer auth is impossible then). Empty = nobody |
| `RH_AUDIT_VERIFY_ANCHOR_MAX_AGE_SECONDS` | `86400` | Maximum age of a signed full-verification anchor accepted by incremental preflight (clamped to 60 seconds-30 days) |
| `RH_AUDIT_CRITICAL_SECRET_PATTERNS` | see config | Secret-name patterns whose access raises a critical event |
| `RH_AUDIT_LITE_CHECKPOINT_ENABLED` | `true` | Merkle-checkpoint the read log so reads are tamper-evident |
| `RH_AUDIT_LITE_CHECKPOINT_INTERVAL_SECS` | `60` | How often a read window is sealed into a signed checkpoint |
| `RH_AUDIT_LITE_CHECKPOINT_MAX_ROWS` | `10000` | Max read rows folded into one checkpoint |
| `RH_DEK_KEY_LAZY_CHECK` | `true` | Check `dek_key` age in the reaper loop and alert when stale |
| `RH_RATE_LIMIT_FINDTIME` | `3600` | Counting window for the escalating auth-failure lockout |
| `RH_RECOVERY_TOKEN_TTL_DAYS` | `7` | TTL of the `root-restore-<ts>` token minted after a backup restore |
| `RH_RESTORE_ROTATION_GRACE_DAYS` | `30` | How long post-restore pending token stubs survive before the reaper purges them |

## Frontend (nginx)

| Var | Default | Meaning |
|-----|---------|---------|
| `TLS_ENABLED` | `false` | Listen on `:8443` with mounted certs |
| `TLS_CERT` | `/certs/cert.pem` | Path inside container |
| `TLS_KEY` | `/certs/key.pem` | Path inside container |
| `MAX_BODY_API` | `1m` | nginx `client_max_body_size` for `/api` |
| `MAX_BODY_BACKUP` | `100m` | nginx body size for `/api/v1/vault/backup/restore` |
| `API_UPSTREAM` | `api:8200` | Upstream for `/api` proxy |

## Postgres (in-chart / quickstart compose)

| Var | Default | Meaning |
|-----|---------|---------|
| `POSTGRES_DB` | `rhorizon` | DB name |
| `POSTGRES_USER` | `rhorizon` | App user |
| `POSTGRES_PASSWORD` | (required) | Auto-generated by `install.sh` or Helm |
| `POSTGRES_VERSION` | `18-trixie` | Image tag |

## Quickstart bash (`tools/install.sh`) - container path

These defaults apply when `tools/install.sh` selects Docker/Podman or when
`tools/install-container.sh` is called directly.

| Var | Default | Equivalent flag |
|-----|---------|-----------------|
| `RH_TIER` | `home` | `--tier` (`home`\|`smb`\|`heavy`) |
| `RH_PERSIST` | `false` | `--persist` (auto-start on boot; systemd-only) |
| `RH_DIR` | `~/rhorizon` | `--dir` |
| `RH_API_PORT` | `8200` | `--api-port` |
| `RH_FRONTEND_PORT` | `8443` | `--frontend-port` |
| `RH_FRONTEND_HTTP_PORT` | `8080` | (no flag) |
| `RH_BIND` | `127.0.0.1` | `--bind` |
| `RH_MASTER_PASSWORD` | auto-generated | `--master-password` |
| `RH_REPO_RAW` | `https://raw.githubusercontent.com/JR-Shdw/Horizon/main` | (no flag) |
| `RH_REPO_GIT` | `https://github.com/JR-Shdw/Horizon.git` | (no flag) |

Native mode (`tools/install.sh --mode user|system`, delegated to
`tools/install-native.sh`) uses XDG paths in Linux/*BSD user mode and
OS-native hierarchy paths in system mode. macOS native uses
`tools/install-macos.sh`.

User-mode path defaults:

| Var | Linux/*BSD user | macOS user | Equivalent flag |
|-----|-----------------|------------|-----------------|
| `RH_DIR` | `${XDG_DATA_HOME:-~/.local/share}/rhorizon` | `~/Library/Application Support/rhorizon` | `--dir` |
| `RH_CONFIG_DIR` | `${XDG_CONFIG_HOME:-~/.config}/rhorizon` | `~/Library/Application Support/rhorizon/config` | `--config-dir` |
| `RH_STATE_DIR` | `${XDG_STATE_HOME:-~/.local/state}/rhorizon` | `~/Library/Application Support/rhorizon/state` | `--state-dir` |
| `RH_RUNTIME_DIR` | `$XDG_RUNTIME_DIR/rhorizon`, else `~/.local/state/rhorizon/run` | `$TMPDIR/rhorizon` | `--runtime-dir` |
| `RH_AUDIT_DIR` | `~/.local/state/rhorizon/audit` | `~/Library/Logs/rhorizon` | `--audit-dir` |

System-mode path defaults:

| Var | Linux | FreeBSD | OpenBSD | NetBSD | macOS | Equivalent flag |
|-----|-------|---------|---------|--------|-------|-----------------|
| `RH_DIR` | `/opt/rhorizon` | `/usr/local/rhorizon` | `/usr/local/rhorizon` | `/usr/pkg/rhorizon` | `/Library/Application Support/rhorizon` | `--dir` |
| `RH_CONFIG_DIR` | `/etc/rhorizon` | `/usr/local/etc/rhorizon` | `/etc/rhorizon` | `/usr/pkg/etc/rhorizon` | `/Library/Application Support/rhorizon/config` | `--config-dir` |
| `RH_STATE_DIR` | `/var/lib/rhorizon` | `/var/db/rhorizon` | `/var/db/rhorizon` | `/var/db/rhorizon` | `/Library/Application Support/rhorizon/state` | `--state-dir` |
| `RH_RUNTIME_DIR` | `/run/rhorizon` | `/var/run/rhorizon` | `/var/run/rhorizon` | `/var/run/rhorizon` | `/var/run/rhorizon` | `--runtime-dir` |
| `RH_AUDIT_DIR` | `/var/log/rhorizon` | `/var/log/rhorizon` | `/var/log/rhorizon` | `/var/log/rhorizon` | `/Library/Logs/rhorizon` | `--audit-dir` |

### Sizing (set by `--tier`)

`--tier` writes these into `.env` (`tools/presets/*.env`); override any one
after install. Total RAM is the unsealed stack (PostgreSQL + api + nginx).

| Var | home | smb | heavy |
|-----|------|-----|-------|
| `RH_WORKERS` | 1 | 5 | 10 |
| `RH_API_MEM` | 768M | 1536M | 2560M |
| `POSTGRES_SHARED_BUFFERS` | 128MB | 256MB | 512MB |
| `POSTGRES_EFFECTIVE_CACHE` | 256MB | 512MB | 1536MB |
| `POSTGRES_MAX_CONNECTIONS` | 50 | 200 | 400 |
| `POSTGRES_MEM` | 512M | 1G | 2G |
| `RH_FRONTEND_MEM` | 64M | 64M | 128M |
| **Total RAM** | ~600 MB | ~1.6 GB | ~2.7 GB |

All of these reach `docker-compose.yml`. The three memory limits use a
`${VAR:-default}` fallback, so a deployment with no `.env` gets the historical
defaults (postgres `1G`, api `1536M`, frontend `64M`) unchanged.

These are container **ceilings**, not reservations - the "Total RAM" row is the
expected footprint of the running stack, which sits well under the sum of the
limits.

There is a fourth tier, `super-heavy` (20 workers, `RH_API_MEM` 4608M,
~5 GB total), accepted by `--tier` like the others. See
[DEPLOYMENT.md](https://github.com/JR-Shdw/Horizon/blob/main/docs/DEPLOYMENT.md)
for when it is worth it.

Override any single value in `.env` after install; the tier only seeds them.

## Agent (rh-fetch / rh-inject / rh-watch)

| Var | Read by | Meaning |
|-----|---------|---------|
| `RH_ADDR` | all | API base URL |
| `RH_TOKEN_FILE` | all | Path mode 0400 (preferred over env) |
| `RH_TOKEN` | all | Bearer in env (legacy, `unsetenv`'d after read) |
| `RH_SECRETS` | rh-fetch / rh-watch | `name:/path,name:/path,...` |
| `RH_POLL_SECS` | rh-watch | Default 30, min 5 |
| `RH_RELOAD_PID` | rh-watch | PID to signal on change |
| `RH_RELOAD_SIGNAL` | rh-watch | `HUP` / `USR1` / `USR2` / `TERM` (default `HUP`) |
| `RH_EPHEMERAL` | rh-watch | `true` to mint TTL'd ephemerals |
| `RH_EPHEMERAL_TTL` | rh-watch | Default 3600, range 60-86400 |
