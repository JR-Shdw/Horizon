# HA cluster operations runbook

Operational procedures for an HA deployment: the provider-neutral Database HA
layer it requires, bootstrap, rolling restart, and recovery. For the
architecture and options see [HA-CLUSTER.md](HA-CLUSTER.md).
The normative topology and production acceptance gates are consolidated in
[Production HA reference](HA-PRODUCTION-REFERENCE.md).

## 0. Database HA layer (prerequisite)

The cross-container coordination assumes a highly-available PostgreSQL
underneath. Deploy it once before any HA node JOINs. (Single host, no PG HA?
Skip this section, see [DEPLOYMENT.md](DEPLOYMENT.md).)

Patroni is the reference provider on Linux and in Kubernetes operators.
[`rhorizon-pgha`](PGHA.md)
(`pgha`) is the native provider on FreeBSD, OpenBSD, and NetBSD. Both must
present one stable PostgreSQL write endpoint and status that can be normalized
as the `database_ha` component of `/cluster/health`.

### 0.1 Topology

```mermaid
flowchart TB
    provider["Database HA provider<br/>Patroni+DCS or pgha quorum agents"]
    subgraph PGL["PostgreSQL (PG 18)"]
        pg["database leader + replicas"]
    end
    lbpg["stable write endpoint / VIP<br/>routes only to the database leader"]
    subgraph APP["rhorizon API (hostname-scoped, 5 workers each)"]
        rh["host A / B / C"]
    end
    lbapi["HAProxy + keepalived VIP<br/>/readiness probe"]
    provider --> pg
    pg --> lbpg
    lbpg --> rh
    rh --> lbapi
    lbapi --> clients["clients"]
```

Three shapes:
- **Multi-VM Linux** (reference): 3 VMs API, 3 VMs PG+Patroni+etcd, 2 VMs
  HAProxy+keepalived. Easiest to debug.
- **Multi-host BSD**: 3 hosts PG+`pgha` agents, with the provider supervising
  quorum, promotion, replication, and write-VIP ownership.
- **Docker Swarm**: API as `replicas=3`; PG+Patroni on dedicated VMs **outside**
  Swarm (its rescheduling clashes with PG identity).
- **Kubernetes**: API `Deployment replicas=3`; PG via a PG operator
  StatefulSet (Zalando / CrunchyData / CloudNativePG) - never hand-roll Patroni.

The three leadership roles are separate: the **application primary** owns
rhorizon singleton work, each application container has a **local crypto
master**, and the **database leader** owns PostgreSQL writes. Never assume
changing one role changes either of the other two.

### 0.2 Patroni reference provider

Per node: PG 18 + Patroni 4.x, etcd reachable, NTP, ports open (5432 PG, 8008
Patroni REST, 2379 etcd). Minimal `/etc/patroni/patroni.yml`:

```yaml
scope: rhorizon-pg
name: pg-1                     # unique per node
restapi: { listen: 0.0.0.0:8008, connect_address: 10.0.0.11:8008 }
etcd3:
  hosts: 10.0.0.21:2379,10.0.0.22:2379,10.0.0.23:2379
bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    synchronous_mode: true              # secret writes need durability
    synchronous_mode_strict: false      # fall back to async if no replica
    member_slots_ttl: 10min             # release slots for absent members
    postgresql:
      use_pg_rewind: true
      use_slots: true
      parameters:
        wal_level: replica
        wal_keep_size: 1GB
        max_slot_wal_keep_size: 4GB     # bound stale-slot disk liability
        archive_mode: 'on'
        archive_command: 'pgbackrest --stanza=rhorizon archive-push %p'
  initdb: [ {encoding: UTF8}, data-checksums ]
postgresql:
  listen: 0.0.0.0:5432
  connect_address: 10.0.0.11:5432
  authentication:
    superuser: {username: postgres, password: '{{ PG_SUPERUSER_PASSWORD }}'}
    replication: {username: replicator, password: '{{ PG_REPLICATION_PASSWORD }}'}
  parameters: { ssl: 'on', ssl_cert_file: /etc/patroni/server.crt, ssl_key_file: /etc/patroni/server.key }
```

Repeat for pg-2/pg-3 (change `name`, addresses). `synchronous_mode: true` keeps
every committed write on >=2 nodes. Bootstrap: `systemctl enable --now patroni`
on pg-1 (becomes Leader), then pg-2/pg-3 bootstrap from it. The rhorizon schema
applies itself at API startup (idempotent).

Each rhorizon host points `RH_DATABASE_URL` at the **LB URL**, never a PG
node directly:

```ini
RH_DATABASE_URL=postgresql+asyncpg://rhorizon:${POSTGRES_PASSWORD}@haproxy.local:5432/rhorizon
```

On database failover HAProxy re-points to the new database leader via
`/master`; asyncpg reconnects with one retriable error.

#### BSD-native pgha provider

On FreeBSD, OpenBSD, and NetBSD, configure
`RH_DATABASE_HA_PROVIDER=pgha` and list every agent status endpoint in
`RH_DATABASE_HA_STATUS_URLS`. The agents, not rhorizon application election,
own database quorum, promotion, replication supervision, and the write VIP.
Every agent report must be fresh and agree on one database leader; exactly
that leader must own the VIP. Installation and supervisor commands live in the
rhorizon HA infrastructure repository's
[`pgha` design](PGHA.md)
and
[BSD deployment guide](PGHA.md).

Do not apply `patronictl`, Patroni REST, or DCS procedures to a `pgha`
deployment. Conversely, do not use an application `cluster promote` command
to repair either Database HA provider.

### 0.3 Stable write endpoint and API load balancer

The following reference configuration uses two HAProxy listeners: PostgreSQL
(Patroni database leader via `/master`) and API (ready hosts via
`/readiness`). With `pgha`, its agents own the write VIP; keep the same
invariant that `RH_DATABASE_URL` never targets a member directly.

```
# /etc/haproxy/haproxy.cfg
listen rhorizon-pg
    bind *:5432
    mode tcp
    option httpchk OPTIONS /master
    http-check expect status 200
    default-server inter 3s fall 3 rise 2 on-marked-down shutdown-sessions
    server pg-1 10.0.0.11:5432 check port 8008
    server pg-2 10.0.0.12:5432 check port 8008
    server pg-3 10.0.0.13:5432 check port 8008

listen rhorizon-api
    bind *:8200
    mode http
    option httpchk GET /readiness
    http-check expect status 200
    default-server inter 2s fall 2 rise 2 observe layer7 error-limit 10 on-error mark-down
    server rh-a 10.0.1.11:8200 check
    server rh-b 10.0.1.12:8200 check
    server rh-c 10.0.1.13:8200 check
```

Run two HAProxy instances behind a keepalived VIP. The `/readiness` contract
drives the LB:

| Signal | Code | Meaning | LB action |
|---|---|---|---|
| live process | `200` on `/health` | up (even sealed) | liveness only |
| sealed / quarantined | `503` on `/readiness` | no keys / fenced | **eject** |
| load-shed / recovering | `429` + Retry-After | transient | **back off**, do NOT eject |

k8s: `livenessProbe` on `/health`, `readinessProbe` on `/readiness`. To avoid
the per-worker blind spot, run one worker per pod (`RH_WORKERS=1`, scale
via `replicas`) or add Envoy/Istio `outlierDetection`.

### 0.4 Backup (pgBackRest)

Repo on separate storage, encrypted at rest, shipped offsite for DR:

```ini
# /etc/pgbackrest/pgbackrest.conf
[global]
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=${PGBACKREST_CIPHER_PASS}
[rhorizon]
pg1-path=/var/lib/postgresql/18/main
```

```bash
sudo -u postgres pgbackrest --stanza=rhorizon stanza-create
sudo -u postgres pgbackrest --stanza=rhorizon --type=full backup   # timers: full daily, diff hourly
```

### 0.5 Database HA operations

| Operation | Patroni | pgha |
|---|---|---|
| Planned switchover | `patronictl -c /etc/patroni/patroni.yml switchover`; HAProxy follows `/master` | use the provider's BSD supervisor procedure; verify agent consensus and VIP ownership |
| Unplanned failover | automatic promotion; verify `patronictl list` | automatic promotion only with agent quorum; verify all fresh status reports name the same leader |
| Add a replica | provision PG 18 + Patroni, then `systemctl enable --now patroni`; bootstrap uses `pg_basebackup` | provision PG 18 + `pgha`, enroll it in the provider quorum, and wait for `streaming` before making it eligible |
| Watch | replication lag, timeline, DCS quorum, archive status | replication lag, timeline, agent freshness, quorum, VIP owner, archive status |

#### Provider-neutral database HA status

The HA tab, `rhorizon cluster health`, and `/cluster/health` expose the
component as `database_ha`, not as a particular orchestrator. Set
`RH_DATABASE_HA_PROVIDER=patroni` with the three Patroni REST base URLs, or
`RH_DATABASE_HA_PROVIDER=pgha` with the three `rhorizon-pgha` agent status
base URLs.

The normalized contract is deliberately strict:

| State | Operator meaning |
|---|---|
| green `●` | one database leader; every reported member reachable and replica streaming with known lag within budget; for `pgha`, every expected agent reports fresh quorum evidence and exactly one write-VIP owner |
| orange `●` | forming, recovering, stale supervision, unknown/excess lag, a non-streaming replica, or a timeline mismatch |
| red `●` | no single leader, lost quorum, contradictory identity, wrong/multiple VIP owner, or all provider endpoints unreachable |
| black/grey `○` | provider disabled, unknown, or not configured; never sufficient for a failover drill or chaos preflight |

Provider-specific evidence remains labeled under `provider`. Patroni does not
report VIP ownership through the normalized probe, so its green state proves a
single leader and converged replication; the external LB/VIP must be monitored
separately. `pgha` reports VIP ownership directly.

Legacy `RH_PATRONI_REST_URLS` deployments remain supported in `auto` mode, but
new deployments should use `RH_DATABASE_HA_*`.

### 0.6 Risk: stale replication slot exhausts `pg_wal`

**Severity: critical availability risk.** Database HA deployments commonly
maintain a physical replication slot for every member. A replica can remain
registered and report PostgreSQL `running` while its WAL receiver is stuck on
an already removed segment. Its slot then stops advancing. Patroni will not
expire such a slot via `member_slots_ttl` while the member still has a live
DCS heartbeat; an equivalent live-but-stale member must also be fenced by
`pgha` supervision. With PostgreSQL's default
`max_slot_wal_keep_size=-1`, the slot may retain unlimited WAL and fill every
potential database leader's disk.

The safety invariant is:

| Control | Required behavior |
|---|---|
| `max_slot_wal_keep_size` | Finite and below the filesystem emergency reserve; `4GB` is the reference for a 20-40GB lab volume |
| `member_slots_ttl` | Finite (`10min` reference) so slots for genuinely absent members are eventually released |
| WAL archive | `archive_mode=on` only with a tested, monitored `archive_command`; a failing archive also prevents recycling |
| Replica health | Healthy only when state is `streaming`, lag is known and below threshold, and timeline matches the leader |
| Capacity | Alert on `pg_wal`/filesystem usage before 70%; retain space for checkpoint and crash recovery |
| Chaos preflight | Refuse load/fault injection unless `/cluster/health` reports `database` and `database_ha` green with every member converged |

`wal_keep_size` is a **minimum**, not a disk cap. `max_wal_size` is a soft
checkpoint target and does not override a replication slot.

Monitor the leader:

```sql
SELECT slot_name, active, restart_lsn,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn))
         AS retained_wal
FROM pg_replication_slots
ORDER BY pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) DESC;
```

If a member exceeds the lag budget:

1. Stop high-write load and verify that another healthy leader/replica contains
   the required data.
2. Determine whether the replica can fetch its required WAL from the archive.
   If its physical slot has `wal_status='lost'`, stop and fence the stale
   replica, drop that invalid slot on the database leader with
   `pg_drop_replication_slot()`, and let the configured provider recreate it.
   A base backup alone does not repair an already-invalid slot.
3. If the WAL is unavailable, reinitialize the replica. With Patroni use
   `patronictl -c /etc/patroni/patroni.yml reinit rhorizon-pg <member>`; with
   `pgha`, use its documented BSD supervisor rebuild procedure.
4. Never manually delete files from `pg_wal`. If the filesystem is full, add
   temporary capacity first, start one authoritative database leader, let a
   checkpoint enforce the slot cap, then reinitialize stale replicas.
5. Confirm every replica is `streaming`, timelines and lag are converged, and
   `/cluster/health` is green before restoring workload.

The finite cap intentionally prefers rebuilding an irrecoverably stale replica
over taking the writable database leader down with `ENOSPC`.

> HA gives availability, not integrity: it does NOT protect against
> master-password loss (use Shamir), a compromised password/token (see
> [THREAT-MODEL.md](THREAT-MODEL.md)), or cross-region DR (ship pgBackRest
> offsite + a cold standby).

## 0.1 Cluster mTLS at the reverse proxy (prerequisite)

**Do this before bootstrap, or node certificates will stop renewing about a
month later.** It is the one HA prerequisite with no immediate symptom.

HA members authenticate to each other with certificates issued by the cluster CA,
but rhorizon does not read them off the TLS socket. It expects the reverse proxy
to request a client certificate and forward it, and it refuses the header from
any peer that is not explicitly trusted:

1. nginx runs `ssl_verify_client optional_no_ca` and forwards the presented
   certificate as `X-Client-Cert`. nginx does **not** validate the chain -- the
   real authentication (cluster-CA signature, NotAfter, revocation) happens in
   `api/app/cluster_mtls.py`.
2. The API rejects `X-Client-Cert` unless the direct peer is listed in
   **`proxy_trusted_ips`**, so a client reaching the API socket directly cannot
   forge the header.

Enable it on every HA member. The bundled nginx emits the directives when asked;
it is **off by default** because requesting a client certificate makes some
browsers prompt the user to pick one, which is wrong for a single-node install:

```sh
# container path
RH_CLUSTER_MTLS=true

# native path
RH_NGINX_CLUSTER_MTLS=1 sh tools/install-native.sh --mode system
```

Then trust the proxy. `proxy_trusted_ips` is **empty by default** and is a
*different* setting from `xff_trusted_ips` (which only recovers the client IP for
audit, rate limiting and token IP allowlists) -- setting one does nothing for the
other:

```sh
RH_PROXY_TRUSTED_IPS=127.0.0.1/32,::1/128   # the local nginx in front of this node
```

Rolling your own proxy instead? It must do exactly this:

```nginx
ssl_verify_client optional_no_ca;
proxy_set_header X-Client-Cert $ssl_client_escaped_cert;   # on every /api/ location
```

## 0.2 Upstream keep-alive (prerequisite)

The proxy-to-uvicorn hop is HTTP/1.1 even when clients speak HTTP/2, and it
needs a connection pool plus a **strict timing inequality**. Get this wrong and
you get rare `RemoteProtocolError` / transport failures under load that look
like network flakiness:

```nginx
upstream rhorizon_api {
    server 127.0.0.1:8200;
    keepalive 64;
    keepalive_timeout 25s;      # MUST be < uvicorn --timeout-keep-alive
    keepalive_requests 1000;
}
```

```sh
uvicorn app.main:app ... --timeout-keep-alive 30    # MUST be > the nginx value
```

**Both halves are required.** Two ways to get it wrong, both observed:

- `proxy_http_version 1.1` and `proxy_set_header Connection ""` with **no
  `upstream` block** asks nginx to hold connections alive with no pool to hold
  them in.
- Leaving uvicorn at its **5s default** while nginx closes at 25s *inverts* the
  inequality: uvicorn closes first and the race is back. This is worse than
  having no pool, because the configuration looks correct.

Verified by a 24h chaos run: with the inequality inverted, transport errors
appeared in steady state, hundreds of seconds from any induced fault, behind an
HTTP/2 nginx. HTTP/2 removes the race for the *client* hop only.

**How the omission shows up.** Nothing fails at bootstrap. The cluster forms,
joins, elects, and passes health. Then the per-node renewal loop fires at
`cert_not_after - 30 days`, calls `POST /cluster/refresh-cert`, and gets
`X-Client-Cert header is required` -- weeks after the install that caused it. If
you are debugging that error now, this section is the fix.

## 1. Bootstrap

The common path is in [HA-CLUSTER.md](HA-CLUSTER.md) "Quick start"
(`rhorizon cluster init` -> distribute `ha_password` -> boot joiners with
`RH_HA_AUTO_JOIN`). Pre-flight on every node: vault unsealed,
`RH_CLUSTER_HA_ENABLED=true`, `/var/lib/rhorizon` persistent, `/run/rhorizon`
tmpfs 0700, TLS on.

`ha_password` distribution patterns (out of band, mode 0400):
- **Swarm**: `docker secret create ha_password ha_password.b64`, mount at
  `/run/secrets/ha_password`.
- **K8s**: `kubectl create secret generic ha-password
  --from-file=ha_password=./ha_password.b64`, mount as `subPath`.
- **Bare metal**: `scp` to `/run/ha_password`, `chmod 0400`, `chown 1500:1500`.

`RH_HA_PASSWORD_FILE` reads the **raw 32 bytes**
(`base64 -d < ha_password.b64 > ha_password.raw`), not the base64. After JOIN,
remove the secret - steady-state mTLS does not use it. A portable
age+vault delivery alternative is in section 3.8.

## 2. Rolling restart

Invariants: never leave the application cluster headless (hand the application
primary role to a healthy secondary before restarting it), wait
`>= 2 * cluster_join_quarantine_secs` between nodes, verify the audit chain
after each step.

```bash
# pre-flight: every member hb < 5s, none joining/draining, cert_expiry >= 7d
rhorizon cluster status --json | jq '[.members[] | {uuid, state:.ha_state, hb:.heartbeat_age_secs, expiry:.cert_expiry_days}]'
```

Order: **secondaries first** (lowest version, then closest cert expiry),
**application primary last** (only after demote).

```bash
# each secondary:
docker service update --force rhorizon_api      # or: kubectl rollout restart deployment/rhorizon-api
sleep 120                                        # 2 * cluster_join_quarantine_secs
rhorizon cluster status                          # confirm hb < 5 + SECONDARY

# the application primary: explicit handover, then restart it like a secondary
PRIMARY_UUID=$(rhorizon cluster status --json | jq -r '.primary_uuid')
SUCCESSOR=$(rhorizon cluster status --json | jq -r '.members[]|select(.ha_state=="SECONDARY").node_uuid' | head -n1)
rhorizon cluster demote "$PRIMARY_UUID" && rhorizon cluster promote "$SUCCESSOR"
```

Post-restart, the audit chain must stay intact (else stop and investigate):

```bash
curl -fs -H "Authorization: Bearer $TOKEN" "$RH_API/api/v1/vault/audit/verify" | jq .chain_intact   # true
```

If a restarted node shows `joining` past `cluster_joining_orphan_ttl_secs`, the
reaper purges the row and it REJOINs via mTLS. If it stays `null` past 5 min,
suspect a TLS cert error or a stale `cluster-cert.pem` on the volume.

## 2.1 End-to-end failure and response matrix

Use the role and component name in alerts. “Primary down” is not actionable
until it says application primary or database leader.

| Failure or pressure | Expected signal and automatic response | Operator response | K7 / client interpretation |
|---|---|---|---|
| One follower worker fails; local crypto master remains | worker coverage falls temporarily; sibling workers keep delegating to the local crypto master | inspect worker supervision if coverage does not recover within the attach/convergence budget | injected-window loss may be expected; any stale worker after convergence is a defect |
| Local crypto master fails with Shamir quorum intact | followers elect a new local crypto master and reconstruct/re-split keys | normally observe only; investigate if the container seals or election exceeds its budget | transient, correctly identified retry may be expected; silent misses or post-convergence failures are defects |
| Application secondary/container fails | LB removes it after failed readiness; other active/active application nodes serve traffic | recover/replace the node; verify worker coverage and membership converge | a connection already on the dead node may fail; generic failures after LB convergence are defects |
| Application primary fails | application secondaries elect a successor after lease expiry; ordinary reads/writes remain active/active, singleton jobs wait for the new application primary | intervene with `cluster promote` only if automatic election fails and Database HA is healthy | classify the injected election window separately; do not call this a database failover |
| Database leader fails with provider quorum | Patroni or `pgha` promotes one database replica; write endpoint/VIP moves; application pools reconnect | verify exactly one database leader, streaming replicas, acceptable lag, and correct VIP owner where reported | in-flight database work can be retriable during the declared window; errors after database and worker convergence are defects |
| Replica stops streaming or its slot retains excessive WAL | `database_ha` orange; WAL/disk guardrails alert before the leader volume fills | stop chaos/high-write load, preserve one authoritative leader, repair or rebuild the stale replica as in section 0.6 | never continue K7 as though the cluster were healthy; this is a failed preflight/guardrail |
| Database quorum lost, multiple/no leaders, or wrong VIP owner | `database_ha` red and `/readiness` must not claim the cluster is safe | fence writes and restore provider quorum; do not use application promotion commands | real HA failure, even during a chaos window |
| Database HA supervision unavailable/unconfigured | black/grey `database_ha`; health is unknown | repair/configure status endpoints before a drill | preflight must refuse K7; grey is not a pass |
| Healthy cluster reaches admission capacity | API returns structured `429 capacity_overloaded` with `Retry-After`; readiness remains a health signal | tune capacity or back off clients; correlate API, database, WAL and CPU metrics | expected load-shed at the measured ceiling; do not rewrite as `503` |
| Node is sealed, quarantined, or deliberately fenced | `/readiness` returns `503`; LB ejects that backend | correct the stated seal/quarantine/fence cause | availability state, not capacity overload |
| Edge has no ready upstream, or upstream connection breaks | edge/gateway may emit `502`/`503`; message must state that no ready backend/upstream is available where the proxy can do so | correlate LB backend state with `/cluster/health`; preserve proxy and API evidence | not a successful overload response and never relabel as `capacity_overloaded` |
| Audit verification, worker coverage, or requests fail after all convergence gates are green | no expected HA exception remains | stop and investigate integrity/attachment/load root cause | real defect; never hide it as `expected_fault` |

If a request reached rhorizon, preserve its structured error body and
`Retry-After`. If no backend accepted the request, the edge must report the
actual upstream condition; it cannot manufacture an application-level
diagnosis. K7 may mark an error `expected_fault` only when it occurs inside the
declared injection/recovery window **and** matches the expected semantics in
this matrix. Keep expected controlled rejections, transport failures, and
post-convergence defects as separate counters.

## 2.2 Planned maintenance and version upgrade

A restart is not automatically a safe upgrade. Before rolling versions, verify
that the release supports a mixed-version cluster and that its schema changes
are backward-compatible. The complete preflight, edge/API/database ordering,
worker re-admission gates, post-upgrade evidence, and rollback limits are in
[HA-PRODUCTION-REFERENCE.md](HA-PRODUCTION-REFERENCE.md#maintenance-and-upgrades).

The short invariant is: **one failure domain at a time, application
secondaries first, application primary after explicit handover, database
replicas first and database leader after a provider-controlled switchover**.
Require full worker, membership, replication, WAL, and audit convergence after
every step. If mixed-version or downgrade compatibility is not explicitly
documented, close client writes and use a declared maintenance window instead
of attempting a rolling upgrade.

## 3. Recovery scenarios

### 3.1 Local crypto master crash with quorum survival

`master_watch_loop` detects the stale master; followers race for
`pg_advisory_xact_lock('role:master')`, the winner collects `M-1` Shamir shares
(`M = cluster_shamir_threshold`, default `max(2, total//2+1)`), reconstructs the
sub-keys, unseals, and re-splits shares to the survivors. Operator: usually
nothing - tail `vault_logs` for `election_won`, confirm `rhorizon cluster
status`, check `/audit/verify` stays `chain_intact=true`.

- 2-node application cluster: blind election only while the Database HA layer
  reports quorum and its write endpoint is writable (the database is the
  external arbiter); otherwise the survivor enters operator-managed mode.
  Recover with `rhorizon cluster promote <uuid>` only for a missing
  **application primary**, never for a missing database leader.
- Quorum loss (< `M-1` followers): the cluster freezes sealed; recover with
  `POST /unseal` (master password + 2FA) on one node.

### 3.2 CA leak suspected

```bash
rhorizon cluster rotate-ca --yes
```

Mints a fresh CA, keeps the previous one for the grace window
(`cluster_ca_grace_window_secs`, default 7d, dual-CA verify), and flips
`force_renew_at` on every node; each node's renewal loop (poll 12h) refreshes
its cert via `/cluster/refresh-cert`. The prev CA is dropped once all nodes
rotated, or at grace expiry. Push the new bundle to any pinning proxy:

```bash
rhorizon cluster ca-bundle --output /etc/nginx/ssl/cluster-ca.pem && reload nginx   # prints the SHA-256
```

### 3.3 ha_password rotation (planned)

Stage -> verify -> confirm (or cancel). No at-rest plaintext window; the new
secret is minted inside `confirm` and returned once. TTL
`cluster_pending_ha_rotation_ttl_secs` (default 3600s); a `confirm` post-expiry
returns 410.

```bash
B="$RH_API/api/v1/vault/cluster/rotate-ha-password"; H="Authorization: Bearer $TOKEN"
curl -fsS -X POST -H "$H" "$B/stage"
curl -fsS       -H "$H" "$B"              # GET status (no /status suffix)
curl -fsS -X POST -H "$H" "$B/confirm"    # or .../cancel
```

After confirm, redistribute the new `ha_password` to nodes that have not yet
JOINed (existing members keep working via mTLS) and rotate any persisted
`RH_HA_PASSWORD_FILE`.

### 3.4 Node cert near expiry

Auto-renewed under `cluster_cert_renewal_threshold_days` (default 30d) by the
per-node loop. Force now:

```bash
rhorizon cluster rotate-cert <node_uuid>     # one node; --all to broadcast
```

### 3.5 Node loss (volume wiped, host destroyed)

A node that lost `/var/lib/rhorizon` boots with a new UUID and auto-JOINs as new;
the old row goes stale. Evict it (appends to `revoked_node_uuids`, so the lost
cert can never re-onboard):

```bash
rhorizon cluster status --json | jq '.members[]|select(.heartbeat_age_secs>600).node_uuid'
rhorizon cluster evict <stale_uuid>
```

### 3.6 Evicted by mistake

```bash
rhorizon cluster unrevoke <node_uuid>        # then restart the node to re-JOIN under the same UUID
```

### 3.7 Cluster CA signs nginx server certs

The cluster CA signs both the per-node identity cert (mTLS) and the nginx
server cert; the renewal loop refreshes both in one round-trip. At first
bootstrap nginx starts with a self-signed cert; `bootstrap.yml` then calls
`POST /cluster/issue-server-cert` on the application primary and hot-swaps the
cluster-CA-signed pair. To re-issue (new SAN / IP):

```bash
curl -sf -H "Authorization: Bearer $ROOT_TOKEN" \
  -d '{"san_ips":["10.0.1.11"],"san_dns":["rhorizon-1","vault.lab"]}' \
  https://rhorizon-1:8443/api/v1/vault/cluster/issue-server-cert | tee server-cert.json
# drop server_cert_pem/server_key_pem into /etc/nginx/ssl/server.{crt,key}; systemctl reload nginx
```

Local-crypto-master-only (503 retry-after on follower-worker routing),
`admin:w`. nginx reload is run via `RH_CLUSTER_NGINX_RELOAD_CMD`
(sudoers-bound to `systemctl reload nginx`).

#### Verify every node, not just the primary

`issue-server-cert` runs against the application primary only. Joiners get
their cluster-CA-signed server cert from the per-node renewal loop, so a
joiner that never completed one keeps the self-signed cert nginx started
with. That cert works -- TLS succeeds, the API answers -- so nothing fails
visibly; peers simply cannot verify that node's identity.

Check each node directly, not through the load balancer:

```bash
for h in rhorizon-1 rhorizon-2 rhorizon-3; do
  printf '%s ' "$h"
  echo | openssl s_client -connect "$h:8443" 2>/dev/null \
    | openssl x509 -noout -issuer -subject -enddate
done
```

`issuer` must be the cluster CA. If `issuer` equals `subject`, the node is
still self-signed. A second tell is the lifetime: cluster-CA-signed certs
carry `cluster_node_cert_validity_days` (90 by default), while the bootstrap
placeholder is minted for 10 years.

The renewal loop treats a self-signed server cert as due for renewal
regardless of its expiry, so an affected node repairs itself on the next
tick -- within `RH_CLUSTER_CERT_RENEWAL_POLL_SECS` (default 43200, i.e. up
to 12 h). To repair now rather than wait, re-run `issue-server-cert` for
that node and reload nginx.

Do not rely on a pinned CA bundle to catch this. A bundle built by collecting
what the nodes currently serve will contain the self-signed certs, and every
check that trusts it then passes.

### 3.8 Portable ha_password delivery (age + vault)

A cross-platform alternative to the tmpfs `RH_HA_PASSWORD_FILE` flow.
Once, post-`/cluster/init`: generate a 32-byte age key, store it as a vault
secret `cluster-ha/ha-bootstrap`, and age-encrypt the `ha_password` with it.
Per joiner: mint a scoped, IP-locked, 24h token and drop the
`{ha-password.age, token}` pair (mode 0400). Joiner env:

```ini
RH_HA_PASSWORD_STORAGE=age_vault
RH_HA_PASSWORD_AGE_PATH=/etc/rhorizon/ha-password.age
RH_HA_BOOTSTRAP_TOKEN_FILE=/etc/rhorizon/ha-bootstrap-token
RH_HA_BOOTSTRAP_SECRET_NAME=ha-bootstrap
RH_HA_BOOTSTRAP_NAMESPACE=cluster-ha
RH_HA_PRIMARY_URL=https://<application-primary>:8200
```

At boot the joiner fetches the age key (the read is audited with its source
IP), decrypts in mlock'd RAM, runs the normal JOIN, then unlinks both
artifacts. Revoke the bootstrap token once the node has JOINed (defense in
depth; the 24h TTL expires it anyway). After an `ha_password` rotation,
re-encrypt the new password and re-deploy the `.age` file to not-yet-joined
nodes (already-JOINed nodes use cert REJOIN, unaffected).

### 3.9 Joiner stuck in PermanentError post-409

The membership row exists but the wrapped key from the original `/cluster/join`
was lost in transit. The application primary's JOIN idempotency cache
(`cluster_join_idempotency_ttl_secs`, default 300s) covers the transient case;
beyond it, soft-reset (R1):

```bash
# on the application primary (admin token), UUID = stuck joiner
curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$PRIMARY/cluster/evict/$UUID"
curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$PRIMARY/cluster/unrevoke/$UUID"
# on the joiner: wipe a partial cert if present, keep node-uuid, restart
rm -f /var/lib/rhorizon/cluster-cert.pem /var/lib/rhorizon/cluster-cert.key
docker compose restart rhorizon-api
```

Keep `/var/lib/rhorizon/node-uuid` so the joiner re-uses the same UUID (R1 stays
soft). R2 (last resort, multiple nodes stuck): seal every node, wipe the
`vault_cluster_nodes` + `vault_cluster_config` cluster rows in psql, re-run
`/cluster/init` on the new application primary, re-distribute `ha_password`,
boot joiners from clean cert paths. R2 breaks the signed audit-chain linkage of
pre-reset JOINs - prefer R1 for compliance contexts.

## 4. References

- [HA-CLUSTER.md](HA-CLUSTER.md) - architecture, state machine, options, endpoints
- [HA-BENCH.md](HA-BENCH.md) - failover timing under load
- [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) - backup/restore, audit-chain repair
