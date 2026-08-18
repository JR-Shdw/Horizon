# Capacity planning & benchmarking

rhorizon ships a load harness in `tools/bench/`. Size a deployment for **your**
workload: the numbers below give the shape, but run the harness on your own
hardware before committing to an SLO.

## Capacity constraints

Three resources saturate before the others:

1. **PostgreSQL.** Every read does a durable write (an audit-lite row), so
   throughput is bound by the DB tier, not the crypto. The default per-worker
   pool is 8 + 8 connections. Size the database against the whole cluster:
   `nodes x workers_per_node x (pool_size + max_overflow)`, then retain at
   least 20% for migrations, health probes, autovacuum, and operators.
2. **Master RPC.** Every encrypt/decrypt converges on one master process. It is
   the first wall only on crypto-heavy `read_secret` load.
3. **Bandwidth and PG IOPS.** Usually last to saturate, most likely on a cheap
   VPS.

Workers (uvicorn processes) scale horizontally: each adds HTTP/DB/auth
parallelism. Budget **160 MB steady-state RSS per worker** (Python + Rust
extension + asyncpg pool) - that is the figure `api/app/mem_hardening.py` uses,
and it is what the boot guard checks against.

Total memory is not just `workers x 160`. Argon2id wires a transient **256 MB**
at unseal, and another **192 MB** covers the PG pool, background tasks and
fragmentation:

```
required_MB = workers x 160 + 256 + 192
```

Size the container limit to at least that. Undersizing does not degrade
gracefully - `mlockall` wires the Argon2id allocation, so the master is
OOM-killed at the moment of unseal. The boot guard warns when the cgroup limit
is below this figure.

Keep workers at or below `cluster_shamir_total` so every worker also holds a
failover share.

### Separated custody adds to the same limit

With `RH_CUSTODY_MODE=separated` the custodian pool runs beside the API pool
**in the same container**, so it counts against the same limit. The boot guard
includes it, and the full budget is:

```
required_MB = (workers + python_custodians) x 160 + rust_slots x 4 + 256 + 192
```

| Custody | Extra processes | Extra memory |
|---|---|---|
| `embedded` (default) | none - API workers hold the shares | 0 |
| `separated` + `rust` | `RH_RUST_CUSTODIAN_SLOTS` daemons (3/5/7/9) | 4 MB each: **12 to 36 MB** |
| `separated` + `python` | `RH_CUSTODIAN_WORKERS` uvicorn processes (3/5/7/9) | 160 MB each: **480 to 1440 MB** |

The Rust budget comes from measured RSS on a live sealed pool (~2.6 MB per
slot). A Rust custodian is a small mlock'd daemon holding one share, not an
application process. The Python figure is the full per-worker budget, because a
Python custodian **is** the same `uvicorn app.main:app` process started with
`RH_PROCESS_ROLE=custodian`.

The consequence: Rust custody fits inside every shipped preset's headroom;
Python custody fits in none of them. `smb` with `separated` + `python` needs
~2050 MB against a 1536 MB limit, and the failure mode is an OOM kill at
unseal.

The `256 MB` Argon2id term is counted **once**, not per pool. Only the API
process serving an unseal derives the master key; a custodian holds a share and
never derives one. Under Rust custody that term is also rare - a restart
reopens from the persisted shares with no password at all - but it stays in the
budget because it remains the peak whenever an operator does unseal, and
`mlockall` wires it.

## Tuning

Presets (`tools/install.sh --tier`) set these for you. Change them only with a
reason; each has a footprint or an availability consequence.

| Variable | Values | What it buys | Cost |
|---|---|---|---|
| `RH_WORKERS` | `1`, or `5`+ | HTTP/DB/auth parallelism | 160 MB each. `1` is the explicit single-process home mode; 2-4 are promoted to 5 because they cannot form the Shamir quorum |
| `RH_CUSTODY_MODE` | `embedded`, `separated` | `separated` makes API workers disposable: they hold no share and never see key material | a second process pool in the same container |
| `RH_CUSTODY_BACKEND` | `python`, `rust` | `rust` holds shares in a small mlock'd daemon instead of a full app process | `rust` requires `separated`; ~50x cheaper in memory |
| `RH_CUSTODIAN_WORKERS` | `3`, `5`, `7`, `9` | custodian quorum size, Python backend | 160 MB each |
| `RH_RUST_CUSTODIAN_SLOTS` | `3`, `5`, `7`, `9` | custodian quorum size, Rust backend | ~3 MB each |
| `RH_RUST_CUSTODIAN_THRESHOLD` | `0` (majority), or `2`..slots | how many custodians must agree | lower = more available, less compartmented |

Fault tolerance is `slots - threshold`: a `3-of-5` pool survives two lost
custodians, `2-of-3` survives one. More slots does not make the pool safer
against a *host* failure - every slot lives on the same host - it compartments
against a single process being compromised.

!!! warning "Slots and threshold are read at launch"
    A running pool cannot be reshaped, and a pool that already holds shares
    will not start under a different shape. Do not edit these on a live
    deployment that holds a custody generation.

`custody_mode=embedded` is the right answer for a single-worker (home)
deployment: with one process there is no follower to delegate to and no peer to
reconstruct from, so a custodian pool adds processes without adding
compartmentation.

### Preset footprints

What the shipped presets budget, against the formula. Every preset carries
roughly 25% above the computed figure, which is what absorbs a Rust custodian
pool at any slot count.

| Preset | Workers | `workers x 160 + 448` | `RHORIZON_API_MEM` | Headroom | `separated` + `rust` (5 slots) | `separated` + `python` (5) |
|---|---|---|---|---|---|---|
| home | 1 | 608 MB | 768 M | 160 MB | 628 MB, fits (not recommended) | 1408 MB, no |
| smb | 5 | 1248 MB | 1536 M | 288 MB | 1268 MB, fits | 2048 MB, raise to 2048 M+ |
| heavy | 10 | 2048 MB | 2560 M | 512 MB | 2068 MB, fits | 2848 MB, raise to 2900 M+ |
| super-heavy | 20 | 3648 MB | 4608 M | 960 MB | 3668 MB, fits | 4448 MB, raise to 4500 M+ |

Raise `RHORIZON_API_MEM` before switching a preset to `separated` + `python`.
Switching to `separated` + `rust` needs no change.

## Sizing

Starting points, validated with the harness. `read_secret` is the
throughput-limiting path; `whoami` and `list_secrets` scale higher.

Latency is reported as percentiles (response times, ranked fastest to slowest):

- **p50** (median): half the requests are faster than this.
- **p95**: 95% are faster; the slowest 5% are above it.
- **p99**: 99% are faster; only the slowest 1% (the tail) are above it.

Size against p99, not the mean: an average hides the tail.

### Single host (one API container, commodity hardware)

Historical clean envelope, 5 workers, PG `max_connections=200`, with an
explicit benchmark override of pool 15 + 15:

| Concurrency | read RPS | p99 (ms) | Errors |
|---|---|---|---|
| 10 | 244 | 66 | 0 |
| 100 | 236 | 1400 | 0 |
| 500 (burst) | 173 | 12 600 | < 0.04% |
| **Breaking point** | a single hot token caps read at ~240 regardless of size (PG row-lock on `vault_tokens.last_used_at`) | | spread load across tokens |

A 5-worker dev box sustains a c=500 burst at 99.96% success. For context, a
5000-employee org with 500 service consumers peaks around 100 to 300 RPS on
secret reads, bursting to 500, so a single host already covers most internal
infra.

### HA cluster (multi-node, larger DB tier)

Clean envelope, 10 workers, PG `max_connections=400`, 32-core / 64 GB host,
load split across many tokens:

| Client config | read RPS | p99 (ms) | Errors |
|---|---|---|---|
| 10 tokens, 1 client | 716 | 118 | 0 |
| 50 tokens, 4 clients | 1235 | 290 | 0 |
| 50 tokens, 8 clients | 1348 | 290 | 0 |
| **Breaking point** | ~1350 RPS server ceiling on this hardware | | first LWLock waits on the WAL / audit-lite buffer; scale the DB tier to lift it |

Capacity scales with worker count and PG `max_connections`. To raise the
ceiling, scale the DB tier (leader vCPU, connection pooling); the crypto is not
the limiter (HMAC over an audit record is sub-microsecond against a millisecond
DB write).

### Recommended starting config

| Scale | Workers | RAM (API) | PG `max_connections` | Notes |
|---|--:|---|---|---|
| Single host / default | 5 | 512 MB to 1 GB | 200 | quorum minimum, comfortable headroom |
| Mid-size internal | 8 | 768 MB | 250 | ~240 connections used |
| Large platform | 10 to 12 | 1 GB | 300 + pgbouncer | `cluster_shamir_total` auto-derives to N |
| Multi-tenant SaaS | 12 to 16 | 2 GB | 400 + pgbouncer | two replicas behind a load balancer |

## Admission control

`RH_MAX_CONCURRENT_REQUESTS` is a per-worker in-flight cap. Above it a
request gets `429 + Retry-After` instead of queueing (node cap = the value x
`RH_WORKERS`). It is a backstop, not a throughput tuner: it keeps an
overloaded node failing fast (429, retryable) rather than sealing under load,
which would be a full outage.

The HA Ansible role ships `64` per worker (320 per node), well above any
healthy steady state. Size it generously: the cap must never fire on a healthy
node. It cannot raise the ceiling (throughput is DB-bound); it only changes the
failure mode past the ceiling. Watch `rhorizon_requests_inflight` and
`rhorizon_requests_shed_total{reason="request_concurrency_limit"}`: sustained
shedding means the admitted ceiling has been reached. It can indicate either
an undersized cap or real downstream saturation; correlate DB latency, CPU,
WAL and pool usage before tuning. `rhorizon_http_requests_total` counts
admitted traffic only, so offered RPS is admitted RPS plus shed RPS.

`429` (busy, retry) keeps the node in a passive load balancer's rotation; a
genuinely down node (sealed or quarantined) returns `503` so the LB ejects it.

## Running the bench

```bash
# 1. Seed test data (100 secrets bench-0000, ...)
python -m tools.bench.bench seed --url http://127.0.0.1:8200 --token rh_xxx --count 100

# 2. Run a profile (small / medium / large)
python -m tools.bench.bench profile --url http://127.0.0.1:8200 --token rh_xxx \
  --profile small --output bench-small.json

# 3. Clean up
python -m tools.bench.bench cleanup --url http://127.0.0.1:8200 --token rh_xxx
```

The harness prints a Markdown table to stdout (RPS, p50/p95/p99, OK/Err per
scenario). Rotate across several tokens for a realistic run: a single hot token
serialises on the `last_used_at` row-lock and understates capacity by 3 to 5x.

Profiles: `small` (concurrency 10), `medium` (100), `large` (500).

## Interpreting results

| Symptom | Likely cause | Action |
|---|---|---|
| `read_secret` p99 climbs, `whoami` flat | master RPC saturation | adding workers will not help; profile master CPU |
| all scenarios climb together | bandwidth or PG IOPS | move the bench client off-box, check `iostat` |
| `list_secrets` slow, `read_secret` fast | PG sequential scan / bad index | check `EXPLAIN ANALYZE`, ensure the schema is current |
| `whoami` p99 > 50 ms | PG `max_connections` exhausted | bump it or add pgbouncer |
| errors appear | rate-limit hit or a single hot token | spread load across tokens, check `vault_rate_limits` |

Not measured by the harness: cold-start latency (first call after unseal runs
Argon2id, ~1 s), failover latency (covered by the cluster tests), and remote
network round-trip (run the harness adjacent to the vault for comparable local
measurements).

## Reproducibility

Every run records the rhorizon version, worker count, kernel, CPU model, PG
version, and harness git SHA. Two runs are comparable only if all match. When
publishing numbers, include the full JSON so a reader can verify the conditions.
