# rhorizon bench

Reproducible load harness for rhorizon. Drives the API with concurrent async
clients, reports p50 / p95 / p99 latency and sustained RPS per scenario.

The output is intended to be **published** : run on your own infra, paste the
generated Markdown into an issue, a doc page, or a tender response. The
defaults map to three classes of deployment so the numbers tell the same
story across operators.

## Why this exists

rhorizon is AGPL : deployments range from a single host to a multi-host
platform. Capacity planning needs **measured** numbers, not the author's
guesses. The harness is deliberately small (one file, stdlib + httpx) so it
ships with the repo, runs anywhere Python 3.12 runs, and can be re-executed
on any release to detect regressions.

## Profiles

| Profile  | Concurrency | Duration | Target use case                          |
|----------|-------------|----------|------------------------------------------|
| `small`  | 10          | 30 s     | dev / single-host infra (<= 50 hosts) |
| `medium` | 100         | 60 s     | mid-size internal platform (50 - 500 services) |
| `large`  | 500         | 120 s    | Enterprise / multi-tenant SaaS (1 000+ consumers) |

Each profile runs the four scenarios sequentially.

## Scenarios

| Scenario       | Hot path exercised                                      |
|----------------|---------------------------------------------------------|
| `whoami`       | Auth only - HMAC index lookup, no DB join, no crypto    |
| `list_secrets` | DB SELECT only, no crypto (lists names)                 |
| `read_secret`  | Full path : auth + DB SELECT + master RPC decrypt       |
| `mixed`        | 70 % read / 20 % list / 10 % whoami (realistic prod)    |
| `cluster_ha` | visibility: admin auth + DB SELECT on vault_cluster_nodes + `is_loaded_anywhere` (master RPC `has_ha_password` when handled by a follower) |

`read_secret` is the path that exercises the master RPC bottleneck.
`mixed` is the most representative number for sizing decisions.
`cluster_ha` targets the cross-host RPC dispatch cost; pair it
with `/metrics` snapshots (see `~/dev/rhorizon_ha/tests/bench_cluster_ha.py`).

## Usage

The harness needs an unsealed vault, an root token, and at least one secret
to read. Seed first :

```bash
python -m tools.bench.bench seed \
  --url http://127.0.0.1:8200 \
  --token rh_xxx \
  --count 100
```

Then run a profile :

```bash
python -m tools.bench.bench profile \
  --url http://127.0.0.1:8200 \
  --token rh_xxx \
  --profile small \
  --output bench-results.json
```

Or a single scenario with custom knobs :

```bash
python -m tools.bench.bench run \
  --url http://127.0.0.1:8200 \
  --token rh_xxx \
  --scenario read_secret \
  --concurrency 50 \
  --duration 30
```

The JSON file holds per-scenario quantiles and RPS ; a Markdown table is
printed to stdout (paste it into an issue, a doc page, a tender response).

## Cleaning up

Seeded secrets carry the prefix `bench-`. To remove them after a run :

```bash
python -m tools.bench.bench cleanup \
  --url http://127.0.0.1:8200 \
  --token rh_xxx
```

## Reproducibility

Every run records the rhorizon version, worker count, PG version, kernel,
CPU model, and harness git SHA into the output JSON. Two runs comparable iff
all five match.
