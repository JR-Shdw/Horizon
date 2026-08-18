#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# Measures the custody-boundary throughput gate: "Rust custody throughput is at
# least 95% of the current native RPC baseline".
#
# Three configurations, run SEQUENTIALLY on the same host so the numbers are
# comparable, each against a fresh PostgreSQL and a fresh vault:
#
#   embedded    RH_CUSTODY_MODE=embedded. The master worker holds the sub-keys
#               in-process and followers delegate over the cluster RPC socket.
#               This is the "native RPC baseline" the gate names.
#   python      RH_CUSTODY_MODE=separated RH_CUSTODY_BACKEND=python. A separate
#               Python custodian uvicorn pool on a Unix socket. NOT in-process:
#               this isolates the cost of the custody boundary itself.
#   rust        RH_CUSTODY_MODE=separated RH_CUSTODY_BACKEND=rust. The Rust
#               custodian quorum, length-prefixed JSON frames with hex payloads.
#
# The third point is what makes the result actionable. If rust and python land
# together well under embedded, the framing is not the cost -- the boundary is,
# and moving the protocol to binary framing would not buy the gate back.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_BENCH_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_BENCH_API_WORKERS:-5}"
SLOTS="${RH_BENCH_RUST_SLOTS:-3}"
CUSTODIAN_WORKERS="${RH_BENCH_PY_CUSTODIANS:-3}"
PG_PORT="${RH_BENCH_PG_PORT:-55441}"
API_PORT="${RH_BENCH_API_PORT:-18204}"
PG_IMAGE="${RH_BENCH_PG_IMAGE:-docker.io/library/postgres:18-trixie}"
CUSTODIAN_BIN="${RH_RUST_CUSTODIAN_BINARY:-$ROOT/api/rust/target/release/rhorizon-custodian}"
SEED_COUNT="${RH_BENCH_SEED:-100}"
CONCURRENCY="${RH_BENCH_CONCURRENCY:-50}"
# One Python process driving the whole load is itself a bottleneck: a single
# asyncio loop plus httpx caps out well below what the API can serve, and the
# symptom is throughput that FALLS as concurrency rises while errors stay zero.
# Split the load across processes and sum, so the number describes the server.
CLIENTS="${RH_BENCH_CLIENTS:-4}"
DURATION="${RH_BENCH_DURATION:-30}"
WARMUP="${RH_BENCH_WARMUP:-5}"
SCENARIOS="${RH_BENCH_SCENARIOS:-read_secret mixed whoami}"
OUTDIR="${RH_BENCH_OUTDIR:-$ROOT/.bench-custody}"

PG_NAME=""
WORK=""
LAUNCHER_PID=""

say() { printf '[custody-bench] %s\n' "$*"; }
fail() {
    printf '[custody-bench] FAIL: %s\n' "$*" >&2
    [ -z "$WORK" ] || [ ! -f "$WORK/rhorizon.log" ] || tail -60 "$WORK/rhorizon.log" >&2
    exit 1
}

teardown() {
    [ -z "$LAUNCHER_PID" ] || kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
    [ -z "$LAUNCHER_PID" ] || wait "$LAUNCHER_PID" 2>/dev/null || true
    LAUNCHER_PID=""
    [ -z "$PG_NAME" ] || docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    PG_NAME=""
    [ -z "$WORK" ] || rm -rf "$WORK" 2>/dev/null || true
    WORK=""
}
trap teardown EXIT

command -v docker >/dev/null || fail "no container runtime"
[ -x "$PY" ] || fail "no venv at $PY"
[ -x "$CUSTODIAN_BIN" ] || fail "no custodian binary at $CUSTODIAN_BIN (cd api/rust && cargo build --release -p rhorizon-custodian)"

apply_schema() {
    "$PY" - "$PG_PORT" "$ROOT/schema.sql" <<'PYEOF' || fail "schema apply failed"
import asyncio
import sys

import asyncpg


async def main():
    port, schema_path = sys.argv[1:]
    schema = open(schema_path, encoding="utf-8").read()
    last = None
    for _ in range(60):
        try:
            conn = await asyncpg.connect(
                f"postgresql://postgres:bench@127.0.0.1:{port}/rhorizon", timeout=5
            )
            await conn.execute(schema)
            await conn.close()
            return
        except Exception as exc:
            last = exc
            await asyncio.sleep(1)
    raise RuntimeError(f"PostgreSQL did not become ready: {last}")


asyncio.run(main())
PYEOF
}

# Sum RSS of the custody-holding processes for this configuration. Reported for
# the "three idle Rust custodians use no more than 128 MiB RSS combined" gate.
# Sampled while the vault is unsealed but idle, before any load is applied.
custody_rss_kib() {
    config=$1
    case "$config" in
        rust)
            ps -o rss= -C rhorizon-custodian 2>/dev/null \
                | awk '{s+=$1} END {print s+0}'
            ;;
        python)
            # The custodian pool is the uvicorn group bound to the UDS.
            pgrep -f "uvicorn app.main:app --uds $WORK/run/custodian-http.sock" 2>/dev/null \
                | while read -r pid; do
                      ps -o rss= -p "$pid" 2>/dev/null || true
                  done | awk '{s+=$1} END {print s+0}'
            ;;
        *)
            echo 0
            ;;
    esac
}

launch_stack() {
    config=$1
    WORK="$(mktemp -d "${TMPDIR:-$HOME/tmp}/rh-custody-bench.XXXXXX")"
    PG_NAME="rhorizon-custody-bench-pg-$$"

    # api/app/database.py states the budget: workers * (pool_size +
    # max_overflow) must stay under max_connections, and each worker is capped
    # at 16. Stock postgres allows 100, so anything past 6 workers exhausts it
    # and the API answers 500 -- a harness artefact that reads exactly like a
    # server that fell over. Size the server to the pool it will actually face.
    pg_max_connections=$(( API_WORKERS * 16 + 50 ))
    [ "$pg_max_connections" -ge 100 ] || pg_max_connections=100
    say "[$config] starting temporary PostgreSQL on 127.0.0.1:$PG_PORT (max_connections=$pg_max_connections)"
    docker run -d --rm --name "$PG_NAME" \
        -e POSTGRES_PASSWORD=bench -e POSTGRES_DB=rhorizon \
        -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" \
        -c max_connections="$pg_max_connections" >/dev/null
    apply_schema

    mkdir -p "$WORK/audit" "$WORK/run" "$WORK/data" "$WORK/custody" "$WORK/prom"
    chmod 700 "$WORK/run" "$WORK/data" "$WORK/custody"

    case "$config" in
        embedded) mode=embedded; backend=python ;;
        python)   mode=separated; backend=python ;;
        rust)     mode=separated; backend=rust ;;
        *) fail "unknown config: $config" ;;
    esac

    say "[$config] launching API (mode=$mode backend=$backend workers=$API_WORKERS)"
    (
        cd "$ROOT/api"
        PATH="$(dirname "$PY"):$PATH" \
        RH_DATABASE_URL="postgresql+asyncpg://postgres:bench@127.0.0.1:$PG_PORT/rhorizon" \
        RH_DATABASE_SSL=disable \
        RH_AUDIT_DIR="$WORK/audit" \
        RH_AUTHFAIL_LOG="$WORK/audit/authfail.log" \
        RH_RUNTIME_DIR="$WORK/run" \
        RHORIZON_RUNTIME_DIR="$WORK/run" \
        RH_NODE_UUID_PATH="$WORK/data/node-uuid" \
        RH_CLUSTER_CERT_PATH="$WORK/data/cluster-cert.pem" \
        RH_CLUSTER_CERT_KEY_PATH="$WORK/data/cluster-cert.key" \
        RH_CUSTODY_MODE="$mode" \
        RH_CUSTODY_BACKEND="$backend" \
        RH_CUSTODIAN_WORKERS="$CUSTODIAN_WORKERS" \
        RH_RUST_CUSTODIAN_SLOTS="$SLOTS" \
        RH_RUST_CUSTODIAN_THRESHOLD=0 \
        RH_RUST_CUSTODIAN_BINARY="$CUSTODIAN_BIN" \
        RH_RUST_CUSTODIAN_KEY_DIR="$WORK/custody" \
        RH_CUSTODIAN_TOKEN_FILE="$WORK/run/custodian-control.token" \
        RH_WORKERS="$API_WORKERS" \
        RH_UVICORN_HOST=127.0.0.1 \
        RH_UVICORN_PORT="$API_PORT" \
        PROMETHEUS_MULTIPROC_DIR="$WORK/prom" \
            ./run-api.sh
    ) >"$WORK/rhorizon.log" 2>&1 &
    LAUNCHER_PID=$!

    for _ in $(seq 1 240); do
        curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
        kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "[$config] launcher exited during startup"
        sleep 0.5
    done
    curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null \
        || fail "[$config] public API did not start"
}

run_config() {
    config=$1
    launch_stack "$config"

    password="custody-bench-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
    say "[$config] unsealing"
    unseal="$(curl -sS -m 180 -H 'Content-Type: application/json' \
        --data "{\"password\":\"$password\"}" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/unseal")"
    printf '%s' "$unseal" | grep -q '"status":"unsealed"' \
        || fail "[$config] unseal failed: $unseal"
    token="$(printf '%s' "$unseal" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
    [ -n "$token" ] || fail "[$config] no root token returned"

    # Let the pool settle so followers have attached before we sample or load.
    sleep 5
    rss="$(custody_rss_kib "$config")"
    say "[$config] idle custody RSS: ${rss} KiB"

    say "[$config] seeding $SEED_COUNT secrets"
    (cd "$ROOT" && "$PY" -m tools.bench.bench seed \
        --url "http://127.0.0.1:$API_PORT" --token "$token" \
        --count "$SEED_COUNT") >/dev/null || fail "[$config] seed failed"

    mkdir -p "$OUTDIR"
    say "[$config] warmup ${WARMUP}s"
    (cd "$ROOT" && "$PY" -m tools.bench.bench run \
        --url "http://127.0.0.1:$API_PORT" --token "$token" \
        --scenario read_secret --concurrency "$CONCURRENCY" \
        --duration "$WARMUP") >/dev/null 2>&1 || true

    per_client=$(( CONCURRENCY / CLIENTS ))
    [ "$per_client" -ge 1 ] || fail "RH_BENCH_CONCURRENCY must be >= RH_BENCH_CLIENTS"
    for scenario in $SCENARIOS; do
        say "[$config] scenario $scenario ($CLIENTS clients x c=$per_client, ${DURATION}s)"
        pids=""
        client=1
        while [ "$client" -le "$CLIENTS" ]; do
            (cd "$ROOT" && "$PY" -m tools.bench.bench run \
                --url "http://127.0.0.1:$API_PORT" --token "$token" \
                --scenario "$scenario" --concurrency "$per_client" \
                --duration "$DURATION" \
                --output "$OUTDIR/$config-$scenario.client$client.json") >/dev/null 2>&1 &
            pids="$pids $!"
            client=$((client + 1))
        done
        for pid in $pids; do
            wait "$pid" || fail "[$config] scenario $scenario client failed"
        done
        # Sum the concurrent clients into the single-file shape the reporters
        # already read, so the aggregate is what gets compared.
        "$PY" - "$OUTDIR" "$config" "$scenario" "$CLIENTS" <<'PYEOF' \
            || fail "[$config] could not merge client results for $scenario"
import json
import sys
from pathlib import Path

outdir, config, scenario, clients = sys.argv[1:]
parts = []
for index in range(1, int(clients) + 1):
    path = Path(outdir) / f"{config}-{scenario}.client{index}.json"
    parts.append(json.loads(path.read_text()))
results = [part["results"][0] for part in parts]
merged = dict(parts[0])
first = dict(results[0])
first["concurrency"] = sum(r["concurrency"] for r in results)
first["requests_total"] = sum(r["requests_total"] for r in results)
first["requests_ok"] = sum(r["requests_ok"] for r in results)
first["requests_err"] = sum(r["requests_err"] for r in results)
first["rps"] = round(sum(r["rps"] for r in results), 1)
# Latency quantiles do not sum. Report the worst client per quantile: with the
# load split evenly they are drawn from the same distribution, and taking the
# max refuses to flatter the result.
for key in ("p50_ms", "p95_ms", "p99_ms", "p999_ms"):
    first[key] = max(r[key] for r in results)
merged["results"] = [first]
merged["clients"] = int(clients)
Path(outdir, f"{config}-{scenario}.json").write_text(json.dumps(merged, indent=1))
print(
    f"  -> {scenario}: rps={first['rps']} "
    f"p50={first['p50_ms']}ms p95={first['p95_ms']}ms err={first['requests_err']}"
)
PYEOF
    done

    printf '%s\n' "$rss" > "$OUTDIR/$config-rss.kib"
    teardown
    say "[$config] done"
}

mkdir -p "$OUTDIR"
CONFIGS="${1:-embedded python rust}"
for config in $CONFIGS; do
    run_config "$config"
done

say "results in $OUTDIR"
