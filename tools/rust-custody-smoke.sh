#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# Live end-to-end check for the standalone Rust custody canary against REAL
# custodian daemons. PostgreSQL runs in a temporary container; the Rust quorum
# and the API pool both run natively through the production launchers.
#
# What this proves that the unit suites cannot: a password unseal against a
# pool that ALREADY holds a generation REOPENS it from the shares the daemons
# kept, instead of migrating a fresh split. The generation counter must not
# move across seal/unseal, because a resplit would use a different polynomial.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_SMOKE_API_WORKERS:-2}"
SLOTS="${RH_SMOKE_RUST_SLOTS:-3}"
PG_PORT="${RH_SMOKE_PG_PORT:-55439}"
API_PORT="${RH_SMOKE_API_PORT:-18202}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:18-trixie}"
CUSTODIAN_BIN="${RH_RUST_CUSTODIAN_BINARY:-$ROOT/api/rust/target/release/rhorizon-custodian}"
PG_NAME="rhorizon-rust-custody-smoke-pg-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rh-rust-custody-smoke.XXXXXX")"
LOG="$WORK/rhorizon.log"
LAUNCHER_PID=""

say() { printf '[rust-custody-smoke] %s\n' "$*"; }
fail() {
    printf '[rust-custody-smoke] FAIL: %s\n' "$*" >&2
    [ ! -f "$LOG" ] || tail -60 "$LOG" >&2
    exit 1
}

cleanup() {
    if [ -n "${RH_SMOKE_KEEP:-}" ]; then
        say "RH_SMOKE_KEEP set: leaving the stack UP for inspection"
        say "  api:      http://127.0.0.1:$API_PORT (launcher pid $LAUNCHER_PID)"
        say "  log:      $LOG"
        say "  postgres: postgresql://postgres:smoke@127.0.0.1:$PG_PORT/rhorizon"
        say "  stop it:  kill $LAUNCHER_PID; docker rm -f $PG_NAME; rm -rf $WORK"
        return
    fi
    [ -z "$LAUNCHER_PID" ] || kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
    [ -z "$LAUNCHER_PID" ] || wait "$LAUNCHER_PID" 2>/dev/null || true
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

command -v docker >/dev/null || { say "no container runtime -- skip"; exit 2; }
[ -x "$PY" ] || { say "no venv at $PY -- skip"; exit 2; }
[ -x "$CUSTODIAN_BIN" ] || {
    say "no custodian binary at $CUSTODIAN_BIN -- build with:"
    say "  (cd api/rust && cargo build --release -p rhorizon-custodian)"
    exit 2
}

query() {
    "$PY" - "$PG_PORT" "$1" <<'PYEOF'
import asyncio
import sys

import asyncpg


async def main():
    port, sql = sys.argv[1:]
    conn = await asyncpg.connect(
        f"postgresql://postgres:smoke@127.0.0.1:{port}/rhorizon"
    )
    try:
        value = await conn.fetchval(sql)
    finally:
        await conn.close()
    sys.stdout.write("" if value is None else str(value))


asyncio.run(main())
PYEOF
}

# A seal or an unseal reaches only the worker that served it; the rest follow
# on their maintenance tick, so convergence is eventual BY DESIGN. What must
# never happen is a pool that does not converge: requests round-robin across
# workers, so a straggler either 503s a healthy vault or answers sealed=false
# while every crypto op fails against sealed daemons. Assert both directions.
wait_for_whole_pool() {
    want=$1     # sealed value to require: true | false
    label=$2
    secs="${RH_SMOKE_CONVERGE_SECS:-60}"
    probes=$((API_WORKERS * 6))
    # date +%s rather than $SECONDS: portable to a plain POSIX shell if this
    # ever has to run inside the BSD VM matrix.
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        mismatch=0
        for _ in $(seq 1 "$probes"); do
            probe="$(curl -sS -m 5 "http://127.0.0.1:$API_PORT/api/v1/vault/status" || true)"
            printf '%s' "$probe" | grep -q "\"sealed\":$want" || mismatch=$((mismatch + 1))
        done
        if [ "$mismatch" -eq 0 ]; then
            say "all $API_WORKERS workers converged to $label ($probes consecutive probes)"
            return 0
        fi
        sleep 2
    done
    fail "$mismatch/$probes probes still disagreed with '$label' after ${secs}s: the decision never reached the whole API pool"
}

custody_state() {
    query "SELECT value FROM vault_config WHERE key LIKE 'rust_custody_generation_state%'"
}

activation_state() {
    query "SELECT value FROM vault_config WHERE key = 'rust_custody_activation_state'"
}

say "starting temporary PostgreSQL on 127.0.0.1:$PG_PORT"
docker run -d --rm --name "$PG_NAME" \
    -e POSTGRES_PASSWORD=smoke -e POSTGRES_DB=rhorizon \
    -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" >/dev/null

"$PY" - "$PG_PORT" "$ROOT/schema.sql" <<'PYEOF' || fail "schema apply failed"
import asyncio
import sys

import asyncpg


async def main():
    port, schema_path = sys.argv[1:]
    schema = open(schema_path, encoding="utf-8").read()
    last = None
    for _ in range(30):
        try:
            conn = await asyncpg.connect(
                f"postgresql://postgres:smoke@127.0.0.1:{port}/rhorizon",
                timeout=5,
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

mkdir -p "$WORK/audit" "$WORK/run" "$WORK/data" "$WORK/custody" "$WORK/prom"
chmod 700 "$WORK/run" "$WORK/data" "$WORK/custody"

say "starting $SLOTS Rust custodians and $API_WORKERS disposable API workers"
(
    cd "$ROOT/api"
    PATH="$(dirname "$PY"):$PATH" \
    RH_DATABASE_URL="postgresql+asyncpg://postgres:smoke@127.0.0.1:$PG_PORT/rhorizon" \
    RH_DATABASE_SSL=disable \
    RH_AUDIT_DIR="$WORK/audit" \
    RH_AUTHFAIL_LOG="$WORK/audit/authfail.log" \
    RH_RUNTIME_DIR="$WORK/run" \
    RHORIZON_RUNTIME_DIR="$WORK/run" \
    RH_NODE_UUID_PATH="$WORK/data/node-uuid" \
    RH_CLUSTER_CERT_PATH="$WORK/data/cluster-cert.pem" \
    RH_CLUSTER_CERT_KEY_PATH="$WORK/data/cluster-cert.key" \
    RH_CUSTODY_MODE=separated \
    RH_CUSTODY_BACKEND=rust \
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
) >"$LOG" 2>&1 &
LAUNCHER_PID=$!

for _ in $(seq 1 120); do
    curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
    kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "Rust custody launcher exited"
    sleep 0.5
done
curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null \
    || fail "public API did not start"

slot=1
while [ "$slot" -le "$SLOTS" ]; do
    [ -S "$WORK/run/rust-custodian-$slot.sock" ] \
        || fail "custodian slot $slot has no socket"
    slot=$((slot + 1))
done
say "all $SLOTS custodian daemons are live"

MASTER_PASSWORD="rust-custody-smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"

# --- first unseal: empty pool, so this MIGRATES the local bundle -------------
UNSEAL="$(curl -sS -m 120 -H 'Content-Type: application/json' \
    --data "{\"password\":\"$MASTER_PASSWORD\"}" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/unseal")"
printf '%s' "$UNSEAL" | grep -q '"status":"unsealed"' \
    || fail "first unseal (migration) failed: $UNSEAL"
TOKEN="$(printf '%s' "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "bootstrap did not return a root token"

FIRST_STATE="$(custody_state)"
[ -n "$FIRST_STATE" ] || fail "no durable Rust custody generation after activation"
say "after activation: $FIRST_STATE"
printf '%s' "$FIRST_STATE" | grep -q '"phase": *"stable"' \
    || fail "custody generation is not stable after activation"

GENERATION_BEFORE="$("$PY" -c \
    'import json,sys; print(json.loads(sys.argv[1])["active_generation"])' \
    "$FIRST_STATE")"
[ -n "$GENERATION_BEFORE" ] || fail "could not read active generation"
say "active generation after migration: $GENERATION_BEFORE"

wait_for_whole_pool false unsealed

# --- write a secret so we can prove the SAME bundle comes back --------------
# -f so an HTTP error is a failure here, not a confusing 404 on the next read.
curl -fsS -m 15 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    --data '{"name":"rust-custody-canary","value":"reopen-must-preserve-this","namespace":"default"}' \
    "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/" >/dev/null \
    || fail "could not create the canary secret"

READ_BEFORE="$(curl -sS -m 15 -H "Authorization: Bearer $TOKEN" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/rust-custody-canary?namespace=default")"
printf '%s' "$READ_BEFORE" | grep -q 'reopen-must-preserve-this' \
    || fail "canary secret did not read back before seal: $READ_BEFORE"
say "canary secret written and read through the Rust quorum"

# --- manual seal: durable intent must flip to sealed ------------------------
curl -sS -m 30 -X POST -H "Authorization: Bearer $TOKEN" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/seal" >/dev/null \
    || fail "seal request failed"

# Stored as the literal string "sealed"/"unsealed", not JSON.
ACTIVATION="$(activation_state)"
say "activation state after seal: $ACTIVATION"
[ "$ACTIVATION" = "sealed" ] \
    || fail "durable activation intent did not flip to sealed: $ACTIVATION"

wait_for_whole_pool true sealed
say "vault sealed across the whole pool; daemons still hold their shares"

# --- second unseal: pool HOLDS a generation, so this must REOPEN ------------
REOPEN="$(curl -sS -m 120 -H 'Content-Type: application/json' \
    --data "{\"password\":\"$MASTER_PASSWORD\"}" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/unseal")"
printf '%s' "$REOPEN" | grep -q '"status":"unsealed"' \
    || fail "reopen after seal failed: $REOPEN"

SECOND_STATE="$(custody_state)"
say "after reopen: $SECOND_STATE"
GENERATION_AFTER="$("$PY" -c \
    'import json,sys; print(json.loads(sys.argv[1])["active_generation"])' \
    "$SECOND_STATE")"

# THE assertion this harness exists for. A migration would have split a new
# polynomial and bumped the counter; a reopen reuses the shares the custodians
# kept, so the generation is identical.
[ "$GENERATION_BEFORE" = "$GENERATION_AFTER" ] \
    || fail "generation moved $GENERATION_BEFORE -> $GENERATION_AFTER: the pool RESPLIT instead of reopening"
say "generation unchanged across seal/unseal ($GENERATION_AFTER): reopened, not resplit"

# --- and the reopened generation must serve the pre-seal secret -------------
wait_for_whole_pool false unsealed
READ_AFTER="$(curl -fsS -m 15 -H "Authorization: Bearer $TOKEN" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/rust-custody-canary?namespace=default")"
printf '%s' "$READ_AFTER" | grep -q 'reopen-must-preserve-this' \
    || fail "canary secret unreadable after reopen: $READ_AFTER"
say "canary secret still readable: the reopened quorum holds the same bundle"

say "PASS: live ${SLOTS}-slot pool migrated, sealed, reopened without a resplit"
