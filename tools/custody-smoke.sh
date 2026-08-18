#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# End-to-end check for separated local custody. PostgreSQL runs in a temporary
# container; both rhorizon pools run natively through the production launcher.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_SMOKE_API_WORKERS:-3}"
API_RECYCLES="${RH_SMOKE_API_RECYCLES:-6}"
CUSTODIANS="${RH_SMOKE_CUSTODIANS:-3}"
PG_PORT="${RH_SMOKE_PG_PORT:-55438}"
API_PORT="${RH_SMOKE_API_PORT:-18201}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:17-bookworm}"
PG_NAME="rhorizon-custody-smoke-pg-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rh-custody-smoke.XXXXXX")"
LOG="$WORK/rhorizon.log"
LAUNCHER_PID=""

say() { printf '[custody-smoke] %s\n' "$*"; }
fail() {
    printf '[custody-smoke] FAIL: %s\n' "$*" >&2
    [ ! -f "$LOG" ] || tail -40 "$LOG" >&2
    exit 1
}

cleanup() {
    [ -z "$LAUNCHER_PID" ] || kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
    [ -z "$LAUNCHER_PID" ] || wait "$LAUNCHER_PID" 2>/dev/null || true
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

command -v docker >/dev/null || { say "no container runtime -- skip"; exit 2; }
[ -x "$PY" ] || { say "no venv at $PY -- skip"; exit 2; }

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

mkdir -p "$WORK/audit" "$WORK/run" "$WORK/data" "$WORK/prom"
chmod 700 "$WORK/run" "$WORK/data"
say "starting $CUSTODIANS fixed custodians and $API_WORKERS disposable API workers"
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
    RH_CUSTODIAN_WORKERS="$CUSTODIANS" \
    RH_CUSTODIAN_UDS_PATH="$WORK/run/custodian-http.sock" \
    RH_CUSTODIAN_TOKEN_FILE="$WORK/run/custodian-control.token" \
    RH_WORKERS="$API_WORKERS" \
    RH_UVICORN_HOST=127.0.0.1 \
    RH_UVICORN_PORT="$API_PORT" \
    PROMETHEUS_MULTIPROC_DIR="$WORK/prom" \
        ./run-api.sh
) >"$LOG" 2>&1 &
LAUNCHER_PID=$!

for _ in $(seq 1 80); do
    curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
    kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "two-pool launcher exited"
    sleep 0.5
done
curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null \
    || fail "public API did not start"

MASTER_PASSWORD="custody-smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
UNSEAL="$(curl -sS -m 60 -H 'Content-Type: application/json' \
    --data "{\"password\":\"$MASTER_PASSWORD\"}" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/unseal")"
printf '%s' "$UNSEAL" | grep -q '"status":"unsealed"' \
    || fail "unseal through custody failed: $UNSEAL"
TOKEN="$(printf '%s' "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "bootstrap did not return a root token"

read_registry() {
    "$PY" - "$PG_PORT" <<'PYEOF'
import asyncio
import sys

import asyncpg


async def main():
    conn = await asyncpg.connect(
        f"postgresql://postgres:smoke@127.0.0.1:{sys.argv[1]}/rhorizon"
    )
    rows = await conn.fetch("""
        SELECT pid, worker_state
        FROM vault_workers
        WHERE last_heartbeat > NOW() - INTERVAL '5 seconds'
        ORDER BY pid
    """)
    await conn.close()
    print(" ".join(f"{row['pid']}:{row['worker_state']}" for row in rows))


asyncio.run(main())
PYEOF
}

REGISTRY=""
for _ in $(seq 1 30); do
    REGISTRY="$(read_registry)"
    registered="$(wc -w <<<"$REGISTRY" | tr -d ' ')"
    masters="$(grep -o ':master' <<<"$REGISTRY" | wc -l | tr -d ' ' || true)"
    followers="$(grep -o ':follower' <<<"$REGISTRY" | wc -l | tr -d ' ' || true)"
    [ "$registered" -eq "$CUSTODIANS" ] \
        && [ "$masters" -eq 1 ] \
        && [ "$followers" -eq "$((CUSTODIANS - 1))" ] && break
    sleep 1
done
[ "$registered" -eq "$CUSTODIANS" ] \
    || fail "worker registry contains API processes: $REGISTRY"
[ "$masters" -eq 1 ] && [ "$followers" -eq "$((CUSTODIANS - 1))" ] \
    || fail "custodian quorum did not converge: $REGISTRY"

STATUS="$(curl -sS -m 5 "http://127.0.0.1:$API_PORT/api/v1/vault/status")"
printf '%s' "$STATUS" | "$PY" -c '
import json
import sys

status = json.load(sys.stdin)
expected = int(sys.argv[1])
threshold = max(2, expected // 2 + 1)
assert status["custody_mode"] == "separated", status
assert status["custodian_workers_expected"] == expected, status
assert status["custodian_workers_live"] == expected, status
assert status["custodian_quorum_threshold"] == threshold, status
assert status["custodian_master_present"] is True, status
' "$CUSTODIANS" || fail "custody status is inconsistent: $STATUS"

AUTH="Authorization: Bearer $TOKEN"
CREATE="$(curl -sS -m 15 -w '\n%{http_code}' -H "$AUTH" \
    -H 'Content-Type: application/json' \
    --data '{"name":"custody-smoke","value":"survives-api-recycle"}' \
    "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/")"
[ "$(tail -1 <<<"$CREATE")" = 201 ] || fail "secret create failed: $CREATE"

# Crash the elected custodian. The two surviving shares must reconstruct the
# generation, and the fixed supervisor must replace the lost process using a
# spare share from that same polynomial.
MASTER_PID=""
for entry in $REGISTRY; do
    case "$entry" in *:master) MASTER_PID=${entry%:*}; break ;; esac
done
[ -n "$MASTER_PID" ] || fail "could not identify custody master: $REGISTRY"
say "crashing custody master $MASTER_PID"
kill -KILL "$MASTER_PID"

REGISTRY_RECOVERED=""
for _ in $(seq 1 90); do
    REGISTRY_RECOVERED="$(read_registry)"
    registered="$(wc -w <<<"$REGISTRY_RECOVERED" | tr -d ' ')"
    masters="$(grep -o ':master' <<<"$REGISTRY_RECOVERED" | wc -l | tr -d ' ' || true)"
    followers="$(grep -o ':follower' <<<"$REGISTRY_RECOVERED" | wc -l | tr -d ' ' || true)"
    if [ "$registered" -eq "$CUSTODIANS" ] \
        && [ "$masters" -eq 1 ] \
        && [ "$followers" -eq "$((CUSTODIANS - 1))" ] \
        && ! grep -qw "$MASTER_PID:master" <<<"$REGISTRY_RECOVERED"; then
        break
    fi
    sleep 1
done
[ "$registered" -eq "$CUSTODIANS" ] \
    && [ "$masters" -eq 1 ] \
    && [ "$followers" -eq "$((CUSTODIANS - 1))" ] \
    && ! grep -qw "$MASTER_PID:master" <<<"$REGISTRY_RECOVERED" \
    || fail "custody quorum did not recover after master crash: $REGISTRY_RECOVERED"

READ=""
for _ in $(seq 1 30); do
    READ="$(curl -sS -m 5 -H "$AUTH" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/custody-smoke" \
        2>/dev/null || true)"
    printf '%s' "$READ" | grep -q '"value":"survives-api-recycle"' && break
    sleep 1
done
printf '%s' "$READ" | grep -q '"value":"survives-api-recycle"' \
    || fail "secret read failed after custody failover: $READ"
REGISTRY="$REGISTRY_RECOVERED"

# Kill and replace one public worker. It must never alter the custody rows or
# consume a Shamir share. The Uvicorn supervisor is a direct launcher child;
# its workers are spawn_main children.
API_SUPERVISOR="$(ps -eo pid=,ppid=,args= | awk \
    -v parent="$LAUNCHER_PID" -v port="$API_PORT" \
    '$2 == parent && $0 ~ "--port " port { print $1; exit }')"
[ -n "$API_SUPERVISOR" ] || fail "could not identify API supervisor"
api_worker_pids() {
    ps -eo pid=,ppid=,args= | awk \
        -v parent="$API_SUPERVISOR" '$2 == parent && /spawn_main/ { print $1 }'
}

for cycle in $(seq 1 "$API_RECYCLES"); do
    OLD_API_WORKER="$(api_worker_pids | head -1)"
    [ -n "$OLD_API_WORKER" ] || fail "could not identify disposable API worker"
    say "recycling public API worker $OLD_API_WORKER ($cycle/$API_RECYCLES)"
    kill -TERM "$OLD_API_WORKER"

    replacement=0
    for _ in $(seq 1 80); do
        current="$(api_worker_pids)"
        current_count="$(wc -w <<<"$current" | tr -d ' ')"
        if [ "$current_count" -eq "$API_WORKERS" ] \
            && ! grep -qw "$OLD_API_WORKER" <<<"$current"; then
            replacement=1
            break
        fi
        sleep 0.25
    done
    [ "$replacement" -eq 1 ] \
        || fail "API supervisor did not restore its full worker count"
done

for _ in $(seq 1 20); do
    READ="$(curl -sS -m 5 -H "$AUTH" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/custody-smoke" \
        2>/dev/null || true)"
    printf '%s' "$READ" | grep -q '"value":"survives-api-recycle"' && break
    sleep 0.5
done
printf '%s' "$READ" | grep -q '"value":"survives-api-recycle"' \
    || fail "secret read failed after API recycle: $READ"

REGISTRY_AFTER="$(read_registry)"
[ "$REGISTRY_AFTER" = "$REGISTRY" ] \
    || fail "API recycle changed Shamir custody registry: before=$REGISTRY after=$REGISTRY_AFTER"
! grep -q "Already borrowed" "$LOG" \
    || fail "share-server borrow race recurred during custody failover"

say "PASS -- custody master failed over; API worker replaced without changing $REGISTRY_AFTER; secret remained readable"
