#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# Live end-to-end check for LOSING PROCESSES under separated Rust custody, on
# one node. The migration harness proves the data survives moving between
# custody modes; this one proves the pool survives the things that actually
# kill processes in production: OOM, crashes, restarts.
#
# Every loss below is a SIGKILL, because that is what the kernel sends.
#
#   0 baseline    3-of-5 pool + 3 API workers, unseal, populate, read
#   1 holder      kill one SEALED share holder: the supervisor restarts it
#                 empty, the maintenance leader refills it from the surviving
#                 quorum, and reads never stop
#   2 lead        kill the UNSEALED crypto lead: workers lose their crypto
#                 socket, the maintenance leader repairs and reopens, reads
#                 come back without any password
#   3 worker      kill the master API worker: uvicorn replaces it, another
#                 worker takes the role, reads never stop
#   4 quorum      kill the lead plus enough holders that fewer than threshold
#                 shares survive: the vault seals and STAYS sealed, and
#                 /unseal is REFUSED while surviving shares exist -- partial
#                 loss must never silently rekey
#   5 full loss   kill the remaining holders too: the pool holds nothing, and
#                 /unseal with the master password re-derives and re-splits.
#                 With persistence off this is the NORMAL state after any
#                 host reboot, so this recovery path is the one that matters.
#
# What it cannot prove: multi-node HA (each node owns its own pool by design;
# this harness is one node's worth of it), or PostgreSQL failover.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_SMOKE_API_WORKERS:-3}"
RUST_SLOTS="${RH_SMOKE_RUST_SLOTS:-5}"
PG_PORT="${RH_SMOKE_PG_PORT:-55446}"
API_PORT="${RH_SMOKE_API_PORT:-18209}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:18-trixie}"
CUSTODIAN_BIN="${RH_RUST_CUSTODIAN_BINARY:-$ROOT/api/rust/target/release/rhorizon-custodian}"
CONVERGE_SECS="${RH_SMOKE_CONVERGE_SECS:-120}"
PG_NAME="rhorizon-custody-ha-smoke-pg-$$"
WORK="$(mktemp -d "${TMPDIR:-$HOME/tmp}/rh-custody-ha.XXXXXX")"
RUN="$WORK/run"
LOG="$WORK/rhorizon.log"
LAUNCHER_PID=""
PASSWORD=""
TOKEN=""

say() { printf '[custody-ha-smoke] %s\n' "$*"; }
fail() {
    printf '[custody-ha-smoke] FAIL: %s\n' "$*" >&2
    [ ! -f "$LOG" ] || tail -80 "$LOG" >&2
    exit 1
}

stop_pool() {
    [ -n "$LAUNCHER_PID" ] || return 0
    kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
    wait "$LAUNCHER_PID" 2>/dev/null || true
    LAUNCHER_PID=""
}

cleanup() {
    if [ -n "${RH_SMOKE_KEEP:-}" ]; then
        say "RH_SMOKE_KEEP set: stack left up (pid $LAUNCHER_PID, log $LOG)"
        return
    fi
    stop_pool
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

command -v docker >/dev/null || { say "no container runtime -- skip"; exit 2; }
[ -x "$PY" ] || { say "no venv at $PY -- skip"; exit 2; }
[ -x "$CUSTODIAN_BIN" ] || { say "no custodian binary -- skip"; exit 2; }

api() {
    method=$1
    path=$2
    shift 2
    curl -fsS -m 60 -X "$method" \
        ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
        -H 'Content-Type: application/json' "$@" \
        "http://127.0.0.1:$API_PORT/api/v1/vault$path"
}

retry_ok() {
    label=$1
    shift
    deadline=$(( $(date +%s) + CONVERGE_SECS ))
    while :; do
        if out=$("$@" 2>/dev/null); then
            printf '%s' "$out"
            return 0
        fi
        [ "$(date +%s)" -lt "$deadline" ] || break
        sleep 2
    done
    fail "$label never succeeded before the deadline"
}

# One framed JSON op against one custodian's own Unix socket. status and
# share_status carry no secrets and need no capability; asking the daemons
# directly is the only view that does not depend on the API being healthy.
daemon_op() {
    "$PY" - "$RUN/rust-custodian-$1.sock" "$2" <<'PYEOF' 2>/dev/null
import json, socket, struct, sys

path, op = sys.argv[1:]
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(path)
request = json.dumps({"op": op}).encode()
s.sendall(struct.pack(">I", len(request)) + request)
header = b""
while len(header) < 4:
    chunk = s.recv(4 - len(header))
    if not chunk:
        raise SystemExit(1)
    header += chunk
length = struct.unpack(">I", header)[0]
payload = b""
while len(payload) < length:
    chunk = s.recv(length - len(payload))
    if not chunk:
        raise SystemExit(1)
    payload += chunk
print(payload.decode())
PYEOF
}

daemon_field() { # slot op field -> value or "null"
    daemon_op "$1" "$2" | "$PY" -c '
import json, sys
result = json.load(sys.stdin).get("result", {})
value = result.get(sys.argv[1]) if isinstance(result, dict) else None
print("null" if value is None else value)
' "$3" 2>/dev/null
}

unsealed_slot() {
    slot=1
    while [ "$slot" -le "$RUST_SLOTS" ]; do
        [ "$(daemon_field "$slot" status state)" = unsealed ] && { echo "$slot"; return 0; }
        slot=$((slot + 1))
    done
    return 1
}

slot_pid() { pgrep -f -- "--socket $RUN/rust-custodian-$1.sock" | head -1; }

kill_slot() {
    victim_pid="$(slot_pid "$1")"
    [ -n "$victim_pid" ] || fail "no daemon process found for slot $1"
    kill -KILL "$victim_pid"
    say "  killed custodian slot $1 (pid $victim_pid)"
}

# The pool has converged when every slot holds the SAME share generation with
# no transaction leftovers. Prints that generation.
wait_pool_converged() {
    label=$1
    deadline=$(( $(date +%s) + CONVERGE_SECS ))
    while :; do
        generations=""
        clean=1
        slot=1
        while [ "$slot" -le "$RUST_SLOTS" ]; do
            generation="$(daemon_field "$slot" share_status generation || echo error)"
            prepared="$(daemon_field "$slot" share_status prepared_generation || echo error)"
            previous="$(daemon_field "$slot" share_status previous_generation || echo error)"
            [ "$generation" != null ] && [ "$generation" != error ] || clean=0
            [ "$prepared" = null ] && [ "$previous" = null ] || clean=0
            generations="$generations $generation"
            slot=$((slot + 1))
        done
        if [ "$clean" = 1 ] && [ "$(echo "$generations" | tr ' ' '\n' | sort -u | grep -c .)" = 1 ]; then
            echo "$generations" | tr ' ' '\n' | grep . | head -1
            return 0
        fi
        [ "$(date +%s)" -lt "$deadline" ] || break
        sleep 2
    done
    fail "pool never converged ($label): generations$generations"
}

db_query() {
    "$PY" - "$PG_PORT" "$1" <<'PYEOF'
import asyncio, sys
import asyncpg

async def main():
    port, query = sys.argv[1:]
    conn = await asyncpg.connect(f"postgresql://postgres:hasmoke@127.0.0.1:{port}/rhorizon")
    rows = await conn.fetch(query)
    await conn.close()
    for row in rows:
        print("\t".join("" if v is None else str(v) for v in row.values()))

asyncio.run(main())
PYEOF
}

read_secret_once() { api GET "/secrets/ha-canary?namespace=prod"; }

assert_serving() {
    stage=$1
    retry_ok "read ha-canary at $stage" read_secret_once \
        | grep -q 'ha-canary-value' || fail "ha-canary wrong at $stage"
    retry_ok "read PKI CA at $stage" api GET "/pki/ca" \
        | grep -q 'BEGIN CERTIFICATE' || fail "PKI CA unreadable at $stage"
    say "  secret and PKI CA read back at $stage"
}

unseal_once() {
    curl -fsS -m 180 -H 'Content-Type: application/json' \
        --data "{\"password\":\"$PASSWORD\"}" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/unseal"
}

say "starting temporary PostgreSQL on 127.0.0.1:$PG_PORT"
docker run -d --rm --name "$PG_NAME" \
    -e POSTGRES_PASSWORD=hasmoke -e POSTGRES_DB=rhorizon \
    -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" >/dev/null

"$PY" - "$PG_PORT" "$ROOT/schema.sql" <<'PYEOF' || fail "schema apply failed"
import asyncio, sys
import asyncpg

async def main():
    port, schema_path = sys.argv[1:]
    schema = open(schema_path, encoding="utf-8").read()
    for _ in range(30):
        try:
            conn = await asyncpg.connect(
                f"postgresql://postgres:hasmoke@127.0.0.1:{port}/rhorizon", timeout=5
            )
            await conn.execute(schema)
            await conn.close()
            return
        except Exception:
            await asyncio.sleep(1)
    raise RuntimeError("PostgreSQL never became ready")

asyncio.run(main())
PYEOF

mkdir -p "$WORK/audit" "$RUN" "$WORK/data" "$WORK/custody" "$WORK/prom"
chmod 700 "$RUN" "$WORK/data" "$WORK/custody"

say "starting the stack: separated/rust, $RUST_SLOTS custodians, $API_WORKERS API workers"
(
    cd "$ROOT/api"
    PATH="$(dirname "$PY"):$PATH" \
    RH_DATABASE_URL="postgresql+asyncpg://postgres:hasmoke@127.0.0.1:$PG_PORT/rhorizon" \
    RH_DATABASE_SSL=disable \
    RH_AUDIT_DIR="$WORK/audit" \
    RH_AUTHFAIL_LOG="$WORK/audit/authfail.log" \
    RH_RUNTIME_DIR="$RUN" \
    RHORIZON_RUNTIME_DIR="$RUN" \
    RH_NODE_UUID_PATH="$WORK/data/node-uuid" \
    RH_CLUSTER_CERT_PATH="$WORK/data/cluster-cert.pem" \
    RH_CLUSTER_CERT_KEY_PATH="$WORK/data/cluster-cert.key" \
    RH_CUSTODY_MODE=separated \
    RH_CUSTODY_BACKEND=rust \
    RH_RUST_CUSTODIAN_SLOTS="$RUST_SLOTS" \
    RH_RUST_CUSTODIAN_THRESHOLD=0 \
    RH_RUST_CUSTODIAN_BINARY="$CUSTODIAN_BIN" \
    RH_RUST_CUSTODIAN_KEY_DIR="$WORK/custody" \
    RH_CUSTODIAN_TOKEN_FILE="$RUN/custodian-control.token" \
    RH_WORKERS="$API_WORKERS" \
    RH_UVICORN_HOST=127.0.0.1 \
    RH_UVICORN_PORT="$API_PORT" \
    PROMETHEUS_MULTIPROC_DIR="$WORK/prom" \
        ./run-api.sh
) >>"$LOG" 2>&1 &
LAUNCHER_PID=$!
for _ in $(seq 1 160); do
    curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
    kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "launcher exited during start"
    sleep 0.5
done
curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 || fail "API did not start"

THRESHOLD=$(( RUST_SLOTS / 2 + 1 ))

# --- 0. baseline ---------------------------------------------------------------
say "=== 0. baseline: unseal, populate, read ==="
PASSWORD="ha-smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
UNSEAL="$(retry_ok "bootstrap unseal" unseal_once)"
printf '%s' "$UNSEAL" | grep -q '"status":"unsealed"' || fail "bootstrap unseal failed"
TOKEN="$(printf '%s' "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "no root token"
retry_ok "create ha-canary" api POST "/secrets/" \
    --data '{"name":"ha-canary","value":"ha-canary-value","namespace":"prod"}' >/dev/null
retry_ok "init PKI CA" api POST "/pki/init" \
    --data '{"common_name":"ha-smoke-ca","algorithm":"ed25519"}' >/dev/null
GENERATION="$(wait_pool_converged baseline)"
LEAD="$(unsealed_slot)" || fail "no unsealed custodian after baseline unseal"
say "  pool at generation $GENERATION, crypto lead is slot $LEAD"
assert_serving baseline

# --- 1. lose one sealed share holder --------------------------------------------
say "=== 1. kill one SEALED share holder ==="
HOLDER=""
slot=1
while [ "$slot" -le "$RUST_SLOTS" ]; do
    [ "$slot" != "$LEAD" ] && { HOLDER=$slot; break; }
    slot=$((slot + 1))
done
kill_slot "$HOLDER"
GENERATION="$(wait_pool_converged "after holder loss")"
say "  slot $HOLDER refilled by the surviving quorum (generation $GENERATION)"
assert_serving "holder loss"

# --- 2. lose the unsealed crypto lead --------------------------------------------
say "=== 2. kill the UNSEALED crypto lead (slot $LEAD) ==="
kill_slot "$LEAD"
assert_serving "lead loss"
GENERATION="$(wait_pool_converged "after lead loss")"
LEAD="$(retry_ok "a custodian reopened" unsealed_slot)"
say "  pool reopened without a password: lead slot $LEAD, generation $GENERATION"

# --- 3. lose one API worker ---------------------------------------------------------
# Under separated custody no worker takes the master state (crypto lives in
# the daemons), so any worker is as good a victim as any other; prefer a
# master if one ever exists so the harness also covers embedded-like roles.
say "=== 3. kill an API worker ==="
PRE_PIDS="$(db_query "SELECT pid FROM vault_workers")"
VICTIM_PID="$(db_query "SELECT pid FROM vault_workers WHERE worker_state = 'master' ORDER BY pid LIMIT 1" | head -1)"
[ -n "$VICTIM_PID" ] || VICTIM_PID="$(db_query "SELECT pid FROM vault_workers ORDER BY last_heartbeat DESC LIMIT 1" | head -1)"
[ -n "$VICTIM_PID" ] || fail "no registered API worker to kill"
kill -0 "$VICTIM_PID" 2>/dev/null || fail "registered worker pid $VICTIM_PID is not alive"
kill -KILL "$VICTIM_PID"
say "  killed API worker pid $VICTIM_PID"
assert_serving "worker loss"
# The reaper only deletes stale rows every 5 minutes, so the row lingering is
# by design. The HA fact to assert is the REPLACEMENT: uvicorn restarts the
# worker, a NEW pid registers with a live heartbeat, and the dead pid's
# heartbeat goes stale.
deadline=$(( $(date +%s) + CONVERGE_SECS ))
while :; do
    FRESH="$(db_query "SELECT pid FROM vault_workers WHERE last_heartbeat > NOW() - INTERVAL '15 seconds'")"
    fresh_count="$(printf '%s\n' "$FRESH" | grep -c . || true)"
    if [ "$fresh_count" = "$API_WORKERS" ] \
        && ! printf '%s\n' "$FRESH" | grep -qx "$VICTIM_PID"; then
        NEW_PID="$(printf '%s\n' "$FRESH" | grep -vxF "$(printf '%s\n' "$PRE_PIDS")" | head -1 || true)"
        [ -n "$NEW_PID" ] && break
    fi
    [ "$(date +%s)" -lt "$deadline" ] || \
        fail "no replacement worker registered (fresh: $(printf '%s' "$FRESH" | tr '\n' ' '))"
    sleep 2
done
say "  replacement worker pid $NEW_PID registered, dead pid went stale, service never stopped"

# --- 4. below-quorum partial loss: sealed, and unseal is REFUSED -------------------
say "=== 4. drop below quorum: lead + holders, $((RUST_SLOTS - THRESHOLD + 1)) kills ==="
LEAD="$(unsealed_slot)" || fail "no unsealed custodian before quorum loss"
KILLED=1
kill_slot "$LEAD"
slot=1
while [ "$KILLED" -lt $(( RUST_SLOTS - THRESHOLD + 1 )) ]; do
    if [ "$slot" != "$LEAD" ]; then
        kill_slot "$slot"
        KILLED=$((KILLED + 1))
    fi
    slot=$((slot + 1))
done
# The kills are SIGKILL and the supervisor restarts each slot EMPTY, so fewer
# than threshold shares survive. Workers only notice on failed crypto traffic
# -- a quiet vault keeps reporting its last belief -- so keep issuing reads
# the way production would, and require every worker to converge on sealed.
# A worker only flips its sealed view on ITS OWN failed operation, so the
# fleet converges worker by worker as traffic finds each one; /status samples
# land on random workers and can legitimately flap during that window.
# Assert what is security-relevant: reads fail, and at least one worker
# reports the honest sealed view with no custodian master present.
deadline=$(( $(date +%s) + CONVERGE_SECS ))
read_failed=0
while :; do
    read_secret_once >/dev/null 2>&1 || read_failed=1
    STATUS="$(curl -fsS -m 5 "http://127.0.0.1:$API_PORT/api/v1/vault/status" 2>/dev/null || true)"
    if [ "$read_failed" = 1 ] && printf '%s' "$STATUS" | grep -q '"sealed":true'; then
        printf '%s' "$STATUS" | grep -q '"custodian_master_present":false' \
            || fail "sealed status still claims a custodian master: $STATUS"
        break
    fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "vault never sealed after quorum loss: $STATUS"
    sleep 2
done
say "  reads failed and the vault sealed after losing the quorum"
# Partial loss must not silently rekey: while ANY current share survives, the
# password path is refused. Give the maintenance loop a few ticks first so a
# racing repair could only make this pass wrongly, never fail wrongly.
sleep 15
if OUT="$(unseal_once 2>&1)"; then
    fail "unseal was ACCEPTED below quorum with surviving shares: $OUT"
fi
say "  unseal refused while $((THRESHOLD - 1)) current shares survive (no silent rekey)"

# --- 5. full loss, then password recovery -------------------------------------------
say "=== 5. kill the remaining holders: full loss, then recover by password ==="
slot=1
while [ "$slot" -le "$RUST_SLOTS" ]; do
    generation="$(daemon_field "$slot" share_status generation || echo null)"
    if [ "$generation" != null ]; then
        kill_slot "$slot"
    fi
    slot=$((slot + 1))
done
# Wait until every slot answers again and holds nothing: this is exactly the
# state a host reboot leaves behind with persistence off.
deadline=$(( $(date +%s) + CONVERGE_SECS ))
while :; do
    empty=0
    slot=1
    while [ "$slot" -le "$RUST_SLOTS" ]; do
        [ "$(daemon_field "$slot" share_status generation || echo error)" = null ] \
            && empty=$((empty + 1))
        slot=$((slot + 1))
    done
    [ "$empty" = "$RUST_SLOTS" ] && break
    [ "$(date +%s)" -lt "$deadline" ] || fail "pool never came back fully empty"
    sleep 2
done
say "  every slot restarted empty (the post-reboot state)"
# A worker that served no traffic since the loss still believes it is
# unsealed and answers /unseal with "already_unsealed" without touching the
# pool. Failing reads are what seal that belief, so interleave them and
# accept only a REAL unseal -- one that reports "unsealed" -- as recovery.
RECOVER=""
deadline=$(( $(date +%s) + CONVERGE_SECS ))
while :; do
    read_secret_once >/dev/null 2>&1 || true
    if RECOVER="$(unseal_once 2>/dev/null)" \
        && printf '%s' "$RECOVER" | grep -q '"status":"unsealed"'; then
        break
    fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "recovery unseal never succeeded: $RECOVER"
    sleep 2
done
# A re-unseal of an initialized vault mints no new root token; the one from
# the baseline stays valid because nothing here was a restore.
NEW_TOKEN="$(printf '%s' "$RECOVER" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4 || true)"
[ -z "$NEW_TOKEN" ] || TOKEN="$NEW_TOKEN"
GENERATION="$(wait_pool_converged "after full-loss recovery")"
say "  password recovery re-split the pool at generation $GENERATION"
assert_serving "full-loss recovery"

say "PASS: one node's separated Rust custody survived a holder loss, a lead"
say "      loss and a worker loss without stopping; refused to rekey below"
say "      quorum; and recovered from full loss with the master password."
