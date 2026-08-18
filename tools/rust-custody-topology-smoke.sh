#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# Live end-to-end check for a custodian TOPOLOGY change against REAL daemons.
# PostgreSQL runs in a temporary container; the Rust quorum and the API pool
# both run natively through the production launchers, and the pool is really
# stopped and relaunched under a different RH_RUST_CUSTODIAN_SLOTS.
#
# What this proves that the unit suites cannot: the operator's restart IS the
# decision. The same recorded envelopes roll FORWARD when the pool comes back
# under the target shape and are DROPPED when it comes back under the old one,
# with the secret readable across every outcome and no password re-entered --
# custodians reload their shares from disk, so a topology change is a restart,
# not an unseal ceremony.
#
# Three transitions, one stack:
#   grow    3 -> 5   relaunch under the target: roll forward
#   abort   5 -> 3   relaunch under the OLD shape: drop the target
#   shrink  5 -> 3   relaunch under the target: roll forward, no new keys

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_SMOKE_API_WORKERS:-2}"
PG_PORT="${RH_SMOKE_PG_PORT:-55441}"
API_PORT="${RH_SMOKE_API_PORT:-18204}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:18-trixie}"
CUSTODIAN_BIN="${RH_RUST_CUSTODIAN_BINARY:-$ROOT/api/rust/target/release/rhorizon-custodian}"
PG_NAME="rhorizon-custody-topology-smoke-pg-$$"
WORK="$(mktemp -d "${TMPDIR:-$HOME/tmp}/rh-custody-topology-smoke.XXXXXX")"
LOG="$WORK/rhorizon.log"
LAUNCHER_PID=""
POOL_SLOTS=""

say() { printf '[custody-topology-smoke] %s\n' "$*"; }
fail() {
    printf '[custody-topology-smoke] FAIL: %s\n' "$*" >&2
    [ ! -f "$LOG" ] || tail -80 "$LOG" >&2
    exit 1
}

stop_pool() {
    [ -n "$LAUNCHER_PID" ] || return 0
    kill -TERM "$LAUNCHER_PID" 2>/dev/null || true
    wait "$LAUNCHER_PID" 2>/dev/null || true
    LAUNCHER_PID=""
    # The launcher removes its own sockets on the way out. A leftover one
    # would make the next start refuse, which is the guard working, not a
    # flake -- so surface it rather than cleaning up behind it.
    slot=1
    while [ "$slot" -le 9 ]; do
        [ ! -S "$WORK/run/rust-custodian-$slot.sock" ] \
            || fail "custodian socket for slot $slot outlived the launcher"
        slot=$((slot + 1))
    done
}

cleanup() {
    if [ -n "${RH_SMOKE_KEEP:-}" ]; then
        say "RH_SMOKE_KEEP set: leaving the stack UP for inspection"
        say "  api:      http://127.0.0.1:$API_PORT (launcher pid $LAUNCHER_PID)"
        say "  log:      $LOG"
        say "  custody:  $WORK/custody"
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

custody_state() {
    query "SELECT value FROM vault_config WHERE key LIKE 'rust_custody_generation_state%'"
}

envelope_rows() {
    query "SELECT count(*) FROM vault_custody_topology_reshare"
}

json_field() {
    "$PY" -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}

# Same env for the launcher and for the out-of-process ceremony driver: both
# have to see the same database, the same runtime directory and the same key
# directory, or the driver would talk to a pool the API does not own.
pool_env() {
    RH_DATABASE_URL="postgresql+asyncpg://postgres:smoke@127.0.0.1:$PG_PORT/rhorizon"
    RH_DATABASE_SSL=disable
    RH_AUDIT_DIR="$WORK/audit"
    RH_AUTHFAIL_LOG="$WORK/audit/authfail.log"
    RH_RUNTIME_DIR="$WORK/run"
    RHORIZON_RUNTIME_DIR="$WORK/run"
    RH_NODE_UUID_PATH="$WORK/data/node-uuid"
    RH_CLUSTER_CERT_PATH="$WORK/data/cluster-cert.pem"
    RH_CLUSTER_CERT_KEY_PATH="$WORK/data/cluster-cert.key"
    RH_CUSTODY_MODE=separated
    RH_CUSTODY_BACKEND=rust
    RH_RUST_CUSTODIAN_BINARY="$CUSTODIAN_BIN"
    RH_RUST_CUSTODIAN_KEY_DIR="$WORK/custody"
    RH_CUSTODIAN_TOKEN_FILE="$WORK/run/custodian-control.token"
    PROMETHEUS_MULTIPROC_DIR="$WORK/prom"
    export RH_DATABASE_URL RH_DATABASE_SSL RH_AUDIT_DIR RH_AUTHFAIL_LOG \
        RH_RUNTIME_DIR RHORIZON_RUNTIME_DIR RH_NODE_UUID_PATH \
        RH_CLUSTER_CERT_PATH RH_CLUSTER_CERT_KEY_PATH RH_CUSTODY_MODE \
        RH_CUSTODY_BACKEND RH_RUST_CUSTODIAN_BINARY RH_RUST_CUSTODIAN_KEY_DIR \
        RH_CUSTODIAN_TOKEN_FILE PROMETHEUS_MULTIPROC_DIR
}

# start_pool <configured_slots> [expected_slots]
# The two differ exactly when the configuration names a shape the pool does not
# hold: the launcher resolves the durable one, so asserting a socket per
# CONFIGURED slot would fail on the very case that is being tested.
start_pool() {
    start_slots=$1
    expect_slots=${2:-$1}
    POOL_SLOTS=$expect_slots
    say "starting the pool with RH_RUST_CUSTODIAN_SLOTS=$start_slots (expecting $expect_slots live)"
    (
        cd "$ROOT/api"
        pool_env
        PATH="$(dirname "$PY"):$PATH" \
        RH_RUST_CUSTODIAN_SLOTS="$start_slots" \
        RH_RUST_CUSTODIAN_THRESHOLD=0 \
        RH_WORKERS="$API_WORKERS" \
        RH_UVICORN_HOST=127.0.0.1 \
        RH_UVICORN_PORT="$API_PORT" \
            ./run-api.sh
    ) >>"$LOG" 2>&1 &
    LAUNCHER_PID=$!

    for _ in $(seq 1 120); do
        curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
        kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "launcher exited during start"
        sleep 0.5
    done
    curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null \
        || fail "public API did not start with $start_slots slots"

    slot=1
    while [ "$slot" -le "$expect_slots" ]; do
        [ -S "$WORK/run/rust-custodian-$slot.sock" ] \
            || fail "custodian slot $slot has no socket"
        slot=$((slot + 1))
    done
    next=$((expect_slots + 1))
    [ ! -S "$WORK/run/rust-custodian-$next.sock" ] \
        || fail "slot $next came up: more daemons than the resolved shape"
    say "all $expect_slots custodian daemons are live"
}

# A relaunched pool is reopened by the maintenance leader, not by an operator:
# the durable intent is still "unsealed" and the shares are on disk. Waiting on
# the API's own sealed=false is therefore the honest end-to-end signal.
#
# One probe is not enough. An unseal reaches only the worker that served it and
# the rest follow on their maintenance tick, so requests round-robin into a
# straggler that still answers sealed -- exactly the 503 a canary write hits.
# Require consecutive agreement across more probes than there are workers.
wait_unsealed() {
    secs="${RH_SMOKE_CONVERGE_SECS:-90}"
    probes=$((API_WORKERS * 6))
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        mismatch=0
        for _ in $(seq 1 "$probes"); do
            probe="$(curl -sS -m 5 "http://127.0.0.1:$API_PORT/api/v1/vault/status" || true)"
            printf '%s' "$probe" | grep -q '"sealed":false' || mismatch=$((mismatch + 1))
        done
        if [ "$mismatch" -eq 0 ]; then
            say "all $API_WORKERS workers converged to unsealed ($probes consecutive probes)"
            return 0
        fi
        sleep 2
    done
    fail "$mismatch/$probes probes still answered sealed after ${secs}s: the pool never reopened across the whole API pool"
}

wait_for_phase_stable() {
    want_generation=$1
    want_threshold=$2
    want_slots=$3
    deadline=$(( $(date +%s) + ${RH_SMOKE_CONVERGE_SECS:-90} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(custody_state)"
        if [ -n "$state" ] \
            && [ "$(json_field "$state" phase)" = stable ] \
            && [ "$(json_field "$state" active_generation)" = "$want_generation" ] \
            && [ "$(json_field "$state" threshold)" = "$want_threshold" ] \
            && [ "$(json_field "$state" slots)" = "$want_slots" ]; then
            say "durable state converged: $state"
            return 0
        fi
        sleep 2
    done
    fail "durable state never reached stable $want_threshold-of-$want_slots at generation $want_generation: $(custody_state)"
}

# An unseal reaches only the worker that served it; the others follow on their
# own tick. Every worker accepts from the same socket, so probing /status can
# repeatedly hit the one that is already open while another is still sealed --
# a barrier built on probes is a coin toss. Retry the operation itself instead:
# 503 means "not this worker, not yet", and a real failure still runs out of
# attempts.
retry_ok() {
    retry_label=$1
    shift
    retry_deadline=$(( $(date +%s) + ${RH_SMOKE_CONVERGE_SECS:-90} ))
    while :; do
        if retry_output=$("$@" 2>/dev/null); then
            printf '%s' "$retry_output"
            return 0
        fi
        [ "$(date +%s)" -lt "$retry_deadline" ] || break
        sleep 2
    done
    fail "$retry_label never succeeded before the deadline"
}

read_canary_once() {
    curl -fsS -m 15 -H "Authorization: Bearer $TOKEN" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/custody-topology-canary?namespace=default"
}

read_canary() {
    retry_ok "canary read" read_canary_once
}

write_canary_once() {
    curl -fsS -m 15 -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' \
        --data '{"name":"custody-topology-canary","value":"must-survive-every-reshape","namespace":"default"}' \
        "http://127.0.0.1:$API_PORT/api/v1/vault/secrets/"
}

# The half of the ceremony an API process can do. Runs OUT of process on
# purpose: it proves the whole thing is reachable over the custodian control
# sockets plus the database, which is exactly what a future admin route does
# from inside the container.
begin_change() {
    from_slots=$1
    from_threshold=$2
    to_threshold=$3
    to_slots=$4
    (
        cd "$ROOT/api"
        pool_env
        "$PY" - "$WORK" "$from_slots" "$from_threshold" "$to_threshold" "$to_slots" \
            "$CUSTODIAN_BIN" <<'PYEOF'
import asyncio
import os
import subprocess
import sys
from pathlib import Path

work, from_slots, from_threshold, to_threshold, to_slots, binary = sys.argv[1:]
from_slots = int(from_slots)
to_slots = int(to_slots)

# Private key material: the launcher runs under umask 077 and so must this.
os.umask(0o077)

from app.custody_reshare import begin_rust_custodian_topology_change
from app.rust_custody_backend import build_rust_custodian_pool

run_dir = Path(work) / "run"
key_dir = Path(work) / "custody"


def transport_public_key(slot: int) -> str:
    """Bootstrap a genuinely new slot's transport key BEFORE the change.

    The envelopes are sealed to these public keys, and the pool launcher only
    generates a missing key when it starts the slot -- which is after the
    restart, far too late. A shrink adds no slot and so needs none of this.
    """
    key_file = key_dir / f"slot-{slot}.transport-key"
    if key_file.exists():
        command = [binary, "print-transport-public-key", "--transport-key-file", str(key_file)]
    else:
        command = [binary, "generate-transport-key", "--output", str(key_file)]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout.strip()


new_peer_keys = {
    slot: transport_public_key(slot) for slot in range(from_slots + 1, to_slots + 1)
}

pool = build_rust_custodian_pool(
    runtime_directory=run_dir,
    control_token_file=run_dir / "custodian-control.token",
    slots=from_slots,
    threshold=int(from_threshold),
)

target = asyncio.run(
    begin_rust_custodian_topology_change(
        pool,
        threshold=int(to_threshold),
        slots=to_slots,
        new_peer_keys=new_peer_keys,
    )
)
print(target)
PYEOF
    )
}

# Sweep the state the resolved changes superseded, down to below each dead
# shape's own threshold. Same out-of-process pattern as begin_change.
shred_state() {
    shred_slots=$1
    shred_threshold=$2
    (
        cd "$ROOT/api"
        pool_env
        "$PY" - "$WORK" "$shred_slots" "$shred_threshold" <<'PYEOF'
import asyncio
import json
import sys
from pathlib import Path

work, slots, threshold = sys.argv[1:]

from app.custody_shred import shred_superseded_custody_state
from app.rust_custody_backend import build_rust_custodian_pool

run_dir = Path(work) / "run"
pool = build_rust_custodian_pool(
    runtime_directory=run_dir,
    control_token_file=run_dir / "custodian-control.token",
    slots=int(slots),
    threshold=int(threshold),
)
report = asyncio.run(
    shred_superseded_custody_state(pool, key_dir=Path(work) / "custody")
)
print(json.dumps(report, sort_keys=True))
PYEOF
    )
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

# --- activate a 2-of-3 pool and put a secret behind it ----------------------
start_pool 3

MASTER_PASSWORD="custody-topology-smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
UNSEAL="$(curl -sS -m 120 -H 'Content-Type: application/json' \
    --data "{\"password\":\"$MASTER_PASSWORD\"}" \
    "http://127.0.0.1:$API_PORT/api/v1/vault/unseal")"
printf '%s' "$UNSEAL" | grep -q '"status":"unsealed"' \
    || fail "first unseal (migration) failed: $UNSEAL"
TOKEN="$(printf '%s' "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "bootstrap did not return a root token"
wait_unsealed

retry_ok "canary write" write_canary_once >/dev/null
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable on the initial 2-of-3 pool"

GEN0="$(json_field "$(custody_state)" active_generation)"
wait_for_phase_stable "$GEN0" 2 3
say "baseline: generation $GEN0 on a 2-of-3 pool, canary readable"

# --- grow 3 -> 5: relaunch under the target, roll forward -------------------
say "=== grow 3 -> 5 ==="
TARGET_GROW="$(begin_change 3 2 3 5)" || fail "begin (3 -> 5) failed"
[ -n "$TARGET_GROW" ] || fail "begin (3 -> 5) returned no target generation"
say "recorded envelopes for target generation $TARGET_GROW"
[ "$(envelope_rows)" = 5 ] \
    || fail "expected 5 recorded envelopes, got $(envelope_rows)"

# The running pool must be untouched by the call itself: still 2-of-3, still
# serving the old generation, secret still readable.
STATE_AFTER_BEGIN="$(custody_state)"
[ "$(json_field "$STATE_AFTER_BEGIN" phase)" = resharding \
    -a "$(json_field "$STATE_AFTER_BEGIN" active_generation)" = "$GEN0" ] \
    || fail "begin disturbed the live generation: $STATE_AFTER_BEGIN"
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable while the change is pending"
say "pool still live on generation $GEN0 with the change pending"

stop_pool
start_pool 5
wait_for_phase_stable "$TARGET_GROW" 3 5
wait_unsealed
[ "$(envelope_rows)" = 0 ] \
    || fail "envelopes outlived the resolved transition: $(envelope_rows) rows"
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable after growing to 3-of-5"

slot=1
while [ "$slot" -le 5 ]; do
    [ -f "$WORK/custody/slot-$slot.3-of-5.share-state" ] \
        || fail "slot $slot has no 3-of-5 share state"
    slot=$((slot + 1))
done
# The transition closed, so reconciliation has already swept what it
# superseded: reverting to 2-of-3 stopped being supported the moment the new
# shape became durable, and its shares still decrypt until they are removed.
# What must remain is fewer than that shape needs, not zero.
GROW_DEAD="$(ls "$WORK/custody"/*.2-of-3.share-state 2>/dev/null | wc -l)"
[ "$GROW_DEAD" -lt 2 ] \
    || fail "2-of-3 still has $GROW_DEAD decryptable shares after the change closed, threshold is 2"
say "PASS grow: 3-of-5 live at generation $TARGET_GROW, 2-of-3 swept to $GROW_DEAD share(s)"

# --- abort: begin a shrink, then relaunch under the OLD shape ---------------
say "=== abort (begin 5 -> 3, relaunch at 5) ==="
TARGET_ABORT="$(begin_change 5 3 2 3)" || fail "begin (5 -> 3, to abort) failed"
[ "$(envelope_rows)" = 3 ] \
    || fail "expected 3 recorded envelopes, got $(envelope_rows)"
stop_pool
start_pool 5
wait_for_phase_stable "$TARGET_GROW" 3 5
wait_unsealed
[ "$(envelope_rows)" = 0 ] \
    || fail "aborted envelopes were not dropped: $(envelope_rows) rows"
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable after the aborted change"
say "PASS abort: target $TARGET_ABORT dropped, generation $TARGET_GROW untouched"

# --- shrink 5 -> 3 for real: no new transport key at all --------------------
say "=== shrink 5 -> 3 ==="
KEYS_BEFORE="$(ls "$WORK/custody"/*.transport-key | wc -l)"
TARGET_SHRINK="$(begin_change 5 3 2 3)" || fail "begin (5 -> 3) failed"
KEYS_AFTER="$(ls "$WORK/custody"/*.transport-key | wc -l)"
[ "$KEYS_BEFORE" = "$KEYS_AFTER" ] \
    || fail "a shrink minted transport keys ($KEYS_BEFORE -> $KEYS_AFTER)"
stop_pool
start_pool 3
wait_for_phase_stable "$TARGET_SHRINK" 2 3
wait_unsealed
[ "$(envelope_rows)" = 0 ] \
    || fail "envelopes outlived the shrink: $(envelope_rows) rows"
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable after shrinking to 2-of-3"
say "PASS shrink: 2-of-3 live at generation $TARGET_SHRINK, no new keys minted"

# --- re-grow 3 -> 5: back into a shape this pool has ALREADY run ------------
# The direction is irrelevant to the guard that used to wedge this. What
# matters is that every target slot still holds that shape's superseded share
# from the first grow, which is why this case has to be exercised too.
say "=== re-grow 3 -> 5 (target shape already run once) ==="
# The sweep leaves each dead shape just below its threshold rather than empty,
# so some slots still hold a superseded 3-of-5 share. Those are exactly the
# slots that used to wedge a delivery, so the case is still exercised -- assert
# that at least one survives, or this phase proves nothing.
REGROW_STALE="$(ls "$WORK/custody"/*.3-of-5.share-state 2>/dev/null | wc -l)"
[ "$REGROW_STALE" -ge 1 ] \
    || fail "no superseded 3-of-5 state survives: the wedge case is not being tested"
say "re-growing into a shape $REGROW_STALE slot(s) still hold stale state for"
TARGET_REGROW="$(begin_change 3 2 3 5)" || fail "begin (re-grow 3 -> 5) failed"
stop_pool
start_pool 5
wait_for_phase_stable "$TARGET_REGROW" 3 5
wait_unsealed
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable after re-growing into a previously run shape"
say "PASS re-grow: 3-of-5 live again at generation $TARGET_REGROW"

# --- shred what those changes superseded ------------------------------------
# The live shape is 3-of-5. The dead 2-of-3 still has all three of its shares
# decryptable, which is a quorum for it, so exactly two must go and one may
# stay: below threshold reveals nothing, and every file left alone is one the
# sweep cannot have broken.
say "=== shred superseded state ==="
# Reconciliation sweeps as each change closes, so by now the dead 2-of-3 shape
# must ALREADY be below its own threshold without anyone asking. Assert the
# automation first; the manual sweep then has to be a no-op, which is what
# makes it safe to re-run.
AUTO_REMAINING="$(ls "$WORK/custody"/*.2-of-3.share-state 2>/dev/null | wc -l)"
[ "$AUTO_REMAINING" -lt 2 ] \
    || fail "the automatic sweep left $AUTO_REMAINING decryptable 2-of-3 shares, threshold is 2"
say "automatic sweep already left 2-of-3 at $AUTO_REMAINING share(s), below its threshold"

REPORT="$(shred_state 5 3)" || fail "shred refused on a healthy stable pool"
say "manual re-run report: $REPORT"
printf '%s' "$REPORT" | grep -q '"superseded_share_state": \[\]' \
    || fail "a re-run found more to shred, so the automatic sweep was incomplete: $REPORT"
REMAINING_DEAD="$(ls "$WORK/custody"/*.2-of-3.share-state 2>/dev/null | wc -l)"
[ "$REMAINING_DEAD" -lt 2 ] \
    || fail "2-of-3 still has $REMAINING_DEAD decryptable shares, threshold is 2"
slot=1
while [ "$slot" -le 5 ]; do
    [ -f "$WORK/custody/slot-$slot.3-of-5.share-state" ] \
        || fail "the sweep destroyed live share state for slot $slot"
    [ -f "$WORK/custody/slot-$slot.transport-key" ] \
        || fail "the sweep destroyed a live transport key for slot $slot"
    slot=$((slot + 1))
done
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable immediately after the sweep"

# THE assertion this phase exists for. Deleting custody state has no soft
# landing: a pool that lost something load-bearing does not degrade, it fails
# to start. Only a real restart proves the sweep kept what the disk needs.
stop_pool
start_pool 5
wait_for_phase_stable "$TARGET_REGROW" 3 5
wait_unsealed
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable after restarting a swept pool"
say "PASS shred: dead shape below threshold, pool restarted and reopened intact"

# --- drift: the environment names a shape the pool does not hold -------------
# Until the launcher resolved its shape from the durable state, this was the
# unrecoverable case: seven daemons would come up holding nothing, and the API
# would refuse to start with no way back except guessing the old value. The
# pool must ignore the configuration and come up as what it actually holds.
say "=== drift (configure 7 slots against a 3-of-5 pool) ==="
stop_pool
start_pool 7 5
wait_for_phase_stable "$TARGET_REGROW" 3 5
wait_unsealed
grep -q "rather than the configured" "$LOG" \
    || fail "the launcher obeyed a configuration the pool cannot hold, or said nothing"
say "launcher: $(grep -h 'rather than the configured' "$LOG" | tail -1)"
slot=1
while [ "$slot" -le 5 ]; do
    [ -S "$WORK/run/rust-custodian-$slot.sock" ] || fail "slot $slot is not live"
    slot=$((slot + 1))
done
[ ! -S "$WORK/run/rust-custodian-6.sock" ] \
    || fail "a sixth slot came up: the configured shape was launched after all"
read_canary | grep -q 'must-survive-every-reshape' \
    || fail "canary unreadable after a drifted configuration"
say "PASS drift: pool held 3-of-5 and stayed open despite RH_RUST_CUSTODIAN_SLOTS=7"

say "PASS: grow, abort, shrink, re-grow, shred and drift all survive the operator's restart"
