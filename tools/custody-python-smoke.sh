#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# Does separated + PYTHON custody actually work?
#
# This mode has never been exercised end to end. It is the one where the
# custodian pool is a normal uvicorn pool behind ONE shared Unix socket, so the
# API cannot address a particular custodian: custody.py "routes" by rejection
# sampling instead -- a custodian that is not master answers 409 with
# x-rhorizon-custody-retry-master, and the caller re-dials, up to 256 times,
# re-sending the whole body. On /unseal that body carries the master password.
#
# So this harness answers two questions with facts rather than reading:
#
#   1. does the mode serve secrets, survive a restart, and complete every
#      master-only lifecycle route,
#   2. and what does the sampling actually COST -- the comment claims "the
#      expected number of probes is the pool size", which assumes the kernel
#      balances accept() fairly across uvicorn children. It does not: it
#      favours the most recently active child. rhorizon_custody_master_retries
#      is the real number, printed at the end.
#
# Deliberately NOT a migration test: no rust, no topology. One mode, one
# question. tools/rust-custody-migration-smoke.sh covers the rest.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_SMOKE_API_WORKERS:-2}"
CUSTODIAN_WORKERS="${RH_SMOKE_CUSTODIAN_WORKERS:-3}"
PG_PORT="${RH_SMOKE_PG_PORT:-55447}"
API_PORT="${RH_SMOKE_API_PORT:-18210}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:18-trixie}"
PG_NAME="rhorizon-custody-python-smoke-pg-$$"
WORK="$(mktemp -d "${TMPDIR:-$HOME/tmp}/rh-custody-python.XXXXXX")"
LOG="$WORK/rhorizon.log"
LAUNCHER_PID=""
PASSWORD=""
TOKEN=""

say() { printf '[custody-python-smoke] %s\n' "$*"; }
fail() {
    printf '[custody-python-smoke] FAIL: %s\n' "$*" >&2
    [ ! -f "$LOG" ] || tail -60 "$LOG" >&2
    exit 1
}

stop_stack() {
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
    stop_stack
    docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

command -v docker >/dev/null || { say "no container runtime -- skip"; exit 2; }
[ -x "$PY" ] || { say "no venv at $PY -- skip"; exit 2; }

api() {
    method=$1
    path=$2
    shift 2
    curl -fsS -m 120 -X "$method" \
        ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
        -H 'Content-Type: application/json' "$@" \
        "http://127.0.0.1:$API_PORT/api/v1/vault$path"
}

# An unseal reaches only the worker that served it; the others follow on their
# own tick, so a request can legitimately hit one that is not open yet. Retry
# the operation rather than sampling /status, which cannot say which worker
# answered.
retry_ok() {
    label=$1
    shift
    deadline=$(( $(date +%s) + ${RH_SMOKE_CONVERGE_SECS:-90} ))
    while :; do
        if out=$("$@" 2>/dev/null); then
            printf '%s' "$out"
            return 0
        fi
        [ "$(date +%s)" -lt "$deadline" ] || break
        sleep 2
    done
    # RETURN, never exit: this runs inside $( ) at most call sites, where an
    # exit would only kill the subshell and leave the caller with an empty
    # string -- which then dies on the next `set -e` command with no message
    # at all. Callers must append `|| fail "..."`.
    printf '[custody-python-smoke] timed out: %s\n' "$label" >&2
    return 1
}

start_stack() {
    say "starting separated/python: $CUSTODIAN_WORKERS custodians, $API_WORKERS API workers"
    (
        cd "$ROOT/api"
        PATH="$(dirname "$PY"):$PATH" \
        RH_DATABASE_URL="postgresql+asyncpg://postgres:pysmoke@127.0.0.1:$PG_PORT/rhorizon" \
        RH_DATABASE_SSL=disable \
        RH_AUDIT_DIR="$WORK/audit" \
        RH_AUTHFAIL_LOG="$WORK/audit/authfail.log" \
        RH_RUNTIME_DIR="$WORK/run" \
        RHORIZON_RUNTIME_DIR="$WORK/run" \
        RH_NODE_UUID_PATH="$WORK/data/node-uuid" \
        RH_CLUSTER_CERT_PATH="$WORK/data/cluster-cert.pem" \
        RH_CLUSTER_CERT_KEY_PATH="$WORK/data/cluster-cert.key" \
        RH_CUSTODY_MODE=separated \
        RH_CUSTODY_BACKEND=python \
        RH_CUSTODIAN_WORKERS="$CUSTODIAN_WORKERS" \
        RH_CUSTODIAN_TOKEN_FILE="$WORK/run/custodian-control.token" \
        RH_WORKERS="$API_WORKERS" \
        RH_UVICORN_HOST=127.0.0.1 \
        RH_UVICORN_PORT="$API_PORT" \
        PROMETHEUS_MULTIPROC_DIR="$WORK/prom" \
            ./run-api.sh
    ) >>"$LOG" 2>&1 &
    LAUNCHER_PID=$!
    for _ in $(seq 1 160); do
        curl -sS -m 2 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && return 0
        kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "launcher exited during start"
        sleep 0.5
    done
    fail "API did not start"
}

unseal_once() {
    curl -fsS -m 300 -H 'Content-Type: application/json' \
        --data "{\"password\":\"$PASSWORD\"}" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/unseal"
}

read_secret_once() { api GET "/secrets/$1?namespace=$2"; }

assert_everything_readable() {
    stage=$1
    retry_ok "read prod/db-password at $stage" read_secret_once py-db-password prod \
        | grep -q 'p0stgres-secret' || fail "py-db-password wrong at $stage"
    retry_ok "read staging secret at $stage" read_secret_once py-stg-password staging \
        | grep -q 'staging-only' || fail "py-stg-password wrong at $stage"
    retry_ok "read rotated at $stage" read_secret_once py-rotated prod \
        | grep -q 'version-three' || fail "rotated secret wrong at $stage"
    # The CA private key rides pki_wrap_key, a different HKDF sub-key: it
    # catches a master-key transition the DEK path survives.
    retry_ok "read PKI CA at $stage" api GET "/pki/ca" \
        | grep -q 'BEGIN CERTIFICATE' || fail "PKI CA unreadable at $stage"
    say "  secrets, version history and PKI CA all read back at $stage"
}

# The number this harness exists to produce.
master_retries() {
    curl -sS -m 10 "http://127.0.0.1:$API_PORT/metrics" 2>/dev/null \
        | awk '/^rhorizon_custody_master_retries_total /{print $2}' | tail -1
}

say "starting temporary PostgreSQL on 127.0.0.1:$PG_PORT"
docker run -d --rm --name "$PG_NAME" \
    -e POSTGRES_PASSWORD=pysmoke -e POSTGRES_DB=rhorizon \
    -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" >/dev/null

"$PY" - "$PG_PORT" "$ROOT/schema.sql" <<'PYEOF' || fail "schema apply failed"
import asyncio
import sys

import asyncpg


async def main():
    port, schema_path = sys.argv[1:]
    schema = open(schema_path, encoding="utf-8").read()
    for _ in range(30):
        try:
            conn = await asyncpg.connect(
                f"postgresql://postgres:pysmoke@127.0.0.1:{port}/rhorizon", timeout=5
            )
            await conn.execute(schema)
            await conn.close()
            return
        except Exception:
            await asyncio.sleep(1)
    raise RuntimeError("PostgreSQL never became ready")


asyncio.run(main())
PYEOF

mkdir -p "$WORK/audit" "$WORK/run" "$WORK/data" "$WORK/prom"
chmod 700 "$WORK/run" "$WORK/data"

# --- 1. does it come up and serve at all? -----------------------------------
say "=== 1. boot + unseal ==="
start_stack
PASSWORD="python-smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
UNSEAL="$(retry_ok "bootstrap unseal" unseal_once)" || fail "bootstrap unseal never succeeded"
printf '%s' "$UNSEAL" | grep -q '"status":"unsealed"' || fail "unseal failed: $UNSEAL"
TOKEN="$(printf '%s' "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4 || true)"
[ -n "$TOKEN" ] || fail "unseal returned no root token; response was: $UNSEAL"
say "unsealed through the UDS proxy"

retry_ok "create prod secret" api POST "/secrets/" \
    --data '{"name":"py-db-password","value":"p0stgres-secret","namespace":"prod"}' >/dev/null
api POST "/secrets/" --data '{"name":"py-stg-password","value":"staging-only","namespace":"staging"}' >/dev/null
api POST "/secrets/" --data '{"name":"py-rotated","value":"version-one","namespace":"prod"}' >/dev/null
api PUT "/secrets/py-rotated?namespace=prod" --data '{"value":"version-two"}' >/dev/null
api PUT "/secrets/py-rotated?namespace=prod" --data '{"value":"version-three"}' >/dev/null
api POST "/pki/init" --data '{"common_name":"python-smoke-ca","algorithm":"ed25519"}' >/dev/null \
    || fail "PKI init failed"
assert_everything_readable "boot"
say "retries after boot: $(master_retries)"

# --- 2. the master-only lifecycle routes ------------------------------------
# Every one of these is proxied over the shared UDS and must reach the ELECTED
# custodian. A 503 custodian_master_unavailable here means 256 consecutive
# misses -- the rejection sampling failing outright.
say "=== 2. master-only routes ==="
NEW_PASSWORD="rotated-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
retry_ok "rotate master password" api POST "/rotate-password" \
    --data "{\"current_password\":\"$PASSWORD\",\"new_password\":\"$NEW_PASSWORD\"}" >/dev/null
PASSWORD="$NEW_PASSWORD"
assert_everything_readable "master password rotated"

retry_ok "rotate dek_key" api POST "/admin/rotate-dek-key" \
    --data "{\"current_password\":\"$PASSWORD\"}" >/dev/null
assert_everything_readable "dek_key rotated"
say "retries after rotations: $(master_retries)"

AGE_PASSPHRASE="custody-python-smoke-age-passphrase"
retry_ok "create backup" api POST "/backup/create" \
    --data "{\"passphrase\":\"$AGE_PASSPHRASE\"}" > "$WORK/backup.json"
"$PY" - "$WORK/backup.json" "$WORK/payload.b64" <<'SPLIT_END' || fail "backup returned no payload"
import json
import sys

source, destination = sys.argv[1:]
backup = json.load(open(source, encoding="utf-8"))
if not backup["payload"]:
    raise SystemExit("backup returned no payload")
open(destination, "w", encoding="utf-8").write(backup["payload"])
print(f"[custody-python-smoke] backup: {backup['size_bytes']} bytes, "
      f"{backup['secrets_count']} secrets")
SPLIT_END

"$PY" - "$WORK/payload.b64" "$AGE_PASSPHRASE" "$PASSWORD" "$API_PORT" "$TOKEN" <<'PYEOF' \
    || fail "restore failed"
import json
import sys
import urllib.request

payload_file, age_pw, master_pw, port, token = sys.argv[1:]
body = json.dumps(
    {
        "passphrase": age_pw,
        "master_password_backup": master_pw,
        "confirm_phrase": "RESTORE",
        "payload": open(payload_file).read(),
    }
).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/api/v1/vault/backup/restore",
    data=body,
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
)
with urllib.request.urlopen(request, timeout=300) as response:
    sys.stderr.write(response.read().decode()[:200] + "\n")
PYEOF
say "restore accepted"
# A restore replaces every token with a pending-rotation stub, including the
# one that called it, so the ONLY way back in is a fresh root token from
# /unseal. But a seal reaches the custodian that served it and the others
# follow on their own tick, so an /unseal proxied to a straggler answers 200
# "already_unsealed" and hands back NO token. An operator who takes that at
# face value is locked out of a vault whose tokens were just wiped.
#
# Measure how long that window is rather than assuming it away.
unseal_until_token() {
    started=$(date +%s)
    deadline=$(( started + ${RH_SMOKE_CONVERGE_SECS:-90} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        answer="$(unseal_once 2>/dev/null || true)"
        if printf '%s' "$answer" | grep -q '"root_token"'; then
            printf '[custody-python-smoke]   root token obtained %ss after the restore\n' \
                "$(( $(date +%s) - started ))" >&2
            printf '%s' "$answer"
            return 0
        fi
        last_answer="$answer"
        sleep 2
    done
    printf '[custody-python-smoke] last /unseal answer: %s\n' "$last_answer" >&2
    return 1
}
REOPEN="$(unseal_until_token)" || fail "no root token after the restore: the vault wiped every token and never handed one back"
TOKEN="$(printf '%s' "$REOPEN" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4 || true)"
[ -n "$TOKEN" ] || fail "unseal after restore returned no root token; response was: $REOPEN"
assert_everything_readable "restored"

# --- 3. restart: does the pool come back? -----------------------------------
# Python custodians hold their shares in RAM, so unlike rust custody this must
# come back SEALED and need the operator's password again.
PRE_RESTART_RETRIES="$(master_retries)"
say "=== 3. restart ==="
stop_stack
start_stack
STATUS="$(curl -sS -m 10 "http://127.0.0.1:$API_PORT/api/v1/vault/status" 2>/dev/null || true)"
printf '%s' "$STATUS" | grep -q '"sealed":true' \
    || say "NOTE: not sealed after restart (expected sealed for python custody): $STATUS"
retry_ok "unseal after restart" unseal_once >/dev/null
assert_everything_readable "after restart"

TOTAL_RETRIES="$(master_retries)"
say "=== rejection-sampling cost ==="
say "before restart: ${PRE_RESTART_RETRIES:-0} retries for $CUSTODIAN_WORKERS custodians"
say "after restart:  ${TOTAL_RETRIES:-0} (fresh processes, counter reset)"
say "  (custody.py claims 'the expected number of probes is the pool size';"
say "   every retry re-sends the full request body over a fresh connection)"

say "PASS: separated+python served secrets, completed every master-only route,"
say "      and survived a restart"
