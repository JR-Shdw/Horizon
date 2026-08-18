#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# Live end-to-end check for MIGRATING A POPULATED VAULT onto Rust custody, and
# back off it. The topology harness proves reshaping a pool; this one proves
# the thing an operator actually does first, against data that already exists.
#
# Every phase re-reads the same secrets. That is the point: key material moves
# between an in-process Shamir quorum, a standalone daemon quorum, a rotated
# master password and a rotated dek_key, and a restore -- and a secret written
# before any of it must still read after all of it.
#
#   0 embedded   populate: secrets in two namespaces, a version history, a
#                token, a PKI CA (its key rides pki_wrap_key, so it is the
#                canary that catches a bad master-key transition)
#   1 -> rust    restart separated+rust, unseal migrates the local bundle
#   2 rotate     master password, then dek_key, with the daemons holding shares
#   3 backup     create + restore under Rust custody
#   4 -> back    restart embedded again, unseal, read: the round trip closes
#
# What it cannot prove: HA/cluster interaction, or the scale of a real vault.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
API_WORKERS="${RH_SMOKE_API_WORKERS:-2}"
PG_PORT="${RH_SMOKE_PG_PORT:-55445}"
API_PORT="${RH_SMOKE_API_PORT:-18208}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:18-trixie}"
CUSTODIAN_BIN="${RH_RUST_CUSTODIAN_BINARY:-$ROOT/api/rust/target/release/rhorizon-custodian}"
PG_NAME="rhorizon-custody-migration-smoke-pg-$$"
WORK="$(mktemp -d "${TMPDIR:-$HOME/tmp}/rh-custody-migration.XXXXXX")"
LOG="$WORK/rhorizon.log"
LAUNCHER_PID=""
PASSWORD=""
TOKEN=""

say() { printf '[custody-migration-smoke] %s\n' "$*"; }
fail() {
    printf '[custody-migration-smoke] FAIL: %s\n' "$*" >&2
    [ ! -f "$LOG" ] || tail -60 "$LOG" >&2
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

# Convergence is eventual by design: an unseal reaches the worker that served
# it and the others follow on their own tick, so a request can legitimately hit
# one that is not open yet. Retry the operation rather than sampling /status,
# which cannot tell which worker answered.
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
    fail "$label never succeeded before the deadline"
}

start_stack() {
    mode=$1     # embedded | separated
    backend=$2  # python   | rust
    say "starting the stack: custody_mode=$mode backend=$backend"
    (
        cd "$ROOT/api"
        PATH="$(dirname "$PY"):$PATH" \
        RH_DATABASE_URL="postgresql+asyncpg://postgres:migr@127.0.0.1:$PG_PORT/rhorizon" \
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
        RH_RUST_CUSTODIAN_SLOTS="${RH_SMOKE_RUST_SLOTS:-3}" \
        RH_RUST_CUSTODIAN_THRESHOLD=0 \
        RH_RUST_CUSTODIAN_BINARY="$CUSTODIAN_BIN" \
        RH_RUST_CUSTODIAN_KEY_DIR="$WORK/custody" \
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
        kill -0 "$LAUNCHER_PID" 2>/dev/null || fail "launcher exited during start ($mode/$backend)"
        sleep 0.5
    done
    fail "API did not start ($mode/$backend)"
}

unseal_once() {
    curl -fsS -m 180 -H 'Content-Type: application/json' \
        --data "{\"password\":\"$PASSWORD\"}" \
        "http://127.0.0.1:$API_PORT/api/v1/vault/unseal"
}

read_secret_once() { api GET "/secrets/$1?namespace=$2"; }

# Every phase asserts the SAME facts, so a regression names itself.
assert_everything_readable() {
    stage=$1
    retry_ok "read prod/db-password at $stage" read_secret_once prod-db-password prod \
        | grep -q 'p0stgres-secret' || fail "prod-db-password wrong at $stage"
    retry_ok "read prod/api-key at $stage" read_secret_once prod-api-key prod \
        | grep -q 'sk-live-4242' || fail "prod-api-key wrong at $stage"
    retry_ok "read staging/db-password at $stage" read_secret_once stg-db-password staging \
        | grep -q 'staging-only' || fail "stg-db-password wrong at $stage"
    # The rotated secret must serve its CURRENT value, not the first one.
    retry_ok "read rotated at $stage" read_secret_once rotated prod \
        | grep -q 'version-three' || fail "rotated secret wrong at $stage"
    # The CA private key is wrapped under pki_wrap_key, a different HKDF
    # sub-key: it catches a master-key transition that the DEK path survives.
    retry_ok "read PKI CA at $stage" api GET "/pki/ca" \
        | grep -q 'BEGIN CERTIFICATE' || fail "PKI CA unreadable at $stage"
    say "  all secrets, the version history and the PKI CA read back at $stage"
}

say "starting temporary PostgreSQL on 127.0.0.1:$PG_PORT"
docker run -d --rm --name "$PG_NAME" \
    -e POSTGRES_PASSWORD=migr -e POSTGRES_DB=rhorizon \
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
                f"postgresql://postgres:migr@127.0.0.1:{port}/rhorizon", timeout=5
            )
            await conn.execute(schema)
            await conn.close()
            return
        except Exception:
            await asyncio.sleep(1)
    raise RuntimeError("PostgreSQL never became ready")


asyncio.run(main())
PYEOF

mkdir -p "$WORK/audit" "$WORK/run" "$WORK/data" "$WORK/custody" "$WORK/prom"
chmod 700 "$WORK/run" "$WORK/data" "$WORK/custody"

# --- 0. a populated vault, on the compatibility path --------------------------
say "=== 0. populate an EMBEDDED vault ==="
start_stack embedded python
PASSWORD="migration-smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
UNSEAL="$(retry_ok "bootstrap unseal" unseal_once)"
printf '%s' "$UNSEAL" | grep -q '"status":"unsealed"' || fail "bootstrap unseal failed"
TOKEN="$(printf '%s' "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "no root token"

retry_ok "create prod-db-password" api POST "/secrets/" \
    --data '{"name":"prod-db-password","value":"p0stgres-secret","namespace":"prod"}' >/dev/null
# Every one of these has to retry, not just the first. Convergence is
# eventual by design: an unseal reaches the worker that served it and the
# others follow on their own tick, so ANY of these can legitimately land on a
# worker that is still sealed and answer 503. Guarding only the first call
# made the whole harness a coin toss on a busy machine.
retry_ok "create prod-api-key" api POST "/secrets/" \
    --data '{"name":"prod-api-key","value":"sk-live-4242","namespace":"prod"}' >/dev/null
retry_ok "create stg-db-password" api POST "/secrets/" \
    --data '{"name":"stg-db-password","value":"staging-only","namespace":"staging"}' >/dev/null
retry_ok "create rotated" api POST "/secrets/" \
    --data '{"name":"rotated","value":"version-one","namespace":"prod"}' >/dev/null
retry_ok "rotate to v2" api PUT "/secrets/rotated?namespace=prod" \
    --data '{"value":"version-two"}' >/dev/null
retry_ok "rotate to v3" api PUT "/secrets/rotated?namespace=prod" \
    --data '{"value":"version-three"}' >/dev/null
retry_ok "create canary token" api POST "/tokens/" \
    --data '{"name":"migration-canary","permissions":{"secrets":"r"}}' >/dev/null
retry_ok "init PKI CA" api POST "/pki/init" \
    --data '{"common_name":"migration-smoke-ca","algorithm":"ed25519"}' >/dev/null
# Bulk fill, to put the O(N) paths -- dek_key rotation, backup, restore --
# under a realistic load. Custody migration itself is O(1) in secrets: it
# splits a 96-byte sub-key bundle, and every secret stays encrypted under its
# own DEK throughout, so the count below does not change phase 1 at all.
BULK="${RH_SMOKE_BULK_SECRETS:-0}"
if [ "$BULK" -gt 0 ]; then
    say "bulk-filling $BULK secrets to load the O(N) paths"
    "$PY" "$ROOT/tools/bulk-fill-secrets.py" "$API_PORT" "$TOKEN" "$BULK" \
        || fail "bulk fill failed"
fi
say "populated: 4 secrets, 2 namespaces, 3 versions on one, a token, a CA (+$BULK bulk)"
assert_everything_readable "embedded"

# --- 1. migrate onto Rust custody --------------------------------------------
say "=== 1. migrate EMBEDDED -> SEPARATED/RUST ==="
stop_pool
start_stack separated rust
MIGRATE="$(retry_ok "unseal onto rust custody" unseal_once)"
printf '%s' "$MIGRATE" | grep -q '"status":"unsealed"' || fail "unseal after migration failed"
STATE="$("$PY" - "$PG_PORT" <<'PYEOF'
import asyncio, sys
import asyncpg
async def main():
    conn = await asyncpg.connect(f"postgresql://postgres:migr@127.0.0.1:{sys.argv[1]}/rhorizon")
    v = await conn.fetchval("SELECT value FROM vault_config WHERE key LIKE 'rust_custody_generation_state%'")
    await conn.close()
    sys.stdout.write(v or "")
asyncio.run(main())
PYEOF
)"
printf '%s' "$STATE" | grep -q '"phase": *"stable"' \
    || fail "no stable Rust custody generation after migration: $STATE"
say "custody state after migration: $STATE"
assert_everything_readable "rust custody"

# --- 2. rotate the master password, then the dek_key -------------------------
say "=== 2. rotate master password and dek_key under Rust custody ==="
NEW_PASSWORD="rotated-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
retry_ok "rotate master password" api POST "/rotate-password" \
    --data "{\"current_password\":\"$PASSWORD\",\"new_password\":\"$NEW_PASSWORD\"}" >/dev/null
PASSWORD="$NEW_PASSWORD"
assert_everything_readable "master password rotated"

retry_ok "rotate dek_key" api POST "/admin/rotate-dek-key" \
    --data "{\"current_password\":\"$PASSWORD\"}" >/dev/null
assert_everything_readable "dek_key rotated"

# --- 3. backup and restore, with the daemons holding the shares --------------
say "=== 3. backup + restore under Rust custody ==="
AGE_PASSPHRASE="migration-smoke-age-passphrase"
# Straight to a file: a backup of a realistically full vault is far past
# ARG_MAX, so it must never travel as a shell argument.
retry_ok "create backup" api POST "/backup/create" \
    --data "{\"passphrase\":\"$AGE_PASSPHRASE\"}" > "$WORK/backup.json"
"$PY" - "$WORK/backup.json" "$WORK/payload.b64" <<'SPLIT_END' || fail "backup returned no payload"
import json
import sys

source, destination = sys.argv[1:]
backup = json.load(open(source, encoding="utf-8"))
payload = backup["payload"]
if not payload:
    raise SystemExit("backup returned no payload")
open(destination, "w", encoding="utf-8").write(payload)
print(f"[custody-migration-smoke] backup created ({backup['size_bytes']} bytes, "
      f"{backup['secrets_count']} secrets, {backup['tokens_count']} tokens)")
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
with urllib.request.urlopen(request, timeout=180) as response:
    sys.stderr.write(response.read().decode()[:200] + "\n")
PYEOF
say "restore accepted"
# A restore replaces every token with a pending-rotation stub, so the operator
# token used to call it is dead by design -- re-authenticate the way an
# operator would, from the password, and take the freshly minted root token.
REOPEN="$(retry_ok "unseal after restore" unseal_once)"
TOKEN="$(printf '%s' "$REOPEN" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "unseal after restore returned no root token: $REOPEN"
say "re-authenticated after the restore (previous token was invalidated)"
assert_everything_readable "restored under rust custody"

# --- 4. back to embedded: the round trip has to close ------------------------
say "=== 4. migrate back SEPARATED/RUST -> EMBEDDED ==="
stop_pool
start_stack embedded python
retry_ok "unseal back on embedded" unseal_once >/dev/null
assert_everything_readable "embedded again"

say "PASS: a populated vault migrated onto Rust custody, survived a master"
say "      password rotation, a dek_key rotation and a restore, and came back"
