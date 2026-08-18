#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Native cluster smoke: run rhorizon NATIVELY (bare `uvicorn --workers N`, no
# container) against an ephemeral PG, unseal it, and assert the multi-worker
# cluster forms -- 1 master + N-1 followers with the crypto-ops / keys / share
# RPC sockets under the runtime dir. Catches regressions in the native deploy
# path (the one quickstart-laptop-native.sh drives) that the container e2e and
# the unit tests don't exercise.
#
# Fast (~30s), no k8s, no Docker daemon for the app itself (only the throwaway
# PG container). Exits 0 PASS / 1 FAIL / 2 SKIP (no container runtime / venv).
#
# Run:  make native-smoke   (or  tools/native-cluster-smoke.sh)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKERS="${RH_SMOKE_WORKERS:-5}"
PG_PORT="${RH_SMOKE_PG_PORT:-55437}"
API_PORT="${RH_SMOKE_API_PORT:-18200}"
PG_IMAGE="${RH_SMOKE_PG_IMAGE:-docker.io/library/postgres:17-bookworm}"
PG_NAME="rhorizon-smoke-pg"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rh-native-smoke.XXXXXX")"
PY="${RH_SMOKE_PY:-$ROOT/.venv/bin/python}"
LOG="$WORK/uvicorn.log"
UVPID=""

say()  { printf '[native-smoke] %s\n' "$*"; }
fail() { printf '[native-smoke] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  [ -n "$UVPID" ] && kill "$UVPID" 2>/dev/null || true
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "[native-smoke] no container runtime -- skip"; exit 2; }
[ -x "$PY" ] || { echo "[native-smoke] no venv at $PY -- skip"; exit 2; }

# --- ephemeral PG -----------------------------------------------------------
say "starting ephemeral PG ($PG_IMAGE) on 127.0.0.1:$PG_PORT"
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$PG_NAME" \
  -e POSTGRES_PASSWORD=smoke -e POSTGRES_DB=rhorizon \
  -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" >/dev/null
# A bare native run can't reach the image path /app/schema.sql, so pre-apply it
# here over the mapped port (idempotent). asyncpg (a project dep) doubles as the
# readiness wait and avoids `docker exec`, so this also works under a filtered
# docker-socket-proxy (CI) where exec is disabled. The retry covers the
# postgres image's temp-init-then-restart race.
"$PY" - "$PG_PORT" "$ROOT/schema.sql" <<'PYEOF' || fail "schema apply failed"
import asyncio, sys, asyncpg
port, schema = sys.argv[1], sys.argv[2]
async def main():
    sql = open(schema).read(); last = None
    for _ in range(20):
        try:
            c = await asyncpg.connect(f"postgresql://postgres:smoke@127.0.0.1:{port}/rhorizon", timeout=5)
            await c.execute(sql); await c.close(); return
        except Exception as e:
            last = e; await asyncio.sleep(1)
    print(f"schema apply failed: {last}", file=sys.stderr); sys.exit(1)
asyncio.run(main())
PYEOF

# --- native uvicorn (N workers) ---------------------------------------------
# Native, non-root: node-uuid + cluster-cert + audit default to /var/lib and
# /var/log (unwritable) -- point them at the work dir (same fix the native
# installer ships).
mkdir -p "$WORK/audit" "$WORK/run" "$WORK/data" "$WORK/prom"
chmod 700 "$WORK/run" "$WORK/data"
say "starting uvicorn --workers $WORKERS on 127.0.0.1:$API_PORT"
RHORIZON_DATABASE_URL="postgresql+asyncpg://postgres:smoke@127.0.0.1:$PG_PORT/rhorizon" \
RHORIZON_DATABASE_SSL=disable \
RHORIZON_AUDIT_DIR="$WORK/audit" \
RHORIZON_AUTHFAIL_LOG="$WORK/audit/authfail.log" \
RHORIZON_RUNTIME_DIR="$WORK/run" \
RHORIZON_NODE_UUID_PATH="$WORK/data/node-uuid" \
RHORIZON_CLUSTER_CERT_PATH="$WORK/data/cluster-cert.pem" \
RHORIZON_CLUSTER_CERT_KEY_PATH="$WORK/data/cluster-cert.key" \
RHORIZON_WORKERS="$WORKERS" \
PROMETHEUS_MULTIPROC_DIR="$WORK/prom" \
  "$PY" -m uvicorn app.main:app --app-dir "$ROOT/api" \
    --host 127.0.0.1 --port "$API_PORT" --workers "$WORKERS" >"$LOG" 2>&1 &
UVPID=$!

for _ in $(seq 1 40); do
  curl -s -m3 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
  kill -0 "$UVPID" 2>/dev/null || fail "uvicorn died at boot (see below)$(printf '\n'; tail -15 "$LOG")"
  sleep 1
done
curl -s -m3 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 || fail "API never came up"

# --- unseal -----------------------------------------------------------------
MP="smoke-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"
say "unsealing (bootstrap)"
UNSEAL="$(curl -s -m30 --data "{\"password\":\"$MP\"}" -H 'Content-Type: application/json' \
  "http://127.0.0.1:$API_PORT/api/v1/vault/unseal")"
echo "$UNSEAL" | grep -q '"status":"unsealed"' || fail "unseal failed: $UNSEAL"
TOKEN="$(echo "$UNSEAL" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$TOKEN" ] || fail "no root token from unseal"

# --- assert the cluster formed ----------------------------------------------
# followers attach within a couple of 1s poll cycles after unseal.
masters=0; followers=0
for _ in $(seq 1 10); do
  CL="$(curl -s -m5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$API_PORT/api/v1/vault/cluster")"
  # grep exits 1 on no-match; tolerate it (pipefail would kill the poll loop)
  masters="$(echo "$CL" | grep -oE '"master"' | wc -l | tr -d ' ' || true)"
  followers="$(echo "$CL" | grep -oE '"worker_state":"follower"' | wc -l | tr -d ' ' || true)"
  [ "$masters" -ge 1 ] && [ "$followers" -ge "$((WORKERS - 1))" ] && break
  sleep 2
done
socks="$(ls "$WORK/run" 2>/dev/null | grep -c '\.sock$' || true)"

say "result: masters=$masters followers=$followers sockets=$socks (want 1 master, $((WORKERS-1)) followers)"
[ "$masters" -ge 1 ] || fail "no master worker after unseal"
[ "$followers" -ge "$((WORKERS - 1))" ] || fail "expected $((WORKERS-1)) followers, got $followers"
if [ "$WORKERS" -eq 1 ]; then
  # Home preset: single-worker fast-path holds keys in-process, binds no RPC
  # socket and skips the Shamir split, so zero sockets is the correct outcome.
  [ "$socks" -eq 0 ] || fail "single-worker expected 0 rpc sockets, got $socks"
  say "PASS -- native single-worker home mode (1 master, 0 sockets, keys held locally)"
else
  # crypto-ops + keys + N-1 follower share-backs (master keeps share #0 in-proc)
  [ "$socks" -ge "$WORKERS" ] || fail "expected >= $WORKERS rpc sockets, got $socks"
  say "PASS -- native $WORKERS-worker cluster formed (1 master + $followers followers, $socks sockets)"
fi
