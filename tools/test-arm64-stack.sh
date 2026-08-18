#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Full-stack arm64 smoke: build the api + frontend images for aarch64, pull
# postgres:18 arm64, bring the stack up in a pod (shared netns -> no
# podman-compose healthcheck hang), unseal, and round-trip a secret. Proves the
# whole application runs on ARM (not just the crypto unit tests -- see
# tools/test-arm64.sh for those).
#
# Everything runs under QEMU emulation, so it is slow (image builds + the
# Argon2id 256MB unseal are CPU-heavy emulated). On native arm64 it is fast.
#
# Usage:
#   tools/test-arm64-stack.sh            # build images if missing, then smoke
#   RH_ARM_REBUILD=1 tools/test-arm64-stack.sh   # force image rebuild
#
# Prerequisite: aarch64 binfmt registered (F flag), see tools/test-arm64.sh.
# Exit: 0 pass / 1 fail / 2 skip (no arm64 emulation).
set -uo pipefail
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POD=rhorizon-arm-smoke; AP="${RH_ARM_PORT:-18990}"; PGPW=arm
API_IMG=localhost/rhorizon-api:arm64
FRONT_IMG=localhost/rhorizon-frontend:arm64
PG_IMG=docker.io/library/postgres:18-trixie
command -v podman >/dev/null 2>&1 && RT=podman || RT=docker
say(){ printf '\033[1;36m[arm64-stack]\033[0m %s\n' "$*"; }
fail(){ printf '\033[1;31m[arm64-stack]\033[0m FAIL: %s\n' "$*" >&2; "$RT" logs --tail 25 arm-api 2>/dev/null; "$RT" pod rm -f $POD >/dev/null 2>&1; exit 1; }
trap '"$RT" pod rm -f $POD >/dev/null 2>&1' EXIT

"$RT" run --rm --platform linux/arm64 docker.io/library/alpine uname -m 2>/dev/null | grep -q aarch64 || {
    echo "[arm64-stack] SKIP: no aarch64 emulation. Register it:"
    echo "    sudo $RT run --rm --privileged docker.io/tonistiigi/binfmt --install arm64"; exit 2; }

have(){ "$RT" image inspect "$1" >/dev/null 2>&1 && [ "$("$RT" image inspect --format '{{.Architecture}}' "$1")" = arm64 ]; }
say "images (arm64)"
"$RT" pull --platform linux/arm64 "$PG_IMG" >/dev/null 2>&1 || fail "pull pg"
if [ "${RH_ARM_REBUILD:-0}" = 1 ] || ! have "$API_IMG"; then
    say "building api arm64 (emulated; 30-90 min)"; "$RT" build --platform linux/arm64 -t "$API_IMG" -f "$R/api/Dockerfile" "$R" || fail "api build"; fi
if [ "${RH_ARM_REBUILD:-0}" = 1 ] || ! have "$FRONT_IMG"; then
    say "building frontend arm64"; "$RT" build --platform linux/arm64 -t "$FRONT_IMG" -f "$R/frontend/Dockerfile" "$R/frontend" || fail "frontend build"; fi

"$RT" pod rm -f $POD >/dev/null 2>&1
"$RT" pod create --name $POD -p 127.0.0.1:$AP:8200 >/dev/null || fail "pod create"
say "postgres 18 arm64 (+ schema via initdb)"
"$RT" run -d --pod $POD --name arm-pg --platform linux/arm64 \
    -e POSTGRES_PASSWORD=$PGPW -e POSTGRES_DB=rhorizon -e POSTGRES_USER=rhorizon \
    -v "$R/schema.sql":/docker-entrypoint-initdb.d/01_schema.sql:ro "$PG_IMG" >/dev/null || fail "pg run"
for _ in $(seq 1 90); do "$RT" exec arm-pg pg_isready -U rhorizon >/dev/null 2>&1 && break; sleep 2; done
"$RT" exec arm-pg pg_isready -U rhorizon >/dev/null 2>&1 || fail "pg not ready"
say "pg $("$RT" exec arm-pg uname -m) $("$RT" exec arm-pg postgres --version | grep -oE '[0-9]+\.[0-9]+' | head -1)"

say "api arm64 (WORKERS=1)"
"$RT" run -d --pod $POD --name arm-api --platform linux/arm64 \
    -e RHORIZON_DATABASE_URL="postgresql+asyncpg://rhorizon:$PGPW@127.0.0.1:5432/rhorizon" \
    -e RHORIZON_DATABASE_SSL=false -e RHORIZON_WORKERS=1 \
    -e RHORIZON_NODE_UUID_PATH=/tmp/node-uuid -e RHORIZON_AUDIT_DIR=/tmp/audit \
    -e RHORIZON_RUNTIME_DIR=/tmp/run -e RHORIZON_AUTHFAIL_LOG=/tmp/authfail.log \
    -e RHORIZON_CLUSTER_CERT_PATH=/tmp/c.pem -e RHORIZON_CLUSTER_CERT_KEY_PATH=/tmp/c.key \
    "$API_IMG" >/dev/null || fail "api run"
ok=0; for _ in $(seq 1 120); do curl -fsS -m3 http://127.0.0.1:$AP/health >/dev/null 2>&1 && { ok=1; break; }; "$RT" inspect -f '{{.State.Running}}' arm-api 2>/dev/null | grep -q true || fail "api exited"; sleep 2; done
[ $ok = 1 ] || fail "api never healthy"
say "api $("$RT" exec arm-api uname -m) healthy"

say "unseal (Argon2id 256MB, emulated -> slow)"
MP="arm-$(head -c9 /dev/urandom|base64|tr -dc A-Za-z0-9)Aa1"
U=$(curl -s -m300 --data "{\"password\":\"$MP\"}" -H 'Content-Type: application/json' http://127.0.0.1:$AP/api/v1/vault/unseal)
echo "$U" | grep -q '"status":"unsealed"' || fail "unseal: $U"
TOK=$(echo "$U" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)
MP_STATE=$(curl -s -m10 http://127.0.0.1:$AP/api/v1/vault/status | grep -oE '"memory_protection":"[a-z-]+"' | cut -d'"' -f4)
case "$MP_STATE" in
    mlock|zeroize-only) ;;
    *) fail "unknown memory_protection=$MP_STATE" ;;
esac
say "unsealed; memory_protection=$MP_STATE"

curl -s -m20 -X POST http://127.0.0.1:$AP/api/v1/vault/secrets/ -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d '{"name":"arm-canary","value":"arm64-works"}' >/dev/null
[ "$(curl -s -m10 -H "Authorization: Bearer $TOK" http://127.0.0.1:$AP/api/v1/vault/secrets/arm-canary | grep -oE arm64-works)" = arm64-works ] || fail "secret round-trip"
say "PASS -- pg18 + api + rust crypto on aarch64: unseal + secret round-trip OK"
