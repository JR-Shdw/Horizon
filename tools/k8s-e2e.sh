#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# k8s IMAGE-LOADED end-to-end: build the api + frontend images, load them into
# an ephemeral k3d cluster, helm-install the chart, wait for Ready, unseal, and
# assert the stack serves + the multi-worker cluster forms. This is the deploy
# the chart actually ships -- it catches the class of k8s-only regressions
# (env ordering, readonly-fs paths, NetworkPolicy egress, memory floor, the
# frontend upstream) that the server-side dry-run in k8s-test.sh cannot.
#
# DB modes (RH_E2E_DB):
#   inchart  -- chart's bundled Postgres StatefulSet (fast, default in CI)
#   patroni  -- Zalando postgres-operator + a Patroni cluster, external DB
#               (the real HA target; exercises sslMode + the netpol egress fix).
#               Heavier: pulls the spilo image (~1.5GB).
#
# Prereqs: k3d + kubectl + helm + docker. On a host without a reachable Docker
# API (e.g. node-5 rootless-podman, no user-systemd) k3d can't run -> exit 2
# (skip), same contract as tools/k8s-test.sh. Meant for CI / a Docker host.
#
# Run:  make k8s-e2e             (or  tools/k8s-e2e.sh)
#       RH_E2E_DB=patroni make k8s-e2e

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${RH_E2E_CLUSTER:-rh-e2e}"
DB="${RH_E2E_DB:-inchart}"
TAG="${RH_E2E_TAG:-e2e}"
NS="${RH_E2E_NS:-default}"
OPERATOR_CHART_VERSION="${RH_E2E_OPERATOR_VERSION:-1.14.0}"
WORKERS="${RH_E2E_WORKERS:-5}"
KUBECTL=(kubectl)

say()  { printf '[k8s-e2e] %s\n' "$*"; }
fail() { printf '[k8s-e2e] FAIL: %s\n' "$*" >&2; exit 1; }

for b in k3d kubectl helm docker; do
  command -v "$b" >/dev/null || { echo "[k8s-e2e] $b not installed -- skip (run on a Docker host / CI)"; exit 2; }
done

cleanup() { k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# --- ephemeral k3d cluster --------------------------------------------------
say "creating k3d cluster: $CLUSTER (db=$DB)"
if ! k3d cluster create "$CLUSTER" --wait --timeout 120s; then
  echo "[k8s-e2e] k3d could not create a cluster -- no reachable Docker API." >&2
  echo "          Run on a Docker-capable host / CI (node-5 can't run k3s)." >&2
  exit 2
fi

# --- build + load images ----------------------------------------------------
# api Dockerfile COPYs api/... so its context is the repo root; the frontend
# Dockerfile COPYs js/icons/... so its context is frontend/.
say "building images (tag=$TAG)"
docker build -f "$ROOT/api/Dockerfile"      -t "rhorizon-api:$TAG"      "$ROOT"          >/dev/null
docker build -f "$ROOT/frontend/Dockerfile" -t "rhorizon-frontend:$TAG" "$ROOT/frontend" >/dev/null
say "importing images into k3d"
k3d image import "rhorizon-api:$TAG" "rhorizon-frontend:$TAG" -c "$CLUSTER" >/dev/null

HELM_DB_ARGS=()
if [ "$DB" = patroni ]; then
  # --- Zalando postgres-operator + a Patroni cluster ------------------------
  say "installing postgres-operator $OPERATOR_CHART_VERSION"
  helm repo add postgres-operator-charts \
    https://opensource.zalando.com/postgres-operator/charts/postgres-operator >/dev/null 2>&1 || true
  helm repo update >/dev/null
  helm install postgres-operator postgres-operator-charts/postgres-operator \
    --version "$OPERATOR_CHART_VERSION" -n "$NS" --wait --timeout 4m >/dev/null
  say "creating Patroni cluster rhorizon-pg (2 instances) -- pulls spilo, be patient"
  "${KUBECTL[@]}" apply -n "$NS" -f - <<YAML
apiVersion: acid.zalan.do/v1
kind: postgresql
metadata: { name: rhorizon-pg }
spec:
  teamId: rhorizon
  volume: { size: 1Gi }
  numberOfInstances: 2
  users: { rhorizon: [superuser, createdb] }
  databases: { rhorizon: rhorizon }
  postgresql: { version: "17" }
YAML
  say "waiting for Patroni master + replica"
  for _ in $(seq 1 60); do
    n="$("${KUBECTL[@]}" -n "$NS" get pods -l cluster-name=rhorizon-pg --no-headers 2>/dev/null | grep -c Running || true)"
    [ "${n:-0}" -ge 2 ] && break
    sleep 5
  done
  [ "$("${KUBECTL[@]}" -n "$NS" get pods -l cluster-name=rhorizon-pg --no-headers 2>/dev/null | grep -c Running || true)" -ge 2 ] \
    || fail "Patroni cluster did not reach 2 running pods"
  # bridge the operator-managed password into the chart's existingSecret shape
  PW="$("${KUBECTL[@]}" -n "$NS" get secret \
    rhorizon.rhorizon-pg.credentials.postgresql.acid.zalan.do \
    -o jsonpath='{.data.password}' | base64 -d)"
  [ -n "$PW" ] || fail "could not read Patroni rhorizon password"
  "${KUBECTL[@]}" -n "$NS" create secret generic rhorizon-db \
    --from-literal=postgres-password="$PW" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
  HELM_DB_ARGS=(
    --set postgres.external.enabled=true
    --set postgres.external.host=rhorizon-pg
    --set postgres.external.port=5432
    --set postgres.external.database=rhorizon
    --set postgres.external.username=rhorizon
    --set postgres.external.sslMode=require
    --set postgres.external.existingSecret=rhorizon-db
  )
fi

# --- helm install rhorizon --------------------------------------------------
say "helm install rhorizon"
helm install rhorizon "$ROOT/helm/rhorizon" -n "$NS" \
  --set image.api.repository=rhorizon-api,image.api.tag="$TAG",image.api.pullPolicy=Never \
  --set image.frontend.repository=rhorizon-frontend,image.frontend.tag="$TAG",image.frontend.pullPolicy=Never \
  --set api.replicas=1 --set api.workers="$WORKERS" \
  "${HELM_DB_ARGS[@]}" >/dev/null

say "waiting for api + frontend Ready"
"${KUBECTL[@]}" -n "$NS" rollout status deploy/rhorizon-api --timeout=4m \
  || fail "api never became Ready$(printf '\n'; "${KUBECTL[@]}" -n "$NS" logs -l app.kubernetes.io/component=api --tail=25 2>/dev/null)"
"${KUBECTL[@]}" -n "$NS" rollout status deploy/rhorizon-frontend --timeout=2m \
  || fail "frontend never became Ready"

# --- smoke + unseal + assert cluster ---------------------------------------
api_svc="$("${KUBECTL[@]}" -n "$NS" get svc -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')"
[ -n "$api_svc" ] || fail "no api service found"
base="http://$api_svc:8200"
MP="e2e-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"

kexec() { # run a one-shot busybox wget inside the cluster
  "${KUBECTL[@]}" -n "$NS" run "e2e-curl-$RANDOM" --rm -i --restart=Never --image=busybox:1.36 \
    --timeout=40s -- sh -c "$1" 2>/dev/null | grep -v 'pod .* deleted' || true
}

say "GET /health"
kexec "wget -qO- -T5 $base/health" | grep -q '"status":"ok"' || fail "/health not ok"

say "POST /unseal (bootstrap)"
unseal="$(kexec "wget -qO- -T15 --post-data='{\"password\":\"$MP\"}' --header='Content-Type: application/json' $base/api/v1/vault/unseal")"
echo "$unseal" | grep -q '"status":"unsealed"' || fail "unseal failed: $unseal"
tok="$(echo "$unseal" | grep -oE '"root_token":"[^"]+"' | cut -d'"' -f4)"
[ -n "$tok" ] || fail "no root token"

say "assert multi-worker cluster formed"
ok=""
for _ in $(seq 1 10); do
  cl="$(kexec "wget -qO- -T8 --header='Authorization: Bearer $tok' $base/api/v1/vault/cluster")"
  m="$(echo "$cl" | grep -oE '"master"' | wc -l | tr -d ' ' || true)"
  f="$(echo "$cl" | grep -oE '"worker_state":"follower"' | wc -l | tr -d ' ' || true)"
  [ "${m:-0}" -ge 1 ] && [ "${f:-0}" -ge "$((WORKERS - 1))" ] && { ok=1; break; }
  sleep 3
done
[ -n "$ok" ] || fail "cluster did not form (masters=${m:-0} followers=${f:-0}, want 1 + $((WORKERS-1)))"

say "PASS -- rhorizon up on k3d (db=$DB): api+frontend Ready, unsealed, 1 master + $f followers"
