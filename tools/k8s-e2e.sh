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
# Run:  make k8s-e2e             (single-node deployment smoke)
#       make k8s-ha-e2e          (three-node application HA + failover)
#       RH_E2E_DB=patroni make k8s-e2e

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${RH_E2E_CLUSTER:-rh-e2e}"
DB="${RH_E2E_DB:-inchart}"
TAG="${RH_E2E_TAG:-e2e}"
NS="${RH_E2E_NS:-default}"
OPERATOR_CHART_VERSION="${RH_E2E_OPERATOR_VERSION:-1.14.0}"
WORKERS="${RH_E2E_WORKERS:-5}"
# RH_E2E_HA=1 exercises the real application-HA bootstrap and failover path.
# It starts with one Pod, initialises the cluster, provisions the short-lived
# JOIN Secret, scales to three Pods, then removes the Secret before disruption.
HA="${RH_E2E_HA:-0}"
REPLICAS=1
HA_REPLICAS="${RH_E2E_REPLICAS:-3}"
if [ "$HA" = "1" ]; then
  API_PORT="${RH_E2E_API_PORT:-6552}"
else
  API_PORT="${RH_E2E_API_PORT:-6551}"
fi
API_HOST="${RH_E2E_API_HOST:-127.0.0.1}"
KUBECTL=(kubectl)

say()  { printf '[k8s-e2e] %s\n' "$*"; }
fail() { printf '[k8s-e2e] FAIL: %s\n' "$*" >&2; exit 1; }

case "$API_HOST" in
  0.0.0.0 | :: | "[::]") fail "RH_E2E_API_HOST must not expose the Kubernetes API on every interface" ;;
esac

diagnose_k3d() {
  local node
  echo "[k8s-e2e] k3d container state:" >&2
  docker ps -a --filter "name=k3d-${CLUSTER}-" \
    --format 'table {{.Names}}\t{{.Status}}' >&2 || true
  for node in "k3d-${CLUSTER}-server-0" "k3d-${CLUSTER}-serverlb"; do
    docker inspect --format \
      '{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' \
      "$node" >&2 2>/dev/null || continue
    echo "[k8s-e2e] tail $node:" >&2
    docker logs --tail 40 "$node" >&2 2>/dev/null || true
  done
  awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print}' /proc/meminfo >&2 || true
  if [ -r /sys/fs/cgroup/memory.current ] && [ -r /sys/fs/cgroup/memory.max ]; then
    printf '[k8s-e2e] step cgroup memory: current=%s max=%s\n' \
      "$(< /sys/fs/cgroup/memory.current)" "$(< /sys/fs/cgroup/memory.max)" >&2
  fi
}

wait_for_k8s_api() {
  local attempt
  for attempt in $(seq 1 60); do
    if "${KUBECTL[@]}" --request-timeout=5s get --raw=/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  diagnose_k3d
  return 1
}

diagnose_api_pod() {
  local pod="${1:-rhorizon-api-0}" restart_count
  echo "[k8s-e2e] describe $pod:" >&2
  "${KUBECTL[@]}" -n "$NS" describe pod "$pod" >&2 2>/dev/null || true
  echo "[k8s-e2e] current logs $pod:" >&2
  "${KUBECTL[@]}" -n "$NS" logs "$pod" --tail=120 >&2 2>/dev/null || true
  restart_count="$("${KUBECTL[@]}" -n "$NS" get pod "$pod" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || true)"
  if [ "${restart_count:-0}" -gt 0 ]; then
    echo "[k8s-e2e] previous logs $pod:" >&2
    "${KUBECTL[@]}" -n "$NS" logs "$pod" --previous --tail=120 >&2 2>/dev/null || true
  fi
}

for b in k3d kubectl helm docker jq; do
  command -v "$b" >/dev/null || { echo "[k8s-e2e] $b not installed -- skip (run on a Docker host / CI)"; exit 2; }
done

cleanup() { k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true; }

# Build before starting k3s. The API image includes the Rust extension and can
# briefly consume enough RAM to evict k3s on a small CI runner. Keeping the
# cluster out of that peak also makes an API-server loss a Horizon/Kubernetes
# failure rather than a side effect of the image build.
say "building images (tag=$TAG)"
docker build -f "$ROOT/api/Dockerfile"       -t "rhorizon-api:$TAG"       "$ROOT"          >/dev/null
docker build -f "$ROOT/frontend/Dockerfile" -t "rhorizon-frontend:$TAG" "$ROOT/frontend" >/dev/null

# --- ephemeral k3d cluster --------------------------------------------------
# A CI cancellation sends SIGKILL to the step container, so its EXIT trap
# cannot remove the cluster it created through the host Docker socket. Delete
# only this explicitly named disposable cluster before recreating it.
if k3d cluster list --no-headers 2>/dev/null | awk '{print $1}' | grep -Fxq "$CLUSTER"; then
  say "removing stale k3d cluster: $CLUSTER"
  cleanup
fi
say "creating k3d cluster: $CLUSTER (db=$DB)"
# A workstation binds the API to loopback. A CI step using the host Docker
# socket is a separate network namespace, so its own 127.0.0.1 cannot reach a
# port published on the Docker host. The CI workflow therefore supplies only
# its private bridge gateway as RH_E2E_API_HOST. Never use 0.0.0.0 here: the
# generated kubeconfig is an admin credential and the API needs no LAN access.
# Separate loopback defaults (6551 smoke, 6552 HA) let the two named test
# clusters coexist safely even when a CI scheduler overlaps their cleanup.
if ! k3d cluster create "$CLUSTER" --api-port "$API_HOST:$API_PORT" \
        --wait --timeout 120s; then
  cleanup
  echo "[k8s-e2e] k3d could not create a cluster -- no reachable Docker API." >&2
  echo "          Run on a Docker-capable host / CI (node-5 can't run k3s)." >&2
  exit 2
fi
trap cleanup EXIT

# --- load images ------------------------------------------------------------
say "importing images into k3d"
k3d image import "rhorizon-api:$TAG" "rhorizon-frontend:$TAG" -c "$CLUSTER" >/dev/null
say "waiting for the Kubernetes API after image import"
wait_for_k8s_api || fail "Kubernetes API did not recover after image import"

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

# --- HA extras --------------------------------------------------------------
HELM_HA_ARGS=()
if [ "$HA" = "1" ]; then
  [ "$HA_REPLICAS" -ge 3 ] || fail "RH_E2E_REPLICAS must be at least 3"
  say "HA mode: bootstrap one Pod, then scale to $HA_REPLICAS"
  pod_cidr="$("${KUBECTL[@]}" get nodes -o jsonpath='{.items[0].spec.podCIDR}')"
  [ -n "$pod_cidr" ] || fail "could not read the Pod CIDR for proxyTrustedIps"
  HELM_HA_ARGS=(
    --set api.clusterEnabled=true
    --set api.maxConcurrentRequests=64
    --set api.persistence.enabled=true
    --set api.proxyTrustedIps="$pod_cidr"
    --set api.haPrimaryUrl=https://rhorizon-frontend:8443
    --set api.haServerCaSecretName=rhorizon-frontend-tls
    --set api.haServerCaSecretKey=tls.crt
  )
fi

# --- helm install rhorizon --------------------------------------------------
say "helm install rhorizon"
helm install rhorizon "$ROOT/helm/rhorizon" -n "$NS" \
  --set image.api.repository=rhorizon-api,image.api.tag="$TAG",image.api.pullPolicy=Never \
  --set image.frontend.repository=rhorizon-frontend,image.frontend.tag="$TAG",image.frontend.pullPolicy=Never \
  --set api.replicas="$REPLICAS" --set api.workers="$WORKERS" \
  "${HELM_HA_ARGS[@]}" "${HELM_DB_ARGS[@]}" >/dev/null

say "waiting for the bootstrap API Pod to run"
# Readiness deliberately stays false while sealed, so waiting for a StatefulSet
# rollout before POST /unseal deadlocks. The headless Service publishes sealed
# Pods and is the only bootstrap path used below.
for _ in $(seq 1 60); do
  phase="$("${KUBECTL[@]}" -n "$NS" get pod rhorizon-api-0 -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = Running ] && break
  sleep 2
done
[ "${phase:-}" = Running ] \
  || fail "bootstrap API Pod did not reach Running$(printf '\n'; "${KUBECTL[@]}" -n "$NS" logs rhorizon-api-0 --tail=25 2>/dev/null)"

# --- smoke + unseal + assert cluster ---------------------------------------
api_svc="$("${KUBECTL[@]}" -n "$NS" get svc -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')"
[ -n "$api_svc" ] || fail "no api service found"
base="http://$api_svc:8200"
bootstrap_base="http://rhorizon-api-0.rhorizon-api-headless:8200"
MP="e2e-$(head -c12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')Aa1"

kexec() { # run a one-shot busybox wget inside the cluster, preserving failures
  local out rc
  set +e
  out="$("${KUBECTL[@]}" -n "$NS" run "e2e-curl-$RANDOM" --rm -i --restart=Never --image=busybox:1.36 \
    --quiet --timeout=40s -- sh -c "$1; rc=\$?; printf '\\n'; exit \$rc" 2>/dev/null)"
  rc=$?
  set -e
  printf '%s\n' "$out" | grep -v '^pod .* deleted$' || true
  return "$rc"
}

api_exec_request() { # method path JSON-payload [bearer]
  local method="$1" path="$2" payload="$3" bearer="${4:-}" request
  request="$(jq -cn --arg method "$method" --arg path "$path" \
    --arg payload "$payload" --arg bearer "$bearer" \
    '{method:$method,path:$path,payload:$payload,bearer:$bearer}')"
  # One-shot responses (unseal root token, HA bootstrap password) must not
  # depend on kubectl-run attachment to a disposable Pod. Send credentials on
  # stdin and return an explicit transport/status/body envelope from localhost.
  printf '%s' "$request" | "${KUBECTL[@]}" -n "$NS" exec -i rhorizon-api-0 -- \
    python -c 'import httpx,json,sys
q=json.load(sys.stdin)
h={"Content-Type":"application/json"}
if q["bearer"]: h["Authorization"]="Bearer "+q["bearer"]
try:
 r=httpx.request(q["method"],"http://127.0.0.1:8200"+q["path"],content=q["payload"].encode(),headers=h,timeout=35)
 print(json.dumps({"transport":"ok","status":r.status_code,"body":r.text}))
except Exception as exc:
 print(json.dumps({"transport":"error","error_type":type(exc).__name__,"error":str(exc)}))
 raise SystemExit(2)'
}

unseal_pod() {
  local pod="$1" result
  result="$(kexec "wget -qO- -T30 --post-data='{\"password\":\"$MP\"}' --header='Content-Type: application/json' http://$pod.rhorizon-api-headless:8200/api/v1/vault/unseal" || true)"
  printf '%s' "$result" | jq -e \
    '.status == "unsealed" or .status == "already_unsealed"' >/dev/null
}

wait_for_ha_rollout() {
  local deadline pod phase ready current update
  deadline=$(( $(date +%s) + 360 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for pod in $("${KUBECTL[@]}" -n "$NS" get pod -l app.kubernetes.io/component=api \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null); do
      phase="$("${KUBECTL[@]}" -n "$NS" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      [ "$phase" = Running ] && unseal_pod "$pod" || true
    done
    ready="$("${KUBECTL[@]}" -n "$NS" get statefulset rhorizon-api -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
    current="$("${KUBECTL[@]}" -n "$NS" get statefulset rhorizon-api -o jsonpath='{.status.currentRevision}' 2>/dev/null || true)"
    update="$("${KUBECTL[@]}" -n "$NS" get statefulset rhorizon-api -o jsonpath='{.status.updateRevision}' 2>/dev/null || true)"
    [ "${ready:-0}" -eq "$HA_REPLICAS" ] && [ -n "$current" ] && [ "$current" = "$update" ] && return 0
    sleep 2
  done
  return 1
}

say "waiting for GET /health"
health=""
health_envelope=""
health_status=0
health_stable=0
health_deadline=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$health_deadline" ]; do
  # Probe localhost in the long-lived API Pod. Creating a disposable Pod for
  # every attempt made scheduler and attach latency look like an API failure.
  # Three successful responses still guard the one-shot unseal response from
  # a worker pool that is in the middle of restarting siblings.
  health_envelope="$(api_exec_request GET /health '' || true)"
  health_status="$(printf '%s' "$health_envelope" | jq -r '.status // 0' 2>/dev/null || true)"
  health="$(printf '%s' "$health_envelope" | jq -r '.body // empty' 2>/dev/null || true)"
  if [ "${health_status:-0}" -eq 200 ] \
      && printf '%s' "$health" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    health_stable=$((health_stable + 1))
  else
    health_stable=0
  fi
  if [ "$health_stable" -ge 3 ]; then
    break
  fi
  sleep 2
done
if [ "$health_stable" -lt 3 ]; then
  "${KUBECTL[@]}" -n "$NS" get pod rhorizon-api-0 -o wide >&2 || true
  diagnose_api_pod rhorizon-api-0
  fail "/health did not become stable within 300 seconds: $health_envelope"
fi

say "POST /unseal (bootstrap)"
unseal=""
unseal_envelope=""
for _ in $(seq 1 15); do
  unseal_envelope="$(api_exec_request POST /api/v1/vault/unseal \
    "{\"password\":\"$MP\"}" || true)"
  unseal="$(printf '%s' "$unseal_envelope" | jq -r '.body // empty' 2>/dev/null || true)"
  if printf '%s' "$unseal" | jq -e \
    '.status == "unsealed" and (.root_token | length > 0)' >/dev/null 2>&1; then
    break
  fi
  # Safe retry boundary: TCP refused means the server accepted no bytes. Do
  # not retry a timeout/reset, where the vault may have unsealed and returned
  # the root token on a response the client lost.
  printf '%s' "$unseal_envelope" | jq -e \
    '.transport == "error" and .error_type == "ConnectError" and (.error | contains("Connection refused"))' \
    >/dev/null 2>&1 \
    || fail "unseal failed without a safe retry condition: $unseal_envelope"
  sleep 2
done
printf '%s' "$unseal" | jq -e \
  '.status == "unsealed" and (.root_token | length > 0)' >/dev/null 2>&1 \
  || fail "unseal remained unavailable after safe retries: $unseal"
tok="$(printf '%s' "$unseal" | jq -r '.root_token // empty')"
[ -n "$tok" ] || fail "no root token"

say "waiting for api + frontend Ready"
"${KUBECTL[@]}" -n "$NS" rollout status statefulset/rhorizon-api --timeout=4m \
  || fail "api never became Ready$(printf '\n'; "${KUBECTL[@]}" -n "$NS" logs -l app.kubernetes.io/component=api --tail=25 2>/dev/null)"
"${KUBECTL[@]}" -n "$NS" rollout status deploy/rhorizon-frontend --timeout=2m \
  || fail "frontend never became Ready"

say "assert multi-worker cluster formed"
ok=""
for _ in $(seq 1 10); do
  cl="$(kexec "wget -qO- -T8 --header='Authorization: Bearer $tok' $base/api/v1/vault/cluster" || true)"
  m="$(echo "$cl" | grep -oE '"master"' | wc -l | tr -d ' ' || true)"
  f="$(echo "$cl" | grep -oE '"worker_state":"follower"' | wc -l | tr -d ' ' || true)"
  [ "${m:-0}" -ge 1 ] && [ "${f:-0}" -ge "$((WORKERS - 1))" ] && { ok=1; break; }
  sleep 3
done
[ -n "$ok" ] || fail "cluster did not form (masters=${m:-0} followers=${f:-0}, want 1 + $((WORKERS-1)))"

# --- per-Pod identity (HA mode) ---------------------------------------------
if [ "$HA" = "1" ]; then
  say "initialise application HA and capture the one-time JOIN password"
  init=""
  init_envelope=""
  init_rc=1
  for _ in $(seq 1 15); do
    init_envelope="$(api_exec_request POST /api/v1/vault/cluster/init \
      '{"cluster_name":"k8s-e2e"}' "$tok" || true)"
    init_status="$(printf '%s' "$init_envelope" | jq -r '.status // 0' 2>/dev/null || echo 0)"
    init="$(printf '%s' "$init_envelope" | jq -r '.body // empty' 2>/dev/null || true)"
    if [ "$init_status" -eq 200 ]; then
      init_rc=0
      break
    fi
    if [ "$init_status" -eq 429 ] || [ "$init_status" -eq 503 ]; then
      sleep 1
      continue
    fi
    fail "cluster init failed: $init_envelope"
  done
  [ "$init_rc" -eq 0 ] \
    || fail "cluster init remained unavailable after 15 retries: $init_envelope"
  ha_b64="$(printf '%s' "$init" | jq -r '.ha_password // empty')"
  primary_before="$(printf '%s' "$init" | jq -r '.primary_uuid // empty')"
  [ -n "$ha_b64" ] && [ -n "$primary_before" ] \
    || fail "cluster init did not return bootstrap material: $init"

  # Kubernetes Secret.data is already base64. Writing the returned string
  # directly preserves the raw 32 bytes expected by RH_HA_PASSWORD_FILE.
  printf '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"rhorizon-ha-join","namespace":"%s"},"type":"Opaque","data":{"ha-password":"%s"}}\n' \
    "$NS" "$ha_b64" | "${KUBECTL[@]}" apply -f - >/dev/null

  say "scale to $HA_REPLICAS Pods with temporary auto-JOIN enabled"
  helm upgrade rhorizon "$ROOT/helm/rhorizon" -n "$NS" --reuse-values \
    --set api.replicas="$HA_REPLICAS" \
    --set api.haAutoJoin=true \
    --set api.haPasswordSecretName=rhorizon-ha-join >/dev/null
  REPLICAS="$HA_REPLICAS"

  say "unseal Pods as the StatefulSet rolls and wait for JOIN readiness"
  wait_for_ha_rollout || fail "HA rollout did not converge while unsealing Pods"

  say "wait for exactly one primary and $((HA_REPLICAS - 1)) secondaries"
  ha=""
  for _ in $(seq 1 90); do
    ha="$(kexec "wget -qO- -T15 --header='Authorization: Bearer $tok' $base/api/v1/vault/cluster/ha" || true)"
    primaries="$(printf '%s' "$ha" | jq '[.nodes[] | select(.ha_state == "primary")] | length' 2>/dev/null || echo 0)"
    secondaries="$(printf '%s' "$ha" | jq '[.nodes[] | select(.ha_state == "secondary")] | length' 2>/dev/null || echo 0)"
    [ "$primaries" -eq 1 ] && [ "$secondaries" -eq $((HA_REPLICAS - 1)) ] && break
    sleep 2
  done
  [ "${primaries:-0}" -eq 1 ] && [ "${secondaries:-0}" -eq $((HA_REPLICAS - 1)) ] \
    || fail "HA membership did not converge: $ha"

  say "create and verify a signed audit anchor"
  audit_preflight=""
  for _ in $(seq 1 15); do
    audit_preflight="$(kexec "wget -qO- -T30 --post-data='' --header='Authorization: Bearer $tok' $base/api/v1/vault/audit/verify/preflight" || true)"
    printf '%s' "$audit_preflight" | jq -e 'has("preflight_ready")' >/dev/null 2>&1 && break
    sleep 1
  done
  printf '%s' "$audit_preflight" | jq -e 'has("preflight_ready")' >/dev/null 2>&1 \
    || fail "audit preflight did not answer: $audit_preflight"
  audit_job_id="$(printf '%s' "$audit_preflight" | jq -r '.full_verification_job.job_id // empty')"
  if [ -n "$audit_job_id" ]; then
    audit_job=""
    audit_job_status=""
    for _ in $(seq 1 90); do
      audit_job="$(kexec "wget -qO- -T15 --header='Authorization: Bearer $tok' $base/api/v1/vault/audit/verify/jobs/$audit_job_id" || true)"
      audit_job_status="$(printf '%s' "$audit_job" | jq -r '.status // empty' 2>/dev/null || true)"
      [ "$audit_job_status" = succeeded ] && break
      [ "$audit_job_status" = failed ] && fail "audit verification job failed: $audit_job"
      sleep 2
    done
    [ "$audit_job_status" = succeeded ] \
      || fail "audit verification job did not complete: $audit_job"
    audit_preflight="$(kexec "wget -qO- -T30 --post-data='' --header='Authorization: Bearer $tok' $base/api/v1/vault/audit/verify/preflight" || true)"
  fi
  printf '%s' "$audit_preflight" | jq -e '.preflight_ready == true' >/dev/null \
    || fail "signed audit anchor is not ready: $audit_preflight"

  say "run the live HTTPS/mTLS preflight"
  preflight="$(kexec "wget -qO- -T30 --header='Authorization: Bearer $tok' '$base/api/v1/vault/cluster/preflight?live=true'" || true)"
  printf '%s' "$preflight" | jq -e '
    .live_mtls_requested == true and
    ([.checks[] | select(.id == "health_cluster" or .id == "worker_convergence" or .id == "peer_state" or .id == "mtls_live")] | length) == 4 and
    ([.checks[] | select(.id == "health_cluster" or .id == "worker_convergence" or .id == "peer_state" or .id == "mtls_live") | select(.status != "pass")] | length) == 0
  ' >/dev/null || fail "live HA checks failed: $preflight"
  if [ "$DB" = inchart ]; then
    printf '%s' "$preflight" | jq -e \
      '(.failed_checks | sort) == ["health_database_ha"]' >/dev/null \
      || fail "in-chart HA preflight has unexpected failures: $preflight"
  else
    printf '%s' "$preflight" | jq -e '.ready == true and .overall == "pass"' >/dev/null \
      || fail "external-DB HA preflight failed: $preflight"
  fi

  say "remove bootstrap password from the steady-state Pods"
  helm upgrade rhorizon "$ROOT/helm/rhorizon" -n "$NS" --reuse-values \
    --set api.haAutoJoin=false --set-string api.haPasswordSecretName= >/dev/null
  wait_for_ha_rollout \
    || fail "Pods did not become Ready after removing the JOIN mount"
  "${KUBECTL[@]}" -n "$NS" delete secret rhorizon-ha-join >/dev/null

  say "assert one distinct identity and one PVC per Pod"
  pods="$("${KUBECTL[@]}" -n "$NS" get pod -l app.kubernetes.io/component=api \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
  n_pods="$(printf '%s\n' "$pods" | grep -c . || true)"
  [ "$n_pods" -eq "$REPLICAS" ] || fail "want $REPLICAS api Pods, found $n_pods"
  ids=""
  for p in $pods; do
    u="$("${KUBECTL[@]}" -n "$NS" exec "$p" -- cat /var/lib/rhorizon/node-uuid 2>/dev/null || true)"
    [ -n "$u" ] || fail "no node-uuid on $p"
    ids="$ids$u\n"
  done
  distinct="$(printf '%b' "$ids" | grep -c . || true)"
  unique="$(printf '%b' "$ids" | sort -u | grep -c . || true)"
  [ "$unique" -eq "$distinct" ] \
    || fail "Pods share a node identity ($unique unique for $distinct Pods)"
  pvcs="$("${KUBECTL[@]}" -n "$NS" get pvc -o name | grep -c rhorizon-data || true)"
  [ "$pvcs" -ge "$REPLICAS" ] || fail "want >=$REPLICAS identity PVCs, found $pvcs"
  say "$distinct Pods, $unique distinct identities, $pvcs identity PVCs"

  say "replace one secondary and retain its node identity"
  secondary_uuid="$(printf '%s' "$ha" | jq -r '.nodes[] | select(.ha_state == "secondary") | .node_uuid' | head -1)"
  secondary_pod=""
  for p in $pods; do
    u="$("${KUBECTL[@]}" -n "$NS" exec "$p" -- cat /var/lib/rhorizon/node-uuid 2>/dev/null || true)"
    [ "$u" = "$secondary_uuid" ] && { secondary_pod="$p"; break; }
  done
  [ -n "$secondary_pod" ] || fail "could not map a secondary UUID to a Pod"
  "${KUBECTL[@]}" -n "$NS" delete pod "$secondary_pod" --wait=true >/dev/null
  for _ in $(seq 1 90); do
    phase="$("${KUBECTL[@]}" -n "$NS" get pod "$secondary_pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = Running ] && break
    sleep 2
  done
  [ "$phase" = Running ] || fail "$secondary_pod did not restart"
  restarted_unseal=""
  for _ in $(seq 1 60); do
    restarted_unseal="$(kexec "wget -qO- -T15 --post-data='{\"password\":\"$MP\"}' --header='Content-Type: application/json' http://$secondary_pod.rhorizon-api-headless:8200/api/v1/vault/unseal" || true)"
    printf '%s' "$restarted_unseal" | jq -e \
      '.status == "unsealed" or .status == "already_unsealed"' >/dev/null 2>&1 && break
    sleep 2
  done
  printf '%s' "$restarted_unseal" | jq -e \
    '.status == "unsealed" or .status == "already_unsealed"' >/dev/null \
    || fail "$secondary_pod did not unseal after restart: $restarted_unseal"
  "${KUBECTL[@]}" -n "$NS" wait --for=condition=Ready "pod/$secondary_pod" --timeout=4m >/dev/null \
    || fail "$secondary_pod did not become Ready after restart"
  uuid_restarted="$("${KUBECTL[@]}" -n "$NS" exec "$secondary_pod" -- cat /var/lib/rhorizon/node-uuid 2>/dev/null || true)"
  [ "$uuid_restarted" = "$secondary_uuid" ] || fail "secondary identity changed after replacement"

  say "freeze the primary and require bounded automatic failover"
  ha_before_failover=""
  for _ in $(seq 1 15); do
    ha_before_failover="$(kexec "wget -qO- -T15 --header='Authorization: Bearer $tok' $base/api/v1/vault/cluster/ha" || true)"
    printf '%s' "$ha_before_failover" | jq -e '.primary_uuid | length > 0' >/dev/null 2>&1 && break
    sleep 1
  done
  primary_before="$(printf '%s' "$ha_before_failover" | jq -r '.primary_uuid // empty')"
  [ -n "$primary_before" ] || fail "cluster reported no primary before failover"
  primary_pod=""
  for p in $("${KUBECTL[@]}" -n "$NS" get pod -l app.kubernetes.io/component=api -o name | cut -d/ -f2); do
    u="$("${KUBECTL[@]}" -n "$NS" exec "$p" -- cat /var/lib/rhorizon/node-uuid 2>/dev/null || true)"
    [ "$u" = "$primary_before" ] && { primary_pod="$p"; break; }
  done
  [ -n "$primary_pod" ] || fail "could not map the primary UUID to a Pod"
  # A StatefulSet can recreate a deleted Pod before the 30-second FROZEN
  # window, which proves restart but not failover. Suspend every worker in the
  # primary container instead. Readiness removes it from the Service while the
  # container remains recoverable; liveness allows roughly 90 seconds, well
  # beyond the expected promotion window.
  "${KUBECTL[@]}" -n "$NS" exec "$primary_pod" -- sh -c 'kill -STOP -1'
  promoted=""
  for _ in $(seq 1 60); do
    ha_after="$(kexec "wget -qO- -T10 --header='Authorization: Bearer $tok' $base/api/v1/vault/cluster/ha" || true)"
    new_primary="$(printf '%s' "$ha_after" | jq -r '.primary_uuid // empty' 2>/dev/null || true)"
    [ -n "$new_primary" ] && [ "$new_primary" != "$primary_before" ] && { promoted=1; break; }
    sleep 2
  done
  if [ -z "$promoted" ]; then
    "${KUBECTL[@]}" -n "$NS" exec "$primary_pod" -- sh -c 'kill -CONT -1' >/dev/null 2>&1 || true
    fail "no new primary was elected within 120 seconds"
  fi
  say "automatic failover elected $new_primary"

  say "resume the old primary without the JOIN Secret"
  "${KUBECTL[@]}" -n "$NS" exec "$primary_pod" -- sh -c 'kill -CONT -1' >/dev/null 2>&1 || true
  for _ in $(seq 1 90); do
    phase="$("${KUBECTL[@]}" -n "$NS" get pod "$primary_pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = Running ] && unseal_pod "$primary_pod" && break
    sleep 2
  done
  "${KUBECTL[@]}" -n "$NS" wait --for=condition=Ready "pod/$primary_pod" --timeout=4m >/dev/null \
    || fail "$primary_pod did not recover after failover"
  final_ha=""
  for _ in $(seq 1 60); do
    final_ha="$(kexec "wget -qO- -T15 --header='Authorization: Bearer $tok' $base/api/v1/vault/cluster/ha" || true)"
    if printf '%s' "$final_ha" | jq -e --argjson replicas "$HA_REPLICAS" \
      '([.nodes[] | select(.ha_state == "primary")] | length) == 1 and
       ([.nodes[] | select(.ha_state == "secondary")] | length) == ($replicas - 1)' >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  printf '%s' "$final_ha" | jq -e --argjson replicas "$HA_REPLICAS" \
    '([.nodes[] | select(.ha_state == "primary")] | length) == 1 and
     ([.nodes[] | select(.ha_state == "secondary")] | length) == ($replicas - 1)' >/dev/null \
    || fail "membership did not reconverge after failover: $final_ha"
fi

# --- node identity survives Pod replacement ---------------------------------
# The StatefulSet must preserve the node UUID and its bound certificates across
# Pod replacement.
if [ "$HA" != "1" ]; then
  say "assert node identity survives Pod replacement"
  pod="$("${KUBECTL[@]}" -n "$NS" get pod -l app.kubernetes.io/component=api \
    -o jsonpath='{.items[0].metadata.name}')"
  [ -n "$pod" ] || fail "no api Pod found"
  uuid_before="$("${KUBECTL[@]}" -n "$NS" exec "$pod" -- cat /var/lib/rhorizon/node-uuid 2>/dev/null || true)"
  [ -n "$uuid_before" ] || fail "no node-uuid on $pod before restart"

  "${KUBECTL[@]}" -n "$NS" delete pod "$pod" --wait=true >/dev/null
  for _ in $(seq 1 90); do
    phase="$("${KUBECTL[@]}" -n "$NS" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = Running ] && unseal_pod "$pod" && break
    sleep 2
  done
  "${KUBECTL[@]}" -n "$NS" wait --for=condition=Ready "pod/$pod" --timeout=4m >/dev/null \
    || fail "api never became Ready again after Pod deletion"
  uuid_after="$("${KUBECTL[@]}" -n "$NS" exec "$pod" -- cat /var/lib/rhorizon/node-uuid 2>/dev/null || true)"
  [ "$uuid_after" = "$uuid_before" ] \
    || fail "node identity changed across Pod replacement: '$uuid_before' -> '$uuid_after'"
  say "node identity preserved: $uuid_before"
fi

if [ "$HA" = "1" ]; then
  say "PASS -- Kubernetes HA bootstrap, JOIN, live mTLS, bootstrap-secret removal, secondary restart and primary failover"
else
  say "PASS -- rhorizon up on k3d (db=$DB): api+frontend Ready, unsealed, 1 master + $f followers, identity stable across restart"
fi
