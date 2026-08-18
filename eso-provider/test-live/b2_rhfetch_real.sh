#!/usr/bin/env bash
# B2 - rh-fetch real integration on k3s: init-container writes secrets,
# app container reads them. Validates the production path (parallel to ESO).
#
# Prereqs:
#   - KUBECONFIG points at k3s lab
#   - RH_TOK = master token with tokens:rw, secrets:rw on claude ns
#   - vault reachable at RH_ADDR from pods (192.168.10.1:8200)

set -u
RH_ADDR="${RH_ADDR:-http://192.168.10.1:8200}"
RH_TOK="${RH_TOK:?must export RH_TOK}"
RH_ADDR_POD="${RH_ADDR_POD:-http://192.168.10.1:8200}"
NS="claude"
KCTL="kubectl"

PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
ko() { FAIL=$((FAIL+1)); printf '  [FAIL] %s - %s\n' "$1" "$2"; }
log() { printf '%s\n' "$*"; }

api() {
  local m="$1" p="$2" body="${3:-}" tok="${4:-$RH_TOK}"
  if [ -n "$body" ]; then
    curl -sS -o /tmp/.rh.body -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $tok" -H "Content-Type: application/json" \
      -X "$m" "$RH_ADDR$p" --data "$body"
  else
    curl -sSL -o /tmp/.rh.body -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $tok" -X "$m" "$RH_ADDR$p"
  fi
}
jsonq() { python3 -c "import json,sys; d=json.load(open('/tmp/.rh.body')); print($1)" 2>/dev/null; }

# unique suffix to avoid collisions when re-running
SUFFIX="$$"
TOK_NAME="k3s-rhfetch-test-$SUFFIX"
SEC_A="eso-rhfetch-a-$SUFFIX"
SEC_B="eso-rhfetch-b-$SUFFIX"
VAL_A="apple-$RANDOM-$SUFFIX"
VAL_B="banana-$RANDOM-$SUFFIX"

cleanup() {
  log "--- cleanup ---"
  $KCTL delete pod rh-fetch-real --ignore-not-found >/dev/null 2>&1
  $KCTL delete secret rh-sidecar-bootstrap --ignore-not-found >/dev/null 2>&1
  api DELETE "/api/v1/vault/secrets/$SEC_A?namespace=$NS" >/dev/null
  api DELETE "/api/v1/vault/secrets/$SEC_B?namespace=$NS" >/dev/null
  # Revoke and delete sidecar token by id (need to look it up)
  api GET "/api/v1/vault/tokens/" >/dev/null
  tok_id=$(python3 -c '
import json
d = json.load(open("/tmp/.rh.body"))
items = d if isinstance(d, list) else d.get("items", [])
for t in items:
    if t.get("name") == "'"$TOK_NAME"'":
        print(t.get("id",""))
        break
' 2>/dev/null)
  if [ -n "$tok_id" ]; then
    api DELETE "/api/v1/vault/tokens/$tok_id" >/dev/null
  fi
}
trap cleanup EXIT

log "=== B2 - rh-fetch real integration on k3s ==="

# --- prep: 2 secrets + scoped sidecar token ---
api POST /api/v1/vault/secrets/ '{"name":"'"$SEC_A"'","namespace":"'"$NS"'","value":"'"$VAL_A"'"}' >/dev/null
api POST /api/v1/vault/secrets/ '{"name":"'"$SEC_B"'","namespace":"'"$NS"'","value":"'"$VAL_B"'"}' >/dev/null
api POST /api/v1/vault/tokens/ '{"name":"'"$TOK_NAME"'","permissions":{"secrets":"r","namespaces":["'"$NS"'"]}}' >/dev/null
SIDECAR_TOK=$(jsonq 'd.get("token","")')
[ -n "$SIDECAR_TOK" ] || { ko "prep" "could not mint sidecar token"; exit 1; }
log "prep ok (secrets + token $TOK_NAME minted)"

# --- create k8s Secret holding sidecar token ---
$KCTL delete secret rh-sidecar-bootstrap --ignore-not-found >/dev/null 2>&1
$KCTL create secret generic rh-sidecar-bootstrap --from-literal=token="$SIDECAR_TOK" >/dev/null

# --- pod: init container rh-fetch, app container alpine sleep ---
$KCTL delete pod rh-fetch-real --ignore-not-found >/dev/null 2>&1
cat <<EOF | $KCTL apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: rh-fetch-real
spec:
  restartPolicy: Never
  volumes:
    - name: secrets
      emptyDir: { medium: Memory, sizeLimit: 1Mi }
    - name: token
      secret:
        secretName: rh-sidecar-bootstrap
        defaultMode: 0444
  initContainers:
    - name: rh-fetch
      image: ghcr.io/jr-shdw/rhorizon-agent:latest
      command: ["/usr/local/bin/rh-fetch"]
      env:
        - name: RHORIZON_ADDR
          value: "$RH_ADDR_POD"
        - name: RHORIZON_TOKEN_FILE
          value: /var/run/rh/token
        - name: RHORIZON_SECRETS
          value: "$SEC_A:/secrets/sec_a,$SEC_B:/secrets/sec_b"
      volumeMounts:
        - { name: secrets, mountPath: /secrets }
        - { name: token,   mountPath: /var/run/rh, readOnly: true }
  containers:
    - name: app
      image: alpine:3.21
      command: ["sh","-c","sleep 300"]
      volumeMounts:
        - { name: secrets, mountPath: /secrets, readOnly: true }
EOF

# --- T20: init container completes successfully ---
log "  waiting for pod Running (init container done)..."
ok_phase=0
for i in $(seq 1 60); do
  phase=$($KCTL get pod rh-fetch-real -o jsonpath='{.status.phase}' 2>/dev/null)
  if [ "$phase" = "Running" ]; then ok_phase=1; break; fi
  if [ "$phase" = "Failed" ] || [ "$phase" = "Succeeded" ]; then break; fi
  sleep 1
done
init_status=$($KCTL get pod rh-fetch-real -o jsonpath='{.status.initContainerStatuses[0].state.terminated.reason}' 2>/dev/null)
init_exit=$($KCTL get pod rh-fetch-real -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode}' 2>/dev/null)
if [ "$ok_phase" = "1" ] && [ "$init_exit" = "0" ]; then
  ok "T20 init container rh-fetch terminated reason=$init_status exit=0"
else
  ko "T20" "phase=$phase init.reason=$init_status init.exit=$init_exit"
  $KCTL logs rh-fetch-real -c rh-fetch 2>&1 | sed 's/^/    /' | head -20
fi

# --- T21: /secrets/sec_a present in app container, matches VAL_A ---
read_a=$($KCTL exec rh-fetch-real -c app -- cat /secrets/sec_a 2>/dev/null)
[ "$read_a" = "$VAL_A" ] \
  && ok "T21 /secrets/sec_a content matches VAL_A" \
  || ko "T21" "got='$read_a' expected='$VAL_A'"

# --- T22: /secrets/sec_b present, matches VAL_B ---
read_b=$($KCTL exec rh-fetch-real -c app -- cat /secrets/sec_b 2>/dev/null)
[ "$read_b" = "$VAL_B" ] \
  && ok "T22 /secrets/sec_b content matches VAL_B" \
  || ko "T22" "got='$read_b' expected='$VAL_B'"

# --- T23: file mode of /secrets/sec_a (rh-fetch atomic_write) ---
mode=$($KCTL exec rh-fetch-real -c app -- stat -c '%a' /secrets/sec_a 2>/dev/null)
# rh-fetch uses atomic_write - typical mode is 0600 or 0644 depending on impl
if [ "$mode" = "600" ] || [ "$mode" = "644" ] || [ "$mode" = "400" ]; then
  ok "T23 /secrets/sec_a mode=$mode (restrictive enough)"
else
  ko "T23" "unexpected mode=$mode"
fi

# --- T24: rh-fetch init container logs structured output ---
logs=$($KCTL logs rh-fetch-real -c rh-fetch 2>/dev/null)
echo "$logs" | grep -q "rh-fetch" && echo "$logs" | grep -q "$SEC_A" \
  && ok "T24 rh-fetch logged secrets fetched" \
  || ko "T24" "logs missing markers: $logs"

# --- T25: app container DOES NOT see RHORIZON_TOKEN in its env ---
toks_in_app=$($KCTL exec rh-fetch-real -c app -- env 2>/dev/null | grep -c "RHORIZON_TOKEN")
[ "$toks_in_app" = "0" ] \
  && ok "T25 app container env clean (no RHORIZON_TOKEN leaked)" \
  || ko "T25" "RHORIZON_TOKEN visible in app env"

# --- T26: app container CANNOT write to /secrets (mounted readOnly) ---
$KCTL exec rh-fetch-real -c app -- sh -c 'echo bad > /secrets/sec_a' >/dev/null 2>&1
rc=$?
[ "$rc" != "0" ] \
  && ok "T26 /secrets is readOnly from app (write fails)" \
  || ko "T26" "app could write to /secrets - read-only mount missing"

# --- T27: token file present in init's volume not app's ---
# (test by re-deploying would be too expensive; assert via spec)
mounts=$($KCTL get pod rh-fetch-real -o jsonpath='{.spec.containers[0].volumeMounts[*].mountPath}' 2>/dev/null)
echo "$mounts" | grep -q '/var/run/rh' \
  && ko "T27" "token volume mounted in app container (spec leak)" \
  || ok "T27 token volume NOT mounted in app container"

# --- T28: failure path - bad token causes init to fail ---
$KCTL delete pod rh-fetch-real-bad --ignore-not-found >/dev/null 2>&1
$KCTL delete secret rh-bad-token --ignore-not-found >/dev/null 2>&1
$KCTL create secret generic rh-bad-token --from-literal=token="rh_not_a_real_token_xxx" >/dev/null
cat <<EOF | $KCTL apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: rh-fetch-real-bad
spec:
  restartPolicy: Never
  volumes:
    - name: secrets
      emptyDir: { medium: Memory }
    - name: token
      secret: { secretName: rh-bad-token, defaultMode: 0400 }
  initContainers:
    - name: rh-fetch
      image: ghcr.io/jr-shdw/rhorizon-agent:latest
      command: ["/usr/local/bin/rh-fetch"]
      env:
        - { name: RHORIZON_ADDR, value: "$RH_ADDR_POD" }
        - { name: RHORIZON_TOKEN_FILE, value: /var/run/rh/token }
        - { name: RHORIZON_SECRETS, value: "$SEC_A:/secrets/x" }
      volumeMounts:
        - { name: secrets, mountPath: /secrets }
        - { name: token, mountPath: /var/run/rh, readOnly: true }
  containers:
    - name: app
      image: alpine:3.21
      command: ["sh","-c","sleep 60"]
EOF
for i in $(seq 1 30); do
  state=$($KCTL get pod rh-fetch-real-bad -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode}' 2>/dev/null)
  reason=$($KCTL get pod rh-fetch-real-bad -o jsonpath='{.status.initContainerStatuses[0].state.waiting.reason}' 2>/dev/null)
  if [ -n "$state" ] || [ "$reason" = "CrashLoopBackOff" ]; then break; fi
  sleep 1
done
exitcode=$($KCTL get pod rh-fetch-real-bad -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode}' 2>/dev/null)
last_reason=$($KCTL get pod rh-fetch-real-bad -o jsonpath='{.status.initContainerStatuses[0].state.terminated.reason}{.status.initContainerStatuses[0].state.waiting.reason}' 2>/dev/null)
if [ -n "$exitcode" ] && [ "$exitcode" != "0" ]; then
  ok "T28 bad token -> init exit=$exitcode reason=$last_reason"
else
  ko "T28" "expected non-zero exit; exit=$exitcode reason=$last_reason"
  $KCTL logs rh-fetch-real-bad -c rh-fetch 2>&1 | sed 's/^/    /' | head -10
fi
$KCTL delete pod rh-fetch-real-bad --ignore-not-found >/dev/null 2>&1
$KCTL delete secret rh-bad-token --ignore-not-found >/dev/null 2>&1

# --- summary ---
log ""
log "=== B2 summary: PASS=$PASS  FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ]
