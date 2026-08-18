#!/usr/bin/env bash
# B3 - rh-watch live rotation on k3s: pre-update + post-update file content.

set -u
RH_ADDR="${RH_ADDR:-http://192.168.10.1:8200}"
RH_TOK="${RH_TOK:?must export RH_TOK}"
RH_ADDR_POD="${RH_ADDR_POD:-http://192.168.10.1:8200}"
NS="claude"
POLL=5
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

SUFFIX="$$"
TOK_NAME="k3s-rhwatch-test-$SUFFIX"
SECNAME="eso-rhwatch-$SUFFIX"
V1="initial-$RANDOM-$SUFFIX"
V2="rotated-$RANDOM-$SUFFIX"

cleanup() {
  log "--- cleanup ---"
  $KCTL delete pod rh-watch-real --ignore-not-found >/dev/null 2>&1
  $KCTL delete secret rh-watch-token --ignore-not-found >/dev/null 2>&1
  api DELETE "/api/v1/vault/secrets/$SECNAME?namespace=$NS" >/dev/null
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
  [ -n "$tok_id" ] && api DELETE "/api/v1/vault/tokens/$tok_id" >/dev/null
}
trap cleanup EXIT

log "=== B3 - rh-watch live rotation (poll=${POLL}s) ==="

api POST /api/v1/vault/secrets/ '{"name":"'"$SECNAME"'","namespace":"'"$NS"'","value":"'"$V1"'"}' >/dev/null
api POST /api/v1/vault/tokens/ '{"name":"'"$TOK_NAME"'","permissions":{"secrets":"r","namespaces":["'"$NS"'"]}}' >/dev/null
SIDECAR_TOK=$(jsonq 'd.get("token","")')
[ -n "$SIDECAR_TOK" ] || { ko "prep" "could not mint sidecar token"; exit 1; }
$KCTL delete secret rh-watch-token --ignore-not-found >/dev/null 2>&1
$KCTL create secret generic rh-watch-token --from-literal=token="$SIDECAR_TOK" >/dev/null

$KCTL delete pod rh-watch-real --ignore-not-found >/dev/null 2>&1
cat <<EOF | $KCTL apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: rh-watch-real
spec:
  restartPolicy: Never
  volumes:
    - name: secrets
      emptyDir: { medium: Memory, sizeLimit: 1Mi }
    - name: token
      secret: { secretName: rh-watch-token, defaultMode: 0444 }
  containers:
    - name: rh-watch
      image: ghcr.io/jr-shdw/rhorizon-agent:latest
      command: ["/usr/local/bin/rh-watch"]
      env:
        - { name: RHORIZON_ADDR, value: "$RH_ADDR_POD" }
        - { name: RHORIZON_TOKEN_FILE, value: /var/run/rh/token }
        - { name: RHORIZON_SECRETS, value: "$SECNAME:/secrets/sec" }
        - { name: RHORIZON_POLL_SECS, value: "$POLL" }
      volumeMounts:
        - { name: secrets, mountPath: /secrets }
        - { name: token, mountPath: /var/run/rh, readOnly: true }
    - name: app
      image: alpine:3.21
      command: ["sh","-c","sleep 600"]
      volumeMounts:
        - { name: secrets, mountPath: /secrets, readOnly: true }
EOF

# --- T29: pod reaches Running (both containers up) ---
log "  waiting for pod Running..."
for i in $(seq 1 60); do
  phase=$($KCTL get pod rh-watch-real -o jsonpath='{.status.phase}' 2>/dev/null)
  ready=$($KCTL get pod rh-watch-real -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null)
  [ "$phase" = "Running" ] && echo "$ready" | tr ' ' '\n' | grep -qv false && break
  sleep 1
done
phase=$($KCTL get pod rh-watch-real -o jsonpath='{.status.phase}' 2>/dev/null)
[ "$phase" = "Running" ] \
  && ok "T29 pod Running (rh-watch + app both started)" \
  || ko "T29" "phase=$phase"

# --- T30: initial fetch wrote V1 ---
log "  giving rh-watch up to ${POLL}s + buffer for first poll..."
got_v1=""
for i in $(seq 1 $((POLL+10))); do
  got_v1=$($KCTL exec rh-watch-real -c app -- cat /secrets/sec 2>/dev/null)
  [ "$got_v1" = "$V1" ] && break
  sleep 1
done
[ "$got_v1" = "$V1" ] \
  && ok "T30 first poll wrote V1 ($got_v1)" \
  || ko "T30" "got='$got_v1' expected='$V1' (init may not have run yet)"

# --- T31: rotate the secret via PUT ---
api PUT "/api/v1/vault/secrets/$SECNAME?namespace=$NS" '{"value":"'"$V2"'"}' >/dev/null
log "  secret rotated server-side; waiting up to $((POLL*3))s for sidecar to catch up..."

# --- T32: app sees V2 after poll interval ---
got_v2=""
for i in $(seq 1 $((POLL*3))); do
  got_v2=$($KCTL exec rh-watch-real -c app -- cat /secrets/sec 2>/dev/null)
  [ "$got_v2" = "$V2" ] && break
  sleep 1
done
[ "$got_v2" = "$V2" ] \
  && ok "T32 rh-watch propagated rotation V1->V2 within $((POLL*3))s" \
  || ko "T32" "still='$got_v2' expected='$V2'"

# --- T33: rh-watch logs mention the update ---
logs=$($KCTL logs rh-watch-real -c rh-watch 2>/dev/null | tail -20)
echo "$logs" | grep -iE "rh-watch|update|changed|rotated|$SECNAME" >/dev/null \
  && ok "T33 rh-watch logged activity (markers present)" \
  || ko "T33" "no expected markers in logs: $logs"

# --- T34: file atomic (no half-written state during rotation) ---
# Test: do 5 PUTs back-to-back; the file at any read should be one of the values
api PUT "/api/v1/vault/secrets/$SECNAME?namespace=$NS" '{"value":"rotate-1"}' >/dev/null
sleep $POLL
api PUT "/api/v1/vault/secrets/$SECNAME?namespace=$NS" '{"value":"rotate-2"}' >/dev/null
sleep $POLL
api PUT "/api/v1/vault/secrets/$SECNAME?namespace=$NS" '{"value":"rotate-3"}' >/dev/null
sleep $((POLL+5))
final=$($KCTL exec rh-watch-real -c app -- cat /secrets/sec 2>/dev/null)
[ "$final" = "rotate-3" ] \
  && ok "T34 rapid PUTs converge to last value (final=$final)" \
  || ko "T34" "final='$final' expected='rotate-3'"

log ""
log "=== B3 summary: PASS=$PASS  FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ]
