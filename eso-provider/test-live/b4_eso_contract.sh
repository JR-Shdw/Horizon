#!/usr/bin/env bash
# B4 - Validates the contract exercised by the ESO provider (eso-provider/client.go)
# against the live rhorizon API. Simulates what ESO does on each reconcile:
#   - GetSecret with "ns/name" prefix resolution
#   - JSON property extraction
#   - GetSecretMap returning multi-field map for JSON values
#   - GetAllSecrets with namespace listing

set -u
RH_ADDR="${RH_ADDR:-http://192.168.10.1:8200}"
RH_TOK="${RH_TOK:?must export RH_TOK}"
NS="claude"
PREFIX="eso-contract"

PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
ko() { FAIL=$((FAIL+1)); printf '  [FAIL] %s - %s\n' "$1" "$2"; }
log() { printf '%s\n' "$*"; }

api() {
  local m="$1" p="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -o /tmp/.rh.body -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $RH_TOK" -H "Content-Type: application/json" \
      -X "$m" "$RH_ADDR$p" --data "$body"
  else
    curl -sSL -o /tmp/.rh.body -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $RH_TOK" -X "$m" "$RH_ADDR$p"
  fi
}
jsonq() { python3 -c "import json,sys; d=json.load(open('/tmp/.rh.body')); print($1)" 2>/dev/null; }

cleanup() {
  log "--- cleanup ---"
  for n in "$PREFIX-plain" "$PREFIX-json"; do
    api DELETE "/api/v1/vault/secrets/$n?namespace=$NS" >/dev/null
  done
}
trap cleanup EXIT

log "=== B4 - ESO provider contract simulation against $RH_ADDR ==="

# Setup: a plain secret and a JSON-multi-field secret
JSON_VALUE='{"username":"appuser","password":"hunter2","port":"5432"}'
api POST /api/v1/vault/secrets/ '{"name":"'"$PREFIX"'-plain","namespace":"'"$NS"'","value":"plain-string-value"}' >/dev/null
api POST /api/v1/vault/secrets/ "{\"name\":\"$PREFIX-json\",\"namespace\":\"$NS\",\"value\":$(printf %s "$JSON_VALUE" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}" >/dev/null

# --- T35: ESO `remoteRef.Key = "claude/<name>"` (prefix split) ---
#   client.go resolveKey() splits at first slash; the API GET should be
#   /api/v1/vault/secrets/<name>?namespace=claude
code=$(api GET "/api/v1/vault/secrets/$PREFIX-plain?namespace=$NS")
val=$(jsonq 'd["value"]')
[ "$code" = "200" ] && [ "$val" = "plain-string-value" ] \
  && ok "T35 ESO prefix 'claude/$PREFIX-plain' resolves to plain value" \
  || ko "T35" "code=$code val=$val"

# --- T36: ESO `remoteRef.Key = "<name>"` with default ns on store ---
#   resolveKey() returns (name, c.namespace) when no slash; same URL pattern
code=$(api GET "/api/v1/vault/secrets/$PREFIX-plain?namespace=$NS")
[ "$code" = "200" ] \
  && ok "T36 ESO bare key + store default ns -> identical URL" \
  || ko "T36" "code=$code"

# --- T37: GetSecret with remoteRef.Property on JSON value ---
#   client.go json.Unmarshal then lookup obj[Property]; verify the underlying
#   stored value is valid JSON (so ESO can parse it)
code=$(api GET "/api/v1/vault/secrets/$PREFIX-json?namespace=$NS")
raw=$(jsonq 'd["value"]')
prop=$(printf %s "$raw" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("password",""))' 2>/dev/null)
[ "$code" = "200" ] && [ "$prop" = "hunter2" ] \
  && ok "T37 stored JSON is parseable; .password = hunter2" \
  || ko "T37" "code=$code prop=$prop raw=$raw"

# --- T38: GetSecretMap on JSON value - every top-level key becomes an entry ---
#   ESO returns a map[string][]byte over JSON top-level keys
keys=$(printf %s "$raw" | python3 -c 'import json,sys; print(",".join(sorted(json.loads(sys.stdin.read()).keys())))' 2>/dev/null)
[ "$keys" = "password,port,username" ] \
  && ok "T38 GetSecretMap source covers 3 keys: $keys" \
  || ko "T38" "keys='$keys'"

# --- T39: GetSecretMap on plain value - single entry keyed by short name ---
#   client.go: if json.Unmarshal fails -> map{shortName: value}
code=$(api GET "/api/v1/vault/secrets/$PREFIX-plain?namespace=$NS")
raw=$(jsonq 'd["value"]')
is_json=$(python3 -c 'import json,sys
try: json.loads(open("/tmp/.rh.body").read())
except: pass
try: json.loads(open("/tmp/.rh.body").read()).get("value")
except: pass
try:
  v = json.load(open("/tmp/.rh.body"))["value"]
  json.loads(v)
  print("yes")
except: print("no")' 2>/dev/null)
[ "$is_json" = "no" ] \
  && ok "T39 plain value not JSON -> ESO falls back to {shortName: value}" \
  || ko "T39" "is_json=$is_json (plain detected as JSON?)"

# --- T40: GetAllSecrets - list+filter by namespace (ESO Find use) ---
#   client.go calls listSecrets(ns); returns metadata only
code=$(api GET "/api/v1/vault/secrets/?namespace=$NS")
has_plain=$(python3 -c '
import json
d = json.load(open("/tmp/.rh.body"))
items = d if isinstance(d, list) else d.get("items", [])
print(any(s.get("name")=="'"$PREFIX"'-plain" for s in items))
' 2>/dev/null)
has_json=$(python3 -c '
import json
d = json.load(open("/tmp/.rh.body"))
items = d if isinstance(d, list) else d.get("items", [])
print(any(s.get("name")=="'"$PREFIX"'-json" for s in items))
' 2>/dev/null)
[ "$code" = "200" ] && [ "$has_plain" = "True" ] && [ "$has_json" = "True" ] \
  && ok "T40 GetAllSecrets lists both eso-contract-* in $NS" \
  || ko "T40" "code=$code has_plain=$has_plain has_json=$has_json"

# --- T41: PushSecret (ESO PushSecret API; uses putSecret) ---
#   client.go: putSecret -> PUT /api/v1/vault/secrets/{name}
code=$(api PUT "/api/v1/vault/secrets/$PREFIX-plain?namespace=$NS" '{"value":"eso-pushed-value"}')
[ "$code" = "200" ] \
  && ok "T41 ESO PushSecret PUT -> 200" \
  || ko "T41" "code=$code body=$(cat /tmp/.rh.body)"

# Verify update
code=$(api GET "/api/v1/vault/secrets/$PREFIX-plain?namespace=$NS")
val=$(jsonq 'd["value"]')
[ "$val" = "eso-pushed-value" ] \
  && ok "T41b read-back confirms eso-pushed-value" \
  || ko "T41b" "val=$val"

# --- T42: DeleteSecret (ESO uses deleteSecret -> DELETE) ---
code=$(api DELETE "/api/v1/vault/secrets/$PREFIX-json?namespace=$NS")
[ "$code" = "200" ] || [ "$code" = "204" ] \
  && ok "T42 ESO DeleteSecret DELETE -> $code" \
  || ko "T42" "code=$code"

# --- T43: error mapping - ESO expects NoSecretErr style on 404 ---
#   client.go translates apiError{Status:404} to esv1beta1.NoSecretErr
code=$(api GET "/api/v1/vault/secrets/$PREFIX-json?namespace=$NS")
detail=$(jsonq 'd.get("detail","")')
[ "$code" = "404" ] && echo "$detail" | grep -qi "not found" \
  && ok "T43 404 + detail contains 'not found' (mappable to NoSecretErr)" \
  || ko "T43" "code=$code detail=$detail"

# --- T44: Validate() endpoint - ESO calls it on each store reconcile ---
#   client.go Validate() must succeed if creds work; whoami is a good proxy
code=$(api GET /api/v1/vault/tokens/whoami)
active=$(jsonq 'd.get("active",False)')
[ "$code" = "200" ] && [ "$active" = "True" ] \
  && ok "T44 store Validate() -> whoami ok, token active" \
  || ko "T44" "code=$code active=$active"

# --- summary ---
log ""
log "=== B4 summary: PASS=$PASS  FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ]
