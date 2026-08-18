#!/usr/bin/env bash
# B1 - rhorizon API conformance battery (validates what ESO + sidecars exercise).
# All actions are scoped to `claude` namespace with `eso-test-*` prefix; cleanup at end.

set -u
RH_ADDR="${RH_ADDR:-http://192.168.10.1:8200}"
RH_TOK="${RH_TOK:?must export RH_TOK}"
NS="claude"
PREFIX="eso-test"

PASS=0; FAIL=0
log() { printf '%s\n' "$*"; }
ok()  { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
ko()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s - %s\n' "$1" "$2"; }

api() {
  # api METHOD PATH [BODY]
  local m="$1" p="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -o /tmp/.rh.body -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $RH_TOK" \
      -H "Content-Type: application/json" \
      -X "$m" "$RH_ADDR$p" --data "$body"
  else
    curl -sSL -o /tmp/.rh.body -w '%{http_code}' --max-time 10 \
      -H "Authorization: Bearer $RH_TOK" \
      -X "$m" "$RH_ADDR$p"
  fi
}

body() { cat /tmp/.rh.body; }
jsonq() { python3 -c "import json,sys; d=json.load(open('/tmp/.rh.body')); print($1)" 2>/dev/null; }

delete_token_by_name() {
  local name="$1" tid
  curl -sSL --max-time 10 -o /tmp/.rh.body -w '' \
    -H "Authorization: Bearer $RH_TOK" \
    "$RH_ADDR/api/v1/vault/tokens/" >/dev/null
  tid=$(python3 -c '
import json
d = json.load(open("/tmp/.rh.body"))
items = d if isinstance(d, list) else d.get("items", [])
for t in items:
    if t.get("name") == "'"$name"'":
        print(t.get("id",""))
        break
' 2>/dev/null)
  if [ -n "$tid" ]; then
    curl -sSL --max-time 10 -o /dev/null -w '' -X DELETE \
      -H "Authorization: Bearer $RH_TOK" \
      "$RH_ADDR/api/v1/vault/tokens/$tid"
  fi
}

cleanup() {
  log "--- cleanup ---"
  for n in "$PREFIX-foo" "$PREFIX-bar" "$PREFIX-conflict"; do
    api DELETE "/api/v1/vault/secrets/$n?namespace=$NS" >/dev/null
    api DELETE "/api/v1/vault/secrets/$n?namespace=forgejo" >/dev/null
  done
  delete_token_by_name "k3s-eso-sidecar"
}
# Pre-cleanup so re-runs succeed even after interruption.
delete_token_by_name "k3s-eso-sidecar"
trap cleanup EXIT

log "=== B1 - API conformance against $RH_ADDR (ns=$NS) ==="

# --- T01: health (no auth) ---
code=$(curl -sS -o /tmp/.rh.body -w '%{http_code}' --max-time 5 "$RH_ADDR/health")
[ "$code" = "200" ] && [ "$(body)" = '{"status":"ok"}' ] \
  && ok "T01 /health 200 {status:ok}" \
  || ko "T01" "code=$code body=$(body)"

# --- T02: whoami with token ---
code=$(api GET /api/v1/vault/tokens/whoami)
[ "$code" = "200" ] && [ "$(jsonq 'd["name"]')" = "claude-ns" ] \
  && ok "T02 /tokens/whoami -> claude-ns" \
  || ko "T02" "code=$code name=$(jsonq 'd.get(\"name\")')"

# --- T03: auth fails with bad token ---
RH_TOK_BAK="$RH_TOK"; RH_TOK="rh_notarealtoken"
code=$(api GET /api/v1/vault/tokens/whoami); RH_TOK="$RH_TOK_BAK"
[ "$code" = "401" ] || [ "$code" = "403" ] \
  && ok "T03 bad token -> $code" \
  || ko "T03" "expected 401/403, got $code"

# --- T04: list namespaces ---
code=$(api GET /api/v1/vault/secrets/namespaces)
nslist=$(jsonq '[i["namespace"] for i in d["items"]]')
echo "$nslist" | grep -q claude && [ "$code" = "200" ] \
  && ok "T04 /secrets/namespaces contains 'claude' ($nslist)" \
  || ko "T04" "code=$code nslist=$nslist"

# --- T05: create a secret in claude ns ---
code=$(api POST /api/v1/vault/secrets/ '{"name":"'"$PREFIX"'-foo","namespace":"claude","value":"v1-plain-value"}')
[ "$code" = "201" ] || [ "$code" = "200" ] \
  && ok "T05 create $PREFIX-foo in claude -> $code" \
  || ko "T05" "code=$code body=$(body)"

# --- T06: GET by name with explicit namespace ---
code=$(api GET "/api/v1/vault/secrets/$PREFIX-foo?namespace=$NS")
val=$(jsonq 'd["value"]')
[ "$code" = "200" ] && [ "$val" = "v1-plain-value" ] \
  && ok "T06 GET ?namespace=$NS returns v1-plain-value" \
  || ko "T06" "code=$code val=$val"

# --- T07: GET by name WITHOUT namespace (post-fix should be 200 if unique) ---
code=$(api GET "/api/v1/vault/secrets/$PREFIX-foo")
[ "$code" = "200" ] \
  && ok "T07 GET unique name w/o ?namespace -> 200 (post-fix tolerant)" \
  || ko "T07" "expected 200 unique, got $code body=$(body)"

# --- T08: GET non-existent secret ---
code=$(api GET "/api/v1/vault/secrets/nonexistent-canary-xyz?namespace=$NS")
[ "$code" = "404" ] \
  && ok "T08 non-existent -> 404" \
  || ko "T08" "expected 404, got $code"

# --- T09: GET with wrong namespace (secret exists in claude only) ---
code=$(api GET "/api/v1/vault/secrets/$PREFIX-foo?namespace=forgejo")
[ "$code" = "404" ] \
  && ok "T09 GET with wrong ns -> 404 (namespace filter actif post-fix)" \
  || ko "T09" "expected 404, got $code body=$(body)"

# --- T10: PUT update the secret value ---
code=$(api PUT "/api/v1/vault/secrets/$PREFIX-foo?namespace=$NS" '{"value":"v2-updated-value"}')
[ "$code" = "200" ] \
  && ok "T10 PUT update -> 200" \
  || ko "T10" "code=$code body=$(body)"

# --- T11: GET reads new value + version >= 2 ---
code=$(api GET "/api/v1/vault/secrets/$PREFIX-foo?namespace=$NS")
val=$(jsonq 'd["value"]'); ver=$(jsonq 'd["version"]')
[ "$val" = "v2-updated-value" ] && [ "$ver" -ge 2 ] 2>/dev/null \
  && ok "T11 GET reads v2-updated-value, version=$ver" \
  || ko "T11" "val=$val ver=$ver"

# --- T12: cross-namespace ambiguity (same name in claude + forgejo) ---
code1=$(api POST /api/v1/vault/secrets/ '{"name":"'"$PREFIX"'-conflict","namespace":"claude","value":"claude-side"}')
code2=$(api POST /api/v1/vault/secrets/ '{"name":"'"$PREFIX"'-conflict","namespace":"forgejo","value":"forgejo-side"}')
code=$(api GET "/api/v1/vault/secrets/$PREFIX-conflict")
if [ "$code" = "409" ]; then
  ok "T12 ambiguous name w/o ?namespace -> 409 (fix 2026-05-21 actif)"
elif [ "$code" = "200" ]; then
  ko "T12" "expected 409 ambiguous, got 200 - fix namespace possiblement absent ou non actif"
else
  ko "T12" "expected 409, got $code body=$(body)"
fi
# But disambiguation via ?namespace= still works:
code=$(api GET "/api/v1/vault/secrets/$PREFIX-conflict?namespace=forgejo")
val=$(jsonq 'd["value"]')
[ "$code" = "200" ] && [ "$val" = "forgejo-side" ] \
  && ok "T12b disambiguated with ?namespace=forgejo -> forgejo-side" \
  || ko "T12b" "code=$code val=$val"

# --- T13: LIST secrets in claude ns ---
code=$(api GET "/api/v1/vault/secrets/?namespace=$NS")
n=$(python3 -c 'import json; d=json.load(open("/tmp/.rh.body")); items = d if isinstance(d, list) else d.get("items", []); print(len(items))' 2>/dev/null)
has=$(python3 -c 'import json; d=json.load(open("/tmp/.rh.body")); items = d if isinstance(d, list) else d.get("items", []); print(any(s.get("name")=="'"$PREFIX"'-foo" for s in items))' 2>/dev/null)
[ "$code" = "200" ] && [ "$has" = "True" ] \
  && ok "T13 LIST ns=$NS -> $n items, contient $PREFIX-foo" \
  || ko "T13" "code=$code n=$n has=$has"

# --- T14: DELETE the test secret ---
code=$(api DELETE "/api/v1/vault/secrets/$PREFIX-foo?namespace=$NS")
[ "$code" = "200" ] || [ "$code" = "204" ] \
  && ok "T14 DELETE -> $code" \
  || ko "T14" "code=$code body=$(body)"

# --- T15: GET after delete -> 404 ---
code=$(api GET "/api/v1/vault/secrets/$PREFIX-foo?namespace=$NS")
[ "$code" = "404" ] \
  && ok "T15 GET after delete -> 404" \
  || ko "T15" "expected 404, got $code"

# --- T16: mint a scoped sidecar token (claude only, secrets:r) ---
api DELETE "/api/v1/vault/tokens/k3s-eso-sidecar" >/dev/null
code=$(api POST /api/v1/vault/tokens/ '{"name":"k3s-eso-sidecar","permissions":{"secrets":"r","namespaces":["claude"]}}')
SIDECAR_TOK=$(jsonq 'd.get("token","")')
[ "$code" = "201" ] && [ -n "$SIDECAR_TOK" ] \
  && ok "T16 mint scoped token k3s-eso-sidecar (claude/secrets:r)" \
  || ko "T16" "code=$code tok-len=${#SIDECAR_TOK}"
echo "SIDECAR_TOK=$SIDECAR_TOK" > /tmp/.rh-sidecar-tok

# --- T17: sidecar token can read in claude ---
RH_TOK_BAK="$RH_TOK"; RH_TOK="$SIDECAR_TOK"
api POST /api/v1/vault/secrets/ '{"name":"'"$PREFIX"'-bar","namespace":"claude","value":"sidecar-readable"}' >/dev/null
RH_TOK="$RH_TOK_BAK"
api POST /api/v1/vault/secrets/ '{"name":"'"$PREFIX"'-bar","namespace":"claude","value":"sidecar-readable"}' >/dev/null
RH_TOK="$SIDECAR_TOK"
code=$(api GET "/api/v1/vault/secrets/$PREFIX-bar?namespace=$NS")
val=$(jsonq 'd["value"]')
RH_TOK="$RH_TOK_BAK"
[ "$code" = "200" ] && [ "$val" = "sidecar-readable" ] \
  && ok "T17 sidecar token reads claude/$PREFIX-bar" \
  || ko "T17" "code=$code val=$val"

# --- T18: sidecar token CANNOT write (secrets:r only) ---
RH_TOK_BAK="$RH_TOK"; RH_TOK="$SIDECAR_TOK"
code=$(api PUT "/api/v1/vault/secrets/$PREFIX-bar?namespace=$NS" '{"value":"should-fail"}')
RH_TOK="$RH_TOK_BAK"
[ "$code" = "403" ] || [ "$code" = "401" ] \
  && ok "T18 sidecar token PUT -> $code (read-only enforce)" \
  || ko "T18" "expected 401/403, got $code body=$(body)"

# --- T19: sidecar token CANNOT read forgejo ns ---
RH_TOK_BAK="$RH_TOK"; RH_TOK="$SIDECAR_TOK"
code=$(api GET "/api/v1/vault/secrets/$PREFIX-conflict?namespace=forgejo")
RH_TOK="$RH_TOK_BAK"
[ "$code" = "403" ] || [ "$code" = "404" ] \
  && ok "T19 sidecar token forgejo -> $code (namespace fence)" \
  || ko "T19" "expected 403/404, got $code"

# --- summary ---
log ""
log "=== B1 summary: PASS=$PASS  FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ]
