#!/bin/bash
# Functional smoke against a running native install: seal/unseal, token + secret
# CRUD with value assertions, scoped-token authz, audit chain. Run ON the host
# (needs sudo to read the master password + restart the service). NOT a unit test
# replacement -- an end-to-end "does the vault actually work under confinement".
set -u
B=http://127.0.0.1:8200/api/v1/vault
SVC_RESTART="${1:-sudo systemctl restart rhorizon}"
SECRET_FILE="${RH_SECRET_FILE:-/etc/rhorizon/rhorizon.env-secrets}"
MP=$(sudo sed -n 's/^MASTER_PASSWORD=//p' "$SECRET_FILE")
[ -n "$MP" ] || { echo "no master password in $SECRET_FILE"; exit 2; }
j(){ python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception as e: print('<non-json>'); sys.exit(0)
print(d.get('$1','<missing>') if isinstance(d,dict) else d)"; }
P=0; F=0
ok(){ echo "  PASS  $1"; P=$((P+1)); }
no(){ echo "  FAIL  $1"; F=$((F+1)); }
eq(){ if [ "$2" = "$3" ]; then ok "$1 = $2"; else no "$1 : expected [$3] got [$2]"; fi; }

echo "== SEAL / UNSEAL =="
eval "$SVC_RESTART"; sleep 5
echo "  raw /status: $(curl -s $B/status)"
eq "sealed after restart" "$(curl -s $B/status | j sealed)" "True"
UNSEAL=$(curl -s -X POST $B/unseal -H 'Content-Type: application/json' -d "{\"password\":\"$MP\"}")
echo "  raw /unseal keys: $(printf '%s' "$UNSEAL" | python3 -c 'import sys,json;print(list(json.load(sys.stdin).keys()))' 2>/dev/null)"
RT=$(printf '%s' "$UNSEAL" | j root_token)
[ -n "$RT" ] && [ "$RT" != "<missing>" ] && ok "unseal minted root token" || no "unseal did not mint root token"
eq "unsealed" "$(curl -s $B/status | j sealed)" "False"
AH="Authorization: Bearer $RT"

echo "== SECRET create + read (value round-trip) =="
VAL="smoke-$(date +%s)-$$"
echo "  create http: $(curl -s -o /dev/null -w '%{http_code}' -X POST $B/secrets/ -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"smoke\",\"value\":\"$VAL\"}")"
eq "secret read back == written" "$(curl -s $B/secrets/smoke -H "$AH" | j value)" "$VAL"

echo "== TOKEN mint + scoped authz =="
TOK=$(curl -s -X POST $B/tokens/ -H "$AH" -H 'Content-Type: application/json' -d '{"name":"smoke-reader","permissions":{"secrets":"r"}}' | j token)
[ -n "$TOK" ] && [ "$TOK" != "<missing>" ] && ok "scoped token minted" || no "scoped token mint failed"
eq "scoped token reads secret" "$(curl -s $B/secrets/smoke -H "Authorization: Bearer $TOK" | j value)" "$VAL"
eq "scoped token DENIED write" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/secrets/ -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"name":"x","value":"y"}')" "403"

echo "== AUDIT chain =="
echo "  raw /audit/verify: $(curl -s $B/audit/verify -H "$AH")"

echo "== cleanup + SEAL =="
curl -s -o /dev/null -X DELETE $B/secrets/smoke -H "$AH"
eq "seal http" "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/seal -H "$AH")" "200"
eq "sealed after seal" "$(curl -s $B/status | j sealed)" "True"

echo "== RESULT: $P passed, $F failed =="
[ "$F" = 0 ]
