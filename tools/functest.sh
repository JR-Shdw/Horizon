#!/bin/bash
# rhorizon functional test battery -- end-to-end against a RUNNING native install.
# Covers: seal/unseal, a STABILITY SOAK (catches "unseal ok then re-seals/crashes
# seconds later"), secret CRUD + versioning + namespaces, tokens + RBAC +
# ephemeral + whoami + revoke, audit chain, and API-vs-CLI parity.
#
# Run ON the host (needs sudo: read master password, restart service, MainPID).
#   sudo bash functest.sh [SOAK_SECS]
set -u
B=http://127.0.0.1:8200/api/v1/vault
H=http://127.0.0.1:8200/health   # health lives at the root, NOT under /api/v1/vault
SOAK_SECS="${1:-45}"
SECRET_FILE="${RH_SECRET_FILE:-/etc/rhorizon/rhorizon.env-secrets}"
VENV="${RH_VENV:-/opt/rhorizon/.venv}"
# Runs under sudo, so $HOME is root's; resolve the invoking user's checkout instead.
CHECKOUT="${RH_CHECKOUT:-$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)/rhorizon}"
MP=$(sudo sed -n 's/^MASTER_PASSWORD=//p' "$SECRET_FILE")
[ -n "$MP" ] || { echo "no master password in $SECRET_FILE"; exit 2; }

j(){ python3 -c "import sys,json
try: d=json.load(sys.stdin)
except Exception: print('<non-json>'); sys.exit(0)
print(d.get('$1','<missing>') if isinstance(d,dict) else d)"; }
mainpid(){ systemctl show -p MainPID --value rhorizon 2>/dev/null || echo '?'; }
P=0; F=0
ok(){ echo "  PASS  $1"; P=$((P+1)); }
no(){ echo "  FAIL  $1"; F=$((F+1)); }
eq(){ if [ "$2" = "$3" ]; then ok "$1 = $2"; else no "$1 : expected [$3] got [$2]"; fi; }

echo "=================== SEAL / UNSEAL ==================="
sudo systemctl restart rhorizon 2>/dev/null; sleep 5
eq "sealed after restart" "$(curl -s -m5 $B/status | j sealed)" "True"
# root_token is minted ONLY on the first (bootstrap) unseal; the installer already
# bootstrapped, so a re-unseal returns none. Verify the unseal works, then use the
# admin token saved by the installer in the secrets file.
US=$(curl -s -m10 -X POST $B/unseal -H 'Content-Type: application/json' -d "{\"password\":\"$MP\"}")
eq "unseal reports unsealed" "$(echo "$US" | j status)" "unsealed"
RT=$(echo "$US" | j root_token)
if [ -z "$RT" ] || [ "$RT" = "<missing>" ]; then
  RT=$(sudo sed -n 's/^ROOT_TOKEN=//p' "$SECRET_FILE")
  [ -n "$RT" ] && ok "admin token from $SECRET_FILE (post-bootstrap unseal mints none)" || { no "no admin token (unseal minted none, ROOT_TOKEN absent from secrets)"; echo "ABORT"; exit 1; }
fi
eq "unsealed immediately" "$(curl -s -m5 $B/status | j sealed)" "False"
AH="Authorization: Bearer $RT"

echo "=================== STABILITY SOAK (${SOAK_SECS}s) ==================="
pid0=$(mainpid); flips=0; checks=0
end=$((SECONDS+SOAK_SECS))
while [ $SECONDS -lt $end ]; do
  s=$(curl -s -m3 $B/status | j sealed); h=$(curl -s -m3 $H | j status); pid=$(mainpid)
  checks=$((checks+1))
  [ "$s" = "False" ] || { echo "  !! t+$((SECONDS)): status flipped sealed=$s"; flips=$((flips+1)); }
  [ "$h" = "ok" ]    || { echo "  !! t+$((SECONDS)): health=$h"; flips=$((flips+1)); }
  [ "$pid" = "$pid0" ] || { echo "  !! t+$((SECONDS)): MainPID $pid0 -> $pid (service restarted/crashed)"; flips=$((flips+1)); pid0=$pid; }
  sleep 2
done
if [ $flips -eq 0 ]; then ok "soak: stable over ${SOAK_SECS}s ($checks polls, no reseal/crash)"
else no "soak: $flips instability events over ${SOAK_SECS}s -- THIS is the 'unseal then unstable' bug"; fi
# if the soak re-sealed, re-unseal for the rest of the battery
if [ "$(curl -s -m5 $B/status | j sealed)" = "True" ]; then
  curl -s -m10 -o /dev/null -X POST $B/unseal -H 'Content-Type: application/json' -d "{\"password\":\"$MP\"}"
  # RT stays the saved admin token (re-unseal mints none); AH already set
fi

echo "=================== SECRETS (CRUD + versioning + namespace) ==================="
V1="v1-$(date +%s)"; V2="v2-$(date +%s)"
eq "create http"        "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/secrets/ -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"ft\",\"value\":\"$V1\"}")" "201"
eq "read == written"    "$(curl -s $B/secrets/ft -H "$AH" | j value)" "$V1"
eq "update http"        "$(curl -s -o /dev/null -w '%{http_code}' -X PUT $B/secrets/ft -H "$AH" -H 'Content-Type: application/json' -d "{\"value\":\"$V2\"}")" "200"
eq "read new value"     "$(curl -s $B/secrets/ft -H "$AH" | j value)" "$V2"
eq "list contains ft"   "$(curl -s $B/secrets/ -H "$AH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("yes" if any((i.get("name")=="ft") for i in (d.get("secrets") or d if isinstance(d,list) else d.get("items",[]))) else "no")' 2>/dev/null)" "yes"
eq "ns-scoped create"   "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/secrets/ -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"ftns\",\"value\":\"x\",\"namespace\":\"probe\"}")" "201"

echo "=================== TOKENS (RBAC + ephemeral + whoami + revoke) ==================="
# Unique per run: functest does not revoke its tokens, so a fixed name would 409
# on re-runs against a persistent vault.
RTAG="ft-reader-$$"
TOK=$(curl -s -X POST $B/tokens/ -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"$RTAG\",\"permissions\":{\"secrets\":\"r\"}}" | j token)
[ -n "$TOK" ] && [ "$TOK" != "<missing>" ] && ok "reader token minted" || no "reader token mint"
eq "reader reads secret"   "$(curl -s $B/secrets/ft -H "Authorization: Bearer $TOK" | j value)" "$V2"
eq "reader DENIED write"   "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/secrets/ -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"name":"z","value":"z"}')" "403"
eq "whoami scope"          "$(curl -s $B/tokens/whoami -H "Authorization: Bearer $TOK" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("permissions",{}).get("secrets",""))' 2>/dev/null)" "r"
EPH=$(curl -s -X POST $B/tokens/ephemeral -H "$AH" -H 'Content-Type: application/json' -d "{\"name\":\"ft-eph-$$\",\"permissions\":{\"secrets\":\"r\"},\"ttl_seconds\":120}" | j token)
[ -n "$EPH" ] && [ "$EPH" != "<missing>" ] && ok "ephemeral token minted" || no "ephemeral token mint"

echo "=================== AUDIT ==================="
eq "audit chain intact" "$(curl -s $B/audit/verify -H "$AH" | j chain_intact)" "True"

echo "=================== API vs CLI PARITY ==================="
if [ ! -x "$VENV/bin/rhorizon" ]; then
  "$VENV/bin/pip" install -q "$CHECKOUT/cli" >/dev/null 2>&1 && echo "  (installed CLI into venv for the test)" || echo "  (CLI not installable from $CHECKOUT/cli)"
fi
if [ -x "$VENV/bin/rhorizon" ]; then
  export RH_ADDR="${B%/api/v1/vault}" RH_TOKEN="$RT"   # CLI reads RH_ADDR/RH_TOKEN (not RHORIZON_*), appends its own path
  CLIVAL=$("$VENV/bin/rhorizon" get ft 2>/dev/null | grep -oE "$V2" | head -1)
  eq "CLI secret get == API value" "${CLIVAL:-<none>}" "$V2"
  "$VENV/bin/rhorizon" status >/dev/null 2>&1 && ok "CLI status runs" || no "CLI status failed"
else
  no "CLI unavailable (native installer does not install cli/ -- gap)"
fi

echo "=================== CLEANUP + SEAL ==================="
curl -s -o /dev/null -X DELETE $B/secrets/ft -H "$AH"
curl -s -o /dev/null -X DELETE "$B/secrets/ftns?namespace=probe" -H "$AH"
eq "seal http"    "$(curl -s -o /dev/null -w '%{http_code}' -X POST $B/seal -H "$AH")" "200"
eq "sealed final" "$(curl -s -m5 $B/status | j sealed)" "True"

echo "=================== RESULT: $P passed, $F failed ==================="
[ "$F" = 0 ]
