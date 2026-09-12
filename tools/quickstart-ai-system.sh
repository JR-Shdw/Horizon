#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Linux onboarding with recovery authority separated from the AI account.
# Run only from reviewed, root-owned source.

set -euo pipefail
set +x

say() { printf '\n  %s\n' "$*"; }
ok() { printf '  ok  %s\n' "$*"; }
die() { printf '\n  stop  %s\n\n' "$*" >&2; exit 1; }

TARGET_USER="${RH_TARGET_USER:-${SUDO_USER:-}}"
WORKERS="${RH_WORKERS:-1}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --user) [ "$#" -ge 2 ] || die "--user needs an account name"; TARGET_USER=$2; shift ;;
        --workers) [ "$#" -ge 2 ] || die "--workers needs a number"; WORKERS=$2; shift ;;
        -h|--help)
            sed -n '2,34p' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

[ "$(id -u)" -eq 0 ] || die "Run this script as root after reviewing it: sudo tools/quickstart-ai-system.sh --user YOUR_ACCOUNT"
[ "$(uname -s)" = Linux ] || die "The identity-separated AI install is currently validated on Linux only."
[ -n "$TARGET_USER" ] || die "Name the non-root account used by the AI tool with --user ACCOUNT."
[ "$TARGET_USER" != rhorizon ] || die "The AI tool cannot share the rhorizon service account."
command -v getent >/dev/null 2>&1 || die "getent is required to resolve the target account."
command -v runuser >/dev/null 2>&1 || die "runuser is required to cross the operator/agent identity boundary."
TARGET_PASSWD=$(getent passwd "$TARGET_USER") || die "Account '$TARGET_USER' does not exist."
TARGET_UID=$(printf '%s\n' "$TARGET_PASSWD" | cut -d: -f3)
TARGET_HOME=$(printf '%s\n' "$TARGET_PASSWD" | cut -d: -f6)
[ "$TARGET_UID" -ne 0 ] || die "The AI tool must not run as root."
[ -d "$TARGET_HOME" ] || die "Home directory for '$TARGET_USER' does not exist: $TARGET_HOME"
case "$WORKERS" in ''|*[!0-9]*) die "--workers must be a positive integer" ;; esac
[ "$WORKERS" -ge 1 ] || die "--workers must be at least 1"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
[ -f "$REPO_ROOT/tools/install-native.sh" ] || die "install-native.sh is missing from $REPO_ROOT"

# A sudo command authorises the code on disk. If the agent account can replace
# the checkout, it can replace what root will execute between review and use.
_path=$REPO_ROOT
while [ "$_path" != / ]; do
    if runuser -u "$TARGET_USER" -- test -w "$_path"; then
        die "'$TARGET_USER' can modify $_path. Copy the reviewed release to a root-owned tree such as /usr/local/src/rhorizon before running this script."
    fi
    _path=$(dirname -- "$_path")
done
unset _path
SOURCE_LINK=$(find "$REPO_ROOT" -path "$REPO_ROOT/.git" -prune -o -type l -print -quit)
[ -z "$SOURCE_LINK" ] || die "The privileged source tree contains a symbolic link ($SOURCE_LINK). Use a clean release checkout."
unset SOURCE_LINK

if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
    die "'$TARGET_USER' is in the docker group, which is normally root-equivalent. Remove that membership before claiming an OS boundary."
fi
if [ -S /var/run/docker.sock ] && runuser -u "$TARGET_USER" -- test -w /var/run/docker.sock; then
    die "'$TARGET_USER' can write the Docker socket, which is normally root-equivalent."
fi
if command -v sudo >/dev/null 2>&1; then
    # Clear cached credentials so this probe detects NOPASSWD policy.
    runuser -u "$TARGET_USER" -- sudo -K >/dev/null 2>&1 || true
    if runuser -u "$TARGET_USER" -- sudo -n true >/dev/null 2>&1; then
        die "'$TARGET_USER' has passwordless sudo authority, so it is not isolated from root-owned recovery material."
    fi
fi
if command -v doas >/dev/null 2>&1 && runuser -u "$TARGET_USER" -- doas -n true >/dev/null 2>&1; then
    die "'$TARGET_USER' has passwordless doas authority, so it is not isolated from root-owned recovery material."
fi

CONFIG_DIR=/etc/rhorizon
SECRET_DIR=$CONFIG_DIR/secrets
ROOT_TOKEN_FILE=$SECRET_DIR/root-token
CA_SOURCE=$CONFIG_DIR/certs/cert.pem
BASE_URL="https://127.0.0.1:8200"
TARGET_CONFIG=$TARGET_HOME/.config/rhorizon
TARGET_MCP_DIR=$TARGET_HOME/.config/rhorizon-mcp
TARGET_DATA=$TARGET_HOME/.local/share/rhorizon-mcp
TARGET_TOKEN=$TARGET_CONFIG/mcp.token
TARGET_CA=$TARGET_CONFIG/ca.pem
TARGET_POLICY=$TARGET_MCP_DIR/policy.toml
TARGET_VENV=$TARGET_DATA/.venv
MCP_TOKEN_NAME=${RH_MCP_TOKEN_NAME:-mcp-agent}
MCP_NAMESPACE=${RH_MCP_NAMESPACE:-mcp}
MCP_GROUP_NAME=${RH_MCP_GROUP:-mcp-agents}
for _label in "$MCP_TOKEN_NAME" "$MCP_NAMESPACE" "$MCP_GROUP_NAME"; do
    case "$_label" in
        ''|*[!A-Za-z0-9._-]*) die "MCP names may contain only letters, digits, dot, underscore and hyphen." ;;
    esac
done
unset _label

PW_INPUT=
cleanup() {
    [ -z "${AUTH_CONFIG:-}" ] || rm -f -- "$AUTH_CONFIG"
    [ -z "${MCP_AUTH_CONFIG:-}" ] || rm -f -- "$MCP_AUTH_CONFIG"
    [ -z "${PW_INPUT:-}" ] || rm -f -- "$PW_INPUT"
    if command -v sudo >/dev/null 2>&1; then
        runuser -u "$TARGET_USER" -- sudo -K >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

say "Installing Horizon under the dedicated rhorizon service account"
if [ ! -s "$SECRET_DIR/master-password" ]; then
    [ -r /dev/tty ] || die "A terminal is required to enter the new master password without using argv, environment or chat."
    PW_INPUT=$(mktemp /tmp/rhorizon-master.XXXXXX)
    chmod 0600 "$PW_INPUT"
    IFS= read -r -s -p "  New master password (not shown): " MASTER_ONE </dev/tty
    printf '\n' >/dev/tty
    IFS= read -r -s -p "  Repeat master password: " MASTER_TWO </dev/tty
    printf '\n' >/dev/tty
    [ -n "$MASTER_ONE" ] || die "The master password cannot be empty."
    [ "$MASTER_ONE" = "$MASTER_TWO" ] || die "The two master passwords differ."
    printf '%s' "$MASTER_ONE" >"$PW_INPUT"
    unset MASTER_ONE MASTER_TWO
    sh "$REPO_ROOT/tools/install-native.sh" --mode system --workers "$WORKERS" --master-password-file "$PW_INPUT"
    rm -f -- "$PW_INPUT"
    PW_INPUT=
else
    sh "$REPO_ROOT/tools/install-native.sh" --mode system --workers "$WORKERS"
fi

[ -s "$ROOT_TOKEN_FILE" ] || die "The root-only admin token is missing at $ROOT_TOKEN_FILE; finish the first unseal as the operator, then rerun."
[ -s "$CA_SOURCE" ] || die "The TLS certificate is missing at $CA_SOURCE."
curl -fsS --max-time 10 --cacert "$CA_SOURCE" "$BASE_URL/health" >/dev/null \
    || die "Horizon is not reachable at $BASE_URL after installation."

# Keep the bearer token out of argv with a root-only curl config.
AUTH_CONFIG=$(mktemp /tmp/rhorizon-curl.XXXXXX)
chmod 0600 "$AUTH_CONFIG"
python3 - "$ROOT_TOKEN_FILE" "$AUTH_CONFIG" <<'PY'
import pathlib
import sys

token = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if not token or "\n" in token or "\r" in token or '"' in token:
    raise SystemExit("invalid root token file")
pathlib.Path(sys.argv[2]).write_text(
    f'header = "Authorization: Bearer {token}"\n', encoding="utf-8"
)
PY

RH_CODE=
RH_BODY=
rh_api() { # METHOD PATH [JSON]
    local method=$1 path=$2 body=${3:-} response
    if [ -n "$body" ]; then
        response=$(curl -sS --max-time 20 --cacert "$CA_SOURCE" --config "$AUTH_CONFIG" \
            -X "$method" -H 'Content-Type: application/json' -d "$body" \
            -o - -w '\n%{http_code}' "$BASE_URL$path" 2>&1) || die "API request failed: $method $path"
    else
        response=$(curl -sS --max-time 20 --cacert "$CA_SOURCE" --config "$AUTH_CONFIG" \
            -X "$method" -o - -w '\n%{http_code}' "$BASE_URL$path" 2>&1) || die "API request failed: $method $path"
    fi
    RH_CODE=${response##*$'\n'}
    RH_BODY=${response%$'\n'*}
}

json_field() {
    python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]) or "")' "$1"
}
json_named_id() {
    python3 -c 'import json,sys
rows=json.load(sys.stdin).get("items", [])
print(next((str(row["id"]) for row in rows if row.get("name") == sys.argv[1] and (not sys.argv[2] or row.get("active") is True)), ""))' "$1" "${2:-}"
}

say "Creating the vault-enforced MCP grant"
rh_api POST /api/v1/vault/groups/ "{\"name\":\"$MCP_GROUP_NAME\",\"permissions\":{\"secrets\":\"r\"}}"
case "$RH_CODE" in
    201)
        MCP_GROUP_ID=$(printf '%s' "$RH_BODY" | json_field id)
        GROUP_NEEDS_UPDATE=0
        ;;
    409)
        rh_api GET /api/v1/vault/groups/
        [ "$RH_CODE" = 200 ] || die "Cannot list access groups."
        MCP_GROUP_ID=$(printf '%s' "$RH_BODY" | json_named_id "$MCP_GROUP_NAME")
        if printf '%s' "$RH_BODY" | python3 -c 'import json,sys
name=sys.argv[1]
row=next((r for r in json.load(sys.stdin).get("items", []) if r.get("name") == name), None)
raise SystemExit(0 if row and row.get("permissions") == {"secrets": "r"} else 1)' "$MCP_GROUP_NAME"; then
            GROUP_NEEDS_UPDATE=0
        else
            GROUP_NEEDS_UPDATE=1
        fi
        ;;
    *) die "Cannot create access group (HTTP $RH_CODE)." ;;
esac
[ -n "$MCP_GROUP_ID" ] || die "Cannot resolve access group '$MCP_GROUP_NAME'."
if [ "$GROUP_NEEDS_UPDATE" = 1 ]; then
    rh_api PUT "/api/v1/vault/groups/$MCP_GROUP_ID" '{"permissions":{"secrets":"r"}}'
    [ "$RH_CODE" = 200 ] || die "Cannot constrain the access group (HTTP $RH_CODE)."
fi
unset GROUP_NEEDS_UPDATE

rh_api GET "/api/v1/vault/namespaces/$MCP_NAMESPACE"
case "$RH_CODE" in
    200)
        if ! printf '%s' "$RH_BODY" | python3 -c 'import json,sys
row=json.load(sys.stdin)
raise SystemExit(0 if str(row.get("owner_group_id")) == sys.argv[1] and row.get("enforce_membership") is True else 1)' "$MCP_GROUP_ID"; then
            rh_api PUT "/api/v1/vault/namespaces/$MCP_NAMESPACE" "{\"owner_group_id\":\"$MCP_GROUP_ID\",\"enforce_membership\":true}"
            [ "$RH_CODE" = 200 ] || die "The existing namespace could not be governed (HTTP $RH_CODE)."
        fi
        ;;
    404)
        rh_api POST /api/v1/vault/namespaces/ "{\"name\":\"$MCP_NAMESPACE\",\"owner_group_id\":\"$MCP_GROUP_ID\",\"enforce_membership\":true}"
        [ "$RH_CODE" = 201 ] || die "Cannot create the governed namespace (HTTP $RH_CODE)."
        ;;
    *) die "Cannot inspect the governed namespace (HTTP $RH_CODE)." ;;
esac

rh_api GET /api/v1/vault/tokens/
[ "$RH_CODE" = 200 ] || die "Cannot inspect existing tokens (HTTP $RH_CODE)."
TOKEN_LIST_BODY=$RH_BODY
MCP_TOKEN_ID=$(printf '%s' "$TOKEN_LIST_BODY" | json_named_id "$MCP_TOKEN_NAME" active)
if [ -n "$MCP_TOKEN_ID" ]; then
    if printf '%s' "$TOKEN_LIST_BODY" | python3 -c 'import json,sys
name, namespace = sys.argv[1:]
expected = {"secrets": "r", "namespaces": [namespace]}
row = next((r for r in json.load(sys.stdin).get("items", []) if r.get("name") == name and r.get("active") is True), None)
raise SystemExit(0 if row and row.get("permissions") == expected else 1)' "$MCP_TOKEN_NAME" "$MCP_NAMESPACE"; then
        rh_api POST "/api/v1/vault/tokens/$MCP_TOKEN_ID/rotate"
        [ "$RH_CODE" = 200 ] || die "Cannot rotate the existing MCP token (HTTP $RH_CODE)."
        MCP_TOKEN=$(printf '%s' "$RH_BODY" | json_field token)
    else
        # Revoke mismatched scope before handing a token to the agent.
        rh_api POST "/api/v1/vault/tokens/$MCP_TOKEN_ID/revoke"
        [ "$RH_CODE" = 200 ] || die "Cannot revoke the incorrectly scoped MCP token (HTTP $RH_CODE)."
        MCP_TOKEN_ID=
    fi
fi
unset TOKEN_LIST_BODY
if [ -z "$MCP_TOKEN_ID" ]; then
    rh_api POST /api/v1/vault/tokens/ "{\"name\":\"$MCP_TOKEN_NAME\",\"permissions\":{\"secrets\":\"r\",\"namespaces\":[\"$MCP_NAMESPACE\"]}}"
    [ "$RH_CODE" = 201 ] || die "Cannot create the scoped MCP token (HTTP $RH_CODE)."
    MCP_TOKEN=$(printf '%s' "$RH_BODY" | json_field token)
    MCP_TOKEN_ID=$(printf '%s' "$RH_BODY" | json_field id)
fi
[ -n "$MCP_TOKEN" ] && [ -n "$MCP_TOKEN_ID" ] || die "The vault did not return the scoped token and its id."

rh_api POST "/api/v1/vault/groups/$MCP_GROUP_ID/members" \
    "{\"principal_type\":\"token\",\"principal_id\":\"$MCP_TOKEN_ID\"}"
[ "$RH_CODE" = 201 ] || die "Cannot bind the scoped token to the governed namespace (HTTP $RH_CODE)."

# Verify strict namespace membership before persisting the token.
MCP_AUTH_CONFIG=$(mktemp /tmp/rhorizon-mcp-curl.XXXXXX)
chmod 0600 "$MCP_AUTH_CONFIG"
printf 'header = "Authorization: Bearer %s"\n' "$MCP_TOKEN" >"$MCP_AUTH_CONFIG"
MCP_GRANT_CODE=$(curl -sS --max-time 20 --cacert "$CA_SOURCE" --config "$MCP_AUTH_CONFIG" \
    -o /dev/null -w '%{http_code}' "$BASE_URL/api/v1/vault/secrets/?namespace=$MCP_NAMESPACE") \
    || die "Cannot verify the scoped MCP grant."
[ "$MCP_GRANT_CODE" = 200 ] || die "The scoped MCP grant is not effective (HTTP $MCP_GRANT_CODE)."
rm -f -- "$MCP_AUTH_CONFIG"
MCP_AUTH_CONFIG=

# Write user files as the target account; root does not follow user-owned paths.
printf '%s' "$MCP_TOKEN" | runuser -u "$TARGET_USER" -- sh -c '
    set -eu; umask 077
    mkdir -p "$1"
    test ! -L "$2"
    cat >"$2"
    chmod 0400 "$2"
' sh "$TARGET_CONFIG" "$TARGET_TOKEN"
unset MCP_TOKEN RH_BODY

runuser -u "$TARGET_USER" -- sh -c '
    set -eu; umask 077
    mkdir -p "$1"
    test ! -L "$2"
    cat >"$2"
    chmod 0444 "$2"
' sh "$TARGET_CONFIG" "$TARGET_CA" <"$CA_SOURCE"

runuser -u "$TARGET_USER" -- mkdir -p "$TARGET_DATA"
runuser -u "$TARGET_USER" -- python3 -m venv "$TARGET_VENV"
runuser -u "$TARGET_USER" -- "$TARGET_VENV/bin/pip" install -q "$REPO_ROOT/mcp"

if [ ! -e "$TARGET_POLICY" ]; then
    runuser -u "$TARGET_USER" -- sh -c '
        set -eu; umask 077
        mkdir -p "$1"
        test ! -L "$2"
        cat >"$2"
        chmod 0600 "$2"
    ' sh "$TARGET_MCP_DIR" "$TARGET_POLICY" <<'POLICY'
# This local policy narrows what the assistant sees. The vault-side group and
# namespace membership remain the security boundary if this file is changed.
[secrets]
whitelist = []

[namespaces]
allow = []

[tools]
allow = [
    "vault_status",
    "vault_whoami",
    "vault_list_namespaces",
    "vault_list_secrets",
    "vault_get_secret",
    "vault_audit_tail",
]
POLICY
fi

ok "Service runs as rhorizon; recovery material remains root-only."
ok "'$TARGET_USER' received only the scoped MCP token in $TARGET_TOKEN."
cat <<EOF

Add this MCP server to the AI client's configuration:

{
  "mcpServers": {
    "rhorizon": {
      "command": "$TARGET_VENV/bin/rhorizon-mcp-server",
      "env": {
        "RH_VAULT_URL": "$BASE_URL",
        "RH_VAULT_CAFILE": "$TARGET_CA",
        "RH_TOKEN_FILE": "$TARGET_TOKEN",
        "RHORIZON_MCP_POLICY": "$TARGET_POLICY"
      }
    }
  }
}

The administrator token stays at $ROOT_TOKEN_FILE and requires root to read.
The master password stays at $SECRET_DIR/master-password and requires root.
EOF
