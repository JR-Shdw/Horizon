#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon laptop quickstart - NATIVE install (no Docker, no containers).
#
# Sister of tools/quickstart-laptop.sh : same end-state ("vault running,
# AI assistant wired in"), but everything runs natively on the host.
# Useful when :
#
#   - You don't want Docker Desktop (Mac/Windows licensing, RAM overhead).
#   - You're on WSL2 and want the lightest possible setup.
#   - You're on a Linux laptop and prefer systemd / native processes.
#
# This is a thin wrapper. The whole install (system deps, PostgreSQL, venv +
# Rust extension, boot service, first unseal) is done by the shared native
# trunk tools/install-native.sh --mode user. It also enables memory-lock
# protection when the host has unencrypted swap (see docs/DEPLOYMENT.md 3.6).
# This script adds only the non-tech layer on top : the MCP server for your
# AI assistant, a scoped access key, and the copy-paste config block.
#
# Scope v1 : Linux + WSL2 (Debian/Ubuntu/Arch/Fedora/Rocky/openSUSE via the
# trunk drivers). macOS native is not supported yet -> use the container path.
#
# Re-runnable. Idempotent at every step.

set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

say() { printf "\n\033[1;36m  %s\033[0m\n" "$*"; }
ok()  { printf "\033[1;32m  ok\033[0m  %s\n" "$*"; }
warn(){ printf "\033[1;33m  !!\033[0m  %s\n" "$*" >&2; }
die() { printf "\n\033[1;31m  stop\033[0m  %s\n\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Defaults (the trunk owns the vault layout; we only need to read its secrets)
# ---------------------------------------------------------------------------

XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"

# RH_* is the canonical env prefix product-wide; promote any RH_<X> over its
# deprecated RHORIZON_<X> alias so the reads below honor the canonical name.
for _rn in DIR CONFIG_DIR STATE_DIR RUNTIME_DIR AUDIT_DIR API_PORT FRONTEND_PORT \
        FRONTEND_HTTP_PORT BIND API_BIND TIER PERSIST WORKERS MASTER_PASSWORD \
        MCP_VENV MCP_TOKEN_FILE MCP_POLICY MCP_TOKEN_NAME TLS_CERT \
        REPO_BASE REPO_RAW REPO_GIT; do
    eval "_rv=\${RH_${_rn}:-}"
    if [ -n "${_rv}" ]; then eval "RHORIZON_${_rn}=\${_rv}"; fi
done
unset _rn _rv
CONFIG_DIR="${RHORIZON_CONFIG_DIR:-$XDG_CONFIG_HOME/rhorizon}"
SECRET_FILE="$CONFIG_DIR/rhorizon.env-secrets"   # written by install-native.sh
APP_DIR="${RHORIZON_DIR:-$XDG_DATA_HOME/rhorizon}"

API_PORT="${RHORIZON_API_PORT:-8200}"
BIND_ADDR="${RHORIZON_BIND:-127.0.0.1}"
# The trunk installer terminates TLS at uvicorn and mints the certificate below,
# so everything downstream -- this script, the CLI, the MCP server -- has to
# trust that one file. There is no plaintext port to fall back to.
CA_FILE="${RHORIZON_TLS_CERT:-$CONFIG_DIR/certs/cert.pem}"
BASE_URL="https://$BIND_ADDR:$API_PORT"
WORKERS="${RHORIZON_WORKERS:-1}"                 # 1 = home preset (laptop)

MCP_VENV="${RHORIZON_MCP_VENV:-$XDG_DATA_HOME/rhorizon-mcp/.venv}"
MCP_TOKEN_FILE="${RHORIZON_MCP_TOKEN_FILE:-$CONFIG_DIR/mcp.token}"
MCP_POLICY_FILE="${RHORIZON_MCP_POLICY:-$XDG_CONFIG_HOME/rhorizon-mcp/policy.toml}"
MCP_TOKEN_NAME="${RHORIZON_MCP_TOKEN_NAME:-mcp-agent}"

REPO_BASE="${RHORIZON_REPO_BASE:-https://github.com/JR-Shdw/Horizon}"
case "$REPO_BASE" in
    *github.com*)
        _gh_path="${REPO_BASE#*github.com/}"
        REPO_RAW="${RHORIZON_REPO_RAW:-https://raw.githubusercontent.com/$_gh_path/main}"
        ;;
    *)
        REPO_RAW="${RHORIZON_REPO_RAW:-$REPO_BASE/raw/branch/main}"
        ;;
esac
REPO_GIT="${RHORIZON_REPO_GIT:-$REPO_BASE.git}"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

cat <<'BANNER'

  Resurgamus Horizon - laptop quickstart (NATIVE install, no Docker)
  ----------------------------------------------------------------
  Same end state as the container path : vault running, your AI
  assistant wired in. Everything runs natively - no Docker, no
  containers. Best for WSL2 and Linux hosts.

BANNER

# ---------------------------------------------------------------------------
# Step 0 - system checks
# ---------------------------------------------------------------------------

say "Step 0/3   Checking your system"

UNAME="$(uname -s)"
case "$UNAME" in
    Linux) ;;
    Darwin) die "macOS native install is not supported yet. Use the container path : 'bash tools/quickstart-laptop.sh'." ;;
    *) die "Unsupported OS '$UNAME'. Native install supports Linux only (incl. WSL2)." ;;
esac

# The trunk installer needs sudo for packages + PostgreSQL. Fail early with a
# clear message rather than 5 minutes in.
command -v sudo >/dev/null 2>&1 || die "sudo not found. The native install needs sudo to install system packages (PostgreSQL, libsodium, Python venv tools). Install sudo, or run as root."

# WSL detection - only used to shape the config snippet at the end.
IS_WSL=false
if grep -qi 'microsoft\|wsl' /proc/version 2>/dev/null; then
    IS_WSL=true
    [ -r /etc/os-release ] && . /etc/os-release
    WSL_DISTRO="${WSL_DISTRO_NAME:-${ID:-Ubuntu}}"
    ok "Detected : Linux under WSL2 (distro : $WSL_DISTRO)"
else
    ok "Detected : Linux"
fi

# ---------------------------------------------------------------------------
# Step 1 - get the source code
# ---------------------------------------------------------------------------

say "Step 1/3   Getting the source code"

_RAW="${BASH_SOURCE[0]:-$0}"
if [ -n "$_RAW" ] && [ -f "$_RAW" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$_RAW")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

if [ -n "${REPO_ROOT:-}" ] && [ -f "$REPO_ROOT/tools/install-native.sh" ]; then
    ok "Using local checkout at $REPO_ROOT"
else
    # curl | bash entry point - clone into the XDG data tree (kept: the user
    # service runs uvicorn from this checkout).
    command -v git >/dev/null 2>&1 || die "git not found. Install git or run from a local clone."
    mkdir -p "$APP_DIR"
    if [ ! -d "$APP_DIR/source/.git" ]; then
        say "Cloning rhorizon source..."
        git clone --depth 1 "$REPO_GIT" "$APP_DIR/source"
    else
        (cd "$APP_DIR/source" && git pull --ff-only)
    fi
    REPO_ROOT="$APP_DIR/source"
    ok "Source at $REPO_ROOT"
fi

[ -x "$REPO_ROOT/tools/install-native.sh" ] || die "$REPO_ROOT/tools/install-native.sh not found or not executable."

# ---------------------------------------------------------------------------
# Step 2 - install the vault via the shared native trunk
#
# install-native.sh --mode user does everything: system deps (per-OS driver),
# venv + Rust extension, PostgreSQL role/db + schema, an XDG env file, a
# systemd --user unit (nohup fallback on WSL2 without systemd), the memlock
# drop-in when swap is unencrypted, then waits for /health and performs the
# first /unseal. It saves the master password + admin root token to
# $CONFIG_DIR/rhorizon.env-secrets (mode 600).
# ---------------------------------------------------------------------------

say "Step 2/3   Installing the vault (sudo password may be asked)"

INSTALL_ARGS="--mode user --workers $WORKERS"
[ -n "${RHORIZON_MASTER_PASSWORD:-}" ] && INSTALL_ARGS="$INSTALL_ARGS --master-password $RHORIZON_MASTER_PASSWORD"
# shellcheck disable=SC2086
sh "$REPO_ROOT/tools/install-native.sh" $INSTALL_ARGS

[ -f "$SECRET_FILE" ] || die "Expected $SECRET_FILE after the installer. Check its output above."
ROOT_TOKEN="$(sed -n 's/^ROOT_TOKEN=//p' "$SECRET_FILE" 2>/dev/null || true)"
[ -n "$ROOT_TOKEN" ] || die "No admin token in $SECRET_FILE. The vault may be unsealed from a previous install with a token that was not saved; mint one with 'rhorizon tokens create' and re-run."

# Sanity: the trunk already unsealed and health-checked, but confirm reachable
# before we mint the MCP key.
[ -f "$CA_FILE" ] || die "No TLS certificate at $CA_FILE after the installer. Check its output above."
curl -fsS -m 5 --cacert "$CA_FILE" "$BASE_URL/health" >/dev/null 2>&1 || die "Vault not reachable at $BASE_URL after install. Check 'systemctl --user status rhorizon'."
ok "Vault up and unsealed at $BASE_URL"

# ---------------------------------------------------------------------------
# Step 3 - MCP server for your AI assistant (the non-tech layer)
# ---------------------------------------------------------------------------

say "Step 3/3   Setting up the MCP server for your AI assistant"

PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PYV_MAJOR="${PYV%.*}"; PYV_MINOR="${PYV#*.}"
if [ "$PYV_MAJOR" -lt 3 ] || { [ "$PYV_MAJOR" -eq 3 ] && [ "$PYV_MINOR" -lt 12 ]; }; then
    die "Python 3.12+ required for the MCP server (found $PYV)."
fi

if [ ! -d "$MCP_VENV" ]; then
    mkdir -p "$(dirname "$MCP_VENV")"
    python3 -m venv "$MCP_VENV"
fi
if ! "$MCP_VENV/bin/rhorizon-mcp-server" --help >/dev/null 2>&1; then
    "$MCP_VENV/bin/pip" install -q --upgrade pip >/dev/null
    "$MCP_VENV/bin/pip" install -q -e "$REPO_ROOT/mcp" >/dev/null
fi
ok "MCP server : $MCP_VENV/bin/rhorizon-mcp-server"

mkdir -p "$(dirname "$MCP_TOKEN_FILE")"
chmod 0700 "$(dirname "$MCP_TOKEN_FILE")"
if [ -f "$MCP_TOKEN_FILE" ]; then
    ok "MCP access key already exists at $MCP_TOKEN_FILE - reusing"
else
    MINT_RESP=$(curl -fsS --cacert "$CA_FILE" -X POST "$BASE_URL/api/v1/vault/tokens/" \
        -H "Authorization: Bearer $ROOT_TOKEN" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"$MCP_TOKEN_NAME\",\"permissions\":{\"secrets\":\"r\",\"namespaces\":[\"mcp\"]}}" \
        2>&1) || die "Could not create MCP token. Vault response : $MINT_RESP"
    MCP_TOKEN=$(printf '%s' "$MINT_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token") or "")')
    [ -n "$MCP_TOKEN" ] || die "Vault did not return a token. Response : $MINT_RESP"
    umask 077 && printf '%s' "$MCP_TOKEN" > "$MCP_TOKEN_FILE"
    chmod 0400 "$MCP_TOKEN_FILE"
    ok "MCP access key : $MCP_TOKEN_FILE"
fi

mkdir -p "$(dirname "$MCP_POLICY_FILE")"
chmod 0700 "$(dirname "$MCP_POLICY_FILE")"
if [ ! -f "$MCP_POLICY_FILE" ]; then
    cat > "$MCP_POLICY_FILE" <<'POLICY'
# rhorizon-mcp policy - what your AI assistant is allowed to read.
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
    chmod 0600 "$MCP_POLICY_FILE"
    ok "Policy : $MCP_POLICY_FILE (whitelist empty - the assistant can read nothing yet)"
fi

# ---------------------------------------------------------------------------
# Final - AI assistant config snippet + summary
# ---------------------------------------------------------------------------

USE_SYSTEMD=false
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
    USE_SYSTEMD=true
fi

cat <<EOF


  ================================================================
  Native install complete. Two things left to do - copy-paste only.
  ================================================================

  1) OPEN YOUR AI ASSISTANT'S MCP CONFIG FILE

     Each client keeps this file in its own place. Claude Desktop
     paths are shown as the example ; Cursor / Cline / Codex use
     their own config file (see the examples under mcp/ in the repo).

     Claude Desktop -
       Linux        : ~/.config/Claude/claude_desktop_config.json
       Windows/WSL  : %APPDATA%\\Claude\\claude_desktop_config.json
                      (open from Windows Explorer ; this file lives on
                      the Windows side, NOT inside WSL)

EOF

if $IS_WSL; then
    cat <<EOF
  2) PASTE THIS BLOCK INTO YOUR AI ASSISTANT'S CONFIG (Claude Desktop: claude_desktop_config.json) :

     (You're on WSL. A desktop app like Claude Desktop runs on
      Windows but the MCP server lives in WSL - the block uses
      wsl.exe to bridge them.)

  ----------------------------------------------------------------
{
  "mcpServers": {
    "rhorizon": {
      "command": "wsl.exe",
      "args": [
        "-d", "$WSL_DISTRO",
        "--",
        "env",
        "RH_VAULT_URL=$BASE_URL",
        "RH_VAULT_CAFILE=$CA_FILE",
        "RH_TOKEN_FILE=$MCP_TOKEN_FILE",
        "RHORIZON_MCP_POLICY=$MCP_POLICY_FILE",
        "$MCP_VENV/bin/rhorizon-mcp-server"
      ]
    }
  }
}
  ----------------------------------------------------------------

EOF
else
    cat <<EOF
  2) PASTE THIS BLOCK INTO YOUR AI ASSISTANT'S CONFIG (Claude Desktop: claude_desktop_config.json) :

  ----------------------------------------------------------------
{
  "mcpServers": {
    "rhorizon": {
      "command": "$MCP_VENV/bin/rhorizon-mcp-server",
      "env": {
        "RH_VAULT_URL": "$BASE_URL",
        "RH_VAULT_CAFILE": "$CA_FILE",
        "RH_TOKEN_FILE": "$MCP_TOKEN_FILE",
        "RHORIZON_MCP_POLICY": "$MCP_POLICY_FILE"
      }
    }
  }
}
  ----------------------------------------------------------------

EOF
fi

cat <<EOF
  3) RESTART YOUR AI ASSISTANT

     Quit the app fully, then open it again. You should see
     "rhorizon" appear in your tools.

  HOW TO ADD A SECRET, OR LET THE ASSISTANT READ ONE :
     Use the prompts in docs/AI-PROMPTS.md - copy-paste, no
     command line typing required.

  ALL YOUR FILES :
     Vault data           PostgreSQL on the host (system-managed)
     App/source           $REPO_ROOT
     Vault secrets        $SECRET_FILE  (master password + admin token, mode 600)
     API env file         $CONFIG_DIR/rhorizon.env
     TLS certificate      $CA_FILE  (export RH_CA_FILE=$CA_FILE for the CLI)
     Assistant access key $MCP_TOKEN_FILE
     Assistant policy     $MCP_POLICY_FILE

  CONTROLLING THE API :
EOF

if $USE_SYSTEMD; then
    cat <<'EOF'
     Status : systemctl --user status rhorizon
     Stop   : systemctl --user stop rhorizon
     Start  : systemctl --user start rhorizon
     Logs   : journalctl --user -u rhorizon -f
EOF
else
    cat <<EOF
     The API runs via nohup (no user systemd on this host). Manage it
     from the installer output, or enable systemd on WSL2 ([boot]
     systemd=true in /etc/wsl.conf, 'wsl --shutdown', re-run) for the
     cleaner path.
EOF
fi

cat <<EOF

  WHY NATIVE OVER CONTAINER ?
     Lighter (no Docker Desktop), faster startup, uses your distro's
     PostgreSQL. Trade-off : updates are 'git pull' + re-run this
     script, instead of 'docker compose pull'.

EOF

if $IS_WSL; then
    cat <<EOF
  WSL NOTE :
     You ran this inside WSL distribution "$WSL_DISTRO". If your AI
     assistant launches the wrong distro, edit "args" in the JSON above
     ('wsl.exe -l -v' in PowerShell to list).

EOF
fi
