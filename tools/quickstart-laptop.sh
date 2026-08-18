#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon laptop quickstart - from zero to "my AI assistant reads my
# secrets" in one command.
#
# Audience : non-technical users (lawyers, consultants, anyone who
# wants their AI assistant - Claude, Cursor, Cline, Codex, a local
# model - to access their secrets without learning vault concepts).
# No jargon in messages. One question max (master password).
# Idempotent : safe to re-run.
#
# Usage :
#
#   bash tools/quickstart-laptop.sh
#
# What it does :
#
#   1. Calls tools/install.sh - installs the vault stack + emits a
#      master password + root token (saved to ~/rhorizon/secrets/).
#   2. Sets up the MCP server (Python venv + rhorizon-mcp).
#   3. Mints a dedicated MCP token (scope secrets:r) using the root
#      token. Saves to ~/.config/rhorizon/mcp.token (mode 0400).
#   4. Writes a starter ~/.config/rhorizon-mcp/policy.toml.
#   5. Prints the JSON snippet to paste into your AI assistant's MCP
#      config (Claude Desktop, Cursor, Cline, Codex, ...).
#
# Requires : docker (or podman with docker shim), python3, openssl,
# curl. Same prereqs as install.sh.

set -euo pipefail

# ---------------------------------------------------------------------------
# Pretty output - keep messages short, calm, copy-paste-friendly.
# ---------------------------------------------------------------------------

say() { printf "\n\033[1;36m  %s\033[0m\n" "$*"; }
ok()  { printf "\033[1;32m  ok\033[0m  %s\n" "$*"; }
warn(){ printf "\033[1;33m  !!\033[0m  %s\n" "$*" >&2; }
die() { printf "\n\033[1;31m  stop\033[0m  %s\n\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Locate the script + repo. We support two entry points :
#
#   (a) `bash tools/quickstart-laptop.sh` from a checkout
#       BASH_SOURCE points at the script ; REPO_ROOT is the parent dir.
#
#   (b) `curl -fsSL .../tools/quickstart-laptop.sh | bash`
#       BASH_SOURCE is empty / not a file. We rely on install.sh to
#       clone the repo to $WORK_DIR/source ; afterwards REPO_ROOT
#       points there for the MCP setup.
#
# install.sh ALREADY supports both modes (clone if not in checkout),
# so the curl-pipe entry point of this script just delegates and
# then re-points REPO_ROOT at the cloned source.
# ---------------------------------------------------------------------------

_RAW="${BASH_SOURCE[0]:-$0}"
if [ -n "$_RAW" ] && [ -f "$_RAW" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$_RAW")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    SCRIPT_DIR=""
    REPO_ROOT=""
fi

# RH_* is the canonical env prefix product-wide; promote any RH_<X> over its
# deprecated RHORIZON_<X> alias so the reads below honor the canonical name.
for _rn in DIR CONFIG_DIR STATE_DIR RUNTIME_DIR AUDIT_DIR API_PORT FRONTEND_PORT \
        FRONTEND_HTTP_PORT BIND API_BIND TIER PERSIST WORKERS MASTER_PASSWORD \
        MCP_VENV MCP_TOKEN_FILE MCP_POLICY MCP_TOKEN_NAME REPO_BASE REPO_RAW REPO_GIT; do
    eval "_rv=\${RH_${_rn}:-}"
    if [ -n "${_rv}" ]; then eval "RHORIZON_${_rn}=\${_rv}"; fi
done
unset _rn _rv
WORK_DIR="${RHORIZON_DIR:-$HOME/rhorizon}"
API_PORT="${RHORIZON_API_PORT:-8200}"
BIND_ADDR="${RHORIZON_BIND:-127.0.0.1}"

MCP_VENV="${RHORIZON_MCP_VENV:-$HOME/.local/share/rhorizon-mcp/.venv}"
MCP_TOKEN_FILE="${RHORIZON_MCP_TOKEN_FILE:-$HOME/.config/rhorizon/mcp.token}"
MCP_POLICY_FILE="${RHORIZON_MCP_POLICY:-$HOME/.config/rhorizon-mcp/policy.toml}"
MCP_TOKEN_NAME="${RHORIZON_MCP_TOKEN_NAME:-mcp-agent}"

# Repo URL derivation - same pattern as install.sh. RHORIZON_REPO_BASE is
# the single override ; RAW URL auto-derives based on the host (gitea vs
# github.com use different raw-file URL shapes).
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

cat <<'BANNER'

  Resurgamus Horizon - laptop quickstart
  ----------------------------------------------------------------
  This will set up your personal vault and connect it to your AI
  assistant (Claude Desktop, Cursor, Cline, Codex, or any MCP
  client). Takes ~5 minutes the first run, mostly Docker building
  images. Re-runnable.

BANNER

# ---------------------------------------------------------------------------
# Route: no container runtime -> hand off to the native installer
# ---------------------------------------------------------------------------
# docker present -> docker ; podman present -> podman (install.sh picks the
# matching compose variant) ; neither -> native (no containers).
if ! command -v docker >/dev/null 2>&1 && ! command -v podman >/dev/null 2>&1; then
    say "No docker or podman found - switching to the native install (no containers)."
    if [ -n "$REPO_ROOT" ] && [ -x "$REPO_ROOT/tools/quickstart-laptop-native.sh" ]; then
        exec bash "$REPO_ROOT/tools/quickstart-laptop-native.sh" "$@"
    fi
    command -v curl >/dev/null 2>&1 || die "no container runtime and no curl. Install docker/podman or curl, then retry."
    NATIVE_TMP="$(mktemp -t rhorizon-native.XXXXXX.sh)"
    curl -fsSL "$REPO_RAW/tools/quickstart-laptop-native.sh" -o "$NATIVE_TMP" \
        || die "Could not download the native installer from $REPO_RAW."
    exec bash "$NATIVE_TMP" "$@"
fi

# ---------------------------------------------------------------------------
# Step 1 - bring up the vault
# ---------------------------------------------------------------------------

say "Step 1/4   Installing the vault stack"

if [ -n "$REPO_ROOT" ] && [ -x "$REPO_ROOT/tools/install.sh" ]; then
    # Run from a local checkout - hand install.sh the local copy.
    bash "$REPO_ROOT/tools/install.sh"
else
    # curl | bash entry point - fetch install.sh on the fly. install.sh
    # itself will git-clone the repo into $WORK_DIR/source on first run.
    command -v curl >/dev/null 2>&1 || die "curl not found. Install curl, or 'git clone' the repo manually and run 'bash tools/quickstart-laptop.sh' from inside it."
    INSTALL_TMP="$(mktemp -t rhorizon-install.XXXXXX.sh)"
    trap 'rm -f "$INSTALL_TMP"' EXIT
    curl -fsSL "$REPO_RAW/tools/install.sh" -o "$INSTALL_TMP" || die "Could not download install.sh from $REPO_RAW. Check your network / VPN."
    bash "$INSTALL_TMP"
    # install.sh has now cloned the source to $WORK_DIR/source. Point
    # REPO_ROOT there so the MCP setup below can pip-install from it.
    REPO_ROOT="$WORK_DIR/source"
    [ -d "$REPO_ROOT/mcp" ] || die "Expected $REPO_ROOT/mcp after install.sh ; cannot continue with MCP setup."
fi

ROOT_TOKEN_FILE="$WORK_DIR/secrets/root-token"
[ -f "$ROOT_TOKEN_FILE" ] || die "install.sh did not produce $ROOT_TOKEN_FILE. Re-run install.sh manually and check its output."

ROOT_TOKEN="$(cat "$ROOT_TOKEN_FILE")"

# ---------------------------------------------------------------------------
# Step 2 - install the MCP server (Python venv)
# ---------------------------------------------------------------------------

say "Step 2/4   Installing the MCP server (Python)"

command -v python3 >/dev/null 2>&1 || die "python3 not found in PATH. Install Python 3.12+ then re-run this script."

PYV="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PYV_MAJOR="${PYV%.*}"
PYV_MINOR="${PYV#*.}"
if [ "$PYV_MAJOR" -lt 3 ] || { [ "$PYV_MAJOR" -eq 3 ] && [ "$PYV_MINOR" -lt 12 ]; }; then
    die "Python 3.12+ required (found $PYV). Install a newer Python and re-run."
fi

if [ ! -d "$MCP_VENV" ]; then
    mkdir -p "$(dirname "$MCP_VENV")"
    python3 -m venv "$MCP_VENV"
fi

# shellcheck disable=SC1091
. "$MCP_VENV/bin/activate"

if ! "$MCP_VENV/bin/rhorizon-mcp-server" --help >/dev/null 2>&1; then
    pip install -q --upgrade pip >/dev/null
    pip install -q -e "$REPO_ROOT/mcp" >/dev/null
fi

ok "MCP server : $MCP_VENV/bin/rhorizon-mcp-server"

# ---------------------------------------------------------------------------
# Step 3 - mint a dedicated MCP token
# ---------------------------------------------------------------------------

say "Step 3/4   Creating a dedicated access key for your AI assistant"

mkdir -p "$(dirname "$MCP_TOKEN_FILE")"
chmod 0700 "$(dirname "$MCP_TOKEN_FILE")"

if [ -f "$MCP_TOKEN_FILE" ]; then
    ok "Access key already exists at $MCP_TOKEN_FILE - reusing"
else
    # Mint via API. We ask the vault for a token scoped to read-only
    # secrets in the 'mcp' namespace. Anything outside is unreachable
    # by the assistant even if the policy is later widened by mistake.
    MINT_RESP=$(curl -fsS -X POST "http://$BIND_ADDR:$API_PORT/api/v1/vault/tokens/" \
        -H "Authorization: Bearer $ROOT_TOKEN" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"$MCP_TOKEN_NAME\",\"permissions\":{\"secrets\":\"r\",\"namespaces\":[\"mcp\"]}}" \
        2>&1) || die "Could not create MCP token. Vault response : $MINT_RESP"

    MCP_TOKEN=$(printf '%s' "$MINT_RESP" | python3 -c '
import sys, json
data = json.load(sys.stdin)
tok = data.get("token") or ""
print(tok)
')
    [ -n "$MCP_TOKEN" ] || die "Vault did not return a token. Response : $MINT_RESP"

    umask 077 && printf '%s' "$MCP_TOKEN" > "$MCP_TOKEN_FILE"
    chmod 0400 "$MCP_TOKEN_FILE"
    ok "Access key saved to $MCP_TOKEN_FILE (mode 0400)"
fi

# ---------------------------------------------------------------------------
# Step 4 - write a starter policy
# ---------------------------------------------------------------------------

say "Step 4/4   Writing a starter policy (what your AI assistant is allowed to read)"

mkdir -p "$(dirname "$MCP_POLICY_FILE")"
chmod 0700 "$(dirname "$MCP_POLICY_FILE")"

if [ -f "$MCP_POLICY_FILE" ]; then
    ok "Policy already exists at $MCP_POLICY_FILE - leaving it alone"
else
    cat > "$MCP_POLICY_FILE" <<'POLICY'
# rhorizon-mcp policy - what your AI assistant is allowed to read.
#
# This file is your firewall. Empty whitelist = nothing readable
# (safe default). Add a secret name below the day you want your AI
# assistant to be able to read it. Edit this file by hand, or ask
# your AI assistant to rewrite it for you using one of the prompts in
# docs/AI-PROMPTS.md.

[secrets]
# Fully-qualified names: "<namespace>/<secret-name>".
# Example (commented out - uncomment when you actually have these
# secrets in the vault) :
#
# whitelist = [
#     "mcp/clients/dupont-database-password",
#     "mcp/clients/dupont-api-key",
# ]
whitelist = []

[namespaces]
# Coarser allow : every secret in a namespace is reachable. Use only
# when you trust everything in that namespace and the namespace is
# narrow. Empty by default.
allow = []

[tools]
# What MCP tools your AI assistant can call. Leaving these on is safe
# - they are read-only and the [secrets] whitelist still applies.
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
    ok "Policy written : $MCP_POLICY_FILE (currently empty whitelist - the assistant can read nothing yet)"
fi

# ---------------------------------------------------------------------------
# Final - print the AI assistant's MCP config snippet
#
# Three flavours :
#   - Linux native + macOS : the desktop app launches the MCP server directly
#     by absolute path. Single venv binary path, single env block.
#   - WSL2 (Linux running under Windows) : a desktop app like Claude Desktop
#     is a WINDOWS app that cannot exec a Linux binary directly. We wrap the
#     call in `wsl.exe -- env VAR=val ... /path/to/rhorizon-mcp-server`. The
#     env vars must be set INSIDE the wsl invocation (the app's `env` block
#     lives in Windows ; WSL processes don't inherit it).
# ---------------------------------------------------------------------------

# WSL detection : /proc/version mentions "microsoft" (case-insensitive) on
# every Microsoft-built kernel (WSL1 and WSL2). The /proc/sys/fs/binfmt_misc
# WSLInterop check is more specific to WSL2 but the broader check is fine
# for our purposes (the wsl.exe wrapper works on both).
IS_WSL=false
if grep -qi 'microsoft\|wsl' /proc/version 2>/dev/null; then
    IS_WSL=true
    # WSL distribution name - needed by the desktop app's wsl.exe call
    # to disambiguate when the user has multiple distros installed.
    WSL_DISTRO="${WSL_DISTRO_NAME:-$(wslpath -w / 2>/dev/null | sed -E 's|^\\\\wsl(\\.localhost)?\\\\([^\\]+).*|\2|')}"
    WSL_DISTRO="${WSL_DISTRO:-Ubuntu}"
fi

cat <<EOF


  ================================================================
  All set. Two things left to do - copy-paste, no typing required.
  ================================================================

  1) OPEN YOUR AI ASSISTANT'S MCP CONFIG FILE

     Each client keeps this file in its own place. Claude Desktop
     paths are shown as the example ; Cursor / Cline / Codex use
     their own config file (see the examples under mcp/ in the repo).

     Claude Desktop -
       Linux        : ~/.config/Claude/claude_desktop_config.json
       macOS        : ~/Library/Application Support/Claude/claude_desktop_config.json
       Windows/WSL  : %APPDATA%\\Claude\\claude_desktop_config.json
                      (open from Windows Explorer ; this file lives on the
                      Windows side, NOT inside WSL)

     If the file does not exist, create it with the content below.
     If it exists, merge the "rhorizon" entry into your existing
     "mcpServers" object (don't lose what's already there).

EOF

if $IS_WSL; then
    cat <<EOF
  2) PASTE THIS BLOCK INTO YOUR AI ASSISTANT'S CONFIG (Claude Desktop: claude_desktop_config.json) :

     (You're on WSL. A desktop app like Claude Desktop runs on
      Windows but the MCP server lives in WSL - the block below uses
      wsl.exe to bridge the two. The env vars are set inside the WSL
      invocation because the app's "env" block stays on the Windows
      side and is not inherited by WSL processes.)

  ----------------------------------------------------------------
{
  "mcpServers": {
    "rhorizon": {
      "command": "wsl.exe",
      "args": [
        "-d", "$WSL_DISTRO",
        "--",
        "env",
        "RH_VAULT_URL=http://$BIND_ADDR:$API_PORT",
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
        "RH_VAULT_URL": "http://$BIND_ADDR:$API_PORT",
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
     "rhorizon" appear in your tools. Ask it :

       "What can you do with rhorizon ?"

     It will list the operations it has access to. The policy
     starts empty - that's intentional. To let it actually read
     a secret, you need to (a) put a secret in the vault, then
     (b) add it to the whitelist in the policy file.

  HOW DO I DO THAT ?

     The easy way is to ask your AI assistant to do it for you.
     Open docs/AI-PROMPTS.md and copy the prompt that matches
     what you want :

       - "Add a new secret for client X"
       - "Let my AI assistant read secret Y for this task"
       - "Revoke my AI assistant's access to Z"
       - "My AI assistant doesn't see rhorizon - debug"

  ALL YOUR FILES :
     Vault data           $WORK_DIR
     Master password      $WORK_DIR/secrets/master-password
     Root token (admin)   $WORK_DIR/secrets/root-token
     Assistant access key $MCP_TOKEN_FILE
     Assistant policy     $MCP_POLICY_FILE
     MCP server binary    $MCP_VENV/bin/rhorizon-mcp-server

EOF

if $IS_WSL; then
    cat <<EOF
  WSL NOTE :
     You ran this script inside WSL distribution "$WSL_DISTRO".
     If you have multiple WSL distros and your AI assistant launches
     into the wrong one, edit "args[1]" in the JSON block above to
     match the right distribution name (run "wsl.exe -l -v" in
     PowerShell to see the list).

EOF
fi
