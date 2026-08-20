#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon quickstart - single-host bring-up.
#
# Usage :
#
#   curl -fsSL "$RHORIZON_REPO_BASE/raw/branch/main/tools/install.sh" | bash
# (default RHORIZON_REPO_BASE = https://github.com/JR-Shdw/Horizon - see
# below for the centralised variable. Override this env var to point at a
# fork or the public mirror when it lands.)
#
# Or :
#
#   bash tools/install.sh [--tier home|smb|heavy|super-heavy] [--dir DIR] [--api-port PORT]
#                         [--frontend-port PORT] [--bind ADDR]
#                         [--master-password VALUE] [--no-build] [--persist]
#
# --persist : make the stack restart on boot. No-op on Docker (the daemon
#   already does it). On rootless podman it enables linger + writes a
#   systemd --user unit; the stack returns SEALED, so unseal again after a
#   reboot. linger may need `sudo loginctl enable-linger <user>` once.
#
# Tiers (tools/presets/*.env) scale api workers + PG + memory:
#   home  (default) 1 worker,  localhost,      ~600 MB total
#   smb             5 workers, minimum for pro, ~1.6 GB total
#   heavy          10 workers, high concurrency, ~2.7 GB total
# Re-run with a different --tier to switch; data volumes persist across the swap
# (the vault re-seals on restart, so unseal again after switching).
#
# What it does :
#
#   1. Checks a container runtime (docker or podman) + a compose implementation
#   2. Creates a working directory (default ~/rhorizon)
#   3. Generates a strong random POSTGRES_PASSWORD
#   4. Fetches docker-compose.quickstart.yml + schema.sql + repo source
#      (if not run from a repo checkout)
#   5. Builds the API + frontend images (or pulls if RHORIZON_*_IMAGE set)
#   6. Brings up the stack, waits for /health
#   7. Leaves the vault SEALED. You set the master password with the first
#      unseal -- the installer does not invent one.
#   8. ONLY with --master-password (unattended installs): unseals for you and
#      writes master password + root token to ./secrets/ at mode 0400. That
#      pair grants full control, so the summary tells you to move it into a
#      password manager and delete the files.
#   9. Prints a summary with URL + next steps
#
# Idempotent : safe to re-run. Preserves POSTGRES_PASSWORD + bind/ports; the
# --tier knobs are re-applied each run. Localhost-only by default.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config / args
# ---------------------------------------------------------------------------

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
FRONTEND_PORT="${RHORIZON_FRONTEND_PORT:-8443}"
FRONTEND_HTTP_PORT="${RHORIZON_FRONTEND_HTTP_PORT:-8080}"
BIND_ADDR="${RHORIZON_BIND:-127.0.0.1}"
BIND_SET=false
# TIER selects a tools/presets/*.env sizing profile. Empty here means "not
# explicitly chosen": a fresh install defaults to home, a re-run keeps the
# tier already in .env. An explicit env RHORIZON_TIER or --tier pins it.
TIER="${RHORIZON_TIER:-}"
[ -n "$TIER" ] && TIER_SET=true || TIER_SET=false
MASTER_PASSWORD="${RHORIZON_MASTER_PASSWORD:-}"
MASTER_PASSWORD_FILE=""
MASTER_PW_FROM_ARGV=""
DO_BUILD=true
# Opt-in: make the stack come back on boot. No-op on Docker (the daemon already
# does); on rootless podman it enables linger + a systemd --user unit.
DO_PERSIST=false
case "${RHORIZON_PERSIST:-}" in 1|true|yes|on) DO_PERSIST=true ;; esac

# Repo URL - single source of truth.
# RHORIZON_REPO_BASE is the canonical override (overrides everything below).
# When the project moves to its public GitHub home, the default below flips
# in ONE place. The two derived URLs (RAW for fetching individual files,
# GIT for cloning) auto-derive from the base unless explicitly overridden.
REPO_BASE="${RHORIZON_REPO_BASE:-https://github.com/JR-Shdw/Horizon}"
case "$REPO_BASE" in
    *github.com*)
        # github.com/<user>/<repo>  ->  raw.githubusercontent.com/<user>/<repo>/main
        _gh_path="${REPO_BASE#*github.com/}"
        REPO_RAW="${RHORIZON_REPO_RAW:-https://raw.githubusercontent.com/$_gh_path/main}"
        ;;
    *)
        # gitea / forgejo pattern : <base>/raw/branch/main
        REPO_RAW="${RHORIZON_REPO_RAW:-$REPO_BASE/raw/branch/main}"
        ;;
esac
REPO_GIT="${RHORIZON_REPO_GIT:-$REPO_BASE.git}"

while [ $# -gt 0 ]; do
    case "$1" in
        --tier) TIER="$2"; shift 2 ;;
        --dir) WORK_DIR="$2"; shift 2 ;;
        --api-port) API_PORT="$2"; shift 2 ;;
        --frontend-port) FRONTEND_PORT="$2"; shift 2 ;;
        --bind) BIND_ADDR="$2"; BIND_SET=true; shift 2 ;;
        # argv is world-readable in /proc/<pid>/cmdline while this runs, and
        # lands in shell history. Kept for compatibility; it warns below.
        --master-password) MASTER_PASSWORD="$2"; MASTER_PW_FROM_ARGV=1; shift 2 ;;
        --master-password-file) MASTER_PASSWORD_FILE="$2"; shift 2 ;;
        --no-build) DO_BUILD=false; shift ;;
        --persist) DO_PERSIST=true; shift ;;
        -h|--help)
            sed -n '/^# Usage/,/^# Idempotent/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Capture the script's own location BEFORE we `cd` into WORK_DIR. When
# invoked via `curl ... | bash` (no $0 path), BASH_SOURCE is empty and
# this resolves to the curl pipe's CWD - fine because the local-checkout
# branch below will then fall through to the git-clone path.
_RAW_BSH="${BASH_SOURCE[0]:-$0}"
if [ -n "$_RAW_BSH" ] && [ -f "$_RAW_BSH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$_RAW_BSH")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd 2>/dev/null || true)"
else
    SCRIPT_DIR=""
    REPO_ROOT=""
fi

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

say() { printf "\033[1;36m[rhorizon]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[rhorizon]\033[0m %s\n" "$*" >&2; }
die() { printf "\033[1;31m[rhorizon]\033[0m %s\n" "$*" >&2; exit 1; }

# Resolve the master password source. Same contract as install-native.sh so a
# command can move between a Docker host and a native one unchanged.
if [ -n "$MASTER_PASSWORD_FILE" ]; then
    [ -f "$MASTER_PASSWORD_FILE" ] || die "master password file not found: $MASTER_PASSWORD_FILE"
    # Strip a single trailing newline only, so `printf secret >f` and
    # `echo secret >f` agree without truncating a password that genuinely
    # ends in one.
    MASTER_PASSWORD="$(printf '%s' "$(cat "$MASTER_PASSWORD_FILE")")"
    [ -n "$MASTER_PASSWORD" ] || die "master password file is empty: $MASTER_PASSWORD_FILE"
fi
if [ -n "$MASTER_PW_FROM_ARGV" ]; then
    warn "--master-password puts the secret in this process's command line"
    warn "  (readable via ps / /proc) and in your shell history."
    warn "  Prefer --master-password-file FILE, or omit it to keep the vault sealed."
fi

# Classify the host's persistent swap. Memory locking is useful when plaintext
# pages could reach disk; it is unnecessary for absent swap, zram, or storage
# backed by dm-crypt. Detection is advisory and must never block installation.
swap_protection() {
    case "${RH_SWAP_PROTECTION:-${RHORIZON_SWAP_PROTECTION:-}}" in
        protected|unencrypted|unknown)
            printf '%s\n' "${RH_SWAP_PROTECTION:-$RHORIZON_SWAP_PROTECTION}"
            return
            ;;
        "") ;;
        *)
            warn "invalid RH_SWAP_PROTECTION value; using unknown"
            printf '%s\n' unknown
            return
            ;;
    esac
    if [ "$(uname -s 2>/dev/null || true)" != Linux ] || [ ! -r /proc/swaps ]; then
        printf '%s\n' unknown
        return
    fi

    local swap_path swap_type rest source types saw_unknown=false
    while read -r swap_path swap_type rest; do
        case "$swap_path" in Filename|"") continue ;; esac
        case "$swap_path" in /dev/zram*) continue ;; esac

        source="$swap_path"
        if [ "$swap_type" = file ]; then
            if command -v findmnt >/dev/null 2>&1; then
                source=$(findmnt -n -o SOURCE --target "$swap_path" 2>/dev/null || true)
                source=$(printf '%s' "$source" | sed 's/\[.*$//')
            elif command -v df >/dev/null 2>&1; then
                source=$(df -P "$swap_path" 2>/dev/null | awk 'NR == 2 { print $1 }')
            else
                source=""
            fi
        fi

        if [ -z "$source" ] || ! command -v lsblk >/dev/null 2>&1; then
            saw_unknown=true
            continue
        fi
        types=$(lsblk -nso TYPE "$source" 2>/dev/null || true)
        if printf '%s\n' "$types" | grep -qx crypt; then
            continue
        fi
        if [ -n "$types" ]; then
            printf '%s\n' unencrypted
            return
        fi
        saw_unknown=true
    done < /proc/swaps

    if [ "$saw_unknown" = true ]; then
        printf '%s\n' unknown
    else
        printf '%s\n' protected
    fi
}

setup_persistence() {
    # Detect runtime + init via tools/detect-system.sh (fallback: inline checks).
    local OS="" INIT="" DISTRO="" RUNTIME="" ROOTLESS=""
    if [ -r "$SOURCE_DIR/tools/detect-system.sh" ]; then
        eval "$(sh "$SOURCE_DIR/tools/detect-system.sh" 2>/dev/null)"
    fi
    [ -n "$RUNTIME" ] || { command -v podman >/dev/null 2>&1 && RUNTIME=podman || RUNTIME=docker; }
    [ -n "$INIT" ] || { [ -d /run/systemd/system ] && INIT=systemd || INIT=unknown; }

    # Docker (incl Docker Desktop): daemon + restart policy already persist.
    if [ "$RUNTIME" = docker ]; then
        say "persistence: Docker restarts the stack on boot (restart: unless-stopped) - nothing to do"
        return 0
    fi
    # Rootless-podman auto-setup is systemd-only. BSD -> native install (rc.d);
    # macOS/other -> start the engine on login, restart policy does the rest.
    if [ "$INIT" != systemd ]; then
        warn "persistence: --persist auto-setup is systemd-only (init: $INIT)."
        warn "  BSD: use the native install (tools/quickstart-laptop-native.sh, root) -> rc.d."
        warn "  macOS/other: start the container engine on login; restart policy does the rest."
        warn "  Or add manually:  $DC -f $WORK_DIR/docker-compose.yml --env-file $WORK_DIR/.env up -d"
        return 0
    fi
    local u; u="$(id -un)"
    say "persistence (rootless podman + systemd): enabling boot auto-start"
    # 1. Linger: run the user's systemd manager without an active login.
    if loginctl show-user "$u" 2>/dev/null | grep -q 'Linger=yes'; then
        say "  linger already enabled for $u"
    elif loginctl enable-linger "$u" 2>/dev/null; then
        say "  linger enabled for $u"
    else
        warn "  linger needs root. Run once:  sudo loginctl enable-linger $u"
        warn "  then re-run:  bash tools/install.sh --tier $TIER --persist"
        return 0
    fi
    # 2. A user unit that re-converges the stack on boot. It returns SEALED
    #    (sealed-by-default), so unseal again after a reboot.
    local dc_abs
    # Absolute path: a systemd unit has no useful PATH. Handles both the
    # plugin form ("<bin> compose") and a standalone compose binary, for
    # either runtime.
    case "$DC" in
        *" compose") dc_abs="$(command -v "${DC% compose}") compose" ;;
        *)           dc_abs="$(command -v "$DC")" ;;
    esac
    local unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$unit_dir"
    cat > "$unit_dir/rhorizon.service" <<UNIT
[Unit]
Description=rhorizon vault stack ($TIER tier)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$WORK_DIR
ExecStart=$dc_abs -f $WORK_DIR/docker-compose.yml --env-file $WORK_DIR/.env up -d
ExecStop=$dc_abs -f $WORK_DIR/docker-compose.yml --env-file $WORK_DIR/.env down

[Install]
WantedBy=default.target
UNIT
    if systemctl --user daemon-reload 2>/dev/null && systemctl --user enable rhorizon.service 2>/dev/null; then
        say "  enabled $unit_dir/rhorizon.service (stack returns SEALED on boot - unseal again)"
    else
        warn "  wrote $unit_dir/rhorizon.service but could not enable it; run:  systemctl --user enable rhorizon.service"
    fi
}

# Container runtime. This script installs Horizon USING a runtime; it does not
# install one. Podman is a first-class target here -- the script ships
# tools/docker-compose.quickstart.podman.yml and branches on RUNTIME further
# down -- but the preflight used to demand the `docker` binary specifically, so
# a host with podman + podman-compose and no docker shim died before ever
# reaching that support. Detect the runtime FIRST, then everything downstream
# uses $CONTAINER_BIN instead of a hardcoded `docker`.
if command -v docker >/dev/null 2>&1; then
    CONTAINER_BIN=docker
elif command -v podman >/dev/null 2>&1; then
    CONTAINER_BIN=podman
else
    die "no container runtime found (looked for 'docker' and 'podman').
  This script installs Horizon USING one; it does not install it.
  Install docker or podman, or run 'sh tools/install.sh', which falls back
  to the native installer when no runtime is present."
fi
say "using runtime : $CONTAINER_BIN"

# Compose: v2 plugin form ('<bin> compose') or the standalone v1 binary. Both
# runtimes ship both shapes, so probe all four rather than assuming the pairing
# -- podman-compose is commonly installed without `podman compose` working, and
# a docker shim over podman gives `docker compose` without docker-compose.
if $CONTAINER_BIN compose version >/dev/null 2>&1; then
    DC="$CONTAINER_BIN compose"
elif command -v "$CONTAINER_BIN-compose" >/dev/null 2>&1; then
    DC="$CONTAINER_BIN-compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
elif command -v podman-compose >/dev/null 2>&1; then
    DC="podman-compose"
else
    die "no compose implementation found (tried '$CONTAINER_BIN compose', '$CONTAINER_BIN-compose', docker-compose, podman-compose)"
fi
say "using compose : $DC"

command -v openssl >/dev/null 2>&1 || die "openssl not found (needed to generate passwords)"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found (used to parse the unseal response). On Alpine: 'apk add python3'."
SWAP_PROTECTION=$(swap_protection)

# ---------------------------------------------------------------------------
# Working directory + sources
# ---------------------------------------------------------------------------

mkdir -p "$WORK_DIR" "$WORK_DIR/secrets"
chmod 0700 "$WORK_DIR/secrets"
cd "$WORK_DIR"
say "working dir : $WORK_DIR"

# Locate the repo : either we're inside a checkout (dev mode, REPO_ROOT
# was captured pre-cd above), or fetch from REPO_GIT. The full source is
# needed for `docker compose build` (Dockerfiles, requirements, schema).

if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/api/Dockerfile" ] && [ -f "$REPO_ROOT/schema.sql" ]; then
    say "using local checkout at $REPO_ROOT"
    SOURCE_DIR="$REPO_ROOT"
else
    if [ ! -d "$WORK_DIR/source" ]; then
        say "cloning rhorizon source ..."
        git clone --depth 1 "$REPO_GIT" "$WORK_DIR/source"
    else
        say "refreshing source"
        (cd "$WORK_DIR/source" && git pull --ff-only)
    fi
    SOURCE_DIR="$WORK_DIR/source"
fi
cp "$SOURCE_DIR/schema.sql" "$WORK_DIR/schema.sql"
cp "$SOURCE_DIR/dynamic-engines.ini" "$WORK_DIR/dynamic-engines.ini"
cp "$SOURCE_DIR/tools/docker-compose.memory-lock.yml" \
    "$WORK_DIR/docker-compose.memory-lock.yml"

# Pick the compose variant for the detected engine - a host runs one, not both.
# podman needs the portable tmpfs + plain depends_on; Docker keeps the strict form.
RUNTIME=""
[ -r "$SOURCE_DIR/tools/detect-system.sh" ] && eval "$(sh "$SOURCE_DIR/tools/detect-system.sh" 2>/dev/null)"
# Fall back to what the preflight resolved. The previous probe asked
# `docker version | grep podman`, which only ever identified podman when it was
# reached THROUGH a docker shim -- on a shim-less podman host it both failed to
# run and, had it run, would have concluded "docker".
[ -n "$RUNTIME" ] || { { $CONTAINER_BIN version 2>/dev/null || true; } | grep -qi podman && RUNTIME=podman || RUNTIME="$CONTAINER_BIN"; }
if [ "$RUNTIME" = podman ] && [ -f "$SOURCE_DIR/tools/docker-compose.quickstart.podman.yml" ]; then
    say "engine: podman - using the podman compose variant"
    warn "note: the podman variant runs the STOCK upstream postgres image, which"
    warn "  bundles gosu (a Go binary) carrying Go-stdlib CVEs that upstream has"
    warn "  not rebuilt. They are NOT exploitable here - gosu is exec-only (no"
    warn "  socket, no TLS, no parsing) - so this is accepted at your own risk."
    warn "  The Docker variant ships a gosu-free postgres image (postgres/Dockerfile)."
    cp "$SOURCE_DIR/tools/docker-compose.quickstart.podman.yml" "$WORK_DIR/docker-compose.yml"
else
    say "engine: docker"
    cp "$SOURCE_DIR/tools/docker-compose.quickstart.yml" "$WORK_DIR/docker-compose.yml"
fi

# ---------------------------------------------------------------------------
# .env - generate or reuse
# ---------------------------------------------------------------------------

# Preserve stable values across re-runs (POSTGRES_PASSWORD is minted once,
# bind/ports persist unless overridden); the tier knobs are re-applied every
# run so switching --tier converges on the next `up -d`.
PREV_TIER=""
if [ -f "$WORK_DIR/.env" ]; then
    # shellcheck disable=SC1091
    set -a; . "$WORK_DIR/.env"; set +a
    PREV_TIER="${RHORIZON_TIER:-}"
    [ "$BIND_SET" = true ] || BIND_ADDR="${RHORIZON_API_BIND:-$BIND_ADDR}"
    API_PORT="${RHORIZON_API_PORT:-$API_PORT}"
    FRONTEND_PORT="${RHORIZON_FRONTEND_PORT:-$FRONTEND_PORT}"
    FRONTEND_HTTP_PORT="${RHORIZON_FRONTEND_HTTP_PORT:-$FRONTEND_HTTP_PORT}"
fi
: "${POSTGRES_PASSWORD:=$(openssl rand -hex 32)}"

# Finalize tier: explicit wins; otherwise keep the current one, default home.
[ "$TIER_SET" = true ] || TIER="${PREV_TIER:-home}"
TIER_FILE="$SOURCE_DIR/tools/presets/$TIER.env"
[ -f "$TIER_FILE" ] || die "unknown tier '$TIER' (want home, smb, heavy or super-heavy)"
# shellcheck disable=SC1090
set -a; . "$TIER_FILE"; set +a
if [ -n "$PREV_TIER" ] && [ "$PREV_TIER" != "$TIER" ]; then
    say "switching tier $PREV_TIER -> $TIER (data persists; re-unseal after)"
else
    say "tier: $TIER (${RHORIZON_WORKERS} worker(s))"
fi

# ---------------------------------------------------------------------------
# TLS is mandatory. Mint a self-signed cert on first install so the stack comes
# up on https with no extra steps; the compose file already mounts
# ${TLS_CERT_DIR:-./certs} into the frontend and reads TLS_CERT / TLS_KEY.
#
# Self-signed rather than the PKI engine on purpose: /pki/init needs an
# UNSEALED vault, and unsealing needs the very connection this cert secures.
# The PKI engine's default algorithm is also the composite hybrid, which stock
# TLS stacks cannot parse. Once you run HA, POST /cluster/issue-server-cert
# replaces this with a cluster-CA-signed pair (docs/HA-RUNBOOK.md 3.7).
# ---------------------------------------------------------------------------
CERT_DIR="$WORK_DIR/certs"
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        die "openssl is required to generate the TLS certificate"
    fi
    mkdir -p "$CERT_DIR"
    # SANs: loopback always, plus the bind address when it is not loopback, so
    # the same cert works for a LAN/VPN-reachable install without regeneration.
    _san="DNS:localhost,IP:127.0.0.1,IP:::1"
    case "$BIND_ADDR" in
        127.0.0.1|localhost|::1) ;;
        *) _san="$_san,IP:$BIND_ADDR" ;;
    esac
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -days 825 -subj "/CN=rhorizon" -addext "subjectAltName=$_san" \
        >/dev/null 2>&1 || die "openssl failed to generate the TLS certificate"
    chmod 0600 "$CERT_DIR/key.pem"
    chmod 0644 "$CERT_DIR/cert.pem"
    say "TLS: generated self-signed certificate ($_san)"
else
    say "TLS: reusing existing certificate in $CERT_DIR"
fi

cat > "$WORK_DIR/.env" <<EOF
# rhorizon quickstart .env - generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
RHORIZON_TIER=$TIER
RHORIZON_API_BIND=$BIND_ADDR
RHORIZON_API_PORT=$API_PORT
RHORIZON_FRONTEND_BIND=$BIND_ADDR
RHORIZON_FRONTEND_PORT=$FRONTEND_PORT
RHORIZON_FRONTEND_HTTP_PORT=$FRONTEND_HTTP_PORT
RHORIZON_API_IMAGE=localhost/rhorizon-api:quickstart
RHORIZON_FRONTEND_IMAGE=localhost/rhorizon-frontend:quickstart
RHORIZON_POSTGRES_IMAGE=localhost/rhorizon-postgres:quickstart
RH_SWAP_PROTECTION=$SWAP_PROTECTION
RHORIZON_WORKERS=$RHORIZON_WORKERS
RHORIZON_API_MEM=$RHORIZON_API_MEM
POSTGRES_SHARED_BUFFERS=$POSTGRES_SHARED_BUFFERS
POSTGRES_EFFECTIVE_CACHE=$POSTGRES_EFFECTIVE_CACHE
POSTGRES_MAX_CONNECTIONS=$POSTGRES_MAX_CONNECTIONS
POSTGRES_MEM=$POSTGRES_MEM
RHORIZON_FRONTEND_MEM=$RHORIZON_FRONTEND_MEM
TLS_ENABLED=true
TLS_CERT_DIR=$CERT_DIR
TLS_CERT=/certs/cert.pem
TLS_KEY=/certs/key.pem
EOF
chmod 0600 "$WORK_DIR/.env"

# ---------------------------------------------------------------------------
# Build images
# ---------------------------------------------------------------------------

if $DO_BUILD; then
    say "building API image (this can take a few minutes the first time)"
    $CONTAINER_BIN build -t localhost/rhorizon-api:quickstart \
        -f "$SOURCE_DIR/api/Dockerfile" "$SOURCE_DIR" 2>&1 | tail -3
    say "building frontend image"
    $CONTAINER_BIN build -t localhost/rhorizon-frontend:quickstart \
        -f "$SOURCE_DIR/frontend/Dockerfile" "$SOURCE_DIR/frontend" 2>&1 | tail -3
    # Docker path only: build the gosu-free postgres image locally (never
    # published). Podman keeps stock upstream postgres (see the setup warning).
    if [ "$RUNTIME" = docker ]; then
        say "building gosu-free postgres image"
        $CONTAINER_BIN build -t localhost/rhorizon-postgres:quickstart \
            -f "$SOURCE_DIR/postgres/Dockerfile" "$SOURCE_DIR" 2>&1 | tail -3
    fi
else
    say "skipping build (--no-build) - assumes images already exist"
fi

# ---------------------------------------------------------------------------
# Bring up
# ---------------------------------------------------------------------------

say "bringing up the stack"
$DC -f "$WORK_DIR/docker-compose.yml" --env-file "$WORK_DIR/.env" up -d

# Poll /health on the API. The compose health check is more defensive
# (port mapping may take a few seconds to settle).
say "waiting for API to become healthy on http://$BIND_ADDR:$API_PORT/health"
DEADLINE=$(( $(date +%s) + 180 ))
while true; do
    if curl -fsS -m 2 "http://$BIND_ADDR:$API_PORT/health" >/dev/null 2>&1; then
        say "API up"
        break
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        die "API did not become healthy within 180 seconds. Check '$DC logs api'."
    fi
    sleep 2
done

# Everything that carries the master password or the root token goes over the
# TLS frontend, never the plaintext API port. Both ports are published on
# $BIND_ADDR, and --bind is explicitly supported for LAN/VPN installs (the
# certificate above even gets a SAN for it), so an unattended install was
# POSTing the master password in clear over the network and getting the root
# token back the same way. The plaintext port stays up for debugging and for
# health checks, which carry nothing.
#
# --cacert pins the self-signed certificate we just minted: -k would accept
# any certificate and defeat the point.
VAULT_URL="https://$BIND_ADDR:$FRONTEND_PORT"
CACERT="$CERT_DIR/cert.pem"

# Wait for the frontend too, otherwise the first sensitive call races nginx.
# -f is what makes this a real probe: without it curl exits 0 on nginx's 502
# while the backend is still starting.
say "waiting for the TLS frontend on $VAULT_URL/health"
# One restart is allowed, for a specific and reproducible reason: nginx
# resolves the api container's address ONCE, when it loads its config. If the
# api container is (re)created after the frontend started, it comes back on a
# new address and the frontend keeps proxying to the old one, answering 502 to
# everything until it is reloaded. Compose start ordering makes that likely on
# a first install, and it does not heal on its own.
_fe_restarted=0
DEADLINE=$(( $(date +%s) + 90 ))
while true; do
    if curl --cacert "$CACERT" -fsS -m 2 "$VAULT_URL/health" >/dev/null 2>&1; then
        say "TLS frontend up"
        break
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ] && [ "$_fe_restarted" = 0 ]; then
        say "frontend is answering but cannot reach the api (stale upstream address)"
        say "  restarting it so nginx re-resolves"
        $DC -f "$WORK_DIR/docker-compose.yml" --env-file "$WORK_DIR/.env" \
            restart frontend >/dev/null 2>&1 || true
        _fe_restarted=1
        DEADLINE=$(( $(date +%s) + 90 ))
    elif [ "$(date +%s)" -ge "$DEADLINE" ]; then
        die "TLS frontend did not answer. Check '$DC logs frontend'."
    fi
    sleep 2
done

# POST /unseal with the password read from stdin. The password is serialised
# by python3's json module and handed to curl on stdin, so it never lands in
# argv (/proc, ps), in the environment, or in a shell string.
#
# It used to be interpolated: -d "{\"password\": \"$PW\"}". A password
# containing a double quote, a backslash or a newline produced invalid or
# silently altered JSON -- and a vault master password has to be opaque input,
# not something the operator has to keep shell-safe.
unseal_post() {
    python3 -c 'import json,sys; sys.stdout.write(json.dumps({"password": sys.stdin.read()}))' \
        | curl --cacert "$CACERT" -fsS -m 180 -X POST "$VAULT_URL/api/v1/vault/unseal" \
            -H 'Content-Type: application/json' --data-binary @-
}

# ---------------------------------------------------------------------------
# First unseal - sets master password + returns root token
# ---------------------------------------------------------------------------

ROOT_TOKEN_FILE="$WORK_DIR/secrets/root-token"
MASTER_PW_FILE="$WORK_DIR/secrets/master-password"
# Whether THIS run unsealed and therefore wrote credentials to disk. Drives the
# summary: a sealed install must not advertise files that do not exist, and an
# unsealed one must not stay quiet about the ones that do. Defaults false so a
# re-run (root token already present) takes neither branch under `set -u`.
UNSEALED_BY_INSTALLER=false

# Persist an explicitly supplied password too. The summary promises this file,
# and restart/tier/override convergence needs it to re-unseal automatically.
if [ -n "$MASTER_PASSWORD" ] && [ ! -f "$MASTER_PW_FILE" ]; then
    umask 077 && printf '%s' "$MASTER_PASSWORD" > "$MASTER_PW_FILE"
    chmod 0400 "$MASTER_PW_FILE"
fi

if [ -f "$ROOT_TOKEN_FILE" ]; then
    say "root token already on disk - skipping first-boot unseal"
    SEALED=$(curl -fsS "http://$BIND_ADDR:$API_PORT/api/v1/vault/status" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sealed", True))')
    if [ "$SEALED" = "True" ] && [ -f "$MASTER_PW_FILE" ]; then
        # A --tier switch (or a reboot) recreated the api container, so the
        # vault came back sealed. Re-unseal from the saved master password to
        # keep the toggle seamless. Fails cleanly if 2FA is on (unseal by hand).
        say "vault sealed after restart - re-unsealing from saved master password"
        # Say out loud what makes this possible. A vault that unseals itself is
        # a vault whose master password is readable by the machine: the
        # convenience and the exposure are the same fact, so the operator has
        # to be told where the file is rather than just enjoying the effect.
        warn "this worked because the master password is stored at $MASTER_PW_FILE"
        warn "  anyone who can read that file can unseal this vault; it is mode 0400,"
        warn "  so it is only as protected as this host's disk and root account."
        warn "  Delete it to require a manual unseal after every restart."
        if unseal_post < "$MASTER_PW_FILE" >/dev/null 2>&1; then
            say "re-unsealed"
        else
            warn "auto re-unseal failed (2FA enabled?). Run /unseal manually."
        fi
    elif [ "$SEALED" = "True" ]; then
        warn "vault is sealed but we already had credentials. Re-run /unseal manually."
    fi
else
    # Re-run of an install that already has a saved password: reuse it, the
    # operator opted into the scripted path once already.
    if [ -z "$MASTER_PASSWORD" ] && [ -f "$MASTER_PW_FILE" ]; then
        MASTER_PASSWORD="$(cat "$MASTER_PW_FILE")"
    fi
fi

# Sealed by default. The installer no longer invents a master password: the
# vault stays sealed and the operator sets it with the first unseal, which is
# what README and docs/QUICKSTART.md describe.
#
# Generating one meant the key protecting everything was chosen by a shell
# script and written to disk, on a host the operator had not yet been told
# holds it -- while the documentation said "choose a strong password". Anyone
# who followed the docs never learned the file existed.
#
# --master-password / RH_MASTER_PASSWORD keeps the unattended path working. It
# is opt-in, and it is the only branch that writes credentials to disk.
if [ ! -f "$ROOT_TOKEN_FILE" ] && [ -z "$MASTER_PASSWORD" ]; then
    UNSEALED_BY_INSTALLER=false
    # Worded to hold on a RE-RUN too. A default install writes no root-token
    # file, so a --tier switch re-enters this branch on a vault that already
    # has a master password -- "set the master password with the first unseal"
    # would be wrong there, and the installer cannot tell the two apart from
    # /status, which reports sealed:true either way.
    say "vault is SEALED - unseal it to finish (the FIRST unseal is what sets"
    say "  the master password; later ones just reopen it with that password)"
elif [ ! -f "$ROOT_TOKEN_FILE" ]; then
    UNSEALED_BY_INSTALLER=true
    say "performing first /unseal (sets master password)"
    # printf is a shell builtin, so the password does not reach any process
    # argument list on its way to the serialiser.
    UNSEAL_RESP=$(printf '%s' "$MASTER_PASSWORD" | unseal_post)

    ROOT_TOKEN=$(printf '%s' "$UNSEAL_RESP" | python3 -c '
import sys, json
data = json.load(sys.stdin)
tok = data.get("root_token")
if tok:
    print(tok)
else:
    print("", end="")
')
    if [ -z "$ROOT_TOKEN" ]; then
        die "first /unseal did not return a root_token (already initialised?). Response: $UNSEAL_RESP"
    fi
    umask 077 && printf '%s' "$ROOT_TOKEN" > "$ROOT_TOKEN_FILE"
    chmod 0400 "$ROOT_TOKEN_FILE"
    say "root token saved to $ROOT_TOKEN_FILE (mode 0400)"
fi

# ---------------------------------------------------------------------------
# Persistence (opt-in) - stack returns on boot
# ---------------------------------------------------------------------------

if [ "$DO_PERSIST" = true ]; then
    setup_persistence
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

cat <<EOF

================================================================================
  rhorizon is up and running.

  Frontend (UI)        : https://$BIND_ADDR:$FRONTEND_PORT/
  API endpoint         : https://$BIND_ADDR:$FRONTEND_PORT/api/
                         (plain HTTP is still up on :$FRONTEND_HTTP_PORT and
                          :$API_PORT for debugging; the vault logs a
                          PLAINTEXT TRANSPORT warning for every call that
                          uses them)

  TLS certificate      : $CERT_DIR/cert.pem  (self-signed, 825 days)

$(if [ "$UNSEALED_BY_INSTALLER" = true ]; then cat <<CREDS
  Master password      : $MASTER_PW_FILE
  Root token           : $ROOT_TOKEN_FILE

  SECURITY ACTION REQUIRED
  ------------------------
  You passed --master-password, so the vault was unsealed for you and BOTH
  credentials are on disk at the paths above (mode 0400).

  Together they are enough to take full control of this instance.

  Move them into a password manager (pass, gopass, KeePassXC, Bitwarden or
  another offline manager) and delete the files once you have verified the
  backup. Do not leave them in shell history, Git, notes or chat.
CREDS
else cat <<SEALED
  Vault state          : SEALED - no credentials were generated or written

  Unseal it to finish (section 4 of docs/QUICKSTART.md). The CLI reads the
  password without echoing it and keeps it out of your shell history:

    rhorizon unseal

  Nothing is written to disk on this path, which is also why the vault
  cannot reopen itself: unattended unseal needs the password readable by
  the machine. See "Automatic unseal" in the README, and the warning at
  the bottom of this summary.
SEALED
fi)

  Put these in your shell profile - the CA line is what makes the
  self-signed certificate trusted by the CLI and the rh-* agents :

    export RH_ADDR=https://$BIND_ADDR:$FRONTEND_PORT
    export RH_CA_FILE=$CERT_DIR/cert.pem

  Quick API check (once you hold a token) :

    export RH_TOKEN=$(if [ "$UNSEALED_BY_INSTALLER" = true ]; then \
        printf '\\$(cat %s/secrets/root-token)' "$WORK_DIR"; \
      else printf '<the root token the first unseal printed>'; fi)
    curl --cacert $CERT_DIR/cert.pem \\
      -H "Authorization: Bearer \$RH_TOKEN" \\
      https://$BIND_ADDR:$FRONTEND_PORT/api/v1/vault/tokens/whoami

  Stop the stack       : cd $WORK_DIR && $DC down
  Wipe everything      : cd $WORK_DIR && $DC down -v && cd .. && rm -rf $WORK_DIR

  Production hardening checklist :
    - TLS is on by default with a self-signed certificate; replace it
      with a cluster-CA or public-CA pair for anything shared
    - choose a master password you can re-enter; it is required to unseal
      after every restart
    - rotate the root token immediately and create per-service tokens
      with narrow scopes + IP allowlists
    - enable 2FA via the Core view in the UI
    - back up the Postgres volume and the secrets/ directory

--------------------------------------------------------------------------------
  WARNING ON A FIRST UNSEAL THIS SETS THE MASTER PASSWORD AND RETURNS A
  ONE-TIME ROOT TOKEN, STORE THAT IN A PASSWORD MANAGER.

  On a later one (after a reboot or a --tier switch) it just reopens the
  vault with the password you already chose.
--------------------------------------------------------------------------------
================================================================================

EOF

case "$SWAP_PROTECTION" in
    unencrypted)
        warn "unencrypted swap detected: memory locking is recommended"
        warn "  optional enforcement (fails closed if IPC_LOCK is unavailable):"
        warn "  cd $WORK_DIR && $DC -f docker-compose.yml -f docker-compose.memory-lock.yml --env-file .env up -d"
        ;;
    unknown)
        warn "swap encryption could not be verified; the stack remains in portable best-effort mode"
        warn "  check memory/swap state with: rhorizon status"
        ;;
    protected)
        say "memory: swap is absent, encrypted, or RAM-only; zeroize-on-drop is sufficient for swap exposure"
        ;;
esac
