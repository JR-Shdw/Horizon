#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon NATIVE installer -- no Docker. Detects the OS and delegates the
# OS-specific work to a driver in tools/drivers/<os>.sh. The Docker path lives
# in tools/install.sh; this handles *BSD and Linux-without-Docker.
#
#   sh tools/install-native.sh [--mode user|system] [--workers N] [--dry-run]
#       [--dir APP_DIR] [--config-dir DIR] [--state-dir DIR]
#       [--runtime-dir DIR] [--audit-dir DIR] [--bind ADDR] [--api-port N]
#       [--master-password-file FILE] [--external-db URL] [--tls-cert F --tls-key F]
#       [--memory-lock-mode best-effort|required] [--no-service]
#       [--no-nginx] [--pq-nginx] [--backend-port N]
#
# TLS is mandatory and automatic: the installer mints a self-signed pair under
# <config-dir>/certs on first run. --tls-cert/--tls-key substitute a real one.
#
# It terminates at nginx when the driver can supervise one (HTTP/2, plus the SPA
# and the security headers), with uvicorn on loopback behind it. Otherwise
# uvicorn terminates directly: still TLS, but HTTP/1.1 only since uvicorn has no
# HTTP/2 implementation. --no-nginx forces the latter.
#
# The two properties are independent and neither is free on every OS:
#
#   post-quantum (X25519MLKEM768) needs OpenSSL >= 3.5 in whatever terminates
#     TLS. It is what defeats harvest-now-decrypt-later, where a recorded
#     handshake is broken later by a quantum computer -- so it protects traffic
#     captured today, not just future traffic.
#   HTTP/2 removes the HTTP/1.1 keep-alive race that drops connections under
#     load (see the c=500 bench note in frontend/nginx-tls.conf). If you need
#     real throughput rather than occasional calls, h2 is the floor.
#
# Several lanes ship an nginx or a python that can do only one of the two.
# --pq-nginx builds nginx against an OpenSSL that has ML-KEM so you get both;
# it is a source build, hence opt-in. docs/TLS.md has the measured per-lane
# table -- consult it rather than assuming your OS is fine.
#
# Path convention:
#   user mode (Linux/*BSD): XDG data/config/state, XDG runtime if present,
#     audit under XDG state.
#   Linux system:   /opt/rhorizon, /etc/rhorizon, /var/lib/rhorizon,
#                   /run/rhorizon, /var/log/rhorizon.
#   FreeBSD system: /usr/local/rhorizon, /usr/local/etc/rhorizon,
#                   /var/db/rhorizon, /var/run/rhorizon, /var/log/rhorizon.
#   OpenBSD system: /usr/local/rhorizon, /etc/rhorizon,
#                   /var/db/rhorizon, /var/run/rhorizon, /var/log/rhorizon.
#   NetBSD system:  /usr/pkg/rhorizon, /usr/pkg/etc/rhorizon,
#                   /var/db/rhorizon, /var/run/rhorizon, /var/log/rhorizon.
#   macOS native has Apple-specific Library paths and lives in
#   tools/install-macos.sh, not this generic POSIX driver.
#
# --workers N (default 1): API worker processes. The app mlockall()s each worker
#   out of swap, so RAM need = N*160MB (worker RSS) + 256MB (Argon2id unseal
#   spike) + 192MB (headroom). The memlock ceiling is set to exactly that:
#     workers  RAM/memlock   typical tier
#       1        608 MB        home (default)
#       5       1248 MB        smb
#      10       2048 MB        heavy
#   Pick N to fit the host RAM; the app also warns at boot if the limit is short.
#
# POSTGRESQL: by default the installer sets up a LOCAL PostgreSQL (the driver
#   installs postgresql-server, initdb's a cluster, then creates role `rhorizon`
#   + db `rhorizon` with a random password and applies schema.sql). To use an
#   existing/remote DB instead, pass --external-db <sqlalchemy-url> and no local
#   PG is touched.
#   *** SYSTEM-WIDE change on *BSD ***: PostgreSQL needs far more SysV semaphores
#   / shared memory than the BSD kernel defaults (OpenBSD semmni=10, etc.), and
#   these are KERNEL-GLOBAL -- there is no per-process equivalent. So the driver
#   raises kern.seminfo.* / kern.ipc.* via sysctl AND persists them to
#   /etc/sysctl.conf (so PG restarts across reboot). This only RAISES ceilings
#   (nothing is restricted) but it affects the whole host -- intended for a
#   dedicated rhorizon box. (memlock, by contrast, is per-process / this service
#   only.) Linux uses cgroups, so no global sysctl is needed there.
#
# DRIVER CONTRACT -- tools/drivers/<os>.sh defines these POSIX functions:
#   driver_pkg                 install build deps (+ postgresql unless --external-db)
#   driver_python              stdout: path to a python3 whose ssl works
#                              (OpenBSD builds one from source vs eopenssl)
#   driver_build_env           stdout: KEY=VAL lines exported before pip/maturin
#   driver_pg_setup            init+start PG, create role/db; stdout: DATABASE_URL
#   driver_service_install D V E   write+enable a boot service (dir, venv, envfile)
#   driver_start               start the service
# Optional, and their presence is the feature switch for the nginx front:
#   driver_service_install_nginx B P C   boot service for nginx (bin, prefix, conf)
#   driver_start_nginx         start it
#   RH_NGINX_REQUIRE_PQ=1      decline nginx unless it offers X25519MLKEM768
#                              (OpenBSD: its uvicorn does, the packaged nginx does not)
#   RH_NGINX_BIN               use this nginx instead of the one on PATH
set -eu

# --- args ----------------------------------------------------------------
# RH_* is the canonical env prefix product-wide; promote any RH_<X> over its
# deprecated RHORIZON_<X> alias so the reads below honor the canonical name.
for _rn in DIR CONFIG_DIR STATE_DIR RUNTIME_DIR AUDIT_DIR API_PORT FRONTEND_PORT \
        FRONTEND_HTTP_PORT BIND API_BIND TIER PERSIST WORKERS MASTER_PASSWORD \
        MEMORY_LOCK_MODE MCP_VENV MCP_TOKEN_FILE MCP_POLICY MCP_TOKEN_NAME \
        SWAP_PROTECTION TLS_CERT TLS_KEY PQ_NGINX BACKEND_PORT NGINX_CLUSTER_MTLS \
        REPO_BASE REPO_RAW REPO_GIT; do
    eval "_rv=\${RH_${_rn}:-}"
    if [ -n "${_rv}" ]; then eval "RHORIZON_${_rn}=\${_rv}"; fi
done
unset _rn _rv
DRY_RUN=0; WORK_DIR="${RHORIZON_DIR:-}"; BIND="127.0.0.1"
CONFIG_DIR="${RHORIZON_CONFIG_DIR:-}"
STATE_DIR="${RHORIZON_STATE_DIR:-}"
RUNTIME_DIR="${RHORIZON_RUNTIME_DIR:-}"
AUDIT_DIR="${RHORIZON_AUDIT_DIR:-}"
# MASTER_PASSWORD is in the RH_*->RHORIZON_* promotion list above, but this
# used to initialise to "" and never read it, so RH_MASTER_PASSWORD was
# accepted by tools/install.sh, honoured on a Docker host, and SILENTLY
# discarded on a native one -- the install just behaved differently with no
# error. install-container.sh has always read it.
API_PORT=8200; MASTER_PW="${RHORIZON_MASTER_PASSWORD:-}"; EXTERNAL_DB=""; WANT_SERVICE=1; RH_MODE="system"
TLS_CERT="${RHORIZON_TLS_CERT:-}"; TLS_KEY="${RHORIZON_TLS_KEY:-}"
BACKEND_PORT="${RHORIZON_BACKEND_PORT:-}"; WANT_NGINX=1
WANT_PQ_NGINX="${RHORIZON_PQ_NGINX:-0}"
WORKERS="${RHORIZON_WORKERS:-1}"
MEMORY_LOCK_MODE="${RHORIZON_MEMORY_LOCK_MODE:-best-effort}"
SWAP_PROTECTION="${RHORIZON_SWAP_PROTECTION:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --mode) RH_MODE=$2; shift ;;       # user (laptop) | system (server)
        --workers) WORKERS=$2; shift ;;    # 1 (home) | 5 (smb) | 10 (heavy) | ...
        --dir) WORK_DIR=$2; shift ;;
        --config-dir) CONFIG_DIR=$2; shift ;;
        --state-dir) STATE_DIR=$2; shift ;;
        --runtime-dir) RUNTIME_DIR=$2; shift ;;
        --audit-dir) AUDIT_DIR=$2; shift ;;
        --bind) BIND=$2; shift ;;
        --api-port) API_PORT=$2; shift ;;
        --tls-cert) TLS_CERT=$2; shift ;;  # bring your own pair; both or neither
        --tls-key) TLS_KEY=$2; shift ;;
        --backend-port) BACKEND_PORT=$2; shift ;;  # loopback uvicorn behind nginx
        --no-nginx) WANT_NGINX=0 ;;        # uvicorn terminates TLS, HTTP/1.1 only
        --pq-nginx) WANT_PQ_NGINX=1 ;;     # build nginx for HTTP/2 *and* PQ
        # A secret passed in argv is world-readable in /proc/<pid>/cmdline for
        # the life of the process and lands in shell history. Kept for
        # compatibility, but it warns and --master-password-file is preferred.
        --master-password) MASTER_PW=$2; MASTER_PW_FROM_ARGV=1; shift ;;
        --master-password-file) MASTER_PW_FILE=$2; shift ;;
        --external-db) EXTERNAL_DB=$2; shift ;;
        --memory-lock-mode) MEMORY_LOCK_MODE=$2; shift ;;
        --no-service) WANT_SERVICE=0 ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done
case "$RH_MODE" in user|system) ;; *) printf 'bad --mode: %s (user|system)\n' "$RH_MODE" >&2; exit 1 ;; esac
case "$MEMORY_LOCK_MODE" in
    best-effort|required) ;;
    *) printf '%s\n' "--memory-lock-mode must be best-effort or required" >&2; exit 1 ;;
esac
case "$SWAP_PROTECTION" in
    ""|protected|unencrypted|unknown) ;;
    *) printf '%s\n' "RH_SWAP_PROTECTION must be protected, unencrypted, or unknown" >&2; exit 1 ;;
esac
if { [ -n "$TLS_CERT" ] && [ -z "$TLS_KEY" ]; } || { [ -z "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; }; then
    printf '%s\n' "--tls-cert and --tls-key go together (pass both, or neither for a generated pair)" >&2; exit 1
fi
case "$WORKERS" in ''|*[!0-9]*) printf '%s\n' "--workers must be a positive integer" >&2; exit 1 ;; esac
[ "$WORKERS" -ge 1 ] || { printf '%s\n' "--workers must be >= 1" >&2; exit 1; }
# A multi-worker cluster needs >= 5 workers (2-4 cannot hold a survivable
# failover quorum), so floor them to 5 -- matching the container boot wrapper.
# 1 stays 1 = single-worker home preset (keys in-process). Only 1 and 5+ are
# real operating points; memory is sized on the floored value.
if [ "$WORKERS" -gt 1 ] && [ "$WORKERS" -lt 5 ]; then
    printf '%s\n' "[rhorizon] --workers=$WORKERS below the multi-worker floor; using 5" >&2
    WORKERS=5
fi
# Memory budget (mlockall wires the whole process out of swap). Same formula the
# app self-checks (mem_hardening.required_memory_mb): per-worker RSS + the 256MB
# Argon2id unseal spike + headroom. The memlock ceiling is set to exactly this.
RH_MEM_MB=$(( WORKERS * 160 + 256 + 192 ))
RH_MEMLOCK_KB=$(( RH_MEM_MB * 1024 ))
export RH_MEMLOCK_KB
export DRY_RUN RH_MODE

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/tools/lib/common.sh"

detect_host

if [ "$RH_MODE" = user ]; then
    XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
    XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
    [ -n "$WORK_DIR" ] || WORK_DIR="$XDG_DATA_HOME/rhorizon"
    [ -n "$CONFIG_DIR" ] || CONFIG_DIR="$XDG_CONFIG_HOME/rhorizon"
    [ -n "$STATE_DIR" ] || STATE_DIR="$XDG_STATE_HOME/rhorizon"
    if [ -z "$RUNTIME_DIR" ]; then
        if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
            RUNTIME_DIR="$XDG_RUNTIME_DIR/rhorizon"
        else
            RUNTIME_DIR="$STATE_DIR/run"
        fi
    fi
    [ -n "$AUDIT_DIR" ] || AUDIT_DIR="$STATE_DIR/audit"
else
    case "$RH_OS" in
        freebsd)
            _default_work="/usr/local/rhorizon"
            _default_config="/usr/local/etc/rhorizon"
            _default_state="/var/db/rhorizon"
            _default_runtime="/var/run/rhorizon"
            _default_audit="/var/log/rhorizon"
            ;;
        openbsd)
            _default_work="/usr/local/rhorizon"
            _default_config="/etc/rhorizon"
            _default_state="/var/db/rhorizon"
            _default_runtime="/var/run/rhorizon"
            _default_audit="/var/log/rhorizon"
            ;;
        netbsd)
            _default_work="/usr/pkg/rhorizon"
            _default_config="/usr/pkg/etc/rhorizon"
            _default_state="/var/db/rhorizon"
            _default_runtime="/var/run/rhorizon"
            _default_audit="/var/log/rhorizon"
            ;;
        *)
            _default_work="/opt/rhorizon"
            _default_config="/etc/rhorizon"
            _default_state="/var/lib/rhorizon"
            _default_runtime="/run/rhorizon"
            _default_audit="/var/log/rhorizon"
            ;;
    esac
    [ -n "$WORK_DIR" ] || WORK_DIR="$_default_work"
    [ -n "$CONFIG_DIR" ] || CONFIG_DIR="$_default_config"
    [ -n "$STATE_DIR" ] || STATE_DIR="$_default_state"
    [ -n "$RUNTIME_DIR" ] || RUNTIME_DIR="$_default_runtime"
    [ -n "$AUDIT_DIR" ] || AUDIT_DIR="$_default_audit"
fi
export RH_NATIVE_CONFIG_DIR="$CONFIG_DIR"
export RH_NATIVE_STATE_DIR="$STATE_DIR"
export RH_NATIVE_RUNTIME_DIR="$RUNTIME_DIR"
export RH_NATIVE_AUDIT_DIR="$AUDIT_DIR"

log "host: os=$RH_OS arch=$RH_ARCH distro=${RH_DISTRO:-n/a}  app=$WORK_DIR  config=$CONFIG_DIR  state=$STATE_DIR  dry-run=$DRY_RUN"

DRIVER="$ROOT_DIR/tools/drivers/$RH_OS.sh"
[ "$RH_OS" = linux ] && [ -f "$ROOT_DIR/tools/drivers/linux-$RH_DISTRO.sh" ] \
    && DRIVER="$ROOT_DIR/tools/drivers/linux-$RH_DISTRO.sh"
[ -f "$DRIVER" ] || die "no driver for os=$RH_OS distro=${RH_DISTRO:-} ($DRIVER)"
log "driver: ${DRIVER#$ROOT_DIR/}"
. "$DRIVER"

# --- phases --------------------------------------------------------------
log "[1/7] packages"; driver_pkg

log "[2/7] python (ssl-capable)"
PYBIN=$(driver_python) || die "driver_python failed"
log "python: $PYBIN"

log "[3/7] venv + deps + rust ext"
# driver_build_env emits KEY=VAL lines (may be empty); source them (set -a
# auto-exports). Bare `export` would dump the environment, so never do that.
_bef=$(mktemp); driver_build_env > "$_bef" 2>/dev/null || true
set -a; . "$_bef"; set +a; rm -f "$_bef"
[ -n "${TMPDIR:-}" ] && run mkdir -p "$TMPDIR"   # driver may route build scratch off a small /tmp

# Cargo build scratch, created with mktemp -d so it is OURS.
#
# cargo ignores TMPDIR for its two biggest artifacts: the registry goes to
# ~/.cargo and release output to the checkout's api/rust/target, both on the
# root filesystem. NetBSD cannot absorb that -- a 13G root filled to 12G and
# killed initdb with ENOSPC. So both are redirected here.
#
# mktemp -d rather than a fixed path like $TMPDIR/cargo: a fixed path may
# already exist and belong to another tool or user, and deleting a directory we
# did not create is not ours to do. Owning it by construction is what makes the
# cleanup below safe -- and means an uninstall has nothing to chase.
BUILD_SCRATCH=""
if [ "$DRY_RUN" != 1 ]; then
    BUILD_SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/rhorizon-build.XXXXXX") || BUILD_SCRATCH=""
    if [ -n "$BUILD_SCRATCH" ]; then
        CARGO_HOME="$BUILD_SCRATCH/cargo"
        CARGO_TARGET_DIR="$BUILD_SCRATCH/cargo-target"
        export CARGO_HOME CARGO_TARGET_DIR
        log "build scratch: $BUILD_SCRATCH (removed after the build)"
    fi
fi

VENV="$WORK_DIR/.venv"
run mkdir -p "$WORK_DIR"
make_venv "$PYBIN" "$VENV"
# optional per-OS step after venv, before pip (e.g. NetBSD copies pkgsrc crypto)
command -v driver_venv_extra >/dev/null 2>&1 && driver_venv_extra "$VENV"
pip_install "$VENV" "$ROOT_DIR"
build_ext "$VENV" "$ROOT_DIR"

# The wheel is installed into the venv by now, so the scratch is dead weight --
# several GB of it. Only ever the directory mktemp handed us.
if [ -n "$BUILD_SCRATCH" ] && [ -d "$BUILD_SCRATCH" ]; then
    rm -rf "$BUILD_SCRATCH"
    log "build scratch removed"
fi

# System mode: relocate app code + schema into the confined WORK_DIR. The service
# must not depend on the build-time checkout ($ROOT_DIR) -- it lives in a user
# home that SELinux rhorizon_t cannot read, and may be removed after install.
# User mode keeps referencing the checkout (updated via git pull + re-run).
if [ "$RH_MODE" = system ]; then
    # Copy the app package into the confined tree with a PORTABLE cp (BSD tar
    # has no --exclude). Only api/app is needed at runtime (--app-dir=api imports
    # app.main); the rust build tree + deps live in the venv, not here.
    run sh -c "rm -rf '$WORK_DIR/api'; mkdir -p '$WORK_DIR/api'; cp -R '$ROOT_DIR/api/app' '$WORK_DIR/api/app'; find '$WORK_DIR/api' -name __pycache__ -exec rm -rf {} + 2>/dev/null || true"
    run cp -f "$ROOT_DIR/schema.sql" "$WORK_DIR/schema.sql"
    run cp -f "$ROOT_DIR/dynamic-engines.ini" "$WORK_DIR/dynamic-engines.ini"
    # Own the relocated code as root so the confined service reads it via the
    # OWNER bit (it runs as root but is NOT granted dac_read_search, so it can
    # not override a file owned by the build-checkout's uid). Numeric 0:0 --
    # BSD's root group is "wheel", not "root". Guarantee OWNER read/traverse
    # only; never widen group/other (do not loosen a vault's files).
    run sh -c "chown -R 0:0 '$WORK_DIR/api' '$WORK_DIR/schema.sql' '$WORK_DIR/dynamic-engines.ini'; chmod -R u+rX '$WORK_DIR/api'; chmod u+r '$WORK_DIR/schema.sql' '$WORK_DIR/dynamic-engines.ini'"
    APP_DIR="$WORK_DIR/api"; SCHEMA_FILE="$WORK_DIR/schema.sql"
    DYNAMIC_MODULES_FILE="$WORK_DIR/dynamic-engines.ini"
else
    APP_DIR="$ROOT_DIR/api"; SCHEMA_FILE="$ROOT_DIR/schema.sql"
    DYNAMIC_MODULES_FILE="$ROOT_DIR/dynamic-engines.ini"
fi

log "[4/7] database"
if [ -n "$EXTERNAL_DB" ]; then DB_URL="$EXTERNAL_DB"; log "external db"
else DB_URL=$(driver_pg_setup); fi
# The app applies schema.sql from the hardcoded /app/schema.sql on first boot
# (advisory-locked). Link it so a fresh DB gets its tables.
if [ "$(id -u)" = 0 ]; then run mkdir -p /app; run ln -sf "$SCHEMA_FILE" /app/schema.sql
else run sudo mkdir -p /app; run sudo ln -sf "$SCHEMA_FILE" /app/schema.sql; fi

log "[5/7] env file"
log "workers=$WORKERS -> RAM/memlock ~${RH_MEM_MB}MB (${WORKERS}x160 worker + 256 Argon2 unseal + 192 headroom)"
ENVFILE="$CONFIG_DIR/rhorizon.env"
SECRET_FILE="$CONFIG_DIR/rhorizon.env-secrets"
# Shared credential layout, same shape as install-container.sh and
# quickstart-laptop.sh: one secret per file under <base>/secrets/.
SECRET_DIR="$CONFIG_DIR/secrets"
# Idempotent re-run: reuse the master password already provisioned on this host.
# A freshly generated one cannot unseal the existing vault (argon2_salt +
# master_check are fixed at first init) and would clobber the saved secret.
# An explicit --master-password / --master-password-file still wins.
#
# The file form is read here rather than at parse time so a missing file fails
# after the cheap argument validation, not in the middle of it.
if [ -n "${MASTER_PW_FILE:-}" ]; then
    [ -f "$MASTER_PW_FILE" ] || { printf 'master password file not found: %s\n' "$MASTER_PW_FILE" >&2; exit 1; }
    # Strip a single trailing newline only: `printf secret > file` and
    # `echo secret > file` must yield the same password, but a password whose
    # real last byte is a newline is not silently truncated further.
    MASTER_PW=$(printf '%s' "$(cat "$MASTER_PW_FILE")")
    [ -n "$MASTER_PW" ] || { printf 'master password file is empty: %s\n' "$MASTER_PW_FILE" >&2; exit 1; }
fi
if [ -n "${MASTER_PW_FROM_ARGV:-}" ]; then
    printf '%s\n' \
      "WARNING: --master-password puts the secret in this process's command line" \
      "         (readable via ps / /proc) and in your shell history." \
      "         Prefer --master-password-file FILE, or omit it to keep the" \
      "         vault sealed." >&2
fi
# Shared layout first, then the pre-existing single-file form so an install
# made before the layouts converged still re-runs.
if [ -z "$MASTER_PW" ] && [ -f "$SECRET_DIR/master-password" ]; then
    MASTER_PW=$(cat "$SECRET_DIR/master-password" 2>/dev/null || true)
fi
if [ -z "$MASTER_PW" ] && [ -f "$SECRET_FILE" ]; then
    MASTER_PW=$(sed -n 's/^MASTER_PASSWORD=//p' "$SECRET_FILE" 2>/dev/null || true)
fi
# Sealed by default, matching tools/install-container.sh. The installer used to
# mint a master password here (`: "${MASTER_PW:=$(gen_secret 24)}"`) and unseal
# with it, so the key protecting everything was chosen by a shell script and
# written to disk on a host nobody had told the operator held it -- while
# README and docs/QUICKSTART.md said "choose a strong password".
#
# Providing one (--master-password, --master-password-file, or a saved
# SECRET_FILE from an earlier run) keeps the unattended path working, and is
# the only way credentials land on disk.
if [ -z "$MASTER_PW" ]; then
    UNSEAL_AT_INSTALL=0
else
    UNSEAL_AT_INSTALL=1
fi
# Preserve an admin root token already saved (minted only on the first-ever
# unseal). A re-install mints none, so we must not lose it on the rewrite.
ROOT_TOKEN=""
# Shared layout first, legacy single-file second -- same order as the master
# password above. A root token is minted only on the first-ever unseal, so
# losing it here would strand the operator with no admin credential.
[ -f "$SECRET_DIR/root-token" ] && ROOT_TOKEN=$(cat "$SECRET_DIR/root-token" 2>/dev/null || true)
[ -z "$ROOT_TOKEN" ] && [ -f "$SECRET_FILE" ] && ROOT_TOKEN=$(sed -n 's/^ROOT_TOKEN=//p' "$SECRET_FILE" 2>/dev/null || true)
run mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR"
run chmod 700 "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR"

# TLS is mandatory. The native path has no nginx -- that layer is container-only
# -- so uvicorn terminates TLS itself and the certificate goes straight to the
# ASGI server. Self-signed rather than the PKI engine on purpose: /pki/init needs
# an UNSEALED vault and unsealing needs the very connection this cert secures,
# and the engine's default algorithm is the composite hybrid no stock TLS stack
# parses. Pass --tls-cert/--tls-key to use a real pair instead.
if [ -z "$TLS_CERT" ]; then
    ensure_tls_cert "$CONFIG_DIR/certs" "$BIND"
    TLS_CERT="$CONFIG_DIR/certs/cert.pem"; TLS_KEY="$CONFIG_DIR/certs/key.pem"
else
    [ "$DRY_RUN" = 1 ] || [ -f "$TLS_CERT" ] || die "--tls-cert not found: $TLS_CERT"
    [ "$DRY_RUN" = 1 ] || [ -f "$TLS_KEY" ] || die "--tls-key not found: $TLS_KEY"
    log "TLS: using the supplied certificate $TLS_CERT"
fi
# A wildcard bind names no host to dial, and no cert can carry it as a SAN;
# verification has to target a real address. Loopback is the one always present.
case "$BIND" in
    0.0.0.0|'::'|'') LOCAL_HOST=127.0.0.1 ;;
    *) LOCAL_HOST=$BIND ;;
esac

# ---------------------------------------------------------------------------
# Where TLS terminates.
#
# nginx when the driver can supervise it: uvicorn has no HTTP/2 implementation
# (it does not even advertise ALPN, so every client falls back to HTTP/1.1), and
# nginx additionally brings the SPA, the security headers and the CSP that the
# native path never had. uvicorn then listens plaintext on loopback only.
#
# uvicorn otherwise. That path is TLS too -- PQ included, since uvicorn inherits
# OpenSSL's default groups -- just HTTP/1.1. Drivers without an nginx service
# yet keep working exactly as before rather than failing the install.
# ---------------------------------------------------------------------------
USE_NGINX=0
# A driver may point at an nginx that is not the one on PATH -- OpenBSD builds
# one against a newer OpenSSL (tools/build-nginx-bsd.sh) precisely because the
# packaged binary links LibreSSL and cannot do ML-KEM.
NGINX_BIN="${RH_NGINX_BIN:-}"
if [ -z "$NGINX_BIN" ] || [ ! -x "$NGINX_BIN" ]; then
    NGINX_BIN=$(command -v nginx 2>/dev/null || true)
fi
if [ "$WANT_NGINX" = 1 ]; then
    if [ -z "$NGINX_BIN" ]; then
        log "TLS at uvicorn: nginx not installed (HTTP/1.1 only)"
    elif ! command -v driver_service_install_nginx >/dev/null 2>&1; then
        log "TLS at uvicorn: ${RH_OS} driver cannot supervise nginx yet (HTTP/1.1 only)"
    else
        USE_NGINX=1
    fi
fi

# --pq-nginx: build nginx against an OpenSSL that has ML-KEM, so this host gets
# HTTP/2 AND post-quantum instead of one or the other. Opt-in because it is a
# source build (a couple of minutes) rather than a package install; see the
# per-lane table in docs/TLS.md for which OSes need it and why.
#
# Built BEFORE the probe rather than after: the probe asks the binary what it
# supports, so it has to be asked about the binary we intend to run.
if [ "$USE_NGINX" = 1 ] && [ "$WANT_PQ_NGINX" = 1 ]; then
    case "$RH_OS" in
        freebsd|openbsd|netbsd)
            if [ "$DRY_RUN" = 1 ]; then
                log "[dry-run] build PQ nginx via tools/build-nginx-bsd.sh"
            else
                log "--pq-nginx: building nginx against a PQ-capable OpenSSL"
                if _pqbin=$(sh "$ROOT_DIR/tools/build-nginx-bsd.sh" | tail -1) \
                   && [ -x "$_pqbin" ]; then
                    NGINX_BIN="$_pqbin"
                    log "--pq-nginx: using $NGINX_BIN"
                else
                    # Not fatal: the packaged nginx still gives HTTP/2, and the
                    # probe below will report the key exchange honestly.
                    warn "--pq-nginx: build failed; continuing with the packaged nginx"
                fi
            fi
            ;;
        *)
            warn "--pq-nginx only applies to the BSD lanes (build-nginx-bsd.sh);"
            warn "  on ${RH_OS} the packaged nginx is used as-is"
            ;;
    esac
fi

if [ "$USE_NGINX" = 1 ]; then
    # uvicorn moves off the public port so nginx can take it; the address stays
    # loopback so the plaintext hop cannot leave the host.
    [ -n "$BACKEND_PORT" ] || BACKEND_PORT=$((API_PORT + 1))
    WEB_ROOT="$WORK_DIR/web"
    install_web_root "$ROOT_DIR/frontend" "$WEB_ROOT"
    RH_NGINX_BIN="$NGINX_BIN"
    RH_NGINX_PREFIX="$STATE_DIR/nginx"
    RH_NGINX_CONF="$STATE_DIR/nginx/nginx.conf"
    RH_NGINX_WEB_ROOT="$WEB_ROOT"
    RH_NGINX_CERT="$TLS_CERT"; RH_NGINX_KEY="$TLS_KEY"
    # Address AND port. A bare `listen 8200` binds every interface, which would
    # silently turn --bind 127.0.0.1 into a world-reachable vault. IPv6 literals
    # need brackets in an nginx listen directive.
    case "$BIND" in
        *:*) RH_NGINX_PORT="[$BIND]:$API_PORT" ;;
        *)   RH_NGINX_PORT="$BIND:$API_PORT" ;;
    esac
    RH_NGINX_UPSTREAM="127.0.0.1:$BACKEND_PORT"
    RH_NGINX_LOG_DIR="$AUDIT_DIR"
    RH_NGINX_TPL="$ROOT_DIR/frontend/nginx-tls.conf"
    # Cluster mTLS forwarding for HA members. Off unless asked -- see
    # docs/HA-RUNBOOK.md 0.1; without it node certs stop renewing ~30 days on.
    RH_NGINX_CLUSTER_MTLS="${RHORIZON_NGINX_CLUSTER_MTLS:-0}"
    export RH_NGINX_BIN RH_NGINX_PREFIX RH_NGINX_CONF RH_NGINX_WEB_ROOT \
           RH_NGINX_CERT RH_NGINX_KEY RH_NGINX_PORT RH_NGINX_UPSTREAM \
           RH_NGINX_LOG_DIR RH_NGINX_TPL RH_NGINX_CLUSTER_MTLS
    if [ "$DRY_RUN" = 1 ]; then
        log "[dry-run] render nginx config -> $RH_NGINX_CONF"
        NGINX_GROUPS="$RH_PQ_GROUPS"
    else
        NGINX_GROUPS=$(render_nginx_conf) || NGINX_GROUPS=""
    fi
    if [ -z "$NGINX_GROUPS" ]; then
        # nginx cannot serve this config at all -- most likely built without
        # ngx_http_v2_module, which is opt-in at compile time. Fall back rather
        # than fail an install the uvicorn path would have completed.
        # Do not guess the cause here: nginx already printed it above, and a
        # hardcoded explanation misleads. The first version of this message
        # blamed a missing --with-http_v2_module while the real failure on
        # OpenBSD was SSL_CTX_set1_curves_list() -- an operator following it
        # would have chased the wrong module.
        warn "nginx rejected the generated config (its error is above);"
        warn "  keeping TLS at uvicorn -- HTTP/1.1 only."
        USE_NGINX=0
    else
    case "$NGINX_GROUPS" in
        *MLKEM*) log "TLS at nginx on :$API_PORT (HTTP/2, post-quantum $NGINX_GROUPS)" ;;
        *)
            # A driver sets RH_NGINX_REQUIRE_PQ when its uvicorn has a stronger
            # key exchange than its nginx -- OpenBSD, where the driver installs
            # the eopenssl port for CPython while the nginx package links base
            # LibreSSL, which has no ML-KEM. On a vault, keeping post-quantum
            # key exchange beats gaining HTTP/2, so that lane declines nginx
            # instead of silently downgrading the handshake.
            if [ "${RH_NGINX_REQUIRE_PQ:-0}" = 1 ]; then
                warn "this nginx links a libssl without X25519MLKEM768;"
                warn "  keeping TLS at uvicorn to preserve post-quantum key exchange"
                warn "  (HTTP/1.1 only). Re-run with --pq-nginx for both: it builds"
                warn "  nginx against an OpenSSL that has ML-KEM."
                USE_NGINX=0
            else
                # Do NOT suggest --no-nginx as a PQ workaround: whether uvicorn
                # has ML-KEM depends on what its interpreter links. On FreeBSD
                # that is the same base OpenSSL 3.0 nginx uses, so falling back
                # loses HTTP/2 and gains nothing. Point at the fix instead.
                warn "TLS at nginx on :$API_PORT (HTTP/2) but this nginx links a libssl"
                warn "  without X25519MLKEM768 -- key exchange is classical only, which"
                warn "  does not resist harvest-now-decrypt-later."
                warn "  Re-run with --pq-nginx to get both."
            fi
            ;;
    esac
    fi
fi

# Decided after the probe, because the probe can still send us back to uvicorn.
if [ "$USE_NGINX" = 1 ]; then
    UVICORN_HOST=127.0.0.1
    UVICORN_PORT=$BACKEND_PORT
else
    UVICORN_HOST=$BIND
    UVICORN_PORT=$API_PORT
fi

# Behind nginx every request arrives from 127.0.0.1, so the real client address
# has to come from X-Forwarded-For or audit rows, rate-limit counters and
# per-token IP allowlists all collapse onto loopback -- allowlists would reject
# every legitimate caller. Narrowed to our own proxy rather than the default
# all-RFC1918 list; this setting never authorizes identity headers.
XFF_LINE=""
if [ "$USE_NGINX" = 1 ]; then
    XFF_LINE="RH_XFF_TRUSTED_IPS=127.0.0.1/32,::1/128"
fi

run sh -c "cat > '$ENVFILE' <<EOF
RHORIZON_DATABASE_URL=$DB_URL
RHORIZON_DATABASE_SSL=disable
RHORIZON_TLS_ENABLED=true
${XFF_LINE}
RHORIZON_RUNTIME_DIR=$RUNTIME_DIR
RHORIZON_AUDIT_DIR=$AUDIT_DIR
RHORIZON_SCHEMA_PATH=$SCHEMA_FILE
RH_DYNAMIC_MODULES_FILE=$DYNAMIC_MODULES_FILE
RHORIZON_NODE_UUID_PATH=$STATE_DIR/node-uuid
RHORIZON_CLUSTER_CERT_PATH=$STATE_DIR/cluster-cert.pem
RHORIZON_CLUSTER_CERT_KEY_PATH=$STATE_DIR/cluster-cert.key
RHORIZON_WORKERS=$WORKERS
RH_MEMORY_LOCK_MODE=$MEMORY_LOCK_MODE
${SWAP_PROTECTION:+RH_SWAP_PROTECTION=$SWAP_PROTECTION}
EOF"
run chmod 600 "$ENVFILE"

RUNCMD="$VENV/bin/python -m uvicorn app.main:app --app-dir $APP_DIR --host $UVICORN_HOST --port $UVICORN_PORT --workers $WORKERS"
if [ "$USE_NGINX" = 0 ]; then
    # No proxy in front: uvicorn owns the certificate.
    RUNCMD="$RUNCMD --ssl-certfile $TLS_CERT --ssl-keyfile $TLS_KEY"
fi

if [ "$WANT_SERVICE" = 1 ]; then
    log "[6/7] service (boot-safe)"; driver_service_install "$WORK_DIR" "$VENV" "$ENVFILE" "$RUNCMD"
    if [ "$USE_NGINX" = 1 ]; then
        driver_service_install_nginx "$RH_NGINX_BIN" "$RH_NGINX_PREFIX" "$RH_NGINX_CONF"
    fi
    log "[7/7] start"; driver_start
    if [ "$USE_NGINX" = 1 ]; then driver_start_nginx; fi
else
    log "[6/7] service skipped (--no-service)"; log "[7/7] start: run '$RUNCMD'"
fi

if [ "$UNSEAL_AT_INSTALL" = 0 ]; then
    # No password supplied: leave it sealed and write nothing. Anything the
    # installer could store here would be a credential the operator never
    # asked it to create.
    log "done. vault is SEALED and no credentials were written."
    log "  Unseal it to finish. The FIRST unseal sets the master password and"
    log "  returns a one-time root token; later ones reopen it with that password."
    log "  Because nothing is on disk, the vault cannot reopen itself after a"
    log "  restart -- unattended unseal needs the password readable by the machine."
    log "  Pass --master-password-file FILE if you want that instead."
else
    log "unseal"
    _minted_rt=$(unseal_vault "https://$LOCAL_HOST:$API_PORT" "$MASTER_PW" "$TLS_CERT")
    [ -n "$_minted_rt" ] && ROOT_TOKEN="$_minted_rt"   # first-boot/restore mints one; else keep the saved one
    # One credential layout across every installer: <base>/secrets/<name>, one
    # secret per file, mode 0400 in a 0700 directory. install-container.sh and
    # tools/quickstart-laptop.sh already used it; this path wrote a single
    # KEY=VALUE rhorizon.env-secrets instead, so no instruction covered both
    # and the docs described a native path that did not exist.
    #
    # One secret per file also means `cat` reads a credential without parsing,
    # which is what the docs and the printed RH_TOKEN hint assume.
    #
    # rhorizon.env-secrets is READ above so an install made before this keeps
    # working, and refreshed below ONLY IF IT ALREADY EXISTS.
    #
    # It must never be created on a fresh install. Writing it unconditionally
    # turned two secrets into three files -- master-password, root-token, AND a
    # third holding both -- which is more exposure than the single file this
    # was meant to replace, not less. One extra copy of a credential that grants
    # full control is one extra thing to find, back up by accident, or miss when
    # deleting.
    [ "$DRY_RUN" = 1 ] || { umask 077
        run mkdir -p "$SECRET_DIR"
        run chmod 700 "$SECRET_DIR"
        printf '%s' "$MASTER_PW" > "$SECRET_DIR/master-password"
        chmod 0400 "$SECRET_DIR/master-password"
        if [ -n "$ROOT_TOKEN" ]; then
            printf '%s' "$ROOT_TOKEN" > "$SECRET_DIR/root-token"
            chmod 0400 "$SECRET_DIR/root-token"
        fi
        if [ -f "$SECRET_FILE" ]; then
            {
                printf 'MASTER_PASSWORD=%s\n' "$MASTER_PW"
                [ -n "$ROOT_TOKEN" ] && printf 'ROOT_TOKEN=%s\n' "$ROOT_TOKEN"
            } > "$SECRET_FILE"
            _legacy_secret_file=1
        fi
    }
    if [ -n "$ROOT_TOKEN" ]; then log "done. master password + admin root token saved in $SECRET_DIR/ (mode 0400)"
    else log "done. master password saved in $SECRET_DIR/master-password (mode 0400; no root token minted -- reuse an existing admin token)"; fi
    # The convenience and the exposure are the same fact: this host can reopen
    # the vault unattended precisely because the password is readable on it.
    log "SECURITY: $SECRET_DIR/ now holds credentials sufficient for full control"
    log "  of this instance. Move them into a password manager and delete them,"
    log "  or keep them and accept that anyone who can read them can unseal this vault."
    if [ -n "${_legacy_secret_file:-}" ]; then
        # Pre-existing install: it has been mirrored into the new layout, so the
        # old file is now a REDUNDANT third copy of the same two secrets. Say so
        # and let the operator delete it -- removing a credential file on their
        # behalf is not this script's call.
        log "NOTE: $SECRET_FILE predates the shared layout and still holds both"
        log "  secrets. They are now in $SECRET_DIR/ as well, so that file is a"
        log "  redundant copy -- delete it once you have checked the new one:"
        log "      rm $SECRET_FILE"
    fi
fi
log "vault: https://$LOCAL_HOST:$API_PORT"
log "clients need the CA file -- add to your shell profile:"
log "    export RH_ADDR=https://$LOCAL_HOST:$API_PORT"
log "    export RH_CA_FILE=$TLS_CERT"
# System mode keeps CONFIG_DIR at 0700 root-only, so a non-root client cannot
# read the cert in place. Say so rather than let it fail as a permission error.
if [ "$RH_MODE" = system ]; then
    log "    (system mode: copy it out first -- sudo cp $TLS_CERT ~/rhorizon-ca.pem)"
fi
