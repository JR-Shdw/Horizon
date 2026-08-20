#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon macOS native installer -- Homebrew deps + production-style user
# install.
#
# Validated on Apple Silicon: .github/workflows/macos-native.yml runs this
# end-to-end on GitHub-hosted macos-latest (Homebrew deps -> PostgreSQL -> venv
# -> Rust extension -> LaunchAgent -> unseal) and asserts the vault serves and
# unseals. Intel is NOT covered -- GitHub retired the macos-13 image and there
# is no free x86_64 darwin runner, so that arch is unverified rather than
# known-broken.
#
# --mode user is the only mode implemented; system mode is documented as intent.
# --dry-run previews everything without touching the machine.
#
# Path convention:
#   user mode (implemented):
#     app/venv        ~/Library/Application Support/rhorizon
#     config/secrets  ~/Library/Application Support/rhorizon/config
#     state           ~/Library/Application Support/rhorizon/state
#     runtime         ${TMPDIR}/rhorizon
#     audit/logs      ~/Library/Logs/rhorizon
#     service         ~/Library/LaunchAgents/com.resurgamus.rhorizon.plist
#
#   system mode (documented, not implemented here):
#     app/venv        /Library/Application Support/rhorizon
#     config/secrets  /Library/Application Support/rhorizon/config
#     state           /Library/Application Support/rhorizon/state
#     runtime         /var/run/rhorizon
#     audit/logs      /Library/Logs/rhorizon
#     service         /Library/LaunchDaemons/com.resurgamus.rhorizon.plist
#
# Homebrew's prefix (/opt/homebrew on Apple silicon, /usr/local on Intel) is
# used only for dependencies and PostgreSQL's own data directory, not for
# rhorizon's application state.
#
#   sh tools/install-macos.sh [--mode user] [--workers N] [--dry-run]
#       [--dir APP_DIR] [--config-dir DIR] [--state-dir DIR]
#       [--runtime-dir DIR] [--audit-dir DIR] [--bind ADDR] [--api-port N]
#       [--master-password-file FILE] [--external-db URL]
#       [--memory-lock-mode best-effort|required] [--no-service]

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/tools/lib/common.sh"

# RH_* is the canonical env prefix product-wide; promote any RH_<X> over its
# deprecated RHORIZON_<X> alias so the reads below honor the canonical name.
for _rn in DIR CONFIG_DIR STATE_DIR RUNTIME_DIR AUDIT_DIR API_PORT FRONTEND_PORT \
        FRONTEND_HTTP_PORT BIND API_BIND TIER PERSIST WORKERS MASTER_PASSWORD \
        MEMORY_LOCK_MODE MCP_VENV MCP_TOKEN_FILE MCP_POLICY MCP_TOKEN_NAME \
        SWAP_PROTECTION \
        REPO_BASE REPO_RAW REPO_GIT; do
    eval "_rv=\${RH_${_rn}:-}"
    if [ -n "${_rv}" ]; then eval "RHORIZON_${_rn}=\${_rv}"; fi
done
unset _rn _rv
DRY_RUN=0; RH_MODE=user; WORK_DIR="${RHORIZON_DIR:-}"; BIND="${RHORIZON_BIND:-127.0.0.1}"
CONFIG_DIR="${RHORIZON_CONFIG_DIR:-}"
STATE_DIR="${RHORIZON_STATE_DIR:-}"
RUNTIME_DIR="${RHORIZON_RUNTIME_DIR:-}"
AUDIT_DIR="${RHORIZON_AUDIT_DIR:-}"
API_PORT="${RHORIZON_API_PORT:-8200}"
MASTER_PW="${RHORIZON_MASTER_PASSWORD:-}"
EXTERNAL_DB=""
WANT_SERVICE=1
WORKERS="${RHORIZON_WORKERS:-1}"
MEMORY_LOCK_MODE="${RHORIZON_MEMORY_LOCK_MODE:-best-effort}"
SWAP_PROTECTION="${RHORIZON_SWAP_PROTECTION:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --mode) RH_MODE=$2; shift ;;
        --workers) WORKERS=$2; shift ;;
        --dir) WORK_DIR=$2; shift ;;
        --config-dir) CONFIG_DIR=$2; shift ;;
        --state-dir) STATE_DIR=$2; shift ;;
        --runtime-dir) RUNTIME_DIR=$2; shift ;;
        --audit-dir) AUDIT_DIR=$2; shift ;;
        --bind) BIND=$2; shift ;;
        --api-port) API_PORT=$2; shift ;;
        # A secret passed in argv is world-readable in /proc/<pid>/cmdline for
        # the life of the process and lands in shell history. Kept for
        # compatibility, but it warns and --master-password-file is preferred.
        --master-password) MASTER_PW=$2; MASTER_PW_FROM_ARGV=1; shift ;;
        --master-password-file) MASTER_PW_FILE=$2; shift ;;
        --external-db) EXTERNAL_DB=$2; shift ;;
        --memory-lock-mode) MEMORY_LOCK_MODE=$2; shift ;;
        --no-service) WANT_SERVICE=0 ;;
        # Through 43, not 32: the invocation synopsis lives at 39-43, so the
        # option list was never actually printed by --help.
        -h|--help) sed -n '5,43p' "$0"; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done

# Checked here, not at the staging in [5/7]: that runs after Homebrew and the
# PostgreSQL setup, so a typo'd path would fail several minutes into an install
# rather than immediately. The bytes are read later; this only proves the file
# is there and non-empty.
if [ -n "${MASTER_PW_FILE:-}" ]; then
    [ -f "$MASTER_PW_FILE" ] || { printf 'master password file not found: %s\n' "$MASTER_PW_FILE" >&2; exit 1; }
    [ -s "$MASTER_PW_FILE" ] || { printf 'master password file is empty: %s\n' "$MASTER_PW_FILE" >&2; exit 1; }
fi
if [ -n "${MASTER_PW_FROM_ARGV:-}" ]; then
    printf '%s\n' \
      "WARNING: --master-password puts the secret in this process's command line" \
      "         (readable via ps) and in your shell history." \
      "         Prefer --master-password-file FILE." >&2
fi

case "$RH_MODE" in
    user) ;;
    system)
        if [ "$DRY_RUN" != 1 ]; then
            die "macOS system mode is documented but not implemented; use --mode user or Docker Desktop"
        fi
        ;;
    *) die "bad --mode: $RH_MODE (user|system)" ;;
esac
case "$WORKERS" in ''|*[!0-9]*) die "--workers must be a positive integer" ;; esac
[ "$WORKERS" -ge 1 ] || die "--workers must be >= 1"
case "$MEMORY_LOCK_MODE" in
    best-effort|required) ;;
    *) die "--memory-lock-mode must be best-effort or required" ;;
esac
case "$SWAP_PROTECTION" in
    ""|protected|unencrypted|unknown) ;;
    *) die "RH_SWAP_PROTECTION must be protected, unencrypted, or unknown" ;;
esac

if [ "$(uname -s)" != Darwin ] && [ "$DRY_RUN" != 1 ]; then
    die "tools/install-macos.sh must run on macOS (Darwin)"
fi

if [ "$RH_MODE" = user ]; then
    MAC_APP_BASE="$HOME/Library/Application Support/rhorizon"
    [ -n "$WORK_DIR" ] || WORK_DIR="$MAC_APP_BASE"
    [ -n "$CONFIG_DIR" ] || CONFIG_DIR="$MAC_APP_BASE/config"
    [ -n "$STATE_DIR" ] || STATE_DIR="$MAC_APP_BASE/state"
    _tmp="${TMPDIR:-/tmp}"
    _tmp=${_tmp%/}
    [ -n "$RUNTIME_DIR" ] || RUNTIME_DIR="$_tmp/rhorizon"
    [ -n "$AUDIT_DIR" ] || AUDIT_DIR="$HOME/Library/Logs/rhorizon"
    PLIST="$HOME/Library/LaunchAgents/com.resurgamus.rhorizon.plist"
    LAUNCHD_DOMAIN="gui/$(id -u)"
else
    [ -n "$WORK_DIR" ] || WORK_DIR="/Library/Application Support/rhorizon"
    [ -n "$CONFIG_DIR" ] || CONFIG_DIR="/Library/Application Support/rhorizon/config"
    [ -n "$STATE_DIR" ] || STATE_DIR="/Library/Application Support/rhorizon/state"
    [ -n "$RUNTIME_DIR" ] || RUNTIME_DIR="/var/run/rhorizon"
    [ -n "$AUDIT_DIR" ] || AUDIT_DIR="/Library/Logs/rhorizon"
    PLIST="/Library/LaunchDaemons/com.resurgamus.rhorizon.plist"
    LAUNCHD_DOMAIN="system"
fi

export DRY_RUN
log "macOS native: mode=$RH_MODE app=$WORK_DIR config=$CONFIG_DIR state=$STATE_DIR runtime=$RUNTIME_DIR audit=$AUDIT_DIR dry-run=$DRY_RUN"
log "status: macOS skeleton/untested"

if command -v brew >/dev/null 2>&1; then
    BREW=$(brew --prefix)
    BREW_BIN=$(command -v brew)
elif [ "$DRY_RUN" = 1 ]; then
    BREW="${HOMEBREW_PREFIX:-/opt/homebrew}"
    BREW_BIN=brew
else
    die "Homebrew is required -- install it from https://brew.sh"
fi

log "[1/7] Homebrew packages"
run "$BREW_BIN" install python@3.12 rust postgresql@18 libsodium openldap pkgconf curl git

export PATH="${BREW}/opt/python@3.12/bin:${BREW}/opt/postgresql@18/bin:${PATH}"
export CFLAGS="-I${BREW}/include -I${BREW}/opt/openldap/include -I${BREW}/opt/libsodium/include"
export LDFLAGS="-L${BREW}/lib -L${BREW}/opt/openldap/lib -L${BREW}/opt/libsodium/lib"

PYBIN="${BREW}/opt/python@3.12/bin/python3.12"
VENV="$WORK_DIR/.venv"
RUN_APP="$WORK_DIR/run-app.sh"
ENVFILE="$CONFIG_DIR/rhorizon.env"
SECRET_FILE="$CONFIG_DIR/rhorizon.env-secrets"
PG_PW_FILE="$CONFIG_DIR/secrets/postgres-password"

log "[2/7] directories"
run mkdir -p "$WORK_DIR" "$CONFIG_DIR/secrets" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR"
run chmod 700 "$CONFIG_DIR" "$CONFIG_DIR/secrets" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR"

log "[3/7] venv + deps + rust ext"
make_venv "$PYBIN" "$VENV"
pip_install "$VENV" "$ROOT_DIR"
build_ext "$VENV" "$ROOT_DIR"

log "[4/7] database"
if [ -n "$EXTERNAL_DB" ]; then
    DB_URL="$EXTERNAL_DB"
    log "external db"
else
    : "${PG_PASSWORD:=$(gen_secret 24)}"
    if [ "$DRY_RUN" != 1 ]; then
        if [ -f "$PG_PW_FILE" ]; then
            PG_PASSWORD=$(cat "$PG_PW_FILE")
        else
            umask 077; printf '%s' "$PG_PASSWORD" > "$PG_PW_FILE"
            chmod 400 "$PG_PW_FILE"
        fi
    fi
    PGDATA="${BREW}/var/postgresql@18"
    if [ "$DRY_RUN" = 1 ]; then
        printf '   [dry-run] initdb/start Homebrew PostgreSQL at %s\n' "$PGDATA"
        printf '   [dry-run] create/alter role+db rhorizon\n'
    else
        if [ ! -d "$PGDATA/base" ]; then
            initdb -D "$PGDATA" -U "$(whoami)" --locale=en_US.UTF-8 >/dev/null
        fi
        pg_ctl -D "$PGDATA" status >/dev/null 2>&1 \
            || pg_ctl -D "$PGDATA" -l "$PGDATA/server.log" start
        sleep 3
        psql -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='rhorizon'" \
            | grep -q 1 || \
            psql -d postgres -c "CREATE USER rhorizon WITH PASSWORD '$PG_PASSWORD'"
        psql -d postgres -c "ALTER USER rhorizon WITH PASSWORD '$PG_PASSWORD'" >/dev/null
        psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='rhorizon'" \
            | grep -q 1 || \
            psql -d postgres -c "CREATE DATABASE rhorizon OWNER rhorizon"
        PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -U rhorizon -d rhorizon -f "$ROOT_DIR/schema.sql" >/dev/null
    fi
    DB_URL="postgresql+asyncpg://rhorizon:$PG_PASSWORD@127.0.0.1:5432/rhorizon"
fi

sq() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

xml_escape() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

log "[5/7] env + launch wrapper"
# Stage the master password in a FILE, never hand it to unseal_vault by value.
# A shell variable cannot carry a password that ends in a newline -- any $(...)
# on the way in strips all of them -- and a vault initialised with a truncated
# master password cannot be reopened with the one the operator holds. Same
# shape as tools/install-native.sh and tools/install-container.sh.
PW_STAGE=$(TMPDIR=/tmp mktemp)
chmod 0600 "$PW_STAGE"
trap 'rm -f "$PW_STAGE"' EXIT INT TERM
if [ -n "${MASTER_PW_FILE:-}" ]; then
    # python reads the bytes and removes at most ONE trailing newline, so
    # `printf secret >f` and `echo secret >f` still agree, and a password whose
    # last byte really is a newline survives. Same normalisation as the other
    # two installers, so one password file works against all three.
    python3 - "$MASTER_PW_FILE" "$PW_STAGE" <<'PY' || exit 1
import sys
data = open(sys.argv[1], "rb").read()
if data.endswith(b"\n"):
    data = data[:-1]
if not data:
    sys.exit("master password file is empty once its trailing newline is removed")
with open(sys.argv[2], "wb") as fh:
    fh.write(data)
PY
elif [ -n "$MASTER_PW" ]; then
    # argv / RH_MASTER_PASSWORD: already a shell string, so whatever it holds is
    # what the operator passed. Write it byte for byte.
    printf '%s' "$MASTER_PW" > "$PW_STAGE"
else
    # Last resort: mint one. Unlike install-native.sh, which stays SEALED when
    # given nothing, macOS keeps this path so an unattended run (the GitHub
    # Actions macOS runner is the only place this script is exercised end to
    # end) still reaches an unsealed vault and validates the whole install.
    # The $(...) capture is safe HERE specifically: gen_secret returns lowercase
    # hex, which contains no newline of its own, so stripping the one openssl
    # appends loses nothing.
    printf '%s' "$(gen_secret 24)" > "$PW_STAGE"
fi
# TLS is mandatory and uvicorn terminates it -- the native path has no nginx.
# Same helper and same reasoning as tools/install-native.sh.
ensure_tls_cert "$CONFIG_DIR/certs" "$BIND"
TLS_CERT="$CONFIG_DIR/certs/cert.pem"; TLS_KEY="$CONFIG_DIR/certs/key.pem"
case "$BIND" in
    0.0.0.0|'::'|'') LOCAL_HOST=127.0.0.1 ;;
    *) LOCAL_HOST=$BIND ;;
esac
if [ "$DRY_RUN" = 1 ]; then
    printf '   [dry-run] write %s\n' "$ENVFILE"
    printf '   [dry-run] write %s\n' "$RUN_APP"
else
    umask 077
    {
        printf 'RHORIZON_DATABASE_URL=%s\n' "$(sq "$DB_URL")"
        printf 'RHORIZON_DATABASE_SSL=false\n'
        printf 'RHORIZON_TLS_ENABLED=true\n'
        printf 'RHORIZON_TLS_CERT=%s\n' "$(sq "$TLS_CERT")"
        printf 'RHORIZON_TLS_KEY=%s\n' "$(sq "$TLS_KEY")"
        printf 'RHORIZON_BIND=%s\n' "$(sq "$BIND")"
        printf 'RHORIZON_API_PORT=%s\n' "$(sq "$API_PORT")"
        printf 'RHORIZON_WORKERS=%s\n' "$(sq "$WORKERS")"
        printf 'RH_MEMORY_LOCK_MODE=%s\n' "$(sq "$MEMORY_LOCK_MODE")"
        if [ -n "$SWAP_PROTECTION" ]; then
            printf 'RH_SWAP_PROTECTION=%s\n' "$(sq "$SWAP_PROTECTION")"
        fi
        printf 'RHORIZON_RUNTIME_DIR=%s\n' "$(sq "$RUNTIME_DIR")"
        printf 'RHORIZON_AUDIT_DIR=%s\n' "$(sq "$AUDIT_DIR")"
        printf 'RHORIZON_NODE_UUID_PATH=%s\n' "$(sq "$STATE_DIR/node-uuid")"
        printf 'RHORIZON_CLUSTER_CERT_PATH=%s\n' "$(sq "$STATE_DIR/cluster-cert.pem")"
        printf 'RHORIZON_CLUSTER_CERT_KEY_PATH=%s\n' "$(sq "$STATE_DIR/cluster-cert.key")"
    } > "$ENVFILE"
    chmod 600 "$ENVFILE"

    cat > "$RUN_APP" <<EOF
#!/bin/sh
ulimit -l unlimited 2>/dev/null || true
set -a
. '$ENVFILE'
set +a
mkdir -p "\$RHORIZON_RUNTIME_DIR" "\$RHORIZON_AUDIT_DIR"
exec '$VENV/bin/python' -m uvicorn app.main:app --app-dir '$ROOT_DIR/api' --host "\$RHORIZON_BIND" --port "\$RHORIZON_API_PORT" --workers "\$RHORIZON_WORKERS" --ssl-certfile "\$RHORIZON_TLS_CERT" --ssl-keyfile "\$RHORIZON_TLS_KEY"
EOF
    chmod 700 "$RUN_APP"
fi

log "[6/7] service"
if [ "$WANT_SERVICE" = 1 ]; then
    if [ "$DRY_RUN" = 1 ]; then
        printf '   [dry-run] write %s\n' "$PLIST"
        printf '   [dry-run] launchctl bootstrap %s %s\n' "$LAUNCHD_DOMAIN" "$PLIST"
        printf '   [dry-run] launchctl kickstart -k %s/com.resurgamus.rhorizon\n' "$LAUNCHD_DOMAIN"
    else
        mkdir -p "$(dirname "$PLIST")"
        cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.resurgamus.rhorizon</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "$RUN_APP")</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$(xml_escape "$ROOT_DIR")</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$(xml_escape "$AUDIT_DIR/service.out.log")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "$AUDIT_DIR/service.err.log")</string>
</dict>
</plist>
EOF
        chmod 644 "$PLIST"
        launchctl bootout "$LAUNCHD_DOMAIN" "$PLIST" >/dev/null 2>&1 || true
        launchctl bootstrap "$LAUNCHD_DOMAIN" "$PLIST"
        launchctl enable "$LAUNCHD_DOMAIN/com.resurgamus.rhorizon" >/dev/null 2>&1 || true
        launchctl kickstart -k "$LAUNCHD_DOMAIN/com.resurgamus.rhorizon" >/dev/null 2>&1 || true
    fi
else
    log "service skipped (--no-service); start manually with: $RUN_APP"
fi

log "[7/7] unseal"
if [ "$WANT_SERVICE" = 1 ]; then
    unseal_vault "https://$LOCAL_HOST:$API_PORT" "$PW_STAGE" "$TLS_CERT"
else
    log "unseal skipped because --no-service was used"
fi

if [ "$DRY_RUN" = 1 ]; then
    printf '   [dry-run] write %s\n' "$SECRET_FILE"
else
    # KEY=VALUE cannot represent a newline: it would end the line, so the file
    # would name a DIFFERENT password than the one the vault was initialised
    # with, and this is the only copy. Write the byte-exact form beside it and
    # say which one is real rather than record a password that does not work.
    umask 077
    if [ "$(wc -l < "$PW_STAGE")" -eq 0 ]; then
        printf 'MASTER_PASSWORD=%s\n' "$(cat "$PW_STAGE")" > "$SECRET_FILE"
    else
        cat "$PW_STAGE" > "$CONFIG_DIR/master-password"
        chmod 0400 "$CONFIG_DIR/master-password"
        log "NOTE: this master password contains a newline, which $SECRET_FILE"
        log "  cannot hold without changing it. The byte-exact copy is at"
        log "  $CONFIG_DIR/master-password -- that is the one that unseals."
    fi
fi

log "done. env=$ENVFILE service=$PLIST logs=$AUDIT_DIR"
log "vault: https://$LOCAL_HOST:$API_PORT"
log "clients need the CA file -- add to your shell profile:"
log "    export RH_ADDR=https://$LOCAL_HOST:$API_PORT"
log "    export RH_CA_FILE=$TLS_CERT"
