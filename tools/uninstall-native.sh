#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon native UNINSTALL -- reverses tools/install-native.sh. Idempotent:
# safe to re-run and safe on a partial install (every step guards on presence
# and ignores absence).
#
# Usage:
#   sh tools/uninstall-native.sh [--mode user|system] [--purge-db] [--yes]
#       [--dir D] [--config-dir D] [--state-dir D] [--runtime-dir D] [--audit-dir D]
#
#   --purge-db   ALSO drop the rhorizon PostgreSQL role + database. This
#                DESTROYS ALL VAULT DATA. Off by default (service + files only).
#   --yes / -y   non-interactive; skip the confirmation prompt.
#
# Path derivation mirrors install-native.sh -- keep the two in sync.
set -eu

DRY_RUN=0; RH_MODE="system"; PURGE_DB=0; ASSUME_YES=0
WORK_DIR=""; CONFIG_DIR=""; STATE_DIR=""; RUNTIME_DIR=""; AUDIT_DIR=""
# RH_* is the canonical env prefix product-wide; promote any RH_<X> over its
# deprecated RHORIZON_<X> alias so the reads below honor the canonical name.
for _rn in DIR CONFIG_DIR STATE_DIR RUNTIME_DIR AUDIT_DIR API_PORT WORKERS; do
    eval "_rv=\${RH_${_rn}:-}"
    if [ -n "${_rv}" ]; then eval "RHORIZON_${_rn}=\${_rv}"; fi
done
unset _rn _rv
API_PORT="${RHORIZON_API_PORT:-8200}"
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) RH_MODE=$2; shift ;;
        --purge-db) PURGE_DB=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --dir) WORK_DIR=$2; shift ;;
        --config-dir) CONFIG_DIR=$2; shift ;;
        --state-dir) STATE_DIR=$2; shift ;;
        --runtime-dir) RUNTIME_DIR=$2; shift ;;
        --audit-dir) AUDIT_DIR=$2; shift ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '5,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done
case "$RH_MODE" in user|system) ;; *) printf 'bad --mode: %s (user|system)\n' "$RH_MODE" >&2; exit 1 ;; esac
export DRY_RUN RH_MODE

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/tools/lib/common.sh"
detect_host                              # sets RH_OS / RH_ARCH / RH_DISTRO
DRIVER="$ROOT_DIR/tools/drivers/$RH_OS.sh"
[ -f "$DRIVER" ] || die "no driver for os=$RH_OS"
. "$DRIVER"

# --- path derivation: MIRROR install-native.sh -------------------------------
if [ "$RH_MODE" = user ]; then
    XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
    XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
    XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
    [ -n "$WORK_DIR" ]    || WORK_DIR="$XDG_DATA_HOME/rhorizon"
    [ -n "$CONFIG_DIR" ]  || CONFIG_DIR="$XDG_CONFIG_HOME/rhorizon"
    [ -n "$STATE_DIR" ]   || STATE_DIR="$XDG_STATE_HOME/rhorizon"
    [ -n "$RUNTIME_DIR" ] || RUNTIME_DIR="${XDG_RUNTIME_DIR:+$XDG_RUNTIME_DIR/rhorizon}"
    [ -n "$RUNTIME_DIR" ] || RUNTIME_DIR="$STATE_DIR/run"
    [ -n "$AUDIT_DIR" ]   || AUDIT_DIR="$STATE_DIR/audit"
else
    case "$RH_OS" in
        freebsd) _dw=/usr/local/rhorizon; _dc=/usr/local/etc/rhorizon; _ds=/var/db/rhorizon; _dr=/var/run/rhorizon; _da=/var/log/rhorizon ;;
        openbsd) _dw=/usr/local/rhorizon; _dc=/etc/rhorizon;           _ds=/var/db/rhorizon; _dr=/var/run/rhorizon; _da=/var/log/rhorizon ;;
        netbsd)  _dw=/usr/pkg/rhorizon;   _dc=/usr/pkg/etc/rhorizon;   _ds=/var/db/rhorizon; _dr=/var/run/rhorizon; _da=/var/log/rhorizon ;;
        *)       _dw=/opt/rhorizon;       _dc=/etc/rhorizon;           _ds=/var/lib/rhorizon; _dr=/run/rhorizon; _da=/var/log/rhorizon ;;
    esac
    [ -n "$WORK_DIR" ]    || WORK_DIR="$_dw"
    [ -n "$CONFIG_DIR" ]  || CONFIG_DIR="$_dc"
    [ -n "$STATE_DIR" ]   || STATE_DIR="$_ds"
    [ -n "$RUNTIME_DIR" ] || RUNTIME_DIR="$_dr"
    [ -n "$AUDIT_DIR" ]   || AUDIT_DIR="$_da"
fi
# Exported so driver_uninstall can strip matching SELinux fcontext specs.
export RH_NATIVE_WORK_DIR="$WORK_DIR" RH_NATIVE_CONFIG_DIR="$CONFIG_DIR" \
       RH_NATIVE_STATE_DIR="$STATE_DIR" RH_NATIVE_RUNTIME_DIR="$RUNTIME_DIR" \
       RH_NATIVE_AUDIT_DIR="$AUDIT_DIR"

log "uninstall: os=$RH_OS mode=$RH_MODE app=$WORK_DIR config=$CONFIG_DIR purge-db=$PURGE_DB dry-run=$DRY_RUN"

if [ "$ASSUME_YES" != 1 ] && [ "$DRY_RUN" != 1 ]; then
    printf 'This stops+removes the rhorizon service and deletes:\n'
    printf '  %s\n  %s\n  %s\n  %s\n  %s\n' "$WORK_DIR" "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR"
    [ "$PURGE_DB" = 1 ] && printf '  AND drops the PostgreSQL rhorizon role+database (ALL VAULT DATA LOST).\n'
    printf 'Type "yes" to proceed: '
    read _ans || _ans=""
    [ "$_ans" = yes ] || { echo "aborted"; exit 1; }
fi

# --- helpers -----------------------------------------------------------------
_rmsudo() { if [ "$(id -u)" = 0 ]; then run rm -rf "$1"; else run sudo rm -rf "$1"; fi; }
_rm() {
    [ -e "$1" ] || [ -L "$1" ] || return 0
    if [ "$RH_MODE" = user ]; then run rm -rf "$1"; else _rmsudo "$1"; fi
}

# --- [1/3] service + MAC policy (per-OS) -------------------------------------
log "[1/3] service"
driver_uninstall "$API_PORT"

# --- [2/3] database (optional, DESTRUCTIVE) ----------------------------------
if [ "$PURGE_DB" = 1 ]; then
    log "[2/3] database: dropping rhorizon role + db"
    driver_db_drop || true
else
    log "[2/3] database kept (pass --purge-db to drop rhorizon role+db)"
fi

# --- [3/3] files -------------------------------------------------------------
log "[3/3] files"
for _d in "$WORK_DIR" "$CONFIG_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR"; do _rm "$_d"; done

# No build-cache cleanup here, deliberately. An uninstaller must not rm -rf a
# path it merely guessed: /var/tmp/cargo may predate rhorizon or belong to
# another tool or user, and no amount of guarding makes deleting someone else's
# directory correct. The installer instead creates its build scratch with
# mktemp -d, owns it by construction, and removes it when the build finishes --
# so by the time anyone uninstalls there is nothing left to clean up.
[ "$RH_MODE" = user ] || _rm /app/schema.sql

log "done. rhorizon uninstalled (mode=$RH_MODE)."
# Say what is deliberately left, so nobody has to reverse-engineer it later.
# Packages are shared: removing nginx or postgresql could break other software
# on the host, so that stays an operator decision.
log "left in place: OS packages (nginx, postgresql, openssl, ...) and, unless"
log "  --purge-db was given, the rhorizon role + database."
if [ "$RH_MODE" = user ]; then
    log "  a --pq-nginx build installs under /usr/local or /usr/pkg (system"
    log "  paths) and is NOT part of a user-mode tree; remove it by hand."
fi
