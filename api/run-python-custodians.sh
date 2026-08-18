#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

# One Python custodian per slot, each on its OWN Unix socket.
#
# The pool used to be a single uvicorn with --workers N behind one shared
# socket. That works, but it makes the elected master unaddressable: a shared
# listener cannot name a process, so the control plane reached the master by
# re-dialling until the kernel happened to hand it over. Measured on three
# custodians, the same workload cost 4, 5, 7 and 41 re-dials across four runs,
# each re-sending the whole request body -- which on unseal and rotate-password
# is the master password. The kernel favours the most recently active child, so
# the "expected probes is the pool size" model does not hold.
#
# A socket per slot makes the master directly addressable. Separated custody
# exists so the key holder is not the thing every request queues behind;
# hunting for it with retries gives that back.
#
# Structure deliberately mirrors run-rust-custodians.sh: same validation, same
# supervise-and-restart loop, same cleanup, so run-api.sh treats both backends
# identically -- one supervisor pid either way.

set -eu
umask 077

disable_core_dumps=${RH_DISABLE_CORE_DUMPS:-${RHORIZON_DISABLE_CORE_DUMPS:-true}}
case "$disable_core_dumps" in
    1|true|TRUE|yes|YES|on|ON)
        ulimit -S -c 0 && ulimit -H -c 0 || {
            echo "[rhorizon] could not disable core dumps before starting custody" >&2
            exit 1
        }
        ;;
    0|false|FALSE|no|NO|off|OFF) ;;
    *) echo "[rhorizon] RH_DISABLE_CORE_DUMPS must be a boolean" >&2; exit 1 ;;
esac

slots=${RH_CUSTODIAN_WORKERS:-${RHORIZON_CUSTODIAN_WORKERS:-5}}
runtime_dir=${RH_RUNTIME_DIR:-${RHORIZON_RUNTIME_DIR:-/run/rhorizon}}
host=${HOSTNAME:-$(hostname 2>/dev/null || echo default)}

case "$slots" in
    3|5|7|9) ;;
    *) echo "[rhorizon] RH_CUSTODIAN_WORKERS must be 3, 5, 7, or 9" >&2; exit 2 ;;
esac

case "$runtime_dir" in
    /|/run|/tmp|'') echo "[rhorizon] refusing unsafe runtime directory" >&2; exit 2 ;;
    /*) ;;
    *) echo "[rhorizon] runtime directory must be absolute" >&2; exit 2 ;;
esac
[ ! -L "$runtime_dir" ] || {
    echo "[rhorizon] runtime directory must not be a symlink" >&2
    exit 2
}
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"

socket_for() { echo "$runtime_dir/custodian-$host-$1.sock"; }

pid_1=""; pid_2=""; pid_3=""; pid_4=""; pid_5=""
pid_6=""; pid_7=""; pid_8=""; pid_9=""

set_slot_pid() {
    case "$1" in
        1) pid_1=$2 ;; 2) pid_2=$2 ;; 3) pid_3=$2 ;;
        4) pid_4=$2 ;; 5) pid_5=$2 ;; 6) pid_6=$2 ;;
        7) pid_7=$2 ;; 8) pid_8=$2 ;; 9) pid_9=$2 ;;
        *) echo "[rhorizon] invalid internal custodian slot $1" >&2; exit 1 ;;
    esac
}

load_slot_pid() {
    case "$1" in
        1) slot_pid=$pid_1 ;; 2) slot_pid=$pid_2 ;; 3) slot_pid=$pid_3 ;;
        4) slot_pid=$pid_4 ;; 5) slot_pid=$pid_5 ;; 6) slot_pid=$pid_6 ;;
        7) slot_pid=$pid_7 ;; 8) slot_pid=$pid_8 ;; 9) slot_pid=$pid_9 ;;
        *) echo "[rhorizon] invalid internal custodian slot $1" >&2; exit 1 ;;
    esac
}

start_slot() {
    start_slot_number=$1
    socket=$(socket_for "$start_slot_number")
    # Liveness, not inode existence, decides whether the path is reclaimable.
    # The probe removes only an orphan and refuses a live or unanswerable
    # socket, so a second launcher cannot unlink a running custodian.
    python -m app.socket_paths "$socket" || {
        echo "[rhorizon] refusing to start Python custodian slot $start_slot_number: socket ownership is not safely reclaimable" >&2
        exit 1
    }
    # RH_CUSTODIAN_SLOT is what lets the process publish its own socket in
    # vault_workers, which is how the control plane addresses it.
    RH_PROCESS_ROLE=custodian \
    RH_CUSTODIAN_SLOT="$start_slot_number" \
    RH_WORKERS=1 \
        python -m uvicorn app.main:app --uds "$socket" \
        --http httptools --loop uvloop --timeout-keep-alive 30 \
        --backlog 4096 --limit-concurrency 250 --workers 1 &
    set_slot_pid "$start_slot_number" "$!"
}

wait_slot_ready() {
    wait_slot_number=$1
    attempt=0
    while [ "$attempt" -lt 300 ]; do
        load_slot_pid "$wait_slot_number"
        if ! kill -0 "$slot_pid" 2>/dev/null; then
            return 1
        fi
        if [ -S "$(socket_for "$wait_slot_number")" ]; then
            return 0
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    return 1
}

cleanup() {
    trap - EXIT INT TERM
    slot=1
    while [ "$slot" -le "$slots" ]; do
        load_slot_pid "$slot"
        [ -z "$slot_pid" ] || kill -TERM "$slot_pid" 2>/dev/null || true
        slot=$((slot + 1))
    done
    slot=1
    while [ "$slot" -le "$slots" ]; do
        socket=$(socket_for "$slot")
        [ ! -S "$socket" ] || rm -f "$socket"
        slot=$((slot + 1))
    done
    slot=1
    while [ "$slot" -le "$slots" ]; do
        load_slot_pid "$slot"
        [ -z "$slot_pid" ] || wait "$slot_pid" 2>/dev/null || true
        slot=$((slot + 1))
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Refuse the whole pool before starting any process when even one path is live
# or cannot be inspected. This avoids bringing up a partial quorum.
set --
slot=1
while [ "$slot" -le "$slots" ]; do
    socket=$(socket_for "$slot")
    if [ -L "$socket" ]; then
        echo "[rhorizon] refusing symlinked custodian socket $socket" >&2
        exit 1
    fi
    set -- "$@" "$socket"
    slot=$((slot + 1))
done
python -m app.socket_paths "$@" || {
    echo "[rhorizon] refusing to start the Python custodian pool: socket ownership is not safely reclaimable" >&2
    exit 1
}

slot=1
while [ "$slot" -le "$slots" ]; do
    start_slot "$slot"
    slot=$((slot + 1))
done

slot=1
while [ "$slot" -le "$slots" ]; do
    if ! wait_slot_ready "$slot"; then
        echo "[rhorizon] Python custodian slot $slot did not become ready" >&2
        exit 1
    fi
    slot=$((slot + 1))
done

echo "[rhorizon] Python custodian pool ready: $slots addressable slots" >&2
while :; do
    slot=1
    while [ "$slot" -le "$slots" ]; do
        load_slot_pid "$slot"
        if ! kill -0 "$slot_pid" 2>/dev/null; then
            set +e
            wait "$slot_pid"
            status=$?
            set -e
            echo "[rhorizon] Python custodian slot $slot exited ($status); restarting" >&2
            start_slot "$slot"
            if ! wait_slot_ready "$slot"; then
                echo "[rhorizon] Python custodian slot $slot restart failed" >&2
                exit 1
            fi
        fi
        slot=$((slot + 1))
    done
    sleep 1
done
