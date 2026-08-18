#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

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

binary=${RH_RUST_CUSTODIAN_BINARY:-${RHORIZON_RUST_CUSTODIAN_BINARY:-rhorizon-custodian}}
slots=${RH_RUST_CUSTODIAN_SLOTS:-${RHORIZON_RUST_CUSTODIAN_SLOTS:-3}}
threshold=${RH_RUST_CUSTODIAN_THRESHOLD:-${RHORIZON_RUST_CUSTODIAN_THRESHOLD:-}}
runtime_dir=${RH_RUNTIME_DIR:-${RHORIZON_RUNTIME_DIR:-/run/rhorizon}}
key_dir=${RH_RUST_CUSTODIAN_KEY_DIR:-${RHORIZON_RUST_CUSTODIAN_KEY_DIR:-/var/lib/rhorizon/custody}}
threads=${RH_RUST_CUSTODIAN_THREADS:-${RHORIZON_RUST_CUSTODIAN_THREADS:-}}
control_token=${RH_CUSTODIAN_TOKEN_FILE:-${RHORIZON_CUSTODIAN_TOKEN_FILE:-$runtime_dir/custodian-control.token}}
# Where the key that protects a PERSISTED share comes from. "none" (the
# default) means the share is never written: it lives in the daemon's locked
# memory and nowhere else.
#
# Persisting is only safe if the state file is wrapped by a secret that is NOT
# on the same disk. Today the sealed state is opened with a key derived from
# the transport key stored beside it, so a copy of $key_dir yields shares --
# and with threshold-many slots co-located, the whole sub-key bundle. No
# password is involved.
#
# What persistence actually buys is narrow: a surviving quorum already refills
# an empty slot by itself, so the file only matters when FEWER than threshold
# custodians still hold a share (simultaneous multi-daemon loss, or a host
# reboot). That is not worth the at-rest guarantee, so it is off until a
# provider (tpm2, yubikey) can wrap the transport key off-disk.
state_provider=${RH_RUST_CUSTODIAN_STATE_PROVIDER:-${RHORIZON_RUST_CUSTODIAN_STATE_PROVIDER:-none}}

case "$slots" in
    3|5|7|9) ;;
    *) echo "[rhorizon] RH_RUST_CUSTODIAN_SLOTS must be 3, 5, 7, or 9" >&2; exit 2 ;;
esac
case "$state_provider" in
    none) ;;
    tpm2|yubikey)
        # Refuse rather than silently falling back to on-disk persistence: an
        # operator who asked for a hardware-protected share must not get an
        # unprotected one because the provider is not built yet.
        echo "[rhorizon] RH_RUST_CUSTODIAN_STATE_PROVIDER=$state_provider is not implemented yet" >&2
        exit 2 ;;
    *)
        echo "[rhorizon] RH_RUST_CUSTODIAN_STATE_PROVIDER must be none, tpm2, or yubikey" >&2
        exit 2 ;;
esac
if [ -z "$threshold" ] || [ "$threshold" = 0 ]; then
    threshold=$((slots / 2 + 1))
fi
case "$threshold" in
    ''|*[!0-9]*)
        echo "[rhorizon] RH_RUST_CUSTODIAN_THRESHOLD must be an integer" >&2
        exit 2
        ;;
esac
if [ "$threshold" -lt 2 ] || [ "$threshold" -gt "$slots" ]; then
    echo "[rhorizon] RH_RUST_CUSTODIAN_THRESHOLD must be between 2 and $slots" >&2
    exit 2
fi

case "$runtime_dir" in
    /|/run|/tmp|'') echo "[rhorizon] refusing unsafe runtime directory" >&2; exit 2 ;;
    /*) ;;
    *) echo "[rhorizon] runtime directory must be absolute" >&2; exit 2 ;;
esac
case "$key_dir" in
    /|/var|/var/lib|/tmp|'') echo "[rhorizon] refusing unsafe custody key directory" >&2; exit 2 ;;
    /*) ;;
    *) echo "[rhorizon] custody key directory must be absolute" >&2; exit 2 ;;
esac
case "$control_token" in
    /*) ;;
    *) echo "[rhorizon] custodian control token path must be absolute" >&2; exit 2 ;;
esac
if [ "$(dirname "$control_token")" != "$runtime_dir" ]; then
    echo "[rhorizon] custodian control token must be directly under the runtime directory" >&2
    exit 2
fi

[ ! -L "$runtime_dir" ] || {
    echo "[rhorizon] runtime directory must not be a symlink" >&2
    exit 2
}
[ ! -L "$key_dir" ] || {
    echo "[rhorizon] custody key directory must not be a symlink" >&2
    exit 2
}
mkdir -p "$runtime_dir" "$key_dir"
chmod 700 "$runtime_dir" "$key_dir"

if [ "$state_provider" = none ]; then
    # Persistence is off, so any state file already here is exactly the
    # material this change exists to remove: sub-key shares openable with the
    # transport key sitting beside them. Dropping it is safe while the pool is
    # up -- the daemons hold their shares in locked memory, and an empty slot
    # is refilled from the surviving quorum.
    #
    # Honest limit: unlink is not erasure. On journalling filesystems, CoW
    # filesystems, and SSDs with wear levelling, overwrite-in-place does not
    # reliably destroy the old blocks, so `shred` would buy assurance it
    # cannot deliver. Erasure of what was ALREADY written requires full-disk
    # encryption or destroying the medium; what this guarantees is that
    # nothing further is written.
    for stale in "$key_dir"/slot-*.share-state; do
        [ -e "$stale" ] || continue
        rm -f "$stale"
        echo "[rhorizon] removed persisted custodian share state $stale" >&2
    done
fi

if [ ! -e "$control_token" ]; then
    "$binary" generate-control-token --output "$control_token"
fi

slot=1
while [ "$slot" -le "$slots" ]; do
    key_file="$key_dir/slot-$slot.transport-key"
    public_file="$runtime_dir/rust-custodian-$slot.public"
    if [ -L "$public_file" ]; then
        echo "[rhorizon] refusing symlinked public-key scratch file $public_file" >&2
        exit 1
    fi
    if [ -e "$public_file" ]; then
        # Our own litter from an incarnation that died before cleanup ran --
        # note the redirect below CREATES this file, so even a failed exec of
        # the custodian binary leaves one. The runtime directory is 0700 and
        # owned by this service, so a regular file here cannot be a plant.
        #
        # Refusing it outright wedges every future start on a systemd node,
        # where RuntimeDirectoryPreserve keeps the directory across restarts:
        # one unclean exit and the service crash-loops until a human deletes
        # the file. A container never showed this because its /run is a fresh
        # tmpfs per start. Anything that is not a regular file is still a
        # refusal.
        if [ ! -f "$public_file" ]; then
            echo "[rhorizon] refusing non-regular public-key scratch file $public_file" >&2
            exit 1
        fi
        rm -f "$public_file"
    fi
    set -C
    if [ ! -e "$key_file" ]; then
        "$binary" generate-transport-key --output "$key_file" > "$public_file"
    else
        "$binary" print-transport-public-key \
            --transport-key-file "$key_file" > "$public_file"
    fi
    set +C
    public_key=$(tr -d '\n' < "$public_file")
    case "$public_key" in
        *[!0-9a-f]*|'')
            echo "[rhorizon] invalid transport public key for slot $slot" >&2
            exit 1
            ;;
    esac
    if [ "${#public_key}" -ne 64 ]; then
        echo "[rhorizon] invalid transport public key length for slot $slot" >&2
        exit 1
    fi
    slot=$((slot + 1))
done

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
    socket="$runtime_dir/rust-custodian-$start_slot_number.sock"
    # The persisted share state is named after the topology it belongs to, so
    # relaunching the pool under a reshare target writes BESIDE the current
    # shape's state instead of over it. Reverting the environment and
    # restarting therefore still finds the shares it left behind.
    share_state="$key_dir/slot-$start_slot_number.$threshold-of-$slots.share-state"
    legacy_share_state="$key_dir/slot-$start_slot_number.share-state"
    set -- "$binary" \
        --socket "$socket" \
        --control-token-file "$control_token" \
        --transport-key-file "$key_dir/slot-$start_slot_number.transport-key" \
        --threshold "$threshold" \
        --slots "$slots" \
        --slot "$start_slot_number"
    if [ "$state_provider" != none ]; then
        # The persisted share state is named after the topology it belongs to,
        # so relaunching the pool under a reshare target writes BESIDE the
        # current shape's state instead of over it. Reverting the environment
        # and restarting therefore still finds the shares it left behind.
        set -- "$@" --share-state-file "$share_state"
        # Pools created before the name carried the topology adopt their state
        # once, under the shape they are launched with; the daemon refuses to
        # start if it does not authenticate as that shape.
        [ ! -e "$legacy_share_state" ] || \
            set -- "$@" --adopt-share-state-file "$legacy_share_state"
    fi
    # Unset means "use the daemon's own default"; only forward an explicit
    # operator choice so the default lives in one place.
    [ -z "$threads" ] || set -- "$@" --threads "$threads"
    peer=1
    while [ "$peer" -le "$slots" ]; do
        if [ "$peer" -ne "$start_slot_number" ]; then
            peer_public=$(tr -d '\n' < "$runtime_dir/rust-custodian-$peer.public")
            set -- "$@" --peer-key "$peer:$peer_public"
        fi
        peer=$((peer + 1))
    done
    "$@" &
    set_slot_pid "$start_slot_number" "$!"
}

wait_slot_ready() {
    wait_slot_number=$1
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        load_slot_pid "$wait_slot_number"
        if ! kill -0 "$slot_pid" 2>/dev/null; then
            return 1
        fi
        if [ -S "$runtime_dir/rust-custodian-$wait_slot_number.sock" ]; then
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
    # Unlink BEFORE waiting on the children, not after.
    #
    # systemd sends SIGTERM, then SIGKILLs the whole cgroup once
    # TimeoutStopSec expires. With the unlink last, a wait that outlived that
    # timeout meant the unlink never ran and every socket leaked -- the exact
    # sequence that stranded rust-custodian-2/3.sock across a CLEAN stop.
    # The pool is going down regardless once TERM is sent, so removing the
    # inode first costs nothing and survives being killed mid-shutdown.
    slot=1
    while [ "$slot" -le "$slots" ]; do
        socket="$runtime_dir/rust-custodian-$slot.sock"
        public_file="$runtime_dir/rust-custodian-$slot.public"
        [ ! -S "$socket" ] || rm -f "$socket"
        rm -f "$public_file"
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

# Reclaim orphaned sockets before starting anything.
#
# "The file exists" is NOT "a daemon owns it". The EXIT trap below unlinks
# sockets only after waiting on every child, so a stop-timeout SIGKILL leaves
# them behind. Refusing on mere existence then aborted the WHOLE loop at the
# first leftover -- slot 1 up, slot 2 refused, slot 3 never reached -- leaving
# the pool below threshold, which no unseal can recover from.
#
# app.socket_paths decides liveness with the fail-closed connect-probe and
# unlinks only what nothing is listening on. A live listener still refuses
# (exit 1): that means a second pool is running, which must not be papered
# over. Anything else (including no interpreter, exit 127) also refuses,
# so an unanswerable probe never licenses an unlink.
sockets_to_acquire=""
slot=1
while [ "$slot" -le "$slots" ]; do
    socket="$runtime_dir/rust-custodian-$slot.sock"
    # Refused outright, as in run-python-custodians.sh: the probe below would
    # follow the link and could unlink through it, and the daemon would bind
    # through it too. A symlink here is never something we created.
    if [ -L "$socket" ]; then
        echo "[rhorizon] refusing symlinked custodian socket $socket" >&2
        exit 1
    fi
    sockets_to_acquire="$sockets_to_acquire $socket"
    slot=$((slot + 1))
done
# shellcheck disable=SC2086 # deliberate word-splitting of the path list
if ! python -m app.socket_paths $sockets_to_acquire; then
    echo "[rhorizon] refusing to start the custodian pool" >&2
    exit 1
fi

slot=1
while [ "$slot" -le "$slots" ]; do
    start_slot "$slot"
    slot=$((slot + 1))
done

slot=1
while [ "$slot" -le "$slots" ]; do
    if ! wait_slot_ready "$slot"; then
        echo "[rhorizon] Rust custodian slot $slot did not become ready" >&2
        exit 1
    fi
    slot=$((slot + 1))
done

echo "[rhorizon] Rust custodian pool ready: $threshold-of-$slots (sealed)" >&2
while :; do
    slot=1
    while [ "$slot" -le "$slots" ]; do
        load_slot_pid "$slot"
        if ! kill -0 "$slot_pid" 2>/dev/null; then
            set +e
            wait "$slot_pid"
            status=$?
            set -e
            echo "[rhorizon] Rust custodian slot $slot exited ($status); restarting" >&2
            socket="$runtime_dir/rust-custodian-$slot.sock"
            [ ! -S "$socket" ] || rm -f "$socket"
            start_slot "$slot"
            if ! wait_slot_ready "$slot"; then
                echo "[rhorizon] Rust custodian slot $slot restart failed" >&2
                exit 1
            fi
            echo "[rhorizon] Rust custodian slot $slot restarted sealed" >&2
        fi
        slot=$((slot + 1))
    done
    sleep 1
done
