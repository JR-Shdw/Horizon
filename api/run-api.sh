#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>

set -eu
umask 077

# Custodians are forked before FastAPI's lifespan hardening runs. Apply the
# crash-dump policy here so every child inherits it, including standalone
# custody daemons that may hold Shamir shares for the life of the process.
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

api_workers=${RH_WORKERS:-${RHORIZON_WORKERS:-5}}
custody_mode=${RH_CUSTODY_MODE:-${RHORIZON_CUSTODY_MODE:-embedded}}
custody_backend=${RH_CUSTODY_BACKEND:-${RHORIZON_CUSTODY_BACKEND:-python}}
custodian_workers=${RH_CUSTODIAN_WORKERS:-${RHORIZON_CUSTODIAN_WORKERS:-5}}
rust_custodian_slots=${RH_RUST_CUSTODIAN_SLOTS:-${RHORIZON_RUST_CUSTODIAN_SLOTS:-3}}
runtime_dir=${RH_RUNTIME_DIR:-${RHORIZON_RUNTIME_DIR:-/run/rhorizon}}
custodian_uds=${RH_CUSTODIAN_UDS_PATH:-${RHORIZON_CUSTODIAN_UDS_PATH:-$runtime_dir/custodian-http.sock}}
custodian_token=${RH_CUSTODIAN_TOKEN_FILE:-${RHORIZON_CUSTODIAN_TOKEN_FILE:-$runtime_dir/custodian-control.token}}
prom_dir=${PROMETHEUS_MULTIPROC_DIR:-/tmp/prom_multiproc}
listen_host=${RH_UVICORN_HOST:-0.0.0.0}
listen_port=${RH_UVICORN_PORT:-8200}
# The Rust launcher ships beside this script (/app in the image, api/ in a
# source tree). Resolving it relative to $0 keeps the container path identical
# while letting the native smoke harness drive the same production launcher.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

normalize_api_workers() {
    value=$1
    if [ "$value" -lt 1 ]; then value=1; fi
    # Embedded mode retains its 5-worker Shamir floor. Separated public API
    # workers hold no shares, so every positive pool size is valid.
    if [ "$custody_mode" = embedded ] && [ "$value" -gt 1 ] && [ "$value" -lt 5 ]; then
        echo "[rhorizon] RH_WORKERS=$value below embedded Shamir floor; using 5" >&2
        value=5
    fi
    if [ "$value" -gt 255 ]; then
        echo "[rhorizon] RH_WORKERS=$value exceeds the supported maximum of 255" >&2
        exit 1
    fi
    printf '%s\n' "$value"
}

api_workers=$(normalize_api_workers "$api_workers")
case "$custody_mode" in
    embedded|separated) ;;
    *) echo "[rhorizon] RH_CUSTODY_MODE must be embedded or separated" >&2; exit 1 ;;
esac
case "$custody_backend" in
    python|rust) ;;
    *) echo "[rhorizon] RH_CUSTODY_BACKEND must be python or rust" >&2; exit 1 ;;
esac
if [ "$custody_backend" = rust ] && [ "$custody_mode" != separated ]; then
    echo "[rhorizon] RH_CUSTODY_BACKEND=rust requires RH_CUSTODY_MODE=separated" >&2
    exit 1
fi
case "$rust_custodian_slots" in
    3|5|7|9) ;;
    *) echo "[rhorizon] RH_RUST_CUSTODIAN_SLOTS must be 3, 5, 7, or 9" >&2; exit 1 ;;
esac
case "$custodian_workers" in
    3|5|7|9) ;;
    *) echo "[rhorizon] RH_CUSTODIAN_WORKERS must be 3, 5, 7, or 9" >&2; exit 1 ;;
esac
case "$listen_port" in
    ''|*[!0-9]*) echo "[rhorizon] RH_UVICORN_PORT must be an integer" >&2; exit 1 ;;
esac
if [ "$listen_port" -lt 1 ] || [ "$listen_port" -gt 65535 ]; then
    echo "[rhorizon] RH_UVICORN_PORT must be between 1 and 65535" >&2
    exit 1
fi

rm -rf "$prom_dir"
mkdir -p "$prom_dir"
export PROMETHEUS_MULTIPROC_DIR="$prom_dir"

# Keep request.client as the kernel-observed nginx peer. Rhorizon validates the
# trusted proxy itself before consuming X-Forwarded-For or X-Client-Cert;
# letting Uvicorn rewrite request.client first destroys that trust boundary.
uvicorn_common="--http httptools --loop uvloop --no-proxy-headers --timeout-keep-alive 30 --backlog 4096 --limit-concurrency 250"

if [ "$custody_mode" = embedded ]; then
    export RH_PROCESS_ROLE=api
    exec python -m uvicorn app.main:app \
        --host "$listen_host" --port "$listen_port" \
        $uvicorn_common --workers "$api_workers"
fi

case "$custodian_uds" in
    /*) ;;
    *) echo "[rhorizon] custodian UDS path must be absolute" >&2; exit 1 ;;
esac
case "$custodian_token" in
    /*) ;;
    *) echo "[rhorizon] custodian token path must be absolute" >&2; exit 1 ;;
esac
case "$runtime_dir" in
    /|/run|/tmp|'') echo "[rhorizon] refusing unsafe runtime directory" >&2; exit 1 ;;
    /*) ;;
    *) echo "[rhorizon] runtime directory must be absolute" >&2; exit 1 ;;
esac
if [ "$(dirname "$custodian_uds")" != "$runtime_dir" ] \
    || [ "$(dirname "$custodian_token")" != "$runtime_dir" ]; then
    echo "[rhorizon] custody socket and token must be directly under the runtime directory" >&2
    exit 1
fi

mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir"
export RHORIZON_RUNTIME_DIR="$runtime_dir"
export RH_CUSTODIAN_UDS_PATH="$custodian_uds"
export RH_CUSTODIAN_TOKEN_FILE="$custodian_token"
if [ ! -e "$custodian_token" ]; then
    RH_CUSTODIAN_TOKEN_FILE="$custodian_token" python -c '
import os
import secrets

path = os.environ["RH_CUSTODIAN_TOKEN_FILE"]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, secrets.token_hex(32).encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
'
fi
chmod 600 "$custodian_token"
rm -f "$custodian_uds"

if [ "$custody_backend" = rust ]; then
    # The configured shape is what is WANTED, not necessarily what can be
    # launched. A topology change is prepared by a coordinator still running the
    # OLD shape, so a pool whose configuration has moved ahead comes up as the
    # shape that actually holds the shares and is relaunched once the change is
    # prepared. Launching a shape that holds nothing does not degrade: the API
    # refuses to start and no master password recovers it.
    launch_shape=$(python -m app.custody_launch) || {
        echo "[rhorizon] refusing to start: could not resolve the custodian launch topology" >&2
        exit 1
    }
    launch_threshold=${launch_shape% *}
    launch_slots=${launch_shape#* }
    echo "[rhorizon] starting standalone Rust custody quorum ($launch_threshold-of-$launch_slots)" >&2
    RH_RUST_CUSTODIAN_SLOTS="$launch_slots" \
    RH_RUST_CUSTODIAN_THRESHOLD="$launch_threshold" \
        "$script_dir/run-rust-custodians.sh" &
else
    echo "[rhorizon] starting fixed Python custodian quorum ($custodian_workers slots)" >&2
    RH_CUSTODIAN_WORKERS="$custodian_workers" \
        "$script_dir/run-python-custodians.sh" &
fi
custodian_pid=$!
api_pid=""
watcher_pid=""

shutdown() {
    trap - EXIT INT TERM
    [ -z "$watcher_pid" ] || kill -TERM "$watcher_pid" 2>/dev/null || true
    [ -z "$api_pid" ] || kill -TERM "$api_pid" 2>/dev/null || true
    kill -TERM "$custodian_pid" 2>/dev/null || true
    [ -z "$api_pid" ] || wait "$api_pid" 2>/dev/null || true
    wait "$custodian_pid" 2>/dev/null || true
}
trap shutdown EXIT INT TERM

# Prove the UDS-owning supervisor survived startup. The capability middleware
# intentionally returns 403 without a token, so socket existence plus a live
# parent is the launcher-level readiness gate; API readiness checks the actual
# crypto attachment after unseal.
ready=0
for _ in $(seq 1 100); do
    kill -0 "$custodian_pid" 2>/dev/null || {
        echo "[rhorizon] custodian supervisor exited during startup" >&2
        exit 1
    }
    if [ "$custody_backend" = rust ]; then
        ready=1
        slot=1
        # Count the slots that were LAUNCHED. Waiting on the configured count
        # would hang forever whenever the durable shape is the smaller one.
        while [ "$slot" -le "$launch_slots" ]; do
            [ -S "$runtime_dir/rust-custodian-$slot.sock" ] || ready=0
            slot=$((slot + 1))
        done
        [ "$ready" = 0 ] || break
    else
        # One socket per slot now, so the gate counts them the way the rust
        # branch does rather than waiting on a single shared listener.
        ready=1
        slot=1
        while [ "$slot" -le "$custodian_workers" ]; do
            [ -S "$runtime_dir/custodian-${HOSTNAME:-$(hostname 2>/dev/null || echo default)}-$slot.sock" ] \
                || ready=0
            slot=$((slot + 1))
        done
        [ "$ready" = 0 ] || break
    fi
    sleep 0.1
done
[ "$ready" = 1 ] || {
    echo "[rhorizon] custodian Unix sockets did not appear" >&2
    exit 1
}

echo "[rhorizon] starting disposable API pool ($api_workers workers)" >&2
RH_PROCESS_ROLE=api RH_WORKERS="$api_workers" \
    python -m uvicorn app.main:app --host "$listen_host" --port "$listen_port" \
    $uvicorn_common --workers "$api_workers" &
api_pid=$!

# If custody dies, terminate the public pool so the container supervisor can
# restart a coherent pair instead of leaving an indefinitely crypto-less API.
(
    while kill -0 "$custodian_pid" 2>/dev/null; do sleep 1; done
    kill -TERM "$api_pid" 2>/dev/null || true
) &
watcher_pid=$!

set +e
wait "$api_pid"
status=$?
set -e
api_pid=""
shutdown
exit "$status"
