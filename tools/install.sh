#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon installer -- single entry point. Picks a strategy, then delegates.
#
#   curl -fsSL "$RHORIZON_REPO_BASE/raw/branch/main/tools/install.sh" | sh
#   sh tools/install.sh [--mode auto|docker|user|system] [--tier TIER] [args...]
#
# Modes:
#   auto    (default) Docker if available, else native user (non-root) or
#           system (root). One command that works on a laptop or a server.
#   docker  compose quickstart          -> tools/install-container.sh
#   user    laptop native, no root      -> tools/install-native.sh --mode user
#   system  server native, root + rc.d  -> tools/install-native.sh --mode system
#
# Tiers (sizing, one knob for both paths): home=1 worker, smb=5, heavy=10,
#   super-heavy=20. Container reads tools/presets/<tier>.env; native maps the
#   tier to --workers and derives memory from it.
#
# Extra args are passed through unchanged to the chosen path.
set -eu

MODE=auto
TIER=""
ARGS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE=${2:?--mode needs a value}; shift 2 ;;
        --tier) TIER=${2:?--tier needs a value}; shift 2 ;;
        -h|--help) sed -n '5,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) ARGS="$ARGS $1"; shift ;;
    esac
done

# One tier ladder shared by both paths; native has no presets so map to workers.
if [ -n "$TIER" ]; then
    case "$TIER" in
        home) _TIER_W=1 ;; smb) _TIER_W=5 ;; heavy) _TIER_W=10 ;;
        super-heavy) _TIER_W=20 ;;
        *) printf 'bad --tier: %s (home|smb|heavy|super-heavy)\n' "$TIER" >&2; exit 1 ;;
    esac
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# A usable container runtime is a runtime PLUS a compose implementation.
# Checked in both shapes for each: the v2 plugin ("<bin> compose") and the
# standalone binary ("<bin>-compose"). podman-compose is commonly installed
# without `podman compose` working, and vice versa.
#
# Podman was missing here entirely: auto only ever looked for docker, so a host
# with podman + podman-compose and no docker shim -- which is the normal Arch /
# EndeavourOS / Fedora setup -- silently fell through to the NATIVE installer.
# That is the heavier, more invasive path (packages, PostgreSQL, a boot
# service, sysctl on BSD), chosen not because it fit but because detection was
# blind. install-container.sh has supported podman all along.
has_runtime() {  # has_runtime <docker|podman>
    command -v "$1" >/dev/null 2>&1 || return 1
    "$1" compose version >/dev/null 2>&1 && return 0
    command -v "$1-compose" >/dev/null 2>&1
}

if [ "$MODE" = auto ]; then
    # Docker first: it is the more common target and the better-tested lane.
    if has_runtime docker || has_runtime podman; then MODE=docker
    elif [ "$(id -u)" = 0 ]; then MODE=system
    else MODE=user; fi
fi
printf '>> rhorizon install: mode=%s%s\n' "$MODE" "${TIER:+ tier=$TIER}"

# shellcheck disable=SC2086
case "$MODE" in
    docker)      [ -n "$TIER" ] && ARGS="--tier $TIER $ARGS"
                 exec "$ROOT/tools/install-container.sh" $ARGS ;;
    user|system) [ -n "$TIER" ] && ARGS="--workers $_TIER_W $ARGS"
                 exec "$ROOT/tools/install-native.sh" --mode "$MODE" $ARGS ;;
    *) printf 'bad --mode: %s (auto|docker|user|system)\n' "$MODE" >&2; exit 1 ;;
esac
