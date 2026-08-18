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
has_docker() { command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; }

if [ "$MODE" = auto ]; then
    if has_docker; then MODE=docker
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
