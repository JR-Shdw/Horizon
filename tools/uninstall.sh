#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# rhorizon uninstaller -- single entry point, mirrors tools/install.sh.
#
#   sh tools/uninstall.sh [--mode auto|docker|user|system] [--purge-db] [--yes]
#
# Modes:
#   auto    (default) docker if a running compose stack is found, else native
#           system (root) or user (non-root).
#   docker  compose down -v (stack + volumes) -- DESTROYS vault data
#   user    native user uninstall   -> tools/uninstall-native.sh --mode user
#   system  native system uninstall -> tools/uninstall-native.sh --mode system
#
# Extra args (--purge-db, --yes, path overrides) pass through to the native path.
set -eu

MODE=auto
ARGS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE=${2:?--mode needs a value}; shift 2 ;;
        -h|--help) sed -n '5,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) ARGS="$ARGS $1"; shift ;;
    esac
done

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
has_docker() { command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; }

if [ "$MODE" = auto ]; then
    if has_docker && docker compose -f "$ROOT/docker-compose.yml" ps -q 2>/dev/null | grep -q .; then MODE=docker
    elif [ "$(id -u)" = 0 ]; then MODE=system
    else MODE=user; fi
fi
printf '>> rhorizon uninstall: mode=%s\n' "$MODE"

# shellcheck disable=SC2086
case "$MODE" in
    docker)      exec docker compose -f "$ROOT/docker-compose.yml" down -v --remove-orphans $ARGS ;;
    user|system) exec "$ROOT/tools/uninstall-native.sh" --mode "$MODE" $ARGS ;;
    *) printf 'bad --mode: %s (auto|docker|user|system)\n' "$MODE" >&2; exit 1 ;;
esac
