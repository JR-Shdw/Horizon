#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Detect OS family + init system. Portable POSIX sh (Linux + *BSD + macOS).
#
#   eval "$(tools/detect-system.sh)"     # sets $OS $INIT $DISTRO $RUNTIME $ROOTLESS
#   tools/detect-system.sh --human       # one readable line
#
# INIT drives persistence choices: only `systemd` gets install.sh --persist's
# linger + user-unit auto-setup; BSD (`bsd-rc`) uses the native install + rc.d.
# RUNTIME is the container engine (the `docker` CLI may be a podman shim).

os_family() {
    case "$(uname -s 2>/dev/null)" in
        Linux)   echo linux ;;
        FreeBSD) echo freebsd ;;
        OpenBSD) echo openbsd ;;
        NetBSD)  echo netbsd ;;
        Darwin)  echo darwin ;;
        *)       echo unknown ;;
    esac
}

distro_id() {  # Linux distro id from /etc/os-release, empty elsewhere
    [ -r /etc/os-release ] && ( . /etc/os-release 2>/dev/null; printf '%s' "${ID:-}" )
}

init_system() {
    case "$(os_family)" in
        linux)
            # /run/systemd/system is the canonical "booted under systemd" marker.
            [ -d /run/systemd/system ] && { echo systemd; return; }
            p1="$(ps -p 1 -o comm= 2>/dev/null | tr -d ' /')"
            case "$p1" in
                systemd)        echo systemd ;;
                runit|runsvdir) echo runit ;;
                openrc*)        echo openrc ;;
                init)
                    if [ -d /run/openrc ] || command -v openrc-init >/dev/null 2>&1; then
                        echo openrc
                    else
                        echo sysvinit
                    fi ;;
                *) echo "${p1:-unknown}" ;;
            esac ;;
        freebsd|openbsd|netbsd) echo bsd-rc ;;
        darwin)                 echo launchd ;;
        *)                      echo unknown ;;
    esac
}

container_runtime() {  # docker | podman | none. Resolve what `docker` actually is
    # first (a podman host ships a `docker` shim), so we match the engine compose
    # will really drive; fall back to a bare podman install.
    if command -v docker >/dev/null 2>&1; then
        if docker version 2>/dev/null | grep -qi podman; then echo podman; else echo docker; fi
        return
    fi
    command -v podman >/dev/null 2>&1 && echo podman || echo none
}

runtime_rootless() {  # yes | no  (on macOS/Windows the engine runs in a Linux VM)
    case "$1" in
        podman) [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = true ] && echo yes || echo no ;;
        docker) docker info 2>/dev/null | grep -qiE 'rootless' && echo yes || echo no ;;
        *)      echo no ;;
    esac
}

OS="$(os_family)"
INIT="$(init_system)"
DISTRO="$(distro_id)"
RUNTIME="$(container_runtime)"
ROOTLESS="$(runtime_rootless "$RUNTIME")"

case "${1:-}" in
    -h|--human)
        printf 'OS=%s INIT=%s RUNTIME=%s%s%s\n' "$OS" "$INIT" "$RUNTIME" \
            "$([ "$ROOTLESS" = yes ] && echo '(rootless)')" "${DISTRO:+ DISTRO=$DISTRO}" ;;
    *)
        printf 'OS=%s\nINIT=%s\nDISTRO=%s\nRUNTIME=%s\nROOTLESS=%s\n' \
            "$OS" "$INIT" "$DISTRO" "$RUNTIME" "$ROOTLESS" ;;
esac
