#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Reload nginx when the api container's address changes.
#
# nginx resolves an upstream address ONCE, when it loads its configuration,
# and never again. Recreate the api container -- compose start ordering on a
# first install, an image update, a --tier switch, a crash under
# restart:unless-stopped -- and it comes back on a different address while
# nginx keeps proxying to the old one. Every request then 502s, on both the
# plaintext and the TLS vhost, and it does NOT heal on its own.
#
# Measured on a podman quickstart: api at 10.89.3.4, nginx pinned to
# 10.89.3.2, "connect() failed (113: Host is unreachable)". Restarting the
# frontend fixed it instantly, which is what this does automatically.
#
# Why not the usual `resolver` + variable-in-proxy_pass trick: putting a
# variable in proxy_pass makes nginx re-resolve per request, but it also
# bypasses the upstream{} block, and with it the keepalive pool that
# nginx-tls.conf relies on to close the cross-side race with uvicorn
# (nginx 25s < uvicorn 30s, deliberately). Open-source nginx has no
# `resolve` parameter on `server` directives -- that is nginx Plus. A reload
# re-resolves every upstream while keeping the pool, so it buys the fix
# without giving back a bug that was already closed.
#
# Only reloads when the resolved set actually CHANGES, so a stable
# deployment never reloads at all.

set -eu

[ "${UPSTREAM_WATCH:-1}" = "1" ] || exit 0

# API_UPSTREAM is host:port; DNS only cares about the host.
_host="${API_UPSTREAM:-api:8200}"
_host="${_host%%:*}"
_interval="${UPSTREAM_WATCH_INTERVAL:-10}"

# Numeric address: nothing to re-resolve, so do not spawn the watcher.
case "$_host" in
    *[!0-9.]*) ;;
    *) exit 0 ;;
esac

_resolve() {
    # Sorted + comma-joined so a reordered DNS answer is not read as a change.
    getent hosts "$_host" 2>/dev/null | awk '{print $1}' | sort | tr '\n' ','
}

(
    _last="$(_resolve)"
    while :; do
        sleep "$_interval"
        _now="$(_resolve)"
        # An empty answer means DNS is briefly unavailable, not that the
        # upstream moved. Reloading on that would just churn.
        [ -n "$_now" ] || continue
        if [ -n "$_last" ] && [ "$_now" != "$_last" ]; then
            echo "[upstream-watch] $_host moved: $_last -> $_now, reloading nginx" >&2
            nginx -s reload 2>/dev/null || true
        fi
        _last="$_now"
    done
) &
