#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Run the native aarch64 crypto verification used by GitHub Actions and by a
# Raspberry Pi 4. Unlike tools/test-arm64.sh, this does not use QEMU: the host
# itself must be aarch64 so the assembly gate inspects native code generation.
#
# Usage:
#   tools/check-arm64-native.sh                  # tests + asm + 60s fuzz/target
#   tools/check-arm64-native.sh --fuzz-time 300  # longer fuzz campaign
#   tools/check-arm64-native.sh --no-fuzz        # stable-only tests + asm gate

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUZZ_TIME=60
RUN_FUZZ=true

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m  %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --fuzz-time)
            shift
            [ $# -gt 0 ] || fail "--fuzz-time requires a number of seconds"
            FUZZ_TIME=$1
            ;;
        --no-fuzz)
            RUN_FUZZ=false
            ;;
        -h|--help)
            sed -n '5,13p' "$0"
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
    shift
done

case "$FUZZ_TIME" in
    ''|*[!0-9]*) fail "fuzz time must be a positive integer" ;;
    0) fail "fuzz time must be greater than zero" ;;
esac

[ "$(uname -s)" = Linux ] || fail "native ARM check requires Linux"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) fail "native ARM check requires aarch64, got $(uname -m)" ;;
esac

say "native host"
uname -a
rustc +stable -vV
ok "native aarch64 host confirmed"

say "release crypto suite"
(
    cd "$ROOT/api/rust"
    cargo +stable test --release --locked --no-default-features
)
ok "release crypto suite passed on aarch64"

say "aarch64 GF(256) assembly gate"
bash "$ROOT/tools/check-gf-ct.sh"
ok "aarch64 assembly gate passed"

if $RUN_FUZZ; then
    say "aarch64 fuzzing ($FUZZ_TIME seconds per target)"
    bash "$ROOT/tools/check-fuzz.sh" --time "$FUZZ_TIME"
    ok "aarch64 fuzzing passed"
else
    say "fuzzing skipped (--no-fuzz)"
fi
