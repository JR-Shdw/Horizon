#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# tools/check-rust.sh - pre-flight local pour ne pas iterer en CI.
#
# Reproduit en local exactement les checks Rust de
# .woodpecker/validate.yml :
#
#   1. cargo deny check bans licenses sources
#   2. cargo clippy --no-default-features -- -D warnings
#   3. cargo test --release --no-default-features
#   4. cargo +nightly miri test --no-default-features
#
# Usage :
#
#   bash tools/check-rust.sh                # tout
#   bash tools/check-rust.sh --skip-miri    # sans miri (5 min de moins)
#   bash tools/check-rust.sh --only deny    # un seul check
#
# Pre-requis (one-time) :
#
#   cargo install --locked cargo-deny
#   rustup component add clippy
#   rustup toolchain install nightly --profile minimal
#   rustup +nightly component add miri
#
# Le but : eviter d'enchainer 5 push de fix triviaux qui prennent
# chacun 10 min de CI parce qu'on a oublie un rustup component add.

set -euo pipefail

cd "$(dirname "$0")/../api/rust"

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()  { printf "\033[1;32mOK\033[0m  %s\n" "$*"; }
fail(){ printf "\033[1;31mFAIL\033[0m  %s\n\n" "$*" >&2; exit 1; }

SKIP_MIRI=false
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-miri) SKIP_MIRI=true; shift ;;
        --only) ONLY="$2"; shift 2 ;;
        -h|--help)
            sed -n '/^# tools/,/^# Le but/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) fail "Unknown arg: $1" ;;
    esac
done

want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# ---------------------------------------------------------------------------
# 1. cargo deny - licenses + sources + bans
# ---------------------------------------------------------------------------
if want deny; then
    say "cargo deny check bans licenses sources"
    command -v cargo-deny >/dev/null || \
        fail "cargo-deny missing - run: cargo install --locked cargo-deny"
    cargo deny check bans licenses sources
    ok "cargo deny"
fi

# ---------------------------------------------------------------------------
# 2. cargo clippy - strict (-D warnings = fail on any warning)
# ---------------------------------------------------------------------------
if want clippy; then
    say "cargo clippy --no-default-features -- -D warnings"
    rustup component list --installed 2>/dev/null | grep -q '^clippy' || \
        fail "clippy missing - run: rustup component add clippy"
    cargo clippy --locked --no-default-features -- -D warnings
    ok "cargo clippy"
fi

# ---------------------------------------------------------------------------
# 3. cargo test - release mode, no extension-module feature
# ---------------------------------------------------------------------------
if want test; then
    say "cargo test --release --no-default-features"
    cargo test --release --locked --no-default-features
    ok "cargo test"
fi

# ---------------------------------------------------------------------------
# 4. cargo miri - UB on unsafe paths (nightly)
# ---------------------------------------------------------------------------
if want miri; then
    if $SKIP_MIRI; then
        say "skipping miri (--skip-miri)"
    else
        say "cargo +nightly miri test --no-default-features"
        rustup +nightly component list --installed 2>/dev/null | grep -q '^miri' || \
            fail "miri missing - run: rustup toolchain install nightly --profile minimal && rustup +nightly component add miri"
        cargo +nightly miri test --no-default-features --locked
        ok "cargo miri"
    fi
fi

# ---------------------------------------------------------------------------
# 5. maturin build - final sanity check (does the wheel build ?)
# ---------------------------------------------------------------------------
if want build; then
    say "maturin build --release --locked --strip"
    command -v maturin >/dev/null || \
        fail "maturin missing - run: pip install maturin (in your project venv)"
    maturin build --release --locked --strip
    ok "maturin build"
fi

cat <<EOF


  ================================================================
  All local Rust checks passed.

  validate.yml will run the same sequence in CI ; if this script
  is green, the Rust portion of the pipeline should be green too.

  Network-dependent advisory check (cargo audit) lives in scan.yml
  and runs against the live RustSec advisory-db ; it is NOT
  reproduced here because the CI runner has different network
  topology than your workstation.
  ================================================================

EOF
