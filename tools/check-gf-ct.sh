#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# tools/check-gf-ct.sh - assert constant-time asm posture of gf256_ct.
#
# What this checks :
#
#   1. Build api/rust with --features asm-gate (exposes
#      `#[no_mangle]` symbols for mul, clmul_u8, reduce).
#   2. Emit release-mode assembly via `cargo rustc --emit asm`.
#   3. For each exported GF function, extract its asm body and
#      count :
#         - conditional jumps  (je/jne/jl/jg/jb/ja/jc/jo/jp/js/jz
#                                /loop/jcxz...)  -> MUST be zero
#         - cmov instructions  -> allowed, logged for awareness
#
#   Rationale : on x86_64, `cmov*` instructions are guaranteed
#   constant-time by both Intel and AMD architectural specs.
#   They are the canonical CT-safe primitive for branchless
#   selection. Conditional jumps, on the other hand, expose
#   branch-predictor / fetch-address timing channels and are the
#   actual leak vector this gate exists to prevent.
#
# Usage :
#
#   bash tools/check-gf-ct.sh           # full check
#   bash tools/check-gf-ct.sh --verbose # dump per-function asm
#
# Pre-requis : nothing beyond a working stable Rust toolchain.
# Uses `cargo rustc --emit asm` (built-in, no extra cargo
# subcommand to install).

set -euo pipefail

cd "$(dirname "$0")/../api/rust"

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32mOK\033[0m  %s\n" "$*"; }
warn() { printf "\033[1;33mWARN\033[0m  %s\n" "$*"; }
fail() { printf "\033[1;31mFAIL\033[0m  %s\n\n" "$*" >&2; exit 1; }

VERBOSE=false
[ "${1:-}" = "--verbose" ] && VERBOSE=true

# ---------------------------------------------------------------------------
# 1. Build release-mode asm with the asm-gate feature.
# ---------------------------------------------------------------------------
say "cargo rustc --release --no-default-features --features asm-gate -- --emit asm"
RUSTFLAGS="-C debuginfo=0" cargo +stable rustc --release \
    --no-default-features --features asm-gate --lib -- --emit asm > /dev/null
ASM_FILE="target/release/deps/rhorizon_crypto.s"
[ -f "$ASM_FILE" ] || fail "asm file not produced at $ASM_FILE"
ok "asm emitted"

# ---------------------------------------------------------------------------
# 2. Extract each function's body and assert branchlessness.
# ---------------------------------------------------------------------------
# Conditional jump opcodes on x86_64. `jmp` (unconditional) is excluded.
# `cmov*` is excluded by intent (CT-safe selection primitive).
COND_RE='^[[:space:]]*(j(e|ne|l|le|g|ge|b|be|a|ae|c|nc|o|no|p|np|s|ns|z|nz|cxz|ecxz|rcxz)|loop|loope|loopne)[[:space:]]'

TOTAL_BAD=0
for fn in rhorizon_gf256_ct_clmul rhorizon_gf256_ct_reduce rhorizon_gf256_ct_mul; do
    body=$(awk -v f="^${fn}:" '
        match($0, f) { found=1 }
        found { print }
        /^\.Lfunc_end/ && found { exit }
    ' "$ASM_FILE")

    if [ -z "$body" ]; then
        fail "$fn : symbol not found in $ASM_FILE (asm-gate feature missing?)"
    fi

    bad=$(printf '%s\n' "$body" | grep -cE "$COND_RE" || true)
    cmov=$(printf '%s\n' "$body" | grep -cE '^[[:space:]]*cmov' || true)

    if [ "$bad" -gt 0 ]; then
        printf "\033[1;31mFAIL\033[0m  %s : %d conditional jump(s)\n" "$fn" "$bad"
        printf '%s\n' "$body" | grep -nE "$COND_RE" | head -10 | sed 's/^/    /'
        TOTAL_BAD=$((TOTAL_BAD + bad))
    else
        ok "$fn : 0 conditional jumps, $cmov cmov instruction(s) (allowed)"
    fi

    if $VERBOSE; then
        printf '%s\n' "$body"
    fi
done

if [ "$TOTAL_BAD" -gt 0 ]; then
    fail "$TOTAL_BAD conditional jump(s) detected in gf256_ct GF functions"
fi

cat <<EOF


  ================================================================
  GF(256) constant-time asm gate : PASS.

  All three core functions (mul, clmul_u8, reduce) compile to
  branch-free x86_64 code on the host toolchain. cmov is allowed
  by intent (CT-safe selection primitive per Intel/AMD specs).

  Re-run this script after any change to
  api/rust/custody-core/src/gf256.rs or api/rust/src/gf256_ct.rs
  or after any rustc / LLVM bump. The corresponding CI step lives
  in .woodpecker/validate.yml.

  Caveats this script does NOT cover :
   - microarchitectural channels (cache, port contention, SMT)
   - aarch64 / non-x86_64 codegen (gate runs on the host arch)
   - empirical timing variance (use the dudect bench, run manually
     on node-5 before each release)
  ================================================================

EOF
