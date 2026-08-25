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
#         - x86_64 conditional jumps (je/jne/jl/jg/jb/ja/...) or
#           aarch64 conditional branches (b.eq/b.ne/cbz/tbz/...)
#           -> MUST be zero
#         - branchless conditional selection (x86_64 cmov; aarch64
#           csel/cset and aliases) -> allowed, logged for awareness
#
#   Rationale : conditional selection instructions do not redirect
#   control flow. Conditional branches do, exposing branch-predictor /
#   fetch-address timing channels. This is a code-generation gate, not
#   a formal proof or an empirical timing measurement.
#
# Usage :
#
#   bash tools/check-gf-ct.sh           # full check
#   bash tools/check-gf-ct.sh --verbose # dump per-function asm
#
# Supported native hosts : Linux x86_64 and Linux aarch64 (including
# Raspberry Pi 4 running a 64-bit OS). Cross-compiled assembly is not
# accepted: the gate intentionally checks the active native toolchain.
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

HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
    x86_64|amd64)
        ARCH=x86_64
        # Unconditional `jmp` is excluded. `cmov*` is branchless and allowed.
        COND_RE='^[[:space:]]*(j(e|ne|l|le|g|ge|b|be|a|ae|c|nc|o|no|p|np|s|ns|z|nz|cxz|ecxz|rcxz)|loop|loope|loopne)[[:space:]]'
        SELECT_RE='^[[:space:]]*cmov'
        POSITIVE_CASES=$'je .Lbad\njne .Lbad\nloop .Lbad'
        NEGATIVE_CASES=$'jmp .Lok\ncmove %eax, %ebx\nretq'
        ;;
    aarch64|arm64)
        ARCH=aarch64
        # AArch64 conditional branches. Plain `b`, `br`, `bl`, and `blr` are
        # unconditional control transfers and are deliberately excluded.
        # `bc.<cond>` is the Armv8.8-A consistent-conditional-branch form.
        COND_RE='^[[:space:]]*((b|bc)\.(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)|cbz|cbnz|tbz|tbnz)[[:space:]]'
        SELECT_RE='^[[:space:]]*(csel|csinc|csinv|csneg|cset|csetm)[[:space:]]'
        POSITIVE_CASES=$'b.eq .Lbad\nb.ne .Lbad\ncbz w0, .Lbad\ncbnz x1, .Lbad\ntbz w2, #0, .Lbad\ntbnz x3, #7, .Lbad\nbc.eq .Lbad'
        NEGATIVE_CASES=$'b .Lok\nbr x8\nbl helper\ncsel w0, w1, w2, eq\ncset w0, ne\nret'
        ;;
    *)
        fail "unsupported native architecture: $HOST_ARCH (expected x86_64 or aarch64)"
        ;;
esac

# Guard the guard: a typo in an opcode regex must fail before any compiler
# output is trusted. These fixtures cover every branch family accepted above.
while IFS= read -r instruction; do
    [ -z "$instruction" ] && continue
    printf '%s\n' "$instruction" | grep -qE "$COND_RE" || \
        fail "$ARCH parser self-test missed conditional instruction: $instruction"
done <<< "$POSITIVE_CASES"
while IFS= read -r instruction; do
    [ -z "$instruction" ] && continue
    if printf '%s\n' "$instruction" | grep -qE "$COND_RE"; then
        fail "$ARCH parser self-test rejected allowed instruction: $instruction"
    fi
done <<< "$NEGATIVE_CASES"
ok "$ARCH opcode parser self-test"

# ---------------------------------------------------------------------------
# 1. Build release-mode asm with the asm-gate feature.
# ---------------------------------------------------------------------------
say "cargo rustc --release --locked --no-default-features --features asm-gate -- --emit asm ($ARCH native)"
RUSTFLAGS="-C debuginfo=0" cargo +stable rustc --release \
    --locked --no-default-features --features asm-gate --lib -- --emit asm > /dev/null
TARGET_DIR=${CARGO_TARGET_DIR:-target}
ASM_FILE="$TARGET_DIR/release/deps/rhorizon_crypto.s"
[ -f "$ASM_FILE" ] || fail "asm file not produced at $ASM_FILE"
ok "asm emitted"

# ---------------------------------------------------------------------------
# 2. Extract each function's body and assert branchlessness.
# ---------------------------------------------------------------------------
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
    selections=$(printf '%s\n' "$body" | grep -cE "$SELECT_RE" || true)

    if [ "$bad" -gt 0 ]; then
        printf "\033[1;31mFAIL\033[0m  %s : %d conditional branch(es)\n" "$fn" "$bad"
        printf '%s\n' "$body" | grep -nE "$COND_RE" | head -10 | sed 's/^/    /'
        TOTAL_BAD=$((TOTAL_BAD + bad))
    else
        ok "$fn : 0 conditional branches, $selections branchless selection instruction(s) (allowed)"
    fi

    if $VERBOSE; then
        printf '%s\n' "$body"
    fi
done

if [ "$TOTAL_BAD" -gt 0 ]; then
    fail "$TOTAL_BAD conditional branch(es) detected in gf256_ct GF functions"
fi

cat <<EOF


  ================================================================
  GF(256) constant-time asm gate : PASS.

  All three core functions (mul, clmul_u8, reduce) compile without
  conditional branches for native ${ARCH} on the host toolchain.
  Branchless conditional-selection instructions are allowed.

  Re-run this script after any change to
  api/rust/custody-core/src/gf256.rs or api/rust/src/gf256_ct.rs
  or after any rustc / LLVM bump. The x86_64 CI step lives in
  .woodpecker/validate.yml; the native aarch64 step lives in
  .github/workflows/crypto-arm64.yml.

  Caveats this script does NOT cover :
   - microarchitectural channels (cache, port contention, SMT)
   - architectures other than native ${ARCH}
   - empirical timing variance (use the dudect bench, run manually
     on node-5 before each release)
  ================================================================

EOF
