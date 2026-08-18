#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# tools/check-fuzz.sh - smoke run local des 4 cibles cargo-fuzz.
#
# Reproduit en court ce que .woodpecker/fuzz.yml execute la nuit.
# Le but : surfacer un panic / crash avant push, pas remplacer la
# vraie campagne nightly (60 min par cible vs 60 s ici).
#
# Cibles :
#   - shamir_combine   (adversarial input dans la reconstruction)
#   - shamir_split     (post-conditions sur tout (threshold, total))
#   - aes_gcm_roundtrip
#   - aes_gcm_decrypt
#
# Usage :
#
#   bash tools/check-fuzz.sh                # tout, 60 s par cible
#   bash tools/check-fuzz.sh --time 30      # 30 s par cible
#   bash tools/check-fuzz.sh --only shamir_combine
#
# Pre-requis (one-time) :
#
#   rustup toolchain install nightly --profile minimal
#   cargo install --locked cargo-fuzz
#
# cargo-fuzz a besoin de la toolchain nightly (libfuzzer-sys binde
# le runtime LLVM libFuzzer via des hooks instrumentation ABI
# instables). Stable Rust n'a pas l'instrumentation equivalente.

set -euo pipefail

cd "$(dirname "$0")/../api/rust"

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()  { printf "\033[1;32mOK\033[0m  %s\n" "$*"; }
fail(){ printf "\033[1;31mFAIL\033[0m  %s\n\n" "$*" >&2; exit 1; }

TIME_BUDGET=60
ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --time)
            shift
            TIME_BUDGET="$1"
            ;;
        --only)
            shift
            ONLY="$1"
            ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0
            ;;
        *)
            fail "argument inconnu: $1"
            ;;
    esac
    shift
done

want() {
    [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]
}

# ---------------------------------------------------------------------------
# Pre-flight : nightly + cargo-fuzz installes
# ---------------------------------------------------------------------------
say "pre-flight"
rustup toolchain list 2>/dev/null | grep -q '^nightly' || \
    fail "nightly missing - rustup toolchain install nightly --profile minimal"
command -v cargo-fuzz >/dev/null 2>&1 || cargo fuzz --version >/dev/null 2>&1 || \
    fail "cargo-fuzz missing - cargo install --locked cargo-fuzz"
ok "pre-flight"

TARGETS=(shamir_combine shamir_split aes_gcm_roundtrip aes_gcm_decrypt)

for target in "${TARGETS[@]}"; do
    if ! want "$target"; then
        continue
    fi
    say "cargo +nightly fuzz run $target -- -max_total_time=$TIME_BUDGET"
    # cargo-fuzz exit code: 0 = no crash within budget, !=0 = crash artefact
    # produced or build failure. Either case is a fail for the smoke run.
    cargo +nightly fuzz run "$target" -- -max_total_time="$TIME_BUDGET" \
        || fail "$target produced a crash artefact - inspect api/rust/fuzz/artifacts/$target/"
    ok "$target"
done

cat <<EOF


  ================================================================
  Local fuzz smoke passed (budget: ${TIME_BUDGET}s per target).

  Le vrai run tourne la nuit dans .woodpecker/fuzz.yml (cron
  nightly-fuzz). Si ce script est vert, le pipeline part avec
  une corpus saine.

  Artefacts de crash eventuels : api/rust/fuzz/artifacts/<target>/
  Corpus persistant local      : api/rust/fuzz/corpus/<target>/
  (tous deux git-ignored)
  ================================================================

EOF
