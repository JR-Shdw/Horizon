#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# tools/check-fuzz-pipeline.sh - shadow-execute `.woodpecker/fuzz.yml`
# in a local container so build-time errors surface in ~2 min instead
# of paying a 5+ min round-trip on the node-1 runner.
#
# This is the inner loop (B in the local-first doctrine). The outer
# loop is the rhorizon_test setup (push to local Forgejo, watch local
# Woodpecker UI). Run this first, then the outer loop if green, then
# push to prod.
#
# What it does :
#   1. Spawns `python:3.12-slim-bookworm` (same image fuzz.yml uses)
#      via podman, with the repo bind-mounted read-only.
#   2. Executes the exact apt install / rustup / cargo install /
#      cargo fuzz build / cargo fuzz run sequence fuzz.yml runs.
#   3. Caps each `fuzz run` at MAX_TIME=60 (vs prod 1800) so the
#      whole script finishes in ~5 min instead of 2 h+.
#
# What it does NOT exercise (the outer loop's job) :
#   - Woodpecker $$ substitution
#   - cron / manual / push event matching in `when:`
#   - Label-based agent routing (host: node-1)
#   - Cross-step status conditions (notify-success vs notify-failure)
#   - Volume bind-mount semantics on the runner host
#
# Pre-requis :
#   - podman (already on node-5, doctrine)
#   - tools/check-fuzz.sh complementary : local cargo-fuzz already
#     installed on the host. THIS script does NOT need cargo-fuzz on
#     the host ; everything runs inside the container.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d -p "${TMPDIR:-$HOME/tmp}" rhorizon-fuzz-pipeline.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

MAX_TIME="${MAX_TIME:-60}"
IMAGE="${IMAGE:-docker.io/library/python:3.12-slim-bookworm}"

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32mOK\033[0m  %s\n" "$*"; }
fail() { printf "\033[1;31mFAIL\033[0m  %s\n\n" "$*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 || fail "podman missing - install per Arch doctrine"

mkdir -p "$TMP_DIR/corpus" "$TMP_DIR/artifacts"

say "Spawning $IMAGE (this mirrors .woodpecker/fuzz.yml's fuzz-run step)"
say "Workspace : $REPO_ROOT (read-only)"
say "Corpus    : $TMP_DIR/corpus"
say "Artefacts : $TMP_DIR/artifacts"
say "MAX_TIME  : ${MAX_TIME}s per target (vs prod 1800)"

# Write a small seccomp profile that denies personality(2). Regulus's
# Woodpecker runner blocks this syscall by default ; rootless podman
# on node-5 does NOT, so without this profile our local container is
# more permissive than prod and gives false-positive greens (cf.
# pipeline #536 2026-05-16). Forcing the deny here makes B mirror
# the prod constraint.
SECCOMP_PROFILE="$TMP_DIR/seccomp-deny-personality.json"
cat > "$SECCOMP_PROFILE" <<'JSON'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
JSON
say "Seccomp  : deny personality(2) (mirrors node-1 runner)"

# The script body below is the EXACT shell that fuzz.yml's fuzz-run
# step executes, minus the Woodpecker `$$` escaping. Keep this block
# in lockstep with .woodpecker/fuzz.yml whenever either changes.
podman run --rm \
    --security-opt "seccomp=$SECCOMP_PROFILE" \
    -v "$REPO_ROOT:/workspace:ro,Z" \
    -v "$TMP_DIR/corpus:/corpus:Z" \
    -v "$TMP_DIR/artifacts:/artifacts:Z" \
    -e "MAX_TIME=$MAX_TIME" \
    "$IMAGE" \
    bash -euxo pipefail -c '
echo "[fuzz] Installing build deps + nightly Rust + cargo-fuzz..."
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential curl ca-certificates clang pkg-config
curl --proto "=https" --tlsv1.2 -sSf -o /tmp/rustup-init.sh https://sh.rustup.rs
echo "6c30b75a75b28a96fd913a037c8581b580080b6ee9b8169a3c0feb1af7fe8caf  /tmp/rustup-init.sh" | sha256sum -c -
sh /tmp/rustup-init.sh -y --default-toolchain nightly --profile minimal
rm /tmp/rustup-init.sh
export PATH="/root/.cargo/bin:$PATH"
cargo install cargo-fuzz
echo "[fuzz] Toolchain ready"

# Workspace was mounted read-only ; copy to a writable location so
# cargo can produce build artefacts. Saves ~2 min in iterations
# because the host workspace is left untouched.
cp -r /workspace /build
cd /build/api/rust

# Pre-flight build - fails LOUD if pyo3/python or any other build
# input is missing, instead of being swallowed by the per-target
# || echo below. `--sanitizer none` mirrors fuzz.yml : drops ASan
# which would otherwise abort at init under node-1 seccomp profile
# (personality(2) denied).
echo "[fuzz] Build pre-flight (all 4 targets, no ASan)..."
cargo +nightly fuzz build --sanitizer none
echo "[OK] All fuzz targets built"

# Pre-existing artefact noise check (matches fuzz.yml warning logic).
for t in shamir_combine shamir_split aes_gcm_roundtrip aes_gcm_decrypt; do
    mkdir -p "/corpus/$t" "/artifacts/$t"
    left=$(find "/artifacts/$t" -type f 2>/dev/null | wc -l)
    if [ "$left" -gt 0 ]; then
        echo "[fuzz][WARN] $t carries $left unreviewed crash artefact(s)"
    fi
done

# Run each target. `--sanitizer none` avoids ASan, which would
# abort at init under our deny-personality seccomp profile (mirrors
# node-1). `|| echo` so a real libFuzzer crash on one target does
# not block the next.
for target in shamir_combine shamir_split aes_gcm_roundtrip aes_gcm_decrypt; do
    echo "================================================================"
    echo "[fuzz] target=$target budget=${MAX_TIME}s"
    echo "================================================================"
    cargo +nightly fuzz run --sanitizer none "$target" \
        "/corpus/$target" \
        -- \
        -max_total_time="${MAX_TIME}" \
        -artifact_prefix=/artifacts/"$target"/ \
        || echo "[fuzz][NOTE] $target exited non-zero (crash artefact expected)"
done

echo "================================================================"
echo "[fuzz] Run summary"
echo "================================================================"
for t in shamir_combine shamir_split aes_gcm_roundtrip aes_gcm_decrypt; do
    c=$(find "/corpus/$t" -type f 2>/dev/null | wc -l)
    a=$(find "/artifacts/$t" -type f 2>/dev/null | wc -l)
    echo "  $t : corpus=$c crashes=$a"
done
'

# Mirror the detect-crashes + liveness step that fuzz.yml runs as a
# separate Woodpecker step. Host-side this time because the container
# is gone. Liveness gate : every target must have grown its corpus.
# Without this, a silent build/init failure on every target gives a
# misleading "no crashes" green (cf. pipelines #535, #536 2026-05-16).
say "Detecting crash artefacts + corpus liveness"
total_crashes=0
targets_with_corpus=0
for t in shamir_combine shamir_split aes_gcm_roundtrip aes_gcm_decrypt; do
    n=$(find "$TMP_DIR/artifacts/$t" -type f 2>/dev/null | wc -l)
    c=$(find "$TMP_DIR/corpus/$t" -type f 2>/dev/null | wc -l)
    total_crashes=$((total_crashes + n))
    if [ "$c" -gt 0 ]; then
        targets_with_corpus=$((targets_with_corpus + 1))
    fi
    if [ "$n" -gt 0 ]; then
        printf "\033[1;31mCRASH\033[0m  %s : %d artefact(s) in %s\n" \
            "$t" "$n" "$TMP_DIR/artifacts/$t"
    fi
done
if [ "$targets_with_corpus" -lt 4 ]; then
    fail "only $targets_with_corpus of 4 targets produced corpus inputs (silent failure)"
fi
if [ "$total_crashes" -gt 0 ]; then
    fail "$total_crashes fuzz crash artefact(s) detected"
fi
ok "All 4 targets fuzzed, no crash artefacts"

cat <<EOF


  ================================================================
  fuzz.yml shadow-execution : PASS.

  Build pre-flight green, all 4 targets ran libFuzzer for ${MAX_TIME}s
  each, zero crash artefacts in /tmp/.../artifacts/<target>/.

  Safe to advance to outer loop : push to rhorizon_test, watch
  local Woodpecker UI, then push prod when that is green too.

  tmp dirs auto-cleaned on script exit. Set NO_CLEANUP=1 to keep
  them for inspection (override the trap).
  ================================================================

EOF
