#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Run the rhorizon_crypto (api/rust) test suite on emulated aarch64.
#
# Per-build CI validates the Rust crypto on amd64; the weekly/manual
# arch-matrix job validates aarch64. This script is the local equivalent and
# executes the same suite (`cargo test --release --locked
# --no-default-features` - NIST ACVP KATs for AES-256-GCM / ML-DSA-65 / HMAC,
# Shamir GF(256) + AES-GCM property tests, Argon2id / XChaCha20 / HKDF /
# Ed25519) inside an aarch64 container via QEMU.
#
# The KATs verify the expected outputs for the covered algorithms on the
# emulated aarch64 build. QEMU does not establish behavior of hardware-specific
# acceleration paths; those require a native hardware lane.
#
# Scope: the crypto crate only. The agent crate is built for arm64 separately
# with aws-lc-sys pre-generated bindings; its PQ TLS path is verified by
# tools/pq-verify.sh.
#
# Usage:
#   tools/test-arm64.sh
#
# Prerequisite: aarch64 binfmt registered with the F (fix-binary) flag, e.g.
#   sudo podman run --rm --privileged docker.io/tonistiigi/binfmt --install arm64
# (the same toolchain the multi-arch build pipeline uses).
#
# Exit: 0 pass / 1 fail / 2 skip (no arm64 emulation available).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${RH_ARM_IMAGE:-docker.io/library/rust:1-slim-bookworm}"
CACHE_VOL="rhorizon-arm-cargo"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rh-arm64.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
say() { printf '\033[1;36m[arm64-test]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[arm64-test]\033[0m %s\n' "$*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 && RT=podman || { command -v docker >/dev/null 2>&1 && RT=docker || die "need podman or docker"; }

# --- verify aarch64 emulation is available -----------------------------------
if ! "$RT" run --rm --platform linux/arm64 docker.io/library/alpine uname -m 2>/dev/null | grep -q aarch64; then
    echo "[arm64-test] SKIP: no aarch64 emulation. Register it first:"
    echo "    sudo $RT run --rm --privileged docker.io/tonistiigi/binfmt --install arm64"
    exit 2
fi
say "aarch64 emulation OK ($RT)"

# --- stage the crypto crate (exclude build artefacts) ------------------------
cp -r "$ROOT/api/rust" "$WORK/rust"
rm -rf "$WORK/rust/target" "$WORK/rust/fuzz/target"
"$RT" volume create "$CACHE_VOL" >/dev/null 2>&1 || true

# --- run the suite on emulated aarch64 ---------------------------------------
# python3-dev: build.rs links libpython for the test binary when the
# extension-module feature is off (cargo test path). pkg-config: pyo3 probing.
say "running cargo test --release --locked --no-default-features on aarch64 (emulated; 30-70 min)"
"$RT" run --rm --platform linux/arm64 \
    -v "$WORK":/work \
    -v "$CACHE_VOL":/usr/local/cargo/registry \
    "$IMAGE" \
    bash -c '
        set -e
        echo "[arm64-test] arch=$(uname -m) rustc=$(rustc --version)"
        apt-get update -qq && apt-get install -y --no-install-recommends python3-dev pkg-config >/dev/null 2>&1
        cd /work/rust
        cargo test --release --locked --no-default-features
    '
rc=$?
[ "$rc" -eq 0 ] && say "PASS -- rhorizon_crypto verified on aarch64" || say "FAIL -- rc=$rc"
exit "$rc"
