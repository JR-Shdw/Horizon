#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Fast dev path : install the pre-built rhorizon_crypto wheel into the
# project venv (./.venv) without touching the Rust toolchain.
#
# Use cases :
#   - Contributor cloning the repo to iterate on Python only.
#   - CI cache miss where `maturin build` would re-run from scratch.
#   - Lab VM that doesn't need rustup just to bring rhorizon up.
#
# Compatibility (as of wheel 0.1.0 in api/rust/wheel-out/) :
#   - cp312-abi3 wheel  : cpython 3.12+ on linux x86_64, glibc >= 2.34
#   - cp313 wheel       : cpython 3.13 exact on linux x86_64, glibc >= 2.34
#
# If pip refuses every wheel (musllinux, arm64, BSD, older glibc) the
# script exits with a pointer to the maturin build path.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

VENV="${VENV_DIR:-.venv}"
WHEELDIR="api/rust/wheel-out"

if [ ! -x "${VENV}/bin/python" ]; then
    cat >&2 <<EOF
ERROR: ${VENV}/bin/python not found.

Create a virtualenv first :

    python3 -m venv ${VENV}
    . ${VENV}/bin/activate
    pip install -r api/requirements.txt

Or run the full bootstrap that also installs system deps + Postgres :

    bash tools/install-<distro>.sh

Then re-run :

    bash tools/install-rust-wheel.sh
EOF
    exit 1
fi

# shellcheck disable=SC2144
if ! ls "${WHEELDIR}"/rhorizon_crypto-*.whl >/dev/null 2>&1; then
    cat >&2 <<EOF
ERROR: no pre-built wheel found in ${WHEELDIR}.

Build one locally (requires Rust toolchain + maturin) :

    bash tools/check-rust.sh --only build

The output lands in api/rust/target/wheels/ ; copy it to
${WHEELDIR}/ if you want to commit it as the new shipped artifact.
EOF
    exit 1
fi

echo ">> installing rhorizon_crypto from ${WHEELDIR}/ (skip maturin build)"

# pip refuses the whole CLI invocation if any of the listed wheels is
# unsupported on the current platform -- even if another listed wheel
# would work. Iterate one wheel at a time and stop on the first success.
# Prefer abi3 (broader cpython coverage) over cp-specific tags.
installed=0
for whl in $(ls "${WHEELDIR}"/rhorizon_crypto-*-abi3-*.whl 2>/dev/null) \
           $(ls "${WHEELDIR}"/rhorizon_crypto-*.whl 2>/dev/null); do
    # Skip duplicates (abi3 may have shown up twice).
    case " ${tried-} " in
        *" ${whl} "*) continue ;;
    esac
    tried="${tried-} ${whl}"
    if "${VENV}/bin/pip" install --quiet --force-reinstall "${whl}" 2>/dev/null; then
        echo ">> picked $(basename "${whl}")"
        installed=1
        break
    fi
done

if [ "${installed}" -eq 0 ]; then
    cat >&2 <<EOF

ERROR: pip refused every wheel in ${WHEELDIR}/.

Your venv's Python / platform doesn't match any pre-built tag.

Inspect :

    ls ${WHEELDIR}/
    ${VENV}/bin/python -c "import sysconfig; print(sysconfig.get_platform())"
    ${VENV}/bin/python --version

Build a fresh wheel for this environment :

    bash tools/check-rust.sh --only build
    bash tools/install-rust-wheel.sh   # re-run after the new wheel lands

Unsupported by the shipped wheels :
- musllinux (Alpine)        -> maturin build
- arm64 / aarch64           -> maturin build (cross-compile or native)
- FreeBSD / OpenBSD         -> maturin build (see tools/install-{free,open}bsd.sh)
- cpython < 3.12 on x86_64  -> maturin build (or bump abi3 floor)
EOF
    exit 2
fi

"${VENV}/bin/python" -c "import rhorizon_crypto; print('>> ok :', rhorizon_crypto.__file__)"
