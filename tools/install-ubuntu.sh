#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh Ubuntu 24.04 (noble) system.
# Installs deps + creates a venv + builds the Rust extension + sets up Postgres.
# Run as root (sudo). Idempotent.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing Ubuntu packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates gnupg

# PostgreSQL 18 from the signed PGDG repo (Ubuntu's default is older). Key is
# pinned with signed-by, so apt still verifies package signatures.
. /etc/os-release
install -d /usr/share/postgresql-common/pgdg
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq

# noble ships rust 1.75 (too old for Cargo.lock v4); rustup below pulls current
# stable. python3-venv is split out; the -dev libs are for pynacl/bonsai/cffi.
apt-get install -y -qq \
    python3 python3-venv python3-dev python3-pip \
    libsodium-dev libldap2-dev libsasl2-dev libffi-dev libssl-dev \
    postgresql-18 \
    git pkg-config build-essential rsync

echo ">> installing rustup (Ubuntu's apt cargo is rust 1.75 - too old for Cargo.lock v4)"
USER_NAME="${SUDO_USER:-$(id -un)}"
USER_HOME=$(getent passwd "${USER_NAME}" | cut -d: -f6)
if [ ! -x "${USER_HOME}/.cargo/bin/rustc" ]; then
    su -l "${USER_NAME}" -c "
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain stable --profile minimal
    "
fi

echo ">> initializing PostgreSQL (idempotent)"
systemctl enable --now postgresql
sleep 2

echo ">> creating rhorizon_test role + database"
su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - postgres -c "psql -c \"CREATE USER rhorizon_test WITH PASSWORD 'rhorizon_test' SUPERUSER\""
su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - postgres -c "psql -c \"CREATE DATABASE rhorizon_test OWNER rhorizon_test\""

echo ">> creating rhorizon venv"
chown -R "${USER_NAME}" "${ROOT_DIR}"
su -l "${USER_NAME}" -c "
    . \$HOME/.cargo/env &&
    cd '${ROOT_DIR}' &&
    python3 -m venv .venv &&
    . .venv/bin/activate &&
    pip install --quiet --upgrade pip wheel &&
    pip install --quiet --require-hashes -r api/requirements.txt &&
    pip install --quiet -r tools/test-requirements.txt &&
    pip install --quiet maturin
"

echo ">> building rhorizon_crypto Rust extension"
su -l "${USER_NAME}" -c "
    . \$HOME/.cargo/env &&
    cd '${ROOT_DIR}/api/rust' &&
    . '${ROOT_DIR}/.venv/bin/activate' &&
    maturin build --release --strip &&
    pip install --quiet --force-reinstall target/wheels/*.whl
"

echo ">> install complete"
