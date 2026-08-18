#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh Arch Linux system. Assumes the
# linux-hardened kernel is already running (test-vm.sh installs it
# + reboots before invoking this script). Installs deps + creates a
# venv + builds the Rust extension + sets up Postgres.
# Run as root (sudo). Idempotent.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing Arch packages (kernel: $(uname -r))"
pacman -Sy --noconfirm --quiet
pacman -S --noconfirm --needed --quiet \
    python python-pip \
    rust \
    libsodium libldap libsasl libffi openssl \
    postgresql \
    git curl gcc pkgconf base-devel rsync

echo ">> initializing PostgreSQL (idempotent)"
if [ ! -f /var/lib/postgres/data/PG_VERSION ]; then
    install -d -o postgres -g postgres -m 0700 /var/lib/postgres/data
    su - postgres -c "initdb -D /var/lib/postgres/data --locale=en_US.UTF-8"
fi
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
USER_NAME="${SUDO_USER:-$(id -un)}"
chown -R "${USER_NAME}" "${ROOT_DIR}"
su -l "${USER_NAME}" -c "
    cd '${ROOT_DIR}' &&
    python -m venv .venv &&
    . .venv/bin/activate &&
    pip install --quiet --upgrade pip wheel &&
    pip install --quiet --require-hashes -r api/requirements.txt &&
    pip install --quiet -r tools/test-requirements.txt &&
    pip install --quiet maturin
"

echo ">> building rhorizon_crypto Rust extension"
su -l "${USER_NAME}" -c "
    cd '${ROOT_DIR}/api/rust' &&
    . '${ROOT_DIR}/.venv/bin/activate' &&
    maturin build --release --strip &&
    pip install --quiet --force-reinstall target/wheels/*.whl
"

echo ">> install complete"
