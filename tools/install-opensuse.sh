#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh openSUSE Leap 15.6 Minimal-VM cloud image.
# Installs deps + creates a venv + builds the Rust extension + sets up Postgres.
# Run as root (sudo). Idempotent.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing openSUSE packages"
zypper --non-interactive --quiet refresh
zypper --non-interactive --quiet install \
    python312 python312-devel python312-pip \
    rust cargo \
    libsodium-devel openldap2-devel cyrus-sasl-devel libffi-devel libopenssl-devel \
    postgresql18-server postgresql18-contrib \
    git curl gcc make pkg-config rsync

echo ">> initializing PostgreSQL (idempotent)"
if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
    install -d -o postgres -g postgres -m 0700 /var/lib/pgsql/data
    su - postgres -c "/usr/lib/postgresql*/bin/initdb -D /var/lib/pgsql/data --locale=en_US.UTF-8" 2>/dev/null \
        || su - postgres -c "initdb -D /var/lib/pgsql/data --locale=en_US.UTF-8"
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
    python3.12 -m venv .venv &&
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
