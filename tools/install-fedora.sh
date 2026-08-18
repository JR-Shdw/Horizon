#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh Fedora system.
# Installs deps + creates a venv + builds the Rust extension + sets up Postgres.
# Run as root (sudo). Idempotent.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing Fedora packages"
dnf install -y -q \
    python3 python3-devel python3-pip \
    rust cargo \
    libsodium-devel openldap-devel cyrus-sasl-devel libffi-devel openssl-devel \
    postgresql-server postgresql-contrib \
    git curl gcc make pkgconf-pkg-config rsync

echo ">> initializing PostgreSQL (idempotent)"
if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
    postgresql-setup --initdb
fi
systemctl enable --now postgresql
sleep 2

# Fedora defaults loopback TCP auth to ident. The laptop quickstart creates a
# password-authenticated app role and connects over 127.0.0.1, so add a narrow
# scram rule before the default ident entries.
HBA_FILE="$(su - postgres -c "psql -tAc 'SHOW hba_file'" | tr -d '[:space:]')"
if [ -n "$HBA_FILE" ] \
   && ! grep -qE '^host[[:space:]]+all[[:space:]]+all[[:space:]]+127\.0\.0\.1/32[[:space:]]+scram-sha-256' "$HBA_FILE"; then
    [ -f "${HBA_FILE}.rhorizon.bak" ] || cp "$HBA_FILE" "${HBA_FILE}.rhorizon.bak"
    TMP_HBA="$(mktemp)"
    {
        echo "host all all 127.0.0.1/32 scram-sha-256"
        echo "host all all ::1/128 scram-sha-256"
        cat "$HBA_FILE"
    } > "$TMP_HBA"
    cat "$TMP_HBA" > "$HBA_FILE"
    rm -f "$TMP_HBA"
    systemctl reload postgresql
fi

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
    python3 -m venv .venv &&
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
