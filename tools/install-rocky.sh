#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh Rocky Linux 9 system.
# Installs deps + creates a venv + builds the Rust extension + sets up Postgres.
# Run as root (sudo). Idempotent.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing Rocky 9 packages"
# EPEL gives us recent libsodium-devel and similar dev headers.
dnf install -y -q epel-release
# PostgreSQL 18 from the signed PGDG yum repo (Rocky 9 default is PG13). The
# repo RPM + packages are GPG-signed; dnf verifies signatures. Disable the
# built-in postgresql module so it doesn't shadow the PGDG packages.
dnf install -y -q https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -qy module disable postgresql
dnf install -y -q \
    python3.12 python3.12-devel python3-pip \
    rust cargo \
    libsodium-devel openldap-devel cyrus-sasl-devel libffi-devel openssl-devel \
    postgresql18-server postgresql18-contrib \
    git curl gcc make pkgconf-pkg-config rsync

echo ">> initializing PostgreSQL 18 (idempotent)"
PGDATA=/var/lib/pgsql/18/data
if [ ! -f "${PGDATA}/PG_VERSION" ]; then
    /usr/pgsql-18/bin/postgresql-18-setup initdb
fi
# Overwrite pg_hba with a minimal trust-only config (test VM, localhost-only).
cat > "${PGDATA}/pg_hba.conf" <<'EOF'
# rhorizon test VM (install-rocky.sh)
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
EOF
systemctl enable --now postgresql-18
sleep 2

echo ">> creating rhorizon_test role + database"
su - postgres -c "/usr/pgsql-18/bin/psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - postgres -c "/usr/pgsql-18/bin/psql -c \"CREATE USER rhorizon_test WITH PASSWORD 'rhorizon_test' SUPERUSER\""
su - postgres -c "/usr/pgsql-18/bin/psql -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - postgres -c "/usr/pgsql-18/bin/psql -c \"CREATE DATABASE rhorizon_test OWNER rhorizon_test\""

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
