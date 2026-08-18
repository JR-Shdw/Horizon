#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh FreeBSD 14.x system.
# Installs deps + creates a venv + builds the Rust extension + sets up Postgres.
# Run as root (sudo). Idempotent.

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing FreeBSD packages"
ASSUME_ALWAYS_YES=yes pkg update -q
# Note: pip+virtualenv come bundled via python3.12 -m ensurepip / -m venv;
# pkg only ships py311-pip / py311-virtualenv on FreeBSD 14.x.
ASSUME_ALWAYS_YES=yes pkg install -y \
    python312 py312-sqlite3 \
    rust \
    libsodium openldap26-client cyrus-sasl \
    postgresql18-server postgresql18-client \
    git pkgconf gcc curl ca_root_nss

# Defensive: when bsd-firstboot does a freebsd-update + reboot mid-image-init,
# subsequent pkg installs sometimes leave python312 / rust with missing
# shared libs (e.g. librustc_driver-*.so) or stdlib dirs. Verify and
# reinstall if so.
echo ">> verifying critical toolchain"
if ! python3.12 -c 'import encodings' 2>/dev/null; then
    echo ">>   python312 broken, force-reinstalling"
    ASSUME_ALWAYS_YES=yes pkg install -f -y python312
fi
if ! rustc --version >/dev/null 2>&1; then
    echo ">>   rust broken, force-reinstalling"
    ASSUME_ALWAYS_YES=yes pkg install -f -y rust
fi

echo ">> allowing locked memory (rhorizon mlocks key material)"
# rhorizon's Rust crypto mlock()s the wrap key + secure buffers so keys
# never swap. The hard RLIMIT_MEMLOCK comes from the user's login class;
# the default class caps it, so a non-root process (the test user, and a
# real rhorizon service user) hits "mlock failed" on unseal. Grant an
# unlimited memorylocked login class. (Linux gets this via the systemd
# unit's LimitMEMLOCK.) unprivileged_mlock is already 1 by default on 14.x.
sysctl security.bsd.unprivileged_mlock=1 >/dev/null 2>&1 || true
if ! grep -q '^rhorizon-vault:' /etc/login.conf 2>/dev/null; then
    cat >> /etc/login.conf <<'LOGIN'

rhorizon-vault:\
	:memorylocked=unlimited:\
	:tc=default:
LOGIN
    cap_mkdb /etc/login.conf
fi
pw usermod "${SSH_USER:-freebsd}" -L rhorizon-vault 2>/dev/null || \
    pw usermod freebsd -L rhorizon-vault 2>/dev/null || true
# diagnostic so a failing re-run still tells us the live limits
echo ">> mlock diag: unpriv_mlock=$(sysctl -n security.bsd.unprivileged_mlock 2>/dev/null) memlock(freebsd)=$(su -l freebsd -c 'ulimit -l' 2>/dev/null)"

echo ">> initializing PostgreSQL (idempotent)"
if [ ! -d /var/db/postgres/data18 ]; then
    sysrc postgresql_enable=YES
    service postgresql initdb
fi
service postgresql onestart || service postgresql onerestart || true
sleep 3

echo ">> creating rhorizon_test role + database"
su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - postgres -c "psql -c \"CREATE USER rhorizon_test WITH PASSWORD 'rhorizon_test' SUPERUSER\""
su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - postgres -c "psql -c \"CREATE DATABASE rhorizon_test OWNER rhorizon_test\""

echo ">> creating rhorizon venv"
chown -R "${SUDO_USER:-$(whoami)}" "${ROOT_DIR}"
# CFLAGS/LDFLAGS point bonsai's setup.py to OpenLDAP headers (FreeBSD installs
# them under /usr/local, not the Linux-default /usr).
su -l "${SUDO_USER:-$(whoami)}" -c "
    cd '${ROOT_DIR}' &&
    python3.12 -m venv .venv &&
    . .venv/bin/activate &&
    pip install --quiet --upgrade pip wheel &&
    export CFLAGS='-I/usr/local/include' &&
    export LDFLAGS='-L/usr/local/lib' &&
    echo \"CFLAGS=\$CFLAGS LDFLAGS=\$LDFLAGS\" &&
    pip install --quiet --require-hashes -r api/requirements.txt &&
    pip install --quiet -r tools/test-requirements.txt &&
    pip install --quiet maturin
"

echo ">> building rhorizon_crypto Rust extension"
su -l "${SUDO_USER:-$(whoami)}" -c "
    cd '${ROOT_DIR}/api/rust' &&
    . '${ROOT_DIR}/.venv/bin/activate' &&
    RUSTFLAGS='--remap-path-prefix=$(pwd)=.' maturin build --release --strip &&
    pip install --quiet --force-reinstall target/wheels/*.whl
"

echo ">> install complete"
