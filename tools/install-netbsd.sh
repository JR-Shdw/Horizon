#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh NetBSD 10.x/amd64 system.
# Installs deps from the pkgsrc binary repo + creates a venv + builds the
# Rust extension + sets up PostgreSQL. Runs as root (the VM runner SSHes
# in as root).

set -eu

# A non-interactive `ssh host sh script` gets a minimal PATH that omits
# /usr/sbin (pkg_add) and the pkgsrc dirs. Set it explicitly.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/pkg/sbin:/usr/pkg/bin:${PATH:-}"

# NetBSD /tmp is a small tmpfs (~768M); rustc/cargo wheel builds overflow it.
# Redirect temp to the roomy root filesystem.
export TMPDIR="${TMPDIR:-/var/tmp}"
mkdir -p "$TMPDIR"

# NetBSD doesn't install an openssl.cnf at OPENSSLDIR (/etc/openssl); the
# `openssl req` cert-gen used by the TLS tests fails without it.
[ -f /etc/openssl/openssl.cnf ] || \
    cp /usr/share/examples/openssl/openssl.cnf /etc/openssl/openssl.cnf 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

ARCH="$(uname -m)"                  # amd64
# Pinned upstream: NetBSD release + pkgsrc binary repo URL. Override via env.
NBSD_VERSION="${NBSD_VERSION:-10.1}"
PKG_PATH="${PKG_PATH:-http://ftp.fr.netbsd.org/pub/pkgsrc/packages/NetBSD/${ARCH}/${NBSD_VERSION}/All/}"
export PKG_PATH

# Exact pinned package versions -- the set validated on NetBSD 10.1/amd64.
# py312-cryptography is handed to the venv (--no-deps) from pkgsrc because
# rebuilding cryptography from the PyPI sdist on NetBSD is fragile; keep the
# pkgsrc track current when the PyPI pin moves.
#
# Versions are intentionally UNPINNED: the NetBSD binary mirror's All/ keeps
# only the latest build of each package, so any exact pin (e.g. libsodium-1.0.21)
# starts failing "no pkg found" the moment pkgsrc rolls its nbN suffix -- which
# breaks every dep at once and gives zero reproducibility (you can't fetch the
# old build anyway). True pinning would need a private mirror snapshot. Until
# then, take latest-over-HTTPS; the SLSA posture documents pkgsrc as the weak
# (unsigned) install track.
PKGS="python312 rust libsodium \
      postgresql18-server postgresql18-client \
      py312-cryptography \
      openldap-client cyrus-sasl \
      git-base curl libffi"

echo ">> installing pkgsrc binary packages (PKG_PATH=${PKG_PATH})"
for p in ${PKGS}; do
    pkg_add "$p" || true
done

PYTHON=/usr/pkg/bin/python3.12

echo ">> raising SysV semaphore/shm limits (NetBSD defaults are too low for PostgreSQL)"
for kv in kern.ipc.semmni=256 kern.ipc.semmns=4096 kern.ipc.semmnu=512 \
          kern.ipc.shmmax=1073741824 kern.ipc.shmall=262144; do
    sysctl -w "$kv" >/dev/null 2>&1 || true
    grep -q "^${kv%%=*}=" /etc/sysctl.conf 2>/dev/null || echo "$kv" >> /etc/sysctl.conf
done

echo ">> initializing PostgreSQL (idempotent)"
PGDATA=/usr/pkg/pgsql/data
if [ ! -d "${PGDATA}/base" ]; then
    install -d -o pgsql -g pgsql -m 0700 "${PGDATA}"
    su -m pgsql -c "/usr/pkg/bin/initdb -D ${PGDATA} --encoding=UTF8 --locale=C"
fi
# pkgsrc ships the rc.d script as an example; wire it into the system.
[ -f /etc/rc.d/pgsql ] || cp /usr/pkg/share/examples/rc.d/pgsql /etc/rc.d/pgsql
grep -q '^pgsql=YES' /etc/rc.conf || echo 'pgsql=YES' >> /etc/rc.conf
# The pkgsrc pgsql rc.d already runs `pg_ctl -w -D <pgsql_home>/data -l errlog`.
# `pgsql_flags` are POSTMASTER options forwarded via `pg_ctl -o`, so they must
# NOT contain -D/-w (PG18: passing -w yields `postgres: unknown option -- w`).
# Leave it unset; strip any stale line a previous run may have written.
grep -v '^pgsql_flags' /etc/rc.conf > /etc/rc.conf.tmp && mv /etc/rc.conf.tmp /etc/rc.conf
# the rc.d script writes its startup log to /usr/pkg/pgsql/errlog; the pgsql
# user must own that directory or the redirect fails with permission denied.
chown pgsql:pgsql /usr/pkg/pgsql 2>/dev/null || true
/etc/rc.d/pgsql restart || /etc/rc.d/pgsql start
sleep 3

echo ">> creating rhorizon_test role + database"
su -m pgsql -c "/usr/pkg/bin/psql -d postgres -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon_test'\"" \
    | grep -q 1 || \
    su -m pgsql -c "/usr/pkg/bin/psql -d postgres -c \"CREATE USER rhorizon_test WITH PASSWORD 'rhorizon_test' SUPERUSER\""
su -m pgsql -c "/usr/pkg/bin/psql -d postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon_test'\"" \
    | grep -q 1 || \
    su -m pgsql -c "/usr/pkg/bin/psql -d postgres -c \"CREATE DATABASE rhorizon_test OWNER rhorizon_test\""

# The Rust extension mlocks key pages; lift the per-process lock limit.
ulimit -l unlimited 2>/dev/null || true

echo ">> creating rhorizon venv"
${PYTHON} -m venv .venv
. .venv/bin/activate
pip install --quiet --upgrade pip wheel

# Hand the pkgsrc py312-cryptography to the venv before pip resolves anything,
# then install requirements with --no-deps so pip never tries to rebuild
# cryptography from the sdist on NetBSD.
SYS_SITE=/usr/pkg/lib/python3.12/site-packages
VENV_SITE=.venv/lib/python3.12/site-packages
cp -R "${SYS_SITE}/cryptography" "${VENV_SITE}/"
cp -R "${SYS_SITE}"/cryptography-*.dist-info "${VENV_SITE}/"

# pkgsrc installs headers/libs under /usr/pkg ; PyNaCl uses the pkgsrc
# libsodium (SODIUM_INSTALL=system), bonsai needs ldap.h / sasl.h from there.
export CFLAGS='-I/usr/pkg/include'
export LDFLAGS='-L/usr/pkg/lib'
export SODIUM_INSTALL=system

# requirements.txt pins the full transitive tree (pip-compile output), so
# --no-deps installs each line literally. Strip --hash= + line continuations
# and drop the cryptography pin (the venv copy stays canonical).
# Also drop uvloop: its NetBSD build links an undefined `kvm_open` symbol and
# fails to import. It is an optional uvicorn speedup rhorizon does not need;
# without it the event loop falls back to plain asyncio.
sed 's/[[:space:]]*--hash=[^[:space:]]*//g' api/requirements.txt \
    | sed 's/[[:space:]]*\\$//' \
    | grep -vE '^(cryptography|uvloop)==' \
    > "${TMPDIR}/req-netbsd.txt"
pip install --quiet --no-deps -r "${TMPDIR}/req-netbsd.txt"
pip install --quiet -r tools/test-requirements.txt
pip install --quiet maturin

echo ">> building rhorizon_crypto Rust extension"
cd "${ROOT_DIR}/api/rust"
. "${ROOT_DIR}/.venv/bin/activate"
maturin build --release --strip
pip install --quiet --force-reinstall target/wheels/*.whl

echo ">> install complete"
