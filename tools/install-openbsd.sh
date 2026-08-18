#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Bootstrap rhorizon on a fresh OpenBSD 7.7+ system.
# Installs deps + creates a venv + builds the Rust extension + sets up Postgres.
# Designed to run as root (the VM runner SSHes in as root, no doas plumbing).

set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

echo ">> installing OpenBSD packages"
PKG_PATH="${PKG_PATH:-https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/packages/$(uname -m)/}"
export PKG_PATH

# pkg_add -I is non-interactive ; trailing -- requests the default flavor
# when several variants exist (openldap-client vs -gssapi, rsync vs -minimal,
# cyrus-sasl vs -ldap/-pgsql/etc). The python package name is pinned to
# the 3.12.x current at OpenBSD 7.8 ship time - `python%3.12` and
# `python-3.12*` both fail on 7.8 (Can't find), the bare `python-3.12.11`
# resolves cleanly. Bump on OpenBSD release.
# `|| true` because pkg_add returns non-zero when a package is already
# installed - keep going on re-runs against the golden image.
PYTHON_PKG="${PYTHON_PKG-python-3.12.11}"
# py3-cryptography is installed as a bootstrap dependency only. The active
# venv build below uses the OpenSSL port, because current cryptography releases
# do not support OpenBSD base LibreSSL for this wheel path.
# cdn.openbsd.org occasionally truncates a tarball mid-batch ("Premature end
# of archive"), which aborts the WHOLE pkg_add batch and leaves later packages
# (postgresql) uninstalled. A bare `|| true` masks it and the script then dies
# downstream with a cryptic `install: unknown group _postgresql`. So: retry the
# batch (re-fetch is the bypass), then HARD-VERIFY the precondition for the next
# step (_postgresql group) and fail loud + specific instead of cascading.
# NB: the OpenSSL port is version-suffixed and MOVES with the release
# (7.8 = openssl%3.6/eopenssl36, 7.9 = openssl%3.5/eopenssl35). Do NOT pin it in
# this batch -- install it separately below with a newest-first fallback so this
# script survives an OpenBSD bump (matches tools/drivers/openbsd.sh).
PKG_LIST="${PYTHON_PKG} rust libsodium-- openldap-client-- cyrus-sasl--
    postgresql-server-- postgresql-client-- py3-cryptography
    gmake-- pkgconf-- git-- curl-- rsync--"
attempt=1
while [ "${attempt}" -le 3 ]; do
    # non-zero is ambiguous (transient truncation vs already-installed on a
    # golden-image re-run), so the group check below is the real gate.
    pkg_add -I ${PKG_LIST} && break
    grep -q '^_postgresql:' /etc/group && break
    echo ">> pkg_add attempt ${attempt}/3 incomplete, re-fetching..."
    attempt=$((attempt + 1))
    sleep 5
done
if ! grep -q '^_postgresql:' /etc/group; then
    echo "FATAL: postgresql-server absent after 3 pkg_add attempts" >&2
    echo "       (transient cdn.openbsd.org truncation). Re-run, or export" >&2
    echo "       PKG_PATH to a closer/healthier OpenBSD mirror." >&2
    exit 1
fi

# OpenSSL port, newest-first (7.9 = %3.5, 7.8 = %3.6). CPython + cryptography
# are built against it below because base LibreSSL cannot load Ed25519 certs.
pkg_add -I openssl%3.5 || pkg_add -I openssl%3.6 || pkg_add -I openssl || true
if ! ls /usr/local/lib/pkgconfig/eopenssl*.pc >/dev/null 2>&1; then
    echo "FATAL: OpenSSL port (eopenssl) missing after pkg_add" >&2
    exit 1
fi

echo ">> initializing PostgreSQL (idempotent)"
if [ ! -d /var/postgresql/data ]; then
    install -d -o _postgresql -g _postgresql -m 0700 /var/postgresql/data
    su - _postgresql -c "initdb -D /var/postgresql/data --locale=en_US.UTF-8"
fi
rcctl enable postgresql
rcctl restart postgresql || rcctl start postgresql
sleep 3

echo ">> creating rhorizon_test role + database"
# OpenBSD's _postgresql system user has no DB matching its name ; psql
# without -d defaults to current-user-name DB (_postgresql) which does
# not exist. Use `-d postgres` (the bootstrap DB always present after
# initdb) for both the existence checks and the CREATE statements.
su - _postgresql -c "psql -d postgres -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - _postgresql -c "psql -d postgres -c \"CREATE USER rhorizon_test WITH PASSWORD 'rhorizon_test' SUPERUSER\""
su - _postgresql -c "psql -d postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon_test'\"" \
    | grep -q 1 || \
    su - _postgresql -c "psql -d postgres -c \"CREATE DATABASE rhorizon_test OWNER rhorizon_test\""

# OpenBSD pledges `mlock` requires extra resource limits - match the
# systemd LimitMEMLOCK=infinity from the Linux unit file. /etc/login.conf
# capping data/stack also bites the Rust extension; bump login class.
ulimit -l unlimited 2>/dev/null || true
ulimit -d unlimited 2>/dev/null || true

echo ">> building Python from source against OpenSSL (the *BSD way)"
# Base OpenBSD is LibreSSL, and CPython's stdlib `ssl` built against it cannot
# load Ed25519 TLS certs (UNKNOWN_CERTIFICATE_TYPE) -- exactly the cluster mTLS
# cert-renewal + DB-SSL path. Build a CPython whose _ssl links the OpenSSL port
# (eopenssl), found via pkg-config. Source build, the BSD sysadmin way.
# OpenBSD installs the OpenSSL port as eopenssl<NN>, with non-standard
# pkg-config module names (eopenssl36 / libessl36 / libecrypto36) in
# /usr/local/lib/pkgconfig and libs under lib/eopenssl<NN>/. CPython's
# configure and cryptography's openssl-sys both look for the *standard*
# `openssl`/`libssl`/`libcrypto` modules, so alias them and put this dir
# ahead of base LibreSSL's /usr/lib/pkgconfig via PKG_CONFIG_PATH.
EO_VER=$(ls /usr/local/lib/pkgconfig/eopenssl*.pc 2>/dev/null \
    | sed -E 's,.*/eopenssl(.+)\.pc$,\1,' | head -1)
[ -n "${EO_VER}" ] || { echo "!! eopenssl pkgconfig missing -- openssl port not installed:"; pkg_info 2>/dev/null | grep -i ssl; exit 1; }
PCDIR=/usr/local/lib/pkgconfig
ln -sf "eopenssl${EO_VER}.pc"   "${PCDIR}/openssl.pc"
ln -sf "libessl${EO_VER}.pc"    "${PCDIR}/libssl.pc"
ln -sf "libecrypto${EO_VER}.pc" "${PCDIR}/libcrypto.pc"
export PKG_CONFIG_PATH="${PCDIR}"
EO_INC="/usr/local/include/eopenssl${EO_VER}"
EO_LIB="/usr/local/lib/eopenssl${EO_VER}"
echo ">> openssl port eopenssl${EO_VER}; pkg-config openssl -> $(pkg-config --modversion openssl 2>&1)"
# OpenBSD's default disklabel gives small /tmp and / partitions; CPython's
# source build (~1G of objects) + the wheel compiles overflow them. Route all
# build scratch to the roomiest partition (usually /home).
echo ">> disk layout:"; df -h | grep -v '^Filesystem' | sort -k4 -h | tail -4
BUILD_TMP=/home/rh-build
mkdir -p "${BUILD_TMP}"
export TMPDIR="${BUILD_TMP}"
PY_PREFIX=/opt/rhorizon-python
PYBIN="${PY_PREFIX}/bin/python3.12"
PYVER=3.12.11
if [ ! -x "${PYBIN}" ]; then
    ( cd "${BUILD_TMP}"
      [ -f "Python-${PYVER}.tgz" ] || ftp -V -o "Python-${PYVER}.tgz" \
          "https://www.python.org/ftp/python/${PYVER}/Python-${PYVER}.tgz"
      rm -rf "Python-${PYVER}"; tar xzf "Python-${PYVER}.tgz"
      cd "Python-${PYVER}"
      # PKG_CONFIG_PATH is exported above so configure finds the eopenssl alias.
      LDFLAGS="-Wl,-rpath,${EO_LIB}" ./configure --prefix="${PY_PREFIX}" \
          --with-openssl-rpath=auto >"${BUILD_TMP}/py-configure.log" 2>&1 \
          || { echo "!! configure failed:"; tail -30 "${BUILD_TMP}/py-configure.log"; exit 1; }
      grep -iE 'openssl|ssl ' "${BUILD_TMP}/py-configure.log" | tail -4
      gmake -j"$(sysctl -n hw.ncpu)" >"${BUILD_TMP}/py-build.log" 2>&1 \
          || { echo "!! gmake failed:"; tail -30 "${BUILD_TMP}/py-build.log"; exit 1; }
      gmake install >"${BUILD_TMP}/py-install.log" 2>&1 \
          || { echo "!! install failed:"; tail -20 "${BUILD_TMP}/py-install.log"; exit 1; }
      cd "${BUILD_TMP}"; rm -rf "Python-${PYVER}" )    # free ~1G build tree
fi
echo ">> python ssl backend: $(${PYBIN} -c 'import ssl; print(ssl.OPENSSL_VERSION)')"

echo ">> creating rhorizon venv (OpenSSL python; on /home -- / is small)"
"${PYBIN}" -m venv /home/rh-venv
ln -sf /home/rh-venv .venv
. .venv/bin/activate
pip install --quiet --upgrade pip wheel

# cryptography builds its Rust extension against the OpenSSL port here, so
# point it at eopenssl and let pip build it from sdist like every other dep.
# No LibreSSL copy-hack. bonsai also needs ldap.h under /usr/local.
export CFLAGS="-I/usr/local/include"
export LDFLAGS="-L/usr/local/lib"
# cryptography's openssl-sys finds the OpenSSL port via pkg-config
# (PKG_CONFIG_PATH exported above); NO_VENDOR stops it vendoring its own.
# rpath so the built _rust.so finds libssl.so under lib/eopenssl<NN>/.
export OPENSSL_NO_VENDOR=1
export RUSTFLAGS="-C link-arg=-Wl,-rpath,${EO_LIB}"

# requirements.txt already pins the full transitive tree (pip-compile
# output), so --no-deps is safe : pip installs every line literally
# without re-resolving. We strip --hash= and the trailing line
# continuations; cryptography now builds from sdist against the OpenSSL
# port (env set above), no longer the LibreSSL copy-hack.
sed 's/[[:space:]]*--hash=[^[:space:]]*//g' api/requirements.txt \
    | sed 's/[[:space:]]*\\\\$//' \
    > /tmp/req-openbsd.txt
pip install --quiet --no-deps -r /tmp/req-openbsd.txt
pip install --quiet -r tools/test-requirements.txt
pip install --quiet maturin

echo ">> building rhorizon_crypto Rust extension"
cd "${ROOT_DIR}/api/rust"
. "${ROOT_DIR}/.venv/bin/activate"
maturin build --release --strip
pip install --quiet --force-reinstall target/wheels/*.whl

echo ">> install complete"
