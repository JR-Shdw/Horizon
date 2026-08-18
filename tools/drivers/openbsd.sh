# SPDX-License-Identifier: AGPL-3.0-or-later
# rhorizon driver: OpenBSD (7.8/7.9). Native, no Docker.
#
# The hard part: base LibreSSL's CPython ssl cannot load Ed25519 TLS certs, so
# we build CPython from source against the OpenSSL port (eopenssl). See
# ha/bsd/openbsd-7.9-app-node.md. Captured functions (driver_python /
# driver_build_env / driver_pg_setup) print ONLY their value to stdout; all
# progress goes to stderr.

_PY_PREFIX=/usr/local/rhorizon-python
_PYVER=3.12.11

driver_pkg() {
    PKG_PATH="${PKG_PATH:-https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/packages/$(uname -m)/}"
    export PKG_PATH
    # libffi: cffi (a cryptography build dep) needs ffi.h + libffi.pc. It used to
    # arrive via py3-cryptography; we build cryptography from source, so add it.
    run pkg_add -I rust libsodium-- libffi openldap-client-- cyrus-sasl-- \
        gmake-- pkgconf-- git-- curl-- postgresql-server-- postgresql-client-- \
        nginx-- libev--
    # openssl port: 7.9 = %3.5 (eopenssl35), 7.8 = %3.6. Try newest-supported first.
    run sh -c 'pkg_add -I openssl%3.5 || pkg_add -I openssl%3.6 || pkg_add -I openssl' || true
    ls /usr/local/lib/pkgconfig/eopenssl*.pc >/dev/null 2>&1 \
        || { [ "${DRY_RUN:-0}" = 1 ] || die "eopenssl port missing after pkg_add"; }
}

# stdout: the ssl-capable interpreter path. Build from source vs eopenssl if absent.
driver_python() {
    _pybin="$_PY_PREFIX/bin/python3.12"
    if [ "${DRY_RUN:-0}" = 1 ]; then
        echo ">> would build CPython $_PYVER from source vs eopenssl -> $_pybin" >&2
        echo "$_pybin"; return 0
    fi
    if [ ! -x "$_pybin" ]; then
        _eo=$(ls /usr/local/lib/pkgconfig/eopenssl*.pc | sed -E 's,.*/eopenssl(.+)\.pc$,\1,' | head -1)
        _pc=/usr/local/lib/pkgconfig
        ln -sf "eopenssl${_eo}.pc" "$_pc/openssl.pc"
        ln -sf "libessl${_eo}.pc" "$_pc/libssl.pc"
        ln -sf "libecrypto${_eo}.pc" "$_pc/libcrypto.pc"
        export PKG_CONFIG_PATH="$_pc"
        _eolib="/usr/local/lib/eopenssl${_eo}"
        _bt=/home/rh-build; mkdir -p "$_bt"; export TMPDIR="$_bt"
        ( cd "$_bt"
          [ -f "Python-$_PYVER.tgz" ] || ftp -V -o "Python-$_PYVER.tgz" \
              "https://www.python.org/ftp/python/$_PYVER/Python-$_PYVER.tgz"
          rm -rf "Python-$_PYVER"; tar xzf "Python-$_PYVER.tgz"; cd "Python-$_PYVER"
          LDFLAGS="-Wl,-rpath,$_eolib" ./configure --prefix="$_PY_PREFIX" --with-openssl-rpath=auto
          gmake -j"$(sysctl -n hw.ncpu)" && gmake install
          cd "$_bt"; rm -rf "Python-$_PYVER" ) >&2
    fi
    "$_pybin" -c 'import ssl; assert "OpenSSL" in ssl.OPENSSL_VERSION, ssl.OPENSSL_VERSION' >&2 2>&1 \
        || echo ">> warn: ssl backend not OpenSSL" >&2
    echo "$_pybin"
}

# stdout: env assignments for the venv build (cryptography+PyNaCl vs eopenssl).
driver_build_env() {
    _eo=$(ls /usr/local/lib/pkgconfig/eopenssl*.pc 2>/dev/null | sed -E 's,.*/eopenssl(.+)\.pc$,\1,' | head -1)
    echo "CFLAGS=-I/usr/local/include"
    echo "LDFLAGS=-L/usr/local/lib"
    echo "OPENSSL_NO_VENDOR=1"
    echo "PKG_CONFIG_PATH=/usr/local/lib/pkgconfig"
    # OpenBSD's /tmp (~1G) overflows the Rust wheel builds (watchfiles + deps).
    # Route build scratch to the roomy /usr/local partition.
    echo "TMPDIR=/usr/local/rh-build"
    [ -n "$_eo" ] && echo "RUSTFLAGS=-Clink-arg=-Wl,-rpath,/usr/local/lib/eopenssl${_eo}"
}

# stdout: DATABASE_URL. initdb + role + db, idempotent.
driver_pg_setup() {
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "postgresql+asyncpg://rhorizon:DRYRUN@127.0.0.1:5432/rhorizon"; return 0; fi
    _pw=$(gen_secret 18)
    # PG18 needs far more SysV semaphores than OpenBSD's default (semmni=10) or
    # initdb's bootstrap dies "could not create semaphores". Sizing: PG uses
    # ~ceil((max_connections+workers+aux)/16) sets of ~17; default 100 conns = ~8
    # sets/~136 sems. 256/2048 -> ~1900 backends (~18x default), covers the heavy
    # tier + max_connections bumps with no re-tune; sems are ~tens of bytes each.
    # Runtime-settable; persist to /etc/sysctl.conf so PG survives reboot.
    for _kv in kern.seminfo.semmni=256 kern.seminfo.semmns=2048 kern.seminfo.semmnu=256; do
        sysctl -w "$_kv" >/dev/null 2>&1 || true
        grep -q "^${_kv%%=*}=" /etc/sysctl.conf 2>/dev/null || echo "$_kv" >> /etc/sysctl.conf
    done
    # Guard on PG_VERSION, not dir existence: a failed initdb leaves an empty dir.
    [ -f /var/postgresql/data/PG_VERSION ] || {
        install -d -o _postgresql -g _postgresql -m 0700 /var/postgresql/data
        su - _postgresql -c "initdb -D /var/postgresql/data --locale=en_US.UTF-8" >&2
    }
    rcctl enable postgresql >&2 2>&1 || true
    rcctl -f start postgresql >&2 2>&1 || true; sleep 2
    su - _postgresql -c "psql -d postgres -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon'\"" 2>/dev/null | grep -q 1 \
        || su - _postgresql -c "psql -d postgres -c \"CREATE USER rhorizon WITH PASSWORD '$_pw'\"" >&2
    su - _postgresql -c "psql -d postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon'\"" 2>/dev/null | grep -q 1 \
        || su - _postgresql -c "psql -d postgres -c \"CREATE DATABASE rhorizon OWNER rhorizon\"" >&2
    echo "postgresql+asyncpg://rhorizon:$_pw@127.0.0.1:5432/rhorizon"
}

# driver_service_install WORKDIR VENV ENVFILE RUNCMD
# system mode -> rc.d unit (boot-safe); user mode -> wrapper only (nohup start).
driver_service_install() {
    _wd=$1; _env=$3; _run=$4
    run sh -c "cat > '$_wd/run-app.sh' <<EOF
#!/bin/sh
# mlockall() wires the whole process + the transient 256MB Argon2 unseal buffer.
# Bound memlock to the dispatcher-computed budget (workers*160 + 256 + 192 MB),
# NOT unlimited. OpenBSD default -l (~85M) is too small; -d default 4G is ample.
ulimit -l $RH_MEMLOCK_KB 2>/dev/null || true
set -a; . '$_env'; set +a
[ -n "\${RHORIZON_RUNTIME_DIR:-}" ] && mkdir -p "\$RHORIZON_RUNTIME_DIR" && chmod 700 "\$RHORIZON_RUNTIME_DIR"
[ -n "\${RHORIZON_AUDIT_DIR:-}" ] && mkdir -p "\$RHORIZON_AUDIT_DIR" && chmod 700 "\$RHORIZON_AUDIT_DIR"
exec $_run
EOF"
    run chmod +x "$_wd/run-app.sh"
    RH_RUN="$_wd/run-app.sh"; export RH_RUN
    [ "${RH_MODE:-system}" = user ] && return 0
    run sh -c "cat > /etc/rc.d/rhorizon <<EOF
#!/bin/ksh
daemon='$_wd/run-app.sh'
. /etc/rc.d/rc.subr
rc_bg=YES
rc_reload=NO
rc_cmd \\\$1
EOF"
    run chmod +x /etc/rc.d/rhorizon
    run rcctl enable rhorizon
}

# OpenBSD is the one lane where nginx can be WEAKER than uvicorn: this driver
# installs the OpenSSL port (eopenssl 3.5/3.6) and builds CPython against it,
# so uvicorn negotiates X25519MLKEM768 -- while the nginx package links base
# LibreSSL, which has no ML-KEM at all. RH_NGINX_REQUIRE_PQ makes the installer
# probe the actual binary and fall back to uvicorn termination when the group is
# missing: on a vault, keeping post-quantum key exchange beats gaining HTTP/2.
# An nginx built against eopenssl satisfies the probe and gets both:
# tools/build-nginx-bsd.sh does that from a SHA-256- and PGP-pinned source,
# so it does not bypass the supply chain the packages go through.
RH_NGINX_REQUIRE_PQ=1
export RH_NGINX_REQUIRE_PQ

# Prefer an eopenssl-linked nginx if tools/build-nginx-bsd.sh has produced
# one: that build is the only way this lane gets HTTP/2 *and* post-quantum,
# since the packaged binary links base LibreSSL. Absent it, RH_NGINX_REQUIRE_PQ
# above keeps TLS at uvicorn rather than downgrading the handshake.
if [ -x /usr/local/rhorizon/nginx/sbin/nginx ]; then
    RH_NGINX_BIN=/usr/local/rhorizon/nginx/sbin/nginx
    export RH_NGINX_BIN
fi

driver_service_install_nginx() {
    _nbin=$1; _npfx=$2; _nconf=$3
    RH_NGINX_CMD="$_nbin -p $_npfx -c $_nconf"; export RH_NGINX_CMD
    [ "${RH_MODE:-system}" = user ] && return 0
    run sh -c "cat > /etc/rc.d/rhorizon_nginx <<EOF
#!/bin/ksh
daemon='$_nbin'
daemon_flags='-p $_npfx -c $_nconf'
. /etc/rc.d/rc.subr
rc_reload=NO
# rc_pre runs before the daemon: refuse a bad render rather than leave the
# vault unreachable behind a dead proxy.
rc_pre() { $_nbin -t -p $_npfx -c $_nconf; }
rc_cmd \\\$1
EOF"
    run chmod +x /etc/rc.d/rhorizon_nginx
    run rcctl enable rhorizon_nginx
}

driver_start_nginx() {
    if [ "${RH_MODE:-system}" = user ]; then run sh -c "$RH_NGINX_CMD"
    else run rcctl -f start rhorizon_nginx || run rcctl restart rhorizon_nginx; fi
}

driver_start() {
    if [ "${RH_MODE:-system}" = user ]; then run sh -c "nohup '$RH_RUN' >/dev/null 2>&1 &"
    else run rcctl -f start rhorizon || run rcctl restart rhorizon; fi
}

# driver_uninstall -- reverse driver_service_install (rc.d + rcctl). Idempotent.
driver_uninstall() {
    [ "${RH_MODE:-system}" = user ] && return 0
    run rcctl stop rhorizon_nginx >/dev/null 2>&1 || true
    run rcctl disable rhorizon_nginx >/dev/null 2>&1 || true
    run rm -f /etc/rc.d/rhorizon_nginx
    run rcctl stop rhorizon >/dev/null 2>&1 || true
    run rcctl disable rhorizon >/dev/null 2>&1 || true
    run rm -f /etc/rc.d/rhorizon
}

# driver_db_drop -- DESTRUCTIVE: drop the rhorizon role + database. Idempotent.
driver_db_drop() {
    su - _postgresql -c "psql -d postgres -c \"DROP DATABASE IF EXISTS rhorizon\"" >&2 2>&1 || true
    su - _postgresql -c "psql -d postgres -c \"DROP ROLE IF EXISTS rhorizon\"" >&2 2>&1 || true
}
