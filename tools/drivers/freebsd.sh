# SPDX-License-Identifier: AGPL-3.0-or-later
# rhorizon driver: FreeBSD 14.x. Native, no Docker. Base OpenSSL loads Ed25519,
# so cryptography builds from sdist -- no from-source Python (unlike OpenBSD).
# Captured hooks (driver_python/build_env/pg_setup) print ONLY their value.

driver_pkg() {
    export ASSUME_ALWAYS_YES=yes
    run pkg update -q
    run pkg install -y python312 py312-sqlite3 rust libsodium \
        openldap26-client cyrus-sasl postgresql18-server postgresql18-client \
        git pkgconf gcc curl ca_root_nss nginx
    # libev supplies ev.h for cassandra-driver's optional C extension. Kept
    # out of the list above and tolerated: that call aborts the whole install
    # on any unknown package, and this one is only needed by an optional
    # dynamic-secrets engine.
    run pkg install -y libev || true
    # unprivileged_mlock is a SYSTEM-WIDE relaxation; only user (non-root) mode
    # needs it (root can mlock already). Don't touch it for a system install.
    if [ "${RH_MODE:-system}" = user ]; then
        run sysctl security.bsd.unprivileged_mlock=1 >/dev/null 2>&1 || true
    fi
}

driver_python() {
    [ "${DRY_RUN:-0}" = 1 ] && { echo /usr/local/bin/python3.12; return 0; }
    command -v python3.12 >/dev/null 2>&1 || die "python312 missing after driver_pkg"
    python3.12 -c 'import encodings' 2>/dev/null || run pkg install -f -y python312
    command -v python3.12
}

driver_build_env() {
    echo "CFLAGS=-I/usr/local/include"
    echo "LDFLAGS=-L/usr/local/lib"
}

driver_pg_setup() {
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "postgresql+asyncpg://rhorizon:DRYRUN@127.0.0.1:5432/rhorizon"; return 0; fi
    _pw=$(gen_secret 18)
    [ -d /var/db/postgres/data18 ] || { sysrc postgresql_enable=YES >&2; service postgresql initdb >&2; }
    service postgresql onestart >&2 2>&1 || service postgresql onerestart >&2 2>&1 || true
    sleep 3
    su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon'\"" 2>/dev/null | grep -q 1 \
        || su - postgres -c "psql -c \"CREATE USER rhorizon WITH PASSWORD '$_pw'\"" >&2
    su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon'\"" 2>/dev/null | grep -q 1 \
        || su - postgres -c "psql -c \"CREATE DATABASE rhorizon OWNER rhorizon\"" >&2
    echo "postgresql+asyncpg://rhorizon:$_pw@127.0.0.1:5432/rhorizon"
}

# system -> /usr/local/etc/rc.d rc.d + sysrc enable ; user -> nohup wrapper.
driver_service_install() {
    _wd=$1; _env=$3; _run=$4
    run sh -c "cat > '$_wd/run-app.sh' <<EOF
#!/bin/sh
ulimit -l $RH_MEMLOCK_KB 2>/dev/null || true   # mlockall budget (workers*160+256+192 MB)
set -a; . '$_env'; set +a
[ -n "\${RHORIZON_RUNTIME_DIR:-}" ] && mkdir -p "\$RHORIZON_RUNTIME_DIR" && chmod 700 "\$RHORIZON_RUNTIME_DIR"
[ -n "\${RHORIZON_AUDIT_DIR:-}" ] && mkdir -p "\$RHORIZON_AUDIT_DIR" && chmod 700 "\$RHORIZON_AUDIT_DIR"
exec $_run
EOF"
    run chmod +x "$_wd/run-app.sh"
    RH_RUN="$_wd/run-app.sh"; export RH_RUN
    [ "${RH_MODE:-system}" = user ] && return 0
    run sh -c "cat > /usr/local/etc/rc.d/rhorizon <<EOF
#!/bin/sh
# PROVIDE: rhorizon
# REQUIRE: LOGIN postgresql
# KEYWORD: shutdown
. /etc/rc.subr
name=rhorizon
rcvar=rhorizon_enable
command=/usr/sbin/daemon
pidfile=${RH_NATIVE_RUNTIME_DIR:-/var/run/rhorizon}/rhorizon.pid
command_args=\"-f -p \\\${pidfile} $_wd/run-app.sh\"
load_rc_config \\\$name
: \\\${rhorizon_enable:=NO}
run_rc_command \\\$1
EOF"
    run chmod +x /usr/local/etc/rc.d/rhorizon
    run sysrc rhorizon_enable=YES
}

# Prefer an openssl35-linked nginx if tools/build-nginx-bsd.sh has produced one.
# The pkg nginx links BASE OpenSSL (measured: /usr/lib/libssl.so.30, 3.0.20 on
# 14.4), which has no ML-KEM. Unlike OpenBSD there is no RH_NGINX_REQUIRE_PQ
# here on purpose: the packaged python312 links the same base libssl, so uvicorn
# has no post-quantum either -- declining nginx would lose HTTP/2 and gain
# nothing. Build the nginx to get PQ; do not fall back expecting it.
if [ -x /usr/local/rhorizon/nginx/sbin/nginx ]; then
    RH_NGINX_BIN=/usr/local/rhorizon/nginx/sbin/nginx
    export RH_NGINX_BIN
fi

# driver_service_install_nginx BIN PREFIX CONF -- TLS + HTTP/2 front. Defining
# this is what makes install-native.sh choose nginx over uvicorn termination.
# nginx daemonises itself and writes the pidfile named in the generated config,
# so rc.d supervises it directly rather than through daemon(8).
driver_service_install_nginx() {
    _nbin=$1; _npfx=$2; _nconf=$3
    RH_NGINX_CMD="$_nbin -p $_npfx -c $_nconf"; export RH_NGINX_CMD
    [ "${RH_MODE:-system}" = user ] && return 0
    run sh -c "cat > /usr/local/etc/rc.d/rhorizon_nginx <<EOF
#!/bin/sh
# PROVIDE: rhorizon_nginx
# REQUIRE: LOGIN rhorizon
# KEYWORD: shutdown
. /etc/rc.subr
name=rhorizon_nginx
rcvar=rhorizon_nginx_enable
command=$_nbin
command_args=\"-p $_npfx -c $_nconf\"
pidfile=$_npfx/nginx.pid
# Refuse to start on a bad render rather than leave the vault behind a dead
# proxy; rc.d has no ExecStartPre, so the test is a precmd.
start_precmd=\"$_nbin -t -p $_npfx -c $_nconf\"
stop_cmd=\"$_nbin -p $_npfx -c $_nconf -s quit\"
load_rc_config \\\$name
: \\\${rhorizon_nginx_enable:=NO}
run_rc_command \\\$1
EOF"
    run chmod +x /usr/local/etc/rc.d/rhorizon_nginx
    run sysrc rhorizon_nginx_enable=YES
}

driver_start_nginx() {
    if [ "${RH_MODE:-system}" = user ]; then run sh -c "$RH_NGINX_CMD"
    else run service rhorizon_nginx onestart || run service rhorizon_nginx onerestart; fi
}

driver_start() {
    if [ "${RH_MODE:-system}" = user ]; then run sh -c "nohup '$RH_RUN' >/dev/null 2>&1 &"
    else run service rhorizon onestart || run service rhorizon onerestart; fi
}

# driver_uninstall -- reverse driver_service_install (rc.d + sysrc). Idempotent.
driver_uninstall() {
    [ "${RH_MODE:-system}" = user ] && return 0
    run service rhorizon_nginx onestop >/dev/null 2>&1 || true
    run sysrc -x rhorizon_nginx_enable >/dev/null 2>&1 || true
    run rm -f /usr/local/etc/rc.d/rhorizon_nginx
    run service rhorizon onestop >/dev/null 2>&1 || true
    run sysrc -x rhorizon_enable >/dev/null 2>&1 || true
    run rm -f /usr/local/etc/rc.d/rhorizon
}

# driver_db_drop -- DESTRUCTIVE: drop the rhorizon role + database. Idempotent.
driver_db_drop() {
    su - postgres -c "psql -c \"DROP DATABASE IF EXISTS rhorizon\"" >&2 2>&1 || true
    su - postgres -c "psql -c \"DROP ROLE IF EXISTS rhorizon\"" >&2 2>&1 || true
}
