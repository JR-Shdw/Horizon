# SPDX-License-Identifier: AGPL-3.0-or-later
# rhorizon driver: NetBSD 10.x (pkgsrc). Native, no Docker.
# Quirks vs the others: Rust openssl-sys can't build cryptography -> use pkgsrc
# py312-cryptography copied into the venv + excluded from pip; uvloop drops in
# build (kvm_open) -> excluded, asyncio fallback; /etc/openssl/openssl.cnf absent.
# Captured hooks print ONLY their value.

_PYBIN=/usr/pkg/bin/python3.12
_PGDATA=/usr/pkg/pgsql/data

driver_pkg() {
    export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/pkg/sbin:/usr/pkg/bin:${PATH:-}"
    [ -f /etc/openssl/openssl.cnf ] || run sh -c 'cp /usr/share/examples/openssl/openssl.cnf /etc/openssl/openssl.cnf 2>/dev/null || true'
    _arch=$(uname -m); _ver="${NBSD_VERSION:-10.1}"
    PKG_PATH="${PKG_PATH:-http://ftp.fr.netbsd.org/pub/pkgsrc/packages/NetBSD/${_arch}/${_ver}/All/}"
    export PKG_PATH
    for p in python312 rust libsodium postgresql18-server postgresql18-client \
             py312-cryptography openldap-client cyrus-sasl git-base curl libffi \
             nginx libev openssl; do
        run pkg_add "$p" || true
    done
    # PostgreSQL needs higher SysV semaphore + shared-memory limits than NetBSD
    # defaults. Sems: PG uses ~ceil((max_connections+workers+aux)/16) sets of ~17;
    # semmni=256/semmns=4096 -> ~1900 backends, ~18x the 100-conn default, headroom
    # for max_connections bumps (sems are ~tens of bytes). shmmax=1G/shmall=262144
    # pages (=1G): a single shared-memory segment big enough for PG shared_buffers.
    for kv in kern.ipc.semmni=256 kern.ipc.semmns=4096 kern.ipc.semmnu=512 \
              kern.ipc.shmmax=1073741824 kern.ipc.shmall=262144; do
        run sysctl -w "$kv" >/dev/null 2>&1 || true
        grep -q "^${kv%%=*}=" /etc/sysctl.conf 2>/dev/null || run sh -c "echo '$kv' >> /etc/sysctl.conf"
    done
}

driver_python() { [ "${DRY_RUN:-0}" = 1 ] || [ -x "$_PYBIN" ] || die "pkgsrc python312 missing"; echo "$_PYBIN"; }

driver_build_env() {
    echo "CFLAGS=-I/usr/pkg/include"
    echo "LDFLAGS=-L/usr/pkg/lib"
    echo "SODIUM_INSTALL=system"
    # NetBSD /tmp is a small tmpfs (~768M); rustc/cargo wheel builds overflow it.
    # Route build scratch to the roomy /var/tmp (install-native.sh mkdir -p's it).
    echo "TMPDIR=/var/tmp"
    # TMPDIR alone is not enough: cargo ignores it for the two biggest consumers.
    # The registry lands in ~/.cargo and the release artifacts in the checkout's
    # api/rust/target -- both on /, which is how a 13G root filled to 12G and
    # then killed initdb with ENOSPC even after /var/tmp got its own disk.
    # install-native.sh redirects both into a mktemp -d scratch under TMPDIR and
    # removes it after the build; fixed paths are not used, so nothing here can
    # collide with -- or later delete -- a directory the host already owned.
    printf 'RH_PIP_EXCLUDE="%s"\n' 'cryptography|uvloop'   # quoted: | must survive sourcing
}

# copy pkgsrc-built cryptography into the venv (pip can't build it here)
driver_venv_extra() {
    _v=$1
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "   [dry-run] copy pkgsrc cryptography -> $_v"; return 0; fi
    _s=/usr/pkg/lib/python3.12/site-packages
    _d="$_v/lib/python3.12/site-packages"
    cp -R "$_s/cryptography" "$_d/" 2>/dev/null || true
    cp -R "$_s"/cryptography-*.dist-info "$_d/" 2>/dev/null || true
}

driver_pg_setup() {
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "postgresql+asyncpg://rhorizon:DRYRUN@127.0.0.1:5432/rhorizon"; return 0; fi
    _pw=$(gen_secret 18)
    [ -d "$_PGDATA/base" ] || {
        install -d -o pgsql -g pgsql -m 0700 "$_PGDATA"
        su -m pgsql -c "/usr/pkg/bin/initdb -D $_PGDATA --encoding=UTF8 --locale=C" >&2
    }
    [ -f /etc/rc.d/pgsql ] || cp /usr/pkg/share/examples/rc.d/pgsql /etc/rc.d/pgsql
    grep -q '^pgsql=YES' /etc/rc.conf || echo 'pgsql=YES' >> /etc/rc.conf
    chown pgsql:pgsql /usr/pkg/pgsql 2>/dev/null || true
    /etc/rc.d/pgsql restart >&2 2>&1 || /etc/rc.d/pgsql start >&2 2>&1 || true
    sleep 3
    su -m pgsql -c "/usr/pkg/bin/psql -d postgres -tAc \"SELECT 1 FROM pg_roles WHERE rolname='rhorizon'\"" 2>/dev/null | grep -q 1 \
        || su -m pgsql -c "/usr/pkg/bin/psql -d postgres -c \"CREATE USER rhorizon WITH PASSWORD '$_pw'\"" >&2
    su -m pgsql -c "/usr/pkg/bin/psql -d postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='rhorizon'\"" 2>/dev/null | grep -q 1 \
        || su -m pgsql -c "/usr/pkg/bin/psql -d postgres -c \"CREATE DATABASE rhorizon OWNER rhorizon\"" >&2
    echo "postgresql+asyncpg://rhorizon:$_pw@127.0.0.1:5432/rhorizon"
}

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
    run sh -c "cat > /etc/rc.d/rhorizon <<EOF
#!/bin/sh
# PROVIDE: rhorizon
# REQUIRE: DAEMON pgsql
. /etc/rc.subr
name=rhorizon
rcvar=\\\$name
pidfile=${RH_NATIVE_RUNTIME_DIR:-/var/run/rhorizon}/rhorizon.pid
start_cmd=rhorizon_start
stop_cmd=rhorizon_stop
rhorizon_start() { mkdir -p ${RH_NATIVE_RUNTIME_DIR:-/var/run/rhorizon} ${RH_NATIVE_AUDIT_DIR:-/var/log/rhorizon}; /usr/bin/nohup $_wd/run-app.sh > ${RH_NATIVE_AUDIT_DIR:-/var/log/rhorizon}/service.log 2>&1 & echo \\\$! > \\\$pidfile; }
rhorizon_stop() { [ -f \\\$pidfile ] && kill \"\\\$(cat \\\$pidfile)\"; }
load_rc_config \\\$name
run_rc_command \\\$1
EOF"
    run chmod +x /etc/rc.d/rhorizon
    grep -q '^rhorizon=YES' /etc/rc.conf 2>/dev/null || run sh -c "echo 'rhorizon=YES' >> /etc/rc.conf"
}

# driver_service_install_nginx BIN PREFIX CONF -- TLS + HTTP/2 front. Defining
# this is what makes install-native.sh choose nginx over uvicorn termination.
# nginx daemonises and writes its own pidfile, so unlike the API wrapper this
# needs no nohup/pidfile bookkeeping.
driver_service_install_nginx() {
    _nbin=$1; _npfx=$2; _nconf=$3
    RH_NGINX_CMD="$_nbin -p $_npfx -c $_nconf"; export RH_NGINX_CMD
    [ "${RH_MODE:-system}" = user ] && return 0
    run sh -c "cat > /etc/rc.d/rhorizon_nginx <<EOF
#!/bin/sh
# PROVIDE: rhorizon_nginx
# REQUIRE: DAEMON rhorizon
. /etc/rc.subr
name=rhorizon_nginx
rcvar=\\\$name
pidfile=$_npfx/nginx.pid
start_cmd=rhn_start
stop_cmd=rhn_stop
# Config test before start: a bad render must fail loudly, not leave the vault
# unreachable behind a dead proxy.
rhn_start() { $_nbin -t -p $_npfx -c $_nconf || return 1; $_nbin -p $_npfx -c $_nconf; }
rhn_stop() { $_nbin -p $_npfx -c $_nconf -s quit 2>/dev/null || true; }
load_rc_config \\\$name
run_rc_command \\\$1
EOF"
    run chmod +x /etc/rc.d/rhorizon_nginx
    grep -q '^rhorizon_nginx=YES' /etc/rc.conf 2>/dev/null \
        || run sh -c "echo 'rhorizon_nginx=YES' >> /etc/rc.conf"
}

# Prefer an nginx built against pkgsrc OpenSSL if tools/build-nginx-bsd.sh has
# produced one. NetBSD base is OpenSSL 3.0.12 with no ML-KEM, so the packaged
# nginx gives HTTP/2 without post-quantum; pkgsrc's 3.6.3 has it. Like FreeBSD
# and unlike OpenBSD, RH_NGINX_REQUIRE_PQ is deliberately NOT set: the venv
# links base too, so declining nginx would drop HTTP/2 and gain nothing.
if [ -x /usr/pkg/rhorizon/nginx/sbin/nginx ]; then
    RH_NGINX_BIN=/usr/pkg/rhorizon/nginx/sbin/nginx
    export RH_NGINX_BIN
fi

driver_start_nginx() {
    if [ "${RH_MODE:-system}" = user ]; then run sh -c "$RH_NGINX_CMD"
    else run /etc/rc.d/rhorizon_nginx restart || run /etc/rc.d/rhorizon_nginx start; fi
}

driver_start() {
    if [ "${RH_MODE:-system}" = user ]; then run sh -c "nohup '$RH_RUN' >/dev/null 2>&1 &"
    else run /etc/rc.d/rhorizon restart || run /etc/rc.d/rhorizon start; fi
}

# driver_uninstall -- reverse driver_service_install (rc.d + rc.conf). Idempotent.
driver_uninstall() {
    [ "${RH_MODE:-system}" = user ] && return 0
    run /etc/rc.d/rhorizon_nginx stop >/dev/null 2>&1 || true
    run sh -c "if grep -q '^rhorizon_nginx=YES' /etc/rc.conf 2>/dev/null; then grep -v '^rhorizon_nginx=YES' /etc/rc.conf > /etc/rc.conf.tmp && mv /etc/rc.conf.tmp /etc/rc.conf; fi"
    run rm -f /etc/rc.d/rhorizon_nginx
    run /etc/rc.d/rhorizon stop >/dev/null 2>&1 || true
    run sh -c "if grep -q '^rhorizon=YES' /etc/rc.conf 2>/dev/null; then grep -v '^rhorizon=YES' /etc/rc.conf > /etc/rc.conf.tmp && mv /etc/rc.conf.tmp /etc/rc.conf; fi"
    run rm -f /etc/rc.d/rhorizon
}

# driver_db_drop -- DESTRUCTIVE: drop the rhorizon role + database. Idempotent.
driver_db_drop() {
    su -m pgsql -c "/usr/pkg/bin/psql -d postgres -c \"DROP DATABASE IF EXISTS rhorizon\"" >&2 2>&1 || true
    su -m pgsql -c "/usr/pkg/bin/psql -d postgres -c \"DROP ROLE IF EXISTS rhorizon\"" >&2 2>&1 || true
}
