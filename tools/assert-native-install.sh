#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Assertions run inside the disposable VM created by tools/test-vm.sh.
# This is not an installer: it verifies the identity and memory boundary that
# the native system installer promised after the service has started.

set -eu

OS=${1:?usage: assert-native-install.sh OS MODE CA_FILE}
MODE=${2:?usage: assert-native-install.sh OS MODE CA_FILE}
CA_FILE=${3:?usage: assert-native-install.sh OS MODE CA_FILE}

fail() { printf 'FAIL: native install assertion: %s\n' "$*" >&2; exit 1; }
pass() { printf '   PASS: %s\n' "$*"; }

case "$OS" in
    debian|ubuntu|rocky|opensuse|arch|fedora)
        PLATFORM=linux
        WORK_DIR=/opt/rhorizon
        CONFIG_DIR=/etc/rhorizon
        STATE_DIR=/var/lib/rhorizon
        RUNTIME_DIR=/run/rhorizon
        AUDIT_DIR=/var/log/rhorizon
        ;;
    freebsd)
        PLATFORM=freebsd
        WORK_DIR=/usr/local/rhorizon
        CONFIG_DIR=/usr/local/etc/rhorizon
        STATE_DIR=/var/db/rhorizon
        RUNTIME_DIR=/var/run/rhorizon
        AUDIT_DIR=/var/log/rhorizon
        ;;
    netbsd)
        PLATFORM=netbsd
        WORK_DIR=/usr/pkg/rhorizon
        CONFIG_DIR=/usr/pkg/etc/rhorizon
        STATE_DIR=/var/db/rhorizon
        RUNTIME_DIR=/var/run/rhorizon
        AUDIT_DIR=/var/log/rhorizon
        ;;
    openbsd)
        PLATFORM=openbsd
        WORK_DIR=/usr/local/rhorizon
        CONFIG_DIR=/etc/rhorizon
        STATE_DIR=/var/db/rhorizon
        RUNTIME_DIR=/var/run/rhorizon
        AUDIT_DIR=/var/log/rhorizon
        ;;
    *) fail "unsupported VM platform: $OS" ;;
esac

STATUS_URL=https://127.0.0.1:8200/api/v1/vault/status
APP_FILE=$WORK_DIR/api/app/main.py
SECRET_DIR=$CONFIG_DIR/secrets
ENV_FILE=$CONFIG_DIR/rhorizon.env
PYTHON=$WORK_DIR/.venv/bin/python

[ "$MODE" = system ] || {
    printf '   identity assertions skipped for native user mode\n'
    exit 0
}
[ "$(id -u)" -eq 0 ] || fail "assertion helper must run as root"
[ -x "$PYTHON" ] || fail "installed Python not found at $PYTHON"

# Resolve the API process, not nginx and not an rc.d/su supervisor. NetBSD's
# pidfile can name su(1), so the process table is the portable source of truth.
if [ "$PLATFORM" = linux ]; then
    PID=$(systemctl show rhorizon.service -p MainPID --value)
else
    PID=$(ps -ax -o pid= -o user= -o command= | awk \
        -v wd="$WORK_DIR" 'index($0, wd) && /uvicorn/ { print $1; exit }')
fi
case "$PID" in ''|0|*[!0-9]*) fail "could not resolve the running API PID" ;; esac

ACTUAL_USER=$(ps -o user= -p "$PID" | awk '{print $1}')
EXPECTED_USER=rhorizon
[ "$PLATFORM" = openbsd ] && EXPECTED_USER=root
[ "$ACTUAL_USER" = "$EXPECTED_USER" ] \
    || fail "API PID $PID runs as $ACTUAL_USER, expected $EXPECTED_USER"
pass "API PID $PID runs as $EXPECTED_USER"

if [ "$PLATFORM" = linux ]; then
    UNIT_USER=$(systemctl show rhorizon.service -p User --value)
    UNIT_GROUP=$(systemctl show rhorizon.service -p Group --value)
    [ "$UNIT_USER:$UNIT_GROUP" = rhorizon:rhorizon ] \
        || fail "systemd identity is $UNIT_USER:$UNIT_GROUP"

    WORKERS=$(sed -n 's/^RHORIZON_WORKERS=//p' "$ENV_FILE" | tail -1)
    case "$WORKERS" in ''|*[!0-9]*) fail "invalid RHORIZON_WORKERS in $ENV_FILE" ;; esac
    REQUIRED_BYTES=$(( (WORKERS * 160 + 256 + 192) * 1024 * 1024 ))
    set -- $(awk '/Max locked memory/ {print $4, $5}' "/proc/$PID/limits")
    [ "$#" -eq 2 ] || fail "cannot read Max locked memory for PID $PID"
    SOFT=$1
    HARD=$2
    case "$SOFT:$HARD" in *[!0-9:]*|:*) fail "non-numeric memlock limit: $SOFT $HARD" ;; esac
    [ "$SOFT" -ge "$REQUIRED_BYTES" ] && [ "$HARD" -ge "$REQUIRED_BYTES" ] \
        || fail "PID memlock is $SOFT/$HARD bytes, need $REQUIRED_BYTES"
    pass "process memlock is $SOFT/$HARD bytes (need $REQUIRED_BYTES)"
fi

STATUS=$(curl -fsS -m 10 --cacert "$CA_FILE" "$STATUS_URL") \
    || fail "cannot query $STATUS_URL"
PROCESS_PROTECTION=$(printf '%s\n' "$STATUS" | sed -n \
    's/.*"process_memory_protection"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
BUFFER_PROTECTION=$(printf '%s\n' "$STATUS" | sed -n \
    's/.*"memory_protection"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
SWAP_PROTECTION=$(printf '%s\n' "$STATUS" | sed -n \
    's/.*"swap_protection"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ "$PROCESS_PROTECTION" = mlock ] \
    || fail "vault reports process_memory_protection=$PROCESS_PROTECTION"
[ "$BUFFER_PROTECTION" = mlock ] \
    || fail "vault reports memory_protection=$BUFFER_PROTECTION"
pass "vault reports buffer=$BUFFER_PROTECTION process=$PROCESS_PROTECTION swap=$SWAP_PROTECTION"

# Open a path after dropping supplementary groups, gid, and uid. This tests the
# kernel permission decision directly and does not depend on whether the target
# account's login shell is /sbin/nologin on a particular BSD.
assert_read_as() {
    _user=$1
    _path=$2
    "$PYTHON" - "$_user" "$_path" >/dev/null 2>&1 <<'PY'
import os
import pwd
import sys

account = pwd.getpwnam(sys.argv[1])
os.setgroups([])
os.setgid(account.pw_gid)
os.setuid(account.pw_uid)
with open(sys.argv[2], "rb") as handle:
    handle.read(1)
PY
}

assert_denied_as() {
    _user=$1
    _path=$2
    if assert_read_as "$_user" "$_path"; then
        fail "$_user can read protected file $_path"
    fi
}

# OpenBSD intentionally still runs the API as root until its login-class
# memlock budget has been measured. The account boundary is nevertheless
# created and must already be correct for the eventual drop.
assert_read_as rhorizon "$APP_FILE" \
    || fail "rhorizon cannot read installed application code $APP_FILE"
pass "rhorizon can read its application code"

[ -s "$SECRET_DIR/master-password" ] \
    || fail "test master-password was not persisted"
assert_denied_as rhorizon "$SECRET_DIR/master-password"
[ ! -e "$SECRET_DIR/root-token" ] \
    || assert_denied_as rhorizon "$SECRET_DIR/root-token"
pass "rhorizon cannot read recovery material"

assert_denied_as nobody "$SECRET_DIR/master-password"
[ ! -e "$SECRET_DIR/root-token" ] \
    || assert_denied_as nobody "$SECRET_DIR/root-token"
pass "unprivileged agent identity cannot read recovery material"

# Verify ownership numerically so "root" versus "wheel" naming on the BSDs
# does not alter the invariant. Runtime paths belong to the daemon identity;
# configuration stays root-owned and group-readable; recovery stays uid/gid 0.
"$PYTHON" - \
    "$CONFIG_DIR" "$ENV_FILE" "$STATE_DIR" "$RUNTIME_DIR" "$AUDIT_DIR" \
    "$CONFIG_DIR/certs/key.pem" "$SECRET_DIR" "$SECRET_DIR/master-password" <<'PY'
import grp
import os
import pwd
import stat
import sys

config, env_file, state, runtime, audit, tls_key, secrets, password = sys.argv[1:]
service = pwd.getpwnam("rhorizon")
service_group = grp.getgrnam("rhorizon")

expected = (
    (config, 0, service_group.gr_gid, 0o750),
    (env_file, 0, service_group.gr_gid, 0o640),
    (state, service.pw_uid, service_group.gr_gid, 0o700),
    (runtime, service.pw_uid, service_group.gr_gid, 0o700),
    (audit, service.pw_uid, service_group.gr_gid, 0o700),
    (tls_key, service.pw_uid, service_group.gr_gid, 0o400),
    (secrets, 0, 0, 0o700),
    (password, 0, 0, 0o400),
)
for path, uid, gid, mode in expected:
    current = os.stat(path)
    actual = (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode))
    wanted = (uid, gid, mode)
    if actual != wanted:
        raise SystemExit(f"{path}: ownership/mode {actual!r}, expected {wanted!r}")
PY
pass "config, runtime, TLS key, and recovery ownership are separated"

if [ "$PLATFORM" = openbsd ]; then
    printf '   OpenBSD daemon login-class measurement (read-only):\n'
    getcap -f /etc/login.conf daemon 2>/dev/null \
        | tr ':' '\n' | sed 's/^[[:space:]\\]*//' \
        | grep -E '^(memorylocked|datasize|openfiles)=' \
        | sed 's/^/      /' || true
fi
