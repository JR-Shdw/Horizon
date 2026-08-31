#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Destructive only inside the disposable Linux VM used by tools/test-vm.sh.
# Proves required, best-effort, and protected-swap behavior with an actually
# insufficient process memlock budget, then restores the installed service.

set -eu

CA_FILE=${1:?usage: assert-native-install-linux-negative.sh CA_FILE}
ENV_FILE=/etc/rhorizon/rhorizon.env
DROPIN_DIR=/etc/systemd/system/rhorizon.service.d
DROPIN=$DROPIN_DIR/90-rhorizon-vm-negative.conf
ENV_BACKUP=/tmp/rhorizon-vm-negative.env
STATUS_URL=https://127.0.0.1:8200/api/v1/vault/status

fail() { printf 'FAIL: native negative assertion: %s\n' "$*" >&2; exit 1; }
pass() { printf '   PASS: %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || fail "negative assertion helper must run as root"
[ -f "$ENV_FILE" ] || fail "$ENV_FILE is missing"
[ ! -e "$DROPIN" ] || fail "$DROPIN already exists; refusing to overwrite it"

cp -p "$ENV_FILE" "$ENV_BACKUP"

restore_service() {
    systemctl stop rhorizon.service >/dev/null 2>&1 || true
    if [ -f "$ENV_BACKUP" ]; then
        cp -p "$ENV_BACKUP" "$ENV_FILE"
    fi
    rm -f "$DROPIN"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed rhorizon.service >/dev/null 2>&1 || true
    systemctl start rhorizon.service >/dev/null 2>&1 || true
}
trap restore_service EXIT INT TERM

set_env() {
    _key=$1
    _value=$2
    if grep -q "^${_key}=" "$ENV_FILE"; then
        sed -i "s|^${_key}=.*|${_key}=${_value}|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$_key" "$_value" >> "$ENV_FILE"
    fi
}

status_json() {
    # nginx remains up while the API is deliberately stopped. Without --fail,
    # its 502 body looks like a successful curl and turns a fail-closed service
    # into a false test failure.
    curl -fsS -m 3 --cacert "$CA_FILE" "$STATUS_URL" 2>/dev/null
}

wait_for_status() {
    _tries=0
    while [ "$_tries" -lt 30 ]; do
        if status_json; then return 0; fi
        _tries=$((_tries + 1))
        sleep 1
    done
    return 1
}

status_field() {
    _field=$1
    sed -n "s/.*\"${_field}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

start_clean() {
    systemctl stop rhorizon.service >/dev/null 2>&1 || true
    systemctl reset-failed rhorizon.service >/dev/null 2>&1 || true
    systemctl start rhorizon.service >/dev/null 2>&1 || true
}

mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<'EOF'
[Service]
LimitMEMLOCK=8388608
# The installed unit grants CAP_IPC_LOCK, which bypasses RLIMIT_MEMLOCK.
# Clear both settings or this test would not create the intended failure.
AmbientCapabilities=
CapabilityBoundingSet=
EOF
systemctl daemon-reload

# Unknown swap makes required mode fail closed when mlockall cannot lock the
# process. The endpoint must stay unavailable and the explicit reason must be
# present in the journal; merely observing a failed systemctl command is weak.
set_env RH_MEMORY_LOCK_MODE required
set_env RH_SWAP_PROTECTION unknown
start_clean
sleep 6
if status_json >/dev/null 2>&1; then
    fail "required mode served traffic with an 8 MiB limit and no IPC_LOCK"
fi
journalctl -u rhorizon.service -n 200 --no-pager 2>/dev/null \
    | grep -q 'RH_MEMORY_LOCK_MODE=required but mlockall failed' \
    || fail "required-mode refusal was not visible in the service journal"
pass "required mode refuses to serve when mlockall fails"

# The availability-oriented mode may start, but its degradation must be
# observable through the public status model.
set_env RH_MEMORY_LOCK_MODE best-effort
set_env RH_SWAP_PROTECTION unknown
start_clean
BEST_STATUS=$(wait_for_status) || fail "best-effort mode did not start"
BEST_PROCESS=$(printf '%s\n' "$BEST_STATUS" | status_field process_memory_protection)
[ "$BEST_PROCESS" = swappable ] \
    || fail "best-effort reports process_memory_protection=$BEST_PROCESS"
pass "best-effort starts and reports process_memory_protection=swappable"

# Required mode deliberately permits this condition when persistent swap is
# known to be absent, encrypted, or RAM-only. Prove that documented carve-out.
set_env RH_MEMORY_LOCK_MODE required
set_env RH_SWAP_PROTECTION protected
start_clean
PROTECTED_STATUS=$(wait_for_status) || fail "protected-swap carve-out did not start"
PROTECTED_PROCESS=$(printf '%s\n' "$PROTECTED_STATUS" | status_field process_memory_protection)
PROTECTED_SWAP=$(printf '%s\n' "$PROTECTED_STATUS" | status_field swap_protection)
[ "$PROTECTED_PROCESS:$PROTECTED_SWAP" = swappable:protected ] \
    || fail "protected carve-out reports $PROTECTED_PROCESS/$PROTECTED_SWAP"
pass "required mode starts with failed mlock only when swap is protected"

# The EXIT trap restores the production unit, environment, capability, and
# computed limit. Do it now as well so the harness can verify restoration.
restore_service
trap - EXIT INT TERM
RESTORED_STATUS=$(wait_for_status) || fail "restored service did not start"
RESTORED_PROCESS=$(printf '%s\n' "$RESTORED_STATUS" | status_field process_memory_protection)
[ "$RESTORED_PROCESS" = mlock ] \
    || fail "restored service reports process_memory_protection=$RESTORED_PROCESS"
rm -f "$ENV_BACKUP"
pass "original service configuration restored with process mlock"
