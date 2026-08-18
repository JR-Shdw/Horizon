# SPDX-License-Identifier: AGPL-3.0-or-later
# rhorizon driver: Linux (apt/pacman/dnf/zypper). Native, no Docker.
# Modes: system (root, systemd system unit) | user (laptop, systemd --user/nohup).
# Linux CPython's ssl links OpenSSL, so no from-source build (unlike OpenBSD).
# Captured hooks (driver_python/build_env/pg_setup) print ONLY their value.

_sudo() { if [ "$(id -u)" = 0 ]; then run "$@"; else run sudo "$@"; fi; }
# Run a command AS the postgres system user. `_sudo -u postgres ...` is wrong:
# _sudo drops the sudo when we are already root, leaving `-u` as the command.
# sudo -u preserves argv and works whether we are root (passwordless self-switch)
# or a sudoer. sudo is already a hard dep of this driver (see _sudo above).
_pg() {
    command -v sudo >/dev/null 2>&1 || die "sudo required to run postgres bootstrap commands"
    run sudo -u postgres "$@"
}

# --- memory-lock (mlockall) enforcement, gated on swap encryption ----------
# mlockall's only security value is keeping cleartext secret pages off disk
# swap. Enforce it (raise the memlock HARD limit) ONLY when plain unencrypted
# disk swap exists; skip when swap is encrypted / zram / absent.

# Print protected, unencrypted, or unknown. This is advisory: an unknown result
# warns but does not make a normal installation fail or add a capability.
_rh_swap_protection() {
    case "${SWAP_PROTECTION:-}" in
        protected|unencrypted|unknown)
            printf '%s\n' "$SWAP_PROTECTION"
            return
            ;;
    esac
    [ -r /proc/swaps ] || { printf '%s\n' unknown; return; }
    _unknown=0
    while read -r _sw _ty _rest; do
        case "$_sw" in Filename|"") continue ;; esac
        case "$_sw" in /dev/zram*) continue ;; esac
        _src="$_sw"
        if [ "$_ty" = file ]; then
            if command -v findmnt >/dev/null 2>&1; then
                _src=$(findmnt -n -o SOURCE --target "$_sw" 2>/dev/null || true)
                _src=$(printf '%s' "$_src" | sed 's/\[.*$//')
            elif command -v df >/dev/null 2>&1; then
                _src=$(df -P "$_sw" 2>/dev/null | awk 'NR == 2 { print $1 }')
            else
                _src=""
            fi
        fi
        if [ -z "$_src" ] || ! command -v lsblk >/dev/null 2>&1; then
            _unknown=1
            continue
        fi
        _types=$(lsblk -nso TYPE "$_src" 2>/dev/null || true)
        if printf '%s\n' "$_types" | grep -qx crypt; then continue; fi
        if [ -n "$_types" ]; then printf '%s\n' unencrypted; return; fi
        _unknown=1
    done < /proc/swaps
    [ "$_unknown" = 1 ] && printf '%s\n' unknown || printf '%s\n' protected
}

_rh_unencrypted_swap() {
    [ "$(_rh_swap_protection)" = unencrypted ]
}

# Enforce user-mode mlock iff unencrypted swap is present. Raising the memlock
# hard limit needs root: with sudo we write the drop-in, without it we can only
# warn. $1 = systemd|nohup (which limit mechanism to write).
_rh_enforce_mlock_if_needed() {
    _swap_state=$(_rh_swap_protection)
    if [ "$_swap_state" = unknown ]; then
        warn "swap encryption could not be verified: memory locking remains best effort"
        return 0
    fi
    [ "$_swap_state" = unencrypted ] || return 0
    if ! { [ "$(id -u)" = 0 ] || command -v sudo >/dev/null 2>&1; }; then
        warn "unencrypted swap present but no admin rights: memory lock (mlock) NOT enforced -- served secrets could be paged to disk. Re-run with sudo, or encrypt swap. Hibernation also writes RAM to disk."
        return 0
    fi
    case "$1" in
        systemd)
            _di="/etc/systemd/system/user@$(id -u).service.d"
            _sudo mkdir -p "$_di"
            _sudo sh -c "printf '[Service]\nLimitMEMLOCK=%s\n' '$(( RH_MEMLOCK_KB * 1024 ))' > '$_di/rhorizon-memlock.conf'"
            _sudo systemctl daemon-reload
            ;;
        nohup)
            _sudo sh -c "printf '%s - memlock %s\n' '$(id -un)' '$RH_MEMLOCK_KB' > /etc/security/limits.d/rhorizon.conf"
            ;;
    esac
    warn "unencrypted swap present: memory lock (mlock) enabled, effective after next login/reboot. Hibernation still writes RAM to disk -- encrypt swap or disable hibernation for full coverage."
}

# The repo's api/rust/Cargo.lock is lockfile v4 -> needs Rust/Cargo >= 1.78.
# rustup-init pinned by version + per-arch sha256 (no unpinned curl|sh); the
# x86_64 hash matches the one pinned in .woodpecker/fuzz.yml. Bump in lockstep.
_RUSTUP_VER=1.29.0
_rustup_sha() {
    case "$1" in
        x86_64-unknown-linux-gnu)  echo 4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10 ;;
        aarch64-unknown-linux-gnu) echo 9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792 ;;
        *) echo "" ;;
    esac
}

# Ensure a Rust >= 1.78 toolchain is on PATH. Rolling distros (Arch) and
# fast-tracking ones (Fedora) ship it; stable distros (Debian/Ubuntu-LTS/
# openSUSE-Leap/older-RHEL) do not and fail deep in maturin with an opaque
# "lock file version 4" error -- so install a current toolchain via pinned
# rustup and prepend ~/.cargo/bin so the venv build picks it up.
_ensure_rust() {
    [ "${DRY_RUN:-0}" = 1 ] && return 0
    _rv=$(rustc --version 2>/dev/null | awk '{print $2}')   # e.g. 1.63.0
    case "$_rv" in
        [0-9]*.[0-9]*) _maj=${_rv%%.*}; _rest=${_rv#*.}; _min=${_rest%%.*} ;;
        *) _maj=0; _min=0 ;;
    esac
    if [ "${_maj:-0}" -ge 2 ] || { [ "${_maj:-0}" -eq 1 ] && [ "${_min:-0}" -ge 78 ]; }; then
        log "rust: distro ${_rv} (>= 1.78) OK"; return 0
    fi
    [ -n "$_rv" ] && log "distro rust ${_rv} < 1.78; installing pinned rustup" \
                  || log "no distro rust; installing pinned rustup"
    _tr=$(uname -m)
    case "$_tr" in
        x86_64|amd64)  _tr=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) _tr=aarch64-unknown-linux-gnu ;;
        *) die "no pinned rustup for arch $(uname -m); install Rust >= 1.78 manually" ;;
    esac
    _sha=$(_rustup_sha "$_tr"); [ -n "$_sha" ] || die "no pinned rustup-init hash for $_tr"
    # The binary MUST be named `rustup-init`: it dispatches on argv[0] basename,
    # so a mktemp name makes it think it is a rustup proxy ("unknown proxy name").
    _rid=$(mktemp -d); _ri="$_rid/rustup-init"
    run curl -fsSL --proto '=https' --tlsv1.2 -o "$_ri" \
        "https://static.rust-lang.org/rustup/archive/$_RUSTUP_VER/$_tr/rustup-init"
    printf '%s  %s\n' "$_sha" "$_ri" | sha256sum -c - >/dev/null \
        || die "rustup-init sha256 mismatch (supply-chain guard) -- refusing to run"
    run chmod +x "$_ri"
    run "$_ri" -y --no-modify-path --default-toolchain stable --profile minimal
    rm -rf "$_rid"
    export PATH="${HOME}/.cargo/bin:$PATH"
    command -v cargo >/dev/null 2>&1 || die "rustup install did not put cargo on PATH"
    log "rust: rustup $(rustc --version 2>/dev/null | awk '{print $2}') on PATH"
}

# _rh_selinux_setup WORKDIR APPDIR PORT
# Load the confined rhorizon_t policy + label the app tree and API port.
# Hard rule: NO-OP unless the host is *actively enforcing*. A permissive or
# disabled host is left completely untouched (no module, no fcontext, no port).
# Idempotent: semodule -i upgrades in place; semanage add-or-modify; restorecon
# is convergent. Safe to re-run.
_rh_selinux_setup() {
    [ "${DRY_RUN:-0}" = 1 ] && { log "[dry-run] selinux policy setup"; return 0; }
    if [ "$(getenforce 2>/dev/null)" != Enforcing ]; then
        log "selinux: host not enforcing -> leaving selinux untouched"; return 0
    fi
    command -v semodule >/dev/null 2>&1 || { warn "selinux enforcing but policycoreutils absent; skipping"; return 0; }
    _swd=$1; _sapp=$2; _sport=${3:-8200}
    _ste="$ROOT_DIR/tools/selinux/rhorizon.te"
    [ -f "$_ste" ] || { warn "selinux: $_ste missing; skipping policy"; return 0; }
    log "selinux: enforcing host -> installing confined rhorizon_t policy"
    # Build tooling (only pulled on enforcing hosts). Idempotent.
    if command -v dnf >/dev/null 2>&1; then
        _sudo dnf install -y selinux-policy-devel checkpolicy policycoreutils-python-utils >&2 2>&1 || true
    elif command -v zypper >/dev/null 2>&1; then
        _sudo zypper -n install selinux-policy-devel checkpolicy python3-policycoreutils >&2 2>&1 || true
    fi
    [ -f /usr/share/selinux/devel/Makefile ] || { warn "selinux: policy-devel missing; skipping build"; return 0; }
    # Build the module package + load it (semodule -i = install-or-upgrade).
    _sbld=$(mktemp -d); cp "$_ste" "$_sbld/rhorizon.te"
    ( cd "$_sbld" && make -f /usr/share/selinux/devel/Makefile rhorizon.pp ) >&2 2>&1 \
        || { warn "selinux: policy build failed; host policy left untouched"; rm -rf "$_sbld"; return 0; }
    _sudo semodule -i "$_sbld/rhorizon.pp" >&2 2>&1 \
        || { warn "selinux: semodule -i failed"; rm -rf "$_sbld"; return 0; }
    rm -rf "$_sbld"
    # API port -> rhorizon_port_t (add-or-modify).
    _sudo semanage port -a -t rhorizon_port_t -p tcp "$_sport" 2>/dev/null \
        || _sudo semanage port -m -t rhorizon_port_t -p tcp "$_sport" 2>/dev/null || true
    # File contexts: DISJOINT specs (a broad WORKDIR(/.*)? catch-all out-orders
    # the audit/run rules under restorecon, so every path gets its own rule).
    _sconf=${RH_NATIVE_CONFIG_DIR:-$_swd}
    _sstate=${RH_NATIVE_STATE_DIR:-$_swd}
    _srun=${RH_NATIVE_RUNTIME_DIR:-$_swd/run}
    _slog=${RH_NATIVE_AUDIT_DIR:-$_swd/audit}
    _fc() { _sudo semanage fcontext -a -t "$1" "$2" 2>/dev/null || _sudo semanage fcontext -m -t "$1" "$2" 2>/dev/null || true; }
    _fc rhorizon_var_lib_t "$_swd(/.*)?"
    _fc rhorizon_exec_t    "$_swd/run-app\.sh"
    _fc rhorizon_conf_t    "$_sconf(/.*)?"
    _fc rhorizon_var_lib_t "$_swd/\.venv(/.*)?"
    _fc rhorizon_var_lib_state_t "$_sstate(/.*)?"
    _fc rhorizon_log_t     "$_slog(/.*)?"
    _fc rhorizon_var_run_t "$_srun(/.*)?"
    [ -n "$_sapp" ] && _fc rhorizon_var_lib_t "$_sapp(/.*)?"
    _sudo restorecon -RF "$_swd" "$_sconf" "$_sstate" "$_srun" "$_slog" >&2 2>&1 || true
    [ -n "$_sapp" ] && { _sudo restorecon -RF "$_sapp" >&2 2>&1 || true; }
    log "selinux: rhorizon_t loaded; app tree + config + tcp/$_sport labelled (enforcing)"
}

# _rh_apparmor_setup WORKDIR -- confine the service under AppArmor (Debian/Ubuntu;
# the SELinux families use _rh_selinux_setup). No-op unless apparmor is the active
# LSM. Idempotent. Returns 0 (and prints "loaded") only when the profile is
# enforced, so the caller can add AppArmorProfile= to the unit iff it applied.
_rh_apparmor_setup() {
    _awd=$1
    [ "${DRY_RUN:-0}" = 1 ] && { log "[dry-run] apparmor setup"; return 1; }
    [ -d /sys/kernel/security/apparmor ] || { log "apparmor: not enabled on host -> leaving unconfined"; return 1; }
    command -v apparmor_parser >/dev/null 2>&1 || { warn "apparmor enabled but apparmor_parser absent; skipping"; return 1; }
    _aprof="$ROOT_DIR/tools/apparmor/rhorizon"
    [ -f "$_aprof" ] || { warn "apparmor: $_aprof missing; skipping"; return 1; }
    _ac=${RH_NATIVE_CONFIG_DIR:-/etc/rhorizon}; _as=${RH_NATIVE_STATE_DIR:-/var/lib/rhorizon}
    _ar=${RH_NATIVE_RUNTIME_DIR:-/run/rhorizon}; _al=${RH_NATIVE_AUDIT_DIR:-/var/log/rhorizon}
    _sudo sh -c "sed -e 's#@RH_WORK@#$_awd#g' -e 's#@RH_CONFIG@#$_ac#g' -e 's#@RH_STATE@#$_as#g' -e 's#@RH_RUNTIME@#$_ar#g' -e 's#@RH_AUDIT@#$_al#g' '$_aprof' > /etc/apparmor.d/rhorizon"
    if _sudo apparmor_parser -r -W /etc/apparmor.d/rhorizon >&2 2>&1; then
        log "apparmor: rhorizon profile loaded (enforce)"; return 0
    fi
    warn "apparmor: parser failed; profile not loaded"; return 1
}

driver_pkg() {
    if command -v apt-get >/dev/null 2>&1; then
        _sudo apt-get update
        _sudo apt-get install -y python3 python3-venv python3-dev build-essential \
            libsodium-dev libldap2-dev libsasl2-dev libssl-dev pkg-config curl git \
            cargo postgresql apparmor-utils nginx
    elif command -v pacman >/dev/null 2>&1; then
        _sudo pacman -S --needed --noconfirm python libsodium libldap cyrus-sasl \
            openssl base-devel pkgconf curl git rust postgresql nginx
    elif command -v dnf >/dev/null 2>&1; then
        # RHEL/Rocky/Alma: libsodium-devel lives in EPEL, and several -devel
        # packages live in CRB/PowerTools. Enable both (no-ops on Fedora, which
        # has everything in base -- the `|| true` swallows epel-release absence).
        if [ -f /etc/redhat-release ] && ! grep -qi fedora /etc/redhat-release 2>/dev/null; then
            _sudo dnf install -y epel-release 2>/dev/null \
              || _sudo dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel).noarch.rpm" 2>/dev/null || true
            _sudo dnf config-manager --set-enabled crb 2>/dev/null \
              || _sudo dnf config-manager --set-enabled powertools 2>/dev/null || true
        fi
        _sudo dnf install -y python3 python3-devel gcc libsodium-devel openldap-devel \
            cyrus-sasl-devel openssl-devel pkgconf curl git cargo postgresql-server nginx
    elif command -v zypper >/dev/null 2>&1; then
        _sudo zypper -n install python3 python3-devel libsodium-devel openldap2-devel \
            cyrus-sasl-devel libopenssl-devel gcc pkg-config curl git cargo postgresql-server nginx
    else
        die "unsupported Linux: need apt/pacman/dnf/zypper"
    fi
    _ensure_rust
}

driver_python() {
    [ "${DRY_RUN:-0}" = 1 ] && { command -v python3 2>/dev/null || echo /usr/bin/python3; return 0; }
    command -v python3 >/dev/null 2>&1 || die "python3 missing after driver_pkg"; command -v python3
}

driver_build_env() { :; }   # Linux openssl is standard; nothing extra

# stdout: DATABASE_URL. Uses the local system PostgreSQL cluster.
driver_pg_setup() {
    if [ "${DRY_RUN:-0}" = 1 ]; then echo "postgresql+asyncpg://rhorizon:DRYRUN@127.0.0.1:5432/rhorizon"; return 0; fi
    _pw=$(gen_secret 18)
    # Initialise the cluster when the distro ships it empty. Debian/Ubuntu
    # auto-create the 'main' cluster on package install (nothing to do here);
    # Fedora/RHEL/SUSE provide postgresql-setup; Arch ships an empty
    # /var/lib/postgres/data with NO helper -> initdb it by hand as `postgres`,
    # else systemctl start postgresql fails with an empty data dir.
    if command -v postgresql-setup >/dev/null 2>&1; then
        [ -d /var/lib/pgsql/data/base ] || _sudo postgresql-setup --initdb >&2 2>&1 || true
    elif [ -d /var/lib/postgres ] && [ ! -d /var/lib/postgres/data/base ]; then
        _sudo install -d -o postgres -g postgres -m 0700 /var/lib/postgres/data >&2 2>&1 || true
        _pg initdb --locale=C --encoding=UTF8 -D /var/lib/postgres/data >&2 2>&1 || true
    fi
    _sudo systemctl enable --now postgresql >&2 2>&1 || _sudo service postgresql start >&2 2>&1 || true
    sleep 2
    if _pg psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='rhorizon'" 2>/dev/null | grep -q 1; then
        # Idempotent: converge the existing role's password to the one returned
        # below. A skip would strand the role on its old password -> auth fails
        # on every re-run (the connection URL always carries the fresh secret).
        _pg psql -c "ALTER USER rhorizon WITH PASSWORD '$_pw'" >&2
    else
        _pg psql -c "CREATE USER rhorizon WITH PASSWORD '$_pw'" >&2
    fi
    _pg psql -tAc "SELECT 1 FROM pg_database WHERE datname='rhorizon'" 2>/dev/null | grep -q 1 \
        || _pg psql -c "CREATE DATABASE rhorizon OWNER rhorizon" >&2
    # RHEL/Fedora pg_hba defaults TCP loopback to `ident` -> asyncpg fails with
    # "Ident authentication failed". Ensure a scram-sha-256 rule for the
    # rhorizon loopback connection. Idempotent (grep guard); harmless elsewhere.
    _hba=$(_pg psql -tAc "SHOW hba_file" 2>/dev/null | tr -d '[:space:]')
    if [ -n "$_hba" ] && ! _sudo grep -qE '^host[[:space:]]+rhorizon[[:space:]]+rhorizon[[:space:]]+127\.0\.0\.1/32[[:space:]]+scram-sha-256' "$_hba" 2>/dev/null; then
        # Insert ABOVE the distro default loopback rules: pg_hba is first-match,
        # and RHEL/Fedora ship `host all all 127.0.0.1/32 ident` which otherwise
        # shadows this rule -> asyncpg "Ident authentication failed for rhorizon".
        _sudo sed -i '0,/^[[:space:]]*\(host\|local\)[[:space:]]/s//host rhorizon rhorizon 127.0.0.1\/32 scram-sha-256\n&/' "$_hba"
        _sudo systemctl reload postgresql >&2 2>&1 || _pg pg_ctl reload >&2 2>&1 || true
    fi
    echo "postgresql+asyncpg://rhorizon:$_pw@127.0.0.1:5432/rhorizon"
}

# driver_service_install WORKDIR VENV ENVFILE RUNCMD
driver_service_install() {
    _wd=$1; _env=$3; _run=$4
    _unit="[Unit]
Description=rhorizon vault
After=network.target postgresql.service

[Service]
EnvironmentFile=$_env
ExecStart=$_run
Restart=on-failure
# rhorizon mlockall()s the whole process (incl. the 256MB Argon2 unseal buffer)
# out of swap. Bound memlock to the computed budget (workers*160+256+192 MB) in
# bytes -- NOT infinity. Scoped to this unit, not system-wide.
LimitMEMLOCK=$(( RH_MEMLOCK_KB * 1024 ))

[Install]
WantedBy=default.target"
    if [ "${RH_MODE:-system}" = user ]; then
        _dir="$HOME/.config/systemd/user"
        if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
            # A user manager cannot raise its own hard memlock limit. Declaring
            # the system-mode budget here can make ExecStart fail before the
            # application's best-effort policy runs.
            _user_unit=$(printf '%s\n' "$_unit" | sed '/^LimitMEMLOCK=/d')
            run mkdir -p "$_dir"
            run sh -c "printf '%s\n' \"\$1\" > '$_dir/rhorizon.service'" _ "$_user_unit"
            run systemctl --user daemon-reload
            run systemctl --user enable rhorizon.service
            RH_SVC="user-systemd"
            _rh_enforce_mlock_if_needed systemd
        else
            # no user systemd (e.g. WSL2 without systemd) -> nohup wrapper
            run sh -c "cat > '$_wd/run-app.sh' <<EOF
#!/bin/sh
set -a; . '$_env'; set +a
exec $_run
EOF"
            run chmod +x "$_wd/run-app.sh"
            RH_SVC="nohup:$_wd/run-app.sh"
            _rh_enforce_mlock_if_needed nohup
        fi
    else
        # System mode: a wrapper script is the SELinux transition entrypoint
        # (labelled rhorizon_exec_t so systemd's init_daemon_domain transition
        # lands the service in rhorizon_t). It also pins the memlock ceiling and
        # disables .pyc writes into the read-only, confined app tree.
        _wrap="$_wd/run-app.sh"
        run sh -c "cat > '$_wrap' <<EOF
#!/bin/sh
ulimit -l $RH_MEMLOCK_KB 2>/dev/null || true
export PYTHONDONTWRITEBYTECODE=1
set -a; . '$_env'; set +a
exec $_run
EOF"
        run chmod 0755 "$_wrap"
        _unit=$(printf '%s\n' "$_unit" | sed "s#^ExecStart=.*#ExecStart=$_wrap#")
        _swap_state=$(_rh_swap_protection)
        case "$_swap_state" in
            unencrypted)
                _unit=$(printf '%s\n' "$_unit" | sed "/^LimitMEMLOCK=/a AmbientCapabilities=CAP_IPC_LOCK")
                warn "unencrypted swap present: system service will request memory locking"
                ;;
            unknown)
                _unit=$(printf '%s\n' "$_unit" | sed '/^LimitMEMLOCK=/d')
                warn "swap encryption could not be verified: memory locking remains best effort"
                ;;
            protected)
                _unit=$(printf '%s\n' "$_unit" | sed '/^LimitMEMLOCK=/d')
                ;;
        esac
        _unit=$(printf '%s\n' "$_unit" | sed "/^Restart=/a RuntimeDirectory=rhorizon")
        # AppArmor (Debian/Ubuntu): load the profile first, then bind the unit to
        # it only on success -- a stale AppArmorProfile= makes systemd refuse start.
        if _rh_apparmor_setup "$_wd"; then
            _unit=$(printf '%s\n' "$_unit" | sed "/^Restart=/a AppArmorProfile=rhorizon")
        fi
        run sh -c "printf '%s\n' \"\$1\" > /etc/systemd/system/rhorizon.service" _ "$_unit"
        _sudo systemctl daemon-reload
        _sudo systemctl enable rhorizon.service
        # Confine under SELinux (no-op unless the host is actively enforcing).
        _rh_appdir=$(printf '%s' "$_run" | sed -n 's/.*--app-dir \([^ ]*\).*/\1/p')
        _rh_port=$(printf '%s' "$_run" | sed -n 's/.*--port \([0-9]*\).*/\1/p')
        _rh_selinux_setup "$_wd" "$_rh_appdir" "${_rh_port:-8200}"
        RH_SVC="system-systemd"
    fi
    export RH_SVC
}

# driver_service_install_nginx BIN PREFIX CONF -- second boot service, the TLS
# + HTTP/2 front. Its presence is what makes install-native.sh choose nginx
# termination over uvicorn's; a driver without it keeps the uvicorn-TLS path.
#
# Type=forking with an explicit PIDFile: nginx daemonises by default, and
# systemd needs the master's pid, not the launching shell's. ExecStartPre
# re-tests the config so a bad render fails the unit instead of leaving the
# vault unreachable behind a dead proxy.
driver_service_install_nginx() {
    _nbin=$1; _npfx=$2; _nconf=$3
    _nunit="[Unit]
Description=rhorizon frontend (nginx, TLS + HTTP/2)
After=network.target rhorizon.service
Wants=rhorizon.service

[Service]
Type=forking
PIDFile=$_npfx/nginx.pid
ExecStartPre=$_nbin -t -p $_npfx -c $_nconf
ExecStart=$_nbin -p $_npfx -c $_nconf
ExecReload=$_nbin -p $_npfx -c $_nconf -s reload
ExecStop=$_nbin -p $_npfx -c $_nconf -s quit
Restart=on-failure

[Install]
WantedBy=default.target"
    if [ "${RH_MODE:-system}" = user ]; then
        if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
            _ndir="$HOME/.config/systemd/user"
            run mkdir -p "$_ndir"
            run sh -c "printf '%s\n' \"\$1\" > '$_ndir/rhorizon-nginx.service'" _ "$_nunit"
            run systemctl --user daemon-reload
            run systemctl --user enable rhorizon-nginx.service
            RH_NGINX_SVC="user-systemd"
        else
            # No user systemd (WSL2): nginx daemonises itself, so no nohup.
            RH_NGINX_SVC="direct"
        fi
    else
        run sh -c "printf '%s\n' \"\$1\" > /etc/systemd/system/rhorizon-nginx.service" _ "$_nunit"
        _sudo systemctl daemon-reload
        _sudo systemctl enable rhorizon-nginx.service
        # SELinux labels the port nginx binds, not just uvicorn's. Without this
        # nginx cannot bind a non-standard port on an enforcing host.
        # RH_NGINX_PORT carries addr:port for the listen directive; semanage
        # wants the bare port number.
        _nport=${RH_NGINX_PORT##*:}
        if command -v semanage >/dev/null 2>&1; then
            _sudo semanage port -a -t http_port_t -p tcp "${_nport:-8200}" 2>/dev/null \
              || _sudo semanage port -m -t http_port_t -p tcp "${_nport:-8200}" 2>/dev/null || true
        fi
        RH_NGINX_SVC="system-systemd"
    fi
    export RH_NGINX_SVC
}

driver_start_nginx() {
    case "${RH_NGINX_SVC:-}" in
        user-systemd)   run systemctl --user start rhorizon-nginx.service ;;
        system-systemd) _sudo systemctl start rhorizon-nginx.service ;;
        direct)         run "$RH_NGINX_BIN" -p "$RH_NGINX_PREFIX" -c "$RH_NGINX_CONF" ;;
        *)              warn "nginx service not configured; start it manually" ;;
    esac
}

driver_start() {
    case "${RH_SVC:-}" in
        user-systemd)   run systemctl --user start rhorizon.service ;;
        system-systemd) _sudo systemctl start rhorizon.service ;;
        nohup:*)        run sh -c "nohup '${RH_SVC#nohup:}' >/dev/null 2>&1 &" ;;
        *)              warn "no service configured; start manually" ;;
    esac
}

# driver_uninstall [PORT] -- reverse driver_service_install + _rh_selinux_setup.
# Idempotent: guards on presence, ignores absence. Uses the RH_NATIVE_* dir env
# the uninstaller exports to strip the matching SELinux fcontext specs.
driver_uninstall() {
    _uport="${1:-8200}"
    if [ "${RH_MODE:-system}" = user ]; then
        if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
            # nginx front first: leaving an enabled unit behind would keep
            # restarting a proxy whose backend is gone.
            run systemctl --user disable --now rhorizon-nginx.service >/dev/null 2>&1 || true
            run rm -f "$HOME/.config/systemd/user/rhorizon-nginx.service"
            run systemctl --user disable --now rhorizon.service >/dev/null 2>&1 || true
            run rm -f "$HOME/.config/systemd/user/rhorizon.service"
            run systemctl --user daemon-reload >/dev/null 2>&1 || true
            # remove the one-time root memlock drop-in (guarded: no sudo prompt
            # when there is nothing to clean up)
            _di="/etc/systemd/system/user@$(id -u).service.d"
            if [ -f "$_di/rhorizon-memlock.conf" ]; then
                _sudo rm -f "$_di/rhorizon-memlock.conf"
                _sudo rmdir "$_di" 2>/dev/null || true
                _sudo systemctl daemon-reload >/dev/null 2>&1 || true
            fi
        fi
        [ -f /etc/security/limits.d/rhorizon.conf ] && _sudo rm -f /etc/security/limits.d/rhorizon.conf
        return 0
    fi
    _sudo systemctl disable --now rhorizon-nginx.service >/dev/null 2>&1 || true
    _sudo rm -f /etc/systemd/system/rhorizon-nginx.service
    _sudo systemctl disable --now rhorizon.service >/dev/null 2>&1 || true
    _sudo rm -f /etc/systemd/system/rhorizon.service
    _sudo systemctl daemon-reload >/dev/null 2>&1 || true
    # AppArmor teardown (no-op unless a profile was loaded).
    if [ -f /etc/apparmor.d/rhorizon ]; then
        command -v apparmor_parser >/dev/null 2>&1 && _sudo apparmor_parser -R /etc/apparmor.d/rhorizon >/dev/null 2>&1 || true
        _sudo rm -f /etc/apparmor.d/rhorizon
    fi
    # SELinux teardown (no-op unless the module was ever loaded).
    if command -v semodule >/dev/null 2>&1 && _sudo semodule -l 2>/dev/null | grep -q '^rhorizon'; then
        _sudo semodule -r rhorizon >/dev/null 2>&1 || true
    fi
    command -v semanage >/dev/null 2>&1 || return 0
    _sudo semanage port -d -t rhorizon_port_t -p tcp "$_uport" 2>/dev/null || true
    # The nginx front needed its listen port labelled http_port_t; that is a
    # system-wide change and must not survive an uninstall. Deleting a port the
    # base policy defines (80, 443, ...) fails rather than damaging the policy,
    # and the || true swallows it -- so this only ever removes a label we added.
    _sudo semanage port -d -t http_port_t -p tcp "$_uport" 2>/dev/null || true
    _uwd=${RH_NATIVE_WORK_DIR:-/opt/rhorizon}
    for _spec in "$_uwd(/.*)?" "$_uwd/run-app\.sh" "$_uwd/\.venv(/.*)?" "$_uwd/api(/.*)?" \
                 "${RH_NATIVE_CONFIG_DIR:-/etc/rhorizon}(/.*)?" \
                 "${RH_NATIVE_STATE_DIR:-/var/lib/rhorizon}(/.*)?" \
                 "${RH_NATIVE_AUDIT_DIR:-/var/log/rhorizon}(/.*)?" \
                 "${RH_NATIVE_RUNTIME_DIR:-/run/rhorizon}(/.*)?"; do
        _sudo semanage fcontext -d "$_spec" 2>/dev/null || true
    done
}

# driver_db_drop -- DESTRUCTIVE: drop the rhorizon role + database. Idempotent.
driver_db_drop() {
    _pg psql -c "DROP DATABASE IF EXISTS rhorizon" >&2 2>&1 || true
    _pg psql -c "DROP ROLE IF EXISTS rhorizon" >&2 2>&1 || true
}
