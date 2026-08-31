# SPDX-License-Identifier: AGPL-3.0-or-later
# rhorizon installer -- shared helpers (POSIX sh, sourced by install-native.sh).
# No side effects on source; all actions go through run() so --dry-run is honest.

# --- output --------------------------------------------------------------
log()  { printf '>> %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }
die()  { printf '!! %s\n' "$*" >&2; exit 1; }

# run CMD... : execute, or just print it under DRY_RUN=1
run() {
    if [ "${DRY_RUN:-0}" = 1 ]; then printf '   [dry-run] %s\n' "$*"; return 0; fi
    "$@"
}

# --- service account -----------------------------------------------------
# The vault must not run as root once it is installed. Installation is
# privileged by nature; the daemon afterwards is not, and a compromise of a
# root-run vault is a compromise of the host.
#
# Two properties this must NOT break:
#   * the agent boundary. Recovery material stays root-owned, so an agent under
#     an ordinary login cannot read it. Handing the whole tree to the service
#     account would give the daemon its own recovery keys and widen, not narrow.
#   * an existing install. Adding User= to a unit that has been running as root
#     leaves files the service can no longer read. Migration is therefore
#     explicit and SELECTIVE -- never a recursive chown.

RH_SERVICE_USER="${RH_SERVICE_USER:-rhorizon}"
RH_SERVICE_GROUP="${RH_SERVICE_GROUP:-rhorizon}"

# rh_account_exists NAME : is there such a user?
rh_account_exists() {
    if command -v getent >/dev/null 2>&1; then
        getent passwd "$1" >/dev/null 2>&1
    else
        id "$1" >/dev/null 2>&1   # BSDs without getent
    fi
}

rh_group_exists() {
    if command -v getent >/dev/null 2>&1; then
        getent group "$1" >/dev/null 2>&1
    else
        # OpenBSD/NetBSD: no getent(1); the group file is the source of truth.
        grep -q "^$1:" /etc/group 2>/dev/null
    fi
}

# rh_create_service_account : create RH_SERVICE_GROUP + RH_SERVICE_USER as a
# system account with no login shell and no home. Sets RH_ACCOUNT_READY=1 on
# success, 0 otherwise -- the caller decides what to do about it, because
# silently continuing as root while reporting success is the failure mode this
# whole change exists to remove.
rh_create_service_account() {
    RH_ACCOUNT_READY=0
    _nologin=/usr/sbin/nologin
    [ -x "$_nologin" ] || _nologin=/sbin/nologin
    [ -x "$_nologin" ] || _nologin=/bin/false

    if ! rh_group_exists "$RH_SERVICE_GROUP"; then
        case "$RH_OS" in
            linux)   run groupadd --system "$RH_SERVICE_GROUP" || return 0 ;;
            freebsd) run pw groupadd "$RH_SERVICE_GROUP" || return 0 ;;
            openbsd|netbsd) run groupadd "$RH_SERVICE_GROUP" || return 0 ;;
            darwin)  rh_darwin_create_group || return 0 ;;
            *) warn "no account recipe for $RH_OS"; return 0 ;;
        esac
    fi

    if ! rh_account_exists "$RH_SERVICE_USER"; then
        case "$RH_OS" in
            linux)
                run useradd --system --gid "$RH_SERVICE_GROUP" \
                    --home-dir /nonexistent --no-create-home \
                    --shell "$_nologin" "$RH_SERVICE_USER" || return 0 ;;
            freebsd)
                run pw useradd "$RH_SERVICE_USER" -g "$RH_SERVICE_GROUP" \
                    -d /nonexistent -s "$_nologin" -c "Resurgamus Horizon" || return 0 ;;
            openbsd)
                run useradd -g "$RH_SERVICE_GROUP" -d /nonexistent \
                    -s "$_nologin" -c "Resurgamus Horizon" "$RH_SERVICE_USER" || return 0 ;;
            netbsd)
                run useradd -g "$RH_SERVICE_GROUP" -d /nonexistent \
                    -s "$_nologin" -c "Resurgamus Horizon" "$RH_SERVICE_USER" || return 0 ;;
            darwin)
                rh_darwin_create_user "$_nologin" || return 0 ;;
        esac
    fi

    if rh_account_exists "$RH_SERVICE_USER"; then
        RH_ACCOUNT_READY=1
    elif [ "${DRY_RUN:-0}" = 1 ]; then
        RH_ACCOUNT_READY=1   # nothing was actually created; report the plan
    fi
    return 0
}

# macOS has no useradd; dscl needs an explicitly chosen id in the service range.
rh_darwin_create_group() {
    _gid=$(rh_darwin_free_id _dscl_group)
    [ -n "$_gid" ] || { warn "no free system gid for $RH_SERVICE_GROUP"; return 1; }
    run dscl . -create "/Groups/$RH_SERVICE_GROUP" || return 1
    run dscl . -create "/Groups/$RH_SERVICE_GROUP" PrimaryGroupID "$_gid" || return 1
    return 0
}

rh_darwin_create_user() {
    _shell=$1
    _uid=$(rh_darwin_free_id _dscl_user)
    _gid=$(dscl . -read "/Groups/$RH_SERVICE_GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}')
    [ -n "$_uid" ] && [ -n "$_gid" ] || { warn "no free system uid/gid on darwin"; return 1; }
    run dscl . -create "/Users/$RH_SERVICE_USER" || return 1
    run dscl . -create "/Users/$RH_SERVICE_USER" UserShell "$_shell"
    run dscl . -create "/Users/$RH_SERVICE_USER" RealName "Resurgamus Horizon"
    run dscl . -create "/Users/$RH_SERVICE_USER" UniqueID "$_uid"
    run dscl . -create "/Users/$RH_SERVICE_USER" PrimaryGroupID "$_gid"
    run dscl . -create "/Users/$RH_SERVICE_USER" NFSHomeDirectory /var/empty
    run dscl . -create "/Users/$RH_SERVICE_USER" IsHidden 1
    return 0
}

# Lowest unused id in the 200-400 system range (Apple reserves <500 for system
# accounts and ships up to ~99 itself).
rh_darwin_free_id() {
    _kind=$1
    case "$_kind" in
        _dscl_group) _list=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}') ;;
        *)           _list=$(dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}') ;;
    esac
    _i=200
    while [ "$_i" -lt 400 ]; do
        printf '%s\n' "$_list" | grep -qx "$_i" || { printf '%s' "$_i"; return 0; }
        _i=$((_i + 1))
    done
    return 1
}

# rh_ensure_service_account : rh_create_service_account, at most once.
# Called from two places (before the code is grouped to it, and before the
# runtime paths are handed over) so neither has to assume the other ran.
RH_ACCOUNT_READY=0
rh_ensure_service_account() {
    [ "${_rh_account_attempted:-0}" = 1 ] && return 0
    _rh_account_attempted=1
    rh_create_service_account
}

# rh_require_service_account : make the fallback decision at the first point
# where a system install needs the account. Waiting until service generation
# would let most of the install continue under the old root assumptions before
# finally failing, which hides account-creation errors in a long build log.
rh_require_service_account() {
    rh_ensure_service_account
    [ "${RH_ACCOUNT_READY:-0}" = 1 ] && return 0

    warn "Unable to configure the dedicated $RH_SERVICE_USER service account."
    warn "  Horizon would keep running as root. That still keeps its"
    warn "  credentials away from an unprivileged agent, but a compromise of"
    warn "  the vault would then be a compromise of this host."
    if [ "${RH_ACCOUNT_FALLBACK_ROOT:-}" = 1 ]; then
        warn "  RH_ACCOUNT_FALLBACK_ROOT=1 -- continuing as root."
        return 0
    fi
    die "Refusing to continue silently. Create the account by hand, or re-run with RH_ACCOUNT_FALLBACK_ROOT=1 to accept running as root."
}

# rh_own_runtime_path PATH [MODE] : hand ONE path to the service account.
# Deliberately not recursive and deliberately per-path: the caller names each
# thing the daemon needs at runtime, so nothing it does not need can be swept
# in. Recovery material is never passed here.
rh_own_runtime_path() {
    [ "${RH_ACCOUNT_READY:-0}" = 1 ] || return 0
    if [ "${DRY_RUN:-0}" = 1 ] && [ ! -e "$1" ]; then
        # The path is created by an earlier run() that a dry run skipped. Report
        # the intent rather than silently omitting it: a dry run of a privileged
        # change is the operator's review, so it must not under-report.
        printf '   [dry-run] chown %s:%s %s%s\n' \
            "$RH_SERVICE_USER" "$RH_SERVICE_GROUP" "$1" \
            "${2:+ && chmod $2}"
        return 0
    fi
    [ -e "$1" ] || return 0
    run chown "$RH_SERVICE_USER:$RH_SERVICE_GROUP" "$1"
    [ -n "${2:-}" ] && run chmod "$2" "$1"
    return 0
}

# rh_own_runtime_tree DIR MODE FILEMODE : the directory itself and its direct
# file children, one level. Used for state/audit/run directories, whose contents
# are all runtime artefacts. Still not `chown -R`: a nested secrets/ directory
# must be passed explicitly or not at all.
rh_own_runtime_tree() {
    [ "${RH_ACCOUNT_READY:-0}" = 1 ] || return 0
    if [ "${DRY_RUN:-0}" = 1 ] && [ ! -d "$1" ]; then
        rh_own_runtime_path "$1" "$2"
        return 0
    fi
    [ -d "$1" ] || return 0
    rh_own_runtime_path "$1" "$2"
    for _f in "$1"/*; do
        [ -f "$_f" ] || continue
        rh_own_runtime_path "$_f" "${3:-0600}"
    done
    return 0
}

# --- host detection ------------------------------------------------------
# Sets RH_OS (linux|freebsd|netbsd|openbsd|darwin), RH_DISTRO (linux only),
# RH_ARCH (x86_64|arm64|...). RH_DISTRO comes from /etc/os-release ID.
detect_host() {
    RH_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    RH_ARCH=$(uname -m)
    case "$RH_ARCH" in aarch64) RH_ARCH=arm64 ;; amd64) RH_ARCH=x86_64 ;; esac
    RH_DISTRO=""
    if [ "$RH_OS" = linux ] && [ -r /etc/os-release ]; then
        RH_DISTRO=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")
    fi
    export RH_OS RH_ARCH RH_DISTRO
}

# --- secrets -------------------------------------------------------------
gen_secret() { # gen_secret [nbytes] -> hex
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex "${1:-24}"
    else head -c "${1:-24}" /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# --- TLS ------------------------------------------------------------------
# ensure_tls_cert CERT_DIR BIND : leave CERT_DIR holding a cert.pem/key.pem pair
# uvicorn can serve. Generates a self-signed one on first install and keeps an
# existing pair untouched -- a re-run must not invalidate the CA file already
# handed to clients.
#
# A temporary openssl config, not -addext: that flag needs OpenSSL >= 1.1.1 or
# LibreSSL >= 3.4, and the support matrix still includes NetBSD releases on
# 1.0.2. A [req] section with x509_extensions is understood by every version.
ensure_tls_cert() {
    _cdir=$1; _bind=$2
    if [ -f "$_cdir/cert.pem" ] && [ -f "$_cdir/key.pem" ]; then
        log "TLS: reusing the certificate already in $_cdir"
        return 0
    fi
    command -v openssl >/dev/null 2>&1 \
        || die "openssl is required to generate the TLS certificate"
    # SANs: loopback always, plus the bind address when it is one a client can
    # actually dial, so the same cert serves a LAN/VPN install unregenerated.
    # A wildcard bind names no host, so it contributes no SAN.
    _san="DNS:localhost,IP:127.0.0.1,IP:::1"
    case "$_bind" in
        ''|127.0.0.1|localhost|::1|0.0.0.0|'::') ;;
        *[!0-9.]*) case "$_bind" in
                       *:*) _san="$_san,IP:$_bind" ;;    # IPv6 literal
                       *)   _san="$_san,DNS:$_bind" ;;   # hostname
                   esac ;;
        *) _san="$_san,IP:$_bind" ;;                     # IPv4 literal
    esac
    run mkdir -p "$_cdir"
    run chmod 700 "$_cdir"
    if [ "${DRY_RUN:-0}" = 1 ]; then
        printf '   [dry-run] openssl req -x509 -> %s/{cert,key}.pem (%s)\n' "$_cdir" "$_san"
        return 0
    fi
    _cnf=$(TMPDIR=/tmp mktemp)
    cat > "$_cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions    = ext
prompt             = no
[dn]
CN = rhorizon
[ext]
subjectAltName   = $_san
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
    if ! openssl req -x509 -newkey rsa:2048 -nodes -config "$_cnf" \
            -keyout "$_cdir/key.pem" -out "$_cdir/cert.pem" \
            -days 825 >/dev/null 2>&1; then
        rm -f "$_cnf"
        die "openssl failed to generate the TLS certificate"
    fi
    rm -f "$_cnf"
    chmod 600 "$_cdir/key.pem"
    chmod 644 "$_cdir/cert.pem"
    log "TLS: generated a self-signed certificate ($_san)"
}

# --- nginx (native path) --------------------------------------------------
# The native install terminates TLS at nginx, not uvicorn, for ONE reason:
# HTTP/2. uvicorn has no HTTP/2 implementation and does not even advertise ALPN
# (measured), so every client falls back to HTTP/1.1.
#
# That is the whole justification. uvicorn already serves HTTPS with
# post-quantum key exchange, so an nginx that cannot do h2 adds a hop and buys
# nothing -- it is declined, not accepted as a lesser win. The SPA, the security
# headers and the CSP come along with it and are welcome, but they do not on
# their own justify putting a second daemon in front of a vault.
#
# The server block is NOT duplicated here: frontend/nginx-tls.conf is rendered
# for both deployments. Duplicating it is how the container and native postures
# drift apart.

# nginx_user_directive : echo the `user ...;` line from the OS's stock nginx.conf,
# or nothing. The worker account differs per OS (www-data / nginx / www / nobody)
# and the package already encodes the right answer -- guessing invites a config
# that starts as root and serves as nobody with unreadable temp dirs.
nginx_user_directive() {
    # Only meaningful for a master running as root. Emitting it in user mode
    # makes nginx warn on every start and changes nothing.
    [ "$(id -u)" = 0 ] || return 0
    for _c in /etc/nginx/nginx.conf /usr/local/etc/nginx/nginx.conf \
              /usr/pkg/etc/nginx/nginx.conf; do
        [ -r "$_c" ] || continue
        sed -n 's/^[[:space:]]*\(user[[:space:]][^;]*;\).*/\1/p' "$_c" | head -1
        return 0
    done
}

# nginx_mime_types : absolute path to the OS's mime.types, or empty.
nginx_mime_types() {
    for _m in /etc/nginx/mime.types /usr/local/etc/nginx/mime.types \
              /usr/pkg/etc/nginx/mime.types /opt/homebrew/etc/nginx/mime.types; do
        [ -r "$_m" ] && { printf '%s' "$_m"; return 0; }
    done
}

# _render_nginx GROUPS : write the wrapper + server block using GROUPS as the
# ssl_ecdh_curve value. Split out so the PQ probe can render twice.
_render_nginx() {
    _groups=$1
    # Cluster mTLS forwarding, off unless the caller asks: requesting a client
    # certificate makes some browsers prompt for one, which is wrong for a
    # single-node install. HA members need it or /cluster/refresh-cert rejects
    # them and their node certs stop renewing. Newlines are escaped for sed.
    if [ "${RH_NGINX_CLUSTER_MTLS:-0}" = 1 ]; then
        _ccv='    ssl_verify_client optional_no_ca;\n'
        _cch='        proxy_set_header X-Client-Cert $ssl_client_escaped_cert;\n'
    else
        _ccv=''; _cch=''
    fi
    # "default" means omit ssl_ecdh_curve entirely and let nginx/libssl choose.
    # Needed because the curve NAMES are not portable: LibreSSL rejects even the
    # classical "X25519:secp256r1" with SSL_CTX_set1_curves_list() failed, so a
    # second hardcoded list is not a safe last resort.
    if [ "$_groups" = default ]; then
        _grp_sed="/ssl_ecdh_curve \${SSL_GROUPS};/d"
    else
        _grp_sed="s|\${SSL_GROUPS}|$_groups|g"
    fi
    # sed with | as delimiter: every substituted value is a path or a port, and
    # none can contain a pipe. Paths contain / , so / is not usable here.
    sed -e "$_grp_sed" \
        -e "s|\${TLS_PORT}|$RH_NGINX_PORT|g" \
        -e "s|\${TLS_CERT}|$RH_NGINX_CERT|g" \
        -e "s|\${TLS_KEY}|$RH_NGINX_KEY|g" \
        -e "s|\${WEB_ROOT}|$RH_NGINX_WEB_ROOT|g" \
        -e "s|\${API_UPSTREAM}|$RH_NGINX_UPSTREAM|g" \
        -e "s|\${MAX_BODY_API}|${RH_NGINX_MAX_BODY_API:-1m}|g" \
        -e "s|\${MAX_BODY_BACKUP}|${RH_NGINX_MAX_BODY_BACKUP:-100m}|g" \
        -e "s|\${CLIENT_CERT_VERIFY}|${_ccv}|" \
        -e "s|\${CLIENT_CERT_HEADER}|${_cch}|g" \
        "$RH_NGINX_TPL" > "$RH_NGINX_PREFIX/conf.d/rhorizon-tls.conf"

    # Our own prefix and config rather than the OS's conf.d: a stock conf.d
    # usually ships a default server on :80, and the layout differs on every
    # target. Relative temp paths resolve against the prefix, so nginx keeps
    # its scratch inside the tree we own and chmod.
    {
        printf '%s\n' "$(nginx_user_directive)"
        cat <<EOF
worker_processes auto;
error_log $RH_NGINX_LOG_DIR/nginx-error.log warn;
pid $RH_NGINX_PREFIX/nginx.pid;
# OpenBSD's default login class caps openfiles at 128, well under
# worker_connections -- nginx warns and then silently accepts far fewer
# connections than configured. Raise the process limit to match.
worker_rlimit_nofile 1024;

events { worker_connections 1024; }

http {
${RH_NGINX_MIME:+    include $RH_NGINX_MIME;}
    default_type application/octet-stream;
    # No access log: it would record every secret NAME requested, at a lower
    # protection level than the audit chain and outside its retention policy.
    access_log off;
    client_body_temp_path body;
    proxy_temp_path proxy;
    fastcgi_temp_path fastcgi;
    uwsgi_temp_path uwsgi;
    scgi_temp_path scgi;
    server_tokens off;
    sendfile on;
    keepalive_timeout 65;
    include $RH_NGINX_PREFIX/conf.d/rhorizon-tls.conf;
}
EOF
    } > "$RH_NGINX_CONF"
}

# render_nginx_conf : render the native nginx config, probing for post-quantum
# support. Caller sets RH_NGINX_{BIN,PREFIX,CONF,WEB_ROOT,CERT,KEY,PORT,
# UPSTREAM,LOG_DIR,TPL}. Echoes the group list actually used.
#
# The probe runs `nginx -t` against the PQ list and falls back to the classical
# one when it is rejected. Version parsing was the alternative and it is worse:
# nginx may link a libssl unrelated to the openssl(1) on PATH -- on OpenBSD the
# API's python is built against the OpenSSL port while nginx links base
# LibreSSL, which has no ML-KEM at all. Asking the binary is the only answer
# that cannot be wrong.
RH_PQ_GROUPS="X25519MLKEM768:X25519:secp256r1"
RH_CLASSICAL_GROUPS="X25519:secp256r1"
render_nginx_conf() {
    # logs/ too: nginx opens its compiled-in default error log (prefix/logs/
    # error.log) BEFORE it parses the config's error_log directive, and alerts
    # on every start when the directory is missing.
    mkdir -p "$RH_NGINX_PREFIX/conf.d" "$RH_NGINX_PREFIX/body" \
             "$RH_NGINX_PREFIX/proxy" "$RH_NGINX_PREFIX/fastcgi" \
             "$RH_NGINX_PREFIX/uwsgi" "$RH_NGINX_PREFIX/scgi" \
             "$RH_NGINX_PREFIX/logs"
    RH_NGINX_MIME=$(nginx_mime_types)
    # HTTP/2 is the ONLY reason nginx fronts the native path. uvicorn already
    # serves HTTPS with post-quantum key exchange over HTTP/1.1, so an nginx
    # that cannot do h2 buys nothing and costs a hop. Today the server block
    # hardcodes `http2` in listen, so such an nginx fails nginx -t and we fall
    # back -- but that is incidental. Assert it, so making http2 conditional
    # later cannot silently leave a pointless proxy in front of the vault.
    _assert_h2() {
        grep -q '^[[:space:]]*listen .*http2' \
            "$RH_NGINX_PREFIX/conf.d/rhorizon-tls.conf" && return 0
        warn "rendered nginx config does not enable HTTP/2; declining nginx"
        warn "  (uvicorn already serves HTTPS + PQ over HTTP/1.1)"
        return 1
    }
    _render_nginx "$RH_PQ_GROUPS"
    if "$RH_NGINX_BIN" -t -p "$RH_NGINX_PREFIX" -c "$RH_NGINX_CONF" >/dev/null 2>&1; then
        _assert_h2 || return 1
        printf '%s' "$RH_PQ_GROUPS"
        return 0
    fi
    _render_nginx "$RH_CLASSICAL_GROUPS"
    if "$RH_NGINX_BIN" -t -p "$RH_NGINX_PREFIX" -c "$RH_NGINX_CONF" >/dev/null 2>&1; then
        _assert_h2 || return 1
        printf '%s' "$RH_CLASSICAL_GROUPS"
        return 0
    fi
    # Last resort: no ssl_ecdh_curve at all. Measured on OpenBSD, whose packaged
    # nginx links LibreSSL and rejects the classical list by NAME -- the group
    # syntax is not portable, so omitting it is the only universally valid form.
    _render_nginx default
    # Capture rather than let nginx -t write through: this function's stdout IS
    # the return value, and `syntax is ok` on success would corrupt it.
    if ! _out=$("$RH_NGINX_BIN" -t -p "$RH_NGINX_PREFIX" -c "$RH_NGINX_CONF" 2>&1); then
        # Return, do NOT die. The group list is not the only thing that can be
        # missing from a packaged nginx: ngx_http_v2_module is opt-in at compile
        # time (--with-http_v2_module), so a perfectly good nginx can reject
        # `listen ... http2`. Aborting here would fail an install that the
        # uvicorn-TLS path would have completed. The caller falls back.
        printf '%s\n' "$_out" >&2
        return 1
    fi
    _assert_h2 || return 1
    printf 'default'
}

# install_web_root SRC_FRONTEND DEST : populate the nginx document root.
#
# An explicit allowlist, mirroring frontend/Dockerfile -- NOT `cp -R frontend/.`.
# That directory also holds Dockerfile, nginx.conf and nginx-tls.conf, and a
# recursive copy would publish the reverse-proxy configuration and the cert
# paths over HTTP. Keep this list in sync with the COPY lines in the Dockerfile.
install_web_root() {
    _src=$1; _dst=$2
    run mkdir -p "$_dst"
    for _f in index.html sw.js manifest.json favicon.ico favicon.svg; do
        [ -f "$_src/$_f" ] && run cp -f "$_src/$_f" "$_dst/$_f"
    done
    for _d in icons css js; do
        [ -d "$_src/$_d" ] || continue
        run rm -rf "$_dst/$_d"
        run cp -R "$_src/$_d" "$_dst/$_d"
    done
    # World-readable: nginx workers run as the OS's own nginx account, not as
    # the installing user. Directories need traverse, files need read, nothing
    # needs write -- the SPA is static.
    run sh -c "find '$_dst' -type f -exec chmod 644 {} + ; find '$_dst' -type d -exec chmod 755 {} +"
}

# --- python venv + deps --------------------------------------------------
# make_venv PYBIN VENV_DIR : create venv, upgrade pip. Driver-supplied build
# env (CFLAGS/LDFLAGS/PKG_CONFIG_PATH/...) must already be exported by caller.
make_venv() {
    _py=$1; _venv=$2
    [ "${DRY_RUN:-0}" = 1 ] || [ -x "$_py" ] || die "python interpreter not found: $_py"
    run "$_py" -m venv "$_venv"
    run "$_venv/bin/pip" install --quiet --upgrade pip wheel
}

# pip_install VENV_DIR REPO_ROOT : install pinned requirements (hashes stripped
# so per-OS from-source builds work) + the test/tool deps skipped for user mode.
# A driver may set RH_PIP_EXCLUDE (a `|`-alt regex of dist names) to drop deps
# it satisfies another way -- e.g. NetBSD: cryptography (rust openssl-sys can't
# build) + uvloop (kvm_open). Those come from a driver_venv_extra copy instead.
pip_install() {
    _venv=$1; _root=$2
    _req=$(TMPDIR=/tmp mktemp)
    sed 's/[[:space:]]*--hash=[^[:space:]]*//g; s/[[:space:]]*\\$//' \
        "$_root/api/requirements.txt" > "$_req"
    if [ -n "${RH_PIP_EXCLUDE:-}" ]; then
        grep -vE "^(${RH_PIP_EXCLUDE})==" "$_req" > "$_req.f" && mv "$_req.f" "$_req"
    fi
    run "$_venv/bin/pip" install --quiet --no-deps -r "$_req"
    rm -f "$_req"

    # Optional dynamic backends keep independent hash-locked dependency sets.
    # The value is a closed list, never a path. Empty means core-only.
    _dynamic_deps=${RH_DYNAMIC_ENGINE_DEPS-"mysql redis cassandra"}
    for _module in $_dynamic_deps; do
        case "$_module" in
            mysql|redis|cassandra) ;;
            *) die "unknown RH_DYNAMIC_ENGINE_DEPS module: $_module" ;;
        esac
        _req=$(TMPDIR=/tmp mktemp)
        sed 's/[[:space:]]*--hash=[^[:space:]]*//g; s/[[:space:]]*\\$//' \
            "$_root/api/app/dynamic_engines/$_module/requirements.txt" > "$_req"
        # These engines are OPTIONAL, so a failure here degrades one backend --
        # it must not fail the whole vault install. Some carry C extensions with
        # native deps the OS may not provide: cassandra-driver needs libev's
        # ev.h, and its absence took down an entire OpenBSD install before this.
        # The API answers 501 for an engine whose driver is missing.
        if ! run "$_venv/bin/pip" install --quiet --no-deps -r "$_req"; then
            warn "optional dynamic-secrets engine '$_module' did not install;"
            warn "  that backend will report 501. The vault itself is unaffected."
        fi
        rm -f "$_req"
    done
    unset _dynamic_deps _module
}

# build_ext VENV_DIR REPO_ROOT : build + install rhorizon_crypto Rust wheel.
build_ext() {
    _venv=$1; _root=$2
    run "$_venv/bin/pip" install --quiet maturin
    # Honour CARGO_TARGET_DIR: a driver may redirect it off the root filesystem
    # (NetBSD does, whose 13G root cannot hold the build), and maturin then
    # writes the wheel there instead of ./target. Hardcoding the path made pip
    # try to install a literal '*'.
    _wheels="${CARGO_TARGET_DIR:-target}/wheels"
    # sh -c is needed so the shell expands *.whl, but the interpolated paths
    # must be quoted INSIDE the command string: macOS puts the venv under
    # ~/Library/Application Support/..., and unquoted the space word-splits, so
    # sh tries to run /Users/<user>/Library/Application and dies with
    # "No such file or directory". Only macOS trips this -- every other path
    # convention here is space-free. The glob stays outside the quotes so it
    # still expands.
    ( cd "$_root/api/rust" && run "$_venv/bin/maturin" build --release --strip \
      && run sh -c "'$_venv/bin/pip' install --quiet --force-reinstall '$_wheels'/*.whl" )
    run "$_venv/bin/python" -c 'import rhorizon_crypto' \
        && log "rhorizon_crypto OK" || warn "rhorizon_crypto import failed"
}

# --- app bring-up --------------------------------------------------------
# _curl_ca CAFILE ARGS... : curl, pinned to CAFILE when one is given. Never
# --insecure: an installer that skips verification teaches the operator that
# skipping it is normal.
_curl_ca() {
    _c=$1; shift
    if [ -n "$_c" ]; then curl --cacert "$_c" "$@"; else curl "$@"; fi
}

# unseal_vault BASE_URL PW_FILE [CAFILE] : wait for /health, then POST
# /unseal with the master password read from PW_FILE. Echoes the bootstrap root
# token to STDOUT when the vault mints one (fresh first-boot or post-restore),
# empty otherwise; diagnostics to stderr. CAFILE pins verification when
# BASE_URL is https with a self-signed cert.
#
# The password arrives by FILE, not by value. It used to be the second
# argument, and that forced every caller to hold it in a shell variable --
# which cannot carry a master password, because ANY $(...) capture on the way
# in strips ALL trailing newlines. A password ending in one was silently
# truncated, the vault was initialised with the short version while the
# operator still held the original, and there is no way back in.
# tools/install-container.sh already carried it by file for that reason; the
# signature now makes the value path unrepresentable for the other callers too.
unseal_vault() {
    _url=$1; _pwf=$2; _ca=${3:-}
    if [ "${DRY_RUN:-0}" = 1 ]; then printf '   [dry-run] unseal %s\n' "$_url" >&2; return 0; fi
    # -f matters: without it curl exits 0 on ANY response, including nginx's 502
    # while the backend is still booting. Direct against uvicorn a closed port
    # gave a connection error and this loop waited correctly; with a proxy in
    # front the port is always open, so the probe passed instantly and /unseal
    # fired at a backend that was not up yet.
    _i=0; while [ "$_i" -lt 45 ]; do _curl_ca "$_ca" -fsS -m2 "$_url/health" >/dev/null 2>&1 && break; sleep 2; _i=$((_i+1)); done
    [ -f "$_pwf" ] || { warn "master password file not found: $_pwf" >&2; return 1; }
    # Argon2id (256MB, t=3) can exceed 20s on slow/loaded hosts -- give the client
    # room so the root token in the response is not lost to a premature cutoff.
    # The password is serialised by the driver's resolved Python json module
    # and reaches curl on
    # stdin, so it never lands in argv (/proc, ps) or in the environment.
    # Interpolating it -- -d "{\"password\":\"$_pw\"}" -- produced invalid or
    # silently altered JSON for any password containing a double quote, a
    # backslash or a newline. A vault master password has to be opaque input.
    _resp=$("${PYBIN:-python3}" -c 'import json,sys; sys.stdout.write(json.dumps({"password": sys.stdin.read()}))' < "$_pwf" \
        | _curl_ca "$_ca" -s -m 120 -X POST "$_url/api/v1/vault/unseal" \
            -H 'Content-Type: application/json' --data-binary @-)
    if printf '%s' "$_resp" | grep -q unsealed; then log "vault unsealed" >&2
    else warn "unseal did not confirm (check the service log)" >&2; fi
    printf '%s' "$_resp" | sed -n 's/.*"root_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}
