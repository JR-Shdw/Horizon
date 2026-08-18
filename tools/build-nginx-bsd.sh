#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# Build nginx on *BSD against an OpenSSL that has ML-KEM.
#
#   sh tools/build-nginx-bsd.sh [--prefix DIR] [--keep-src]
#
# WHY THIS EXISTS
#
# Neither BSD's packaged nginx can do post-quantum key exchange, for different
# reasons, and on a vault that matters now -- harvest-now-decrypt-later is a
# present threat, not a future one.
#
#   OpenBSD  the nginx package links base LibreSSL, which has no ML-KEM at all.
#            tools/drivers/openbsd.sh already installs the OpenSSL port
#            (eopenssl 3.5) and builds CPython against it, so uvicorn there DOES
#            negotiate X25519MLKEM768. Adopting that nginx would trade
#            post-quantum away for HTTP/2, so install-native.sh refuses
#            (RH_NGINX_REQUIRE_PQ) and stays on uvicorn: PQ, no h2.
#
#   FreeBSD  base is OpenSSL 3.0 (measured 3.0.20 on 14.4-RELEASE-p8) and the
#            pkg nginx links it -- ldd shows /usr/lib/libssl.so.30. ML-KEM needs
#            3.5+. The packaged python312 links the same base libssl, so uvicorn
#            has no PQ either and there is nothing to fall back TO. This is a
#            property of our packaging, not of FreeBSD: openssl35 (3.5.7, with
#            X25519MLKEM768) sits in pkg, unused.
#
# An nginx linked against the newer OpenSSL breaks the tie: HTTP/2 AND
# post-quantum on the client-facing hop, which is the exposed one. Built here
# from a pinned, signature-verified source.
#
# SUPPLY CHAIN
#
# Every other dependency in this repo arrives hash-pinned or signature-verified,
# and a `curl | make` would be the one exception. So the tarball is checked
# twice: SHA-256 against the pin below, and a detached PGP signature that must
# be made by the pinned signer fingerprint -- not merely "some key that happens
# to be on nginx.org".
#
# Note the release signer's key is NOT in nginx_signing.key. Importing only the
# signing bundle fails with "no public key"; arut.key is a separate file. Bump
# NGINX_SIGNER_FPR together with NGINX_VERSION -- releases are signed by
# whoever cut them, so the fingerprint is version-specific.
#
# --with-http_v2_module is NOT optional here: nginx does not build HTTP/2 by
# default, and without it `listen ... http2` is rejected outright.
#
# VERIFIED end-to-end on OpenBSD 7.8 / eopenssl 3.5.4 (nginx 1.30.4):
#   ldd                      -> /usr/local/lib/eopenssl35/libssl.so.37.0
#   render_nginx_conf probe  -> X25519MLKEM768:X25519:secp256r1
#   ALPN                     -> h2
#   negotiated TLS1.3 group  -> X25519MLKEM768
# The ldd line is the one that matters: -L alone satisfies the linker but the
# binary would load base LibreSSL at run time and lose ML-KEM silently.
set -eu

NGINX_VERSION=1.30.4
NGINX_SHA256=4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b
# Roman Arutyunyan <r.arutyunyan@f5.com>, signer of 1.30.4.
NGINX_SIGNER_FPR=43387825DDB1BB97EC36BA5D007C8D7C15D87369
NGINX_KEY_URL=https://nginx.org/keys/arut.key

# Default prefix follows the OS's own tree, and must match where the driver
# looks for RH_NGINX_BIN: NetBSD keeps third-party software under /usr/pkg, the
# other two under /usr/local. A single hardcoded default would build an nginx
# the installer then ignores.
case "$(uname -s)" in
    NetBSD) PREFIX=/usr/pkg/rhorizon/nginx ;;
    *)      PREFIX=/usr/local/rhorizon/nginx ;;
esac
KEEP_SRC=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift ;;
        --keep-src) KEEP_SRC=1 ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) printf 'unknown arg: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done

log() { printf '>> %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

# Root runs directly: a stock OpenBSD ships no /etc/doas.conf, so assuming doas
# would fail the common case (a system install already running as root).
_priv() { if [ "$(id -u)" = 0 ]; then "$@"; else doas "$@"; fi; }

OS=$(uname -s)
case "$OS" in
    OpenBSD|FreeBSD|NetBSD) ;;
    *) die "OpenBSD, FreeBSD or NetBSD only -- a Linux build cannot produce a BSD binary" ;;
esac

# --- deps + OpenSSL location ----------------------------------------------
# pcre2 is required, not optional: the server block matches JS/CSS with a regex
# location, and an nginx without PCRE rejects it at config-test time. gmake
# because nginx's generated Makefile is not BSD-make compatible.
if [ "$OS" = OpenBSD ]; then
    for _p in gnupg pcre2 gmake; do
        pkg_info -e "$_p-*" >/dev/null 2>&1 || _priv pkg_add -I "$_p" || die "pkg_add $_p failed"
    done
    # Same detection tools/drivers/openbsd.sh uses for CPython, so nginx and the
    # interpreter link the same OpenSSL rather than drifting apart.
    EO=$(ls /usr/local/lib/pkgconfig/eopenssl*.pc 2>/dev/null \
         | sed -E 's,.*/eopenssl(.+)\.pc$,\1,' | head -1)
    [ -n "$EO" ] || die "eopenssl port not installed -- run the installer first (driver_pkg adds it)"
    SSL_INC="/usr/local/include/eopenssl${EO}"
    SSL_LIB="/usr/local/lib/eopenssl${EO}"
    SSL_LABEL="eopenssl${EO}"
elif [ "$OS" = FreeBSD ]; then
    _priv pkg install -y gnupg pcre2 gmake openssl35 >/dev/null 2>&1 \
        || die "pkg install of the build deps (incl. openssl35) failed"
    # openssl35 installs into /usr/local, unversioned -- unlike OpenBSD's
    # eopenssl, which keeps its own subdirectory. Base OpenSSL stays at
    # /usr/lib, so the two do not collide.
    SSL_INC="/usr/local/include"
    SSL_LIB="/usr/local/lib"
    SSL_LABEL="openssl35"
else
    # NetBSD. Base is OpenSSL 3.0.12 (measured on 10.1) with no ML-KEM, while
    # pkgsrc ships 3.6.3 which has it. pkgsrc lives under /usr/pkg and base
    # stays in /usr/lib, so they do not collide either.
    # curl too: this script must stand alone. The driver installs curl during a
    # full install, but the fetch below is the first thing that runs when the
    # script is used on its own, and base ftp cannot do https here.
    for _p in gnupg pcre2 gmake openssl curl; do
        _priv pkg_add -I "$_p" >/dev/null 2>&1 || true
    done
    SSL_INC="/usr/pkg/include"
    SSL_LIB="/usr/pkg/lib"
    SSL_LABEL="pkgsrc openssl"
fi
# The binary is not always called `gpg`: NetBSD's pkgsrc gnupg installs gpg1
# (GnuPG 1.4) with no `gpg` symlink, while the other two provide `gpg`. All of
# them emit VALIDSIG on --status-fd, which is what the pin below matches on.
GPG=""
for _g in gpg gpg2 gpg1; do
    command -v "$_g" >/dev/null 2>&1 && { GPG=$_g; break; }
done
[ -n "$GPG" ] || die "no gpg/gpg2/gpg1 after installing the build deps"
[ -f "$SSL_INC/openssl/ssl.h" ] || die "missing $SSL_INC/openssl/ssl.h"
[ -d "$SSL_LIB" ] || die "missing $SSL_LIB"
log "$SSL_LABEL: $SSL_INC / $SSL_LIB"

# OpenBSD's /tmp is ~1G and too small for a source build; /usr/local is roomy.
#
# mktemp -d, not a fixed $TMPDIR/nginx-build: a fixed path may already exist and
# belong to something else on the host, and this script deletes its build tree
# when it finishes. Creating the directory is what earns the right to remove it.
# The EXIT trap covers the failure paths too -- an aborted build used to leave
# the tree behind.
_scratch_parent=${TMPDIR:-/usr/local/rh-build}
mkdir -p "$_scratch_parent"
BUILD_DIR=$(mktemp -d "$_scratch_parent/rhorizon-nginx.XXXXXX") \
    || die "could not create a build directory under $_scratch_parent"
_cleanup() {
    # --keep-src is for debugging a failed build, so honour it here too.
    if [ "$KEEP_SRC" = 1 ]; then
        printf '>> build tree kept: %s\n' "$BUILD_DIR"
    else
        rm -rf "$BUILD_DIR"
    fi
}
trap _cleanup EXIT INT TERM
cd "$BUILD_DIR"

# --- fetch ----------------------------------------------------------------
TARBALL="nginx-$NGINX_VERSION.tar.gz"
_fetch() { # _fetch URL DEST
    # Both BSDs ship an `ftp`, but they are different programs: OpenBSD's is a
    # URL fetcher, FreeBSD's is tnftp and reads `https://...` as a host named
    # "https:". Dispatch on the OS, do not probe for the command name.
    if [ "$OS" = FreeBSD ]; then
        fetch -q -o "$2" "$1"
    elif [ "$OS" = OpenBSD ]; then
        ftp -V -o "$2" "$1"
    else
        # NetBSD's base ftp is tnftp -- the same program that misparses https://
        # on FreeBSD -- so use curl, which its driver installs.
        curl -fsS --proto '=https' -o "$2" "$1"
    fi
}
[ -f "$TARBALL" ] || _fetch "https://nginx.org/download/$TARBALL" "$TARBALL"
[ -f "$TARBALL.asc" ] || _fetch "https://nginx.org/download/$TARBALL.asc" "$TARBALL.asc"
[ -f signer.key ] || _fetch "$NGINX_KEY_URL" signer.key

# --- verify ---------------------------------------------------------------
_have=$(sha256 -q "$TARBALL" 2>/dev/null || sha256sum "$TARBALL" | cut -d' ' -f1)
[ "$_have" = "$NGINX_SHA256" ] \
    || die "sha256 mismatch: got $_have want $NGINX_SHA256"
log "sha256 OK"

# Throwaway keyring: never touch the builder's real one.
GNUPGHOME="$BUILD_DIR/gnupg"; export GNUPGHOME
rm -rf "$GNUPGHOME"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
"$GPG" --batch --quiet --import signer.key || die "could not import the nginx signing key"
# VALIDSIG carries the signing key's fingerprint. Matching on it -- rather than
# trusting gpg's exit status -- is what makes this a pin: any other key, even a
# genuine nginx one, fails here.
if ! "$GPG" --batch --status-fd 1 --verify "$TARBALL.asc" "$TARBALL" 2>/dev/null \
     | grep -q "^\[GNUPG:\] VALIDSIG $NGINX_SIGNER_FPR"; then
    die "PGP verification failed: not signed by $NGINX_SIGNER_FPR"
fi
log "PGP signature OK ($NGINX_SIGNER_FPR)"

# --- build ----------------------------------------------------------------
rm -rf "nginx-$NGINX_VERSION"
tar xzf "$TARBALL"
cd "nginx-$NGINX_VERSION"

# rpath, not just -L: the binary must find eopenssl at RUN time too, or it
# silently falls back to base LibreSSL and the whole point is lost.
./configure \
    --prefix="$PREFIX" \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-cc-opt="-I$SSL_INC" \
    --with-ld-opt="-L$SSL_LIB -Wl,-rpath,$SSL_LIB" \
    >configure.log 2>&1 || { tail -20 configure.log >&2; die "configure failed"; }
gmake -j"$(sysctl -n hw.ncpu)" >build.log 2>&1 || { tail -20 build.log >&2; die "build failed"; }
_priv gmake install >install.log 2>&1 || die "install failed"

# --- verify the product ---------------------------------------------------
NGINX_BIN="$PREFIX/sbin/nginx"
[ -x "$NGINX_BIN" ] || die "no binary at $NGINX_BIN"
_v=$("$NGINX_BIN" -V 2>&1)

# "built with LibreSSL" here means the link silently fell back and this build is
# pointless -- fail loudly rather than ship a non-PQ nginx that looks fine.
case "$_v" in
    *LibreSSL*) die "linked against LibreSSL -- no ML-KEM. Check $SSL_LIB" ;;
esac
printf '%s\n' "$_v" | grep -q "built with OpenSSL" \
    || die "not linked against OpenSSL: $(printf '%s' "$_v" | tr ',' '\n' | grep -i 'built with')"
printf '%s\n' "$_v" | grep -q -- --with-http_v2_module \
    || die "http_v2 module missing -- listen ... http2 would be rejected"

# The decisive check. -L satisfies the LINKER; only the rpath decides what the
# process loads at RUN time, and the wrong answer is silent: on FreeBSD base
# libssl.so.30 sits in /usr/lib and would be picked up with no error, losing
# ML-KEM while `nginx -V` still looks right.
_ldd=$(ldd "$NGINX_BIN" 2>/dev/null | grep -i 'libssl' || true)
case "$_ldd" in
    *"$SSL_LIB"*) log "runtime libssl: $(printf '%s' "$_ldd" | tr -s ' ' | cut -d' ' -f1-4)" ;;
    "") warn "could not read ldd output; runtime linkage UNVERIFIED" ;;
    *) die "runtime libssl is not from $SSL_LIB -- ML-KEM would be lost:
  $_ldd" ;;
esac

# Belt and braces: the group must actually be offered. A 3.0 libssl that somehow
# satisfied the checks above still cannot do this.
_SSL_BIN="${SSL_LIB%/lib}/bin/openssl"
if [ -x "$_SSL_BIN" ]; then
    if "$_SSL_BIN" list -tls-groups 2>/dev/null | grep -qi X25519MLKEM768; then
        log "X25519MLKEM768 present in $SSL_LABEL"
    else
        warn "$SSL_LABEL does not list X25519MLKEM768 -- the installer's probe"
        warn "  will fall back to a classical group list"
    fi
fi

log "$(printf '%s' "$_v" | tr ',' '\n' | grep -i 'nginx version')"
log "$(printf '%s' "$_v" | tr ',' '\n' | grep -i 'built with')"
log "built: $NGINX_BIN"
log "next: install-native.sh finds it via RH_NGINX_BIN, and its nginx -t probe"
log "      decides PQ vs classical. Confirm end-to-end with:"
log "      sh tools/pq-verify.sh <host>:<port>"

# Nothing to remove here any more: the EXIT trap drops the whole scratch tree,
# which also covers the failure paths this line never did.
printf '%s\n' "$NGINX_BIN"
