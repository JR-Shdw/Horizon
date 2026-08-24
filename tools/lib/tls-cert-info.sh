#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Small, dependency-free helpers shared by the native and container installers.
# This file has no side effects when sourced.

tls_cert_fingerprint_sha256() {
    [ -r "$1" ] || return 1
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
        | sed -n 's/^[^=]*=//p'
}

tls_cert_is_self_signed() {
    [ -r "$1" ] || return 1
    _rh_tls_subject=$(openssl x509 -in "$1" -noout -subject 2>/dev/null \
        | sed 's/^subject=[[:space:]]*//') || return 1
    _rh_tls_issuer=$(openssl x509 -in "$1" -noout -issuer 2>/dev/null \
        | sed 's/^issuer=[[:space:]]*//') || return 1
    [ -n "$_rh_tls_subject" ] && [ "$_rh_tls_subject" = "$_rh_tls_issuer" ]
}

tls_print_browser_notice() {
    _rh_tls_cert=$1
    _rh_tls_url=$2
    _rh_tls_docs=$3
    _rh_tls_fingerprint=$(tls_cert_fingerprint_sha256 "$_rh_tls_cert") || return 1
    [ -n "$_rh_tls_fingerprint" ] || return 1
    cat <<EOF

  FIRST BROWSER VISIT
  -------------------
  This is not an encryption failure. HTTPS is active, but your browser warns
  because the certificate is self-signed and therefore is not known to its
  trust store yet. Before accepting it, open the certificate details and
  compare its SHA-256 fingerprint with the installer value below.

  URL                    : $_rh_tls_url
  SHA-256 fingerprint    : $_rh_tls_fingerprint

  If the fingerprints differ, stop. Trust instructions: $_rh_tls_docs
EOF
}
