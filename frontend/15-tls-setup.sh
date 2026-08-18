#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
# Activate TLS server block if TLS_ENABLED=true
# Runs before nginx's 20-envsubst-on-templates.sh
# Processes tls.conf.tpl manually -> writes to conf.d (tmpfs)

if [ "${TLS_ENABLED}" != "true" ]; then
    exit 0
fi

TLS_CERT="${TLS_CERT:-/certs/cert.pem}"
TLS_KEY="${TLS_KEY:-/certs/key.pem}"
# Defaulted here, not just in compose: envsubst turns an unset variable into an
# empty string, which yields a config nginx either rejects or -- worse -- accepts
# with the wrong value. That already bit this file once for API_UPSTREAM.
# The image pins libssl 3.5.x, so the PQ group list is unconditional here; only
# the native installer has to probe for it.
TLS_PORT="${TLS_PORT:-8443}"
WEB_ROOT="${WEB_ROOT:-/usr/share/nginx/html}"
SSL_GROUPS="${SSL_GROUPS:-X25519MLKEM768:X25519:secp256r1}"
# Cluster mTLS forwarding. Empty unless RH_CLUSTER_MTLS=true, because requesting
# a client cert makes some browsers prompt for one -- see nginx-tls.conf.
# The newlines below are LITERAL, not "\n": envsubst substitutes the value
# verbatim, so an escape sequence would land in the config as backslash-n and
# collapse the directive onto the following line ("unknown directive"). sed, used
# by the native renderer, does interpret \n -- the two paths need different
# encodings of the same value.
if [ "${RH_CLUSTER_MTLS:-false}" = "true" ]; then
    CLIENT_CERT_VERIFY='    ssl_verify_client optional_no_ca;
'
    CLIENT_CERT_HEADER='        proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
'
else
    CLIENT_CERT_VERIFY=""
    CLIENT_CERT_HEADER=""
fi
export TLS_CERT TLS_KEY TLS_PORT WEB_ROOT SSL_GROUPS CLIENT_CERT_VERIFY CLIENT_CERT_HEADER

if [ ! -f "$TLS_CERT" ]; then
    echo "[tls-setup] ERROR: TLS_CERT not found: $TLS_CERT"
    exit 1
fi

if [ ! -f "$TLS_KEY" ]; then
    echo "[tls-setup] ERROR: TLS_KEY not found: $TLS_KEY"
    exit 1
fi

envsubst '${MAX_BODY_API} ${MAX_BODY_BACKUP} ${TLS_CERT} ${TLS_KEY} ${API_UPSTREAM} ${TLS_PORT} ${WEB_ROOT} ${SSL_GROUPS} ${CLIENT_CERT_VERIFY} ${CLIENT_CERT_HEADER}' \
    < /etc/nginx/templates/tls.conf.tpl \
    > /etc/nginx/conf.d/tls.conf

echo "[tls-setup] TLS enabled on :$TLS_PORT (cert: $TLS_CERT)"
