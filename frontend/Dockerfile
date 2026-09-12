FROM docker.io/library/nginx:stable-alpine@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c

# OCI labels for Docker Hub / GHCR / Gitea registry display.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="rhorizon-frontend" \
      org.opencontainers.image.description="Resurgamus Horizon, UI layer (Nginx + SPA) in front of the rhorizon vault API." \
      org.opencontainers.image.url="https://github.com/JR-Shdw/Horizon" \
      org.opencontainers.image.source="https://github.com/JR-Shdw/Horizon" \
      org.opencontainers.image.documentation="https://raw.githubusercontent.com/JR-Shdw/Horizon/main/README.md" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="Resurgamus" \
      org.opencontainers.image.authors="shdw <horizon@resurgamus.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

ARG SOURCE_DATE_EPOCH=315532800
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN rm /etc/nginx/conf.d/default.conf && \
    # Pre-create cache dirs with nginx user ownership (uid 101)
    mkdir -p /var/cache/nginx/client_temp \
             /var/cache/nginx/proxy_temp \
             /var/cache/nginx/fastcgi_temp \
             /var/cache/nginx/uwsgi_temp \
             /var/cache/nginx/scgi_temp && \
    chown -R nginx:nginx /var/cache/nginx

# HTTP config (always active)
COPY nginx.conf /etc/nginx/templates/default.conf.template
# TLS config (activated by 15-tls-setup.sh if TLS_ENABLED=true)
COPY nginx-tls.conf /etc/nginx/templates/tls.conf.tpl
# Entrypoint hook: rename .tpl -> .template before envsubst runs
COPY 15-tls-setup.sh /docker-entrypoint.d/15-tls-setup.sh
RUN chmod +x /docker-entrypoint.d/15-tls-setup.sh
# Entrypoint hook: reload nginx when the api container's address changes.
# nginx resolves an upstream once, at config load, so a recreated api leaves
# the frontend 502ing on a dead address until something reloads it.
COPY 25-upstream-watch.sh /docker-entrypoint.d/25-upstream-watch.sh
RUN chmod +x /docker-entrypoint.d/25-upstream-watch.sh

# Bound the worker count at BUILD time.
#
# The stock config is `worker_processes auto`, which means one worker per CPU.
# Against the compose pids_limit that is a fork storm on any large host: on a
# 32-core machine nginx tried to spawn 32 workers into a 20-pid budget and
# logged 15 "fork() failed while spawning worker process (11: Resource
# temporarily unavailable)" alerts before settling, leaving no pid budget for
# anything else in the container.
#
# It has to be fixed here rather than at runtime: the container is read_only
# with a tmpfs only on /etc/nginx/conf.d, so the image's own
# 30-tune-worker-processes.sh cannot rewrite /etc/nginx/nginx.conf and the
# `auto` silently stands.
#
# Four is ample for a TLS terminator in front of a vault -- nginx is
# event-driven, so workers cap CPU parallelism, not connection count.
RUN sed -i 's/^worker_processes.*/worker_processes 4;/' /etc/nginx/nginx.conf

COPY index.html /usr/share/nginx/html/index.html
COPY sw.js /usr/share/nginx/html/sw.js
COPY manifest.json /usr/share/nginx/html/manifest.json
COPY favicon.ico /usr/share/nginx/html/favicon.ico
COPY favicon.svg /usr/share/nginx/html/favicon.svg
COPY icons/ /usr/share/nginx/html/icons/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/

# Force readable perms regardless of source file modes (otherwise a 0600
# source file becomes 0600 in the image, and nginx (uid 101) gets 403).
RUN find /usr/share/nginx/html -type f -exec chmod 644 {} + && \
    find /usr/share/nginx/html -type d -exec chmod 755 {} +

# The pinned nginx:stable-alpine base (Alpine 3.24) lags Alpine's security
# patches for util-linux: it still carries libuuid 2.42.1-r0, against seven HIGH
# CVEs fixed in 2.42.3-r1 (CVE-2026-53612, CVE-2026-53613, CVE-2026-53614,
# CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410).
# curl is required at runtime by the compose healthcheck, so it stays in the
# image. The previous entries here (curl/libcurl, libexpat, c-ares) are gone
# because the base rebuild this digest points at already carries their fixes,
# along with openssl 3.5.8-r0 for CVE-2026-14456. Per that same rule, drop
# libuuid once upstream rebuilds the base against it.
RUN apk add --no-cache curl && \
    apk upgrade --no-cache libuuid

ENV MAX_BODY_API=1m
ENV MAX_BODY_BACKUP=100m
# API upstream host:port for the nginx proxy_pass. Default = the compose
# service name; the k8s/helm deployment overrides it (e.g. rhorizon-api:8200).
ENV API_UPSTREAM=api:8200
ENV TLS_ENABLED=false
ENV TLS_CERT=/certs/cert.pem
ENV TLS_KEY=/certs/key.pem

EXPOSE 8200 8443
