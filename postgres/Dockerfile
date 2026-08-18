# rhorizon PostgreSQL image -- upstream postgres, minus gosu.
#
# WHY THIS EXISTS
# The official postgres image ships a prebuilt `gosu` binary statically linked
# against an old Go toolchain. Trivy flags every Go-stdlib CVE patched after
# that toolchain against it (1 CRITICAL + 13 HIGH as of 2026-07), and none are
# remediable by us: gosu upstream has not re-released, so bumping the base image
# does nothing. The CVEs are also unreachable -- gosu only drops root->postgres
# at container start (no socket, no TLS, no parsing). We remove the binary and
# reproduce its one behaviour with `setpriv` (util-linux, C, patched via the
# base image). The build fully flattens onto `scratch` so the original gosu
# bytes are physically gone from every layer, not just whited-out.
#
# Reproducible: buildable by a plain `docker/podman compose build` -- no
# --squash-all, no registry, no daemon-specific flags. PQ TLS (ML-KEM
# X25519MLKEM768) is preserved; verified in tools (privilege drop + handshake).

ARG POSTGRES_VERSION=18-trixie@sha256:06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941

FROM docker.io/library/postgres:${POSTGRES_VERSION} AS base

# Guard against silent drift: if POSTGRES_VERSION is bumped to a major/layout we
# do not reproduce below, fail the build loudly rather than ship a broken image.
RUN set -eux; \
    [ "${PG_MAJOR}" = "18" ] || { echo "PG_MAJOR drift: ${PG_MAJOR} (update postgres/Dockerfile ENV)"; exit 1; }; \
    [ "${PGDATA}" = "/var/lib/postgresql/18/docker" ] || { echo "PGDATA drift: ${PGDATA}"; exit 1; }

# CVE-2026-53615, util-linux <= 2.41-5, fixed by Debian in 2.41.5-0+deb13u1.
# postgres:18-trixie has not rebuilt against it, so the pinned base still ships
# the vulnerable set: 9 findings, one source package counted once per binary.
#
# Pinned rather than a bare `apt-get upgrade` so reproducibility.yml keeps
# holding. bsdutils carries epoch 1: and login is versioned
# 1:4.16.0-2+really<ver>, so neither derives from the source version.
#
# Runs in `base`, before the scratch flatten below, so the upgraded files land
# in the single materialised layer and no lower layer keeps the old binaries.
# DELETE once the base ships >= 2.41.5-0+deb13u1.
ARG UTIL_LINUX_VERSION=2.41.5-0+deb13u1
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends --only-upgrade \
        util-linux=${UTIL_LINUX_VERSION} \
        bsdutils=1:${UTIL_LINUX_VERSION} \
        libblkid1=${UTIL_LINUX_VERSION} \
        liblastlog2-2=${UTIL_LINUX_VERSION} \
        libmount1=${UTIL_LINUX_VERSION} \
        libsmartcols1=${UTIL_LINUX_VERSION} \
        libuuid1=${UTIL_LINUX_VERSION} \
        mount=${UTIL_LINUX_VERSION} \
        login=1:4.16.0-2+really${UTIL_LINUX_VERSION}; \
    rm -rf /var/lib/apt/lists/*

# docker-entrypoint.sh only ever calls `gosu postgres <cmd...>`. Replace the
# gosu Go binary with a shim over setpriv: same uid/gid drop + initialised
# supplementary groups (incl. ssl-cert, needed to read the TLS key), env
# preserved, then exec. The trailing sanity exec must resolve + run or the
# build fails.
RUN set -eux; \
    rm -f /usr/local/bin/gosu; \
    printf '%s\n' '#!/bin/sh' 'set -e' 'u="$1"; shift' \
      'exec setpriv --reuid "$u" --regid "$u" --init-groups -- "$@"' \
      > /usr/local/bin/gosu; \
    chmod +x /usr/local/bin/gosu; \
    gosu postgres true

# Flatten to a single layer on scratch: `COPY --from=base / /` materialises the
# merged filesystem (gosu removed), so no lower layer retains the old binary.
# scratch drops the upstream OCI config, so re-declare it verbatim. These values
# mirror the pinned base; the drift guard above keeps them honest.
FROM scratch
COPY --from=base / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/18/bin \
    LANG=en_US.utf8 \
    PG_MAJOR=18 \
    PG_VERSION=18.4-1.pgdg13+1 \
    PGDATA=/var/lib/postgresql/18/docker
EXPOSE 5432
VOLUME /var/lib/postgresql
STOPSIGNAL SIGINT
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
