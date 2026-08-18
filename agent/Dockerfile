FROM docker.io/library/rust:1-slim@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder

# Multi-arch build : buildx fills TARGETARCH automatically with `amd64` or
# `arm64`. Plain `docker build` without buildkit leaves it empty ; we
# default to amd64 so the legacy `docker build .` path still works.
ARG TARGETARCH=amd64

# musl-tools : static musl C toolchain (musl-gcc). cmake + make + perl : build
# AWS-LC (aws-lc-rs, the rustls PQ provider). nasm : x86_64 asm (amd64 only,
# unused on arm64). No clang/libclang: aws-lc-sys uses its pre-generated
# bindings (no bindgen) for both musl targets, which is exactly what lets this
# same line build amd64 AND arm64 (bindgen's libclang panics under QEMU arm64).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        musl-tools cmake make perl nasm pkg-config && \
    rm -rf /var/lib/apt/lists/*

# aws-lc-rs / cc-rs : use musl-gcc as the C compiler for the musl target
# (only the var matching the active target triple is consulted).
ENV CC_x86_64_unknown_linux_musl=musl-gcc \
    CC_aarch64_unknown_linux_musl=musl-gcc

# Resolve the rust target triple from TARGETARCH and persist it so the
# next RUN can re-read it without re-running this case (saves ~100 ms
# for nothing, but keeps the tree readable).
RUN case "$TARGETARCH" in \
        amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
        arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "[rhorizon-agent] unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    echo "$RUST_TARGET" > /rust-target

WORKDIR /build
COPY rust/ .

# Reproducible build:
# - SOURCE_DATE_EPOCH (passed at docker build time) is honored by cargo
#   1.79+ for any embedded date.
# - --remap-path-prefix=/build=. strips absolute build paths from the
#   binary (panic messages, residual symbol references).
# `strip = true` is already set in Cargo.toml [profile.release] ; the
# explicit strip below is belt-and-suspenders. Under buildx + QEMU
# emulation for arm64, the `strip` binary is the emulated arm64 one
# from the rust:1-slim image, so it strips arm64 binaries correctly.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV RUSTFLAGS="--remap-path-prefix=/build=."

RUN RUST_TARGET="$(cat /rust-target)" && \
    cargo build --release --locked --target "$RUST_TARGET" && \
    mkdir -p /out && \
    for b in rh-inject rh-fetch rh-watch rh-mcp-gateway; do \
        cp "target/$RUST_TARGET/release/$b" "/out/$b" && \
        strip "/out/$b"; \
    done


FROM scratch

# OCI labels for Docker Hub / GHCR / Gitea registry display.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="rhorizon-agent" \
      org.opencontainers.image.description="Resurgamus Horizon agent binaries (rh-fetch / rh-inject / rh-watch), pull or inject vault secrets into application containers." \
      org.opencontainers.image.url="https://github.com/JR-Shdw/Horizon" \
      org.opencontainers.image.source="https://github.com/JR-Shdw/Horizon" \
      org.opencontainers.image.documentation="https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docs/docs/howto/agents.md" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="Resurgamus" \
      org.opencontainers.image.authors="shdw <horizon@resurgamus.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Binaries copied from the arch-agnostic /out/ dir (the builder stage
# put them there after resolving the right rust target). This avoids
# the COPY-with-shell-var problem (shell variables don't expand in
# the COPY directive's source path).
COPY --from=builder /out/rh-inject /usr/local/bin/rh-inject
COPY --from=builder /out/rh-fetch /usr/local/bin/rh-fetch
COPY --from=builder /out/rh-watch /usr/local/bin/rh-watch
COPY --from=builder /out/rh-mcp-gateway /usr/local/bin/rh-mcp-gateway

USER 65534

ENTRYPOINT ["/usr/local/bin/rh-fetch"]
