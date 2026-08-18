#!/usr/bin/env bash
# Build all rhorizon docker images with SOURCE_DATE_EPOCH pinned to the
# current git commit timestamp, so two builds at the same commit produce
# identical layer content.
#
# Usage:
#   scripts/build-reproducible.sh [api|frontend|agent|all]   # default: all
#
# Output: built images named rhorizon-{api,frontend,agent}:${TAG} where
# TAG defaults to the short git SHA. Override with TAG=v1.0.0.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! git diff --quiet HEAD 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
  echo "[build] WARNING: working tree has uncommitted changes." >&2
  echo "[build] Reproducibility verification will fail unless every build" >&2
  echo "[build] starts from the exact same source state." >&2
fi

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export SOURCE_DATE_EPOCH

TAG=${TAG:-$(git rev-parse --short HEAD)}
TARGET=${1:-all}

# BuildKit honours SOURCE_DATE_EPOCH for layer mtimes since 0.11+.
# `--build-arg SOURCE_DATE_EPOCH` is also forwarded into RUN steps so
# pip / maturin / cargo can normalise their own outputs.
export DOCKER_BUILDKIT=1

build_one() {
  local name=$1 dockerfile=$2 ctx=$3
  echo "[build] ${name}: SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} TAG=${TAG}"
  docker buildx build \
    --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
    --output type=docker,name="rhorizon-${name}:${TAG}",rewrite-timestamp=true \
    -f "${dockerfile}" \
    "${ctx}"
}

case "$TARGET" in
  api)      build_one api      api/Dockerfile      . ;;
  frontend) build_one frontend frontend/Dockerfile frontend ;;
  agent)    build_one agent    agent/Dockerfile    agent ;;
  all)
    build_one api      api/Dockerfile      .
    build_one frontend frontend/Dockerfile frontend
    build_one agent    agent/Dockerfile    agent
    ;;
  *)
    echo "[build] unknown target: $TARGET" >&2
    exit 1
    ;;
esac
