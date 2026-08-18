#!/usr/bin/env bash
# Resolve image:tag references to image@sha256:DIGEST.
# Uses the Docker Hub / GCR registry HTTP API directly (no daemon required)
# so the produced digest is the OCI index digest - stable across architectures.
#
# Usage:
#   tools/pin-digests.sh                 # print resolved digests for known images
#   tools/pin-digests.sh image:tag       # resolve a single ref
set -euo pipefail

# Reference list - keep in sync with Dockerfiles + .woodpecker/*.yml.
DEFAULT_REFS=(
  "docker.io/library/python:3.12-slim"
  "docker.io/library/nginx:stable-alpine"
  "docker.io/library/rust:1-slim"
  "docker.io/library/postgres:18-trixie"
  "docker.io/library/alpine:3.23"
  "docker.io/library/docker:29-cli"
  "docker.io/aquasec/trivy:0.70.0"
  "gcr.io/projectsigstore/cosign:v3.0.6"
)

resolve() {
  local ref="$1"
  local registry repo tag

  case "$ref" in
    docker.io/*)
      registry="registry-1.docker.io"
      repo="${ref#docker.io/}"
      ;;
    gcr.io/*)
      registry="gcr.io"
      repo="${ref#gcr.io/}"
      ;;
    *)
      echo "[pin] unsupported registry: $ref" >&2
      return 1
      ;;
  esac

  tag="${repo##*:}"
  repo="${repo%:*}"

  local token=""
  if [[ "$registry" == "registry-1.docker.io" ]]; then
    token=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
  fi

  local auth_header=()
  [[ -n "$token" ]] && auth_header=("-H" "Authorization: Bearer $token")

  # Ask for OCI index first, fall back to docker manifest list (multi-arch),
  # then to a single-arch manifest. We want the digest of whatever the tag
  # points to - that's what `FROM image@sha256:...` should reference.
  local digest
  digest=$(curl -fsSI "${auth_header[@]}" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "https://${registry}/v2/${repo}/manifests/${tag}" \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')

  if [[ -z "$digest" ]]; then
    echo "[pin] could not resolve $ref" >&2
    return 1
  fi

  printf '%s@%s\n' "${ref%:*}:${tag}" "${digest}"
}

if [[ $# -eq 0 ]]; then
  for r in "${DEFAULT_REFS[@]}"; do
    resolve "$r"
  done
else
  for r in "$@"; do
    resolve "$r"
  done
fi
