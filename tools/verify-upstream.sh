#!/usr/bin/env bash
# Verify cosign signatures on the upstream images we pull in CI.
# Catches the "compromised registry served a different blob under the
# same digest" case (rare but real - cf. trivy supply-chain incident
# of march 2026, mentioned in CLAUDE.md).
#
# Trust roots are the publisher's GitHub Actions OIDC identity, signed
# via cosign keyless against the public Sigstore Rekor log. We verify
# that the digest we pinned was actually signed by the upstream
# project's CI workflow.
#
# Usage:
#   tools/verify-upstream.sh                # verify all known images
#   tools/verify-upstream.sh trivy          # verify a subset
#
# Requires: cosign locally OR docker (we wrap the digest-pinned cosign
# image so the host doesn't need a cosign install).
set -euo pipefail

# Pinned cosign image - the bootstrap trust anchor. Same digest used by
# .woodpecker/*.yml.
COSIGN_IMAGE="gcr.io/projectsigstore/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"

# Pick the cosign invocation:
# - Native binary if present
# - Else `docker run` against the pinned cosign image
if command -v cosign >/dev/null 2>&1; then
  COSIGN=(cosign)
elif command -v docker >/dev/null 2>&1; then
  COSIGN=(docker run --rm "$COSIGN_IMAGE")
else
  echo "[verify-upstream] need either cosign or docker on PATH" >&2
  exit 1
fi

# Image:tag@digest references - keep in lockstep with versions.env and
# .woodpecker/*.yml. Each entry is paired with the upstream's signing
# identity so we can run `cosign verify` with the right constraints.
#
# Only images we KNOW are cosign-signed go here. Docker Hub `library/*`
# images (postgres, python, rust, alpine, nginx, docker:cli) aren't
# cosign-signed - for those, digest pinning is the trust
# anchor.
#
# Anchore syft (anchore/syft:v1.42.3) is intentionally absent: cosign
# can find a .sig blob next to the image but cannot verify it against
# a Sigstore Rekor entry - the publisher does not publish to the
# public transparency log. We rely on the pinned digest only.
declare -A IMAGES=(
  [trivy]="docker.io/aquasec/trivy:0.71.2@sha256:f5d0e600ecda7449e2a9b272805aef698631d3bb3f3a739a750de2c6819acdc9"
  [cosign]="gcr.io/projectsigstore/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"
)

# Each image is signed via cosign keyless; we pin the exact certificate
# identity (subject) and the OIDC issuer used by the publisher's CI.
# `--certificate-identity` is exact match; `--certificate-identity-regexp`
# is anchored regex. cosign uses Sigstore's Fulcio CA + Rekor log by
# default to validate the certificate chain and transparency entry.
declare -A IDENTITY_TYPE=(
  [trivy]="regexp"
  [cosign]="exact"
)

declare -A IDENTITY=(
  [trivy]="^https://github\\.com/aquasecurity/trivy/\\.github/workflows/.+$"
  [cosign]="keyless@projectsigstore.iam.gserviceaccount.com"
)

declare -A OIDC_ISSUER=(
  [trivy]="https://token.actions.githubusercontent.com"
  [cosign]="https://accounts.google.com"
)

verify_one() {
  local key=$1
  local ref="${IMAGES[$key]:-}"
  local id="${IDENTITY[$key]:-}"
  local id_type="${IDENTITY_TYPE[$key]:-}"
  local issuer="${OIDC_ISSUER[$key]:-}"

  if [[ -z "$ref" ]]; then
    echo "[verify-upstream] unknown image key: $key" >&2
    return 1
  fi

  echo "[verify-upstream] $key -> $ref"
  local id_flag
  if [[ "$id_type" == "regexp" ]]; then
    id_flag="--certificate-identity-regexp"
  else
    id_flag="--certificate-identity"
  fi

  if "${COSIGN[@]}" verify \
       "$id_flag" "$id" \
       --certificate-oidc-issuer "$issuer" \
       "$ref" >/dev/null 2>&1; then
    echo "[verify-upstream]   OK"
    return 0
  fi

  echo "[verify-upstream]   FAIL: signature mismatch or absent" >&2
  echo "[verify-upstream]   ref:      $ref" >&2
  echo "[verify-upstream]   identity: $id" >&2
  echo "[verify-upstream]   issuer:   $issuer" >&2
  return 1
}

if [[ $# -eq 0 ]]; then
  set -- "${!IMAGES[@]}"
fi

failures=0
for key in "$@"; do
  verify_one "$key" || failures=$((failures + 1))
done

if [[ $failures -gt 0 ]]; then
  echo "[verify-upstream] $failures upstream image(s) failed verification" >&2
  exit 1
fi

echo "[verify-upstream] all checked images verified"
