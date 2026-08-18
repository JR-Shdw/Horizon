# Verifying rhorizon images

Every push to `main` builds, pushes, signs, and attests the rhorizon
docker images. Anyone with `cosign.pub` (committed at the repo root
and served at https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub)
can verify them end-to-end before pulling.

## What is signed

For each image (`rhorizon-api`, `rhorizon-frontend`, `rhorizon-agent`):
- The image itself - `cosign sign` produces a signature OCI artifact
  (`sha256-XXXX.sig`) stored next to the image in the Gitea registry.
- A SLSA v1.0 provenance attestation describing the build (commit,
  builder URL, invocation, start time).
- A CycloneDX SBOM attestation (Software Bill of Materials).

All three are bound to the image's content digest, not its tag.

## Prerequisites

- `cosign` v2+ (we currently use v3.0.6 in CI)
- The public key:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub > cosign.pub
  ```

## Verify the image signature

```bash
IMAGE=ghcr.io/jr-shdw/rhorizon-api:latest

cosign verify --key cosign.pub "$IMAGE"
```

Output on success: a JSON array with the signature payload, the
annotations (`git-commit`, `build-time`, `builder`), and the digest
that was signed. Non-zero exit on failure.

## Verify the SLSA provenance

```bash
cosign verify-attestation --key cosign.pub --type slsaprovenance1 "$IMAGE" \
  | jq -r '.payload' | base64 -d | jq .predicate
```

This shows the build metadata: source repo URL + commit, builder
identity (`https://ci.example.com/woodpecker`), pipeline invocation URL,
and start time.

## Verify the SBOM

```bash
cosign verify-attestation --key cosign.pub --type cyclonedx "$IMAGE" \
  | jq -r '.payload' | base64 -d | jq -r '.predicate.components[].name' \
  | sort -u
```

Lists every component (Python package, OS package, Rust crate) baked
into the image.

## Pull-then-verify in a deploy script

```bash
set -euo pipefail
IMAGE=ghcr.io/jr-shdw/rhorizon-api:latest
cosign verify --key /etc/rhorizon/cosign.pub "$IMAGE" >/dev/null
# Resolve the digest cosign just verified, then pull by digest so the
# image we run is exactly the bytes we trusted.
DIGEST=$(docker image inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null \
        || docker pull "$IMAGE" >/dev/null && \
           docker image inspect --format='{{index .RepoDigests 0}}' "$IMAGE")
docker pull "${IMAGE%:*}@${DIGEST##*@}"
```

Refusing the pull when the signature doesn't verify is the consumer
gate. cmdb's deploy path
(`scripts/deploy.sh` and the Portainer pull integration) implements
this check.

## Trust roots

| Artifact | Where | What it proves |
|---|---|---|
| `cosign.pub` | repo root + Gitea raw URL | Anything signed by us is signable only with the matching private key. |
| Private key + password | Woodpecker secrets `cosign_key`, `cosign_password` (node-2) | Independent of rhorizon vault - building rhorizon does **not** require rhorizon to be unsealed. |
| Image digest | Gitea OCI registry | Mutable tags resolve to digests; signatures are bound to digests. |

The signing key intentionally lives outside rhorizon to avoid the
chicken-and-egg case where a sealed/broken rhorizon would block the
release of its own fix.
