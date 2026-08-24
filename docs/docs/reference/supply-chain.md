# Supply chain & SLSA

rhorizon's published container images are built to be **verifiable**:
you can check how and from what they were built rather than trust a
tag. This page summarizes the posture; the repo's `slsa-compliance.md`
maps every requirement to the artifact that proves it.

## Posture at a glance

| Track | Demonstrated level | Status |
|---|---|---|
| Build | L1 | Container provenance is published and signed |

Horizon does not claim Build L2 or L3. The Woodpecker pipeline step that
creates the provenance also receives the Cosign signing key, so the statement
is not non-falsifiable build-platform provenance. Reproducibility, locked
dependencies, signed images and SBOMs are additional controls, not a higher
SLSA level.

## What the build guarantees

- **Provenance** - every image carries a SLSA v1.0 in-toto predicate
  (`cosign attest --type slsaprovenance1`): source URI, commit digest,
  builder ID, pipeline invocation, build timestamp.
- **Signed images** - `cosign` signs the manifest-list digest, which
  covers both `amd64` and `arm64` at once.
- **Pinned, hashed dependencies** - Python deps are `--require-hashes`
  installed from a hash-locked `requirements.txt`. Base images are pinned by
  `@sha256:` digest, not a re-taggable tag. The build still uses networked
  package repositories, so this is not a hermetic-build claim.
- **SBOM** - generated and attached at publish time.
- **Reproducible** - `SOURCE_DATE_EPOCH` is honored so rebuilds match.

## Verify before you run

```bash
# image signature
cosign verify --key cosign.pub ghcr.io/jr-shdw/rhorizon-api:latest

# SLSA provenance
cosign verify-attestation --key cosign.pub --type slsaprovenance1 \
  ghcr.io/jr-shdw/rhorizon-api:latest \
  | jq -r '.payload' | base64 -d | jq .predicate
```

The repo's `verifying-images.md` walks the full check, including digest
pinning in compose / Helm.

## Native installs

The `tools/install-<os>.sh` native track is a weaker chain than the
container build. It pins upstream URLs + versions and relies on each
OS's package signing (apt/dnf/zypper/pacman, FreeBSD pkg, OpenBSD
signify all verify natively). One known gap: NetBSD's pkgsrc binary
repo is unsigned upstream, mitigated by HTTPS + pinned versions. Prefer
the verified container images for production; use native installs for
laptops and unsupported-Docker hosts.
