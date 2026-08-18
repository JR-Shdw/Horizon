# SLSA compliance - rhorizon

[SLSA](https://slsa.dev) is a framework for incrementally hardening
the integrity of software artifacts. This document maps each
applicable requirement to where it's implemented in this repo, with
links so you can verify the claim rather than trust the table.

Last reviewed: 2026-05-03 against SLSA v1.0.

## Summary

| Track | Level | Status |
|---|---|---|
| Build | L1 | yes |
| Build | L2 | yes |
| Build | L3 | yes |
| Build | L4 | ⚠ partial - reproducibility yes, hermetic yes, two-person review no (single maintainer) |
| Source | L1 | yes |
| Source | L2 | yes |
| Source | L3 | ⚠ partial - version-controlled history yes, signed-commit guard added for future changes, retained indefinitely yes |

Below: every requirement with the artifact that demonstrates it.

## Build track

### Build L1 - provenance exists

Requirement: produce a SLSA provenance document that describes how
the artifact was built.

Implementation: `.woodpecker/build.yml::push-and-sign` generates a
SLSA v1.0 in-toto predicate and attaches it to every published image
via `cosign attest --type slsaprovenance1`. The predicate captures:

- `buildDefinition.buildType` - `https://woodpecker-ci.org/build/v1`
- `buildDefinition.externalParameters.source.uri` - git URL
- `buildDefinition.externalParameters.source.digest.sha1` - commit
- `runDetails.builder.id` - `https://ci.example.com/woodpecker`
- `runDetails.metadata.invocationId` - pipeline URL
- `runDetails.metadata.startedOn` - build start time

Verification:

    cosign verify-attestation --key cosign.pub --type slsaprovenance1 \
      ghcr.io/jr-shdw/rhorizon-api:latest \
    | jq -r '.payload' | base64 -d | jq .predicate

### Build L2 - hosted, signed provenance

Requirements:
1. Build runs on a hosted build platform - not a developer workstation.
2. Provenance is digitally signed.

Implementation:
1. Builder is Woodpecker (control plane on node-2), build executes
   on the pinned runner (`labels: host: node-1` for hardware
   enforcement). No developer-laptop builds. See `.woodpecker/build.yml`
   (build + sign are decoupled from `deploy.yml`, which only
   restarts the already-published stack).
2. cosign signs the SLSA attestation with a key held only by Woodpecker
   (Woodpecker secret `cosign_key`, never accessible from the rhorizon
   vault - see "Trust separation" below). The matching public key
   ships at `cosign.pub` in repo root.

Verification: the previous `cosign verify-attestation` command also
checks the cryptographic signature; non-zero exit on tamper.

### Build L3 - non-falsifiable, isolated build

Requirements:
1. Provenance must be unforgeable from inside the build.
2. The build environment cannot be tampered with by other builds.

Implementation:
1. Signing key (`cosign_key`) is a Woodpecker repo secret, not an env
   var the user step writes itself. Steps cannot retrieve the key
   material in plain form to forge a signature later.
2. Each Woodpecker step runs in an isolated container (digest-pinned
   image, commit `7bbb2db`). No shared FS between
   pipeline runs except the explicit `/data/container/obs/trivy/reports`
   volume scoped to the host.

Verification:
- Inspect `.woodpecker/build.yml::push-and-sign.environment` -
  `from_secret: cosign_key` (no plain text).
- Pinned step images: `grep -E "image:.+@sha256:" .woodpecker/*.yml` -
  every image has a digest.

### Build L4 - hermetic, reproducible, two-person review

Requirements:
1. Build is hermetic (no network calls except to declared dependencies).
2. Build is reproducible (deterministic - same inputs -> same outputs).
3. Provenance generation is reviewed by two people.

Implementation:
1. **Hermetic**: every external resource is digest-pinned or
   hash-pinned:
    - Docker base images: `versions.env`
    - Python deps: `api/requirements.txt` with `--require-hashes`
      
    - Rust crates: `api/rust/Cargo.lock` + `agent/rust/Cargo.lock`
      with `--locked`
    - Go module (terraform provider): `terraform-provider-rhorizon/go.sum`
      with `GOFLAGS=-mod=readonly` + `GOTOOLCHAIN=local`
    - npm SDK: `sdk/node/package-lock.json` with `npm ci` (integrity-checked,
      fails on any lockfile/tree mismatch)
    - CI tools: `tools/ci-requirements.txt` with hashes (commit `5c44639`)
   No `apt-get install` of un-pinned packages in pipeline steps;
   `apk add curl jq git` in deploy still leaves a small surface (alpine
   apk repo signed by Alpine but versions floating). Documented in
   `docs/upstream-trust.md`.
2. **Reproducible**:
    - `SOURCE_DATE_EPOCH = git commit timestamp` injected everywhere
      
    - Rust `[profile.release] strip = true, codegen-units = 1, lto = "fat",
      panic = "abort"`
    - `RUSTFLAGS=--remap-path-prefix=/build=.`
    - `.woodpecker/reproducibility.yml` rebuilds wheel + agents twice
      and fails on any SHA256 difference.
      Verified locally before adding the gate (rhorizon_crypto wheel:
      `b34e993f...`, identical across two runs).
3. **Two-person review**: no - single maintainer. Mitigation: every change
   is recorded in git, every release tags an immutable commit, and
   the upstream-bump procedure (`docs/upstream-trust.md`) requires
   running `tools/verify-upstream.sh` and reviewing the changelog
   before bumping a digest. This is "reviewer = self with discipline",
   not L4-grade two-person.

Verification: trigger a no-op push to main; `.woodpecker/reproducibility.yml`
runs and the artifact hashes get printed. Same commit twice =
identical hashes.

### Artifact transparency - per-module SBOM + dep scan

Each shipped client module carries its own supply-chain posture, not
just the container images:

| Module | Package | SBOM | Dep-CVE scan |
|---|---|---|---|
| `api/rust` (`rhorizon_crypto`) | signed wheel | `rhorizon_crypto.sbom.cdx.json` | `cargo audit` (scan.yml) + `cargo deny` (validate.yml) + `trivy fs` |
| `agent/rust` (`rh-*`) | signed musl binaries | `rhorizon-agent.sbom.cdx.json` | `trivy fs` (scan.yml) |
| `terraform-provider-rhorizon` | signed Go binary | `terraform-provider-rhorizon.sbom.cdx.json` | `trivy fs` (scan.yml) |
| `sdk/node` (`@rhorizon/client`) | signed npm tgz | `rhorizon-client.sbom.cdx.json` | `trivy fs --include-dev-deps` (scan.yml) |
| `eso-provider` (vendored lib) | in source tarball | - (no own module) | covered by repo-wide scans |

- **SBOM**: `release.yml` runs `trivy fs --include-dev-deps --format
  cyclonedx` over each module's committed lockfile and cosign-signs the
  result; the SBOM hash is also a provenance subject.
- **Scan**: `scan.yml` (daily cron) runs `trivy fs` over the same
  lockfiles for fresh HIGH/CRITICAL CVEs; findings aggregate into the
  scan summary and the Matrix notification. Non-blocking by design
  (visibility), matching the existing image-scan posture.

## Source track

### Source L1 - version-controlled history

Implementation: Gitea repo `github.com/JR-Shdw/Horizon`. All commits
preserved. Trivially.

### Source L2 - verified history

Requirements:
1. Each change is documented (commit messages).
2. Each change is reviewed (CR / signed merge).

Implementation:
1. Conventional commits (`feat:`, `fix:`, `style:`, ...) - see `git log`.
2. Single-maintainer workflow with discipline: changes are committed locally, lint
   + tests pass before push, every push triggers `.woodpecker/validate.yml`
   (lint, SAST bandit, pip-audit, detect-secrets, pytest, compose
   syntax). No bypass of CI.

For a single-maintainer project, "verified history" means CI gates the merge to
main - no green pipeline, the change doesn't ship.

### Source L3 - retained indefinitely, verified author

Requirements:
1. Source kept for 18+ months after the last release.
2. Each commit's author is cryptographically verified (signed
   commits).

Implementation:
1. yes - Gitea retains commits as long as the repo exists; we don't
   force-push or rewrite history on main (memory feedback says
   "Prefer git merge over rebase to resolve conflicts - no force push").
2. partial - future commits can be verified with the tracked SSH signer
   policy in `.gitsigners`, `tools/check-signed-commits.sh`, and
   `.woodpecker/signed-commits.yml`. This becomes mandatory when Gitea/Forgejo
   branch protection requires the Woodpecker `signed-commits` status; for a
   hard direct-push stop, install
   `contrib/git-hooks/pre-receive-require-signed-commits` on the server.
   Historical unsigned commits remain before the enforcement point.

## Native-install track (BSD-style + distro packages)

The SLSA guarantees above cover the **canonical artifact**: the container
image / Python wheel built in CI (`--require-hashes`, digest-pinned, cosign +
provenance). The `tools/install-${os}.sh` scripts are a **separate track** with
a deliberately different, weaker posture - they exist to (a) validate that
rhorizon runs natively on each OS and (b) serve operators who deploy without
containers. They are NOT the SLSA-grade supply chain, and should not be treated
as one. Stated honestly so nobody assumes otherwise:

What holds on the native-install path:

- **Source integrity.** The Rust extension and the application are built from
  the exact git checkout on the target - not a third-party binary. You run the
  source you reviewed. (`Cargo.lock` is `--locked`, so the Rust dependency tree
  is pinned.)
- **Transport.** Every external fetch is over HTTPS.
- **anita** (the NetBSD golden tooling, `tools/netbsd-bootstrap.sh`) is
  **sha256-pinned** and verified with `sha256sum -c` before use.

What does NOT hold (the gaps, by design):

- **Python dependencies are version-pinned but not hash-verified** on the
  BSD installers (`install-{openbsd,netbsd}.sh`, and FreeBSD where it applies).
  These strip the `--hash=` lines and install with `--no-deps`, because the
  platform hands a pkg-built `cryptography` (LibreSSL / pkgsrc) to the venv and
  the canonical hashed-wheel set does not apply. So the *versions* come from
  `api/requirements.txt`, but `pip` does not enforce the hashes.
- **OS-package integrity is the best each package manager offers - verified
  everywhere except NetBSD:**

  | OS | Package integrity |
  |---|---|
  | Debian / Ubuntu / Rocky / openSUSE | GPG-signed, verified by apt / dnf / zypper (native default) |
  | Arch | signed package database, verified by pacman (native) |
  | FreeBSD | signed repo + pinned fingerprint, verified by `pkg` (native default) |
  | OpenBSD | signify-signed, verified by `pkg_add` (native default) |
  | NetBSD | **unsigned upstream** - the cdn.netbsd.org pkgsrc binary repo ships no `pkg_summary` signature and no per-package sigs, so verification is impossible. Mitigated by HTTPS + exact version pins in `install-netbsd.sh`. |

  So NetBSD is the only OS without signed-package verification, and that gap is
  *upstream* (the repo is unsigned), not a choice the script makes. Package
  versions are pinned on the BSD installers; the Linux installers take the
  distro-current signed version.
- **NetBSD base sets** (installed by anita) are fetched over HTTPS from the
  NetBSD CDN; their integrity rests on transport + the release tree, not a
  pinned manifest.

Why the tradeoff: buildability across heterogeneous OSes (LibreSSL vs OpenSSL,
distro vs pkgsrc PostgreSQL, no manylinux wheels) where the canonical hashed
artifact cannot be reused. The mitigation is that the *interesting* code - the
crypto extension and the app - is built from pinned source, and the result is
validated by running the full test suite on-target (see `docs/COMPATIBILITY.md`
/ `docs/SHIP-VALIDATION.md`).

Recommended posture: **for a SLSA-grade deployment, run the signed container
image** (verify per "Verifying the chain end-to-end" below). Use the native
installers for validation or container-averse hosts, accepting the weaker
dependency-integrity guarantee. Hardening roadmap for the native track: enable
pkgsrc/distro package signature verification, and solve the hashed-`cryptography`
build on LibreSSL so the BSD installers can keep `--require-hashes`.

## Trust separation

The signing key (`cosign_key` Woodpecker secret) is **deliberately not**
stored in rhorizon's own vault. Otherwise a sealed/broken rhorizon
would block its own bug-fix release - the chicken-and-egg case.

Rule (from `docs/supply-chain-plan.md`):
> Secrets needed to **build** a project live in Woodpecker.
> Secrets needed to **run** a project live in rhorizon.

This means an attacker who compromises the rhorizon vault gets all
secrets we keep there, but cannot retroactively sign a malicious
release. The two domains are isolated.

## Verifying the chain end-to-end

```bash
# 1. Pull the public key
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub > /tmp/rhorizon.pub

# 2. Verify image signature + SLSA + SBOM
IMG=ghcr.io/jr-shdw/rhorizon-api:latest
cosign verify --key /tmp/rhorizon.pub "$IMG"
cosign verify-attestation --key /tmp/rhorizon.pub --type slsaprovenance1 "$IMG"
cosign verify-attestation --key /tmp/rhorizon.pub --type cyclonedx "$IMG"

# 3. (Optional) Reproduce the wheel locally and compare hashes
git checkout <commit>
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
docker run --rm -v "$PWD/api/rust:/build" -w /build \
  -e SOURCE_DATE_EPOCH \
  -e RUSTFLAGS="--remap-path-prefix=/build=." \
  python:3.12-slim@sha256:46cb7c... \
  bash -c "apt-get update && apt-get install -y curl gcc libc6-dev && \
           curl https://sh.rustup.rs | sh -s -- -y && \
           PATH=/root/.cargo/bin:\$PATH pip install maturin && \
           PATH=/root/.cargo/bin:\$PATH maturin build --release --locked --strip"
sha256sum api/rust/target/wheels/*.whl
# Should match the .sha256 from the corresponding tag's release assets.
```

## What this protects against

| Threat | Blocked? | By what |
|---|---|---|
| Registry serves different bytes under same digest | yes | `cosign verify` against publisher's identity |
| PyPI mirror substitutes a wheel | yes | `pip install --require-hashes` |
| Crates.io mirror substitutes a transitive dep | yes | `cargo build --locked` against committed `Cargo.lock` |
| Tag mutability on Docker Hub | yes | digest pinning everywhere |
| Build non-determinism (random seed -> different output) | yes | reproducibility CI gate |
| Image pulled by consumer without signature | yes | cmdb consumer gate |
| Forked workflow signs as upstream | yes | `--certificate-identity-regexp` strict on workflow path |
| Compromised Woodpecker (signing key leaks) | ⚠ | partial - separate rhorizon vault unaffected, but signing capability lost |
| Compromised git repo (cosign.pub swapped) | no | git is the trust root |
| Insider commit pushed by legitimate publisher | no | discipline-of-bump only |
| Physical attack on node-1 / node-2 | no | out of scope |

## References

- SLSA v1.0 spec: https://slsa.dev/spec/v1.0/
- Sigstore + cosign: https://docs.sigstore.dev/
- in-toto attestations: https://github.com/in-toto/attestation
- This repo:
    - `docs/supply-chain-plan.md` - the original phased plan
    - `docs/upstream-trust.md` - what we trust upstream and why
    - `docs/verifying-images.md` - image verification recipes
    - `docs/verifying-releases.md` - release artifact verification recipes
    - `cosign.pub` - public signing key
