# Supply-Chain Hardening - rhorizon

> **STATUS: historical planning document.** This was the original phased
> plan, written before implementation. The phases below shipped (with some
> design changes along the way - see the callout in 2.1). For the current,
> maintained-in-sync state, read `docs/slsa-compliance.md` (requirement-by-
> requirement mapping), `docs/verifying-images.md` and
> `docs/verifying-releases.md` (consumer verification recipes). Keep this
> file as the design-history record; don't treat it as live guidance.

**Goal**: every release is reproducible, signed at every artifact boundary,
and verifiable end-to-end by consumers (cmdb, Ansible, k8s).

For each tag `vX.Y.Z`:
1. Reproducible build - same commit => byte-identical artifacts
2. Per-artifact signing on Gitea/GitHub Releases (`*.whl`, binaries, source tarball, SBOM)
3. Image signing on Docker registry push (cosign + SLSA provenance)
4. Upstream source verification - when an upstream signs, we verify
5. Consumer-side signature gate (cmdb deploy refuses unsigned image)

---

## Pinning hard (1-2 days)

Without this, "reproducible" is theatre.

### 0.1 SHA256 digests on every Docker image
Files: `api/Dockerfile`, `frontend/Dockerfile`, `agent/Dockerfile`, `docker-compose.yml`, `docker-compose.test.yml`, `.woodpecker/*.yml`.

```diff
- FROM docker.io/library/python:3.12-slim AS builder
+ FROM docker.io/library/python:3.12-slim@sha256:1e8d624...  AS builder
```

Helper: `tools/pin-digests.sh` resolves current tags -> digests via `docker buildx imagetools inspect`. Run on bump.

### 0.2 `pip install --require-hashes`
Files: `api/requirements.txt`, `cli/requirements.txt`, `mcp/requirements.txt`,
new `api/requirements.in` (loose source), Dockerfile install lines.

```bash
pip-compile --generate-hashes --output-file api/requirements.txt api/requirements.in
```

Pip then refuses any wheel whose hash differs.

### 0.3 `Cargo.lock` for `agent/rust/`
- Commit `agent/rust/Cargo.lock`
- `agent/Dockerfile`: `cargo build --release --locked`
- `api/rust/` already has `Cargo.lock`, just add `--locked` to all `cargo` invocations

### 0.4 CI tooling pinned with hashes
File new: `tools/ci-requirements.txt` (ruff, bandit, pip-audit, detect-secrets, pip-tools, maturin) generated with `--generate-hashes`.

`.woodpecker/validate.yml`:
```diff
- pip install --no-cache-dir ruff
+ pip install --require-hashes --no-cache-dir -r tools/ci-requirements.txt
```

---

## Reproducible build (3-5 days)

### 1.1 `SOURCE_DATE_EPOCH` everywhere
All Dockerfiles: `ARG SOURCE_DATE_EPOCH` + `ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}`.

Build script injects `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`.

Affects tar mtimes, gzip headers, Python `.pyc` timestamps, most modern build tools.

### 1.2 Reproducible Python wheels
- `pip wheel --no-deps --no-binary :all: --wheel-dir=dist/`
- Strip `__pycache__`, `.pyc` from final image (already partial in `api/Dockerfile`)
- `tar --sort=name --owner=0 --group=0 --numeric-owner` for any tarball
- Verify with `diffoscope` two builds at same commit

### 1.3 Reproducible Rust
Files: `api/rust/Cargo.toml`, `agent/rust/Cargo.toml`:
```toml
[profile.release]
strip = true
codegen-units = 1
lto = "fat"
```
+ `RUSTFLAGS="--remap-path-prefix=$PWD=."`
+ `cargo build --release --locked --frozen`

### 1.4 CI rebuild-and-diff job
New: `.woodpecker/reproducibility.yml`. On `push` to `main`:
1. Build full artifact set with `SOURCE_DATE_EPOCH = git_commit_ct`
2. Save hashes
3. Wipe cache, rebuild
4. `diff` hashes - fail pipeline if any artifact differs
5. On failure, run `diffoscope` and upload to artifact storage

---

## Sign artifacts on release publish (2-3 days)

### 2.1 Cosign keypair (offline, dogfood)
- `cosign generate-key-pair` on an isolated workstation
- Private key: store **inside rhorizon itself** under `cosign-private-key`, scope `release:r`
- Password: `cosign-password`

> **Superseded.** Shipped the opposite way on purpose: the key lives in
> Woodpecker secrets (`cosign_key`/`cosign_password`), never in rhorizon's
> own vault. Storing it in-vault would make a sealed/broken rhorizon block
> the release of its own fix - the chicken-and-egg case. See "Trust
> separation" in `docs/slsa-compliance.md`.
- Public key:
  - committed to repo as `cosign.pub` (root)
  - published over HTTPS at `https://example.com/cosign.pub` (channel-diverse)
  - signed git tag at the same commit so the public key chain is checkable

### 2.2 New pipeline `.woodpecker/release.yml`
Trigger: `event: tag` matching `v*.*.*`.

Steps:
1. Reproducible build (calls `scripts/build-all.sh`)
2. For every artifact (`*.whl`, source `*.tar.gz`, static binaries `rh-inject`/`rh-fetch`):
   ```
   cosign sign-blob --key env://COSIGN_KEY artifact > artifact.sig
   ```
3. Generate per-artifact SBOM (CycloneDX via syft)
4. Sign every SBOM the same way
5. Publish via Gitea API `POST /repos/{owner}/{repo}/releases/{id}/assets`:
   `(artifact, artifact.sig, artifact.sbom.json, artifact.sbom.sig)` x N
6. If ship-to-github enabled: `gh release create` with same set + push `cosign.pub`

### 2.3 User verification doc
File new: `docs/verifying-releases.md`
```bash
curl -O https://github.com/JR-Shdw/Horizon/releases/download/v1.0.0/wheel.whl
curl -O https://github.com/JR-Shdw/Horizon/releases/download/v1.0.0/wheel.whl.sig
curl -O https://example.com/cosign.pub

cosign verify-blob --key cosign.pub --signature wheel.whl.sig wheel.whl
```

---

## Sign Docker images (1-2 days)

### 3.1 Activate `.woodpecker/deploy.yml::sbom-and-sign`
Skeleton already exists, currently skipped (no `cosign_key` secret).

Steps:
1. Configure `cosign_key` + `cosign_password` as Woodpecker secrets (sourced from rhorizon vault).
2. Push images to registry (`ghcr.io/jr-shdw/rhorizon-api:vX.Y.Z`) before signing.
3. For each image:
   ```
   cosign sign --key env://COSIGN_KEY \
     --annotations="git-commit=${CI_COMMIT_SHA}" \
     --annotations="build-time=${SOURCE_DATE_EPOCH}" \
     ghcr.io/jr-shdw/rhorizon-api@sha256:DIGEST
   ```
4. SLSA v1.0 provenance attestation:
   ```
   cosign attest --key env://COSIGN_KEY \
     --predicate slsa-provenance.json --type slsaprovenance \
     ghcr.io/jr-shdw/rhorizon-api@sha256:DIGEST
   ```

### 3.2 SLSA predicate generator
New: `tools/gen-slsa-predicate.sh` produces JSON conformant to SLSA v1.0:
- `builder.id`: `https://ci.example.com/woodpecker`
- `buildType`: `https://woodpecker-ci.org/`
- `invocation.configSource.uri` + commit sha
- `materials`: digests of source inputs

---

## Upstream source verification (1-2 days)

We don't sign what we ingest, but when upstream publishes a signature we verify it before pulling/installing.

### 4.1 Cosign-signed images we can verify
| Image | Signed by | Verification |
|---|---|---|
| `gcr.io/projectsigstore/cosign` | sigstore (keyless OIDC) | `cosign verify --certificate-identity-regexp '@sigstore' --certificate-oidc-issuer https://accounts.google.com gcr.io/projectsigstore/cosign:v3.0.6` |
| `aquasec/trivy:0.71.2` | Aqua Security (cosign + Sigstore) | `cosign verify --certificate-identity-regexp '@aquasec.com' aquasec/trivy:0.71.2` |
| Chainguard `cgr.dev/chainguard/*` | Chainguard (signed) | Native cosign verify |

Action: in `.woodpecker/validate.yml` and `scan.yml`, **before** using `aquasec/trivy:0.71.2` or `gcr.io/projectsigstore/cosign:v3.0.6`, run a pre-step `cosign verify` and fail if mismatch. Re-run only on digest bump.

### 4.2 Python deps - verify when available
- pip-audit already checks CVE - keep
- For PyPI packages with PEP 740 sigstore attestations (cryptography, pyca/* family): add `pip-audit --require-attestations` once that flag stabilises (currently experimental)
- Manual one-time check at version bump: download wheel + `.sigstore.json` from PyPI, run `pip-audit --strict`

#### Provenance audit - pinned versions (2026-05-08)

One-shot audit of the `api/requirements.txt` deps at their pinned version
via `https://pypi.org/integrity/<pkg>/<ver>/<wheel>/provenance`:

**Signed (PEP 740 / sigstore attestations, HTTP 200, 14/30):**
anyio, asyncpg, certifi, click, cryptography, fastapi,
idna, pydantic, pydantic-settings, pyrage, python-dotenv,
typing-extensions, typing-inspection, websockets

**Unsigned (HTTP 404, 16/30):**
annotated-types, bonsai, cffi, fido2, greenlet, h11,
httpcore, httptools, httpx, prometheus-client,
pycparser, pydantic-core, pynacl, pyotp, pyyaml,
starlette, uvloop, watchfiles

Consequence: the stack is NOT uniformly SLSA-signed. The crypto-critical
(`pynacl`) and HTTP (`httptools`, `uvloop`, `starlette`, `h11`, `httpx`) deps
remain un-attested on PyPI. The wheels are nonetheless protected by
`pip install --require-hashes` on the Docker builder side.

**Evaluation rule at bump:**

| Criterion | Status | Action |
|---|---|---|
| Solo maintainer + unsigned | reject | example: granian |
| Multi-maintainer + unsigned + hash-pinned | accept | example: pynacl (PyCA), httptools (encode), uvloop (MagicStack) |
| Multi-maintainer + signed | preferred | example: cryptography, fastapi, pydantic |

Only adopt an unsigned dep if it is carried by an established org (PyCA,
encode, MagicStack, AIOHTTP, etc.) - not by an individual account. The target
risk is typosquatting / solo-account hijack, undetectable without a signed
provenance chain.

**Planned follow-up**: at every dep bump, re-run `tools/audit-pypi-provenance.sh`
(to be created), which regenerates this table and diffs it against the
previous version. A dep that flips from signed -> unsigned raises a security
alert (potential upstream account hijack).

### 4.3 Rust crates - verify when possible
- `crates.io` doesn't sign (no native signature scheme)
- For critical crates (`pyo3`, `aes-gcm`, `zeroize`, `memsec`): pin to digest in `Cargo.lock` (already done) + manual GPG verification of release tag at version bump
- Document in `docs/upstream-trust.md` the trust roots we anchored

### 4.4 Git source verification
- All version bumps must check upstream signed tags (`git tag -v vX.Y.Z`) when the project signs (cryptography does, FastAPI doesn't, Rust crates rarely)
- Document the trust anchors in `docs/upstream-trust.md`

### 4.5 Trivy DB
- DB itself is downloaded over HTTPS - currently no signature check
- Action: switch to `--db-repository ghcr.io/aquasecurity/trivy-db` + `--cache-dir /trivy-cache` and verify the cache is populated from a cosign-verified pull (Trivy DB is published as OCI artifact since 0.50)

---

## Consumer-side verification (1 day)

### 5.1 cmdb deploy gate
`~/dev/tools/cmdb/scripts/deploy.sh` and Portainer pull path (`api/app/utils/portainer.py`):

```bash
cosign verify \
  --key https://example.com/cosign.pub \
  ghcr.io/jr-shdw/rhorizon-api@sha256:DIGEST \
  || { echo "Signature invalide - abort"; exit 1; }
```

Same for `cosign verify-attestation --type slsaprovenance` to enforce SLSA chain.

### 5.2 Portainer policy
- If using Portainer Business: turn on "image-signature-required"
- Otherwise: wrapper script that calls `cosign verify` before invoking `portainer pull` via API

---

## Effort + ordering

| Phase | Effort | Blocks next? | Value |
|---|---|---|---|
| 0 - Pinning hard | 1-2d | yes | Foundational |
| 1 - Reproducibility | 3-5d | yes | High |
| 2 - Sign release artifacts | 2-3d | no | High |
| 3 - Sign Docker image | 1-2d | no (parallel with 2) | Critical |
| 4 - Upstream verification | 1-2d | no | High |
| 5 - Consumer gate | 1d | no | Critical for cmdb |

**Total ~10-15 days**, splittable across weeks.

---

## Quick wins (each <1h)

- Digest pinning on the 4 most critical images (api builder, frontend, postgres, trivy)
- Generate cosign keypair, store in rhorizon vault, set Woodpecker secrets, activate existing `sbom-and-sign` step
- Add `--locked` to every `cargo build`/`cargo test`
- Pre-verify `aquasec/trivy:0.71.2` and `gcr.io/projectsigstore/cosign:v3.0.6` signatures in CI
