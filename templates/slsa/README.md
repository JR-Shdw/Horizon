# SLSA supply-chain base

Vendorable hash-locked dependency workflow for any Python project. Treats PyPI
as untrusted: nothing installs unless its exact artifact matches a pinned
`sha256`. Two files, drop into the project root.

## Vendor it

```sh
cp ~/dev/sextant/templates/slsa/slsa-lock.sh ~/dev/sextant/templates/slsa/slsa.mk <project>/
chmod +x <project>/slsa-lock.sh
# in <project>/Makefile:
include slsa.mk
```

## Convention

Edit a `requirements.in` (and/or `requirements-dev.in`, `tools/requirements.in`,
...). Each `*requirements*.in` compiles to a hash-locked `*.txt` sibling.

## Workflow

```sh
make slsa-update          # after bumping a version: rehash (--generate-hashes) + pip-audit
# review the *.txt diff, commit only if the audit was green
```

Then make every install hash-verified:

```dockerfile
RUN pip install --no-cache-dir "pip==26.1.2" && \
    pip install --no-cache-dir --require-hashes -r requirements.txt
```
...in Dockerfiles, CI, and local test gates.

## What it enforces

- **sha256 per artifact** (incl. transitive) - tampered / account-takeover
  releases are rejected by `--require-hashes`.
- **Pinned CVE-fixed pip** (`SLSA_PIP`, default `26.1.2`) - the base image's pip
  itself is often vulnerable (install-time CVEs).
- **`pip-audit` gate** - a bumped version that pulls a known-vulnerable package
  fails the build, so it never gets locked in.

Also exclude the lockfiles' `sha256` strings from `detect-secrets` (CI +
Makefile + pre-commit) - they're hashes, not secrets.

## Reference implementation

`~/dev/tools/cmdb` - see its `SUPPLY_CHAIN.md`: hash-locked deps,
`--require-hashes` in api + tools Dockerfiles and Woodpecker CI, `pip-audit` on
the lock, detect-secrets lock excludes, and `make deps-update`.

## Detect before implement

Before locking, audit the resolved set (`pip-audit`) and scan the host for
startup-hook IOCs (executable-code `.pth`, rogue `sitecustomize`/`usercustomize`).
Harden only once detection is clean.
