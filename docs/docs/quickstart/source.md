# From source

Build the images yourself, run the tests, hack on the code.

## Clone

```bash
git clone https://github.com/JR-Shdw/Horizon.git
cd rhorizon
```

## Run the test suite

The tests need a real PostgreSQL ; the repo ships a `docker-compose.test.yml`
that brings one up on port 5434.

```bash
# Bring up the test PG
docker compose -f docker-compose.test.yml up -d

# Set up the venv
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r api/requirements.txt -r api/requirements-dev.txt

# Run pytest
python -m pytest tests/ --no-header --no-cov -q
```

Expected output : the full suite passes (a couple skips for optional
backends like MySQL). The exact count tracks the codebase - `make test`
is the canonical gate.

## Build images locally

```bash
docker build -t localhost/rhorizon-api:local -f api/Dockerfile .
docker build -t localhost/rhorizon-frontend:local -f frontend/Dockerfile frontend
```

The API Dockerfile is multi-stage : Python builder -> Rust builder
(maturin builds `rhorizon_crypto`) -> minimal runtime. Build takes
~5-8 minutes the first time.

## Run pre-commit

The repo enforces ruff + bandit on every commit. Set up the hooks :

```bash
pip install pre-commit
pre-commit install
```

## VM testing on multiple OSes

`tools/test-vm.sh` brings up a qemu VM (cloud-init) and runs the full
suite inside it. Validated targets :

```bash
tools/test-vm.sh debian      # Debian 12 bookworm
tools/test-vm.sh ubuntu      # Ubuntu 24.04 LTS noble
tools/test-vm.sh rocky       # Rocky Linux 9
tools/test-vm.sh opensuse    # openSUSE Leap 15.6
tools/test-vm.sh arch        # Arch + linux-hardened kernel
tools/test-vm.sh freebsd     # FreeBSD 14.4 (cloud image)
tools/test-vm.sh openbsd     # OpenBSD 7.8 (golden image)
```

OpenBSD requires a one-time golden build via
`tools/openbsd-bootstrap.sh` (~25 min, downloads the install78.iso
+ runs autoinstall via netboot).

For docker-specific validation (postgres / mariadb / n8n
container patterns), see `tools/test-vm-docker.sh`.

## Project layout (high level)

```
api/                  FastAPI + asyncpg + libsodium + Rust bindings
  app/main.py         Lifespan, schema migration, cluster init
  app/vault_state.py  Sealed/unsealed state machine
  app/crypto.py       5-layer cipher stack
  app/auth.py         Token validation, RBAC namespace check
  app/routes/         vault, secrets, tokens, namespaces, audit, ...
  rust/               PyO3 extension : SecureBuffer, WrapKey, Shamir GF(256)

frontend/             Vanilla JS SPA + nginx
  js/views/           Horizon, Eclipse, Quasar, Jets, Cluster, Nebula, ...

agent/                Three Rust binaries (musl static, ~5 MB each)
  rust/src/lib.rs     SecureToken (mlock + zeroize), atomic_write
  rust/src/fetch.rs   Init container : fetch secrets to tmpfs file
  rust/src/inject.rs  Exec wrapper : resolve rh:// env vars then exec
  rust/src/watch.rs   Sidecar : poll + atomic update + reload signal

cli/                  Python typer CLI (unseal, secrets, tokens, audit)
mcp/                  Model Context Protocol server (LLM integration)
helm/rhorizon/        Helm chart (Sprint 1 #2)
tools/                install.sh quickstart, test-vm scripts, ...
docs/                 This documentation site
.woodpecker/          Lint, SAST, pytest, Trivy scans, deploy
schema.sql            Idempotent SQL : tables + indexes + ALTER migrations
```

## Hack on it

The smallest dev loop : edit `api/app/routes/secrets.py`, run
`pytest tests/test_security.py -k "secret"`, repeat.

Start with `api/app/main.py` (lifespan and routing) and
`api/app/routes/vault.py` (seal/unseal lifecycle). The repository map
in `CLAUDE.md` points to the remaining trust boundaries and test suites.
