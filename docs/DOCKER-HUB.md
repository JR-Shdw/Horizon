# Resurgamus Horizon - Docker Hub

This file is the **public description** for the Docker Hub
repositories. Paste it (or sync via `docker-pushrm`) into
`hub.docker.com/r/<org>/rhorizon-{api,frontend,agent}`.

---

## What this is

**Resurgamus Horizon (`rhorizon`)** is a self-hosted secrets vault. It keeps your
passwords, API keys, TLS certificates, database credentials and SSH
keys encrypted at rest, served by a small HTTP API that integrates
with everything that speaks HTTP - Ansible, CI/CD, Kubernetes,
shell scripts, AI agents (MCP).

If you already let Cursor / Cline / Claude Desktop / opencode read your
clients' credentials from the chat or a `.env` file, **rhorizon
keeps that workflow but adds a per-secret access policy and a
chained audit log** - see `QUICKSTART-AI.md` in the
[source repo](https://github.com/JR-Shdw/Horizon).

| Feature | What it gives you |
|---|---|
| **Self-hosted** | Runs on your laptop, your VM, your VPS. No SaaS. No vendor lock-in. AGPL-3.0. |
| **Sealed by default** | After every reboot the vault holds nothing in RAM. An operator (or a Shamir quorum) brings it back online. |
| **Audit-chained** | Every state change is written to a tamper-evident chain, each entry signing the previous (Ed25519 by default, HMAC-SHA512 fallback). Secret reads are tamper-evident too: they go to a fast unsigned access log whose rows are Merkle-hashed into signed checkpoints in that same chain. |
| **AI-ready** | First-class MCP server (Cursor / Cline / Claude Desktop / opencode / OpenAI Responses / Anthropic Messages). Per-secret whitelist, fail-closed by default. |
| **Multi-arch** | `linux/amd64` + `linux/arm64`. Native on Mac M1/M2 and ARM servers. |

---

## Images on this Hub

| Image | Role |
|---|---|
| [`<org>/rhorizon-api`](https://hub.docker.com/r/<org>/rhorizon-api) | The vault - FastAPI + Rust crypto extension + PostgreSQL client. |
| [`<org>/rhorizon-frontend`](https://hub.docker.com/r/<org>/rhorizon-frontend) | The web UI - Nginx + small SPA. Optional but useful for unseal / 2FA setup. |
| [`<org>/rhorizon-agent`](https://hub.docker.com/r/<org>/rhorizon-agent) | Three Rust binaries: `rh-fetch` (init container, write secrets to a tmpfs file), `rh-inject` (resolve `rh://` env vars then exec), `rh-watch` (sidecar for runtime rotation). |

All images are **multi-arch** (amd64 + arm64). All images are
**signed with cosign** - verify with the public key from the source
repo:

```bash
COSIGN_PUB=https://raw.githubusercontent.com/JR-Shdw/Horizon/main/cosign.pub
cosign verify --key "$COSIGN_PUB" docker.io/<org>/rhorizon-api:latest
```

Each image also ships a **CycloneDX SBOM** and a **SLSA v1.0
provenance attestation** as cosign attestations. Inspect with:

```bash
cosign download attestation docker.io/<org>/rhorizon-api:latest
```

---

## Quickstart - laptop

For a non-technical user who wants their AI assistant to read selected
secrets through rhorizon, **one command** (Linux / macOS / WSL2):

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh | bash
```

Builds the stack, generates a master password, mints a dedicated
MCP token with read-only access on the `mcp` namespace, prints a
ready-to-paste JSON snippet for your client's MCP config (for
example `claude_desktop_config.json`).

Native install (no Docker, Linux + WSL2 only):

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop-native.sh | bash
```

Full walkthrough: [`docs/QUICKSTART-AI.md`](https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docs/QUICKSTART-AI.md)
(EN) / [`docs/fr/QUICKSTART-AI.md`](https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docs/fr/QUICKSTART-AI.md)
(FR).

---

## Production deploy (single host)

```yaml
# docker-compose.yml - minimal example
services:
  postgres:
    image: docker.io/library/postgres:18-trixie
    environment:
      POSTGRES_USER: rhorizon
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: rhorizon
    volumes:
      - pg_data:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U rhorizon"]

  api:
    image: docker.io/<org>/rhorizon-api:latest
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      RH_DATABASE_URL: postgresql+asyncpg://rhorizon:${POSTGRES_PASSWORD}@postgres:5432/rhorizon
      RH_BIND: 0.0.0.0
      RH_API_PORT: 8200
      RH_WORKERS: 5
    ports:
      - "127.0.0.1:8200:8200"
    read_only: true
    cap_drop: [ALL]
    tmpfs:
      - /tmp:size=16m,noexec,nosuid

  frontend:
    image: docker.io/<org>/rhorizon-frontend:latest
    ports:
      - "127.0.0.1:8080:80"
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]

volumes:
  pg_data:
```

Full hardening reference (read-only filesystems, cap_drop, tmpfs,
no-new-privileges, pids_limit, memory limits, multi-worker
cluster) in [`docker-compose.yml`](https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docker-compose.yml)
of the source repo.

---

## Network model

> **Never expose rhorizon on the public internet.** A vault that
> holds every secret of your infrastructure must sit behind a VPN
> or a private network. The official deployment guide assumes
> VPN or equivalent - see [`DEPLOYMENT.md`](https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docs/DEPLOYMENT.md).

Two access paths:

| Path | Auth | Network |
|---|---|---|
| Web UI (operators) | Master password + 2FA (WebAuthn / YubiKey HMAC / TOTP) | VPN -> Nginx TLS -> frontend |
| API (machines) | Bearer token HMAC-SHA512 (`rh_xxx`) | VPN / private LAN / Docker internal |

---

## Source, license, support

- **Canonical source**: `github.com/JR-Shdw/Horizon` (private but
  internet-reachable Forgejo of the operator).
- **Public mirror**: [`github.com/JR-Shdw/Horizon`](https://github.com/JR-Shdw/Horizon) (synced from
  Forgejo - same commits, same signatures).
- **License**: AGPL-3.0-or-later. Closed-source rehosting requires
  a commercial license - see `LICENSE-COMMERCIAL.md`.
- **Issues / questions**: please open them on the canonical
  Forgejo. The GitHub mirror does not accept PRs.

---

## Security report

Vulnerabilities: see [`SECURITY.md`](https://raw.githubusercontent.com/JR-Shdw/Horizon/main/SECURITY.md)
for the disclosure process. Public PoCs against released versions
are coordinated via the channel listed there.
