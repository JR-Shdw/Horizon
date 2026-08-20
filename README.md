<!--
-----------------------------------------------------------------------------
Resurgamus Horizon - (c) 2024-2026 shdw <horizon@resurgamus.com> - AGPL-3.0
Self-hosted secrets vault
Source: https://github.com/JR-Shdw/Horizon
-----------------------------------------------------------------------------
-->

<h1>
  <img src="docs/img/icon.png" alt="" height="40" valign="middle">
  Resurgamus Horizon
</h1>

**Self-hosted secrets vault. Open source. No SaaS, no telemetry, no lock-in.**

Resurgamus Horizon (`rhorizon` for short) keeps your passwords, API
tokens, TLS keys, database credentials and SSH keys encrypted at rest,
behind an HTTP API for Ansible, CI/CD, Kubernetes, scripts, and AI
agents.

## Install in 5 minutes

For a local Docker installation:

```bash
git clone https://github.com/JR-Shdw/Horizon.git rhorizon
cd rhorizon
sh tools/install.sh
```

That picks the container path, brings up a localhost-only stack, and prints the
URL and next step. **TLS is mandatory and set up for you**: the installer
generates a self-signed certificate, so the UI is on `https://127.0.0.1:8443`.
Open it, choose the master password, and perform the first unseal. Store the
one-time root token in a password manager; do not place it in chat, shell
history, or source control.

The installer also prints two lines for your shell profile. The CA file is what
makes the generated certificate trusted by the CLI and the `rh-*` agents --
without it they correctly refuse to connect, and there is no skip-verify switch:

```bash
export RH_ADDR=https://127.0.0.1:8443
export RH_CA_FILE=~/rhorizon/certs/cert.pem
```

> **Do not use the repository's root `docker-compose.yml` for a laptop.** It is
> the operator/VPN stack: it publishes on `10.0.0.1` and `10.0.1.1`, so on a
> host without those addresses Docker refuses to start with *"Couldn't listen on
> requested ports"*. The installer uses
> `tools/docker-compose.quickstart.yml`, which binds `127.0.0.1` only. To drive
> that file directly:
>
> ```bash
> docker compose -f tools/docker-compose.quickstart.yml up -d
> ```

Full walkthrough: [`docs/QUICKSTART.md`](docs/QUICKSTART.md). Native,
Kubernetes, Podman, BSD, and production paths are listed in
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

> **Using Cursor, Cline, Claude Desktop, or opencode with client
> credentials?** The local quickstart moves those credentials out of
> chat and readable `.env` files, then gives the assistant explicitly
> scoped, audited access:
>
> ```bash
> # Container path (Docker - Mac + Windows + Linux) :
> curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh | bash
>
> # Native path (no Docker - Linux + WSL2 only) :
> curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop-native.sh | bash
> ```
>
> Read the script before running it. The setup and its trust boundaries
> are documented in [`docs/QUICKSTART-AI.md`](docs/QUICKSTART-AI.md).

> 🇫🇷 Documentation française : [`docs/fr/README.md`](docs/fr/README.md)

---

## Design goals

- **Self-hostable on a single VM** with Docker Compose. No multi-node cluster as a prerequisite.
- **No SaaS dependency.** No phone-home, no licensed control plane, no third-party API key in the path of your other secrets.
- **Sealed by default.** After every reboot, the vault holds nothing in RAM. An operator (or a quorum of operators, via Shamir Secret Sharing) brings it back online.
- **AGPL-3.0.** Modifications must be published; closed-source rehosting is not allowed. A commercial license exists for cases where AGPL is incompatible.

---

## Features at a glance

Core properties:

- **[Quantum-resistant posture](docs/POST-QUANTUM.md)** - the storage core uses 256-bit symmetric primitives and Shamir sharing, which Shor's algorithm does not break. TLS prefers the hybrid `X25519MLKEM768` KEM where both endpoints support it; verify live negotiation before treating a transport path as resistant to harvest-now-decrypt-later attacks.
- **[Keys zeroized in RAM](docs/docs/concepts/memory-protection.md)** - master and sub-keys live in `mlock`'d Rust buffers and are wiped on drop via `zeroize`. The AES-GCM wrap key never enters the Python heap; sealing clears the in-memory key material.
- **[HA across the application and database layers](docs/HA-CLUSTER.md)** -
  active/active API with per-worker key compartmentalization
  (Shamir-distributed shares + automatic failover), running over a supervised
  PostgreSQL 18 Database HA tier. Patroni is the tested Linux/Kubernetes
  reference; BSD-native
  [`rhorizon-pgha`](docs/PGHA.md)
  is supported and feeds the same provider-neutral health model. The
  application failover path is benchmarked; Grafana dashboards ship for API,
  crypto, cluster RPC, Database HA, WAL guardrails, and failover timing.

Plus the essentials:

- **[Encryption at rest](docs/docs/concepts/crypto.md)** - every secret has its own Data Encryption Key (DEK), wrapped under a master-derived key. A database dump alone is insufficient to decrypt secrets without the master-derived key material.
- **[Sealed-by-default state machine](docs/docs/concepts/seal-unseal.md)** - keys live in RAM only, derived from a master password at unseal time.
- **[2FA on unseal](docs/docs/howto/2fa.md)** - WebAuthn/FIDO2 (browser), YubiKey HMAC-SHA1 (CLI), TOTP (RFC 6238). Mix and match.
- **[Shamir Secret Sharing](docs/SECRETS-AND-TOKENS.md)** - split the master key M-of-N to avoid a single operator point of failure.
- **[HMAC-SHA512 token auth](docs/SECRETS-AND-TOKENS.md)** - O(1) lookup, hashed in DB, immediate revocation. Optional namespace scoping (`{"secrets": "rw", "namespaces": ["prod"]}`).
- **[Ephemeral tokens](docs/SECRETS-AND-TOKENS.md)** - 60s to 24h TTL, scoped, never reusable. Designed for CI runners and one-shot jobs.
- **[Tamper-evident audit](docs/docs/concepts/audit.md)** - each entry signs the previous (Ed25519 by default, HMAC-SHA512 fallback), in DB + daily JSONL files, both verifiable independently. Public-key signing means an auditor can verify the chain without holding a key that could forge it. Secret reads are covered too, via Merkle checkpoints anchored in the same chain.
- **[Hardened containers](docs/DOCKER.md)** - read-only filesystem, `cap_drop ALL`, `no-new-privileges`, tmpfs `noexec/nosuid`, pids/memory limits across all services; the API runs non-root (uid 1500).
- **[Native HTTPS](docs/TLS.md)** - bundled nginx + cert/key mounting. No reverse proxy required (but supported via generic labels).
- **[External auth](docs/docs/howto/ldap-sso.md)** - LDAP/AD bind, SSO via reverse-proxy headers (Authelia / Authentik / Keycloak / oauth2-proxy).
- **[MCP (Model Context Protocol)](docs/MCP.md)** - fail-closed, policy-gated, read-only tool surface for AI assistants and autonomous agents.
- **[Backup & restore](docs/DISASTER-RECOVERY.md)** - full PostgreSQL DR plus age-encrypted logical backups for fresh stacks.
- **[fail2ban-friendly](docs/FAIL2BAN.md)** - every authentication failure is logged in a parsable format.
- **Runs on Linux + BSD, container or native** - Debian/Ubuntu/Arch/Rocky/openSUSE, FreeBSD/OpenBSD/NetBSD; full [compatibility matrix](docs/COMPATIBILITY.md).
- **[Documented security posture](docs/THREAT-MODEL.md)** - MITRE ATT&CK + OWASP ASVS L2 mappings, NIS2 Art. 21 control matrix, SLSA build provenance, reproducible signed releases, and release-gated security tests.

---

## Access model at a glance

A token = a **scope** (what it can do) x an optional **`namespaces`** claim (where). No `namespaces` claim = every namespace.

| `permissions` | Can do | Where |
|---|---|---|
| `{"admin":"rw"}` | everything - secrets, tokens, audit, seal/unseal, 2FA | all namespaces - **super-admin** |
| `{"secrets":"r"}` | read secrets | all namespaces |
| `{"secrets":"rw"}` | read + write secrets | all namespaces |
| `{"secrets":"rw","namespaces":["prod"]}` | read + write secrets | only `prod` |
| `{"secrets":"rw","tokens":"rw","namespaces":["prod"]}` | manage secrets + tokens | only `prod` - namespace sub-admin |

`r` read - `w` write - `rw` both. A `namespaces` claim overrides even `admin`. Full reference: [`docs/docs/reference/permissions.md`](docs/docs/reference/permissions.md).

---

## Install matrix - what you actually get, per OS

Every row below was **measured on that OS**, not inferred from its version:
a full install to first unseal, then the TLS posture read off the wire (ALPN
and the negotiated TLS 1.3 group). Where a row says "no", the cause is what the
packaged nginx or python links, and `--pq-nginx` is the fix.

| Install path | Installs | HTTP/2 | Post-quantum | Notes |
|---|---|---|---|---|
| **Docker / Podman** | yes | yes | yes | Recommended. Nothing extra to do. |
| **Debian 13 (trixie)** | yes | yes | yes | The best native lane: OpenSSL 3.5.6 already has ML-KEM. |
| **FreeBSD 14.4** | yes | yes | with `--pq-nginx` | Base OpenSSL is 3.0; `openssl35` is in pkg. |
| **NetBSD 10.1** | yes | yes | with `--pq-nginx` | Base is 3.0.12; pkgsrc has 3.6.3. Needs a roomy `/` for the Rust builds. |
| **OpenBSD 7.8** | yes | with `--pq-nginx` | yes | Only lane where the packaged nginx is *weaker* than the API, so it is declined by default to keep PQ. |
| **Other Linux** | yes | yes | if libssl >= 3.5 | Arch/Fedora/Tumbleweed yes; Rocky 9 / Debian 12 no. Unmeasured. |
| **macOS (native)** | yes | no | unverified | uvicorn only. Use the container path for HTTP/2. |

`sh tools/install.sh` already gives you every "yes" in that table. The flag
below is only for the rows that say **with `--pq-nginx`**, where the packaged
nginx lacks ML-KEM and has to be built against an OpenSSL that has it:

```bash
sh tools/install-native.sh --mode system --pq-nginx
```

**Post-quantum** (X25519MLKEM768) protects traffic recorded *today* from a
future quantum computer. Opt-in only because it is a source build.

**HTTP/2** is a browser-latency win, not a throughput requirement; 1.1 is not a
degraded mode.

Details and the measurements behind each row: [`docs/TLS.md`](docs/TLS.md).

## Automatic unseal

The vault holds its master key in RAM only, so it comes back **sealed** after
every restart and someone must supply the master password again. By default the
installers leave it sealed and write nothing to disk -- you set the password on
the first unseal.

If a host must come back on its own after a reboot, pass the password at
install time:

```bash
sh tools/install.sh --master-password-file /path/to/passphrase
```

The installer then unseals for you and stores both credentials, one secret per
file:

```
<install-dir>/secrets/master-password   # 0400
<install-dir>/secrets/root-token        # 0400, first unseal only
```

Container installs use `~/rhorizon/secrets/`; native installs use
`<config-dir>/secrets/` (`~/.config/rhorizon/secrets/` in user mode). Re-running
the installer after a reboot or a `--tier` switch reuses that file and reopens
the vault without asking.

Prefer `--master-password-file` over `--master-password`: a value on the command
line is readable in `/proc/<pid>/cmdline` while the installer runs, and lands in
your shell history.

**Understand what you are trading.** Automatic unseal and at-rest protection are
the same fact seen from two sides: the host can reopen the vault unattended
*precisely because* the password is readable on that host. Anyone -- or
anything -- that can read those two files owns the vault. There is no
configuration that gives you both.

### Keeping the credentials away from an AI agent

`0400` means "only the owning user may read this". It stops other unprivileged
users on the box. It does **not** stop anything running *as* that user, and an
AI coding assistant with shell access on your account is exactly that: it
inherits your uid, so `cat ~/rhorizon/secrets/master-password` succeeds. The
mode is not the boundary. The account is.

If you run agents, assistants or automation on the same machine:

- **Run the vault under its own OS account** and keep the secrets directory
  owned by it (`chown rhorizon: ~rhorizon/secrets`, `chmod 700`). An agent under
  your login then cannot read them regardless of file mode. The native installer
  in `--mode system` already runs the service as a dedicated user.
- **Do not leave credentials in a directory an agent is pointed at.** Move them
  into a password manager and delete the files; the vault only needs the
  password at unseal time, not permanently on disk.
- **Do not paste them into a prompt, an issue, or a chat.** Anything sent to a
  hosted model leaves the machine, and may be retained or logged.
- **Give automation a scoped token, never the root token.** Per-service tokens
  with narrow scopes and IP allowlists are revocable; the master password is
  not, short of a rotation.
- If you want unattended restart *and* an agent on the same host, treat the two
  as incompatible on one account and separate them by user.

## Compatibility

| Layer | Tested | Also supported |
|---|---|---|
| OS | Debian/Ubuntu, Arch, FreeBSD, OpenBSD, NetBSD, Rocky/RHEL, openSUSE | Windows (WSL2) |
| Run | Docker / Compose, Podman (rootless), Kubernetes / k3s (Helm), systemd, BSD `rc.d` | Docker Swarm |
| Store | PostgreSQL 18; Database HA with Patroni | BSD Database HA with `rhorizon-pgha` (supported; see the full matrix) |
| Auth | password, TOTP, YubiKey, WebAuthn, LDAP/AD, SSO proxy (Authelia/Authentik/Keycloak) | - |
| Observe | Prometheus | Grafana (dashboards shipped) |

Full matrix with per-row notes: [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

---

## Documentation map

### Get started

- [`docs/QUICKSTART-AI.md`](docs/QUICKSTART-AI.md) - local MCP setup for scoped, audited assistant access
- [`docs/AI-PROMPTS.md`](docs/AI-PROMPTS.md) - reviewed prompts for adding access, revocation, diagnostics, rotation, and backup
- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) - boot the stack and store your first secret in 5 minutes
- [`docs/AI-INSTALL-GUIDE.md`](docs/AI-INSTALL-GUIDE.md) - constrained local-install instructions for an AI assistant
- [`docs/USE-CASES.md`](docs/USE-CASES.md) - Ansible, CI/CD, Kubernetes, AI agents - copy-pasteable patterns

### Deploy

- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) - what rhorizon runs on and integrates with (OS, init, orchestration, auth, secret delivery, observability) with support tiers
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) - local, private/VPN, reverse proxy + SSO, LDAP/AD, clustering, backup, hardening checklist
- [`docs/DOCKER.md`](docs/DOCKER.md) - compose stack anatomy, multi-stage Dockerfile, volumes/networks, override patterns, rootless/Podman
- [`docs/K8S.md`](docs/K8S.md) - agent patterns (rh-fetch / rh-inject / rh-watch / cronjob), NetworkPolicy, RBAC, TLS from vault
- [`docs/HA-CLUSTER.md`](docs/HA-CLUSTER.md) - high availability - application membership, local crypto masters, Database HA, identity, JOIN, auto-promote, and per-node mTLS
- [`docs/HA-PRODUCTION-REFERENCE.md`](docs/HA-PRODUCTION-REFERENCE.md) - the production HA target - one logical HTTP/2 edge, three API nodes, three database members, retry/idempotency rules, worker convergence, WAL/audit guardrails, and release gates
- [`docs/HA-RUNBOOK.md`](docs/HA-RUNBOOK.md) - HA operations - provider-neutral Database HA (Patroni reference / BSD `pgha`), PostgreSQL replication and WAL guardrails, bootstrap, rolling restart, and recovery

### Operate

- [`docs/CLI.md`](docs/CLI.md) - full `rhorizon` command reference (vault / secrets / tokens / audit / master / oneshot) with recipes
- [`docs/TLS.md`](docs/TLS.md) - native HTTPS, certificate sources, deployment contexts
- [`docs/FAIL2BAN.md`](docs/FAIL2BAN.md) - IP-level brute-force protection
- [`docs/docs/howto/observability-alerts.md`](docs/docs/howto/observability-alerts.md) - Prometheus alerting cookbook (critical / serious / capacity) + Matrix routing
- [`docs/ROADMAP.md`](docs/ROADMAP.md) - what's stable, what's coming

### Integrate

- [`docs/SECRETS-AND-TOKENS.md`](docs/SECRETS-AND-TOKENS.md) - secret lifecycle, token scopes, ephemeral / oneshot patterns, master-password rotation modes, rotation grace window
- [`docs/DYNAMIC-SECRETS.md`](docs/DYNAMIC-SECRETS.md) - modular leased credentials (PostgreSQL, MySQL/MariaDB, LDAP, Redis, Cassandra), Ansible, renew / revoke
- [`docs/MCP.md`](docs/MCP.md) - Model Context Protocol server (Cursor / Cline / Claude Desktop / Continue / opencode)
- [`docs/N8N.md`](docs/N8N.md) - secure your n8n workflows : protect `N8N_ENCRYPTION_KEY` + per-secret env injection, with audit trail per credential

### Audit, compliance & supply chain

- [`SECURITY.md`](SECURITY.md) - security policy, vulnerability reporting, frameworks cross-references
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) - full MITRE ATT&CK + OWASP ASVS L2 mapping, explicit limitations
- [`docs/NIS2-COMPLIANCE.md`](docs/NIS2-COMPLIANCE.md) - NIS2 Art. 21 control matrix
- [`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md) - living remediation tracker (current findings + status)
- [`docs/slsa-compliance.md`](docs/slsa-compliance.md) - SLSA build-provenance level mapping
- [`docs/verifying-releases.md`](docs/verifying-releases.md) - [`docs/verifying-images.md`](docs/verifying-images.md) - verify signatures + reproducible builds

### Develop

- [`CONTRIBUTING.md`](CONTRIBUTING.md) - contribution policy (closed for now), bug/CVE reporting, how to collaborate
- [`docs/docs/concepts/architecture.md`](docs/docs/concepts/architecture.md) - architecture and repository reference

---

## Project status

**Beta.** Listed features are implemented and exercised by the Python
and Rust test suites; `make test` is the canonical local gate.
The API surface is stable; breaking changes will be announced in the
CHANGELOG.

---

## Stack (one line)

FastAPI on uvicorn (`uvloop`, `httptools`) - SQLAlchemy async over `asyncpg` -
PostgreSQL 18 - PyNaCl (libsodium) - `cryptography` (pyca) - `fido2` (Yubico) -
`pyotp` - `bonsai` (LDAP) - `pyrage` (age) - `prometheus_client` - Rust
extension via PyO3 (`aes-gcm`, `curve25519-dalek`, `blake2`, `crypto_box`,
`crypto_secretbox`, `memsec`, `zeroize`) - a PyO3-free custody core shared with
the standalone Rust custodian daemon - Vanilla JS UI - nginx (Alpine).

Why these and not others: see [`SECURITY.md`](SECURITY.md#software--primitive-choices).

---

## Support the project

Resurgamus Horizon is AGPL-3.0 and free for any self-hosted use. The
project sustains itself through three channels, listed in the order
most users encounter them:

- **Use it for free.** No registration, no telemetry, no upsell. The
  full feature set is in this repository.
- **Commercial license** ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md))
  for organisations that need closed-source redistribution, want to
  rebrand it as part of their own SaaS offer, or otherwise cannot
  accept the AGPL's source-availability requirements.
- **Paid services** - production deployment (multi-VM / Swarm / K8s with the
  Patroni reference topology, or BSD Database HA with `pgha` where
  appropriate), security audits, training, and incident retainers. Contact the
  maintainers for current packages.
- **Sponsorship** - see [`.github/FUNDING.yml`](.github/FUNDING.yml).
  For individuals and orgs who want to fund ongoing maintenance
  without a contractual engagement.

---

## License

> **License & AI policy**
>
> - Licensed under **AGPL-3.0-or-later** ([LICENSE](LICENSE)). Source-available; modifications must remain AGPL.
> - **Closed-source relicensing prohibited.** A commercial license is available - see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
> - **"Resurgamus Horizon" is a reserved project name.** The AGPL license covers the source code only, not the name or logo - it grants no trademark rights. Forks, derivatives, and commercial services built on this code may not use "Resurgamus Horizon" (or a confusingly similar name) to identify themselves without permission from Resurgamus.
