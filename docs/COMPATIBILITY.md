# Compatibility matrix

What rhorizon runs on and integrates with. Status legend:

- **Tested**: exercised in CI or on a real VM/host, part of the support surface.
- **Supported**: built and expected to work; not in the automated test loop.
- **Experimental**: usable, rough edges, no guarantee.
- **Planned**: not yet, tracked.

Anything not listed is neither blocked nor promised, open an issue.

How each **Tested** claim is proven before a release: [SHIP-VALIDATION.md](SHIP-VALIDATION.md).
The per-OS component checklist used to reassess support lives in
[`os-validation/`](os-validation/).

## Operating systems

| OS | Status | Notes |
|---|---|---|
| Debian / Ubuntu | Tested | Debian 13 is the current stable validation lane; Debian 12 kept as oldstable reference. `tools/install-debian.sh`, `install-ubuntu.sh`; CI runs on Debian |
| Arch Linux | Tested | `tools/install-arch.sh` |
| Rocky / RHEL family | Tested | native install unseals under SELinux **enforcing** with the shipped `tools/selinux/rhorizon.te` confined policy, 0 AVC (Rocky 10.2, 2026-07-12); also Rocky 9 full suite green (2026-06-19); `tools/install-rocky.sh` |
| openSUSE | Tested | full suite green in an openSUSE Leap 15.6 VM (AppArmor, 2026-06-19); Leap 16.0 is the current revalidation lane. `tools/install-opensuse.sh` |
| FreeBSD 14.x | Tested | full suite green (1753 passed) on a 14.x VM after the `memorylocked=unlimited` login-class fix in `install-freebsd.sh` (the vault mlocks key material); `tools/install-freebsd.sh` |
| OpenBSD 7.x | Tested | **1753 passed** on a 7.8 VM, HA cluster mTLS included. Base LibreSSL's CPython `ssl` can't load the Ed25519 cluster certs, so `install-openbsd.sh` builds CPython 3.12 from source against the OpenSSL port (eopenssl36), Ed25519 kept. `tools/install-openbsd.sh` |
| NetBSD 10.x | Tested | full suite green on a 10.1 VM (anita-built golden); `tools/install-netbsd.sh` |
| Windows (WSL2) | Supported | via the Linux container or native path under WSL2 |
| macOS (Apple silicon / Intel) | Skeleton (untested) | `tools/install-macos.sh --mode user`; Homebrew deps, Apple Library paths, LaunchAgent |
| aarch64 Linux stack | Validated | Raspberry Pi 4 hardware; full stack: PostgreSQL 18 + API + Rust crypto + frontend |
| arm64 agent (rh-fetch/inject/watch) | Verified (emulated) | Builds for arm64 (incl. under QEMU) via aws-lc-sys pre-generated bindings (`aws-lc-rs` without `bindgen` -- no libclang panic). Post-quantum TLS (X25519MLKEM768) preserved, wire-verified by `tools/pq-verify.sh` (OpenSSL 3.5 + aws-lc-rs both negotiate it). Built multi-arch in CI (`build.yml`). |

## Service / init management

| Manager | Status | Notes |
|---|---|---|
| systemd | Tested | native unit (`rhorizon-api`) on Linux |
| OpenRC / BSD `rc.d` | Tested | `rc.d` scripts for FreeBSD/OpenBSD |
| nohup fallback | Supported | when no service manager is present (laptop/native quickstart) |

## Containers and orchestration

| Platform | Status | Notes |
|---|---|---|
| Docker / Docker Compose | Tested | primary deployment; hardened compose shipped |
| Podman (rootless) | Tested | runs rootless; raise `RLIMIT_MEMLOCK` for mlock |
| Kubernetes | Tested | Helm chart (`helm/rhorizon`): api + frontend + Postgres deploy, unseal, and the multi-worker cluster form on a real cluster. `make k8s-e2e` (k3d) gates it; also run against external Patroni |
| k3s | Tested | same Helm chart, validated on k3s (the `make k8s-e2e` tier spins k3d/k3s) |

## Datastore (the vault's own storage)

| Backend | Status | Notes |
|---|---|---|
| PostgreSQL 18 | Tested | the only supported store, and the only major that can negotiate the post-quantum hybrid KEM (X25519MLKEM768) on the API-to-database link - `ssl_groups` is a PG18+ GUC. On an older major the compose still starts but that link falls back to classical key exchange. |
| Database HA: Patroni | Tested | reference Linux/Kubernetes topology: PostgreSQL 18 + Patroni + etcd + HAProxy + keepalived VIP, multi-node |
| Database HA: `rhorizon-pgha` | Supported | BSD-native peer-quorum provider for FreeBSD/OpenBSD/NetBSD; `/status` integrates with rhorizon's provider-neutral `database_ha` health. The provider has lab evidence, but this repository does not yet run it in the automated release lane; a fenced/stale member currently requires operator rejoin. See the [`pgha` design and evidence](PGHA.md). |

## Operator authentication

| Mechanism | Status | Notes |
|---|---|---|
| Master password (Argon2id) | Tested | always required |
| TOTP (RFC 6238) | Tested | second factor |
| YubiKey HMAC-SHA1 | Tested | second factor, CLI/automation friendly |
| WebAuthn / FIDO2 | Tested | second factor, browser-native |
| LDAP / AD bind | Tested | live bind-auth against a deployed lldap (node-5, 2026-06-19): real bind -> group mapping (lldap_admin) -> scoped session token; wrong password denied |
| SSO proxy headers | Tested | trusted-IP + `Remote-User` / `Remote-Groups` -> group mapping -> session token, exercised in CI (`test_proxy_auth.py`). Works with Authelia / Authentik / Keycloak |

## Secret delivery (to consuming apps)

| Pattern | Status | Notes |
|---|---|---|
| `rh-fetch` (init container + `*_FILE`) | Tested | binary logic; tmpfs file mode 0400; for apps honoring `*_FILE` |
| `rh-watch` (sidecar, rotation + reload) | Tested | binary logic; atomic swap + optional reload signal |
| `rh-inject` (env vars) | Tested | binary logic; exec wrapper for env-only apps |
| ESO (External Secrets Operator) | Experimental | Go provider in `eso-provider/`, PR-target for upstream external-secrets; PQ-capable by default (Go 1.25, no `CurvePreferences`); not merged, no PQ-handshake test yet |
| MCP (LLM agents) | Tested | read-only tool surface; **fail-closed policy validated** (9 tests, `mcp/tests/test_policy.py`), denies anything not whitelisted, per-call gating in `call_tool`; tools are policy-gated wrappers over the tested vault API |

> **rh-* status caveat.** "Tested" above is the **binary logic** -
> `tests/test_agent.py` plus the live scripts in `eso-provider/test-live/`
> (`b2_rhfetch_real.sh`, `b3_rhwatch_rotation.sh`). End-to-end deployment
> on **Docker / Podman / k3s** is **not yet in the automated loop**
> (SHIP-VALIDATION lane 2, pending).

## Dynamic secrets (generated on demand, leased)

| Backend | Status | Notes |
|---|---|---|
| PostgreSQL 18 | Tested | CREATE/DROP ROLE, leased TTL |
| MySQL / MariaDB | Tested | full lease lifecycle proven on live MariaDB 11 + MySQL 8.x, minted cred logs in and runs a query, then login is denied after revoke (node-5, 2026-06-19) |
| LDAP / lldap | Tested | validated against lldap; LDIF add + RFC 3062 Password-Modify. Other LDAP products are accepted as connected but unvalidated. |
| Redis 6+ ACL | Implemented | isolated module, constrained ACL command lifecycle and unit tests; live target validation is still required before promotion to Tested |
| Apache Cassandra role auth | Implemented | isolated TLS-by-default module and unit tests; live target validation is still required before promotion to Tested |
| Ansible collection | Implemented | separate mint/revoke modules, TLS verification and secret-safe error tests; collection packaging and a live play remain to validate |

## Observability

| Tool | Status | Notes |
|---|---|---|
| Prometheus | Tested | `/metrics` exposition, IP-allow-listed |
| Grafana | Tested | core overview, cluster, and HA-bench dashboards were captured against a live 5-worker instance. The provider-neutral HA/WAL operations dashboard is shipped and structurally validated; its deep Patroni/PostgreSQL/WAL panels require the scrape inputs documented in `docs/dashboards/README.md` and are not covered by the single-instance screenshot claim. |

## Notifications

| Channel | Status | Notes |
|---|---|---|
| Matrix | Tested | native channel |
| Webhook (generic) | Tested | POST JSON to any endpoint; **SSRF-guarded**: rejects loopback/private/link-local/metadata destinations (incl. `127.1` / decimal-IP tricks), verified live; delivery logic unit-tested |
| Email (SMTP) | Tested | real delivery verified to a live SMTP server (mailhog) via the SMTP send path; `smtp_host` is SSRF-guarded (node-5, 2026-06-19) |
