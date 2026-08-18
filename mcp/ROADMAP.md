<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# rhorizon-mcp -- status and roadmap

## Built (verified on node-5, 2026-07-10)

- `server/` -- zero-dep stdio MCP server (`rhorizon-mcp-server` 1.0.0b1). Vault
  client over QR-TLS (X25519MLKEM768) when `RH_VAULT_URL` is HTTPS on OpenSSL
  3.5+; `RH_VAULT_PQ=prefer|require`. Read-only tools. `pytest` 9/9. Relocated
  from `rhorizon-agent/mcp` (untracked working tree).
- `connector/` -- `setup.sh` (mints scoped `secrets:r` token, writes fail-closed
  policy, registers local client CLIs / prints opencode block) + client configs +
  `policy.toml.example`.
- `hub/` -- zero-dep stdio federation hub (`rhorizon-mcp-hub` 0.1.0). Spawns N
  local stdio backends, prefixes tools `<backend>_<tool>`, routes `tools/call`,
  per-backend policy (`enabled`, `destructive_requires_confirm` gated by a
  `_confirm` arg), tamper-evident SHA-256 hash-chain audit (`--verify-audit`,
  `--harden-audit`), append-only + 0600 hardening (Linux `chattr +a`, *BSD
  `chflags`), warn-on-change on startup. Installed at
  `~/.config/rhorizon-mcp-hub/hub.toml`; federates 9/11 opencode backends -> 75
  tools.

## Do-next (cheap, no new design)

- `RH_VAULT_CAFILE` for the vault `:8443` private cert -- server refuses a
  self-signed cert by design, so QR-TLS reads need the CA. Loopback
  `http://127.0.0.1:8200` works without it.
- Wire opencode -> hub (replace the 11 entries with one `hub` entry).
- Backends `customer_engagement`, `cve_radio`: binaries absent on node-5.
- PQ "require" is enforced server-side only (nginx `ssl_conf_command Groups
  X25519MLKEM768`). CPython cannot pin or read the negotiated group.

## Roadmap (deferred -- additive, reuses current hub code, no rework)

### Per-agent transport / shared daemon

> **STATUS: shipped**, largely as designed below. `rhorizon-mcp-hub --daemon`
> serves a loopback listener with per-agent bearer identity validated via
> `/tokens/whoami` (SHA-256-keyed cache + negative cache + per-IP rate limit),
> reaches the vault through the `rh-mcp-gateway` Rust sidecar over a unix
> socket, and attributes each call to the calling agent in the server-side
> chained MCP audit. See `docs/MCP.md` section 7.
>
> Two deltas from the sketch below: the agent-facing transport is **loopback
> HTTP (Streamable MCP)** rather than `AF_UNIX` + a stdio shim, so no shim
> component exists; and the sidecar, not the hub, holds the PQ-TLS leg to the
> vault. The identity design landed unchanged - vault-issued per-agent token,
> validated server-side, no local token store.
>
> Still true: stdio remains the default, and per-user stdio hubs remain the
> right answer for single-user hosts. The daemon is opt-in.

Components when built:
- daemon: shared per-host process, `AF_UNIX` socket, per-user socket perms.
- shim: stdio<->socket bridge per agent (MCP clients speak stdio/HTTP only).
- identity: vault-issued per-agent token, validated via `/tokens/whoami`
  (SHA-256 cache + negative cache), used as the vault token so the vault
  enforces per-agent scope/namespace. No local token store.
- locator: token name `rh-<app>-<user>-<host>` = stable identity; `pid` +
  session nonce = audit metadata, not identity.
- ACL: `[agents.<name>]` allow/deny over backends/tools; fine-tune layer under
  the vault scope, never the boundary.
- registration: server-side control-MCP registry (automation) + CLI + local ACL
  override. Blocked on the control-MCP interface.

### Audit anchor + self-fence
Push audit head-hash off-host (vault or remote append-only sink); off-host
verifier walks the chain; on a break, revoke that host's tokens at the vault.
Revocation = containment forward, not undo.

### Multi-host
Deploy to node-6; verify on FreeBSD/OpenBSD/NetBSD. OpenBSD links LibreSSL, which
may not negotiate ML-KEM -> PQ degrades to classical there (verify per host).

## Security posture (decided)

- Authoritative authz = vault: per-host scoped tokens + server-side per-agent
  bearer validation. Hub ACL is convenience, never the boundary.
- IP-ACL host control is a no-op under rootless-podman NAT (source IP masked as
  the gateway). Set podman networking / `proxy_trusted_ips`, or do not count it.
- Non-vault backends (docker, proxmox) are single-guarded by the hub ACL; a
  malicious backend running as the hub user reads everything. Run each backend
  as its own OS user; keep the vault token exclusive to the rhorizon backend;
  disable/confirm-gate dangerous backends by default.
- Tamper-evidence is real only with append-only set (Linux `chattr +a` as root,
  *BSD `chflags sappnd`) AND an off-host anchor. The chain alone is detection
  relative to a trusted head.
