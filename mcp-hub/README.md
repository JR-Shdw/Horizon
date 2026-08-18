<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2024-2026 shdw -->

# rhorizon-mcp-hub

Zero-dependency **per-host MCP federation hub**. Fronts N local stdio MCP
servers behind one endpoint: an agent connects once and sees the union of the
backends' tools, prefixed `<backend>_<tool>`. The hub spawns each enabled
backend as a subprocess, routes `tools/call`, enforces a per-host policy, and
appends every call to a tamper-evident audit log. Default transport is **stdio**
(one agent); an optional **`--daemon`** mode serves many agents with per-agent
identity (see below).

Pure Python standard library -- no third-party dependencies. Internal infra
tooling; the vault-facing MCP server it fronts is `../mcp/`.

## Install

```bash
pipx install .          # puts rhorizon-mcp-hub on PATH (zero runtime deps)
rhorizon-mcp-hub --version
```

## Configure

Copy `hub.toml.example` to `~/.config/rhorizon-mcp-hub/hub.toml`. Each
`[backends.<name>]` becomes the tool prefix `<name>_`; `command` is the stdio
server you would otherwise wire into the client directly.

```toml
[hub]
name = "node-5-hub"
audit_log = "~/.local/state/rhorizon-mcp-hub/calls.jsonl"

[backends.rhorizon]
enabled = true
command = ["/path/to/mcp/.venv/bin/rhorizon-mcp-server"]
[backends.rhorizon.env]
RH_VAULT_URL  = "http://127.0.0.1:8200"
RH_TOKEN_FILE = "/path/to/token"

[backends.docker]
enabled = true
destructive_requires_confirm = true     # rm/kill/prune need "_confirm": true
command = ["/path/to/docker-mcp-server"]
```

Point each agent at `rhorizon-mcp-hub` instead of the
N individual servers.

## Policy (per host)

- `enabled` -- expose this backend on this host or not.
- `destructive_requires_confirm` -- a call is blocked unless it carries
  `"_confirm": true`. Ergonomic guard, not a security boundary.

Security boundaries live at the vault (per-host scoped tokens, per-agent bearer
validation). The hub ACL is convenience + audit. See `../mcp/ROADMAP.md`.

## Daemon mode (optional): multi-agent + per-agent identity

By default the hub is stdio (one agent). `rhorizon-mcp-hub --daemon` instead
serves **many agents** over a loopback HTTP endpoint (Streamable MCP), each
carrying its **own** vault bearer, and adds server-side per-agent auditing.
Everything below is opt-in; the stdio path is unchanged.

```
agents --HTTP+Bearer--> hub daemon (127.0.0.1) --unix socket--> rh-mcp-gateway --HTTP/2 + PQ TLS 1.3--> vault
                         per-agent identity        (sidecar)     X25519MLKEM768
```

- **Per-agent identity.** Each agent authenticates with its own vault token; the
  hub resolves it to `{id, name}` via `/tokens/whoami` (cached, rate-limited) and
  attributes every call to that agent. The UUID is the token's own id.
- **PQ-TLS sidecar.** The hub forwards each agent bearer for authentication
  but does not keep a separate long-lived upstream vault token. The vault leg (auth +
  the `rhorizon` vault backend + audit emit) goes through the **`rh-mcp-gateway`**
  Rust sidecar (`agent/rust`), the only component speaking HTTP/2 + PQ TLS 1.3.
  Run it first; point `[hub].sidecar_socket` at its socket.
- **Server-side audit chain.** Every tool call (allowed / policy_denied / error)
  is POSTed to the vault's chained `/audit/mcp`, visible in the **Jets → MCP** tab
  and tamper-evident (`/audit/mcp/verify`). The local hash-chained JSONL stays as
  an offline backstop.
- **Vault backend via sidecar.** Set `[backends.rhorizon] mode = "sidecar"` so the
  hub reaches the vault with **each agent's** bearer (per-agent identity in the
  vault's own audit too), instead of the fixed-token stdio child.

Config keys: `[hub] bind`, `port`, `sidecar_socket`, `emit_server_audit`. Bind is
loopback-only unless `RHORIZON_HUB_PUBLIC_BIND_OK=1`. See `hub.toml.example`.

## Audit (tamper-evident)

Every call is a SHA-256 hash-chained record. Any edit/delete breaks the chain.

```bash
rhorizon-mcp-hub --verify-audit <path>    # nonzero exit on tamper
rhorizon-mcp-hub --harden-audit <path>    # 0600 + append-only per OS
```

For tamper-evidence against a compromised hub user, deploy the log append-only
(Linux `chattr +a` as root, *BSD `chflags sappnd`) and anchor the head-hash
off-host. Startup verifies the prior chain and warns loudly on a break.

## Portability

Pure stdlib (`socket`, `subprocess`, `select`, `tomllib`, `hashlib`): runs on
Linux + FreeBSD/OpenBSD/NetBSD, x86-64 and ARM64, no compiled artifacts.
