# rhorizon vault connector (any MCP client)

Give an AI agent **read-only, policy-gated** access to your rhorizon vault over
[MCP](https://modelcontextprotocol.io). The `rhorizon-mcp-server` holds the
token, omits it from MCP tool schemas and responses, and filters every call
against `policy.toml`. The account running the server and host root remain
inside the token's trust boundary.

```
[your AI assistant]  --stdio(MCP)-->  rhorizon-mcp-server  --HTTP+token-->  rhorizon vault
                                                                               |
                                                                        policy.toml (fail-closed)
```

## What ships here

| File | Purpose |
|------|---------|
| `setup.sh` | One-shot: mint a read-only token, write the policy, register Claude Code and Codex if available, print the opencode block. |
| `claude.mcp.json` | Claude Code / Desktop config (working; no secret inlined). |
| `codex.config.toml` | Codex `~/.codex/config.toml` block (working; no secret inlined). |
| `opencode.json` | opencode `mcp` block (working; absolute paths). |
| `policy.toml.example` | Fail-closed policy template. |

## Prerequisites

1. **The server** (this directory -- self-contained, **zero third-party
   dependencies**, pure Python stdlib):
   ```bash
   pipx install .               # puts rhorizon-mcp-server on PATH
   ```
   `setup.sh` auto-installs it this way if `pipx` is available. Or set
   `RH_MCP_BIN` to any `rhorizon-mcp-server` binary. See
   `../server/README.md`.
2. **An admin token** with `tokens:rw` over the namespaces you want to expose
   (used *only* by `setup.sh` to mint the scoped read-only token; never stored).

## Quick start

```bash
RH_ADMIN_TOKEN_FILE=~/.config/rhorizon/admin.token \
  ./setup.sh --namespaces mcp,forgejo --vault http://127.0.0.1:8200
```

That will:
- mint a dedicated **`secrets:r`** token scoped to those namespaces →
  `~/.config/rhorizon/mcp.token` (0600),
- write a fail-closed `~/.config/rhorizon-mcp/policy.toml` (read-only tools +
  those namespaces),
- `claude mcp add rhorizon-vault` (user scope) if the `claude` CLI is present,
- `codex mcp add rhorizon-vault` (global config) if the `codex` CLI is present,
- print a ready-to-paste opencode `mcp` block.

Restart your client. The agent then has: `vault_status`, `vault_whoami`,
`vault_list_namespaces`, `vault_list_secrets`, `vault_get_secret`.

## Manual wiring

**Claude Code**: copy `claude.mcp.json` to your project root as `.mcp.json`
(or merge its `mcpServers` into `~/.claude.json`). `${HOME}` is expanded.

**Codex**: run this, or merge `codex.config.toml` into `~/.codex/config.toml`
after replacing placeholders with absolute paths:

```bash
codex mcp add rhorizon-vault \
  --env RH_VAULT_URL=http://127.0.0.1:8200 \
  --env RH_TOKEN_FILE=$HOME/.config/rhorizon/mcp.token \
  --env RH_MCP_POLICY=$HOME/.config/rhorizon-mcp/policy.toml \
  -- "$(command -v rhorizon-mcp-server)"
```

Restart Codex after adding the server so its tools are loaded into the session.

**opencode**: merge `opencode.json`'s `mcp` block into
`~/.config/opencode/opencode.json`, replacing `/home/YOU/...` with absolute
paths (opencode does **not** expand `~`).

Both point at:
- `RH_VAULT_URL` — your vault (`http://127.0.0.1:8200`, or `http://LAN-IP:8200`).
- `RH_TOKEN_FILE` — the 0600 file holding the scoped token.
- `RH_MCP_POLICY` — the policy file.

## Security notes

- **Least privilege**: the connector token is `secrets:r` on named namespaces
  only — no write, no token minting. Even if the MCP process leaks, blast
  radius = reading those namespaces.
- **Fail-closed**: no `policy.toml` → every request denied. Widen deliberately.
- **Audit**: every read is recorded in the rhorizon audit chain with the token
  name as actor.
- **No IP-locking with rootless podman**: a containerized vault sees the
  slirp/pasta gateway (not `127.0.0.1`) as the client source, so an
  `allowed_ips=127.0.0.1` token 403s ("not allowed from this IP"). Either leave
  the token IP-unrestricted (it's already read-only) or lock to the gateway IP.
