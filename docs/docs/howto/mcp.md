# MCP - give an LLM scoped vault access

rhorizon ships an **MCP server** (`rhorizon-mcp`) that exposes a
curated, read-only subset of vault operations to LLM clients - Cursor,
Cline, Continue, opencode, Claude Desktop, Claude Code, or any cloud agent that
speaks Model Context Protocol. With the stdio transport, the MCP server reads
the token from its environment or token file and does not include it in tool
schemas or responses. The local service account and host root remain inside
the trust boundary.

The MCP server is the **trust boundary**: it holds the token, consults
a policy whitelist on every call, and **fails closed** (no
`policy.toml` -> every request denied).

> **Who is this page for?** MCP is an *agent* protocol - the LLM is the
> caller, not the operator. This page is for the **operator** wiring it up
> (token, policy, client config). For a guided local setup, see
> `QUICKSTART-AI.md` and `AI-PROMPTS.md`.
> Operators manage secrets through the Web UI and the `rhorizon` CLI, not MCP.

## Tool catalog (read-only)

| Tool | Returns |
|---|---|
| `vault_status` | sealed / unsealed + 2FA mode |
| `vault_whoami` | scopes + namespaces of the current token |
| `vault_list_namespaces` | namespaces visible to the vault token |
| `vault_list_secrets` | secret names in a namespace (never values) |
| `vault_get_secret` | value of a whitelisted secret |
| `vault_audit_tail` | optional audit lines; requires `audit:r` on the vault token |
| `vault_cluster_health` | optional cluster + PostgreSQL HA health; requires `cluster:r` on the vault token |

No write tool, no seal/unseal, no token management. If you need an
agent to do more, write a new MCP tool that wraps your own policy -
never expose a raw endpoint.

## Transport: the server is stdio only

```bash
rhorizon-mcp-server                                 # stdio - the only mode
```

`--transport http` is **rejected**. The server's in-process HTTP transport was
removed: one server, one token, one local agent.

If you need several agents, per-agent identity, or an HTTP entry point, run
the **hub** in daemon mode instead:

| Setup | Component | Token model |
|---|---|---|
| One local agent (Claude Desktop, Cursor, Cline) | `rhorizon-mcp-server`, stdio | The server process holds one long-lived scoped token; tool payloads never contain it. `policy.toml` allow-list applies |
| Several agents / HTTP clients | `rhorizon-mcp-hub --daemon` | Each request carries the **agent's own** `Authorization: Bearer rh_...`, validated via `/tokens/whoami`. No secret-level allow-list - the token's scopes and `namespaces` claim are the boundary |

The hub daemon listens on loopback (`127.0.0.1:9110`) over **plain HTTP**; a
non-loopback bind is refused unless `RHORIZON_HUB_PUBLIC_BIND_OK=1`, and then
TLS via a reverse proxy is your responsibility. Its leg to the vault runs
through the Rust sidecar over HTTP/2 + post-quantum TLS 1.3. See
[MCP reference](https://github.com/JR-Shdw/Horizon/blob/main/docs/MCP.md).

## Policy - fail-closed whitelist (stdio server only)

`policy.toml` is the allow-list the **`rhorizon-mcp-server`** consults on every
call. Absent, empty or invalid -> `deny_all`. Scope it to a dedicated
namespace, never `prod`:

```toml
# ~/.config/rhorizon-mcp/policy.toml
[secrets]
whitelist = ["mcp/openai-key"]    # explicit secret allow-list

[namespaces]
allow = ["mcp"]                   # optional: all secrets in this namespace

[tools]
allow = ["vault_status", "vault_whoami",
         "vault_list_secrets", "vault_get_secret"]
```

## Recommended setup

Mint a token scoped to MCP only - `secrets:r` on a dedicated `mcp`
namespace, never the operator token:

```bash
curl -X POST http://127.0.0.1:8200/api/v1/vault/tokens/ \
  -H "Authorization: Bearer $ADMIN" \
  -d '{"name": "mcp-agent",
       "permissions": {"secrets": "r", "namespaces": ["mcp"]}}'
```

Point the client at the server (stdio config, same shape for Claude Desktop, Cursor, Cline):

```json
{
  "mcpServers": {
    "rhorizon": {
      "command": "rhorizon-mcp-server",
      "env": { "RH_VAULT_URL": "http://127.0.0.1:8200",
               "RH_TOKEN_FILE": "/path/to/mcp-token" }
    }
  }
}
```

## Federation (many MCP servers, one endpoint)

`rhorizon-mcp-hub` presents N upstream MCP servers behind a single
HTTP endpoint, prefixing tools `<upstream>_<tool>`. With auth
pass-through, the agent's own bearer reaches the upstream rhorizon-mcp
and the audit chain attributes each read to the real agent token, not
a shared service token.

> **Rogue upstream warning** - the hub forwards tool results verbatim.
> A malicious upstream can prompt-inject the agent through returned
> content. Only federate upstreams you audit and control.

The repository's `docs/MCP.md` is the exhaustive reference (bearer
middleware internals, per-agent identity, namespace conventions).
