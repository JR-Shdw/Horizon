---
name: horizon
description: Get tokens, passwords, keys and other credentials through the Horizon vault using its MCP tools. Use before searching for a secret, before asking the user for one, whenever a task needs a credential, and when a vault call returns 403 or 404.
---

# Horizon: credentials come from the vault

Credentials live in Horizon. Start with the MCP tools instead of searching local
files, shell history or environment files. Token files on disk are usually vault
tokens, not service credentials.

Some clients prefix tool names with the server name, for example
`rhorizon_vault_get_secret`.

## Steps

1. Call `vault_status` to confirm the vault is unsealed.
2. Call `vault_whoami` to learn which namespaces this token can read.
3. Call `vault_list_secrets` to find the name. It returns names only.
4. Use the credential at the safest tier available.

| Choice | Tool | The value ends up in |
|---|---|---|
| Best | `vault_call_api` | nowhere the agent can read |
| Workloads | `rh-fetch`, `rh-inject`, `rh-watch` | tmpfs or the process environment |
| Last | `vault_get_secret` | the conversation history |

```
vault_call_api(credential="github-prod", method="GET", path="/user/repos")
```

Prefer project scripts that read the vault themselves. After `vault_get_secret`,
keep the value out of replies, command lines, logs and files.

## Reading refusals

| Result | Meaning | Next step |
|---|---|---|
| `Secret 'x' not found` | The name does not exist | Check the name, or ask for it to be created |
| `Access denied for namespace` | This token cannot read that namespace | Ask the operator for access |
| Policy denied | The MCP policy does not list it | Ask the operator to add it to `policy.toml` |
| `No proxy binding for credential` | No `[proxy.x]` table exists | Ask the operator to add the binding |
| `sealed: true` | The vault is sealed | Ask the operator to unseal it |

## When blocked

Stop after one refusal. Use only the token and path you were given. Name the exact
secret, namespace and vault needed, give the one action that unblocks it, then
continue any work that does not depend on it.
