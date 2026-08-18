# Permissions & scopes

A token = **scope** (what it can do) x optional **`namespaces`** (where). **No `namespaces` claim = every namespace.**

| `permissions` | Can do | Where |
|---|---|---|
| `{"admin":"rw"}` | everything - secrets, tokens, audit, seal/unseal, 2FA | **all namespaces - super-admin** |
| `{"secrets":"r"}` | read secrets | all namespaces |
| `{"secrets":"rw"}` | read + write secrets | all namespaces |
| `{"secrets":"rw","namespaces":["prod"]}` | read + write secrets | only `prod` |
| `{"secrets":"rw","tokens":"rw","namespaces":["prod"]}` | manage secrets + tokens | only `prod` - namespace sub-admin |

`r` read - `w` write - `rw` both. A `namespaces` claim scopes the token to those namespaces and **overrides even `admin`**; no claim = all namespaces.

A token's `permissions` JSONB has the shape :

```json
{
  "secrets": "rw",
  "tokens": "r",
  "namespaces": ["prod", "staging"],
  "audit": "r"
}
```

Every key (except `namespaces`) is a **scope**. The value is the
**mode** : `r` (read), `w` (write), or the string `rw` (both).

## Scope table

| Scope | `r` | `w` | `rw` |
|-------|-----|-----|------|
| `secrets` | Read a secret | Create / update / delete | Both |
| `tokens` | List tokens | Create / revoke | Both |
| `audit` | Read logs | - | - |
| `cluster` | Cluster + PostgreSQL HA status | Node lifecycle (promote / demote / drain / evict / unrevoke / init / repair) | Both |
| `admin` | Read everything | Write everything + seal/unseal/2FA | Full power |

`admin` applies to every scope, **honouring the mode** : `{"admin": "r"}`
grants `r` everywhere (a read-only operator, useful for monitoring), and
`{"admin": "rw"}` is an unrestricted operator. **Never give the latter to
automation.** Use a narrow scope per service.

`cluster` exists so that checking HA health does not require `admin`. A
`{"cluster": "r"}` token reads `/cluster`, `/cluster/health`, `/cluster/ha`
and the CA bundle - enough for a dashboard, an on-call human, or an LLM agent
- and can do nothing else. `cluster:w` adds node lifecycle operations.

The cluster CA (`issue-server-cert`, `rotate-cert`, `rotate-ca`) and the
HA-password rotation stay on `admin:w` deliberately : whoever can issue a node
certificate can impersonate a node in the cluster mTLS, which is a trust-root
capability, not a cluster-operator one.

## Namespace claim

`namespaces` is **not** a scope - it's a per-token allowlist. When
present, it restricts the other scopes to the listed namespaces. Two
modes :

- **Without `namespaces`** : the token sees all namespaces (subject
  to scope). For prod, never mint a token without `namespaces`.
- **With `namespaces`** : the token can only touch the listed namespaces.

Key invariant : **a `namespaces` claim restricts even an `admin`
token.** Without this, a namespace-restricted admin could escape its
scope. The `auth.check_namespace` function enforces this.

## POLA - least privilege grant check

When a token mints another token (`POST /tokens/`), the
`_check_grant_permissions` function ensures the new permissions are
a **subset** of the caller's. Two checks :

1. **Scope check** : every requested mode must be covered by the caller's
   own mode on that scope **union its `admin` mode**. `admin` is not a
   blanket bypass - the modes still have to match. An `{"admin":"rw"}`
   caller can grant anything, but an `{"admin":"r"}` caller can grant
   `secrets:r` and is refused `secrets:w`.
2. **Namespace subset check** : if the caller has a `namespaces`
   claim, the new token's `namespaces` must be a subset - and it may not
   be omitted. A namespace-restricted caller minting a token with no
   `namespaces` claim is refused, since that token would reach every
   namespace. This applies to admin callers too.

A `secrets:r` token cannot mint a `secrets:w` token. A
`namespaces:["dev"]` token cannot mint a `namespaces:["prod"]` token.

## Per-token IP allowlist

Optional `allowed_ips` field on tokens - a CSV mixing IPv4, IPv6,
single IPs, and CIDRs :

```json
{
  "name": "ansible-prod-runner",
  "permissions": {"secrets": "r", "namespaces": ["prod"]},
  "allowed_ips": "10.0.0.1, 10.0.0.1, 10.89.0.0/16"
}
```

Bare IPs are stored as `/32` (v4) or `/128` (v6). Empty / NULL = no
restriction (default - but **not recommended for prod**).

The check happens in `auth.require_vault_token` after hash validation.
A wrong-IP request gets `403 Token not allowed from this IP` - counted
in `rhorizon_auth_failures_total{reason="ip_not_allowed"}` but
**not** in the brute-force rate limiter (a legitimate token from a
wrong IP shouldn't accelerate the lockout for that IP).

### Lateral-movement defense - narrower is safer

If a token leaks, the allowlist is what limits the blast radius.
Reference ranges (use as ceilings, not defaults) :

| Range | Description |
|-------|-------------|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 - IPv4 private |
| `fc00::/7` | IPv6 ULA |
| `10.89.0.0/16` | Podman default bridge |
| `172.17.0.0/16` | Docker default bridge |
| `172.16.0.0/12` | All Docker user-defined bridges |
| `10.0.0.1/24` *(example)* | VPN subnet |

A single host : `allowed_ips: "10.0.0.1/32"` - most restrictive.
A few named hosts : `allowed_ips: "10.0.0.1, 10.0.0.1, 10.0.0.1"`.
VPN mesh : `allowed_ips: "10.0.0.1/24"`. RFC 1918 wide-open is
effectively no protection.

The UI form has inline help with these ranges, but no preset buttons -
intentional, to force the operator to think before clicking.

## Examples

```json
// Read-only access to all namespaces
{"secrets": "r"}

// Read-only, restricted to "uptime" only
{"secrets": "r", "namespaces": ["uptime"]}

// rw on dev + staging, no prod
{"secrets": "rw", "namespaces": ["dev", "staging"]}

// Auditor (read logs all namespaces)
{"audit": "r"}

// CI runner pinned to the runner pool subnet
{
  "permissions": {"secrets": "r", "namespaces": ["ci"]},
  "allowed_ips": "10.0.0.1/24"
}

// Honeytoken - attractive name, fires alert on any use
{
  "name": "prod-pgsql-master",
  "permissions": {"secrets": "rw"},
  "is_honey": true
}

// Full admin (avoid for automation)
{"admin": "rw"}
```
