# LDAP & SSO proxy auth

Two external auth paths - pick depending on whether your IdP is LDAP
(Active Directory, OpenLDAP) or HTTP-based (Authelia, Authentik,
Keycloak via reverse proxy).

## LDAP / Active Directory

### Configure the connection

```bash
curl -X POST http://127.0.0.1:8200/api/v1/vault/auth/ldap/config \
  -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "ldaps://dc1.corp.example:636",
    "bind_dn": "cn=rhorizon-svc,ou=services,dc=corp,dc=example",
    "bind_password": "service-account-password",
    "user_base": "ou=users,dc=corp,dc=example",
    "user_filter": "(sAMAccountName={username})",
    "group_base": "ou=groups,dc=corp,dc=example",
    "group_filter": "(member={user_dn})",
    "group_attr": "cn",
    "tls_verify": true,
    "session_ttl_hours": 8
  }'
```

`url`, `bind_dn`, `bind_password`, `user_base` and `group_base` are required.
`user_filter`, `group_filter`, `group_attr`, `tls_verify` and
`session_ttl_hours` default to the values shown.

The bind password is encrypted with a DEK before storage (AES-256-GCM,
DEK bound to a per-config UUID via AAD).

### Map LDAP groups to vault permissions

```bash
curl -X PUT http://127.0.0.1:8200/api/v1/vault/auth/ldap/mappings \
  -H "Authorization: Bearer $ADMIN" \
  -d '{
    "mappings": {
      "vault-admins":  {"admin": "rw"},
      "ops-team":      {"secrets": "rw", "tokens": "r", "namespaces": ["prod","staging"]},
      "dev-team":      {"secrets": "rw", "namespaces": ["dev"]},
      "audit-readers": {"audit": "r"}
    }
  }'
```

When a user logs in via `POST /auth/ldap` with their LDAP credentials,
rhorizon :

1. Binds as the service account, finds the user's DN.
2. Re-binds as the user with their password (verifies the credential).
3. Reads the user's group memberships via `member` lookup.
4. Merges the permissions of every group the user belongs to.
5. Issues a session token named `ldap:<username>` with TTL 8h.

The request and response shapes are shown below. Use the login UI or submit the
password in an HTTPS request body; do not place a real password in a shell
argument.

```json
{ "username": "alice", "password": "<user-password>" }
```

```json
{
  "token": "rh_...",
  "username": "alice",
  "groups": ["ops-team"],
  "permissions": {"secrets": "rw", "tokens": "r", "namespaces": ["prod","staging"]},
  "expires_at": "..."
}
```

## SSO proxy (Authelia / Authentik / Keycloak)

When you already have an SSO that sits in front of rhorizon as a
reverse proxy and forwards `Remote-User` + `Remote-Groups` headers,
configure :

```bash
curl -X POST http://127.0.0.1:8200/api/v1/vault/auth/proxy/config \
  -H "Authorization: Bearer $ADMIN" \
  -d '{
    "enabled": true,
    "user_header": "Remote-User",
    "groups_header": "Remote-Groups",
    "trusted_ips": "10.0.0.1/32, 10.0.0.1/32",
    "session_ttl_hours": 8
  }'
```

`trusted_ips` MUST list the proxy's source IPs - otherwise anyone
could forge the headers. These identity proxy addresses also participate
in `X-Forwarded-For` resolution. `RH_XFF_TRUSTED_IPS` can trust additional
forwarding-only proxies without authorizing identity headers.

If the response contains `"restart_required": true`, restart all API
workers together. Rhorizon deliberately keeps the previous
`X-Forwarded-For` trust boundary in every worker until that coordinated
restart instead of applying a security-sensitive change to only the
worker that handled the request.

Group -> permission mappings work the same way as LDAP :

```bash
curl -X PUT http://127.0.0.1:8200/api/v1/vault/auth/proxy/mappings \
  -H "Authorization: Bearer $ADMIN" \
  -d '{
    "mappings": {
      "vault-admins": {"admin": "rw"},
      "ops":          {"secrets": "rw"}
    }
  }'
```

Once configured, the proxy POSTs `/auth/proxy` (no body needed - the
SSO headers carry the identity) and gets back a session token named
`proxy:<username>`.

## Live group revocation

For operator session tokens (named `ldap:user` or `proxy:user`),
rhorizon enforces **live** group membership on every request when the
target namespace has `enforce_membership=true`. Removing the source-qualified
external principal from the Rhorizon group takes effect at the **next**
request.

API tokens are separate typed principals keyed by token UUID. Removing that
token principal from the Rhorizon group also takes effect at the next request;
a human login and token display name can never collide.
