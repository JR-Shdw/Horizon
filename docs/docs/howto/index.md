# How-to

Recipes for the common operational tasks. Each page is task-focused
and assumes you've gone through the [quickstart](../quickstart/index.md)
and have a running, unsealed vault.

- [**Agents (rh-fetch / rh-inject / rh-watch)**](agents.md) - the three
  Rust binaries for delivering secrets to your services.
- [**MCP (LLM access)**](mcp.md) - give an AI assistant (Cursor, Cline,
  Claude Desktop) or a cloud agent scoped, fail-closed, read-only vault access.
- [**Kubernetes sidecar pattern**](kubernetes-sidecar.md) - pod
  manifests for init container, env wrapper, and sidecar rotation.
- [**LDAP & SSO proxy auth**](ldap-sso.md) - connect rhorizon to
  Active Directory, OpenLDAP, Authelia, Authentik, or Keycloak.
- [**2FA setup**](2fa.md) - TOTP, YubiKey HMAC-SHA1, WebAuthn / FIDO2.
- [**Native TLS (HTTPS)**](tls.md) - terminate HTTPS at the bundled
  nginx without an external reverse proxy.
- [**High availability**](high-availability.md) - the production topology,
  routing/retry contract, database budget, worker convergence, audit jobs, and
  go-live gates. The page links to the detailed architecture and runbook.
- [**Backup & restore**](backup-restore.md) - full DR and age-encrypted logical backups
  and how to restore them.
