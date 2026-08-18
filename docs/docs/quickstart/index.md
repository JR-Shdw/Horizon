# Quickstart

Three install paths, choose the one that matches your infra :

- [**Single host (docker)**](docker.md) - fastest, one bash one-liner,
  ideal for laptops and small servers.
- [**Kubernetes (Helm)**](kubernetes.md) - production-leaning, in-chart
  PostgreSQL or external, NetworkPolicy lockdown, optional Ingress.
- [**From source**](source.md) - build the images yourself, hack on
  the code, run the test suite.

After install, every path converges on the same first-time flow :

1. Hit the API `/health` endpoint to confirm the stack is up.
2. POST to `/api/v1/vault/unseal` with a master password - this sets
   the password (FIRST CALL ONLY) and returns a one-shot `root_token`.
3. Save the root token. **It is shown once and never again.**
4. Use the root token to create per-service tokens with narrow scopes
   (see [permissions](../reference/permissions.md)).
5. Optionally enable 2FA in the **Core** view of the UI - TOTP, YubiKey
   HMAC-SHA1, and WebAuthn/FIDO2 are all supported.
