# Agents - rh-fetch, rh-inject, rh-watch

Three Rust binaries shipped as a single docker image (`rhorizon-agent`,
~5-8 MB on `FROM scratch`). Pick one per service, depending on how
that service expects to consume secrets.

| Binary | Pattern | Use when... |
|--------|---------|-----------|
| `rh-fetch` | Init container | The service reads secrets from a file path (`*_FILE` env, mounted file) - postgres, mariadb, redis, most modern container images. |
| `rh-inject` | Exec wrapper, PID 1 | The service only reads from environment variables (n8n, older apps). |
| `rh-watch` | Sidecar with rotation | You need rotation runtime - periodic refresh + reload signal to the main container. |

All three share `lib.rs` : `SecureToken` (mlock + zeroize),
`load_token()` (file -> env -> unset), `atomic_write()`
(`.tmp + fsync + rename + chmod 0400`).

## Common env vars

| Var | Lu par | Purpose |
|-----|--------|---------|
| `RH_ADDR` | all | API base URL, e.g. `http://10.0.0.1:8200` |
| `RH_TOKEN_FILE` | all | Path to a mode-0400 file holding the bearer token (preferred) |
| `RH_TOKEN` | all | Legacy : bearer in env var. Auto-`unsetenv`'d after read. |
| `RH_SECRETS` | rh-fetch / rh-watch | `name:/path,name:/path,...` |
| `RH_POLL_SECS` | rh-watch | Poll interval (default 30, min 5) |
| `RH_RELOAD_PID` | rh-watch | PID to signal on change (e.g. `1`) |
| `RH_RELOAD_SIGNAL` | rh-watch | Signal name (default `HUP`) |
| `RH_EPHEMERAL` | rh-watch | `true` to mint TTL'd ephemeral tokens via `/tokens/ephemeral` instead of using the bootstrap directly |
| `RH_EPHEMERAL_TTL` | rh-watch | Ephemeral TTL in seconds (default 3600, range 60-86400) |

## rh-fetch - init container pattern

```yaml
# docker-compose.yml fragment
services:
  rh-fetch-pg:
    image: rhorizon-agent:latest
    entrypoint: /usr/local/bin/rh-fetch
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      RH_SECRETS: prod/db-password:/run/secrets/POSTGRES_PASSWORD
    secrets:
      - rh-bootstrap
    volumes:
      - secrets-pg:/run/secrets

  postgres:
    image: postgres:18
    depends_on:
      rh-fetch-pg:
        condition: service_completed_successfully
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/POSTGRES_PASSWORD
    volumes:
      - secrets-pg:/run/secrets:ro

secrets:
  rh-bootstrap:
    file: ./rh-bootstrap

volumes:
  secrets-pg:
```

The `rh-fetch` container exits 0 once secrets are written. Postgres
starts only after that exit (via `condition: service_completed_successfully`).
Secrets land on the shared `secrets-pg` tmpfs volume at mode 0400.

## rh-inject - exec wrapper pattern

For services that only read env vars (e.g. n8n) :

```dockerfile
# n8n.Dockerfile
FROM rhorizon-agent:latest AS agent
FROM n8nio/n8n:latest
USER root
COPY --from=agent /usr/local/bin/rh-inject /usr/local/bin/rh-inject
USER node
ENTRYPOINT ["/usr/local/bin/rh-inject", "--", "tini", "--"]
CMD ["n8n", "start"]
```

```yaml
services:
  n8n:
    image: localhost/n8n-rh:demo
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      N8N_ENCRYPTION_KEY: rh://prod/n8n-encryption-key
      DB_TYPE: sqlite
    secrets:
      - rh-bootstrap
```

`rh-inject` scans the environment for values starting with `rh://`,
fetches each from the vault, replaces the value in-memory, and
`execve()`s the real command as PID 1. Vault credentials
(`RH_TOKEN_FILE`, `RH_ADDR`) are stripped from the child
env before exec.

**Tradeoff documented** : after `rh-inject` execs the child, the
resolved values live in the child's `/proc/PID/environ`. Visible to
anything running with the same uid + `SYS_PTRACE`. Acceptable for
sidecar-less workflow tools ; for higher-assurance secrets prefer
`rh-fetch` + `_FILE`.

## rh-watch - sidecar with rotation

```yaml
services:
  rh-watch-creds:
    image: rhorizon-agent:latest
    entrypoint: /usr/local/bin/rh-watch
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      RH_SECRETS: prod/db-password:/run/secrets/POSTGRES_PASSWORD
      RH_POLL_SECS: "30"
      RH_RELOAD_PID: "1"           # signal the main app on change
      RH_RELOAD_SIGNAL: "HUP"
      RH_EPHEMERAL: "true"          # mint short-TTL tokens
      RH_EPHEMERAL_TTL: "3600"
    secrets:
      - rh-bootstrap
    volumes:
      - secrets-app:/run/secrets
    pid: "service:app"  # share PID namespace so we can signal PID 1
```

The polling loop atomically replaces `/run/secrets/POSTGRES_PASSWORD`
when the value changes, then sends `SIGHUP` to PID 1 (your app, since
`pid: service:app` shares the namespace).

When `RH_EPHEMERAL=true` is set :

1. At boot, `rh-watch` calls `/tokens/whoami` to read the bootstrap's
   `allowed_ips` and `namespaces` claims.
2. It then mints a TTL'd ephemeral via `/tokens/ephemeral` with
   permissions forced to `secrets:r` and `inherit_group_membership=true`
   (so the new ephemeral picks up the bootstrap's group memberships
   for strict-RBAC namespaces).
3. The bootstrap stays in `mlock`'d RAM, used **only** for whoami +
   mint calls - never for `/secrets/*` fetches.
4. The ephemeral is refreshed at TTL/2.

This is the preferred pattern for production : if the container is
compromised, the attacker walks away with an ephemeral that dies in
<= TTL minutes, not the long-lived bootstrap.

## Token bootstrap on the host

You need a way to get the initial bootstrap token onto the host. Two
common patterns :

- **podman secret / docker secret** : create a secret named
  `rh-bootstrap` with the token value, mount it at
  `/run/secrets/rh-bootstrap` mode 0400.
- **kubernetes Secret** : create a `Secret` with the token in a key,
  mount as a volume in the pod.

Either way, the token never appears in `docker inspect` env vars -
only the path `/run/secrets/rh-bootstrap` is visible.
