# Secure your n8n workflows with rhorizon

n8n stores workflow credentials in its database under a single
`N8N_ENCRYPTION_KEY`, which is commonly supplied through `.env`.
Disclosure of that key and the credential store exposes the catalog.

This guide stores `N8N_ENCRYPTION_KEY` and selected node credentials
in rhorizon, injects them into n8n at boot, and records each retrieval
in the audit trail.

> If you have not run rhorizon yet, start with
> [`QUICKSTART-AI.md`](QUICKSTART-AI.md). It is the same
> vault - the laptop quickstart is enough.

---

## What this protects

| Risk | `.env` baseline | With rhorizon |
|---|---|---|
| Someone reads the n8n volume / image / config dump | Sees `N8N_ENCRYPTION_KEY` and the whole credentials store decryptable | Sees an encrypted store with no key. Useless without the running vault. |
| A workflow leaks a Slack / OpenAI / Stripe key (logs, error message, ...) | Same key keeps working until you remember which `.env` file to rotate | One revocation in the vault ; affected workflow stops working at next run |
| You handed n8n to a contractor / VA | They see every credential because n8n shows them in the UI | You only whitelist what they need ; rhorizon audit shows what was pulled, when, by whom |
| You want a compliance trail "who/what touched the Acme API key in March" | None | `rhorizon audit tail --since 2026-03-01 --until 2026-04-01 --json` |
| Master key rotation | Edit `.env` everywhere, restart n8n, hope nothing breaks | One vault rotation ; lazy migration window keeps existing tokens working ~15 days |

The model maps cleanly onto an outside auditor's checklist :
encryption at rest, key separation, revocation latency, per-secret
audit attribution.

---

## Two patterns

| Pattern | What it protects | When to use |
|---|---|---|
| **A - protect `N8N_ENCRYPTION_KEY`** | n8n's own credential store (the one the UI manages) | Always. Lowest-effort upgrade. |
| **B - per-secret env injection via `rh-inject`** | Individual workflow secrets exposed as `${{$env.MY_KEY}}` in n8n nodes | Workflows that need rotation, per-secret audit, or revocation independent of the n8n UI |

The patterns compose : pattern A is the foundation, pattern B is
opt-in per-secret. You can run pattern A only and keep pattern B for
the secrets that need a tighter audit.

---

## Pattern A - protect N8N_ENCRYPTION_KEY

### What changes

The `N8N_ENCRYPTION_KEY` no longer sits in `.env` next to the
container. It lives in rhorizon and is read from a tmpfs file
mounted into the n8n container at boot. n8n reads it the same way
it always did - the path is the only thing that changed.

### Setup

**1. Generate the key once and store it in rhorizon**

If you already have an `N8N_ENCRYPTION_KEY`, keep that exact value
(rotating it would re-encrypt every existing credential). Use the
prompt from [`AI-PROMPTS.md`](AI-PROMPTS.md) section 1 ("Add a new secret")
with :

- Namespace : `n8n`
- Secret name : `encryption-key`
- Value : your existing `N8N_ENCRYPTION_KEY`

If you do not have one yet, generate one before storing :

```bash
openssl rand -hex 32
```

**2. Mint a token for the n8n host**

```bash
# from the operator workstation, with root token loaded
rhorizon token create n8n-host \
  --scope secrets:r \
  --namespace n8n \
  --allowed-ips 10.89.0.0/16    # your podman / docker bridge subnet
```

The `allowed-ips` is the container subnet where n8n runs. Even if
the token leaks, it cannot be used from anywhere else on the LAN.

**3. Pull the key into the n8n container at boot**

Use `rh-fetch` (an init container that exits when the file is
written ; n8n waits for it) :

```yaml
# docker-compose.yml - n8n service
services:

  rh-fetch-n8n:
    image: localhost/rhorizon-agent:latest
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      RH_SECRETS: encryption-key:/run/n8n-secrets/encryption-key
      RH_NAMESPACE: n8n
    secrets:
      - rh-bootstrap
    volumes:
      - n8n_secrets:/run/n8n-secrets
    restart: "no"

  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    depends_on:
      rh-fetch-n8n:
        condition: service_completed_successfully
    environment:
      N8N_ENCRYPTION_KEY_FILE: /run/n8n-secrets/encryption-key
    volumes:
      - n8n_secrets:/run/n8n-secrets:ro
      - n8n_data:/home/node/.n8n
    ports:
      - "127.0.0.1:5678:5678"

volumes:
  n8n_secrets:
    driver_opts:
      type: tmpfs
      device: tmpfs    # never written to disk
  n8n_data:

secrets:
  rh-bootstrap:
    file: ./rh-bootstrap-token   # the n8n-host token, mode 0400
```

**4. Verify**

```bash
docker compose up -d
docker compose logs -f n8n
```

The log should mention "Encryption key loaded" with no warning
about a default key. The credentials store in the n8n UI now
relies on a key that lives in rhorizon - restart the vault sealed
and n8n will refuse to decrypt the store on its next restart.

---

## Pattern B - per-secret injection with rh-inject

### When this is worth it

Pattern A protects the master key but n8n's UI still shows the
plaintext values once unlocked. Pattern B keeps individual
high-value secrets *outside* the n8n credentials store entirely -
they only exist as environment variables in the n8n container,
referenced from workflow nodes as `={{$env.STRIPE_KEY}}`.

Use this for :

- Secrets that rotate often (Stripe, OpenAI billing, Twilio).
- Secrets shared with a contractor for a fixed engagement.
- Secrets you want to revoke without touching the n8n UI.

### Setup

**1. Store the secret in rhorizon**

Same prompt as before, namespace `n8n`. For example,
`n8n/stripe-key`.

**2. Mint a token (or reuse `n8n-host`)**

If you already have the `n8n-host` token from Pattern A, you can
reuse it - the namespace and scope match.

**3. Build a small custom n8n image**

```dockerfile
# n8n.Dockerfile
FROM localhost/rhorizon-agent:latest AS agent
FROM docker.n8n.io/n8nio/n8n:latest
USER root
COPY --from=agent /usr/local/bin/rh-inject /usr/local/bin/rh-inject
USER node
ENTRYPOINT ["/usr/local/bin/rh-inject", "--", "tini", "--"]
CMD ["n8n", "start"]
```

**4. Reference rhorizon URLs in the env**

```yaml
# docker-compose.yml - n8n service (replaces the previous one)
services:
  n8n:
    image: localhost/n8n-rh:custom        # your built image above
    environment:
      RH_ADDR: https://10.0.0.1:8443
      RH_TOKEN_FILE: /run/secrets/rh-bootstrap
      N8N_ENCRYPTION_KEY_FILE: /run/n8n-secrets/encryption-key
      STRIPE_KEY: rh://n8n/stripe-key
      OPENAI_API_KEY: rh://n8n/openai-key
      TWILIO_AUTH_TOKEN: rh://n8n/twilio-token
    volumes:
      - n8n_secrets:/run/n8n-secrets:ro
      - n8n_data:/home/node/.n8n
    secrets:
      - rh-bootstrap
```

`rh-inject` scans the env at PID 1 startup, finds every value that
starts with `rh://`, fetches each from rhorizon, replaces the value
in-memory, then `execve()`s n8n. The vault credentials
(`RH_TOKEN_FILE`, `RH_ADDR`) are stripped from the
child env before exec - n8n itself never sees them.

**5. Reference in your workflows**

In any n8n node parameter that supports expressions :

```
={{ $env.STRIPE_KEY }}
```

Same as you would do with a regular env var. n8n has no idea it
came from a vault.

### Trade-offs you should know

- The resolved values live in `/proc/<n8n-pid>/environ` after
  exec. Anyone running as the same uid with `SYS_PTRACE` can read
  them. This is unchanged from any "env-var-based secret" setup ;
  rhorizon does not magic this away. For higher-assurance secrets
  prefer Pattern A only and keep them in n8n's own store, or
  prefer Pattern A + `rh-fetch` + `_FILE` for nodes that support
  it.

- `rh-inject` resolves on boot. Rotating a secret requires a
  restart of the n8n container. For runtime rotation, use
  `rh-watch` (sidecar polling pattern) instead - see
  [`docs/docs/howto/agents.md`](docs/howto/agents.md#rh-watch---sidecar-with-rotation) for
  the configuration.

---

## Audit - what your client / your auditor sees

Once n8n is running and a workflow has executed at least once,
every fetch is in the chain :

```bash
# every time the n8n host pulled a secret
rhorizon audit tail --actor n8n-host

# when the OpenAI key was touched, by whom
# (no --target filter; filter client-side on the JSON)
rhorizon audit tail -n 200 --json \
  | jq '.[] | select(.target == "n8n/openai-key")'

# end-of-month export for a client
rhorizon audit tail --since 2026-04-01 --until 2026-04-30 \
  --json > april-audit.json
```

`audit tail` filters server-side on `--actor`, `--action`, `--since` and
`--until`; `--target` is not one of them, so narrow to a secret with `jq` as
above. `-n/--limit` defaults to 20, so raise it before filtering.

The chain is signed - every row signs the previous one, Ed25519 by default
with HMAC-SHA512 as the fallback. If
anyone (including you) edits the database to hide a fetch, the
chain breaks and `rhorizon audit verify` reports it. This is the
property auditors are looking for.

---

## Hardening checklist for an n8n + rhorizon deployment

- [ ] `rhorizon` and `n8n` are on the same private network. The
      vault is **never** exposed publicly. n8n's UI sits behind a
      reverse proxy with TLS + auth (Authelia / Authentik /
      Keycloak / nginx basic-auth at minimum).
- [ ] `n8n-host` token has `allowed-ips` matching the container
      bridge subnet only.
- [ ] `n8n-host` token scope is `secrets:r` only - no write, no
      admin.
- [ ] `n8n-host` token is restricted to the `n8n` namespace.
      Putting other clients' creds in `n8n/` is a footgun ; use
      `clients/<name>/` or split tokens.
- [ ] Bootstrap token file (`rh-bootstrap`) on the n8n host is
      mode 0400 owned by root.
- [ ] tmpfs volume for `/run/n8n-secrets` - never on disk.
- [ ] N8N_ENCRYPTION_KEY rotation : avoid rotating it after the
      credentials store is populated (n8n cannot re-encrypt
      existing entries automatically). If you must, follow the
      n8n upstream procedure first, then update the value in
      rhorizon.
- [ ] Audit retention long enough to satisfy your client / your
      regulator. Default 365 days.

---

## When this is *not* a fit

- **n8n cloud / SaaS deployments.** The whole point is local
  control over the encryption key. If n8n the company holds the
  key, this guide does not apply.
- **High-frequency credential rotation (every few minutes).**
  Pattern B requires a container restart to refresh. Use the
  vault's dynamic secrets engines (PostgreSQL / MySQL / LDAP / Redis /
  Cassandra) for credentials that genuinely need short-lived rotation.
- **Webhook signing where n8n itself signs traffic.** That key is
  used per-request, not per-boot ; pattern B's restart cycle is
  too coarse. Fetch it via the n8n HTTP node directly from the
  vault on demand.

---

## French version

Version française : [`fr/N8N.md`](fr/N8N.md).
