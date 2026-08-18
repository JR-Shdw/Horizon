# Single host - Docker

The simplest path. One bash command, ~5-10 minutes end-to-end on the
first run (5-8 of those are the local image build, which then layer-
caches for subsequent runs). No Kubernetes, no service mesh, no
traefik required.

## Prerequisites

- Linux host (or macOS / Windows with WSL2)
- `docker` + `docker compose` (v2) or `docker-compose` (v1)
- RAM per tier: ~600 MB (home) / ~1.6 GB (smb) / ~2.7 GB (heavy); ~2 GB disk
- `curl` + `openssl` + `git` in PATH

## One-liner install

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/install.sh | bash
```

What this does, step by step :

1. Detects `docker compose` (v2) or `docker-compose` (v1) automatically.
2. Creates `~/rhorizon/` with mode 0700 on `secrets/`.
3. Generates a strong random `POSTGRES_PASSWORD` (`openssl rand -hex 32`).
4. Clones the repo into `~/rhorizon/source` so `docker build` has the
   Dockerfiles, schema, and source tree.
5. Builds `rhorizon-api` and `rhorizon-frontend` images locally
   (~5-8 minutes the first time, cached afterwards).
6. Brings the stack up with `tools/docker-compose.quickstart.yml` -
   localhost-only port bindings, no traefik dependency.
7. Polls `/health` for up to 180 seconds until the API is ready.
8. Performs the first `/unseal` with an auto-generated master password,
   captures the one-shot `root_token`, and saves both to
   `~/rhorizon/secrets/` at mode 0400.
9. Prints a summary with URLs, credentials, and a hardening checklist.

## Sizing preset

`--tier` sizes the whole stack (api workers, PostgreSQL, memory) in one shot.
**home is the default** (single worker, localhost). Re-run with another tier to
switch: volumes persist and the vault re-unseals automatically.

| Preset | Workers | Total RAM | For |
|--------|---------|-----------|-----|
| `home` | 1 | ~600 MB | Personal / laptop |
| `smb` | 5 | ~1.6 GB | Minimum for professional use |
| `heavy` | 10 | ~2.7 GB | High concurrency |

Full knob table: [env-vars reference](../reference/env-vars.md#sizing-set-by-tier).

## Custom flags

```bash
bash tools/install.sh \
  --tier smb \
  --dir /opt/rhorizon \
  --bind 10.0.0.1 \
  --api-port 8200 \
  --frontend-port 8443 \
  --master-password 'your-passphrase' \
  --no-build           # skip image build, expect tags to exist
```

| Flag / env | Default | Meaning |
|------------|---------|---------|
| `--tier` / `RH_TIER` | `home` | Sizing preset (`home`\|`smb`\|`heavy`) |
| `--dir` / `RH_DIR` | `~/rhorizon` | Working directory |
| `--bind` / `RH_BIND` | `127.0.0.1` | Host IP for port mappings |
| `--api-port` / `RH_API_PORT` | `8200` | API HTTP port |
| `--frontend-port` / `RH_FRONTEND_PORT` | `8443` | Frontend HTTPS port (when TLS_ENABLED=true) |
| `--master-password` / `RH_MASTER_PASSWORD` | auto-generated | First-unseal master password |
| `--no-build` | false | Skip `docker build`, requires images already tagged |
| `--persist` / `RH_PERSIST` | false | Auto-start the stack on boot |

## Persistence (`--persist`)

Opt-in; makes the tier restart after a reboot. The mechanism depends on the
runtime (auto-detected via `tools/detect-system.sh`):

| Runtime / init | What `--persist` does |
|---|---|
| Docker (or Docker Desktop on macOS) | Nothing needed - the daemon + `restart: unless-stopped` already restart it |
| Rootless podman + systemd | `loginctl enable-linger` + a `systemd --user` unit (may need `sudo loginctl enable-linger <user>` once) |
| BSD | Not applicable - use the [native install](source.md) (root), which wires PG + API into `rc.d` |
| podman-machine (macOS) | Ensure the machine starts on login (LaunchAgent); containers then honor their restart policy |

The stack always returns **sealed** on boot (sealed-by-default) - unseal again
after a reboot.

## After install

The script prints something like :

```
================================================================================
  rhorizon is up and running.

  Frontend (UI)        : http://127.0.0.1:8080/
  API endpoint         : http://127.0.0.1:8200/

  Master password      : /home/you/rhorizon/secrets/master-password
  Root token           : /home/you/rhorizon/secrets/root-token

  Quick API check :

    export RH_TOKEN=$(cat /home/you/rhorizon/secrets/root-token)
    curl -H "Authorization: Bearer $RH_TOKEN" \
      http://127.0.0.1:8200/api/v1/vault/tokens/whoami
```

Open the UI at the printed URL, log in by pasting the root token in the
**Settings / Auth Token** field, and explore.

## First secret - store and read

A 30-second sanity check that the full pipeline works (API + crypto +
DB + audit). Two ways, pick one.

### Via the CLI (curl)

```bash
export RH_TOKEN=$(cat ~/rhorizon/secrets/root-token)
export RH_URL=http://127.0.0.1:8200/api/v1/vault

# 1. Store a secret
curl -fsS -X POST "$RH_URL/secrets/" \
  -H "Authorization: Bearer $RH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "hello", "value": "world", "namespace": "default"}'
# -> {"name":"hello","version":1,...}

# 2. Read it back
curl -fsS "$RH_URL/secrets/hello" \
  -H "Authorization: Bearer $RH_TOKEN"
# -> {"name":"hello","value":"world","version":1,...}

# 3. Verify the audit trail
curl -fsS "$RH_URL/audit/?limit=2" \
  -H "Authorization: Bearer $RH_TOKEN" | head
# -> two entries : create_secret + read_secret, with chained HMAC signatures
```

If all three calls succeed, you have a working vault end-to-end.

### Via the UI (Eclipse view)

1. Open `http://127.0.0.1:8080/` and paste the root token in
   **Core -> Auth Token**.
2. Navigate to **Eclipse** (the Secrets view).
3. Click **+ New Secret**, fill name `hello`, value `world`, leave
   namespace `default`. Save.
4. Click **Read** on the row. The value appears, then auto-clears
   after 30 s - that auto-clear is the same UX you'll see for every
   read in production.
5. Navigate to **Jets** (audit) - your two operations appear at the
   top of the chain, with `chain_intact: true`.

## Idempotency & re-runs

Running the script twice on the same `--dir` :

- Reuses the existing `.env` (does not regenerate the PG password).
- Reuses the existing root token (does not re-issue).
- Re-builds images if `--no-build` is not set (but `docker build` is
  layer-cached, so it's fast).
- Brings the stack up again - `docker compose up -d` leaves running
  services unchanged.

To wipe and start fresh :

```bash
cd ~/rhorizon
docker compose down -v          # drops the PG volume -> all data lost
cd .. && rm -rf ~/rhorizon
```

## Production hardening

The quickstart binds to `127.0.0.1` and disables TLS for ease. Before
exposing to anything other than `localhost` :

- [ ] Replace the auto-generated master password with a memorable
      passphrase you can re-enter on every restart (the vault is
      sealed at boot - the master password is required to unseal).
- [ ] Rotate the root token immediately and create per-service tokens
      with narrow scopes + IP allowlists. See [permissions](../reference/permissions.md).
- [ ] Enable TLS termination - either through nginx-as-reverse-proxy
      directly, or via an upstream traefik/caddy. The frontend's nginx
      can also serve TLS itself if you set `TLS_ENABLED=true` and
      mount certs in `~/rhorizon/certs/`.
- [ ] Enable 2FA via the **Core** view in the UI (TOTP, YubiKey, WebAuthn).
- [ ] Back up the PG volume + `~/rhorizon/secrets/` directory.
- [ ] Set up an off-site copy of the master password (paper, password
      manager, Shamir split). **If you lose it, all secrets are gone.**

For multi-host or HA deployments, use the [Helm chart](kubernetes.md)
or roll your own with `docker-compose.yml` (the production template
in the repo root, with traefik labels and external network).
