# Install Resurgamus Horizon with help from an AI assistant

> This guide lets an AI assistant walk a non-technical user through a
> local Resurgamus Horizon installation.
>
> Open your AI assistant, say *"I want to install
> Resurgamus Horizon on my computer. Read this file and guide me step
> by step."*, then paste this file into the chat. Review every command
> before running it; the assistant can misunderstand output or local
> conditions.
>
> If a step fails, provide the exact error and step number, after
> removing tokens, passwords, hostnames, and other sensitive values.

The rest of this document is written primarily for the assistant.

---

## Instructions for the AI assistant

You are about to walk a non-technical user through installing
Resurgamus Horizon (a self-hosted secrets vault) on their personal
computer for **local use** (not production, not internet-exposed).

### Operating principles

1. **One step at a time.** Show one command, wait for the user's
   output, then move on. Do not paste a wall of commands.
2. **Check OS first.** Ask the user what operating system they are
   on (Linux distro, macOS, Windows) before recommending any command.
   The Docker install path differs significantly across these.
3. **Quote exact commands.** Copy them character-for-character from
   this document. Do not paraphrase. Do not add flags the user did
   not ask for.
4. **Verify each step before moving on.** Every step has an "expected
   output" pattern. If it doesn't match, fall back to the
   troubleshooting table.
5. **Explain failures precisely.** Do not dismiss an error or claim a
   fix worked until the documented verification succeeds.
6. **Never ask the user to share their master password with you.** It
   is the one thing they pick that nobody else should ever see.
7. **Stay scoped.** This document is for **local installation only**.
   If the user asks about exposing the vault on the internet, redirect
   them to `docs/DEPLOYMENT.md` and stop - that scenario is out of scope
   for this guide.
8. **No commands the user did not approve.** Especially nothing
   destructive (no `rm -rf`, no `docker system prune`, no
   `docker compose -f tools/docker-compose.quickstart.yml down -v` without explicit confirmation).

### Safety boundaries

- Modify code or configuration files inside the cloned repo
- Run any container in `--privileged` mode
- Expose ports outside of `127.0.0.1` ("localhost") without explicit user request
- Disable any security feature mentioned in this document
- Store the user's master password in your context, in chat, or
  anywhere else - direct them to a password manager
- Recommend tools / scripts not in this document; for other install paths,
  point the user at `docs/QUICKSTART.md` or `docs/DEPLOYMENT.md`

---

## Step 0 - Establish context

Ask the user:

```
1. What operating system are you on? (Linux distro / macOS / Windows)
2. Have you used a terminal / command line before? (yes / a little / never)
3. Do you have Docker installed? (yes / no / not sure)
4. How much free disk space do you have? (need at least 3 GB)
5. How much RAM does your computer have? (need at least 512 MB free)
```

If RAM is below 512 MB or disk is below 3 GB, **stop**. Tell the user
the requirements honestly. The bulk of the disk is the container
images. The default `home` tier uses one worker and is the supported
laptop profile. Do not invent an intermediate worker count: clustered
operation starts at the documented five-worker `smb` tier.

---

## Step 1 - Install Docker (if not already)

The user already has Docker if `docker --version` returns a version
string >= 24.

### Linux (Debian / Ubuntu)

```bash
# Official install script - review before piping to sh!
# (Tell the user what this does in plain English.)
curl -fsSL https://get.docker.com | sh

# Add user to the docker group so they don't need sudo
sudo usermod -aG docker $USER
# They MUST log out and back in (or reboot) for this to take effect
```

Verify after re-login:

```bash
docker --version              # expects: Docker version 24.x or higher
docker compose version        # expects: Docker Compose version v2.x.x
```

### Linux (Arch / Manjaro)

```bash
sudo pacman -S docker docker-compose
sudo systemctl enable --now docker.service
sudo usermod -aG docker $USER
# Log out and back in
```

### Linux (Fedora / RHEL / Rocky)

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Log out and back in
```

### macOS

Recommend one of these (they're equivalent for our purposes):

- **OrbStack** (lightweight, fast, free for personal use) - https://orbstack.dev/
- **Docker Desktop** - https://www.docker.com/products/docker-desktop/
- **Colima** (CLI only) - `brew install colima docker docker-compose && colima start`

After installation, verify:

```bash
docker --version
docker compose version
```

### Windows

Install **Docker Desktop with WSL2 backend** - https://www.docker.com/products/docker-desktop/

The user will need:

- Windows 10/11 with WSL2 enabled (`wsl --install` in PowerShell as admin if not already)
- Hyper-V virtualization enabled in BIOS

After install, the user opens **Ubuntu** (or their preferred WSL2
distro) and continues from there. **Don't try to run rhorizon from
PowerShell or cmd.exe** - use the WSL2 shell.

In WSL2, verify:

```bash
docker --version
docker compose version
```

---

## Step 2 - Get the source code

```bash
# In a sensible directory like ~/projects
mkdir -p ~/projects && cd ~/projects

# Clone the public mirror
git clone https://github.com/JR-Shdw/Horizon.git rhorizon
cd rhorizon
```

If `git` is not installed:

| OS | Install |
|---|---|
| Debian/Ubuntu | `sudo apt install git` |
| Arch/Manjaro | `sudo pacman -S git` |
| Fedora | `sudo dnf install git` |
| macOS | `brew install git` (or accept Apple's prompt to install Xcode CLI) |
| Windows (WSL2) | `sudo apt install git` inside Ubuntu |

Verify:

```bash
git --version
ls
# expected: api  CLAUDE.md  docker-compose.yml  docs  env.example  ...
```

---

## Step 3 - Configure (.env file)

```bash
cp env.example .env
```

Now generate a strong PostgreSQL password and write it into `.env`:

```bash
sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 32)|" .env
rm .env.bak                # macOS sed creates a backup; remove it
```

Show the user what was changed:

```bash
grep '^POSTGRES_PASSWORD=' .env
# expects: POSTGRES_PASSWORD=<64 hex characters>
```

That password is used by Postgres internally and is not the user's
master password. They don't need to remember it.

---

## Step 4 - Bring up the stack

```bash
docker compose -f tools/docker-compose.quickstart.yml up -d
```

**Use that exact file.** The repository also has a `docker-compose.yml` at
its root, but that one is the operator/VPN stack: it publishes on
`10.0.0.1` and `10.0.1.1`, so on a normal laptop Docker refuses to start
and prints *"Couldn't listen on requested ports"*. The quickstart file binds
`127.0.0.1` only, which is what you want here.

This pulls the Postgres image (~150 MB) and builds the API and frontend
images locally. **First build takes 5-15 minutes** depending on the
machine. Subsequent runs are instant.

If the build is slow, tell the user it's normal. They can watch
progress with `docker compose -f tools/docker-compose.quickstart.yml logs -f` in another terminal if they
want, but it isn't necessary.

When the prompt returns, verify:

```bash
docker compose -f tools/docker-compose.quickstart.yml ps
```

Expected output: three services with status `running` or `running (healthy)`:
- `rhorizon_postgres`
- `rhorizon_api`
- `rhorizon_frontend`

Wait up to 60 seconds for healthchecks to settle. Then:

```bash
curl http://localhost:8200/health
# expected: {"status": "ok"}
```

If you don't have `curl`, open `http://localhost:8200/health` in a
browser - same result.

---

## Step 5 - Choose a master password

**STOP HERE and read this to the user, verbatim:**

> The next step asks for a master password. This is the **most
> important secret** of your entire vault. **If you lose it, every
> secret you put in the vault is unrecoverable** (that is the whole
> point - there is no "forgot password" link).
>
> Choose something:
>
> - **Long.** 16+ characters minimum. A passphrase like "correct horse battery staple seven" is fine.
> - **Unique.** Don't reuse a password from anywhere else.
> - **Memorable to you.** A random string you can't remember is worse than a long passphrase.
>
> **Save it in TWO places:**
>
> 1. A password manager (KeePassXC, Bitwarden, 1Password, ...)
> 2. **Offline** - written on paper in a safe, or printed and stored at home
>
> Don't paste the password into this AI conversation. Don't email it to
> yourself. Don't put it in a text file on your desktop.
>
> When you're ready, tell me you're ready and I'll show you the
> command. **Type the password directly into your terminal - not into
> this chat.**

Wait for the user's confirmation that they've prepared the password.

---

## Step 6 - Unseal (first time)

Ask the user to enter the master password directly in their terminal:

```bash
read -rsp "Master password: " PASSWORD && echo
printf '%s' "$PASSWORD" \
  | python3 -c 'import json,sys; print(json.dumps({"password": sys.stdin.read()}))' \
  | curl -X POST http://localhost:8200/api/v1/vault/unseal \
  -H "Content-Type: application/json" \
  --data-binary @-
unset PASSWORD
```

The password is read without echo, encoded from standard input, and never
placed in shell history or a process argument. It still exists briefly in the
shell, Python, and curl process memory, which is required to submit it.

**Expected response** (formatted):

```json
{
  "status": "unsealed",
  "root_token": "rh_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

⚠️ **Tell the user**: that `rh_xxx` value is their **root token**. It
will only ever be shown this one time. They must save it the same way
they saved the master password (password manager + offline copy).

The root token is what they'll use to authenticate every API call from
their scripts and tools.

---

## Step 7 - Verify success

```bash
curl http://localhost:8200/api/v1/vault/status
# expected: {"sealed": false, "version": "1.0.0-beta", ...}
```

If `sealed` is `true`, something went wrong. Have them re-do Step 6.

Open the web UI:

- Linux: `xdg-open http://localhost:8200`
- macOS: `open http://localhost:8200`
- Windows (WSL2): they can paste `http://localhost:8200` into their browser

The user should see the "Horizon" dashboard with a **green** indicator
saying the vault is unsealed.

---

## Step 8 - Store the user's first secret

In the web UI:

1. Click on **Eclipse** (Secrets) in the sidebar
2. Paste their root token in the prompt at the top, then click "Set token"
3. Click "+ New secret"
4. Name: `test-secret`, Value: `hello world`, click Save
5. They should see the secret in the list

Or via command line:

```bash
TOKEN="rh_xxxxxxxxxxxxx"   # have them paste their root token here
curl -X POST http://localhost:8200/api/v1/vault/secrets/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-secret", "value": "hello world"}'

# Read it back
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8200/api/v1/vault/secrets/test-secret
# expected: {"name": "test-secret", "value": "hello world", ...}
```

---

## Step 9 - What to do next (for the user)

Congratulate them. Then suggest these next steps (in order):

1. **Read [`docs/QUICKSTART.md`](QUICKSTART.md)** - covers 2FA setup
   (TOTP / YubiKey / WebAuthn), generating scoped tokens for scripts,
   Shamir Secret Sharing, and backup.
2. **Set up 2FA.** This is highly recommended. The simplest path is
   TOTP (using a phone app like Aegis, Google Authenticator, or 1Password).
3. **Plan a backup.** A vault is only as good as its backup. Daily
   `pg_dump` + the audit volume is enough for personal use; see
   [`docs/DEPLOYMENT.md`](DEPLOYMENT.md#9-backup--restore).
4. **After every reboot, re-unseal** with the same command from Step 6.
   This is by design - the vault never persists keys to disk.

---

## Troubleshooting - common errors

| User says / sees | Cause | Fix |
|---|---|---|
| `command not found: docker` | Docker not installed | Step 1 |
| `permission denied while trying to connect to the Docker daemon socket` | User not in `docker` group, or didn't log out and back in after Step 1 | Run `groups` - if `docker` isn't there, `sudo usermod -aG docker $USER` then log out and back in. On systems without group support, use `sudo` in front of every `docker` command. |
| `bind: address already in use` on port 8200 | Another service is using that port | `ss -tlnp \| grep 8200` (Linux) or `lsof -i :8200` (mac) to find the conflict. Stop it, or set `RH_API_PORT=8210` (or another free port) before bringing the stack up. |
| `docker compose -f tools/docker-compose.quickstart.yml up` hangs on "Building" | Slow internet / slow CPU | Patience. First build is genuinely 5-15 min on average hardware. |
| `pull access denied for postgres` | DNS or network issue, possibly behind corporate proxy | Test `docker pull postgres:18-trixie` directly. If it fails, check `~/.docker/config.json` for proxy settings, or ask the user about their network. |
| `unhealthy` on `rhorizon_postgres` | Postgres failed to start | `docker compose -f tools/docker-compose.quickstart.yml logs postgres` and read the last 30 lines. Most often: not enough RAM, or `POSTGRES_PASSWORD` empty in `.env`. |
| `connection refused` on `curl http://localhost:8200/health` | API not yet ready | Wait 30 seconds and retry. If still failing, `docker compose -f tools/docker-compose.quickstart.yml logs api` |
| `{"sealed": true}` after unseal | Wrong password or 2FA misconfigured | Re-check the password (case-sensitive!). If 2FA is on but they didn't supply a token, the unseal request will fail. |
| Web UI shows "Cannot connect" | API container not running | `docker compose -f tools/docker-compose.quickstart.yml ps`, then `docker compose -f tools/docker-compose.quickstart.yml logs api` |
| User wants to start over from scratch | They messed up the master password and there's no data they care about yet | `docker compose -f tools/docker-compose.quickstart.yml down -v` - **WARNING**: this deletes the database. Confirm with the user. Then start again from Step 4. |
| Build fails with `cargo: command not found` or Rust errors | Build cache issue | `docker compose build --no-cache api` |
| `disk full` errors | Out of disk | Check `df -h`. Free space or add disk. Docker images alone need ~3 GB. |

---

## Escalation rules

Send the user to a human (issue tracker, security mailbox, or back to
the docs) if:

- They want to expose the vault on the public internet -> **STOP**, point at `docs/DEPLOYMENT.md`, refuse to assist further with that topology
- They want to deploy to Kubernetes -> point at `docs/K8S.md`
- They want to integrate with Ansible / CI / agents -> point at `docs/USE-CASES.md`
- They report a security vulnerability -> point at `SECURITY.md`
- They want to contribute / fix a bug -> point at `CONTRIBUTING.md`
- They lose their master password -> tell them honestly: **the vault is unrecoverable**. The data is encrypted with a key derived from that password and there is no backdoor by design. They will need to start fresh with `docker compose -f tools/docker-compose.quickstart.yml down -v` and a new password.

---

## Self-check for the AI before you finish

Before declaring the install successful:

- [ ] All three containers show `running (healthy)` in `docker compose -f tools/docker-compose.quickstart.yml ps`
- [ ] `curl http://localhost:8200/health` returns `{"status": "ok"}`
- [ ] `curl http://localhost:8200/api/v1/vault/status` returns `"sealed": false`
- [ ] The user has saved both their master password and their root token in two places (password manager + offline)
- [ ] The user knows that re-booting requires re-unsealing
- [ ] You did not store the master password or root token anywhere

If any check is incomplete, finish it before saying goodbye.
