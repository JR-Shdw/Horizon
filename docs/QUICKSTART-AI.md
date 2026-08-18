# Connect an AI assistant to selected secrets

> This local setup moves credentials out of chat and readable `.env`
> files. An MCP policy controls which secrets the assistant may request:
>
> - the secrets stay in a small encrypted database on your computer ;
> - the AI only sees what you allow ;
> - you can see, after the fact, every secret it read and when ;
> - access can be revoked without deleting a local file.
>
> It does not protect against a compromised host or against disclosure
> by an assistant you explicitly authorize to read a secret. Review the
> bootstrap script and policy before use.

---

## Before you start (1 minute)

You need **three things** on your computer :

1. **Docker** (or **Podman** with the Docker shim) - this runs the
   small server that holds your secrets. If you have Docker Desktop
   already, you're good.
2. **A terminal** - Terminal on macOS, any terminal on Linux, the
   Ubuntu app inside WSL2 on Windows.
3. **About 1 GB of free disk space** for the Docker images.

If you don't have Docker yet :

| Your OS | Get Docker |
|---|---|
| macOS | Install Docker Desktop : https://www.docker.com/products/docker-desktop/ - open it once, accept the prompts. |
| Linux (Debian, Ubuntu, Fedora, Arch, ...) | Use your distribution's package manager. Quickest way : `curl -fsSL https://get.docker.com \| sh` then `sudo usermod -aG docker $USER` and log out / log back in. |
| Windows | Install **WSL2** (search "WSL" in Windows Update / PowerShell : `wsl --install`), then install Ubuntu from the Microsoft Store, then follow the Linux row above **inside the Ubuntu terminal**. |

You also need a **desktop AI assistant with MCP support** (the local
app, not the website) if you want it to use your secrets - for example
Claude Desktop, Cursor, Cline, Continue, or Codex. They all work with
the same setup.

---

## Pick a path : container or native

Two installs are supported, same end-state. Pick whichever fits :

| Path | What it runs | Best for |
|---|---|---|
| **Container** (default, recommended) | A small PostgreSQL + API + frontend in **Docker** containers. | Anyone who already has Docker (Mac, Windows, Linux). Updates via `docker compose pull`. |
| **Native** | PostgreSQL + Python venv + uvicorn running **directly on your host** - no Docker, no containers. | Lighter footprint. WSL2 without Docker Desktop. Linux laptops where you'd rather use your system's PostgreSQL. |

If unsure, take the container path - it's the same script we test against in CI.

### Container path (3 minutes - one command)

Open a terminal. Paste this - **one line, no clone, no setup** :

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh | bash
```

That's it.

If you prefer to inspect the script first (always a good habit) :

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh -o quickstart.sh
less quickstart.sh        # have a look
bash quickstart.sh        # run it
```

If you have already cloned the repo (developers) :

```bash
make laptop               # equivalent to: bash tools/quickstart-laptop.sh
```

### Native path (5 minutes - Linux + WSL2 only)

Same command shape, different script. Native install needs `sudo` to
install PostgreSQL + system libraries - the script will ask for your
password once at the start.

```bash
curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop-native.sh | bash
```

Or from a checkout :

```bash
make laptop-native        # equivalent to: bash tools/quickstart-laptop-native.sh
```

Native install supports : Debian, Ubuntu, Arch, Manjaro, Fedora,
Rocky, AlmaLinux, openSUSE - and any of these running under WSL2.
On macOS, native install isn't supported yet - use the container
path.

Native user installs follow the normal XDG layout:

| Purpose | Path |
|---|---|
| App/source checkout (`curl \| bash`) | `~/.local/share/rhorizon/source` |
| Config, env, local secrets | `~/.config/rhorizon` |
| State, fallback logs, PID files | `~/.local/state/rhorizon` |
| Runtime sockets | `$XDG_RUNTIME_DIR/rhorizon` or `~/.local/state/rhorizon/run` |
| Audit JSONL files | `~/.local/state/rhorizon/audit` |

After install, manage the API like any service :

```bash
# if your distro / WSL2 supports systemd (most do) :
systemctl --user status rhorizon-api
systemctl --user [start|stop|restart] rhorizon-api
journalctl --user -u rhorizon-api -f      # logs

# fallback (no systemd) :
cat ~/.local/state/rhorizon/api.pid       # PID of the running uvicorn
tail -f ~/.local/state/rhorizon/api.log
kill $(cat ~/.local/state/rhorizon/api.pid)  # stop
```

The script will :

1. Build and start a tiny encrypted vault on your computer.
   Container mode uses Docker; native mode uses host PostgreSQL +
   uvicorn.
2. Pick a strong master password for you and save it on disk
   (`~/rhorizon/secrets/master-password` for container installs,
   `~/.config/rhorizon/secrets/master-password` for native installs).
3. Install the small bridge program that lets your AI assistant talk
   to the vault.
4. Give your AI assistant its own access key - separate from yours,
   and read-only by default.
5. Print a small JSON snippet at the end. **Save what it prints**,
   you'll paste it into your AI assistant's config in the next step.

Re-running the script is safe : it skips steps that are already done.

---

## Tell your AI assistant to use the vault (1 minute)

When the script finishes, it prints a block that looks like this :

```json
{
  "mcpServers": {
    "rhorizon": {
      "command": "/home/you/.local/share/rhorizon-mcp/.venv/bin/rhorizon-mcp-server",
      "env": {
        "RH_VAULT_URL": "http://127.0.0.1:8200",
        "RH_TOKEN_FILE": "/home/you/.config/rhorizon/mcp.token",
        "RH_MCP_POLICY": "/home/you/.config/rhorizon-mcp/policy.toml"
      }
    }
  }
}
```

Open your AI assistant's MCP config file and merge the `"rhorizon"`
entry into its `"mcpServers"` section. Each client keeps this file in
its own place. For **Claude Desktop** it lives here :

| Your OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| Windows (WSL) | `%APPDATA%\Claude\claude_desktop_config.json` (open it from Windows Explorer ; the desktop app runs on Windows, not inside WSL) |

**Cursor, Cline, Codex, Continue** and others each have their own
config file (e.g. `.mcp.json` in a project, `~/.codex/config.toml`,
the app's settings) - the same `rhorizon` block goes into their MCP
servers section. See the connector examples shipped under `mcp/`
(`claude.mcp.json`, `codex.config.toml`, `opencode.json`).

If the file doesn't exist, create it with the block above.

If the file does exist, merge the `"rhorizon"` entry into your
existing `"mcpServers"` object - don't lose what's already there.

Quit your AI assistant completely (not just the window - use "Quit"
from the menu bar / system tray), then open it again. In a new
conversation, ask :

> *"What can you do with rhorizon ?"*

It should answer that it has six tools available, all read-only, and
that nothing is whitelisted yet (which is the safe default).

---

## Security boundary after setup

The setup creates these local trust boundaries:

| Where | What it has | Who can read it |
|---|---|---|
| Vault database | Encrypted secret records | The database alone is not sufficient to decrypt them. |
| `~/rhorizon/secrets/master-password` (container) or `~/.config/rhorizon/secrets/master-password` (native) | Master password in clear text | Your account and host root. Mode `0400` blocks other unprivileged users; it does not stop root or compromise of your account. |
| `~/rhorizon/secrets/root-token` (container) or `~/.config/rhorizon/secrets/root-token` (native) | Vault admin token | Your account and host root. |
| `~/.config/rhorizon/mcp.token` | Assistant's read-only vault token | The MCP server, your account, and host root. It is separate from the admin token. |
| `~/.config/rhorizon-mcp/policy.toml` | The list of secrets your AI assistant is allowed to read | Currently **empty**. The assistant can't read anything until you add to this list. |

The laptop quickstart stores the master password beside the local
stack for convenience. Use full-disk encryption and a locked user
session. A stolen unencrypted disk, root access, or compromise of your
account can expose both the encrypted database and its recovery
material. Keep off-host recovery material separate as described in
[`DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md).

Two properties still hold:

1. **You can give your AI assistant one secret without giving it *all*
   secrets.** Each secret you store in the vault stays unreadable to
   the AI until you explicitly add its name to the policy file. Adding
   a second client's secrets next year doesn't open up the first
   client's secrets.

2. **Every read is written down.** When your assistant opens a secret, the
   vault records who asked, which secret, and when, in a journal built so
   that altering or deleting an entry afterwards is detectable. If you ever
   need the journal as evidence, check it first - the vault will tell you
   whether it is intact.

---

## Next steps

[`AI-PROMPTS.md`](AI-PROMPTS.md) contains reviewed prompts for common
operations:

- Add a new secret for a client
- Let your AI assistant read a specific secret for a task
- Revoke an access you no longer need
- Find out what the AI read last week
- Change your master password

Each prompt keeps secret values out of chat and requires review before
commands or configuration changes are approved.

---

## If something goes wrong

| Symptom | First thing to try |
|---|---|
| `docker: command not found` | Install Docker first (see top of this page). |
| `permission denied` on Docker | On Linux, you need to be in the `docker` group : `sudo usermod -aG docker $USER` then log out / log back in. |
| Script ran but your assistant doesn't see "rhorizon" | Did you fully **quit** the app and reopen ? Just closing the window isn't enough - quit from the menu bar / tray icon. |
| Your assistant says "I see rhorizon but no tools" | The policy file is empty (the safe default). Open `AI-PROMPTS.md` and copy the "let the assistant read a secret" prompt. |
| `port already in use` | Another program is using port 8200. Re-run with a different port : `RH_API_PORT=8210 bash tools/quickstart-laptop.sh`. |
| Anything else | Give the assistant the exact error and step number after redacting secrets and local identifiers. The diagnostic sequence is in [`AI-INSTALL-GUIDE.md`](AI-INSTALL-GUIDE.md). |

---

## Tested on

| Platform | Status |
|---|---|
| Linux (Debian, Ubuntu, Arch, Fedora) | Primary platform, tested continuously in CI. |
| macOS (Apple Silicon + Intel) | Supported. Requires Docker Desktop. Same script, same paths under `~/`. Your AI assistant's config path is OS-specific (see the Claude Desktop table above as an example). |
| Windows (WSL2 + Ubuntu) | Supported. Run the script *inside* the WSL2 Ubuntu terminal. The vault listens on `127.0.0.1:8200` of WSL ; your AI assistant runs on Windows and reaches it via `localhost` (WSL2 forwards) and via a `wsl.exe` wrapper for the MCP server itself. The script auto-detects WSL and prints the right Windows-shaped JSON snippet (with `wsl.exe -d <distro>, env ... rhorizon-mcp-server` instead of a bare Linux path). The config path is the Windows one - a desktop app like Claude Desktop is a Windows app, not a WSL app. |

If your platform is missing or broken, open an issue. The macOS and
Windows-WSL paths need to stay smooth.

## Scope - a personal-computer setup

This runs on your laptop and listens only on `127.0.0.1` (your own
machine, nothing else can reach it). Exposing it on the public
internet is a different setup with TLS, reverse proxy, and 2FA,
documented separately in [`DEPLOYMENT.md`](DEPLOYMENT.md).

It also keeps your secrets encrypted and accessible to your AI
assistant on this one computer only. If your laptop dies, restore from
a backup (see the "backup" prompt in [`AI-PROMPTS.md`](AI-PROMPTS.md)).

---

## French version

Version française : [`fr/QUICKSTART-AI.md`](fr/QUICKSTART-AI.md).
