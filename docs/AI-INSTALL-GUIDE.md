# Install Horizon with an AI assistant

Applies to Horizon 0.9.5-beta.

This page is the instruction sheet to give an AI assistant. It covers a local
installation, not an Internet-facing or HA deployment. Read every command
before approving it. An assistant can misunderstand the machine or propose a
command outside this guide.

Never paste a master password, root token, MCP token, private key, `.env` file,
hostname or private address into chat. When reporting an error, redact those
values first.

## Instructions for the assistant

Ask which operating system is in use and whether the user wants convenience or
an operating-system boundary from the AI process. Explain the difference before
showing a command.

### Personal local install

Use [`QUICKSTART-AI.md`](QUICKSTART-AI.md). This is the convenient path for
macOS, Windows/WSL and Linux. It binds Horizon to localhost and gives the MCP
client a vault-scoped token, but the recovery files and the assistant normally
share the same user account. Software running as that user can read those
files. Docker group membership is normally root-equivalent on Linux.

Do not describe this path as protection against a compromised or hostile local
agent. Its security boundary is the vault grant, not the host identity.

### Identity-separated install for an AI tool

This path is currently validated on Linux. Horizon runs as the non-login
`rhorizon` service account. The master password and administrator token remain
under `/etc/rhorizon/secrets`, readable only by root. The user's AI process
receives only a token restricted to the governed `mcp` namespace.

This protects recovery authority after installation. It cannot make blindly
approving arbitrary root commands safe: `sudo` authorises the code being run.
Use a reviewed release in a root-owned source directory.

Run one command at a time and wait for its result.

1. Choose the published release and clone it directly into a root-owned path:

   ```bash
   sudo git clone --branch v0.9.5-beta --depth 1 https://github.com/JR-Shdw/Horizon.git /usr/local/src/rhorizon
   ```

   If that directory already exists, stop. Do not delete, overwrite or update it
   without the user's explicit approval. The release contents and verification
   options are documented in [`verifying-releases.md`](verifying-releases.md).

2. Confirm the checkout cannot be modified by the login account:

   ```bash
   test ! -w /usr/local/src/rhorizon && echo "source is not writable by this account"
   ```

3. Run the dedicated onboarding script. Replace `YOUR_ACCOUNT` with the
   non-root account that runs the AI client; obtain it with `id -un`, not by
   guessing:

   ```bash
   sudo /usr/local/src/rhorizon/tools/quickstart-ai-system.sh --user YOUR_ACCOUNT
   ```

   The script must stop if that account is root, can rewrite the source tree,
   belongs to the `docker` group, can write the Docker socket, or has
   passwordless sudo/doas. Do not bypass those checks.

4. The user enters the master password twice in the terminal. Do not request it
   in chat and do not suggest an environment variable or command-line option.

5. At completion, give the user the printed MCP configuration block. Do not ask
   to read either recovery file. The expected separation is:

   | Material | Owner and location |
   |---|---|
   | Master password | root only, `/etc/rhorizon/secrets/master-password` |
   | Administrator token | root only, `/etc/rhorizon/secrets/root-token` |
   | MCP token | target account, `~/.config/rhorizon/mcp.token` |
   | Local MCP policy | target account, `~/.config/rhorizon-mcp/policy.toml` |

The policy starts with an empty secret whitelist. The target account can edit
that local file, but doing so cannot broaden the token's vault-side namespace
membership.

## Verification

Do not declare success from a running service alone. Ask the user to run:

```bash
sudo systemctl status rhorizon.service --no-pager
sudo test -r /etc/rhorizon/secrets/root-token && echo "root recovery token present"
test ! -r /etc/rhorizon/secrets/root-token && echo "recovery token hidden from login account"
test -r "$HOME/.config/rhorizon/mcp.token" && echo "scoped MCP token present"
```

The service should run as `rhorizon`; the unprivileged read check must fail; the
MCP token check must succeed. The self-signed TLS certificate is copied to the
target account for the MCP client, so no skip-verification flag is needed.

## Stop conditions

Stop and point to the named document when the request changes scope:

- public or production exposure: [`DEPLOYMENT.md`](DEPLOYMENT.md);
- high availability: [`HA-CLUSTER.md`](HA-CLUSTER.md);
- Kubernetes: [`K8S.md`](K8S.md);
- a security report: [`../SECURITY.md`](../SECURITY.md).

Never add the user to the Docker group, disable TLS verification, expose a
localhost installation on all interfaces, weaken file permissions, put a
secret in argv/environment/chat, or continue after a failed security check.

Version française : [`fr/AI-INSTALL-GUIDE.md`](fr/AI-INSTALL-GUIDE.md).
