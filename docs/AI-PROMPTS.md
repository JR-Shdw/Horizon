# Prompts to give to your AI assistant

Each section below is a self-contained prompt. Replace only the
non-secret `<...>` placeholders before using it. Review commands and
configuration changes before approving them. Never put a secret,
token, or master password in the prompt.

These prompts assume you have already run
[`QUICKSTART-AI.md`](QUICKSTART-AI.md). If you haven't, do
that first.

---

## 1. Add a new secret for a client

Use this when a client gives you a password / API key / database URL
and you want to store it in the vault so your AI assistant can use it later.

```
I'm using rhorizon (a small encrypted secrets vault running on my
laptop). My vault is at http://127.0.0.1:8200 and my root token
is in the file ~/rhorizon/secrets/root-token.

Please give me the exact terminal commands to :

  1. Store this secret in the vault, in the namespace "mcp/clients".
     The secret name should be "<short-meaningful-name>" (no spaces).
     Prompt for the value silently in my terminal and pipe it to
     `rhorizon set --stdin`. Do not ask me to paste it into this chat,
     place it in a command argument, or echo it.

  2. Verify the secret was saved by listing the namespace.

After running, tell me the fully-qualified name of the new secret
(format : "mcp/clients/<name>"). I will need it for the next step
(adding it to the policy so your AI assistant can read it).

Show the commands before running them. I will enter the secret only
at the hidden terminal prompt.
```

**What this does** : creates a new entry in the `mcp/clients`
namespace. The value is encrypted at rest using your master
password's derived keys. The local host and any process authorized by
the vault or MCP policy remain inside the trust boundary.

---

## 2. Let your AI assistant read a specific secret

Use this when you have a secret in the vault and you want your AI
assistant to be able to read it. **Without this step,
the secret is invisible to the AI** - that's the safe default.

```
I'm using rhorizon. I want to grant my AI assistant read access to
this secret :

  <paste-the-fully-qualified-name-here>
  (e.g. "mcp/clients/dupont-database-password")

The MCP policy file is at ~/.config/rhorizon-mcp/policy.toml.

Please :

  1. Open that file.
  2. Add the secret name above to the [secrets].whitelist array.
     Don't remove anything that's already in the list.
  3. Show me the new contents of the file before saving.
  4. After I confirm, save it.

Then remind me to FULLY QUIT my AI assistant app (Claude Desktop,
Cursor, Cline...) and reopen it, otherwise the new policy won't load.
```

**What this does** : adds one line to the policy file. Your AI
assistant can now call `vault_get_secret` for that exact secret name, and only
that one. Other secrets stay invisible.

---

## 3. Revoke your AI assistant's access to a secret

Use this when you no longer want your AI assistant to be able to read a secret.
Doesn't delete the secret - only takes your AI assistant's permission away. The
secret stays in the vault.

```
I'm using rhorizon. I want to revoke my AI assistant's access to :

  <paste-the-fully-qualified-name-here>

Please :

  1. Open ~/.config/rhorizon-mcp/policy.toml.
  2. Remove that secret from [secrets].whitelist (and if its
     namespace is in [namespaces].allow, ask me whether to remove
     that too - namespace allow is broader).
  3. Show me the new contents.
  4. After I confirm, save it.

Then tell me to fully quit and reopen my AI assistant so the change
takes effect.
```

**What this does** : removes the secret from the whitelist. The
next time your AI assistant tries to read it, the MCP server returns
`policy_denied`. The secret itself is untouched and still readable
by anyone with the admin (root) token.

---

## 4. Find out what the AI read recently

Use this for client reporting, or before/after a session, or just
to see what your AI has been up to.

```
I'm using rhorizon. The vault is at http://127.0.0.1:8200, my admin
token is in ~/rhorizon/secrets/root-token.

Please give me a single curl command that lists the last 50 audit
entries where the actor is "mcp-agent" (the access key used by my
AI assistant). Format the result as a readable table with columns :
timestamp, action, target. Group by day if there are entries from
multiple days.

Don't include the chain signature column - I just want to see what
was read and when.
```

**What this does** : pulls the last 50 audit log entries for the
MCP token and shows them as a table. The vault audit log is
protected by signed Merkle checkpoints, so changing or deleting a checkpointed
read breaks integrity verification. The newest tail remains pending until its
next checkpoint.

---

## 5. My AI doesn't see rhorizon - debug

Use this when you opened your AI assistant and the `rhorizon` tools
don't appear, or they appear but every call fails.

```
I'm using rhorizon. After running tools/quickstart-laptop.sh and
restarting my AI assistant, [I don't see rhorizon at all / I see
rhorizon but every tool call fails / the AI assistant says the policy
denies everything].

Please walk me through this debug sequence, one step at a time,
asking for the output of each step before moving on :

  1. Is the vault running ? (`docker ps | grep rhorizon_api`)
  2. Is the API healthy ? (`curl -s http://127.0.0.1:8200/health`)
  3. Is the MCP token file present and readable ?
     (`test -s ~/.config/rhorizon/mcp.token && echo present`).
     Do not print the token or ask me to paste it.
  4. Does the token still authenticate ?
     (`curl -s -H "Authorization: Bearer $(cat ~/.config/rhorizon/mcp.token)" \
        http://127.0.0.1:8200/api/v1/vault/tokens/whoami`)
  5. Is the policy file present and parseable ?
     (`cat ~/.config/rhorizon-mcp/policy.toml`)
  6. Is the MCP binary still installed ?
     (`ls -la ~/.local/share/rhorizon-mcp/.venv/bin/rhorizon-mcp-server`)
  7. Does my AI assistant's config file point to the right paths ?
     (e.g. Claude Desktop : inspect
     ~/Library/Application\ Support/Claude/claude_desktop_config.json
     on macOS ; or the equivalent for Cursor / Cline / Codex on my OS).
     Redact tokens and environment values before showing any excerpt.

When we find the problem, give me the exact command to fix it.
Don't suggest anything destructive (no docker prune, no rm of
~/rhorizon/, no policy resets) without asking me first.
```

**What this does** : checks the service, credentials, policy, binary,
and client configuration without printing the token.

---

## 6. Change my master password

Use this if you suspect your master password was seen by someone
else, or as routine hygiene.

```
I'm using rhorizon. I want to change my master password.

Context :
  - the vault is at http://127.0.0.1:8200 ;
  - my current master password is in ~/rhorizon/secrets/master-password ;
  - my root token is in ~/rhorizon/secrets/root-token ;
  - I want existing access keys (my AI assistant's, etc.) to keep working
    for a few days while I migrate - NOT immediate invalidation.

Please give me :

  1. A short explanation (3-4 lines) of what's about to happen.
  2. A way to pick a strong new password (suggest a tool, don't
     generate one for me - never put my master password in your
     context).
  3. The exact curl command to rotate the password (using
     emergency=false because of point 4 above).
  4. The command to update ~/rhorizon/secrets/master-password
     with the new value, and re-`chmod 0400` it.
  5. A reminder that, if I lose this password, the vault contents
     are unrecoverable - and the only protection is to back up
     the new password to a password manager I control.

Don't ask me to type or paste my new password into the chat. I'll
keep it on my side.
```

**What this does** : performs a master password rotation against
the running vault. Existing access keys keep working for a window
of time (~15 days by default), giving you a buffer to update them
without breaking your workflow. After the window, you'll need to
re-mint them.

---

## 7. Back up the vault

Use this on a schedule and before major changes.

```
I'm using rhorizon and want a recoverable off-host backup.

Open docs/DISASTER-RECOVERY.md and follow its documented full
PostgreSQL disaster-recovery procedure. Before running anything:

  1. Explain the recovery path and how I will test a restore.
  2. Encrypt the database backup before it leaves this host.
  3. Keep the master password or recovery shares separate from the
     encrypted database backup. Never place both in one tar archive.
  4. Treat MCP tokens as credentials to re-mint after a restore;
     back up the non-secret policy separately.
  5. Do not invent a raw Docker-volume archive command or run a
     destructive restore command without explicit confirmation.

Show each command and wait for my approval.
```

**What this does** : uses the tested full-DR path without placing the
encrypted database and its recovery material in the same archive.

---

## 8. Guided setup

Use this if you skipped `QUICKSTART-AI.md` and want the AI to
walk you through everything.

```
I want to set up rhorizon (a small encrypted secrets vault) on my
laptop, so my AI assistant (Claude Desktop / Cursor / Cline / opencode) can
read selected secrets in a controlled, auditable way.

I'm running [macOS / Linux distro / Windows with WSL2].

Please open https://raw.githubusercontent.com/JR-Shdw/Horizon/main/docs/AI-INSTALL-GUIDE.md
and walk me through the install, one step at a time. After the
vault is up, also walk me through running
tools/quickstart-laptop.sh, which sets up the MCP bridge to my AI
assistant.

Operating principles :
  - one step at a time, wait for my output before moving on ;
  - don't paste walls of commands ;
  - don't ask for my master password - direct me to a password
    manager ;
  - at every step, tell me what's about to happen and why.
```

**What this does** : asks the assistant to follow the constrained
install guide and stop for verification at each step.

---

## French version

Version française : [`fr/AI-PROMPTS.md`](fr/AI-PROMPTS.md).
