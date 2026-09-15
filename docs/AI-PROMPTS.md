# Prompts to give to your AI assistant

Each section below is a self-contained prompt. Replace only the
non-secret `<...>` placeholders before using it. Review commands and
configuration changes before approving them. Never put a secret,
token, or master password in the prompt.

These prompts assume Horizon is already installed and your assistant has a
scoped MCP key. Start with [`AI-INSTALL-GUIDE.md`](AI-INSTALL-GUIDE.md) to choose
between an identity-separated installation and the personal local quickstart.

---

## The rule every prompt here follows

**Your assistant holds exactly one credential: its own key.** That key is
read-only and valid in one section of the vault. It never receives an
administrative credential, and no prompt below tells it where one is kept.

This is not politeness, it is the only thing that makes the rest work. The
assistant's key is bounded by a grant the vault checks on every request, so
whatever the assistant does with it, it cannot reach outside that section. An
admin token is bounded by nothing: it reads every section, mints keys, and locks
the vault. Handing one to an assistant discards the boundary in a single step,
and the assistant does not even have to misbehave for that to matter - anything
that can read its files inherits the same reach.

So when an operation needs more authority than the assistant's key,
**you run the command and the credential stays in your shell.** The assistant
writes the command, explains it, and reads the output you paste back. It does
not open credential files, and you do not paste credentials into the chat.

## How your assistant got its key

| Your situation | How the key was issued |
|---|---|
| **AI-secure install** - identity-separated Linux installation | The script created the governed section, minted a read-only key scoped to it, and granted that key entry. The administrator token **persists at `/etc/rhorizon/secrets/root-token`, readable only by root**. It is never handed to the assistant. |
| **Personal local quickstart** | The script created the governed section and its scoped read-only key. It printed the admin token once for the operator and removed its file. Recovery material and the assistant share a host account; this path does not isolate recovery authority from a same-UID agent. |
| **Existing Horizon** - the vault was already running | An administrator mints a scoped key, grants it entry to one section, and points the assistant's config at it. The assistant is handed the key, never the means to widen it. |

For an existing Horizon installation, this is the operator-side setup. Run it
yourself, with an admin token in your own shell. It is the same shape the
quickstart automates:

```sh
export RH_TOKEN='<your-admin-token>'      # your shell only, never the chat
BASE=http://127.0.0.1:8200/api/v1/vault

# 1. A group that will own the assistant's section.
GID=$(curl -fsS -X POST "$BASE/groups/" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mcp-agents","permissions":{"secrets":"r"}}' | jq -r .id)

# 2. The section, owned by that group, with membership enforced.
#    enforce_membership is set-once: it cannot be relaxed later.
curl -fsS -X POST "$BASE/namespaces/" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"mcp\",\"owner_group_id\":\"$GID\",\"enforce_membership\":true}"

# 3. The assistant's key: read-only, one section.
MINT=$(curl -fsS -X POST "$BASE/tokens/" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mcp-agent","permissions":{"secrets":"r","namespaces":["mcp"]}}')

# 4. Grant that key entry. Until this lands, nothing can read the section.
curl -fsS -X POST "$BASE/groups/$GID/members" -H "Authorization: Bearer $RH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"principal_type\":\"token\",\"principal_id\":\"$(echo "$MINT" | jq -r .id)\"}"

# 5. Give the assistant only the token value from $MINT, in its config file.
unset RH_TOKEN
```

Taking access away later is step 4 in reverse: remove the principal from the
group and the assistant's next request fails. You do not have to re-mint
anything, and you do not have to trust it to stop using a key.

---

## 1. Add a new secret for a client

Use this when a client gives you a password / API key / database URL
and you want to store it in the vault so your AI assistant can use it later.

Writing a secret needs more authority than your assistant's key has, so this
one is a command you run. I have a token with write access exported as
`RH_TOKEN` in my own shell before I start.

```
I'm using rhorizon (a small encrypted secrets vault running on my
laptop). I want to store a new client secret. I already have a token
with write access exported as RH_TOKEN in my shell - do not read it,
print it, or ask me for it, and do not look for any credential file.

Please give me the exact terminal commands to :

  1. Store this secret in the SECTION my assistant can reach, which is
     the namespace "mcp". Use a structured NAME to keep clients apart,
     not a nested namespace : name "clients/<short-name>" (no spaces)
     in namespace "mcp", i.e.

       rhorizon set "clients/<short-name>" --stdin --namespace mcp

     Prompt for the value silently in my terminal and pipe it in. Do not
     ask me to paste it into this chat, place it in a command argument,
     or echo it.

  2. Verify it was saved by listing the namespace.

After running, tell me the fully-qualified name of the new secret
(format : "mcp/clients/<short-name>"). I need it for the next step.

Show the commands before running them. I will enter the secret only at
the hidden terminal prompt.
```

**What this does** : creates an entry inside the one section your assistant's
key may enter. The value is encrypted at rest using your master password's
derived keys.

**Why the name carries the slash and not the namespace.** Namespaces are matched
exactly, never by prefix, so a secret filed under a namespace called
`mcp/clients` would sit *outside* the `mcp` grant and your assistant could never
read it. Keeping the namespace `mcp` and putting the structure in the name gives
the same readable `mcp/clients/<name>` in the policy file, on the right side of
the boundary.

---

## 2. Let your AI assistant read a specific secret

Use this when you have a secret in the vault and you want your AI
assistant to be able to read it through MCP. **Without this step, the MCP
server refuses the read.** A same-UID agent can edit the policy or call the
vault directly with its scoped key; the vault-side grant remains the boundary.

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

**What this does** : removes the secret from the whitelist. The next time your
AI assistant tries to read it, the MCP server returns `policy_denied`. The
secret itself is untouched.

**This is the soft layer, not the boundary.** The policy file lives under your
account, so an assistant that can run shell commands can put the entry back. It
stops mistakes, not intent. To take access away in a way the assistant cannot
undo, move the secret out of its section, or remove its key from the group that
owns the section - then the vault refuses on the next request, whatever the
policy file says.

---

## 4. Find out what the AI read recently

Use this for client reporting, or before/after a session, or just
to see what your AI has been up to.

Reading the audit log needs `audit:r`, which your assistant's key does not
have. Either run this with your own token exported as `RH_TOKEN`, or mint a
dedicated read-only audit key for it the same way you minted its secrets key.

```
I'm using rhorizon. The vault is at http://127.0.0.1:8200. A token with
audit read access is exported as RH_TOKEN in my shell - do not read it,
print it, or ask me for it, and do not look for any credential file.

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

This one is entirely yours to run. Rotating the master password needs both the
current password and an admin token, which are exactly the two things your
assistant must never hold. It can explain the operation and hand you the
commands; every credential stays on your side of the conversation.

```
I'm using rhorizon. I want to change my master password. I will run
every command myself.

Context :
  - the vault is at http://127.0.0.1:8200 ;
  - I hold the current master password and an admin token. Do not ask
    for either, do not read them from any file, and do not include a
    place to paste them in the commands you write - assume they are
    already in my shell as RH_MASTER_PASSWORD and RH_TOKEN ;
  - I want existing access keys (my assistant's, etc.) to keep working
    for a few days while I migrate - NOT immediate invalidation.

Please give me :

  1. A short explanation (3-4 lines) of what's about to happen.
  2. A way to pick a strong new password (suggest a tool, don't
     generate one for me - never put my master password in your
     context).
  3. The exact curl command to rotate the password, reading both
     values from the environment, using emergency=false because of
     point 3 above.
  4. A reminder to update wherever I keep the password, and to re-run
     nothing else.
  5. A reminder that, if I lose this password, the vault contents are
     unrecoverable - and the only protection is a copy in a password
     manager I control.

Don't ask me to type or paste any password or token into the chat.
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
