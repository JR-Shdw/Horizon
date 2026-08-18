# git-credential-rhorizon - adoption guide

End-to-end recipe to stop embedding API tokens in `.git/config` URLs and
fetch them on demand from a rhorizon vault. The example values below
match the layout this project itself uses.

## What you get

Before:

```ini
# .git/config
[remote "origin"]
    url = https://shdw:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@gitea.example.com/shdw/foo.git
```

After:

```ini
# .git/config
[remote "origin"]
    url = https://gitea.example.com/shdw/foo.git
```

Git no longer holds the credential. Every `git fetch / pull / push` calls
the helper, which calls rhorizon, which returns a still-encrypted-on-disk
token. Revoking the token in rhorizon is the only thing that revokes it
across all repos using the helper.

## Prerequisites

- A running rhorizon instance you can reach (e.g. `https://vault.example.com`,
  `http://127.0.0.1:8200` for a local dev install on the same host as Git).
- A vault root token (just for setup - burned after).
- Python 3.10+ on your machine. No third-party deps.

## 1. Store the actual Git credential in the vault

Mint a `git/gitea-api-token` (or whatever name you prefer - the
helper looks it up via the mapping below). Pick a namespace dedicated
to this consumer so the bootstrap token can't read anything else:

```bash
# 1.a - store the secret
curl -X POST "$VAULT_URL/api/v1/vault/secrets/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "gitea-api-token",
    "namespace": "git",
    "value": "<paste your Gitea API token here>"
  }'
```

## 2. Mint a bootstrap token scoped to that namespace

`secrets:r` on the `git` namespace only - leak-blast-radius is one
namespace's worth of secrets:

```bash
curl -X POST "$VAULT_URL/api/v1/vault/tokens/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "git-credential-helper",
    "permissions": {"secrets": "r", "namespaces": ["git"]},
    "allowed_ips": "10.0.0.1/32"
  }'
# Returns the bootstrap token. Plaintext shown ONCE.
```

`allowed_ips` is optional but strongly recommended for service-account
tokens - bind it to the host(s) where Git runs so a leaked bootstrap
token can't be replayed from elsewhere. See the field documentation in
`docs/SECRETS-AND-TOKENS.md` section 2.3.

## 3. Save the helper config

```bash
mkdir -p ~/.config/rhorizon
chmod 700 ~/.config/rhorizon
umask 077

# The bootstrap token from step 2 - never commit, log, or place in history.
read -rsp 'Bootstrap token: ' RH_TOKEN; echo
printf '%s\n' "$RH_TOKEN" > ~/.config/rhorizon/token
unset RH_TOKEN

# Where the helper looks up the vault.
echo 'https://vault.example.com' > ~/.config/rhorizon/url

# host -> secret name mapping. Copy the example and edit:
cp tools/git-credential-rhorizon.examples/git-map.example \
   ~/.config/rhorizon/git-map
$EDITOR ~/.config/rhorizon/git-map
```

The helper refuses to start if `~/.config/rhorizon/token` is anything
other than mode `0600`.

## 4. Install the helper on `$PATH`

Pick one:

```bash
# system-wide (sudo)
sudo install -m 0755 tools/git-credential-rhorizon /usr/local/bin/

# user-only (no sudo)
install -m 0755 tools/git-credential-rhorizon ~/.local/bin/

# or skip $PATH entirely and configure git with the absolute path
git config --global credential.helper \
    "$(readlink -f tools/git-credential-rhorizon)"
```

If installed on `$PATH` as `git-credential-rhorizon`, register it by
short name:

```bash
git config --global credential.helper rhorizon
```

## 5. Strip the embedded credential from existing repos

This is the destructive step - review carefully. The script below walks
every Git repo under `$HOME` and rewrites its `origin` URL in place,
backing up the old config first.

```bash
ts=$(date +%Y%m%d-%H%M%S)
mkdir -p ~/.local/share/credential-cleanup-$ts
while IFS= read -r repo; do
  # Backup
  cp "$repo/.git/config" \
     "$HOME/.local/share/credential-cleanup-$ts/$(echo "$repo" | tr / _).config.bak"
  # Rewrite every remote on this repo
  while IFS= read -r remote; do
    cur=$(git -C "$repo" remote get-url "$remote")
    new=$(echo "$cur" | sed -E 's#://[^@/]+@#://#')
    [ "$cur" = "$new" ] || git -C "$repo" remote set-url "$remote" "$new"
  done < <(git -C "$repo" remote)
done < <(find "$HOME" -type d -name '.git' -prune \
         -exec sh -c 'grep -lE "://[^@/]+@" "$1/config" >/dev/null \
                      && echo "${1%/.git}"' _ {} \;)
```

Verify nothing still has embedded creds:

```bash
find "$HOME" -type d -name '.git' -prune \
  -exec grep -lE 'url = https?://[^@/]+@' {}/config \;
# (should print nothing)
```

## 6. Validate

```bash
# Dry-run the helper without involving git. Returns username + password
# (the password is the API token from the vault).
printf 'protocol=https\nhost=gitea.example.com\n\n' \
  | git-credential-rhorizon get
```

Then a real Git operation:

```bash
git -C ~/dev/some-repo fetch origin
# git asks the helper for credentials, helper hits the vault, fetch works
```

## 7. Burn the root token

The bootstrap token from step 2 is the only credential the helper needs
ongoing. The root token used to mint it / store the secret is no longer
required and should be revoked.

## Operational notes

- **Token rotation**: rotate the Gitea API token. Update the secret in
  rhorizon. Every repo using the helper picks up the new value on the
  next Git operation. No `.git/config` rewrites needed.
- **Bootstrap token rotation**: replace `~/.config/rhorizon/token`
  contents and revoke the old token in the vault. Permission scope of
  the new token must still be `secrets:r` on the right namespace.
- **Multi-host**: copy the helper config to every workstation. Each
  needs its own bootstrap token (so revocation is granular) and its own
  `allowed_ips` value (the IP of that workstation).
- **CI runners**: same flow, but use ephemeral tokens
  (`POST /tokens/ephemeral` with TTL=15min, `allowed_ips` set to the
  runner host). The runner re-mints at job start.
- **Audit**: every fetch via the helper produces a `read_secret` audit
  entry in rhorizon, attributed to the bootstrap token's name. Useful
  for forensics - you can see exactly which workstation pulled which
  secret when.
