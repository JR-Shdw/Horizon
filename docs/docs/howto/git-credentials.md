# Git credentials from the vault

`rhorizon-git` links a repository to a token stored in the vault. You choose
the repository, the remote, the vault and the secret. Git then reads the token
from the vault on each fetch or push, and `.git/config` holds only the secret
name.

The setting is local to one repository, so two repositories on the same forge
can use different tokens.

## Install

It is one file and needs `python3` (3.9 or newer) and `git`.

From a checkout, on the current machine:

```bash
install -D -m 0755 tools/rhorizon-git ~/.local/bin/rhorizon-git
```

To another host:

```bash
scp tools/rhorizon-git host.example:.local/bin/rhorizon-git
```

From the public repository:

```bash
curl -fsSL -o ~/.local/bin/rhorizon-git \
  https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/rhorizon-git
chmod 0755 ~/.local/bin/rhorizon-git
```

With Ansible:

```yaml
- name: Install rhorizon-git
  ansible.builtin.copy:
    src: tools/rhorizon-git
    dest: /usr/local/bin/rhorizon-git
    mode: "0755"
```

Install it before running `setup`. The linked repository calls the file from
the path it had during `setup`, so run `setup` again if you move it.

## Prepare the vault

Store the forge token. `rhorizon-git setup` can also do this for you if the
vault token has `secrets:w`.

```bash
printf '%s' "$FORGE_TOKEN" | rhorizon set app-github --namespace git --stdin
```

Mint a read-only vault token for the host:

```bash
curl -X POST "$VAULT_URL/api/v1/vault/tokens/" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"git-host-a","permissions":{"secrets":"r","namespaces":["git"]}}'
```

## Link a repository

Run it with no options and answer the prompts:

```text
$ rhorizon-git setup
Repository path [/home/me/dev/app]:
Remote:
  1) origin  https://gitea.example/me/app.git
  2) add a new remote
Choice [1]: 1
Remote URL [https://gitea.example/me/app.git]: https://github.com/acme/app.git
Vault:
  1) add a new vault
Choice [1]: 1
Vault name (for example lab): lab
Vault URL (for example https://vault.example:8443): https://vault.example:8443
Vault CA file (empty for the system CAs): /home/me/.config/rhorizon/lab-ca.pem
Vault token file [/home/me/.config/rhorizon/lab.token]:
Vault token (hidden):
Secret holding the git token:
  1) git/app-github
  2) type a secret name
  3) store a new token in the vault
Choice [1]: 1

Repository  /home/me/dev/app
Remote      origin: https://gitea.example/me/app.git -> https://github.com/acme/app.git
Vault       https://vault.example:8443
Secret      git/app-github (username x-access-token)
Apply? (y/n) [n]: y
Linked and verified: git ls-remote origin works.
```

The vault is saved as a profile, so the next repository only needs its name.

Check the result:

```text
$ rhorizon-git status
origin  https://github.com/acme/app.git
  secret: git/app-github
```

## Unattended use

Pass every value as an option:

```bash
rhorizon-git setup \
  --repo ~/dev/app \
  --remote origin \
  --url https://github.com/acme/app.git \
  --vault lab \
  --secret git/app-github \
  --yes
```

Without a saved profile, replace `--vault` with the vault details:

```bash
rhorizon-git setup --repo ~/dev/app --remote origin \
  --url https://github.com/acme/app.git \
  --vault-url https://vault.example:8443 \
  --token-file ~/.config/rhorizon/lab.token \
  --secret git/app-github --yes
```

## Options

| Option | Purpose |
|---|---|
| `--repo PATH` | Repository to link |
| `--remote NAME` | Remote to change, created if missing |
| `--url URL` | New remote URL |
| `--vault NAME` | Profile from `vaults.ini` |
| `--vault-url URL` | Vault URL, used instead of a profile |
| `--token-file PATH` | Vault token file, used with `--vault-url` |
| `--ca-file PATH` | Vault CA file, used with `--vault-url` |
| `--allow-insecure-vault` | Accept a plain http vault outside localhost |
| `--secret NS/NAME` | Secret holding the forge token |
| `--username NAME` | Git username for the forge |
| `--yes` | Apply without the final question |
| `--no-verify` | Skip the `git ls-remote` check |

## What it does

- **Remote URL:** `git@host:org/app.git` becomes `https://host/org/app.git`, and
  a token embedded in a URL is removed.
- **Username:** `x-access-token` on github.com, `oauth2` on gitlab.com. Other
  forges prompt for one, or take `--username`.
- **Other credential helpers:** they stay active for other hosts and are
  skipped for the linked host in this repository.
- **Verification:** after applying, it runs `git ls-remote`. If that fails, the
  previous remote and credential settings are restored.

## Several secrets

One vault token can serve many repositories. Each repository stores the name
of its own secret, and the tool reads only that secret:

```text
~/dev/app     github.com  ->  git/app-github
~/dev/tools   github.com  ->  git/tools-github
~/dev/app     gitea.example  ->  git/app-gitea
```

The link is per repository and per host. Link a second host by running `setup`
again with the other remote. Running `setup` again on the same host replaces
the link. Each secret holds one single-line token.

## Vault over TLS

Use the vault's TLS port, `:8443` by default. For a private vault, create the
certificate and trust it with `rhorizon-tls`, as shown in
[Private certificate](tls.md#private-certificate). Once `ca.pem` is trusted
machine-wide, leave the CA file empty. Otherwise pass `ca.pem` as the CA file.

A plain http vault outside localhost is refused. To accept one, pass
`--allow-insecure-vault`. Tokens then travel unencrypted.

## Vault profiles

Profiles live in `~/.config/rhorizon/vaults.ini`, mode 0600. Set `RH_CONFIG_DIR`
to use another directory.

```ini
[lab]
url = https://vault.example:8443
token_file = /home/me/.config/rhorizon/lab.token
ca_file = /home/me/.config/rhorizon/lab-ca.pem
```

The token file must be mode 0600.

## Troubleshooting

| Message | Fix |
|---|---|
| `vault ... is sealed` | Unseal the vault, then run `setup` again |
| `vault rejected the token` | The token file must hold a vault token, not the forge token |
| `is plain http` | Use the vault's `https://` URL, usually on `:8443` |
| `certificate not trusted` | Set the CA file, and check the SAN names the vault address |
| `TLS failed` | Connect to the TLS port, usually `:8443` |
| `vault answered 403` | Add the namespace to the vault token |
| `vault answered 404` | Check the `namespace/name` of the secret |
| `... is too open` | `chmod 0600` the vault token file |
| `remote check failed` | Check the forge token and its access to the repository |

To test what Git receives, without printing the token:

```bash
printf 'url=https://github.com/acme/app.git\n\n' \
  | git -C ~/dev/app credential fill | sed 's/^password=.*/password=<hidden>/'
```
