# Signed commits

rhorizon treats signed commits as part of the supply-chain boundary. Container
images, SBOMs, release artifacts, and attestations only mean what they should if
the source commit they describe is also trusted.

## Files

- `.gitsigners` - tracked SSH public keys allowed to sign rhorizon commits and
  tags.
- `tools/check-signed-commits.sh` - local and CI verifier around
  `git verify-commit`.
- `.woodpecker/signed-commits.yml` - Woodpecker gate for pushes, pull requests,
  and manual runs.
- `contrib/git-hooks/pre-receive-require-signed-commits` - server-side hook
  template for Gitea/Forgejo bare repositories.

## Maintainer setup

Configure Git to sign commits and tags with the private key matching a public
key in `.gitsigners`:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/git-signing_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
git config --global gpg.ssh.allowedSignersFile /home/automation/dev/tools/rhorizon/.gitsigners
```

Verify the current commit before pushing:

```sh
tools/check-signed-commits.sh HEAD^..HEAD
```

## Mandatory enforcement

Enable branch protection on `main` in Gitea/Forgejo and require the Woodpecker
`signed-commits` status before merge or push. That blocks normal unsigned
changes from reaching `main`.

For a hard server-side stop against direct pushes, install
`contrib/git-hooks/pre-receive-require-signed-commits` as the repository
`pre-receive` hook on the Gitea/Forgejo server and set:

```sh
RHORIZON_ALLOWED_SIGNERS=/absolute/path/to/rhorizon/.gitsigners
```

This one is **mandatory**: the hook aborts with
`set RHORIZON_ALLOWED_SIGNERS to the tracked .gitsigners file` if it is unset,
which rejects every push to a protected ref.

The hook protects `refs/heads/main` and `refs/heads/release/*` by default. Set
`RHORIZON_SIGNED_REF_REGEX` to change that policy.

`tools/check-signed-commits.sh` reads the same `RHORIZON_ALLOWED_SIGNERS`, but
defaults to the repo's own `.gitsigners` when unset, so local runs need no
configuration.

Historical unsigned commits remain part of history unless the repository is
rewritten. Enforcement starts from the branch-protection or hook activation
point.
