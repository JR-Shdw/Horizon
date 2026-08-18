#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# tools/setup-rhorizon-test.sh - provisions a CI TEST repo on the local
# Forgejo (devinfra) + a dedicated checkout outside the main repo.
#
# Goal: iterate on the `.woodpecker/validate.yml` pipelines (45 min on
# remote CI, 5-10 min on local CI) without touching the prod `rhorizon`
# repo or its instance.
#
# Prerequisites (all already in place on node-5):
#   - Local Forgejo at http://127.0.0.1:3000
#   - Local Woodpecker at http://127.0.0.1:8000 (agent + server)
#   - Local rhorizon vault at http://127.0.0.1:8200
#   - Vault token at ~/.config/rhorizon/dev-infra/token (scope
#     secrets:r on the forgejo namespace)
#   - Secret `forgejo/admin-password` in the vault
#
# Usage:
#
#     bash tools/setup-rhorizon-test.sh
#
# Steps performed:
#   1. Reads admin-password from the local vault (never written to disk)
#   2. Creates the `shdw/rhorizon_test` repo on the local Forgejo via the
#      admin basic-auth API (idempotent: skip if already there)
#   3. Clones the current `rhorizon` repo into ~/dev/tools/rhorizon_test
#   4. Neutralises `.woodpecker/{deploy,release,scan}.yml`
#      (renamed to .disabled) - to keep ONLY validate.yml on the test repo
#   5. Reconfigures the `origin` remote to the local Forgejo
#   6. Initial push
#
# Remaining manual step (10 seconds of UI when you have a browser):
#   - http://127.0.0.1:8000 -> Repositories -> "Add" on shdw/rhorizon_test
#   - That's all. No secret to copy (validate.yml uses none).

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FORGEJO_URL="${FORGEJO_URL:-http://127.0.0.1:3000}"
FORGEJO_USER="${FORGEJO_USER:-shdw}"
VAULT_URL="${RHORIZON_VAULT_URL:-http://192.168.10.1:8200}"
VAULT_TOKEN_FILE="${RHORIZON_VAULT_TOKEN_FILE:-$HOME/.config/rhorizon/dev-infra/token}"
SOURCE_REPO="${SOURCE_REPO:-$HOME/dev/tools/rhorizon}"
TEST_REPO="${TEST_REPO:-$HOME/dev/tools/rhorizon_test}"
TEST_REPO_NAME="${TEST_REPO_NAME:-rhorizon_test}"

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()  { printf "\033[1;32mOK\033[0m  %s\n" "$*"; }
die() { printf "\n\033[1;31mFAIL\033[0m  %s\n\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Fetch admin-password from the local vault
# ---------------------------------------------------------------------------

say "Reading Forgejo admin-password from vault $VAULT_URL"

[ -r "$VAULT_TOKEN_FILE" ] || die "Vault token not found at $VAULT_TOKEN_FILE"
VAULT_TOKEN="$(cat "$VAULT_TOKEN_FILE")"

# Vault returns JSON {"name": "...", "value": "..."}. We parse only on
# stdout, never store the password to disk.
admin_pass_json=$(curl -fsS -H "Authorization: Bearer $VAULT_TOKEN" \
    "$VAULT_URL/api/v1/vault/secrets/admin-password?namespace=forgejo" 2>&1) \
    || die "Vault fetch failed. Response: $admin_pass_json"

ADMIN_PASSWORD=$(printf '%s' "$admin_pass_json" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["value"])')

[ -n "$ADMIN_PASSWORD" ] || die "admin-password is empty"
ok "admin-password retrieved (length=${#ADMIN_PASSWORD})"

# ---------------------------------------------------------------------------
# 2. Create the repo on the local Forgejo (idempotent)
# ---------------------------------------------------------------------------

say "Checking / creating $FORGEJO_USER/$TEST_REPO_NAME on $FORGEJO_URL"

# Try GET first : if 200, repo exists, skip create.
http_code=$(curl -sS -o /tmp/forgejo_check.json -w '%{http_code}' \
    -u "$FORGEJO_USER:$ADMIN_PASSWORD" \
    "$FORGEJO_URL/api/v1/repos/$FORGEJO_USER/$TEST_REPO_NAME")

if [ "$http_code" = "200" ]; then
    ok "Repo $FORGEJO_USER/$TEST_REPO_NAME already exists - reusing"
else
    create_resp=$(curl -sS -X POST \
        -u "$FORGEJO_USER:$ADMIN_PASSWORD" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$TEST_REPO_NAME\",
            \"description\": \"Mirror of shdw/rhorizon for CI iteration testing - validate.yml only, no deploy/release/scan.\",
            \"private\": true,
            \"auto_init\": false,
            \"default_branch\": \"main\"
        }" \
        "$FORGEJO_URL/api/v1/user/repos" 2>&1)
    repo_id=$(printf '%s' "$create_resp" \
        | python3 -c 'import sys, json
d = json.load(sys.stdin)
if "id" in d:
    print(d["id"])
else:
    print("error:", d, file=sys.stderr)
    sys.exit(1)
' 2>&1)
    [ -n "$repo_id" ] || die "Repo creation failed. Response: $create_resp"
    ok "Repo created (id=$repo_id)"
fi

# ---------------------------------------------------------------------------
# 3. Clone the source repo to the test checkout (idempotent)
# ---------------------------------------------------------------------------

say "Cloning $SOURCE_REPO -> $TEST_REPO"

if [ -d "$TEST_REPO" ]; then
    if [ -d "$TEST_REPO/.git" ]; then
        ok "Test checkout already exists at $TEST_REPO - reusing"
    else
        die "$TEST_REPO exists but is not a git repo. Move it aside first."
    fi
else
    git clone "$SOURCE_REPO" "$TEST_REPO"
    ok "Cloned to $TEST_REPO"
fi

cd "$TEST_REPO"

# ---------------------------------------------------------------------------
# 4. Neutralise the pipelines that touch prod / the registry
# ---------------------------------------------------------------------------

say "Neutralising .woodpecker/{deploy,release,scan}.yml"

for f in deploy.yml release.yml scan.yml reproducibility.yml verify-upstream.yml prune.yml; do
    src=".woodpecker/$f"
    dst=".woodpecker/$f.disabled"
    if [ -f "$src" ]; then
        git mv "$src" "$dst" 2>/dev/null || mv "$src" "$dst"
        ok "Disabled $src"
    fi
done

# Only validate.yml remains active. Commit if anything changed.
if ! git diff --quiet HEAD --; then
    git -c user.email="ci-test@local" -c user.name="ci-test setup" \
        commit -am "ci(test): disable deploy/release/scan pipelines on rhorizon_test

This repo is dedicated to fast CI iterations: only validate.yml runs;
the pipelines that touch the prod stack (deploy.yml), publish images
(release.yml) or scan existing images (scan.yml, reproducibility.yml,
verify-upstream.yml, prune.yml) are neutralised (renamed .disabled).

Workflow:
  1. Edit here (or cherry-pick from ~/dev/tools/rhorizon)
  2. git push origin main
  3. Local Woodpecker runs validate.yml (~5-10 min vs 45+ remote)
  4. If green: propagate to the real prod repo
     git push prod main"
    ok "Disable commit created"
fi

# ---------------------------------------------------------------------------
# 5. Configure remote -> Forgejo local
# ---------------------------------------------------------------------------

say "Configuring remote 'origin' -> Forgejo local"

# Re-target origin. We use HTTPS basic auth via .netrc style env, no
# token saved to disk in this script.
ORIGIN_URL="$FORGEJO_URL/$FORGEJO_USER/$TEST_REPO_NAME.git"
git remote set-url origin "$ORIGIN_URL"
ok "origin -> $ORIGIN_URL"

# Also keep a 'prod' remote pointing at the canonical source so the
# operator can `git push prod main` to propagate validated changes.
SOURCE_REMOTE=$(cd "$SOURCE_REPO" && git remote get-url origin 2>/dev/null || true)
if [ -n "$SOURCE_REMOTE" ]; then
    git remote remove prod 2>/dev/null || true
    git remote add prod "$SOURCE_REMOTE"
    ok "prod   -> $SOURCE_REMOTE"
fi

# ---------------------------------------------------------------------------
# 6. Initial push to the local Forgejo
# ---------------------------------------------------------------------------

say "Pushing main to $ORIGIN_URL"

# .netrc-style credentials via env so the password doesn't appear in
# git config. ASKPASS works for the duration of one push.
export GIT_ASKPASS_USER="$FORGEJO_USER"
askpass_script=$(mktemp)
chmod 700 "$askpass_script"
trap 'rm -f "$askpass_script"' EXIT
cat > "$askpass_script" <<EOF
#!/usr/bin/env bash
case "\$1" in
    *Username*) echo "$FORGEJO_USER" ;;
    *Password*) printf '%s' "\$RHORIZON_TEST_PUSH_PW" ;;
esac
EOF

RHORIZON_TEST_PUSH_PW="$ADMIN_PASSWORD" \
GIT_ASKPASS="$askpass_script" \
    git push --set-upstream origin main

ok "Pushed main to $ORIGIN_URL"

# ---------------------------------------------------------------------------
# 7. Final instructions
# ---------------------------------------------------------------------------

cat <<EOF


  ================================================================
  rhorizon_test repo ready on Forgejo local.

  Repo URL    : $FORGEJO_URL/$FORGEJO_USER/$TEST_REPO_NAME
  Local path  : $TEST_REPO

  Last step (Woodpecker UI, ~10 seconds when you have a browser):
    1. Open  http://127.0.0.1:8000
    2. Click "Add Repository"
    3. Toggle ON  shdw/$TEST_REPO_NAME
    4. Confirm.
  No secret to copy - validate.yml uses none.

  Recommended iteration workflow:
    cd $TEST_REPO
    # ... edit / commit ...
    git push origin main          # local CI runs in ~5-10 min
    # when green:
    git push prod main            # propagates to gitea.example.com
  ================================================================

EOF
