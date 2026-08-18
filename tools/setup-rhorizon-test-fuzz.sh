#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# tools/setup-rhorizon-test-fuzz.sh - enable `.woodpecker/fuzz.yml`
# on the rhorizon_test local-Forgejo loop (the "outer loop" in the
# local-first doctrine). Companion to `setup-rhorizon-test.sh`
# which only handles validate.yml.
#
# What this does, idempotently :
#   1. Pulls the latest fuzz.yml + GF code from the `src` remote
#      (local filesystem path to ~/dev/tools/rhorizon).
#   2. Re-applies sed patches to `.woodpecker/fuzz.yml` so it runs
#      on the local node-5 Woodpecker agent instead of node-1 :
#        - drops `labels: host: node-1` (any agent picks it up)
#        - swaps `/data/container/obs/fuzz/` -> `/tmp/rhorizon-fuzz-local/`
#        - drops MAX_TIME to 60 (fast iteration, not real coverage)
#   3. mkdir /tmp/rhorizon-fuzz-local/{corpus,artifacts} on node-5
#      (the bind-mount source).
#   4. Commits the local patches on a clearly-labelled commit message,
#      pushes to local Forgejo (`origin`).
#
# After this script :
#   - http://127.0.0.1:8000 (local Woodpecker UI) -> Repositories
#     -> shdw/rhorizon_test should already be active. Trigger fuzz.yml
#     manually OR push another commit ; it now runs locally in ~5 min
#     (vs 2h+ on node-1 with prod MAX_TIME).
#
# When local fuzz.yml run is green :
#   - cd ~/dev/tools/rhorizon  (back to the main working tree)
#   - git push origin main      (push to gitea.example.com / node-1)
#
# Do NOT run this for inner-loop iteration ; use
# `tools/check-fuzz-pipeline.sh` for that (no Forgejo round trip).
#
# Pre-requis :
#   - ~/dev/tools/rhorizon_test already provisioned (run
#     setup-rhorizon-test.sh first)
#   - Remote `src` configured (local FS path to rhorizon main)

set -euo pipefail

TEST_REPO="${TEST_REPO:-$HOME/dev/tools/rhorizon_test}"
LOCAL_FUZZ_DIR="${LOCAL_FUZZ_DIR:-/tmp/rhorizon-fuzz-local}"
LOCAL_MAX_TIME="${LOCAL_MAX_TIME:-60}"

say()  { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32mOK\033[0m  %s\n" "$*"; }
fail() { printf "\033[1;31mFAIL\033[0m  %s\n\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Pre-flight
# ---------------------------------------------------------------------------

[ -d "$TEST_REPO/.git" ] || fail "$TEST_REPO not a git repo - run setup-rhorizon-test.sh first"
cd "$TEST_REPO"
git remote get-url src >/dev/null 2>&1 || fail "remote 'src' missing on rhorizon_test"
git remote get-url origin >/dev/null 2>&1 || fail "remote 'origin' missing on rhorizon_test"

# ---------------------------------------------------------------------------
# 1. Sync from src (local FS path to rhorizon main)
# ---------------------------------------------------------------------------

say "Fetching latest from src remote"
git fetch src
SRC_HEAD=$(git rev-parse src/main)
say "src/main is at $SRC_HEAD"

# If src/main is reachable from HEAD, we already have the changes -
# skip the merge to keep history flat. Otherwise merge with a clear
# message so the test repo's history is readable.
if git merge-base --is-ancestor "$SRC_HEAD" HEAD; then
    ok "rhorizon_test already contains src/main"
else
    say "Merging src/main"
    git -c user.email="ci-test@local" -c user.name="ci-test setup" \
        merge --no-edit "$SRC_HEAD"
    ok "Merged"
fi

# ---------------------------------------------------------------------------
# 2. Sanity : fuzz.yml must exist after the merge
# ---------------------------------------------------------------------------

FUZZ_YML=".woodpecker/fuzz.yml"
[ -f "$FUZZ_YML" ] || fail "$FUZZ_YML missing post-merge - did src/main lose it?"

# ---------------------------------------------------------------------------
# 3. Patch fuzz.yml for local mode
# ---------------------------------------------------------------------------
# Patches must be idempotent - re-running the script after a future
# sync should re-apply cleanly without doubling lines.

say "Patching $FUZZ_YML for local-mode (host label, volumes, MAX_TIME)"

# 3a. Drop the `host: node-1` agent label so the local node-5 agent
#     picks up the pipeline (the local Woodpecker probably advertises
#     a different label, or none). We comment the label block out
#     rather than delete so a future re-sync from src/main doesn't
#     conflict-cleanly with a deletion.
if grep -q "^labels:" "$FUZZ_YML" && ! grep -q "^# labels:" "$FUZZ_YML"; then
    # Comment out `labels:` line and the indented children below it.
    python3 - "$FUZZ_YML" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1])
lines = p.read_text().splitlines(keepends=True)
out = []
i = 0
n = len(lines)
while i < n:
    line = lines[i]
    if line.startswith("labels:"):
        out.append("# [local-mode] " + line)
        i += 1
        # Comment indented children (lines starting with whitespace).
        while i < n and (lines[i].startswith(" ") or lines[i].startswith("\t")):
            out.append("# [local-mode] " + lines[i])
            i += 1
        continue
    out.append(line)
    i += 1
p.write_text("".join(out))
PY
    ok "labels: block commented out"
else
    ok "labels: block already in local-mode (or absent)"
fi

# 3b. Repoint volume bind-mounts from node-1 paths to node-5-local.
if grep -q "/data/container/obs/fuzz/" "$FUZZ_YML"; then
    sed -i "s|/data/container/obs/fuzz/|${LOCAL_FUZZ_DIR}/|g" "$FUZZ_YML"
    ok "Volume paths -> $LOCAL_FUZZ_DIR"
else
    ok "Volume paths already local (or absent)"
fi

# 3c. Drop MAX_TIME from prod 1800 to local LOCAL_MAX_TIME (default 60).
#     Match `MAX_TIME: "<digits>"` so we don't fight quoting variations.
if grep -qE 'MAX_TIME:\s*"[0-9]+"' "$FUZZ_YML"; then
    sed -i -E "s|MAX_TIME:\s*\"[0-9]+\"|MAX_TIME: \"${LOCAL_MAX_TIME}\"|" "$FUZZ_YML"
    ok "MAX_TIME -> ${LOCAL_MAX_TIME}s"
else
    ok "MAX_TIME line not found (skipped)"
fi

# 3d. Add `event: push` to the `when:` clause so a push to the local
#     Forgejo auto-triggers fuzz.yml. The prod fuzz.yml's `when:` only
#     allows cron + manual ; on the local loop we want push-triggered
#     for fast iteration. Idempotent : skip if already patched.
if ! grep -qE '^\s+- event: push.*\[local-mode\]' "$FUZZ_YML"; then
    python3 - "$FUZZ_YML" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
lines = p.read_text().splitlines(keepends=True)
out = []
inserted = False
for i, line in enumerate(lines):
    out.append(line)
    if not inserted and line.startswith("when:"):
        # Insert immediately after `when:` so push-event is the first
        # trigger Woodpecker evaluates.
        out.append("  - event: push  # [local-mode] auto-fire on push from setup-rhorizon-test-fuzz.sh\n")
        inserted = True
p.write_text("".join(out))
PY
    ok "when: gained 'event: push' for local push-triggered fires"
else
    ok "when: already has local-mode push event"
fi

# ---------------------------------------------------------------------------
# 4. Host-side dirs (the bind-mount source)
# ---------------------------------------------------------------------------

say "Creating bind-mount source dirs on node-5"
mkdir -p "$LOCAL_FUZZ_DIR/corpus" "$LOCAL_FUZZ_DIR/artifacts"
ok "$LOCAL_FUZZ_DIR/{corpus,artifacts} ready"

# ---------------------------------------------------------------------------
# 5. Commit + push to local Forgejo
# ---------------------------------------------------------------------------

if git diff --quiet "$FUZZ_YML"; then
    ok "No fuzz.yml changes vs current HEAD - nothing to commit"
else
    say "Committing local-mode patches"
    git -c user.email="ci-test@local" -c user.name="ci-test setup" \
        commit -m "ci(test): fuzz.yml local-mode (node-5, fast)

- labels: host: node-1 commented out (any local agent picks up)
- volumes: /data/container/obs/fuzz/ -> $LOCAL_FUZZ_DIR/
- MAX_TIME: 1800 -> $LOCAL_MAX_TIME (fast iteration, not coverage)

Inner loop (build-time errors) : tools/check-fuzz-pipeline.sh
Outer loop (full pipeline)     : this commit + local Woodpecker UI" \
        -- "$FUZZ_YML"
    ok "Commit created"
fi

say "Pushing to origin (local Forgejo)"
# Use HEAD so the script works whether the rhorizon_test tree is on
# `main` or on a feature branch left over from a previous validate.yml
# iteration (the user's checkout state is not the script's business).
CURRENT_BRANCH="$(git branch --show-current)"
git push origin "$CURRENT_BRANCH"
ok "Pushed $CURRENT_BRANCH"

cat <<EOF


  ================================================================
  rhorizon_test fuzz.yml ready for local-loop iteration.

  Test repo : $TEST_REPO
  Source    : $LOCAL_FUZZ_DIR/
  Budget    : ${LOCAL_MAX_TIME}s / target (4 targets sequential)

  Next steps :
    1. http://127.0.0.1:8000 -> shdw/rhorizon_test -> fuzz.yml
       (manual fire OR push another commit triggers it)
    2. If green : cd ~/dev/tools/rhorizon && git push origin main
       (propagates to gitea.example.com / node-1)
    3. If red  : edit ~/dev/tools/rhorizon/.woodpecker/fuzz.yml,
       re-run THIS script, re-fire local pipeline.

  Inner loop (no Forgejo round trip) :
    bash ~/dev/tools/rhorizon/tools/check-fuzz-pipeline.sh
  ================================================================

EOF
