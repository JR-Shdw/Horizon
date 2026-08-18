#!/usr/bin/env bash
# Verify that every commit in a range is signed by a trusted key.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ALLOWED_SIGNERS="${RHORIZON_ALLOWED_SIGNERS:-$ROOT/.gitsigners}"
ZERO_RE='^0{40,64}$'

usage() {
  cat <<'USAGE'
Usage: tools/check-signed-commits.sh [<commit-range>]

Verifies every commit in <commit-range> with git verify-commit.
Without an explicit range, the script chooses a CI-friendly range:
  - CI_COMMIT_BEFORE..CI_COMMIT_SHA when Woodpecker exposes both values
  - origin/<target-branch>..HEAD for pull requests when available
  - origin/main..HEAD for non-main local branches
  - HEAD^..HEAD as the conservative fallback

Set RHORIZON_ALLOWED_SIGNERS to override the trusted SSH signer file.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ ! -s "$ALLOWED_SIGNERS" ]; then
  echo "[FAIL] allowed signers file missing or empty: $ALLOWED_SIGNERS" >&2
  exit 2
fi

choose_range() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$1"
    return
  fi

  if [ -n "${CI_COMMIT_BEFORE:-}" ] && [ -n "${CI_COMMIT_SHA:-}" ] \
    && ! [[ "$CI_COMMIT_BEFORE" =~ $ZERO_RE ]]; then
    printf '%s..%s\n' "$CI_COMMIT_BEFORE" "$CI_COMMIT_SHA"
    return
  fi

  if [ -n "${CI_COMMIT_TARGET_BRANCH:-}" ]; then
    target="origin/$CI_COMMIT_TARGET_BRANCH"
    if git rev-parse --verify "$target" >/dev/null 2>&1; then
      printf '%s..%s\n' "$target" "${CI_COMMIT_SHA:-HEAD}"
      return
    fi
  fi

  branch="${CI_COMMIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || printf 'HEAD')}"
  if [ "$branch" != "main" ] && git rev-parse --verify origin/main >/dev/null 2>&1; then
    printf 'origin/main..%s\n' "${CI_COMMIT_SHA:-HEAD}"
    return
  fi

  if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
    printf 'HEAD^..%s\n' "${CI_COMMIT_SHA:-HEAD}"
  else
    printf '%s\n' "${CI_COMMIT_SHA:-HEAD}"
  fi
}

RANGE="$(choose_range "$@")"
echo "[signed-commits] verifying range: $RANGE"
echo "[signed-commits] trusted signers: $ALLOWED_SIGNERS"

if ! COMMITS="$(git rev-list --reverse "$RANGE")"; then
  echo "[FAIL] cannot enumerate commits for range: $RANGE" >&2
  exit 2
fi

if [ -z "$COMMITS" ]; then
  echo "[OK] no commits to verify"
  exit 0
fi

VERIFY_LOG="$(mktemp "${TMPDIR:-/tmp}/rhorizon-verify.XXXXXX")"
trap 'rm -f "$VERIFY_LOG"' EXIT

FAILED=0
while IFS= read -r commit; do
  [ -n "$commit" ] || continue
  summary="$(git log -1 --format='%h %an <%ae> %s' "$commit")"
  : >"$VERIFY_LOG"
  if git -c "gpg.ssh.allowedSignersFile=$ALLOWED_SIGNERS" verify-commit --raw "$commit" >"$VERIFY_LOG" 2>&1; then
    echo "[OK] signed: $summary"
  else
    echo "[FAIL] unsigned or untrusted commit: $summary" >&2
    sed 's/^/       /' "$VERIFY_LOG" >&2
    FAILED=1
  fi
done <<<"$COMMITS"

exit "$FAILED"
