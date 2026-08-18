#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
#
# add-headers.sh - idempotently prepend SPDX + copyright headers to source files.
#
# Run from the repo root. Skips vendor dirs, virtualenvs, tests/, empty
# __init__.py, and any file already containing an SPDX-License-Identifier.
#
# Usage:
#   bash scripts/add-headers.sh         # apply
#   bash scripts/add-headers.sh --check # report missing only, no write

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

SPDX="SPDX-License-Identifier: AGPL-3.0-or-later"
COPYRIGHT="Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>"

# Comment style per extension
declare -A HASH_EXT=([py]=1 [sh]=1 [yml]=1 [yaml]=1 [toml]=1 [conf]=1 [ini]=1)
declare -A SLASH_EXT=([js]=1 [mjs]=1 [rs]=1)
declare -A BLOCK_EXT=([css]=1)
declare -A DASH_EXT=([sql]=1)
declare -A HTML_EXT=([html]=1)

EXCLUDES=(
  -not -path './.git/*'
  -not -path './.venv/*'
  -not -path './node_modules/*'
  -not -path './tests/*'
  -not -path './target/*'
  -not -path './dist/*'
  -not -path './build/*'
  -not -path './htmlcov/*'
  -not -path './.ruff_cache/*'
  -not -path './.pytest_cache/*'
  -not -path './__pycache__/*'
  -not -path './opencve/*'
  -not -name 'versions.env'
)

added=0
skipped=0
checked=0

while IFS= read -r -d '' file; do
  checked=$((checked + 1))
  ext="${file##*.}"

  # Skip empty __init__.py (only whitespace)
  if [[ "$(basename "$file")" == "__init__.py" ]] && [[ ! -s "$file" || -z "$(tr -d '[:space:]' < "$file")" ]]; then
    skipped=$((skipped + 1))
    continue
  fi

  # Already has header -> skip
  if head -10 "$file" | grep -q "SPDX-License-Identifier"; then
    skipped=$((skipped + 1))
    continue
  fi

  # Build header by comment style
  header=""
  if [[ -n "${HASH_EXT[$ext]:-}" ]]; then
    header="# ${SPDX}"$'\n'"# ${COPYRIGHT}"$'\n'
  elif [[ -n "${SLASH_EXT[$ext]:-}" ]]; then
    header="// ${SPDX}"$'\n'"// ${COPYRIGHT}"$'\n'
  elif [[ -n "${BLOCK_EXT[$ext]:-}" ]]; then
    header="/* ${SPDX} */"$'\n'"/* ${COPYRIGHT} */"$'\n'
  elif [[ -n "${DASH_EXT[$ext]:-}" ]]; then
    header="-- ${SPDX}"$'\n'"-- ${COPYRIGHT}"$'\n'
  elif [[ -n "${HTML_EXT[$ext]:-}" ]]; then
    header="<!-- ${SPDX} -->"$'\n'"<!-- ${COPYRIGHT} -->"$'\n'
  else
    skipped=$((skipped + 1))
    continue
  fi

  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "MISSING: $file"
    added=$((added + 1))
    continue
  fi

  # Preserve shebang / xml decl / html doctype on first line; preserve mode.
  first_line="$(head -1 "$file")"
  tmp="$(mktemp)"
  case "$first_line" in
    '#!'*|'<?'*|'<!DOCTYPE'*|'<!doctype'*)
      {
        printf '%s\n' "$first_line"
        printf '%s' "$header"
        tail -n +2 "$file"
      } > "$tmp"
      ;;
    *)
      {
        printf '%s' "$header"
        cat "$file"
      } > "$tmp"
      ;;
  esac
  # Overwrite content in place to preserve mode + ownership
  cat "$tmp" > "$file"
  rm -f "$tmp"
  added=$((added + 1))
  echo "ADDED:   $file"
done < <(find . -type f \( \
  -name '*.py' -o -name '*.sh' -o -name '*.js' -o -name '*.mjs' \
  -o -name '*.css' -o -name '*.sql' -o -name '*.html' -o -name '*.rs' \
  -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' \
  \) "${EXCLUDES[@]}" -print0)

echo
echo "Scanned: $checked  |  Added: $added  |  Skipped: $skipped"
if [[ "$CHECK_ONLY" -eq 1 && "$added" -gt 0 ]]; then
  exit 1
fi
