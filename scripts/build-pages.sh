#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
set -euo pipefail

# Build the GitHub Pages site: mkdocs documentation at the root, the mocked
# frontend demo under /demo/.
#
# Usage: scripts/build-pages.sh [output_dir]
#
# The published site lives at a SUBPATH (/Horizon/), not a domain root, so the
# frontend's root-relative references have to be rewritten. They are correct in
# the repository, because the real deployment does serve the app from /, which
# is why the rewrite happens here and never in frontend/ itself.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$REPO_ROOT/_site}"
SITE_URL="${PAGES_SITE_URL:-https://jr-shdw.github.io/Horizon/}"
VENV="$REPO_ROOT/.venv-pages"

cd "$REPO_ROOT"

# 1. TOOLCHAIN
# Project-local venv: mkdocs-material is a build dependency, never installed
# system-wide.
if [ ! -x "$VENV/bin/mkdocs" ]; then
    echo "[pages] Creating build venv..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" -q install mkdocs-material pymdown-extensions
fi

rm -rf "$OUT"

# 2. DOCUMENTATION
# site_url is overridden on a throwaway copy so the committed mkdocs.yml keeps
# pointing at the canonical site. It drives canonical links and sitemap.xml, so
# it must match where this build is actually served.
echo "[pages] Building documentation (site_url=$SITE_URL)..."
# mkdocs resolves docs_dir relative to the config file, so the override copy
# has to sit beside the original -- in /tmp it would look for /tmp/docs.
TMP_CFG="docs/.mkdocs.pages.yml"
trap 'rm -f "$REPO_ROOT/$TMP_CFG"' EXIT
sed "s|^site_url:.*|site_url: $SITE_URL|" docs/mkdocs.yml > "$TMP_CFG"

# --strict: a broken cross-reference fails the build instead of shipping a
# dead link.
NO_MKDOCS_2_WARNING=1 "$VENV/bin/mkdocs" build \
    -f "$TMP_CFG" --strict -d "$OUT" 2>&1 | grep -vE '^\s*$' || true

if [ ! -f "$OUT/index.html" ]; then
    echo "[ERROR] documentation build produced no index.html"
    exit 1
fi

# 3. DEMO
echo "[pages] Assembling frontend demo..."
mkdir -p "$OUT/demo"
cp -r frontend/. "$OUT/demo/"

cd "$OUT/demo"

# Server-side and build-only artifacts mean nothing on a static host.
rm -f Dockerfile nginx.conf nginx-tls.conf 15-tls-setup.sh 25-upstream-watch.sh sw.js

# Root-relative -> relative, for the subpath.
sed -i -E 's#(src|href)="/#\1="#g' index.html
sed -i -e 's|"start_url": "/"|"start_url": "./"|' \
       -e 's|"scope": "/"|"scope": "./"|' \
       -e 's|"src": "/icons/|"src": "icons/|g' manifest.json

# Demo mode is unconditional here: there is no backend, so the real api() must
# never run, not even if a visitor arrives without ?demo. demo.js reads this
# flag, so no change to demo.js is needed.
python3 - <<'PY'
import io
p = "index.html"
s = io.open(p, encoding="utf-8").read()
anchor = '<script src="demo.js"></script>'
if "__RH_DEMO__ = true" not in s:
    assert s.count(anchor) == 1, "demo.js script tag not found exactly once"
    s = s.replace(anchor, '<script>window.__RH_DEMO__ = true;</script>\n' + anchor, 1)
sw = [l for l in s.splitlines() if "serviceWorker" in l]
for l in sw:
    s = s.replace(l, "<!-- service worker not registered in the Pages demo -->")
io.open(p, "w", encoding="utf-8").write(s)
PY

# 4. VERIFY
echo "[pages] Verifying..."
FAIL=0

if [ "$(grep -coE '(src|href)="/' index.html)" != "0" ]; then
    echo "[ERROR] root-relative references remain in demo/index.html:"
    grep -oE '(src|href)="/[^"]*"' index.html | head -10
    FAIL=1
fi

for f in $(grep -oE '(src|href)="[^"]*"' index.html \
           | sed 's/.*="//;s/"$//' \
           | grep -vE '^(https?:|//|#|mailto:)' | sed 's/?.*//' | sort -u); do
    if [ ! -e "$f" ]; then
        echo "[ERROR] demo references a missing file: $f"
        FAIL=1
    fi
done

grep -q '__RH_DEMO__ = true' index.html || {
    echo "[ERROR] demo mode flag not injected"; FAIL=1; }

[ "$FAIL" -eq 0 ] || exit 1

cd "$OUT"
echo "[OK] $(find . -name '*.html' | wc -l) html pages, $(find . -type f | wc -l) files, $(du -sh . | cut -f1)"
echo
echo "Preview:  python3 -m http.server 8000 -d $OUT"
echo "Deploy :  git -C $OUT init -b gh-pages && git -C $OUT add -A \\"
echo "          && git -C $OUT commit -m 'docs: publish pages site' \\"
echo "          && git -C $OUT push -f https://github.com/JR-Shdw/Horizon.git gh-pages"
echo "Then   :  Settings -> Pages -> Source: deploy from branch -> gh-pages / (root)"
