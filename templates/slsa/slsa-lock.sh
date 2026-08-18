#!/usr/bin/env sh
# slsa-lock.sh - vendored supply-chain lock + audit (SLSA consumer hardening).
#
# Convention: every `*requirements*.in` input compiles to a hash-locked `*.txt`
# sibling (pip-compile --generate-hashes). Installs then use:
#     pip install --require-hashes -r <name>.txt
# so a tampered / account-takeover PyPI release cannot be substituted (incl.
# transitive deps).
#
# Usage:  ./slsa-lock.sh {lock|audit|update}        (default: update)
#   lock   - (re)generate every *.txt from its *.in, with sha256 hashes
#   audit  - pip-audit every generated *.txt (fails on a known vulnerability)
#   update - lock then audit (run after bumping a version in a *.in)
#
# Runs pip-tools / pip-audit in a pinned container - no host Python needed.
# Override via env: SLSA_PIP (pip version, default CVE-fixed 26.1.2),
#                   SLSA_PYTHON (base image ref, default 3.12-slim; for max
#                   integrity pin a digest e.g. 3.12-slim@sha256:<digest>).
set -eu

PIP_PIN="${SLSA_PIP:-26.1.2}"
IMAGE="python:${SLSA_PYTHON:-3.12-slim}"

ins=$(find . -name '*requirements*.in' \
        -not -path '*/.git/*' -not -path '*/node_modules/*' \
        -not -path '*/.venv/*' | sed 's|^\./||' | sort)
if [ -z "$ins" ]; then
  echo "[slsa] no *requirements*.in inputs found under $(pwd)"
  exit 0
fi

_run() { docker run --rm -v "$PWD:/work" -w /work "$IMAGE" sh -c "$1"; }

_lock() {
  s="pip install --no-cache-dir -q 'pip==$PIP_PIN' pip-tools"
  for f in $ins; do
    s="$s && pip-compile --generate-hashes --quiet --output-file='${f%.in}.txt' '$f'"
  done
  _run "$s"
  printf '[slsa] locked:'; for f in $ins; do printf ' %s' "${f%.in}.txt"; done; echo
}

_audit() {
  s="pip install --no-cache-dir -q 'pip==$PIP_PIN' pip-audit"
  for f in $ins; do
    t="${f%.in}.txt"
    [ -f "$t" ] && s="$s && echo '[audit] $t' && pip-audit -r '$t'"
  done
  _run "$s"
  echo "[slsa] no known vulnerabilities in locked deps"
}

case "${1:-update}" in
  lock)   _lock ;;
  audit)  _audit ;;
  update) _lock; _audit ;;
  *) echo "usage: $0 {lock|audit|update}" >&2; exit 2 ;;
esac
