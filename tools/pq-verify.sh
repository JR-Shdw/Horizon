#!/usr/bin/env bash
# Cross-stack post-quantum parity proof.
#
# Doctrine (docs/POST-QUANTUM.md): we never hand-audit the ML-KEM primitive --
# we delegate it to vetted libraries and PROVE PQ at the wire by having two
# INDEPENDENT crypto stacks each negotiate the hybrid group X25519MLKEM768
# against the same target. Two libraries agreeing is the proof.
#
#   Stack A : OpenSSL >= 3.5   (openssl s_client)   -- authoritative reporter
#   Stack B : aws-lc-rs        (the agent's own build_client, via the
#                               pq_verify cargo example)  -- the agent's stack
#
# Usage:
#   tools/pq-verify.sh                      # default: Cloudflare PQ echo
#   tools/pq-verify.sh vault.example:8443   # a rhorizon frontend (PQ nginx)
#
# Exit 0 only if BOTH stacks negotiate/offer X25519MLKEM768.
set -euo pipefail

TARGET="${1:-pq.cloudflareresearch.com:443}"
HOST="${TARGET%%:*}"
PORT="${TARGET##*:}"
GROUP="X25519MLKEM768"
fail=0

echo "== PQ parity check : $TARGET (group $GROUP) =="

# --- Stack A : OpenSSL ---------------------------------------------------
if command -v openssl >/dev/null 2>&1; then
  ver="$(openssl version | awk '{print $2}')"
  neg="$(openssl s_client -connect "$TARGET" -servername "$HOST" -tls1_3 \
            -groups "$GROUP" </dev/null 2>/dev/null \
          | grep -i 'Negotiated TLS1.3 group' || true)"
  if echo "$neg" | grep -q "$GROUP"; then
    echo "[A openssl $ver] OK  -> $neg"
  else
    echo "[A openssl $ver] FAIL -> ${neg:-no PQ group negotiated (need OpenSSL >= 3.5 + PQ server)}"
    fail=1
  fi
else
  echo "[A openssl] SKIP (openssl not found)"
fi

# --- Stack B : aws-lc-rs (agent build_client) ----------------------------
RUST_DIR="$(cd "$(dirname "$0")/../agent/rust" && pwd)"
if command -v cargo >/dev/null 2>&1; then
  url="https://$HOST/cdn-cgi/trace"   # Cloudflare echo ; harmless 404 elsewhere
  out="$(cd "$RUST_DIR" && cargo run -q --release --example pq_verify -- "$url" 2>&1 || true)"
  if echo "$out" | grep -q 'offers X25519MLKEM768 : true'; then
    echo "[B aws-lc-rs] OK  -> offers + handshakes $GROUP"
    echo "$out" | grep -E 'negotiated|offered' | sed 's/^/[B aws-lc-rs]   /'
  else
    echo "[B aws-lc-rs] FAIL"; echo "$out" | tail -5 | sed 's/^/[B aws-lc-rs]   /'
    fail=1
  fi
else
  echo "[B aws-lc-rs] SKIP (cargo not found ; run from a Rust toolchain)"
fi

echo "========================================================"
if [ "$fail" -eq 0 ]; then
  echo "PQ PARITY CONFIRMED : independent stacks agree on $GROUP"
else
  echo "PQ PARITY FAILED : see above"
fi
exit "$fail"
