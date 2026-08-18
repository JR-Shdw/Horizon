#!/usr/bin/env bash
# chaos K3 -- slow follower (egress latency injection).
#
# Adds CHAOS_DELAY_MS (default 500ms) on the egress interface of
# CHAOS_TARGET_HOST for CHAOS_DURATION_SECS (default 300). Verifies:
#   - heartbeats still arrive under the 5s staleness threshold,
#   - cluster_rpc_latency_seconds histogram bumps for affected ops
#     (manual check via Prometheus / /metrics),
#   - quorum unaffected (3 members present throughout).
#
# Required env:
#   RHORIZON_URL          probe endpoint (non-target manager preferred)
#   RHORIZON_TOKEN_FILE   admin:r token
#   CHAOS_TARGET_HOST     manager to slow down
#   CHAOS_TARGET_IFACE    egress interface name (default eth0)
#
# Optional:
#   CHAOS_DELAY_MS        500
#   CHAOS_DURATION_SECS   300
#   CHAOS_NOTES           free-text

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env RHORIZON_URL RHORIZON_TOKEN_FILE CHAOS_TARGET_HOST

IFACE="${CHAOS_TARGET_IFACE:-eth0}"
DELAY="${CHAOS_DELAY_MS:-500}"
DURATION="${CHAOS_DURATION_SECS:-300}"
NOTES="${CHAOS_NOTES:-}"
START_TS=$(date -u +%FT%TZ)

echo "K3: pre-flight"
chaos_assert_quorum

echo "K3: tc netem delay ${DELAY}ms on ${IFACE}@${CHAOS_TARGET_HOST} for ${DURATION}s"
ssh_lab "$CHAOS_TARGET_HOST" "tc qdisc add dev ${IFACE} root netem delay ${DELAY}ms"

cleanup() {
    echo "K3: removing tc qdisc"
    ssh_lab "$CHAOS_TARGET_HOST" "tc qdisc del dev ${IFACE} root netem || true"
}
trap cleanup EXIT INT TERM

# Periodic membership probes.
SAMPLES=$((DURATION / 10))
for ((i = 0; i < SAMPLES; i++)); do
    sleep 10
    N=$(rhorizon_cluster_ha | jq '.members | length')
    if (( N < 3 )); then
        chaos_log_result K3 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
            "quorum dropped mid-run (members=$N at sample $i) ${NOTES}"
        chaos_die "K3 failed: members < 3 mid-run"
    fi
done

cleanup
trap - EXIT INT TERM

if ! rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null; then
    chaos_log_result K3 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "audit chain broken post-event ${NOTES}"
    chaos_die "K3 failed: audit chain not intact"
fi

chaos_log_result K3 "$START_TS" "$(date -u +%FT%TZ)" PASS \
    "delay=${DELAY}ms duration=${DURATION}s ${NOTES}"
