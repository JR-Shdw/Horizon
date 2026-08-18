#!/usr/bin/env bash
# chaos K2 -- network partition on one manager via iptables.
#
# Isolates CHAOS_TARGET_HOST from its 2 peers for CHAOS_DURATION_SECS
# (default 90). Verifies during the partition:
#   - the 2 reachable managers keep quorum (cluster/ha shows them, primary
#     still serves /vault/status),
#   - the isolated mgr cannot reach quorum (its master_watch_loop fires
#     but cannot win an election -> stays sealed).
# After heal:
#   - isolated mgr REJOINs (mTLS, passive REJOIN), audit chain
#     stays intact.
#
# Required env:
#   RHORIZON_URL          API endpoint on a non-target manager (probe)
#   RHORIZON_TOKEN_FILE   admin:r token (or RHORIZON_TOKEN)
#   CHAOS_TARGET_HOST     hostname/IP of the manager to isolate
#   CHAOS_PEER_HOSTS      space-separated list of the 2 peers to block
#
# Optional:
#   CHAOS_DURATION_SECS   90
#   CHAOS_NOTES           free-text appended to result row

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env \
    RHORIZON_URL RHORIZON_TOKEN_FILE \
    CHAOS_TARGET_HOST CHAOS_PEER_HOSTS

DURATION="${CHAOS_DURATION_SECS:-90}"
NOTES="${CHAOS_NOTES:-}"
START_TS=$(date -u +%FT%TZ)

echo "K2: pre-flight"
chaos_assert_quorum
PRIMARY_BEFORE=$(rhorizon_cluster_ha | jq -r '.primary_uuid')

PEER_DROPS=()
for peer in $CHAOS_PEER_HOSTS; do
    PEER_DROPS+=("$peer")
done
peer_csv=$(IFS=,; echo "${PEER_DROPS[*]}")

echo "K2: blocking ${CHAOS_TARGET_HOST} <-> {${peer_csv}} for ${DURATION}s"
ssh_lab "$CHAOS_TARGET_HOST" "iptables -I INPUT -s ${peer_csv} -j DROP \
    && iptables -I OUTPUT -d ${peer_csv} -j DROP"

cleanup() {
    echo "K2: removing iptables drops"
    ssh_lab "$CHAOS_TARGET_HOST" "iptables -D INPUT  -s ${peer_csv} -j DROP || true; \
        iptables -D OUTPUT -d ${peer_csv} -j DROP || true"
}
trap cleanup EXIT INT TERM

sleep "$DURATION"

echo "K2: mid-partition probe"
DURING_HA=$(rhorizon_cluster_ha)
QUORUM_OK=$(echo "$DURING_HA" | jq '.members | length')
if (( QUORUM_OK < 2 )); then
    chaos_log_result K2 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "quorum lost during partition (members=$QUORUM_OK) ${NOTES}"
    chaos_die "K2 failed: quorum dropped to $QUORUM_OK"
fi

cleanup
trap - EXIT INT TERM

echo "K2: heal -- waiting 60s for REJOIN"
sleep 60

POST_HA=$(rhorizon_cluster_ha)
POST_N=$(echo "$POST_HA" | jq '.members | length')
PRIMARY_AFTER=$(echo "$POST_HA" | jq -r '.primary_uuid')

if (( POST_N < 3 )); then
    chaos_log_result K2 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "isolated node failed to REJOIN (members=$POST_N) ${NOTES}"
    chaos_die "K2 failed: members $POST_N < 3 after heal"
fi
if ! rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null; then
    chaos_log_result K2 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "audit chain broken post-event ${NOTES}"
    chaos_die "K2 failed: audit chain not intact"
fi

OUTCOME=PASS
if [[ "$PRIMARY_BEFORE" != "$PRIMARY_AFTER" ]]; then
    OUTCOME="PASS_PRIMARY_FLIPPED"
fi

chaos_log_result K2 "$START_TS" "$(date -u +%FT%TZ)" "$OUTCOME" \
    "before=${PRIMARY_BEFORE} after=${PRIMARY_AFTER} ${NOTES}"
