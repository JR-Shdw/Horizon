#!/usr/bin/env bash
# chaos K1 -- kill the master container, validate election.
#
# Procedure :
#   1. Read /cluster/ha, identify primary_uuid + host via
#      CHAOS_HOST_BY_UUID.
#   2. docker kill the rhorizon-api container on that host.
#   3. Poll /vault/status from CHAOS_PROBE_URL every 500ms,
#      time the API outage window (first 5xx -> first 200 again).
#   4. Read /cluster/ha post-event, expect a different primary_uuid.
#   5. Verify the killed container REJOINs as SECONDARY (Swarm restart
#      policy expected -- abort with note otherwise so the operator
#      knows manual recovery is needed).
#   6. Audit chain stays intact.
#
# Required env :
#   RHORIZON_URL          probe endpoint -- MUST be the cluster VIP /
#                         load-balancer, NOT a per-node URL (the killed
#                         master's URL will 503 for the entire window).
#   RHORIZON_TOKEN_FILE   admin:r token (admin:w only needed if
#                         CHAOS_FORCE_REJOIN=1).
#   CHAOS_HOST_BY_UUID    JSON {"<node_uuid>": "<host>", ...} or path.
#   CHAOS_API_CONTAINER_LABEL   default rhorizon-api.
#
# Optional :
#   CHAOS_ELECTION_WAIT_SECS    15
#   CHAOS_REJOIN_WAIT_SECS      120
#   CHAOS_PROBE_INTERVAL_MS     500
#   CHAOS_FORCE_REJOIN          0 -- if 1, runs /cluster/unrevoke after
#                                    a confirmed evict (defensive : a
#                                    Swarm-managed container usually
#                                    re-attaches without unrevoke).
#   CHAOS_NOTES                 free-text.

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env RHORIZON_URL RHORIZON_TOKEN_FILE CHAOS_HOST_BY_UUID

LABEL="${CHAOS_API_CONTAINER_LABEL:-rhorizon-api}"
ELECTION_WAIT="${CHAOS_ELECTION_WAIT_SECS:-15}"
REJOIN_WAIT="${CHAOS_REJOIN_WAIT_SECS:-120}"
PROBE_MS="${CHAOS_PROBE_INTERVAL_MS:-500}"
NOTES="${CHAOS_NOTES:-}"
START_TS=$(date -u +%FT%TZ)

if [[ -f "$CHAOS_HOST_BY_UUID" ]]; then
    HOST_MAP=$(< "$CHAOS_HOST_BY_UUID")
else
    HOST_MAP="$CHAOS_HOST_BY_UUID"
fi
host_for_uuid() { jq -r --arg u "$1" '.[$u] // empty' <<< "$HOST_MAP"; }

echo "K1: pre-flight"
chaos_assert_quorum
HA_BEFORE=$(rhorizon_cluster_ha)
OLD_PRIMARY_UUID=$(echo "$HA_BEFORE" | jq -r '.primary_uuid')
OLD_PRIMARY_HOST=$(host_for_uuid "$OLD_PRIMARY_UUID")
[[ -n "$OLD_PRIMARY_HOST" ]] || chaos_die "no host mapping for primary $OLD_PRIMARY_UUID"

echo "K1: kill master container on $OLD_PRIMARY_HOST (uuid=$OLD_PRIMARY_UUID)"
CID=$(docker_lab "$OLD_PRIMARY_HOST" ps -q -f "label=${LABEL}" || true)
[[ -n "$CID" ]] || chaos_die "no container with label=${LABEL} on $OLD_PRIMARY_HOST"

KILL_TS=$(date +%s.%3N)
docker_lab "$OLD_PRIMARY_HOST" kill "$CID"

echo "K1: poll /vault/status every ${PROBE_MS}ms, max ${ELECTION_WAIT}s"
FIRST_FAIL_TS=""
RECOVERY_TS=""
PROBE_SLEEP=$(awk "BEGIN{print ${PROBE_MS}/1000}")
DEADLINE=$(awk "BEGIN{print ${KILL_TS} + ${ELECTION_WAIT}}")

while (( $(awk "BEGIN{print ($(date +%s.%3N) < ${DEADLINE})}") )); do
    if rhorizon_status > /dev/null 2>&1; then
        if [[ -n "$FIRST_FAIL_TS" && -z "$RECOVERY_TS" ]]; then
            RECOVERY_TS=$(date +%s.%3N)
            break
        fi
    else
        [[ -z "$FIRST_FAIL_TS" ]] && FIRST_FAIL_TS=$(date +%s.%3N)
    fi
    sleep "$PROBE_SLEEP"
done

if [[ -z "$RECOVERY_TS" ]]; then
    chaos_log_result K1 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "no recovery within ${ELECTION_WAIT}s ${NOTES}"
    chaos_die "K1 failed: election did not complete"
fi

OUTAGE_SECS=$(awk "BEGIN{print ${RECOVERY_TS} - ${FIRST_FAIL_TS:-${KILL_TS}}}")
echo "K1: outage window ${OUTAGE_SECS}s"

HA_AFTER=$(rhorizon_cluster_ha)
NEW_PRIMARY_UUID=$(echo "$HA_AFTER" | jq -r '.primary_uuid')
if [[ "$NEW_PRIMARY_UUID" == "$OLD_PRIMARY_UUID" || -z "$NEW_PRIMARY_UUID" ]]; then
    chaos_log_result K1 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "no new primary -- old=${OLD_PRIMARY_UUID} after=${NEW_PRIMARY_UUID} ${NOTES}"
    chaos_die "K1 failed: primary did not flip"
fi

echo "K1: wait up to ${REJOIN_WAIT}s for old primary to REJOIN as SECONDARY"
REJOINED=0
for _ in $(seq 1 "$REJOIN_WAIT"); do
    if rhorizon_cluster_ha | jq -e --arg u "$OLD_PRIMARY_UUID" \
        '.members[] | select(.node_uuid == $u) | .ha_state == "secondary"' \
        > /dev/null; then
        REJOINED=1
        break
    fi
    sleep 1
done

if (( REJOINED == 0 )); then
    if [[ "${CHAOS_FORCE_REJOIN:-0}" == "1" ]]; then
        echo "K1: CHAOS_FORCE_REJOIN=1 -- attempting /cluster/unrevoke"
        rhorizon_curl -X POST \
            "${RHORIZON_URL}/api/v1/vault/cluster/unrevoke/${OLD_PRIMARY_UUID}" \
            > /dev/null || true
        for _ in $(seq 1 30); do
            sleep 1
            if rhorizon_cluster_ha | jq -e --arg u "$OLD_PRIMARY_UUID" \
                '.members[] | select(.node_uuid == $u) | .ha_state == "secondary"' \
                > /dev/null; then
                REJOINED=1; break
            fi
        done
    fi
fi

if (( REJOINED == 0 )); then
    chaos_log_result K1 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "killed node did not REJOIN -- outage=${OUTAGE_SECS}s ${NOTES}"
    chaos_die "K1 failed: REJOIN timeout"
fi

if ! rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null; then
    chaos_log_result K1 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "audit chain broken ${NOTES}"
    chaos_die "K1 failed: audit chain"
fi

OUTCOME=PASS
if (( $(awk "BEGIN{print (${OUTAGE_SECS} > 10)}") )); then
    OUTCOME=PASS_SLOW
fi

chaos_log_result K1 "$START_TS" "$(date -u +%FT%TZ)" "$OUTCOME" \
    "outage=${OUTAGE_SECS}s old=${OLD_PRIMARY_UUID} new=${NEW_PRIMARY_UUID} ${NOTES}"
