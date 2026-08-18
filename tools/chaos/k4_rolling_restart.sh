#!/usr/bin/env bash
# chaos K4 -- rolling restart of the 3 managers (per runbook s2).
#
# Drives the procedure :
#   1. Identify primary, hold list of secondaries.
#   2. For each secondary :
#        - rhorizon cluster demote <secondary_uuid> is implicit (state
#          already secondary, no-op),
#        - docker restart <api container> on its host,
#        - wait CHAOS_INTER_NODE_SLEEP (default = 2 * quarantine_secs,
#          floor 60),
#        - verify /audit/verify chain_intact,
#        - verify cluster/ha shows the node back as SECONDARY.
#   3. Promote one secondary (the first restarted, for symmetry),
#      demote the original primary, restart it, verify membership.
#
# Required env:
#   RHORIZON_URL          probe endpoint (must be reachable throughout)
#   RHORIZON_TOKEN_FILE   admin:w token
#   CHAOS_HOST_BY_UUID    JSON {"<node_uuid>": "<host>", ...}
#                         or a path to a JSON file
#
# Optional:
#   CHAOS_API_CONTAINER_LABEL   docker container label (default rhorizon-api)
#   CHAOS_INTER_NODE_SLEEP      seconds between restarts (default 60)
#   CHAOS_NOTES                 free-text

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env RHORIZON_URL RHORIZON_TOKEN_FILE CHAOS_HOST_BY_UUID

LABEL="${CHAOS_API_CONTAINER_LABEL:-rhorizon-api}"
SLEEP_INTER="${CHAOS_INTER_NODE_SLEEP:-60}"
NOTES="${CHAOS_NOTES:-}"
START_TS=$(date -u +%FT%TZ)

if [[ -f "$CHAOS_HOST_BY_UUID" ]]; then
    HOST_MAP=$(< "$CHAOS_HOST_BY_UUID")
else
    HOST_MAP="$CHAOS_HOST_BY_UUID"
fi

host_for_uuid() {
    local uuid="$1"
    jq -r --arg u "$uuid" '.[$u] // empty' <<< "$HOST_MAP"
}

restart_one() {
    local uuid="$1" host
    host=$(host_for_uuid "$uuid")
    [[ -n "$host" ]] || chaos_die "no host mapping for $uuid"
    echo "K4: restart api container on $host (uuid=$uuid)"
    local cid
    cid=$(docker_lab "$host" ps -q -f "label=${LABEL}" || true)
    [[ -n "$cid" ]] || chaos_die "no container with label=${LABEL} on $host"
    docker_lab "$host" restart "$cid"
}

verify_member_back() {
    local uuid="$1"
    for _ in $(seq 1 30); do
        if rhorizon_cluster_ha | \
            jq -e --arg u "$uuid" \
                '.members[] | select(.node_uuid == $u) | .ha_state == "secondary"' \
            > /dev/null; then
            return 0
        fi
        sleep 2
    done
    return 1
}

echo "K4: pre-flight"
chaos_assert_quorum
HA_BEFORE=$(rhorizon_cluster_ha)
PRIMARY_UUID=$(echo "$HA_BEFORE" | jq -r '.primary_uuid')
SEC_UUIDS=($(echo "$HA_BEFORE" | \
    jq -r --arg p "$PRIMARY_UUID" \
        '.members[] | select(.node_uuid != $p) | .node_uuid'))

if (( ${#SEC_UUIDS[@]} != 2 )); then
    chaos_die "K4 expects 2 secondaries, got ${#SEC_UUIDS[@]}"
fi

echo "K4: step 1 -- secondaries first"
for uuid in "${SEC_UUIDS[@]}"; do
    restart_one "$uuid"
    sleep "$SLEEP_INTER"
    verify_member_back "$uuid" || chaos_die "secondary $uuid did not return as SECONDARY"
    rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null \
        || chaos_die "audit chain broke after restarting $uuid"
done

echo "K4: step 2 -- demote primary"
NEW_PRIMARY_UUID="${SEC_UUIDS[0]}"
rhorizon_curl -X POST \
    "${RHORIZON_URL}/api/v1/vault/cluster/promote/${NEW_PRIMARY_UUID}" \
    > /dev/null
sleep 5
restart_one "$PRIMARY_UUID"
sleep "$SLEEP_INTER"
verify_member_back "$PRIMARY_UUID" \
    || chaos_die "old primary $PRIMARY_UUID did not return as SECONDARY"

POST_HA=$(rhorizon_cluster_ha)
POST_PRIMARY=$(echo "$POST_HA" | jq -r '.primary_uuid')
POST_N=$(echo "$POST_HA" | jq '.members | length')

if (( POST_N != 3 )); then
    chaos_log_result K4 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "members=$POST_N != 3 ${NOTES}"
    chaos_die "K4 failed: membership"
fi
if ! rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null; then
    chaos_log_result K4 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "audit chain broken ${NOTES}"
    chaos_die "K4 failed: audit chain"
fi

chaos_log_result K4 "$START_TS" "$(date -u +%FT%TZ)" PASS \
    "before_primary=${PRIMARY_UUID} after_primary=${POST_PRIMARY} ${NOTES}"
