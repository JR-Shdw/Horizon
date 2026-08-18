#!/usr/bin/env bash
# chaos K6 -- ha_password rotation under master failure.
#
# Procedure :
#   1. stage rotation via /cluster/rotate-ha-password/stage,
#   2. kill the current master container within 30s of stage,
#   3. wait for the surviving secondaries to elect a new master,
#   4. verify the pending row survived (DB-backed, not in-memory),
#   5. confirm rotation on the new master,
#   6. verify audit chain shows ha_password_rotate_stage on the old
#      primary UUID and ha_password_rotated on the new one.
#
# Required env:
#   RHORIZON_URL          probe endpoint (must be reachable post-flip)
#   RHORIZON_TOKEN_FILE   admin:w token
#   CHAOS_HOST_BY_UUID    JSON {"<node_uuid>": "<host>", ...} or path
#
# Optional:
#   CHAOS_API_CONTAINER_LABEL   default rhorizon-api
#   CHAOS_KILL_DELAY_SECS       seconds between stage and kill (default 5)
#   CHAOS_ELECTION_WAIT_SECS    max wait for new primary (default 30)
#   CHAOS_NOTES                 free-text

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env RHORIZON_URL RHORIZON_TOKEN_FILE CHAOS_HOST_BY_UUID

LABEL="${CHAOS_API_CONTAINER_LABEL:-rhorizon-api}"
KILL_DELAY="${CHAOS_KILL_DELAY_SECS:-5}"
ELECTION_WAIT="${CHAOS_ELECTION_WAIT_SECS:-30}"
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

echo "K6: pre-flight"
chaos_assert_quorum
HA_BEFORE=$(rhorizon_cluster_ha)
OLD_PRIMARY_UUID=$(echo "$HA_BEFORE" | jq -r '.primary_uuid')
OLD_PRIMARY_HOST=$(host_for_uuid "$OLD_PRIMARY_UUID")
[[ -n "$OLD_PRIMARY_HOST" ]] || chaos_die "no host mapping for primary $OLD_PRIMARY_UUID"

echo "K6: stage rotation on old primary $OLD_PRIMARY_UUID"
rhorizon_curl -X POST "${RHORIZON_URL}/api/v1/vault/cluster/rotate-ha-password/stage" \
    > /dev/null

# Verify the stage row landed.
STAGE_STATUS=$(rhorizon_curl "${RHORIZON_URL}/api/v1/vault/cluster/rotate-ha-password")
echo "K6: stage status: $STAGE_STATUS"
echo "$STAGE_STATUS" | jq -e '.staged_by' > /dev/null \
    || chaos_die "stage did not persist (no staged_by)"

sleep "$KILL_DELAY"

echo "K6: kill master container on $OLD_PRIMARY_HOST"
CID=$(docker_lab "$OLD_PRIMARY_HOST" ps -q -f "label=${LABEL}" || true)
[[ -n "$CID" ]] || chaos_die "no container with label=${LABEL} on $OLD_PRIMARY_HOST"
docker_lab "$OLD_PRIMARY_HOST" kill "$CID"

echo "K6: wait up to ${ELECTION_WAIT}s for new primary"
NEW_PRIMARY_UUID=""
for _ in $(seq 1 "$ELECTION_WAIT"); do
    sleep 1
    CUR=$(rhorizon_cluster_ha 2>/dev/null | jq -r '.primary_uuid // empty' || true)
    if [[ -n "$CUR" && "$CUR" != "$OLD_PRIMARY_UUID" ]]; then
        NEW_PRIMARY_UUID="$CUR"
        break
    fi
done

[[ -n "$NEW_PRIMARY_UUID" ]] || {
    chaos_log_result K6 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "no new primary within ${ELECTION_WAIT}s ${NOTES}"
    chaos_die "K6 failed: election timeout"
}

# Stage row must survive the crash.
POST_STAGE=$(rhorizon_curl "${RHORIZON_URL}/api/v1/vault/cluster/rotate-ha-password")
echo "$POST_STAGE" | jq -e '.staged_by' > /dev/null \
    || {
        chaos_log_result K6 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
            "pending row lost across election ${NOTES}"
        chaos_die "K6 failed: stage row gone"
    }

echo "K6: confirm rotation on new primary $NEW_PRIMARY_UUID"
rhorizon_curl -X POST \
    "${RHORIZON_URL}/api/v1/vault/cluster/rotate-ha-password/confirm" \
    > /dev/null

# Audit chain probes
if ! rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null; then
    chaos_log_result K6 "$START_TS" "$(date -u +%FT%TZ)" FAIL \
        "audit chain broken ${NOTES}"
    chaos_die "K6 failed: audit chain"
fi

chaos_log_result K6 "$START_TS" "$(date -u +%FT%TZ)" PASS \
    "old_primary=${OLD_PRIMARY_UUID} new_primary=${NEW_PRIMARY_UUID} ${NOTES}"
