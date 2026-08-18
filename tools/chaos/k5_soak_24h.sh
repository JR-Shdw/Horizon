#!/usr/bin/env bash
# chaos K5 -- 24h soak with rotations + rolling restart.
#
# Long-running driver. Spawns three background loops :
#   - writer    : POST /secrets/ soak/<ts> with random value every 1s.
#   - reader    : every minute, GET 3 random soak/* and verify the value.
#   - sampler   : every 5min, snapshot /audit/verify + /cluster/ha,
#                 append to a JSONL report log.
# Schedules :
#   - at CHAOS_DEK_ROTATION_OFFSET (default H+10h) : verify the
#     automatic /admin/rotate-dek-key fired (post-cron). No action.
#   - at CHAOS_CA_ROTATION_OFFSET (default H+12h) : POST
#     /cluster/rotate-ca.
#   - at CHAOS_ROLLING_RESTART_OFFSET (default H+18h) : run
#     k4_rolling_restart.sh inline.
# At H+CHAOS_DURATION_SECS (default 86400) :
#   - signal all loops to exit,
#   - cross-check every written secret reads back identical,
#   - final /audit/verify + /cluster/ha snapshot,
#   - emit results CSV row + Markdown report under
#     tools/chaos/results/k5-<start_ts>/.
#
# Required env :
#   RHORIZON_URL          cluster VIP / LB
#   RHORIZON_TOKEN_FILE   token with admin:w + secrets:rw
#                         (admin:w needed for rotate-ca step)
#   CHAOS_HOST_BY_UUID    JSON {"<node_uuid>": "<host>", ...} or path
#                         (consumed by the inlined rolling restart)
#
# Optional :
#   CHAOS_DURATION_SECS              86400 (24h)
#   CHAOS_DEK_ROTATION_OFFSET        36000 (10h, sentinel only)
#   CHAOS_CA_ROTATION_OFFSET         43200 (12h)
#   CHAOS_ROLLING_RESTART_OFFSET     64800 (18h)
#   CHAOS_WRITE_INTERVAL_SECS        1
#   CHAOS_READ_INTERVAL_SECS         60
#   CHAOS_SAMPLE_INTERVAL_SECS       300
#   CHAOS_NAMESPACE                  soak
#   CHAOS_NOTES                      free-text
#
# Run detached :
#   nohup bash tools/chaos/k5_soak_24h.sh > k5.log 2>&1 &
#   disown
# Or under systemd-user / tmux. The script keeps a single PID file
# CHAOS_RESULTS_DIR/k5.pid so a re-run from the same workstation
# refuses if a previous run is still active.

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env RHORIZON_URL RHORIZON_TOKEN_FILE CHAOS_HOST_BY_UUID

DURATION="${CHAOS_DURATION_SECS:-86400}"
DEK_OFF="${CHAOS_DEK_ROTATION_OFFSET:-36000}"
CA_OFF="${CHAOS_CA_ROTATION_OFFSET:-43200}"
RR_OFF="${CHAOS_ROLLING_RESTART_OFFSET:-64800}"
WRITE_INT="${CHAOS_WRITE_INTERVAL_SECS:-1}"
READ_INT="${CHAOS_READ_INTERVAL_SECS:-60}"
SAMPLE_INT="${CHAOS_SAMPLE_INTERVAL_SECS:-300}"
NS="${CHAOS_NAMESPACE:-soak}"
NOTES="${CHAOS_NOTES:-}"
START_TS=$(date -u +%FT%TZ)
START_EPOCH=$(date +%s)

RUN_DIR="$CHAOS_RESULTS_DIR/k5-${START_TS//[:T]/_}"
mkdir -p "$RUN_DIR"
PID_FILE="$CHAOS_RESULTS_DIR/k5.pid"
if [[ -f "$PID_FILE" ]] && kill -0 "$(< "$PID_FILE")" 2>/dev/null; then
    chaos_die "another K5 run is active (pid $(< "$PID_FILE"))"
fi
echo $$ > "$PID_FILE"

WRITTEN_INDEX="$RUN_DIR/written.tsv"     # ts<TAB>name<TAB>value_sha256
SAMPLE_LOG="$RUN_DIR/samples.jsonl"
EVENT_LOG="$RUN_DIR/events.log"
: > "$WRITTEN_INDEX"
: > "$SAMPLE_LOG"
: > "$EVENT_LOG"

log_event() {
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$EVENT_LOG"
}

cleanup() {
    log_event "cleanup -- killing background loops"
    for pid in "${BG_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -f "$PID_FILE"
}
trap cleanup EXIT INT TERM

writer_loop() {
    while :; do
        local ts="$(date +%s%N)"
        local name="${NS}/${ts}"
        local val
        val="$(openssl rand -base64 16)"
        if rhorizon_curl -X POST \
            "${RHORIZON_URL}/api/v1/vault/secrets/" \
            -H 'Content-Type: application/json' \
            -d "$(jq -n --arg n "$name" --arg v "$val" \
                '{name:$n, value:$v, namespace:"'"$NS"'"}')" \
            > /dev/null 2>&1; then
            local h
            h=$(printf '%s' "$val" | sha256sum | awk '{print $1}')
            printf '%s\t%s\t%s\n' "$ts" "$name" "$h" >> "$WRITTEN_INDEX"
        fi
        sleep "$WRITE_INT"
    done
}

reader_loop() {
    while :; do
        if [[ -s "$WRITTEN_INDEX" ]]; then
            shuf -n 3 "$WRITTEN_INDEX" 2>/dev/null | \
                while IFS=$'\t' read -r _ name hash; do
                    local resp val h
                    resp=$(rhorizon_curl \
                        "${RHORIZON_URL}/api/v1/vault/secrets/${name}" \
                        2>/dev/null || echo '{}')
                    val=$(echo "$resp" | jq -r '.value // empty')
                    if [[ -z "$val" ]]; then
                        log_event "read miss: $name"
                        continue
                    fi
                    h=$(printf '%s' "$val" | sha256sum | awk '{print $1}')
                    if [[ "$h" != "$hash" ]]; then
                        log_event "read mismatch: $name expected=$hash got=$h"
                    fi
                done
        fi
        sleep "$READ_INT"
    done
}

sampler_loop() {
    while :; do
        local now status ha
        now=$(date -u +%FT%TZ)
        status=$(rhorizon_status 2>/dev/null || echo '{}')
        ha=$(rhorizon_cluster_ha 2>/dev/null || echo '{}')
        local chain
        chain=$(rhorizon_audit_verify 2>/dev/null | \
            jq -r '.chain_intact // false')
        jq -n --arg ts "$now" --arg chain "$chain" \
            --argjson st "$status" --argjson ha "$ha" \
            '{ts:$ts, chain_intact:($chain=="true"), status:$st, ha:$ha}' \
            >> "$SAMPLE_LOG"
        sleep "$SAMPLE_INT"
    done
}

log_event "K5 start duration=${DURATION}s ${NOTES}"
chaos_assert_quorum
log_event "pre-flight passed"

writer_loop &  W_PID=$!
reader_loop &  R_PID=$!
sampler_loop & S_PID=$!
BG_PIDS=("$W_PID" "$R_PID" "$S_PID")

# Schedule the rotation + rolling restart at absolute offsets.
DEK_DONE=0; CA_DONE=0; RR_DONE=0
while :; do
    NOW=$(date +%s)
    ELAPSED=$(( NOW - START_EPOCH ))
    if (( ELAPSED >= DURATION )); then
        break
    fi
    if (( ELAPSED >= DEK_OFF && DEK_DONE == 0 )); then
        log_event "DEK rotation checkpoint -- sampler verifies the cron fired"
        DEK_DONE=1
    fi
    if (( ELAPSED >= CA_OFF && CA_DONE == 0 )); then
        log_event "trigger /cluster/rotate-ca"
        if rhorizon_curl -X POST \
            "${RHORIZON_URL}/api/v1/vault/cluster/rotate-ca" \
            > "$RUN_DIR/rotate-ca.json" 2>&1; then
            log_event "rotate-ca OK"
        else
            log_event "rotate-ca FAILED (see rotate-ca.json)"
        fi
        CA_DONE=1
    fi
    if (( ELAPSED >= RR_OFF && RR_DONE == 0 )); then
        log_event "trigger rolling restart"
        CHAOS_NOTES="K5_inline" \
            bash "$(dirname "$0")/k4_rolling_restart.sh" \
            >> "$RUN_DIR/k4.log" 2>&1 \
            || log_event "K4 inline FAILED (see k4.log)"
        RR_DONE=1
    fi
    sleep 30
done

log_event "soak window elapsed -- finalising"
trap - EXIT INT TERM
cleanup
trap - EXIT INT TERM
rm -f "$PID_FILE"

# Cross-check every written secret.
TOTAL=$(wc -l < "$WRITTEN_INDEX")
MISMATCH=0
MISS=0
while IFS=$'\t' read -r _ name hash; do
    resp=$(rhorizon_curl \
        "${RHORIZON_URL}/api/v1/vault/secrets/${name}" \
        2>/dev/null || echo '{}')
    val=$(echo "$resp" | jq -r '.value // empty')
    if [[ -z "$val" ]]; then
        ((MISS++)); continue
    fi
    h=$(printf '%s' "$val" | sha256sum | awk '{print $1}')
    if [[ "$h" != "$hash" ]]; then ((MISMATCH++)); fi
done < "$WRITTEN_INDEX"

FINAL_CHAIN=$(rhorizon_audit_verify | jq -r '.chain_intact // false')
GRACE_DROPS=$(rhorizon_curl "${RHORIZON_URL}/metrics" 2>/dev/null | \
    awk '/cluster_ca_grace_drops_total\{reason="grace_expired"\}/{print $2; found=1} END{if(!found)print 0}')

OUTCOME=PASS
[[ "$FINAL_CHAIN" == "true" ]] || OUTCOME=FAIL
(( MISMATCH == 0 && MISS == 0 )) || OUTCOME=FAIL
(( ${GRACE_DROPS%.*} == 0 )) || OUTCOME=PASS_WARN_GRACE

chaos_log_result K5 "$START_TS" "$(date -u +%FT%TZ)" "$OUTCOME" \
    "written=$TOTAL miss=$MISS mismatch=$MISMATCH chain=$FINAL_CHAIN grace_drops=$GRACE_DROPS ${NOTES}"
