#!/usr/bin/env bash
# chaos K7 -- 24h random HA chaos under medium/high live workload.
#
# This is the "publish beta with evidence" run:
#   - sustained secret write/read load through the LB;
#   - optional PKI issue/revoke loop;
#   - node server-cert check (issuer must be the cluster CA, not self);
#   - cluster mTLS fail-closed check (refresh-cert must reject a missing or
#     non-CA-signed client cert);
#   - optional dynamic credential mint/renew/revoke loop;
#   - optional notification channel test loop;
#   - random 1-node and 2-node outages;
#   - during 2-node outages, optionally promote and verify the single survivor;
#   - after every fault, bring nodes back, run optional recovery/unseal command,
#     and wait for convergence before the next failure;
#   - capture raw /metrics, /observability, /cluster/ha, a bounded audit-lite
#     canary, /readiness, Docker logs, and final full readback evidence;
#   - run expensive full audit verification only before and after the workload.
#
# Required:
#   RH_URL                     cluster VIP / LB URL
#   RH_TOKEN_FILE              admin:w + secrets:rw + audit:r token
#                              (or RH_TOKEN)
#   CHAOS_HOST_BY_UUID       JSON {"<node_uuid>": "<host>", ...} or a path
#
# Optional node control:
#   CHAOS_API_CONTAINER_LABEL  Docker label used by existing K scripts
#                              (default rhorizon-api)
#   CHAOS_DOWN_CMD             local command template to bring a node down
#   CHAOS_UP_CMD               local command template to bring a node up
#   CHAOS_NODE_RECOVER_CMD     local command template run after node up
#   CHAOS_NODE_URL_TEMPLATE    e.g. "https://{host}:443" for direct probes
#   CHAOS_SERVER_CERT_CHECK    1 (default) verifies each node's nginx server
#                              cert is cluster-CA-minted, not self-signed
#   CHAOS_SERVER_CERT_PORT     TLS port probed for that check (default 8443)
#   CHAOS_SERVER_CERT_INTERVAL_SECS  poll interval (default 300)
#   CHAOS_MTLS_CHECK           1 (default) asserts /cluster/refresh-cert
#                              rejects missing and forged client certs
#   CHAOS_MTLS_PORT            TLS port for that check (default: server-cert port)
#   CHAOS_MTLS_INTERVAL_SECS   poll interval (default 300)
#   CHAOS_PKI_REVOKE_RETRIES   revoke attempts before recording (default 3)
#   CHAOS_PKI_REVOKE_RETRY_DELAY_SECS  delay between them (default 5)
#   CHAOS_URL_BY_UUID          JSON {"<node_uuid>": "https://node:443"} or path
#
# Templates support {uuid}, {host}, and {url}. If CHAOS_DOWN_CMD/UP_CMD are
# unset, Docker-over-SSH stop/start is used.
#
# Optional workload:
#   CHAOS_DURATION_SECS          default 86400
#   CHAOS_LOAD_PROFILE           medium | high (default medium)
#   CHAOS_NAMESPACE              default chaos-k7
#   CHAOS_DYNAMIC_ENGINE_ID      existing dynamic engine id
#   CHAOS_DYNAMIC_ROLE_NAME      existing dynamic role name
#   CHAOS_ALERT_CHANNEL_ID       notification channel id to test
#   CHAOS_LB_HEALTH_URL          optional test-LB diagnostics endpoint
#   CHAOS_DISK_PRESSURE           1 enables bounded remote disk pressure
#   CHAOS_DISK_PRESSURE_CMD       command template; also receives {gib} and
#                                 {run_id}; the command must remove its data
#   CHAOS_DISK_PRESSURE_CLEANUP_CMD  idempotent cleanup template for {run_id}
#   CHAOS_DISK_PRESSURE_MIN_GIB   default 1 (hard-bounded to 1..2)
#   CHAOS_DISK_PRESSURE_MAX_GIB   default 2 (hard-bounded to 1..2)
#   CHAOS_WORKER_KILL_AFTER_PRESSURE  kill one follower after the first
#                                 pressure cycle (default 0)
#   CHAOS_WORKER_KILL_CMD          command template receiving {pid}; required
#                                 when the one-shot worker fault is enabled
#   CHAOS_AUDIT_VERIFY            default 1; set 0 only for a targeted short
#                                 run when a durable full verifier is separate
#
# Evidence:
#   tools/chaos/results/k7-<start_ts>-<run_id>/
#     driver.log, events.jsonl, failures.jsonl, written.tsv, pki.tsv, dynamic.tsv
#     samples/{metrics,observability,ha,health,audit,readiness,notifications,lb}
#     logs/<uuid>-<host>.docker.log
#     final-summary.json, report.md

set -euo pipefail
source "$(dirname "$0")/common.sh"

chaos_require_env RH_URL CHAOS_HOST_BY_UUID
if [[ -z "${RH_TOKEN_FILE:-}" && -z "${RH_TOKEN:-}" ]]; then
    chaos_die "need RH_TOKEN_FILE or RH_TOKEN"
fi

DURATION="${CHAOS_DURATION_SECS:-86400}"
PROFILE="${CHAOS_LOAD_PROFILE:-medium}"
NS="${CHAOS_NAMESPACE:-chaos-k7}"
LABEL="${CHAOS_API_CONTAINER_LABEL:-rhorizon-api}"
START_TS=$(date -u +%FT%TZ)
START_EPOCH=$(date +%s)
RUN_ID="${CHAOS_RUN_ID:-${START_EPOCH}-$$}"
RUN_DIR="$CHAOS_RESULTS_DIR/k7-${START_TS//[:T]/_}-${RUN_ID}"
PID_FILE="$CHAOS_RESULTS_DIR/k7.pid"

if [[ -f "$PID_FILE" ]] && kill -0 "$(< "$PID_FILE")" 2>/dev/null; then
    chaos_die "another K7 run is active (pid $(< "$PID_FILE"))"
fi

mkdir -p "$RUN_DIR"/samples/{metrics,observability,ha,health,audit,readiness,notifications,cluster,lb} \
    "$RUN_DIR"/logs

EVENTS="$RUN_DIR/events.jsonl"
FAILURES="$RUN_DIR/failures.jsonl"
WRITTEN="$RUN_DIR/written.tsv"
PKI_LOG="$RUN_DIR/pki.tsv"
DYNAMIC_LOG="$RUN_DIR/dynamic.tsv"
ALERT_LOG="$RUN_DIR/alert.tsv"
DISK_PRESSURE_LOG="$RUN_DIR/disk-pressure.tsv"
DOWN_FILE="$RUN_DIR/down-nodes.txt"
DRIVER_LOG="$RUN_DIR/driver.log"
FAULT_LOCK="$RUN_DIR/fault.lock"
: > "$EVENTS"
: > "$FAILURES"
: > "$WRITTEN"
: > "$PKI_LOG"
: > "$DYNAMIC_LOG"
: > "$ALERT_LOG"
: > "$DISK_PRESSURE_LOG"
: > "$DOWN_FILE"
: > "$FAULT_LOCK"
: > "$DRIVER_LOG"
exec > >(tee -a "$DRIVER_LOG") 2>&1

case "$PROFILE" in
    medium)
        WRITERS="${CHAOS_WRITERS:-4}"
        READERS="${CHAOS_READERS:-16}"
        WRITER_SLEEP="${CHAOS_WRITER_SLEEP_SECS:-0.25}"
        READER_SLEEP="${CHAOS_READER_SLEEP_SECS:-0.10}"
        SAMPLE_INT="${CHAOS_SAMPLE_INTERVAL_SECS:-30}"
        FAULT_MIN="${CHAOS_FAULT_MIN_INTERVAL_SECS:-300}"
        FAULT_MAX="${CHAOS_FAULT_MAX_INTERVAL_SECS:-1200}"
        PRESSURE_MIN_INTERVAL="${CHAOS_DISK_PRESSURE_MIN_INTERVAL_SECS:-600}"
        PRESSURE_MAX_INTERVAL="${CHAOS_DISK_PRESSURE_MAX_INTERVAL_SECS:-1800}"
        ;;
    high)
        WRITERS="${CHAOS_WRITERS:-8}"
        READERS="${CHAOS_READERS:-48}"
        WRITER_SLEEP="${CHAOS_WRITER_SLEEP_SECS:-0.10}"
        READER_SLEEP="${CHAOS_READER_SLEEP_SECS:-0.03}"
        SAMPLE_INT="${CHAOS_SAMPLE_INTERVAL_SECS:-15}"
        FAULT_MIN="${CHAOS_FAULT_MIN_INTERVAL_SECS:-180}"
        FAULT_MAX="${CHAOS_FAULT_MAX_INTERVAL_SECS:-900}"
        PRESSURE_MIN_INTERVAL="${CHAOS_DISK_PRESSURE_MIN_INTERVAL_SECS:-300}"
        PRESSURE_MAX_INTERVAL="${CHAOS_DISK_PRESSURE_MAX_INTERVAL_SECS:-900}"
        ;;
    *)
        chaos_die "CHAOS_LOAD_PROFILE must be medium or high"
        ;;
esac

ONE_DOWN_MIN="${CHAOS_ONE_DOWN_MIN_SECS:-60}"
ONE_DOWN_MAX="${CHAOS_ONE_DOWN_MAX_SECS:-300}"
TWO_DOWN_MIN="${CHAOS_TWO_DOWN_MIN_SECS:-45}"
TWO_DOWN_MAX="${CHAOS_TWO_DOWN_MAX_SECS:-180}"
TWO_DOWN_PROB="${CHAOS_TWO_DOWN_PROB_PERCENT:-25}"
CONVERGE_WAIT="${CHAOS_CONVERGENCE_WAIT_SECS:-180}"
RECOVER_DELAY="${CHAOS_NODE_RECOVER_DELAY_SECS:-5}"
PROMOTE_SURVIVOR="${CHAOS_PROMOTE_SINGLE_SURVIVOR:-1}"
EXPECTED_WORKERS="${CHAOS_EXPECTED_WORKERS_PER_NODE:-0}"
FINAL_VERIFY_LIMIT="${CHAOS_FINAL_VERIFY_LIMIT:-10000}" # 0 = every write
HTTP_TIMEOUT="${CHAOS_HTTP_TIMEOUT_SECS:-20}"
# Full verification only runs before/after the active workload, but retained
# evidence can make those integrity gates take several minutes.
AUDIT_HTTP_TIMEOUT="${CHAOS_AUDIT_HTTP_TIMEOUT_SECS:-600}"
AUDIT_JOB_TIMEOUT="${CHAOS_AUDIT_VERIFY_JOB_TIMEOUT_SECS:-3600}"
AUDIT_JOB_POLL="${CHAOS_AUDIT_VERIFY_JOB_POLL_SECS:-5}"
CONNECT_TIMEOUT="${CHAOS_CONNECT_TIMEOUT_SECS:-5}"
CAPTURE_JOURNAL_UNIT="${CHAOS_CAPTURE_JOURNAL_UNIT:-}"
CAPTURE_DOCKER_LOGS="${CHAOS_CAPTURE_DOCKER_LOGS:-1}"
FAIL_ON_TRANSIENTS="${CHAOS_FAIL_ON_WORKLOAD_ERRORS:-0}"
PREFLIGHT_ONLY="${CHAOS_PREFLIGHT_ONLY:-0}"
ALLOW_SHARED_SURVIVOR_URL="${CHAOS_ALLOW_SHARED_SURVIVOR_URL:-0}"
DISK_PRESSURE="${CHAOS_DISK_PRESSURE:-0}"
AUDIT_VERIFY="${CHAOS_AUDIT_VERIFY:-1}"
PRESSURE_MIN_GIB="${CHAOS_DISK_PRESSURE_MIN_GIB:-1}"
PRESSURE_MAX_GIB="${CHAOS_DISK_PRESSURE_MAX_GIB:-2}"
WORKER_KILL_AFTER_PRESSURE="${CHAOS_WORKER_KILL_AFTER_PRESSURE:-0}"

if [[ -f "$CHAOS_HOST_BY_UUID" ]]; then
    HOST_MAP=$(< "$CHAOS_HOST_BY_UUID")
else
    HOST_MAP="$CHAOS_HOST_BY_UUID"
fi

if [[ -n "${CHAOS_URL_BY_UUID:-}" && -f "${CHAOS_URL_BY_UUID:-}" ]]; then
    URL_MAP=$(< "$CHAOS_URL_BY_UUID")
else
    URL_MAP="${CHAOS_URL_BY_UUID:-}"
fi

require_uint() {
    local name="$1" value="$2" min="$3" max="${4:-}"
    [[ "$value" =~ ^[0-9]+$ ]] || chaos_die "$name must be an integer, got: $value"
    (( value >= min )) || chaos_die "$name must be >= $min, got: $value"
    if [[ -n "$max" ]]; then
        (( value <= max )) || chaos_die "$name must be <= $max, got: $value"
    fi
}

[[ "$RUN_ID" =~ ^[A-Za-z0-9_-]+$ ]] \
    || chaos_die "CHAOS_RUN_ID may contain only letters, digits, _ and -"
(( ${#RUN_ID} <= 64 )) || chaos_die "CHAOS_RUN_ID must be <= 64 characters"
require_uint CHAOS_DURATION_SECS "$DURATION" 1
require_uint CHAOS_WRITERS "$WRITERS" 1
require_uint CHAOS_READERS "$READERS" 1
require_uint CHAOS_SAMPLE_INTERVAL_SECS "$SAMPLE_INT" 1
require_uint CHAOS_FAULT_MIN_INTERVAL_SECS "$FAULT_MIN" 1
require_uint CHAOS_FAULT_MAX_INTERVAL_SECS "$FAULT_MAX" "$FAULT_MIN"
require_uint CHAOS_DISK_PRESSURE_MIN_INTERVAL_SECS "$PRESSURE_MIN_INTERVAL" 1
require_uint CHAOS_DISK_PRESSURE_MAX_INTERVAL_SECS \
    "$PRESSURE_MAX_INTERVAL" "$PRESSURE_MIN_INTERVAL"
require_uint CHAOS_DISK_PRESSURE_MIN_GIB "$PRESSURE_MIN_GIB" 1 2
require_uint CHAOS_DISK_PRESSURE_MAX_GIB "$PRESSURE_MAX_GIB" "$PRESSURE_MIN_GIB" 2
require_uint CHAOS_ONE_DOWN_MIN_SECS "$ONE_DOWN_MIN" 1
require_uint CHAOS_ONE_DOWN_MAX_SECS "$ONE_DOWN_MAX" "$ONE_DOWN_MIN"
require_uint CHAOS_TWO_DOWN_MIN_SECS "$TWO_DOWN_MIN" 1
require_uint CHAOS_TWO_DOWN_MAX_SECS "$TWO_DOWN_MAX" "$TWO_DOWN_MIN"
require_uint CHAOS_TWO_DOWN_PROB_PERCENT "$TWO_DOWN_PROB" 0 100
require_uint CHAOS_CONVERGENCE_WAIT_SECS "$CONVERGE_WAIT" 1
require_uint CHAOS_FINAL_VERIFY_LIMIT "$FINAL_VERIFY_LIMIT" 0
require_uint CHAOS_AUDIT_HTTP_TIMEOUT_SECS "$AUDIT_HTTP_TIMEOUT" 1
require_uint CHAOS_AUDIT_VERIFY_JOB_TIMEOUT_SECS "$AUDIT_JOB_TIMEOUT" 1
require_uint CHAOS_AUDIT_VERIFY_JOB_POLL_SECS "$AUDIT_JOB_POLL" 1
for toggle in PROMOTE_SURVIVOR CAPTURE_DOCKER_LOGS FAIL_ON_TRANSIENTS PREFLIGHT_ONLY ALLOW_SHARED_SURVIVOR_URL DISK_PRESSURE AUDIT_VERIFY WORKER_KILL_AFTER_PRESSURE; do
    value="${!toggle}"
    [[ "$value" == "0" || "$value" == "1" ]] \
        || chaos_die "$toggle must be 0 or 1, got: $value"
done
if [[ "$DISK_PRESSURE" == "1" ]]; then
    [[ -n "${CHAOS_DISK_PRESSURE_CMD:-}" ]] \
        || chaos_die "CHAOS_DISK_PRESSURE_CMD is required when disk pressure is enabled"
    [[ -n "${CHAOS_DISK_PRESSURE_CLEANUP_CMD:-}" ]] \
        || chaos_die "CHAOS_DISK_PRESSURE_CLEANUP_CMD is required when disk pressure is enabled"
    command -v flock >/dev/null \
        || chaos_die "flock is required when disk pressure is enabled"
fi
if [[ "$WORKER_KILL_AFTER_PRESSURE" == "1" ]]; then
    [[ "$DISK_PRESSURE" == "1" ]] \
        || chaos_die "CHAOS_WORKER_KILL_AFTER_PRESSURE requires disk pressure"
    [[ -n "${CHAOS_WORKER_KILL_CMD:-}" ]] \
        || chaos_die "CHAOS_WORKER_KILL_CMD is required when the worker fault is enabled"
    (( EXPECTED_WORKERS >= 2 )) \
        || chaos_die "the worker fault requires CHAOS_EXPECTED_WORKERS_PER_NODE >= 2"
fi

jq -e 'type == "object"' <<< "$HOST_MAP" >/dev/null \
    || chaos_die "CHAOS_HOST_BY_UUID must be a JSON object or a path to one"
if [[ -n "$URL_MAP" ]]; then
    jq -e 'type == "object"' <<< "$URL_MAP" >/dev/null \
        || chaos_die "CHAOS_URL_BY_UUID must be a JSON object or a path to one"
fi
if [[ -n "${RH_TOKEN_FILE:-}" ]]; then
    [[ -r "$RH_TOKEN_FILE" ]] || chaos_die "RH_TOKEN_FILE is not readable: $RH_TOKEN_FILE"
    [[ -n "$(tr -d '\n\r' < "$RH_TOKEN_FILE")" ]] || chaos_die "RH_TOKEN_FILE is empty"
elif [[ -z "${RH_TOKEN:-}" ]]; then
    chaos_die "need RH_TOKEN_FILE or RH_TOKEN"
fi

curl_base_args=(
    --silent --show-error --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT"
)
tls_ca_file="${RH_CA_FILE:-/etc/rhorizon/cluster-ca.pem}"
# TLS may be pinned to leaf certificates while the server-certificate
# integrity check must verify against the issuing cluster CA. They are the
# same file in a conventional deployment, but separate in the HA lab.
cluster_ca_file="${CHAOS_CLUSTER_CA_FILE:-$tls_ca_file}"
if [[ -f "$tls_ca_file" ]]; then
    curl_base_args+=(--cacert "$tls_ca_file")
elif [[ "${CHAOS_INSECURE_TLS:-0}" == "1" ]]; then
    curl_base_args+=(--insecure)
elif [[ -n "${RH_CA_FILE:-}" ]]; then
    chaos_die "RH_CA_FILE is not readable: $tls_ca_file"
fi
if [[ "$PREFLIGHT_ONLY" != "1" && "${CHAOS_SERVER_CERT_CHECK:-1}" != "0" \
    && ! -r "$cluster_ca_file" ]]; then
    chaos_die "CHAOS_CLUSTER_CA_FILE is not readable: $cluster_ca_file"
fi

token_value() {
    if [[ -n "${RH_TOKEN_FILE:-}" ]]; then
        tr -d '\n\r' < "$RH_TOKEN_FILE"
    else
        printf '%s' "$RH_TOKEN"
    fi
}

curl_raw() {
    curl "${curl_base_args[@]}" --fail-with-body "$@"
}

curl_auth() {
    local url="$1"; shift
    local token
    token="$(token_value)"
    curl "${curl_base_args[@]}" --fail-with-body \
        -H "Authorization: Bearer ${token}" "$@" "$url"
}

api() {
    local path="$1"; shift
    curl_auth "${RH_URL%/}/api/v1/vault${path}" "$@"
}

api_at() {
    local base="$1" path="$2"; shift 2
    curl_auth "${base%/}/api/v1/vault${path}" "$@"
}

audit_api_at() {
    local base="$1" path="$2"; shift 2
    curl_auth "${base%/}/api/v1/vault${path}" \
        --max-time "$AUDIT_HTTP_TIMEOUT" "$@"
}

audit_any_node() {
    # Audit verification grows with retained evidence and can legitimately run
    # longer than the loopback workload proxy's short backend timeout. Query
    # direct node URLs, failing over to the next HA member on connection error.
    local path="$1" uuid base tmp
    shift
    tmp=$(mktemp "$RUN_DIR/.audit-api.XXXXXX")
    for uuid in "${UUIDS[@]}"; do
        base=$(url_for_uuid "$uuid")
        if audit_api_at "$base" "$path" "$@" > "$tmp"; then
            cat "$tmp"
            rm -f "$tmp"
            return 0
        fi
    done
    rm -f "$tmp"
    return 1
}

audit_verify() {
    # New deployments persist verification as a cluster-wide background job,
    # so an O(N) chain walk is never tied to an nginx/client timeout. Keep the
    # synchronous direct-node path as a compatibility fallback during rollout.
    local submitted job_id status started response
    # Submission is application-idempotent while a job is active. Direct-node
    # failover can therefore reconcile a lost POST response without teaching
    # the generic proxy to replay arbitrary mutations.
    submitted=$(audit_any_node "/audit/verify/jobs" -X POST 2>/dev/null || true)
    job_id=$(jq -r '.job_id // empty' <<< "$submitted" 2>/dev/null || true)
    if [[ -z "$job_id" ]]; then
        audit_any_node "/audit/verify"
        return
    fi

    started=$(date +%s)
    while (( $(date +%s) - started < AUDIT_JOB_TIMEOUT )); do
        response=$(api "/audit/verify/jobs/${job_id}" 2>/dev/null || true)
        status=$(jq -r '.status // empty' <<< "$response" 2>/dev/null || true)
        case "$status" in
            succeeded)
                jq -c '.result' <<< "$response"
                return 0
                ;;
            failed)
                jq -r '.error // "audit verification job failed"' <<< "$response" >&2
                return 1
                ;;
            pending|running)
                sleep "$AUDIT_JOB_POLL"
                ;;
            *)
                # A failover can make one poll transiently unavailable. The
                # durable job remains authoritative, so keep polling until the
                # explicit job deadline instead of starting a duplicate scan.
                sleep "$AUDIT_JOB_POLL"
                ;;
        esac
    done
    echo "audit verification job timed out id=${job_id}" >&2
    return 1
}

audit_preflight() {
    # Routine preflight authenticates a recent full anchor and checks only the
    # suffix. If the API reports that a deep scan is required, it has already
    # queued the cluster-wide job; wait on that explicit job, then retry the
    # bounded check once. No reverse-proxy request carries the O(N) scan.
    local response job_id status started
    response=$(audit_any_node "/audit/verify/preflight" -X POST 2>/dev/null || true)
    if jq -e '.preflight_ready == true' <<< "$response" >/dev/null 2>&1; then
        printf '%s\n' "$response"
        return 0
    fi
    job_id=$(jq -r '.full_verification_job.job_id // empty' \
        <<< "$response" 2>/dev/null || true)
    if [[ -z "$job_id" ]]; then
        # Compatibility during a rolling upgrade where one node may not have
        # the incremental endpoint yet.
        audit_verify
        return
    fi

    started=$(date +%s)
    while (( $(date +%s) - started < AUDIT_JOB_TIMEOUT )); do
        response=$(api "/audit/verify/jobs/${job_id}" 2>/dev/null || true)
        status=$(jq -r '.status // empty' <<< "$response" 2>/dev/null || true)
        case "$status" in
            succeeded)
                response=$(audit_any_node "/audit/verify/preflight" \
                    -X POST 2>/dev/null || true)
                printf '%s\n' "$response"
                jq -e '.preflight_ready == true' <<< "$response" >/dev/null
                return
                ;;
            failed)
                jq -r '.error // "audit verification job failed"' \
                    <<< "$response" >&2
                return 1
                ;;
            *)
                sleep "$AUDIT_JOB_POLL"
                ;;
        esac
    done
    echo "audit preflight full-verification job timed out id=${job_id}" >&2
    return 1
}

root_at() {
    local base="$1" path="$2"; shift 2
    curl_raw "$@" "${base%/}${path}"
}

json_event() {
    local kind="$1" msg="$2"
    jq -cn --arg ts "$(date -u +%FT%TZ)" --arg kind "$kind" --arg msg "$msg" \
        '{ts:$ts, kind:$kind, msg:$msg}' >> "$EVENTS"
}

json_failure() {
    local component="$1" msg="$2" severity="${3:-transient}"
    jq -cn --arg ts "$(date -u +%FT%TZ)" --arg severity "$severity" \
        --arg component "$component" --arg msg "$msg" \
        '{ts:$ts, severity:$severity, component:$component, msg:$msg}' >> "$FAILURES"
}

http_failure_summary() {
    # Report only the status/error class and structured reason. Never copy a
    # failed API body wholesale into evidence because it could contain secret
    # request data or another sensitive diagnostic.
    local raw="$1" status reason error_name
    status=$(sed -nE 's/.*returned error: ([0-9]{3}).*/\1/p' <<< "$raw" | tail -1)
    reason=$(grep -oE '"reason"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$raw" \
        | tail -1 | sed -E 's/^"reason"[[:space:]]*:[[:space:]]*"([^"]+)"$/\1/' || true)
    error_name=$(grep -oE '"error"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$raw" \
        | tail -1 | sed -E 's/^"error"[[:space:]]*:[[:space:]]*"([^"]+)"$/\1/' || true)
    printf 'status=%s reason=%s' \
        "${status:-transport_error}" "${reason:-${error_name:-unclassified}}"
}

# Requests issued while a chaos node is intentionally down are expected to
# fail; keep them visible without counting them as HA defects.
expected_fault_window() {
    [[ -s "$DOWN_FILE" ]]
}

host_for_uuid() {
    jq -r --arg u "$1" '.[$u] // empty' <<< "$HOST_MAP"
}

url_for_uuid() {
    local uuid="$1" host url tpl
    host=$(host_for_uuid "$uuid")
    if [[ -n "$URL_MAP" ]]; then
        url=$(jq -r --arg u "$uuid" '.[$u] // empty' <<< "$URL_MAP")
        [[ -n "$url" ]] && { printf '%s\n' "$url"; return; }
    fi
    tpl="${CHAOS_NODE_URL_TEMPLATE:-}"
    if [[ -n "$tpl" ]]; then
        url="${tpl//\{uuid\}/$uuid}"
        url="${url//\{host\}/$host}"
        printf '%s\n' "$url"
        return
    fi
    printf '%s\n' "$RH_URL"
}

render_template() {
    local tpl="$1" uuid="$2" host="$3" url="$4"
    tpl="${tpl//\{uuid\}/$uuid}"
    tpl="${tpl//\{host\}/$host}"
    tpl="${tpl//\{url\}/$url}"
    printf '%s\n' "$tpl"
}

run_template() {
    local label="$1" tpl="$2" uuid="$3" host="$4" url="$5" cmd
    cmd=$(render_template "$tpl" "$uuid" "$host" "$url")
    json_event "$label" "$cmd"
    bash -lc "$cmd"
}

run_pressure_template() {
    local label="$1" tpl="$2" uuid="$3" host="$4" url="$5" gib="$6" cmd
    cmd=$(render_template "$tpl" "$uuid" "$host" "$url")
    cmd="${cmd//\{gib\}/$gib}"
    cmd="${cmd//\{run_id\}/$RUN_ID}"
    json_event "$label" "$cmd"
    bash -lc "$cmd"
}

run_worker_kill_template() {
    local label="$1" tpl="$2" uuid="$3" host="$4" url="$5" pid="$6" cmd
    cmd=$(render_template "$tpl" "$uuid" "$host" "$url")
    cmd="${cmd//\{pid\}/$pid}"
    json_event "$label" "$cmd"
    bash -lc "$cmd"
}

kill_one_follower() {
    local uuid="$1" host="$2" url="$3" topology pid
    if ! topology=$(api_at "$url" "/cluster" 2>/dev/null); then
        json_failure worker_fault \
            "cannot read worker topology uuid=$uuid host=$host" critical
        return 1
    fi
    if ! pid=$(jq -er '
        .this_host as $host
        | [.hosts[$host].followers[]?
            | select(.worker_state == "follower")][0].pid
        | select(type == "number")
    ' <<< "$topology"); then
        json_failure worker_fault \
            "no live follower available uuid=$uuid host=$host" critical
        return 1
    fi

    json_event worker_fault \
        "kill start uuid=$uuid host=$host pid=$pid after=disk_pressure"
    if ! run_worker_kill_template worker_kill_command \
        "$CHAOS_WORKER_KILL_CMD" "$uuid" "$host" "$url" "$pid"; then
        json_failure worker_fault \
            "kill command failed uuid=$uuid host=$host pid=$pid" critical
        return 1
    fi
    if wait_worker_convergence "$uuid"; then
        json_event worker_fault \
            "recovered uuid=$uuid host=$host old_pid=$pid workers=$EXPECTED_WORKERS"
        return 0
    fi
    return 1
}

pressure_cleanup_all() {
    local uuid host url
    [[ "$DISK_PRESSURE" == "1" ]] || return 0
    declare -p UUIDS >/dev/null 2>&1 || return 0
    for uuid in "${UUIDS[@]}"; do
        host=$(host_for_uuid "$uuid")
        url=$(url_for_uuid "$uuid")
        [[ -n "$host" ]] || continue
        if ! run_pressure_template disk_pressure_cleanup \
            "$CHAOS_DISK_PRESSURE_CLEANUP_CMD" "$uuid" "$host" "$url" 0; then
            json_failure disk_pressure \
                "cleanup failed uuid=$uuid host=$host run_id=$RUN_ID" critical
        fi
    done
}

ha_nodes_expr='(.members // .nodes // [])'

ha_snapshot() {
    api "/cluster/ha"
}

ha_node_count() {
    jq "$ha_nodes_expr | length"
}

ha_uuid_list() {
    jq -r "$ha_nodes_expr[]?.node_uuid"
}

ha_state_for() {
    local uuid="$1"
    jq -r --arg u "$uuid" "$ha_nodes_expr[]? | select(.node_uuid == \$u) | .ha_state"
}

ha_is_steady() {
    local want="${1:-3}"
    jq -e --argjson want "$want" '
        (.members // .nodes // []) as $nodes
        | (.primary_uuid // "") as $primary
        | (($nodes | length) >= $want)
          and (($primary | length) > 0)
          and (([$nodes[] | select(.ha_state == "primary")] | length) == 1)
          and (([$nodes[] | select(
            .node_uuid == $primary and .ha_state == "primary"
          )] | length) == 1)
          and (([$nodes[] | select(
            .ha_state != "primary" and .ha_state != "secondary"
          )] | length) == 0)
          and (.ha_loaded == true)
    '
}

rand_between() {
    local min="$1" max="$2"
    if (( max <= min )); then
        echo "$min"
    else
        echo $(( min + RANDOM % (max - min + 1) ))
    fi
}

safe_name() {
    tr '/: ' '___' <<< "$1"
}

container_id_for_host() {
    local host="$1"
    docker_lab "$host" ps -a -q -f "label=${LABEL}" | head -n1
}

mark_down() {
    local uuid="$1"
    grep -qxF "$uuid" "$DOWN_FILE" 2>/dev/null || echo "$uuid" >> "$DOWN_FILE"
}

unmark_down() {
    local uuid="$1" tmp
    tmp="$DOWN_FILE.tmp"
    grep -vxF "$uuid" "$DOWN_FILE" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$DOWN_FILE"
}

stop_node() {
    local uuid="$1" host url cid
    host=$(host_for_uuid "$uuid")
    url=$(url_for_uuid "$uuid")
    [[ -n "$host" ]] || { json_failure fault "no host mapping for $uuid" critical; return 1; }
    json_event fault "down uuid=$uuid host=$host"
    if [[ -n "${CHAOS_DOWN_CMD:-}" ]]; then
        if ! run_template node_down "$CHAOS_DOWN_CMD" "$uuid" "$host" "$url"; then
            json_failure fault "down command failed uuid=$uuid host=$host" critical
            return 1
        fi
    else
        cid=$(container_id_for_host "$host")
        [[ -n "$cid" ]] \
            || { json_failure fault "no container label=$LABEL on $host" critical; return 1; }
        if ! docker_lab "$host" stop "$cid" >/dev/null; then
            json_failure fault "docker stop failed uuid=$uuid host=$host" critical
            return 1
        fi
    fi
    mark_down "$uuid"
}

start_node() {
    local uuid="$1" host url cid
    host=$(host_for_uuid "$uuid")
    url=$(url_for_uuid "$uuid")
    [[ -n "$host" ]] || { json_failure recovery "no host mapping for $uuid" critical; return 1; }
    json_event recovery "up uuid=$uuid host=$host"
    if [[ -n "${CHAOS_UP_CMD:-}" ]]; then
        if ! run_template node_up "$CHAOS_UP_CMD" "$uuid" "$host" "$url"; then
            json_failure recovery "up command failed uuid=$uuid host=$host" critical
            return 1
        fi
    else
        cid=$(container_id_for_host "$host")
        [[ -n "$cid" ]] \
            || { json_failure recovery "no container label=$LABEL on $host" critical; return 1; }
        if ! docker_lab "$host" start "$cid" >/dev/null; then
            json_failure recovery "docker start failed uuid=$uuid host=$host" critical
            return 1
        fi
    fi
    sleep "$RECOVER_DELAY"
    if [[ -n "${CHAOS_NODE_RECOVER_CMD:-}" ]]; then
        if ! run_template node_recover "$CHAOS_NODE_RECOVER_CMD" "$uuid" "$host" "$url"; then
            json_failure recovery "recover command failed uuid=$uuid host=$host" critical
            return 1
        fi
    fi
    # /unseal makes one uvicorn process the local crypto master. The remaining
    # workers attach asynchronously over RPC, so HA membership alone is not a
    # sufficient recovery signal. Keep the node in recovery until every
    # expected worker is operational.
    wait_worker_convergence "$uuid" || return 1
    unmark_down "$uuid"
}

wait_convergence() {
    local want="${1:-3}" deadline start ha n primary states elapsed
    start=$(date +%s)
    deadline=$(( $(date +%s) + CONVERGE_WAIT ))
    while (( $(date +%s) < deadline )); do
        if ha=$(ha_snapshot 2>/dev/null); then
            n=$(echo "$ha" | ha_node_count)
            primary=$(echo "$ha" | jq -r '.primary_uuid // empty')
            states=$(echo "$ha" | jq -r "$ha_nodes_expr[]?.ha_state" | sort | tr '\n' ' ')
            if echo "$ha" | ha_is_steady "$want" >/dev/null; then
                elapsed=$(( $(date +%s) - start ))
                json_event convergence "ok elapsed=${elapsed}s members=$n primary=$primary states=$states"
                return 0
            fi
        fi
        sleep 3
    done
    json_failure convergence "timeout after=${CONVERGE_WAIT}s waiting for members=$want" critical
    return 1
}

wait_worker_convergence() {
    local uuid="$1" base start deadline topology this_host elapsed summary
    (( EXPECTED_WORKERS > 0 )) || return 0

    base=$(url_for_uuid "$uuid")
    start=$(date +%s)
    deadline=$(( start + CONVERGE_WAIT ))
    while (( $(date +%s) < deadline )); do
        if topology=$(api_at "$base" "/cluster" 2>/dev/null); then
            # What this actually needs to know is "are all of this host's
            # workers back and serving", which is the worker COUNT and their
            # freshness. Requiring a master on top of that encoded the embedded
            # model, where one worker holds the sub-keys. Separated custody
            # abolishes that on purpose -- the custodian quorum holds them and
            # every API worker is an equal delegate -- so the master is checked
            # only when there is one, and its absence is not a failure.
            if jq -e --argjson expected "$EXPECTED_WORKERS" '
                .this_host as $host
                | .hosts[$host] as $slot
                | ($slot != null)
                  and ((($slot.followers | length)
                        + (if $slot.master == null then 0 else 1 end))
                       == $expected)
                  and (($slot.master == null)
                       or (($slot.master.age_sec // 999) < 5))
                  and all($slot.followers[]; (.age_sec // 999) < 5)
            ' <<< "$topology" >/dev/null; then
                this_host=$(jq -r '.this_host' <<< "$topology")
                elapsed=$(( $(date +%s) - start ))
                json_event worker_convergence \
                    "ok uuid=$uuid host=$this_host elapsed=${elapsed}s workers=$EXPECTED_WORKERS"
                return 0
            fi
            summary=$(jq -c --argjson expected "$EXPECTED_WORKERS" '
                .this_host as $host
                | .hosts[$host] as $slot
                | {
                    host: $host,
                    expected: $expected,
                    master: ($slot.master.pid // null),
                    followers: ([$slot.followers[]?
                        | select(.worker_state == "follower")] | length),
                    sealed: ([$slot.followers[]?
                        | select(.worker_state == "sealed")] | length),
                    max_age_sec: ($slot.max_age_sec // null)
                  }
            ' <<< "$topology" 2>/dev/null || true)
        fi
        sleep 2
    done
    json_failure worker_convergence \
        "timeout after=${CONVERGE_WAIT}s uuid=$uuid state=${summary:-unavailable}" critical
    return 1
}

promote_survivor_if_needed() {
    local uuid="$1" base state
    base=$(url_for_uuid "$uuid")
    state=$(ha_snapshot 2>/dev/null | ha_state_for "$uuid" || true)
    if [[ "$state" == "primary" ]]; then
        json_event survivor "already primary uuid=$uuid"
        return 0
    fi
    json_event survivor "promote uuid=$uuid base=$base state=${state:-unknown}"
    if api_at "$base" "/cluster/promote/${uuid}" -X POST > "$RUN_DIR/survivor-promote-${uuid}.json" 2>&1; then
        return 0
    fi
    if grep -q "already primary" "$RUN_DIR/survivor-promote-${uuid}.json" 2>/dev/null; then
        return 0
    fi
    json_failure survivor "promote failed uuid=$uuid; see survivor-promote-${uuid}.json" critical
    return 1
}

single_survivor_probe() {
    local uuid="$1" base name val got topology readiness_code this_host
    local followers has_master all_followers_ok expect_master role_detail expected_followers
    base=$(url_for_uuid "$uuid")
    name="k7-survivor-$(date +%s%N)"
    val="$(openssl rand -base64 24)"

    readiness_code=$(curl "${curl_base_args[@]}" --output "$RUN_DIR/readiness-survivor-${uuid}.json" \
        --write-out '%{http_code}' "${base%/}/readiness" 2>/dev/null || true)
    [[ "$readiness_code" == "200" ]] \
        || json_failure survivor "readiness != 200 uuid=$uuid code=${readiness_code:-curl_failed}" critical

    if api_at "$base" "/secrets/" -X POST -H 'Content-Type: application/json' \
        -d "$(jq -n --arg n "$name" --arg v "$val" --arg ns "$NS" \
            '{name:$n,value:$v,namespace:$ns,metadata:{chaos:"k7-single-survivor"}}')" \
        > /dev/null 2>&1; then
        got=$(api_at "$base" "/secrets/${name}?namespace=${NS}" 2>/dev/null | jq -r '.value // empty')
        [[ "$got" == "$val" ]] \
            || json_failure survivor "secret readback mismatch uuid=$uuid name=$name" critical
    else
        json_failure survivor "secret write failed uuid=$uuid" critical
    fi

    # Keep an audit data-path canary in the fault window, but never run the
    # O(N) full-chain verifier while load/fault injection is active.
    if ! api_at "$base" "/audit/lite?limit=1" > "$RUN_DIR/audit-survivor-${uuid}.json" 2>&1; then
        json_failure survivor "audit-lite canary failed uuid=$uuid" critical
    elif ! jq -e '.count >= 1' \
        "$RUN_DIR/audit-survivor-${uuid}.json" >/dev/null; then
        json_failure survivor "audit-lite canary empty uuid=$uuid" critical
    fi

    if topology=$(api_at "$base" "/cluster" 2>/dev/null); then
        printf '%s\n' "$topology" > "$RUN_DIR/cluster-survivor-${uuid}.json"
        if (( EXPECTED_WORKERS > 0 )); then
            this_host=$(jq -r '.this_host // empty' <<< "$topology")

            # Count followers and master SEPARATELY.
            #
            # This used to be followers + (1 if master else 0). Five followers
            # and no master then sums to 5, which equals EXPECTED_WORKERS and
            # passes -- the same number a healthy 4-followers-plus-master host
            # produces. The arithmetic aliased the exact condition the role
            # check below exists to catch.
            followers=$(jq --arg h "$this_host" '[.hosts[$h].followers[]?] | length' <<< "$topology")
            has_master=$(jq -r --arg h "$this_host" 'if .hosts[$h].master then "yes" else "no" end' <<< "$topology")
            all_followers_ok=$(jq -r --arg h "$this_host" \
                'all(.hosts[$h].followers[]?; .worker_state == "follower")' <<< "$topology")

            # A master worker only exists in EMBEDDED / python custody, where one
            # worker holds the sub-keys and the others reach it over a crypto
            # socket -- /cluster only reports `master` for worker_state='master'
            # WITH a crypto_socket_name. Under separated+rust every worker drives
            # the custodian pool in-process, so there is no master and never will
            # be. Demanding one here produced a critical on every probe of a
            # perfectly healthy cluster (26 of them across the 24h run).
            #
            # Detected from the topology rather than configured, so the probe
            # cannot drift from the deployment it is pointed at.
            expect_master=$(jq -r '
                [.hosts[]?.master] | map(select(. != null)) | length > 0
            ' <<< "$topology")

            role_detail=""
            if [[ "$all_followers_ok" != "true" ]]; then
                role_detail="a follower is not in follower state"
            elif [[ "$expect_master" == "true" && "$has_master" == "no" ]]; then
                # Other hosts report a master, so this IS a master-bearing
                # deployment and this host losing its own master is real.
                role_detail="no master on this host while other hosts have one"
            fi

            # Expected worker count excludes the master where one exists, so the
            # two deployment shapes are compared against the same number.
            expected_followers=$EXPECTED_WORKERS
            [[ "$has_master" == "yes" ]] && expected_followers=$(( EXPECTED_WORKERS - 1 ))

            if (( followers != expected_followers )) || [[ -n "$role_detail" ]]; then
                # Say WHICH condition failed. The old message printed only the
                # count, so "worker coverage 5/5 critical" was unreadable.
                json_failure survivor \
                    "worker coverage followers=${followers}/${expected_followers} master=${has_master}${role_detail:+ -- $role_detail} uuid=$uuid" \
                    critical
            fi
        fi
    else
        json_failure survivor "cluster topology failed uuid=$uuid" critical
    fi
}

writer_loop() {
    local id="$1" seq=0 name val hash payload response retry_response
    local failure_detail committed_value reconciled
    while :; do
        name="k7-${RUN_ID}-w${id}-${seq}"
        val="$(openssl rand -base64 24)"
        payload=$(jq -n --arg n "$name" --arg v "$val" --arg ns "$NS" \
            '{name:$n,value:$v,namespace:$ns,metadata:{chaos:"k7"}}')
        reconciled=0
        committed_value=""
        retry_response=""
        if response=$(api "/secrets/" -X POST -H 'Content-Type: application/json' \
            -d "$payload" 2>&1); then
            reconciled=1
        else
            failure_detail=$(http_failure_summary "$response")
            # An HTTP/2 GOAWAY/read error can lose the response after the
            # database committed. The run-specific secret name is unique, so
            # first reconcile by name; only retry when no matching value is
            # visible, then verify once more if that retry is also uncertain.
            committed_value=$(api "/secrets/${name}?namespace=${NS}" 2>/dev/null \
                | jq -r '.value // empty' || true)
            if [[ "$committed_value" == "$val" ]]; then
                reconciled=1
                json_event transport_reconciled \
                    "write committed before uncertain response id=$id name=$name $failure_detail"
            elif [[ -n "$committed_value" ]]; then
                json_failure writer \
                    "write name collision id=$id name=$name" critical
            elif retry_response=$(api "/secrets/" -X POST \
                -H 'Content-Type: application/json' -d "$payload" 2>&1); then
                reconciled=1
                json_event transport_reconciled \
                    "write safely retried after absent readback id=$id name=$name $failure_detail"
            else
                committed_value=$(api "/secrets/${name}?namespace=${NS}" 2>/dev/null \
                    | jq -r '.value // empty' || true)
                if [[ "$committed_value" == "$val" ]]; then
                    reconciled=1
                    json_event transport_reconciled \
                        "write verified after uncertain retry id=$id name=$name $failure_detail"
                else
                    failure_detail=$(http_failure_summary "$retry_response")
                fi
            fi
        fi
        if (( reconciled == 1 )); then
            hash=$(printf '%s' "$val" | sha256sum | awk '{print $1}')
            printf '%s\t%s\t%s\t%s\n' "$(date +%s%N)" "$name" "$hash" "$id" >> "$WRITTEN"
        elif [[ -z "$committed_value" ]]; then
            if expected_fault_window; then
                json_event expected_fault \
                    "write rejected while node fault active id=$id name=$name $failure_detail"
            else
                json_failure writer "write failed id=$id name=$name $failure_detail"
            fi
        fi
        seq=$((seq + 1))
        sleep "$WRITER_SLEEP"
    done
}

reader_loop() {
    local id="$1" row name hash val got_hash response failure_detail
    while :; do
        if [[ -s "$WRITTEN" ]]; then
            row=$(shuf -n 1 "$WRITTEN" 2>/dev/null || true)
            if [[ -n "$row" ]]; then
                IFS=$'\t' read -r _ name hash _writer <<< "$row"
                if response=$(api "/secrets/${name}?namespace=${NS}" 2>&1); then
                    val=$(jq -r '.value // empty' <<< "$response" 2>/dev/null || true)
                else
                    failure_detail=$(http_failure_summary "$response")
                    if expected_fault_window; then
                        json_event expected_fault \
                            "read unavailable while node fault active id=$id name=$name $failure_detail"
                    else
                        json_failure reader \
                            "read failed id=$id name=$name $failure_detail"
                    fi
                    sleep "$READER_SLEEP"
                    continue
                fi
                if [[ -z "$val" ]]; then
                    if expected_fault_window; then
                        json_event expected_fault "read unavailable while node fault active id=$id name=$name"
                    else
                        json_failure reader "miss id=$id name=$name"
                    fi
                else
                    got_hash=$(printf '%s' "$val" | sha256sum | awk '{print $1}')
                    [[ "$got_hash" == "$hash" ]] \
                        || json_failure reader "mismatch id=$id name=$name expected=$hash got=$got_hash" critical
                fi
            fi
        fi
        sleep "$READER_SLEEP"
    done
}

ensure_pki_ca() {
    local ns="${CHAOS_PKI_NAMESPACE:-$NS}" alg="${CHAOS_PKI_ALGORITHM:-ed25519}"
    if api "/pki/ca?namespace=${ns}" > "$RUN_DIR/pki-ca.json" 2>/dev/null; then
        return 0
    fi
    api "/pki/init" -X POST -H 'Content-Type: application/json' \
        -d "$(jq -n --arg ns "$ns" --arg alg "$alg" \
            '{namespace:$ns,algorithm:$alg,common_name:"rhorizon-chaos-k7",validity_days:30}')" \
        > "$RUN_DIR/pki-init.json" 2>&1 || {
            json_failure pki "init failed namespace=$ns; see pki-init.json"
            return 1
        }
}

revoke_pki_serial() {
    # Revoke with retries, and record the HTTP status when it finally fails.
    #
    # Two things were wrong before. The call discarded its response
    # (`> /dev/null 2>&1`), so a failure recorded "revoke failed serial=..."
    # with no status -- unlike reader_loop, which keeps the response and runs
    # http_failure_summary. And there was no retry, so a revoke that raced a
    # deliberate node kill was dropped on the first attempt. Both 2026-08-08
    # failures were of that kind (within 10s of a two-node kill).
    #
    # A dropped revoke is not cosmetic: the certificate stays valid for its
    # full ttl_days. Retrying across the outage is what actually prevents the
    # leftover ; classifying it merely stops it being mistaken for a defect.
    local serial="$1" attempt=1 response=""
    local max="${CHAOS_PKI_REVOKE_RETRIES:-3}"
    local delay="${CHAOS_PKI_REVOKE_RETRY_DELAY_SECS:-5}"
    while :; do
        if response=$(api "/pki/revoke" -X POST -H 'Content-Type: application/json' \
            -d "$(jq -n --arg s "$serial" '{serial:$s,reason:"chaos-k7"}')" 2>&1); then
            (( attempt > 1 )) && json_event pki "revoke succeeded on attempt $attempt serial=$serial"
            return 0
        fi
        (( attempt >= max )) && break
        attempt=$((attempt + 1))
        sleep "$delay"
    done
    local detail
    detail=$(http_failure_summary "$response")
    if expected_fault_window; then
        json_event expected_fault \
            "pki revoke unavailable while node fault active serial=$serial attempts=$max $detail"
    else
        json_failure pki "revoke failed serial=$serial attempts=$max $detail"
    fi
    return 1
}

pki_loop() {
    [[ "${CHAOS_PKI_ENABLED:-1}" == "0" ]] && return 0
    local ns="${CHAOS_PKI_NAMESPACE:-$NS}" seq=0 cn serial issue_detail
    ensure_pki_ca || return 0
    while :; do
        cn="k7-${seq}.chaos.local"
        if api "/pki/issue" -X POST -H 'Content-Type: application/json' \
            -d "$(jq -n --arg ns "$ns" --arg cn "$cn" \
                '{namespace:$ns,common_name:$cn,san_dns:[$cn],ttl_days:1}')" \
            > "$RUN_DIR/pki-issue-${seq}.json" 2>&1; then
            serial=$(jq -r '.serial // empty' "$RUN_DIR/pki-issue-${seq}.json")
            printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$cn" "$serial" >> "$PKI_LOG"
            if [[ -n "$serial" && "${CHAOS_PKI_REVOKE:-1}" == "1" ]]; then
                revoke_pki_serial "$serial"
            fi
        else
            issue_detail=$(http_failure_summary "$(cat "$RUN_DIR/pki-issue-${seq}.json" 2>/dev/null)")
            if expected_fault_window; then
                json_event expected_fault \
                    "pki issue unavailable while node fault active seq=$seq $issue_detail"
            else
                json_failure pki "issue failed seq=$seq $issue_detail"
            fi
        fi
        seq=$((seq + 1))
        sleep "${CHAOS_PKI_INTERVAL_SECS:-30}"
    done
}

server_cert_loop() {
    # Does every node actually serve a cluster-CA-minted server cert?
    #
    # pki_loop above exercises the PKI *engine* (application certs). Nothing
    # checked the nginx server certs the cluster's own mTLS rests on, so a
    # joiner that never got one went unnoticed for a full 24h run: only the
    # primary is handed a CA-signed cert at bootstrap (bootstrap-init.yml step
    # 3b is hosts: rhorizon_primary), and the renewal loop used to trigger on
    # expiry alone -- which never fires on a 10-year self-signed placeholder.
    #
    # The run itself could not notice, because it trusts a pinned bundle that
    # was built by scraping whatever the nodes happened to serve, self-signed
    # entries included. Hence checking the served cert's issuer directly.
    [[ "${CHAOS_SERVER_CERT_CHECK:-1}" == "0" ]] && return 0
    if ! command -v openssl > /dev/null 2>&1; then
        json_event cluster_cert "server-cert check disabled: openssl not found"
        return 0
    fi
    local port="${CHAOS_SERVER_CERT_PORT:-8443}"
    local uuid host pem issuer subject tmp
    while :; do
        while read -r uuid; do
            [[ -n "$uuid" ]] || continue
            host=$(host_for_uuid "$uuid")
            [[ -n "$host" ]] || continue
            pem=$(timeout "$CONNECT_TIMEOUT" openssl s_client -connect "${host}:${port}" \
                < /dev/null 2>/dev/null | openssl x509 2>/dev/null) || pem=""
            # No handshake means the node is down -- this loop runs alongside
            # deliberate outages, so that is not a certificate fault.
            [[ -n "$pem" ]] || continue
            issuer=$(openssl x509 -noout -issuer <<< "$pem" 2>/dev/null)
            subject=$(openssl x509 -noout -subject <<< "$pem" 2>/dev/null)
            if [[ "${issuer#issuer=}" == "${subject#subject=}" ]]; then
                json_failure cluster_cert \
                    "node serves a self-signed server cert (never CA-minted) uuid=$uuid host=$host ${subject}" \
                    critical
                continue
            fi
            tmp=$(mktemp "${TMPDIR:-/tmp}/k7-servercert.XXXXXX") || continue
            printf '%s\n' "$pem" > "$tmp"
            if ! openssl verify -CAfile "$cluster_ca_file" "$tmp" > /dev/null 2>&1; then
                json_failure cluster_cert \
                    "node server cert does not chain to the cluster CA uuid=$uuid host=$host ${issuer}" \
                    critical
            fi
            rm -f "$tmp"
        done < <(jq -r 'keys[]' <<< "$HOST_MAP" 2>/dev/null)
        sleep "${CHAOS_SERVER_CERT_INTERVAL_SECS:-300}"
    done
}

mtls_loop() {
    # Does cluster mTLS actually reject callers it should?
    #
    # nginx fronts the cluster with ssl_verify_client optional_no_ca: it asks
    # for a client cert and forwards whatever it gets as X-Client-Cert without
    # validating it. The API is therefore the ONLY thing deciding whether a
    # caller may reach /cluster/refresh-cert. If that check ever degrades to
    # fail-open, nothing else in the stack notices -- the handshake still
    # succeeds and the request still looks normal in the access log.
    #
    # Both probes below are negative: a 200 is the failure. We cannot mint a
    # cert the cluster CA would accept (that is the point), so this asserts the
    # rejections, which is the security-relevant direction.
    [[ "${CHAOS_MTLS_CHECK:-1}" == "0" ]] && return 0
    if ! command -v openssl > /dev/null 2>&1; then
        json_event cluster_mtls "mTLS check disabled: openssl not found"
        return 0
    fi
    local port="${CHAOS_MTLS_PORT:-${CHAOS_SERVER_CERT_PORT:-8443}}"
    local path="/api/v1/vault/cluster/refresh-cert"
    local dir uuid host code
    dir=$(mktemp -d "${TMPDIR:-/tmp}/k7-mtls.XXXXXX") || return 0
    # A throwaway self-signed pair: valid TLS material, wrong signer. Exactly
    # what an attacker on the wire could produce for themselves.
    if ! openssl req -x509 -newkey rsa:2048 -keyout "$dir/forged.key" \
        -out "$dir/forged.crt" -days 1 -nodes -subj "/CN=k7-forged-client" \
        > /dev/null 2>&1; then
        json_event cluster_mtls "mTLS check disabled: could not mint a test client cert"
        rm -rf "$dir"
        return 0
    fi
    while :; do
        while read -r uuid; do
            [[ -n "$uuid" ]] || continue
            host=$(host_for_uuid "$uuid")
            [[ -n "$host" ]] || continue

            # 1. No client certificate at all.
            code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
                --connect-timeout "$CONNECT_TIMEOUT" --max-time 20 \
                --cacert "$cluster_ca_file" \
                "https://${host}:${port}${path}" 2>/dev/null) || code=""
            # Empty means no answer -- the node is down, which this loop runs
            # alongside on purpose. Not an mTLS fault.
            if [[ "$code" == "200" ]]; then
                json_failure cluster_mtls \
                    "refresh-cert accepted a request with NO client cert uuid=$uuid host=$host" \
                    critical
            fi

            # 2. A syntactically valid cert the cluster CA never signed.
            code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
                --connect-timeout "$CONNECT_TIMEOUT" --max-time 20 \
                --cacert "$cluster_ca_file" \
                --cert "$dir/forged.crt" --key "$dir/forged.key" \
                "https://${host}:${port}${path}" 2>/dev/null) || code=""
            if [[ "$code" == "200" ]]; then
                json_failure cluster_mtls \
                    "refresh-cert accepted a client cert NOT signed by the cluster CA uuid=$uuid host=$host" \
                    critical
            fi
        done < <(jq -r 'keys[]' <<< "$HOST_MAP" 2>/dev/null)
        sleep "${CHAOS_MTLS_INTERVAL_SECS:-300}"
    done
}

dynamic_loop() {
    [[ -n "${CHAOS_DYNAMIC_ENGINE_ID:-}" && -n "${CHAOS_DYNAMIC_ROLE_NAME:-}" ]] || {
        json_event dynamic "disabled: set CHAOS_DYNAMIC_ENGINE_ID and CHAOS_DYNAMIC_ROLE_NAME"
        return 0
    }
    local seq=0 lease user
    while :; do
        if api "/dynamic/engines/${CHAOS_DYNAMIC_ENGINE_ID}/creds/${CHAOS_DYNAMIC_ROLE_NAME}" \
            -X POST -H 'Content-Type: application/json' \
            -d "$(jq -n --argjson ttl "${CHAOS_DYNAMIC_TTL_SECS:-300}" '{ttl_seconds:$ttl}')" \
            > "$RUN_DIR/dynamic-creds-${seq}.json" 2>&1; then
            lease=$(jq -r '.lease_id // empty' "$RUN_DIR/dynamic-creds-${seq}.json")
            user=$(jq -r '.username // empty' "$RUN_DIR/dynamic-creds-${seq}.json")
            printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$user" "$lease" >> "$DYNAMIC_LOG"
            if [[ -n "$lease" && "${CHAOS_DYNAMIC_RENEW:-1}" == "1" ]]; then
                api "/dynamic/leases/${lease}/renew" -X POST -H 'Content-Type: application/json' \
                    -d "$(jq -n --argjson ttl "${CHAOS_DYNAMIC_RENEW_TTL_SECS:-600}" '{ttl_seconds:$ttl}')" \
                    > /dev/null 2>&1 || {
                    if expected_fault_window; then
                        json_event expected_fault "dynamic renew unavailable while node fault active lease=$lease"
                    else
                        json_failure dynamic "renew failed lease=$lease"
                    fi
                }
            fi
            if [[ -n "$lease" && "${CHAOS_DYNAMIC_REVOKE:-1}" == "1" ]]; then
                if ! api "/dynamic/leases/${lease}/revoke" -X POST > /dev/null 2>&1; then
                    if expected_fault_window; then
                        json_event expected_fault "dynamic revoke unavailable while node fault active lease=$lease"
                    else
                        json_failure dynamic "revoke failed lease=$lease"
                    fi
                fi
            fi
        else
            if expected_fault_window; then
                json_event expected_fault "dynamic mint unavailable while node fault active seq=$seq"
            else
                json_failure dynamic "credential mint failed seq=$seq"
            fi
        fi
        seq=$((seq + 1))
        sleep "${CHAOS_DYNAMIC_INTERVAL_SECS:-60}"
    done
}

alert_loop() {
    [[ -n "${CHAOS_ALERT_CHANNEL_ID:-}" ]] || {
        json_event alerting "disabled: set CHAOS_ALERT_CHANNEL_ID to send tests"
        return 0
    }
    local seq=0
    while :; do
        if api "/notifications/${CHAOS_ALERT_CHANNEL_ID}/test" -X POST \
            > "$RUN_DIR/alert-${seq}.json" 2>&1; then
            printf '%s\t%s\n' "$(date -u +%FT%TZ)" "$CHAOS_ALERT_CHANNEL_ID" >> "$ALERT_LOG"
        else
            json_failure alerting "notification test failed channel=$CHAOS_ALERT_CHANNEL_ID"
        fi
        seq=$((seq + 1))
        sleep "${CHAOS_ALERT_INTERVAL_SECS:-900}"
    done
}

sample_once() {
    local idx="$1" ts readiness_file health_file uuid base code
    ts="$(date -u +%FT%TZ)"
    api "/cluster/ha" > "$RUN_DIR/samples/ha/${idx}.json" 2>"$RUN_DIR/samples/ha/${idx}.err" \
        || json_failure sample "cluster/ha failed idx=$idx"
    health_file="$RUN_DIR/samples/health/${idx}.json"
    if ! api "/cluster/health" > "$health_file" 2>"$RUN_DIR/samples/health/${idx}.err"; then
        json_failure database_ha "cluster/health failed idx=$idx" critical
    elif ! jq -e '
        .components.database.state == "green"
        and .components.database_ha.state == "green"
    ' "$health_file" >/dev/null; then
        json_failure database_ha \
            "PostgreSQL tier not green idx=$idx state=$(jq -c '.components.database_ha // {}' "$health_file" 2>/dev/null || printf '{}')" \
            critical
    fi
    api "/cluster" > "$RUN_DIR/samples/cluster/${idx}.json" 2>"$RUN_DIR/samples/cluster/${idx}.err" \
        || true
    api "/audit/lite?limit=1" > "$RUN_DIR/samples/audit/${idx}.json" 2>"$RUN_DIR/samples/audit/${idx}.err" \
        || json_failure sample "audit-lite canary failed idx=$idx"
    api "/observability" > "$RUN_DIR/samples/observability/${idx}.json" 2>"$RUN_DIR/samples/observability/${idx}.err" \
        || true
    api "/notifications/" > "$RUN_DIR/samples/notifications/${idx}.json" 2>"$RUN_DIR/samples/notifications/${idx}.err" \
        || true
    curl_raw "${RH_URL%/}/metrics" > "$RUN_DIR/samples/metrics/${idx}.prom" 2>"$RUN_DIR/samples/metrics/${idx}.err" \
        || json_failure sample "metrics scrape failed idx=$idx"
    if [[ -n "${CHAOS_LB_HEALTH_URL:-}" ]]; then
        curl_raw "$CHAOS_LB_HEALTH_URL" > "$RUN_DIR/samples/lb/${idx}.json" \
            2>"$RUN_DIR/samples/lb/${idx}.err" \
            || json_failure load_balancer "load balancer health failed idx=$idx" critical
    fi

    readiness_file="$RUN_DIR/samples/readiness/${idx}.tsv"
    : > "$readiness_file"
    for uuid in "${UUIDS[@]}"; do
        base=$(url_for_uuid "$uuid")
        code=$(curl "${curl_base_args[@]}" --output "$RUN_DIR/samples/readiness/${idx}-${uuid}.json" \
            --write-out '%{http_code}' "${base%/}/readiness" 2>/dev/null || true)
        printf '%s\t%s\t%s\t%s\n' "$ts" "$uuid" "$base" "${code:-curl_failed}" >> "$readiness_file"
        if [[ "$base" != "${RH_URL%/}" ]]; then
            curl_raw "${base%/}/metrics" > "$RUN_DIR/samples/metrics/${idx}-${uuid}.prom" \
                2>"$RUN_DIR/samples/metrics/${idx}-${uuid}.err" || true
        fi
    done
}

sampler_loop() {
    local idx=0
    while :; do
        sample_once "$(printf '%06d' "$idx")"
        idx=$((idx + 1))
        sleep "$SAMPLE_INT"
    done
}

disk_pressure_loop() {
    local sleep_for uuid host url gib started elapsed worker_kill_done=0
    while :; do
        sleep_for=$(rand_between "$PRESSURE_MIN_INTERVAL" "$PRESSURE_MAX_INTERVAL")
        json_event disk_pressure "sleep ${sleep_for}s before next pressure cycle"
        sleep "$sleep_for"

        # Do not combine a host I/O-pressure cycle with a node outage. Both are
        # useful faults, but overlapping them makes worker recovery evidence
        # ambiguous and can target a node while its VM is intentionally down.
        # The node fault loop takes the same local advisory lock for its whole
        # stop/hold/recovery cycle.
        {
            flock -x 9
            if [[ -s "$DOWN_FILE" ]]; then
                json_event disk_pressure "skip: a node fault is still active"
                continue
            fi

            uuid=$(printf '%s\n' "${UUIDS[@]}" | shuf -n 1)
            host=$(host_for_uuid "$uuid")
            url=$(url_for_uuid "$uuid")
            gib=$(rand_between "$PRESSURE_MIN_GIB" "$PRESSURE_MAX_GIB")
            if [[ -z "$host" ]]; then
                json_failure disk_pressure "no host mapping for $uuid" critical
                continue
            fi

            started=$(date +%s)
            json_event disk_pressure \
                "start uuid=$uuid host=$host size_gib=$gib"
            if run_pressure_template disk_pressure_command \
                "$CHAOS_DISK_PRESSURE_CMD" "$uuid" "$host" "$url" "$gib"; then
                elapsed=$(( $(date +%s) - started ))
                printf '%s\t%s\t%s\t%s\t%s\tok\n' \
                    "$(date -u +%FT%TZ)" "$uuid" "$host" "$gib" "$elapsed" \
                    >> "$DISK_PRESSURE_LOG"
                json_event disk_pressure \
                    "complete uuid=$uuid host=$host size_gib=$gib elapsed=${elapsed}s data_removed=true"
                # First prove pressure itself left a complete worker set. The
                # optional one-shot follower kill then exercises the exact OOM
                # regression without consuming a spare share every cycle.
                if wait_worker_convergence "$uuid"; then
                    if [[ "$WORKER_KILL_AFTER_PRESSURE" == "1" ]] \
                        && (( worker_kill_done == 0 )); then
                        worker_kill_done=1
                        kill_one_follower "$uuid" "$host" "$url" || true
                    fi
                fi
            else
                elapsed=$(( $(date +%s) - started ))
                printf '%s\t%s\t%s\t%s\t%s\tfailed\n' \
                    "$(date -u +%FT%TZ)" "$uuid" "$host" "$gib" "$elapsed" \
                    >> "$DISK_PRESSURE_LOG"
                json_failure disk_pressure \
                    "pressure command failed uuid=$uuid host=$host size_gib=$gib elapsed=${elapsed}s" \
                    critical
            fi
        } 9> "$FAULT_LOCK"
    done
}

fault_loop() {
    local sleep_for n shuffled down survivor hold uuid
    local -a actual_down
    while :; do
        sleep_for=$(rand_between "$FAULT_MIN" "$FAULT_MAX")
        json_event fault "sleep ${sleep_for}s before next fault"
        sleep "$sleep_for"

        {
        flock -x 9

        if (( RANDOM % 100 < TWO_DOWN_PROB )); then
            n=2
        else
            n=1
        fi

        mapfile -t shuffled < <(printf '%s\n' "${UUIDS[@]}" | shuf)
        down=("${shuffled[@]:0:$n}")
        json_event fault "selected n=$n uuids=${down[*]}"

        actual_down=()
        for uuid in "${down[@]}"; do
            if stop_node "$uuid"; then
                actual_down+=("$uuid")
            fi
            sleep 2
        done
        down=("${actual_down[@]}")
        n=${#down[@]}
        if (( n == 0 )); then
            json_failure fault "no selected node could be stopped" critical
            continue
        fi

        if (( n == 2 )); then
            survivor=""
            for uuid in "${UUIDS[@]}"; do
                if [[ "$uuid" != "${down[0]}" && "$uuid" != "${down[1]}" ]]; then
                    survivor="$uuid"
                fi
            done
            [[ -n "$survivor" ]] \
                || json_failure fault "could not determine survivor" critical
            if [[ -n "$survivor" && "$PROMOTE_SURVIVOR" == "1" ]]; then
                promote_survivor_if_needed "$survivor" || true
            fi
            [[ -n "$survivor" ]] && single_survivor_probe "$survivor"
            hold=$(rand_between "$TWO_DOWN_MIN" "$TWO_DOWN_MAX")
        else
            hold=$(rand_between "$ONE_DOWN_MIN" "$ONE_DOWN_MAX")
        fi

        json_event fault "hold ${hold}s with down=${down[*]}"
        sleep "$hold"

        for uuid in "${down[@]}"; do
            start_node "$uuid" || true
            sleep 3
        done
        wait_convergence 3 || true
        } 9> "$FAULT_LOCK"
    done
}

capture_remote_logs() {
    local uuid host safe cid
    for uuid in "${UUIDS[@]}"; do
        host=$(host_for_uuid "$uuid")
        [[ -n "$host" ]] || continue
        safe=$(safe_name "${uuid}-${host}")
        if [[ "$CAPTURE_DOCKER_LOGS" == "1" ]] \
            && cid=$(container_id_for_host "$host" 2>/dev/null) && [[ -n "$cid" ]]; then
            docker_lab "$host" logs --timestamps --since "$START_TS" "$cid" \
                > "$RUN_DIR/logs/${safe}.docker.log" 2>&1 || true
            docker_lab "$host" inspect "$cid" \
                > "$RUN_DIR/logs/${safe}.inspect.json" 2>&1 || true
        fi
        if [[ -n "$CAPTURE_JOURNAL_UNIT" ]]; then
            ssh_lab "$host" "journalctl -u '$CAPTURE_JOURNAL_UNIT' --since '$START_TS' --no-pager" \
                > "$RUN_DIR/logs/${safe}.journal.log" 2>&1 || true
        fi
        ssh_lab "$host" "date -u; uptime; df -h; free -m" \
            > "$RUN_DIR/logs/${safe}.host.txt" 2>&1 || true
    done
}

cleanup() {
    local uuid
    json_event cleanup "start"
    for pid in "${BG_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${BG_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    if [[ "${CHAOS_CLEANUP_START_NODES:-1}" == "1" && -s "$DOWN_FILE" ]]; then
        while read -r uuid; do
            [[ -n "$uuid" ]] && start_node "$uuid" || true
        done < "$DOWN_FILE"
    fi
    pressure_cleanup_all
    rm -f "$PID_FILE"
}

abort_run() {
    # A signal trap returns to the interrupted command unless it exits
    # explicitly.  Without this handler, Ctrl-C stopped the background
    # workload/fault loops but the main duration loop resumed sleeping, leaving
    # the K7 wrapper and loopback proxy orphaned until the original 24h elapsed.
    trap - EXIT INT TERM
    json_event finish "interrupted by signal"
    cleanup
    exit 130
}

BG_PIDS=()
echo $$ > "$PID_FILE"
trap cleanup EXIT
trap abort_run INT TERM

json_event start "K7 duration=${DURATION}s profile=$PROFILE namespace=$NS writers=$WRITERS readers=$READERS"

PRE_HA=$(ha_snapshot)
printf '%s\n' "$PRE_HA" > "$RUN_DIR/pre-cluster-ha.json"
jq -e . "$RUN_DIR/pre-cluster-ha.json" >/dev/null \
    || chaos_die "pre-flight /cluster/ha did not return valid JSON"
if ! api "/cluster/health" > "$RUN_DIR/pre-cluster-health.json"; then
    chaos_die "pre-flight /cluster/health request failed"
fi
if ! jq -e '
    .ready == true
    and .overall == "green"
    and .components.database.state == "green"
    and .components.database_ha.state == "green"
    and ((.components.database_ha.members // 0) >= 3)
    and ((.components.database_ha.lagging_members // []) | length == 0)
    and ((.components.database_ha.unknown_lag_members // []) | length == 0)
    and ((.components.database_ha.non_streaming_replicas // []) | length == 0)
    and ((.components.database_ha.timeline_mismatch_members // []) | length == 0)
' "$RUN_DIR/pre-cluster-health.json" >/dev/null; then
    chaos_die "pre-flight database HA tier is not fully converged; see pre-cluster-health.json"
fi
mapfile -t UUIDS < <(echo "$PRE_HA" | ha_uuid_list)
if (( ${#UUIDS[@]} < 3 )); then
    chaos_die "K7 expects at least 3 HA nodes, got ${#UUIDS[@]}"
fi
if (( TWO_DOWN_PROB > 0 && ${#UUIDS[@]} != 3 )); then
    chaos_die "two-node K7 faults require exactly 3 HA nodes, got ${#UUIDS[@]}"
fi
if ! echo "$PRE_HA" | ha_is_steady 3 >/dev/null; then
    chaos_die "pre-flight HA topology is not steady (primary/secondary, ha_loaded=true required)"
fi
for uuid in "${UUIDS[@]}"; do
    [[ -n "$(host_for_uuid "$uuid")" ]] || chaos_die "missing host mapping for $uuid"
done
if (( TWO_DOWN_PROB > 0 )) && [[ -z "$URL_MAP" && -z "${CHAOS_NODE_URL_TEMPLATE:-}" ]] \
    && [[ "$ALLOW_SHARED_SURVIVOR_URL" != "1" ]]; then
    chaos_die "two-node faults require CHAOS_URL_BY_UUID or CHAOS_NODE_URL_TEMPLATE"
fi
for uuid in "${UUIDS[@]}"; do
    base=$(url_for_uuid "$uuid")
    if (( TWO_DOWN_PROB > 0 )) && [[ "$base" == "${RH_URL%/}" ]] \
        && [[ "$ALLOW_SHARED_SURVIVOR_URL" != "1" ]]; then
        chaos_die "survivor URL for $uuid resolves to RH_URL; configure a direct node URL"
    fi
    readiness_code=$(curl "${curl_base_args[@]}" \
        --output "$RUN_DIR/readiness-preflight-${uuid}.json" \
        --write-out '%{http_code}' "${base%/}/readiness" 2>/dev/null || true)
    [[ "$readiness_code" == "200" ]] \
        || chaos_die "pre-flight readiness != 200 uuid=$uuid code=${readiness_code:-curl_failed}"
    wait_worker_convergence "$uuid" \
        || chaos_die "pre-flight workers did not converge uuid=$uuid"
    if [[ -n "${CHAOS_NODE_CHECK_CMD:-}" ]]; then
        host=$(host_for_uuid "$uuid")
        run_template node_check "$CHAOS_NODE_CHECK_CMD" "$uuid" "$host" "$base" \
            || chaos_die "node check command failed uuid=$uuid host=$host"
    fi
done
if [[ "$AUDIT_VERIFY" == "1" ]]; then
    if ! audit_preflight | jq -e \
        '(.preflight_ready // (.chain_intact == true)) == true
         and (.audit_lite_intact // true) != false' > /dev/null; then
        chaos_die "pre-flight audit evidence verification is not ready"
    fi
else
    json_event audit_verify \
        "skipped by CHAOS_AUDIT_VERIFY=0 for targeted run"
fi
json_event start "pre-flight passed uuids=${UUIDS[*]}"

if [[ "$PREFLIGHT_ONLY" == "1" ]]; then
    json_event finish "pre-flight only passed"
    trap - EXIT INT TERM
    cleanup
    echo "K7 pre-flight complete: PASS"
    echo "Evidence: $RUN_DIR"
    exit 0
fi

# The requested duration is the workload/fault window. Potentially expensive
# preflight checks (notably audit verification on a large retained evidence
# set) must not consume that budget before any writer or fault task starts.
WORKLOAD_START_EPOCH=$(date +%s)

for i in $(seq 1 "$WRITERS"); do
    writer_loop "$i" &
    BG_PIDS+=("$!")
done
for i in $(seq 1 "$READERS"); do
    reader_loop "$i" &
    BG_PIDS+=("$!")
done
pki_loop &
BG_PIDS+=("$!")
server_cert_loop &
BG_PIDS+=("$!")
mtls_loop &
BG_PIDS+=("$!")
dynamic_loop &
BG_PIDS+=("$!")
alert_loop &
BG_PIDS+=("$!")
sampler_loop &
BG_PIDS+=("$!")
fault_loop &
BG_PIDS+=("$!")
if [[ "$DISK_PRESSURE" == "1" ]]; then
    disk_pressure_loop &
    BG_PIDS+=("$!")
fi

while (( $(date +%s) - WORKLOAD_START_EPOCH < DURATION )); do
    sleep 15
done

json_event finish "duration elapsed"
trap - EXIT INT TERM
cleanup
trap - EXIT INT TERM

capture_remote_logs
sample_once final

# Final readback. The default samples 10,000 successful writes so finalisation
# stays bounded after a high-throughput 24h run. Set CHAOS_FINAL_VERIFY_LIMIT=0
# for an intentionally expensive full readback.
VERIFY_INPUT="$WRITTEN"
VERIFY_MODE=full
if (( FINAL_VERIFY_LIMIT > 0 )); then
    VERIFY_INPUT="$RUN_DIR/final-verify-sample.tsv"
    shuf -n "$FINAL_VERIFY_LIMIT" "$WRITTEN" > "$VERIFY_INPUT" 2>/dev/null || cp "$WRITTEN" "$VERIFY_INPUT"
    VERIFY_MODE=sample
fi

TOTAL_WRITTEN=$(wc -l < "$WRITTEN" | tr -d ' ')
VERIFY_COUNT=$(wc -l < "$VERIFY_INPUT" | tr -d ' ')
MISS=0
MISMATCH=0
while IFS=$'\t' read -r _ name hash _writer; do
    [[ -n "$name" ]] || continue
    val=$(api "/secrets/${name}?namespace=${NS}" 2>/dev/null | jq -r '.value // empty' || true)
    if [[ -z "$val" ]]; then
        MISS=$((MISS + 1))
        continue
    fi
    got_hash=$(printf '%s' "$val" | sha256sum | awk '{print $1}')
    [[ "$got_hash" == "$hash" ]] || MISMATCH=$((MISMATCH + 1))
done < "$VERIFY_INPUT"

FINAL_AUDIT="$RUN_DIR/final-audit.json"
FINAL_AUDIT_PREFLIGHT="$RUN_DIR/final-audit-preflight.json"
FINAL_HA="$RUN_DIR/final-cluster-ha.json"
FINAL_HEALTH="$RUN_DIR/final-cluster-health.json"
if [[ "$AUDIT_VERIFY" == "1" ]]; then
    # Close the workload's read-log tail before the authoritative final scan.
    # This remains a bounded incremental call under a fresh run-start anchor.
    audit_preflight > "$FINAL_AUDIT_PREFLIGHT" 2>&1 || true
    audit_verify > "$FINAL_AUDIT" 2>&1 || true
    AUDIT_VERIFY_MODE=full
else
    printf '%s\n' '{"skipped":true,"reason":"CHAOS_AUDIT_VERIFY=0"}' \
        > "$FINAL_AUDIT_PREFLIGHT"
    printf '%s\n' '{"skipped":true,"reason":"CHAOS_AUDIT_VERIFY=0"}' \
        > "$FINAL_AUDIT"
    AUDIT_VERIFY_MODE=skipped
fi
api "/cluster/ha" > "$FINAL_HA" 2>&1 || true
api "/cluster/health" > "$FINAL_HEALTH" 2>&1 || true

if [[ "$AUDIT_VERIFY" == "1" ]]; then
    CHAIN_OK=$(jq -r '.chain_intact // false' "$FINAL_AUDIT" 2>/dev/null || echo false)
    MTREE_OK=$(jq -r '(.audit_lite_intact // true) != false' "$FINAL_AUDIT" 2>/dev/null || echo false)
else
    CHAIN_OK=skipped
    MTREE_OK=skipped
fi
FINAL_DATABASE_HA_GREEN=$(jq -r '
    .components.database.state == "green"
    and .components.database_ha.state == "green"
' "$FINAL_HEALTH" 2>/dev/null || echo false)
FINAL_MEMBERS=$(cat "$FINAL_HA" | ha_node_count 2>/dev/null || echo 0)
FINAL_STEADY=false
if cat "$FINAL_HA" | ha_is_steady 3 >/dev/null 2>&1; then
    FINAL_STEADY=true
fi
FAILURE_COUNT=$(wc -l < "$FAILURES" | tr -d ' ')
CRITICAL_COUNT=$(jq -s '[.[] | select(.severity == "critical")] | length' "$FAILURES")
DISK_PRESSURE_COUNT=$(jq -s \
    '[.[] | select(.kind == "disk_pressure" and (.msg | startswith("complete ")))] | length' \
    "$EVENTS")

OUTCOME=PASS
if { [[ "$AUDIT_VERIFY" == "1" ]] \
      && [[ "$CHAIN_OK" != "true" || "$MTREE_OK" != "true" ]]; } \
    || [[ "$FINAL_DATABASE_HA_GREEN" != "true" ]] \
    || [[ "$FINAL_STEADY" != "true" ]] \
    || (( TOTAL_WRITTEN == 0 || VERIFY_COUNT == 0 || MISS > 0 || MISMATCH > 0 \
          || FINAL_MEMBERS < 3 || CRITICAL_COUNT > 0 )); then
    OUTCOME=FAIL
elif (( FAILURE_COUNT > 0 )); then
    OUTCOME=PASS_TRANSIENT_ERRORS
fi
if [[ "$OUTCOME" == "PASS_TRANSIENT_ERRORS" && "$FAIL_ON_TRANSIENTS" == "1" ]]; then
    OUTCOME=FAIL
fi

jq -n \
    --arg start "$START_TS" \
    --arg end "$(date -u +%FT%TZ)" \
    --arg profile "$PROFILE" \
    --arg run_id "$RUN_ID" \
    --arg namespace "$NS" \
    --arg outcome "$OUTCOME" \
    --arg verify_mode "$VERIFY_MODE" \
    --arg audit_verify_mode "$AUDIT_VERIFY_MODE" \
    --arg chain_ok "$CHAIN_OK" \
    --arg mtree_ok "$MTREE_OK" \
    --arg database_ha_green "$FINAL_DATABASE_HA_GREEN" \
    --arg final_steady "$FINAL_STEADY" \
    --argjson total_written "$TOTAL_WRITTEN" \
    --argjson verify_count "$VERIFY_COUNT" \
    --argjson miss "$MISS" \
    --argjson mismatch "$MISMATCH" \
    --argjson failures "$FAILURE_COUNT" \
    --argjson critical_failures "$CRITICAL_COUNT" \
    --argjson disk_pressure_cycles "$DISK_PRESSURE_COUNT" \
    --argjson final_members "$FINAL_MEMBERS" \
    '{
      start:$start, end:$end, profile:$profile, run_id:$run_id,
      namespace:$namespace,
      outcome:$outcome,
      written:$total_written, verified:$verify_count, verify_mode:$verify_mode,
      readback_miss:$miss, readback_mismatch:$mismatch,
      workload_failures:$failures, critical_failures:$critical_failures,
      disk_pressure_cycles:$disk_pressure_cycles,
      audit_verification:$audit_verify_mode,
      chain_intact:(if $audit_verify_mode=="full" then ($chain_ok=="true") else null end),
      audit_lite_merkle_intact:(if $audit_verify_mode=="full" then ($mtree_ok=="true") else null end),
      final_database_ha_green:($database_ha_green=="true"),
      final_members:$final_members,
      final_topology_steady:($final_steady=="true")
    }' > "$RUN_DIR/final-summary.json"

cat > "$RUN_DIR/report.md" <<EOF
# K7 Random HA Chaos Report

- Start: ${START_TS}
- End: $(date -u +%FT%TZ)
- Profile: ${PROFILE}
- Run ID: ${RUN_ID}
- Namespace: ${NS}
- Outcome: ${OUTCOME}
- Written secrets: ${TOTAL_WRITTEN}
- Final readback checked: ${VERIFY_COUNT} (${VERIFY_MODE})
- Miss: ${MISS}
- Mismatch: ${MISMATCH}
- Workload/probe failures: ${FAILURE_COUNT}
- Critical failures: ${CRITICAL_COUNT}
- Disk pressure cycles: ${DISK_PRESSURE_COUNT}
- Audit verification: ${AUDIT_VERIFY_MODE}
- Audit chain intact: ${CHAIN_OK}
- Audit-lite Merkle intact: ${MTREE_OK}
- Database HA green: ${FINAL_DATABASE_HA_GREEN}
- Final HA members: ${FINAL_MEMBERS}
- Final topology steady: ${FINAL_STEADY}

Evidence files:

- \`events.jsonl\`
- \`failures.jsonl\`
- \`written.tsv\`
- \`pki.tsv\`
- \`dynamic.tsv\`
- \`alert.tsv\`
- \`disk-pressure.tsv\`
- \`driver.log\`
- \`samples/\`
- \`logs/\`
- \`final-summary.json\`
EOF

chaos_log_result K7 "$START_TS" "$(date -u +%FT%TZ)" "$OUTCOME" \
    "profile=$PROFILE written=$TOTAL_WRITTEN verified=$VERIFY_COUNT verify_mode=$VERIFY_MODE miss=$MISS mismatch=$MISMATCH failures=$FAILURE_COUNT critical=$CRITICAL_COUNT disk_pressure=$DISK_PRESSURE_COUNT chain=$CHAIN_OK mtree=$MTREE_OK members=$FINAL_MEMBERS steady=$FINAL_STEADY"

echo "K7 complete: $OUTCOME"
echo "Evidence: $RUN_DIR"
[[ "$OUTCOME" != "FAIL" ]]
