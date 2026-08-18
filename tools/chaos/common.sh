# shellcheck shell=bash
# chaos battery -- shared helpers.
#
# Sourced by k1..k6 scripts. Provides:
#  - rhorizon_status / rhorizon_audit_verify : two read-only probes
#    against the cluster API. Need RH_URL + RH_TOKEN_FILE.
#  - chaos_assert_quorum : sanity check, dies if cluster is not 3-node
#    steady-state.
#  - chaos_log_result : append one CSV row to docs/HA-RUNBOOK.md
#    table is the human-readable log ; CSV under
#    tools/chaos/results/<scenario>-<ts>.csv is the machine-readable one.
#  - ssh_lab / docker_lab : wrappers that route via ssh root@<host>. Lab
#    hosts assumed reachable from the workstation that runs the chaos
#    driver. No bastion hop.

set -u
set -o pipefail

# RH_* is canonical. Keep the historical RHORIZON_* names as input aliases for
# existing operator env files, but always let RH_* win when both are present.
if [[ -n "${RH_URL:-}" ]]; then
    RHORIZON_URL="$RH_URL"
elif [[ -n "${RHORIZON_URL:-}" ]]; then
    RH_URL="$RHORIZON_URL"
fi
if [[ -n "${RH_TOKEN:-}" ]]; then
    RHORIZON_TOKEN="$RH_TOKEN"
elif [[ -n "${RHORIZON_TOKEN:-}" ]]; then
    RH_TOKEN="$RHORIZON_TOKEN"
fi
if [[ -n "${RH_TOKEN_FILE:-}" ]]; then
    RHORIZON_TOKEN_FILE="$RH_TOKEN_FILE"
elif [[ -n "${RHORIZON_TOKEN_FILE:-}" ]]; then
    RH_TOKEN_FILE="$RHORIZON_TOKEN_FILE"
fi
if [[ -n "${RH_CA_FILE:-}" ]]; then
    RHORIZON_CA_FILE="$RH_CA_FILE"
elif [[ -n "${RHORIZON_CA_FILE:-}" ]]; then
    RH_CA_FILE="$RHORIZON_CA_FILE"
fi
export RH_URL RH_TOKEN RH_TOKEN_FILE RH_CA_FILE
export RHORIZON_URL RHORIZON_TOKEN RHORIZON_TOKEN_FILE RHORIZON_CA_FILE

CHAOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_RESULTS_DIR="${CHAOS_RESULTS_DIR:-$CHAOS_DIR/results}"
mkdir -p "$CHAOS_RESULTS_DIR"

# --- required env vars -----------------------------------------------------
chaos_require_env() {
    local var
    for var in "$@"; do
        if [[ -z "${!var:-}" ]]; then
            echo "chaos: missing env var $var" >&2
            return 1
        fi
    done
}

# --- API probes ------------------------------------------------------------
rhorizon_curl() {
    chaos_require_env RHORIZON_URL || return 1
    local token ca_file
    local -a tls_args=()
    if [[ -n "${RHORIZON_TOKEN_FILE:-}" ]]; then
        token="$(< "$RHORIZON_TOKEN_FILE")"
    elif [[ -n "${RHORIZON_TOKEN:-}" ]]; then
        token="$RHORIZON_TOKEN"
    else
        echo "chaos: need RHORIZON_TOKEN_FILE or RHORIZON_TOKEN" >&2
        return 1
    fi
    ca_file="${RHORIZON_CA_FILE:-/etc/rhorizon/cluster-ca.pem}"
    if [[ "${CHAOS_INSECURE_TLS:-0}" == "1" ]]; then
        tls_args+=(--insecure)
    elif [[ -n "${RHORIZON_CA_FILE:-}" ]]; then
        [[ -r "$ca_file" ]] || {
            echo "chaos: CA file is not readable: $ca_file" >&2
            return 1
        }
        tls_args+=(--cacert "$ca_file")
    elif [[ -r "$ca_file" ]]; then
        tls_args+=(--cacert "$ca_file")
    fi
    curl --silent --show-error --fail-with-body \
        --connect-timeout 5 --max-time 15 \
        "${tls_args[@]}" \
        -H "Authorization: Bearer ${token}" \
        "$@"
}

rhorizon_status() {
    rhorizon_curl "${RHORIZON_URL}/api/v1/vault/status"
}

rhorizon_cluster_ha() {
    rhorizon_curl "${RHORIZON_URL}/api/v1/vault/cluster/ha"
}

rhorizon_audit_verify() {
    rhorizon_curl "${RHORIZON_URL}/api/v1/vault/audit/verify"
}

# --- pre-flight ------------------------------------------------------------
chaos_assert_quorum() {
    local n
    if ! n=$(rhorizon_cluster_ha | jq '(.members // .nodes // []) | length'); then
        echo "chaos: cluster/ha probe failed" >&2
        return 1
    fi
    if (( n < 3 )); then
        echo "chaos: need 3-node steady-state, got $n members" >&2
        return 1
    fi
    if ! rhorizon_audit_verify | jq -e '.chain_intact == true' > /dev/null; then
        echo "chaos: audit chain not intact at pre-flight, aborting" >&2
        return 1
    fi
}

# --- ssh / docker helpers --------------------------------------------------
# CHAOS_SSH_USER default root. CHAOS_HOSTS lab hosts space-separated.
chaos_ssh_user() { echo "${CHAOS_SSH_USER:-root}"; }

ssh_lab() {
    local host="$1"; shift
    local -a identity=()
    [[ -z "${CHAOS_SSH_IDENTITY_FILE:-}" ]] \
        || identity=(-i "$CHAOS_SSH_IDENTITY_FILE")
    ssh "${identity[@]}" -o ConnectTimeout=5 \
        -o BatchMode=yes \
        -o StrictHostKeyChecking="${CHAOS_SSH_STRICT:-accept-new}" \
        "$(chaos_ssh_user)@${host}" "$@"
}

docker_lab() {
    local host="$1"; shift
    docker -H "ssh://$(chaos_ssh_user)@${host}" "$@"
}

# --- result logging --------------------------------------------------------
# Args: scenario_id start_ts end_ts outcome notes
chaos_log_result() {
    local scenario="$1" start="$2" end="$3" outcome="$4" notes="$5"
    local csv="$CHAOS_RESULTS_DIR/$scenario.csv"
    if [[ ! -s "$csv" ]]; then
        echo "scenario,start_ts,end_ts,outcome,notes" > "$csv"
    fi
    printf '%s,%s,%s,%s,%q\n' "$scenario" "$start" "$end" "$outcome" "$notes" >> "$csv"
    echo "chaos: $scenario $outcome (logged to $csv)"
}

# --- pretty die ------------------------------------------------------------
chaos_die() {
    echo "chaos: $*" >&2
    exit 1
}
