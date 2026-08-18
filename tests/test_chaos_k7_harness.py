"""Fast contract tests for the operator-driven K7 HA chaos harness."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
K7 = REPO / "tools" / "chaos" / "k7_random_ha_24h.sh"


def test_server_cert_check_can_use_ca_separate_from_tls_leaf_pins():
    source = K7.read_text()
    assert 'tls_ca_file="${RH_CA_FILE:-/etc/rhorizon/cluster-ca.pem}"' in source
    assert 'cluster_ca_file="${CHAOS_CLUSTER_CA_FILE:-$tls_ca_file}"' in source
    assert 'curl_base_args+=(--cacert "$tls_ca_file")' in source


COMMON = REPO / "tools" / "chaos" / "common.sh"


UUIDS = ["node-a", "node-b", "node-c"]


@pytest.fixture
def fake_curl(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "curl.log"
    fake = bindir / "curl"
    fake.write_text(
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys
import urllib.parse

args = sys.argv[1:]
url = next(
    (arg for arg in reversed(args) if arg.startswith(("http://", "https://"))),
    "",
)
path = urllib.parse.urlparse(url).path
with open(os.environ["FAKE_CURL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(path + "\\n")
if path == "/api/v1/vault/cluster/ha":
    node_b_state = (
        "primary"
        if os.environ.get("FAKE_DOUBLE_PRIMARY") == "1"
        else "secondary"
    )
    body = {
        "cluster_id": "fake-cluster",
        "primary_uuid": "node-a",
        "ha_loaded": True,
        "nodes": [
            {"node_uuid": "node-a", "ha_state": "primary"},
            {"node_uuid": "node-b", "ha_state": node_b_state},
            {"node_uuid": "node-c", "ha_state": "secondary"},
        ],
    }
elif path == "/api/v1/vault/audit/verify":
    body = {"chain_intact": True, "audit_lite_intact": True}
elif path == "/api/v1/vault/audit/verify/preflight":
    body = {
        "chain_intact": True,
        "audit_lite_intact": True,
        "evidence_intact": True,
        "preflight_ready": True,
        "verification_scope": "incremental",
    }
elif path == "/api/v1/vault/cluster/health":
    database_ha_state = os.environ.get("FAKE_DATABASE_HA_STATE", "green")
    body = {
        "overall": database_ha_state,
        "ready": database_ha_state == "green",
        "components": {
            "database": {"state": "green"},
            "node": {"state": "green"},
            "cluster": {"state": "green"},
            "database_ha": {
                "state": database_ha_state,
                "provider": "patroni",
                "members": 3,
                "lagging_members": [],
                "unknown_lag_members": [],
                "non_streaming_replicas": [],
                "timeline_mismatch_members": [],
            },
        },
    }
elif path == "/readiness":
    body = {"ready": True}
else:
    body = {"detail": "not found"}
payload = json.dumps(body)
if "--output" in args:
    target = pathlib.Path(args[args.index("--output") + 1])
    target.write_text(payload, encoding="utf-8")
    if "--write-out" in args:
        sys.stdout.write("200")
else:
    sys.stdout.write(payload)
"""
    )
    fake.chmod(0o755)
    return bindir, log


def test_common_prefers_canonical_rh_environment(tmp_path):
    env = {
        **os.environ,
        "CHAOS_RESULTS_DIR": str(tmp_path / "results"),
        "RH_URL": "https://canonical.invalid",
        "RHORIZON_URL": "https://legacy.invalid",
        "RH_TOKEN": "canonical-token",
        "RHORIZON_TOKEN": "legacy-token",
    }
    result = subprocess.run(
        [
            "bash",
            "-c",
            f'source "{COMMON}"; printf "%s\\n%s\\n" "$RHORIZON_URL" "$RHORIZON_TOKEN"',
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "https://canonical.invalid",
        "canonical-token",
    ]


def test_make_check_accepts_canonical_env(tmp_path):
    env_file = tmp_path / "k7.env"
    env_file.write_text(
        "\n".join(
            [
                "RH_URL=http://127.0.0.1:1",
                "RH_TOKEN=test-token",
                "CHAOS_INSECURE_TLS=1",
                'CHAOS_HOST_BY_UUID=\'{"node-a":"host-a"}\'',
                'CHAOS_URL_BY_UUID=\'{"node-a":"http://host-a"}\'',
            ]
        )
    )
    result = subprocess.run(
        ["make", "chaos-k7-check", f"CHAOS_K7_ENV={env_file}"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "check passed" in result.stdout


def test_preflight_only_never_injects_fault_or_workload(tmp_path, fake_curl):
    bindir, curl_log = fake_curl
    host_map = {uuid: f"host-{i}" for i, uuid in enumerate(UUIDS)}
    url_map = {uuid: f"https://{uuid}.invalid" for uuid in UUIDS}
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_CURL_LOG": str(curl_log),
        "RH_URL": "https://lb.invalid",
        "RH_TOKEN": "test-token",
        "CHAOS_RESULTS_DIR": str(tmp_path / "results"),
        "CHAOS_HOST_BY_UUID": json.dumps(host_map),
        "CHAOS_URL_BY_UUID": json.dumps(url_map),
        "CHAOS_PREFLIGHT_ONLY": "1",
        "CHAOS_DURATION_SECS": "1",
        "CHAOS_FAULT_MIN_INTERVAL_SECS": "1",
        "CHAOS_FAULT_MAX_INTERVAL_SECS": "1",
    }
    result = subprocess.run(
        [str(K7)],
        cwd=REPO,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pre-flight complete: PASS" in result.stdout
    requests = curl_log.read_text().splitlines()
    assert requests.count("/api/v1/vault/cluster/health") == 1
    assert requests.count("/readiness") == 3
    assert not any("/secrets" in path for path in requests)
    run_dirs = list((tmp_path / "results").glob("k7-*/events.jsonl"))
    assert len(run_dirs) == 1
    events = [json.loads(line) for line in run_dirs[0].read_text().splitlines()]
    assert not any(event["kind"] == "fault" for event in events)


def test_preflight_rejects_degraded_database_ha_tier(tmp_path, fake_curl):
    bindir, curl_log = fake_curl
    host_map = {uuid: f"host-{i}" for i, uuid in enumerate(UUIDS)}
    url_map = {uuid: f"https://{uuid}.invalid" for uuid in UUIDS}
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_CURL_LOG": str(curl_log),
        "FAKE_DATABASE_HA_STATE": "orange",
        "RH_URL": "https://lb.invalid",
        "RH_TOKEN": "test-token",
        "CHAOS_RESULTS_DIR": str(tmp_path / "results"),
        "CHAOS_HOST_BY_UUID": json.dumps(host_map),
        "CHAOS_URL_BY_UUID": json.dumps(url_map),
        "CHAOS_PREFLIGHT_ONLY": "1",
    }
    result = subprocess.run(
        [str(K7)],
        cwd=REPO,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert result.returncode != 0
    assert "database HA tier is not fully converged" in (result.stdout + result.stderr)
    requests = curl_log.read_text().splitlines()
    assert requests.count("/api/v1/vault/cluster/health") == 1
    assert "/readiness" not in requests


def test_preflight_rejects_double_primary_membership(tmp_path, fake_curl):
    bindir, curl_log = fake_curl
    host_map = {uuid: f"host-{i}" for i, uuid in enumerate(UUIDS)}
    url_map = {uuid: f"https://{uuid}.invalid" for uuid in UUIDS}
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_CURL_LOG": str(curl_log),
        "FAKE_DOUBLE_PRIMARY": "1",
        "RH_URL": "https://lb.invalid",
        "RH_TOKEN": "test-token",
        "CHAOS_RESULTS_DIR": str(tmp_path / "results"),
        "CHAOS_HOST_BY_UUID": json.dumps(host_map),
        "CHAOS_URL_BY_UUID": json.dumps(url_map),
        "CHAOS_PREFLIGHT_ONLY": "1",
    }
    result = subprocess.run(
        [str(K7)],
        cwd=REPO,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert result.returncode != 0
    assert "HA topology is not steady" in (result.stdout + result.stderr)


def test_full_audit_verify_is_outside_active_k7_functions():
    source = K7.read_text()
    survivor_body = source.split("single_survivor_probe() {", 1)[1].split(
        "\n}\n\nwriter_loop()", 1
    )[0]
    sampler_body = source.split("sample_once() {", 1)[1].split(
        "\n}\n\nsampler_loop()", 1
    )[0]
    assert '"/audit/verify"' not in survivor_body
    assert '"/audit/verify"' not in sampler_body
    assert '"/audit/lite?limit=1"' in survivor_body
    assert '"/audit/lite?limit=1"' in sampler_body


def test_full_audit_verify_uses_durable_job_with_legacy_fallback():
    source = K7.read_text()
    verify_body = source.split("audit_verify() {", 1)[1].split("\n}\n\n", 1)[0]
    assert 'audit_any_node "/audit/verify/jobs" -X POST' in verify_body
    assert 'api "/audit/verify/jobs/${job_id}"' in verify_body
    assert 'audit_any_node "/audit/verify"' in verify_body
    assert "AUDIT_JOB_TIMEOUT" in verify_body


def test_audit_preflight_uses_incremental_anchor_and_explicit_full_job():
    source = K7.read_text()
    body = source.split("audit_preflight() {", 1)[1].split("\n}\n\n", 1)[0]
    assert 'audit_any_node "/audit/verify/preflight" -X POST' in body
    assert ".full_verification_job.job_id" in body
    assert 'api "/audit/verify/jobs/${job_id}"' in body
    assert "preflight_ready == true" in body


def test_writer_reconciles_transaction_uncertainty_by_unique_name():
    source = K7.read_text()
    writer_body = source.split("writer_loop() {", 1)[1].split(
        "\n}\n\nreader_loop()", 1
    )[0]
    assert "committed before uncertain response" in writer_body
    assert "safely retried after absent readback" in writer_body
    assert writer_body.count('api "/secrets/${name}?namespace=${NS}"') == 2
    assert writer_body.count('api "/secrets/" -X POST') == 2


def test_signal_handler_cleans_up_and_exits():
    source = K7.read_text()
    abort_body = source.split("abort_run() {", 1)[1].split("\n}\n\nBG_PIDS=()", 1)[0]
    assert "cleanup" in abort_body
    assert "exit 130" in abort_body
    assert "trap cleanup EXIT" in source
    assert "trap abort_run INT TERM" in source


def test_disk_pressure_is_bounded_serialized_and_checks_worker_recovery():
    source = K7.read_text()
    pressure_body = source.split("disk_pressure_loop() {", 1)[1].split(
        "\n}\n\nfault_loop()", 1
    )[0]
    cleanup_body = source.split("cleanup() {", 1)[1].split("\n}\n\nabort_run()", 1)[0]

    assert 'require_uint CHAOS_DISK_PRESSURE_MIN_GIB "$PRESSURE_MIN_GIB" 1 2' in source
    assert (
        'require_uint CHAOS_DISK_PRESSURE_MAX_GIB "$PRESSURE_MAX_GIB" '
        '"$PRESSURE_MIN_GIB" 2'
    ) in source
    assert "flock -x 9" in pressure_body
    assert '9> "$FAULT_LOCK"' in pressure_body
    assert 'wait_worker_convergence "$uuid"' in pressure_body
    assert 'kill_one_follower "$uuid" "$host" "$url"' in pressure_body
    assert "worker_kill_done=1" in pressure_body
    assert "data_removed=true" in pressure_body
    assert "pressure_cleanup_all" in cleanup_body


def test_pressure_worker_fault_is_one_shot_and_selects_only_a_follower():
    source = K7.read_text()
    worker_fault_body = source.split("kill_one_follower() {", 1)[1].split(
        "\n}\n\npressure_cleanup_all()", 1
    )[0]

    assert (
        'WORKER_KILL_AFTER_PRESSURE="${CHAOS_WORKER_KILL_AFTER_PRESSURE:-0}"' in source
    )
    assert ".hosts[$host].followers[]?" in worker_fault_body
    assert 'select(.worker_state == "follower")' in worker_fault_body
    assert '"$CHAOS_WORKER_KILL_CMD"' in worker_fault_body
    assert 'wait_worker_convergence "$uuid"' in worker_fault_body
    assert "old_pid=$pid" in worker_fault_body


def test_disk_pressure_rejects_missing_remote_cleanup(tmp_path):
    env = {
        **os.environ,
        "RH_URL": "https://unused.invalid",
        "RH_TOKEN": "test-token",
        "CHAOS_RESULTS_DIR": str(tmp_path / "results"),
        "CHAOS_HOST_BY_UUID": json.dumps({"node-a": "host-a"}),
        "CHAOS_DISK_PRESSURE": "1",
        "CHAOS_DISK_PRESSURE_CMD": "true",
        "CHAOS_DISK_PRESSURE_CLEANUP_CMD": "",
    }
    result = subprocess.run(
        [str(K7)], capture_output=True, text=True, env=env, timeout=10
    )
    assert result.returncode != 0
    assert "CHAOS_DISK_PRESSURE_CLEANUP_CMD is required" in (
        result.stdout + result.stderr
    )


def test_targeted_run_can_skip_only_the_expensive_audit_gate():
    source = K7.read_text()
    assert 'AUDIT_VERIFY="${CHAOS_AUDIT_VERIFY:-1}"' in source
    assert "skipped by CHAOS_AUDIT_VERIFY=0 for targeted run" in source
    assert 'if [[ "$AUDIT_VERIFY" == "1" ]]; then' in source
    assert "audit_verification:$audit_verify_mode" in source


# ---------------------------------------------------------------------------
# PKI revoke: retry + status capture
#
# A revoke that fails leaves the certificate valid for its full ttl_days, so
# dropping one silently is a real leftover, not cosmetic. The 2026-08-08 run
# recorded two "revoke failed" entries with no HTTP status (the call discarded
# its response) and no retry, both within 10s of a deliberate two-node kill.
# These run the function for real against a stubbed api() rather than
# string-matching it, because the retry counter is the part that can be wrong.
# ---------------------------------------------------------------------------


def _revoke_harness(tmp_path, *, fail_times: int, in_fault_window: bool) -> str:
    """Run revoke_pki_serial with api() failing the first `fail_times` calls."""
    body = K7.read_text().split("revoke_pki_serial() {", 1)[1].split("\n}\n", 1)[0]
    script = tmp_path / "harness.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -uo pipefail\n"
        f'ATTEMPTS_FILE="{tmp_path}/attempts"\n'
        ': > "$ATTEMPTS_FILE"\n'
        "api() {\n"
        '  echo x >> "$ATTEMPTS_FILE"\n'
        f'  if [[ $(wc -l < "$ATTEMPTS_FILE") -le {fail_times} ]]; then\n'
        '    echo "curl returned error: 503"; return 1\n'
        "  fi\n"
        "  return 0\n"
        "}\n"
        'json_event() { echo "EVENT $*"; }\n'
        'json_failure() { echo "FAILURE $*"; }\n'
        'http_failure_summary() { echo "status=503"; }\n'
        f"expected_fault_window() {{ return {0 if in_fault_window else 1}; }}\n"
        "revoke_pki_serial() {" + body + "\n}\n"
        'revoke_pki_serial "SERIAL-1"\n'
        'echo "ATTEMPTS=$(wc -l < "$ATTEMPTS_FILE" | tr -d " ")"\n'
    )
    env = dict(os.environ, CHAOS_PKI_REVOKE_RETRY_DELAY_SECS="0")
    return subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, env=env, timeout=30
    ).stdout


def test_revoke_retries_and_succeeds_without_recording_a_failure(tmp_path):
    """Two transient 503s then success: the run must not carry a failure."""
    out = _revoke_harness(tmp_path, fail_times=2, in_fault_window=False)
    assert "ATTEMPTS=3" in out
    assert "FAILURE" not in out
    assert "EVENT pki revoke succeeded on attempt 3" in out


def test_revoke_gives_up_after_the_configured_attempts(tmp_path):
    out = _revoke_harness(tmp_path, fail_times=99, in_fault_window=False)
    assert "ATTEMPTS=3" in out, out
    assert "FAILURE pki revoke failed serial=SERIAL-1 attempts=3" in out


def test_exhausted_revoke_records_the_http_status(tmp_path):
    """The gap that made the original two failures undiagnosable."""
    out = _revoke_harness(tmp_path, fail_times=99, in_fault_window=False)
    assert "status=503" in out


def test_revoke_during_a_deliberate_outage_is_not_a_failure(tmp_path):
    """Same classification the reader/writer loops already used."""
    out = _revoke_harness(tmp_path, fail_times=99, in_fault_window=True)
    assert "FAILURE" not in out
    assert "EVENT expected_fault pki revoke unavailable" in out
    assert "status=503" in out


def test_pki_and_dynamic_failures_are_classified_like_reads():
    source = K7.read_text()
    pki_body = source.split("pki_loop() {", 1)[1].split("\n}\n", 1)[0]
    dynamic_body = source.split("dynamic_loop() {", 1)[1].split("\n}\n", 1)[0]
    # Every failure path in these loops must first ask whether a node was
    # deliberately down, exactly as reader_loop does.
    for body in (pki_body, dynamic_body):
        assert body.count("expected_fault_window") >= 1
    assert "http_failure_summary" in pki_body
