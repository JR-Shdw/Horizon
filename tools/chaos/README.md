# Chaos battery, HA cluster

Operator-driven scripts that exercise the failure-injection scenarios
defined in `docs/HA-RUNBOOK.md` section 4. Each script reads
the cluster state, applies the fault, samples the API + audit chain
while the fault is active, and appends a one-row result to
`tools/chaos/results/<scenario>.csv`.

## Prerequisites

- 3-node cluster in steady state (`rhorizon cluster status` shows
  `cluster_id`, `primary`, 3 members all `SECONDARY`/`PRIMARY`).
- Workstation has SSH key auth to the lab managers. Per project rule
  (no bastion hop), the workstation must reach the managers directly.
- `jq` and `curl` in the PATH on the workstation.
- A token with the right scopes: `admin:r` for K2/K3, `admin:w` for K4/K6,
  and for K7 `admin:w`, `secrets:rw`, and audit read access. Add any extra
  scopes your notification or dynamic-secret backend policy requires.

## Common env vars

| Var | Purpose | Default |
|---|---|---|
| `RH_URL` | API endpoint to probe (must stay reachable across faults) | required |
| `RH_TOKEN_FILE` | path to bearer token, mode 0400 | required (or `RH_TOKEN`) |
| `RH_CA_FILE` | cluster CA bundle pinned for TLS verify | `/etc/rhorizon/cluster-ca.pem` |
| `CHAOS_CLUSTER_CA_FILE` | issuing cluster CA for server-certificate chain checks; set separately when `RH_CA_FILE` contains pinned leaves | `RH_CA_FILE` |
| `CHAOS_SSH_USER` | SSH user on the lab managers | `root` |
| `CHAOS_NOTES` | free-text appended to the result row | empty |

`/cluster/ha` currently returns `nodes`; older lab exports that still return
`members` are accepted by the shared quorum check and the K7 driver.

## Per-scenario invocation

### K2, network partition

```
RH_URL=https://mgr-1.lab:443 \
RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token \
CHAOS_TARGET_HOST=mgr-2.lab \
CHAOS_PEER_HOSTS="192.168.10.1 192.168.10.1" \
CHAOS_DURATION_SECS=90 \
bash tools/chaos/k2_partition.sh
```

### K3, slow follower

```
RH_URL=https://mgr-1.lab:443 \
RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token \
CHAOS_TARGET_HOST=mgr-2.lab \
CHAOS_TARGET_IFACE=eth0 \
CHAOS_DELAY_MS=500 \
CHAOS_DURATION_SECS=300 \
bash tools/chaos/k3_slow_follower.sh
```

### K4, rolling restart

```
cat > /tmp/hosts.json <<EOF
{
  "0f5c...": "mgr-1.lab",
  "1c8a...": "mgr-2.lab",
  "2b9b...": "mgr-3.lab"
}
EOF

RH_URL=https://mgr-1.lab:443 \
RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token-admin-w \
CHAOS_HOST_BY_UUID=/tmp/hosts.json \
bash tools/chaos/k4_rolling_restart.sh
```

### K6, ha_password rotation under failure

Same `CHAOS_HOST_BY_UUID` as K4. Default settings kill the master
5s after `stage` and wait up to 30s for the election.

```
RH_URL=https://mgr-1.lab:443 \
RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token-admin-w \
CHAOS_HOST_BY_UUID=/tmp/hosts.json \
bash tools/chaos/k6_ha_password_rotation_under_failure.sh
```

## Result log

Each scenario appends to `tools/chaos/results/<scenario>.csv` with
columns `scenario,start_ts,end_ts,outcome,notes`. Outcomes:

- `PASS`, expectations met,
- `PASS_PRIMARY_FLIPPED`, K2/K6 only, election fired during the
  scenario but the cluster recovered cleanly,
- `PASS_SLOW`, K1 only, election > 10s but completed within
  `CHAOS_ELECTION_WAIT_SECS`,
- `PASS_WARN_GRACE`, K5 only, soak passed but
  `cluster_ca_grace_drops_total{reason=grace_expired}` is non-zero
  (operator should investigate the grace expiry root cause),
- `PASS_TRANSIENT_ERRORS`, K7 only, no data loss and final chain/topology are
  intact, but some workload probe failed during a fault window,
- `FAIL`, a pre/post probe diverged from the expected steady state.

The human-readable summary table lives in
`docs/HA-RUNBOOK.md` section 5. Copy the CSV row + a
one-sentence finding into that table after each run.

## Cleanup safety

Every script installs a `trap` that undoes its fault (iptables flush,
`tc qdisc del`) on EXIT/INT/TERM, even when an assertion fires
mid-run. K4 and K6 cannot be auto-reverted (restarts are observable);
re-run from a known-good state if they break.

### K1, kill master

`RH_URL` MUST be the cluster VIP / LB (not a per-node URL) so
the probe survives the killed master. Same `CHAOS_HOST_BY_UUID` map
as K4.

```
RH_URL=https://rhorizon.lab:443 \
RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token \
CHAOS_HOST_BY_UUID=/tmp/hosts.json \
bash tools/chaos/k1_kill_master.sh
```

Outcomes : `PASS` (outage <= 10s) / `PASS_SLOW` (outage > 10s,
recovered) / `FAIL` (no election or no REJOIN).
`CHAOS_FORCE_REJOIN=1` opts in to calling /cluster/unrevoke after a
confirmed evict, only useful when the lab does not auto-restart
the container (raw docker without Swarm restart policy).

### K5, 24h soak

Multi-day driver. Background loops write a fresh secret every second,
read 3 random secrets every minute, and snapshot the audit chain +
cluster topology every 5min. Triggers `/cluster/rotate-ca` at H+12h
and runs K4 rolling restart inline at H+18h.

Run detached :

```
nohup env \
  RH_URL=https://rhorizon.lab:443 \
  RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token-admin-w \
  CHAOS_HOST_BY_UUID=/tmp/hosts.json \
  bash tools/chaos/k5_soak_24h.sh > k5.log 2>&1 &
disown
```

PID file `tools/chaos/results/k5.pid` refuses a second concurrent
run. Outputs land under `tools/chaos/results/k5-<start_ts>/` :

- `written.tsv`, every successful write (`epoch_ns<TAB>name<TAB>sha256`),
- `samples.jsonl`, 5-min `/audit/verify` + `/cluster/ha` snapshots,
- `events.log`, timeline (start, rotations, errors),
- `rotate-ca.json`, `k4.log`, event-specific outputs.

The final CSV row carries `written / miss / mismatch / chain_intact /
cluster_ca_grace_drops_total{reason=grace_expired}` ; transcribe the
finding into runbook s5.

### K7, 24h random HA chaos/load

K7 is the release-evidence HA battery. It runs continuous secret writes and
reads through the VIP/LB, optional PKI issue/revoke, optional dynamic credential
mint/renew/revoke, optional notification test sends, random one-node outages,
and random two-node outages. During a two-node outage it can promote the single
survivor, prove `/readiness`, secret write/read, audit-chain + audit-lite Merkle
verification, and worker coverage on that survivor, then it starts the stopped
nodes again and waits for convergence before the next fault.

Create the node map from the UUIDs in `rhorizon cluster status --json`:

```
cat > /tmp/rhorizon-ha-hosts.json <<EOF
{
  "0f5c...": "mgr-1.lab",
  "1c8a...": "mgr-2.lab",
  "2b9b...": "mgr-3.lab"
}
EOF
```

For the single-survivor proof, provide direct node URLs. The VIP/LB stays as
`RH_URL`, but K7 needs a way to hit the only live node when two nodes are
down. K7 refuses a two-node fault preflight without these URLs (or
`CHAOS_NODE_URL_TEMPLATE`):

```
cat > /tmp/rhorizon-ha-urls.json <<EOF
{
  "0f5c...": "https://mgr-1.lab:443",
  "1c8a...": "https://mgr-2.lab:443",
  "2b9b...": "https://mgr-3.lab:443"
}
EOF
```

Run the full 24h medium profile:

```
nohup env \
  RH_URL=https://rhorizon.lab:443 \
  RH_TOKEN_FILE=$HOME/.rhorizon/chaos-token-admin-w \
  RH_CA_FILE=$HOME/.rhorizon/cluster-ca.pem \
  CHAOS_HOST_BY_UUID=/tmp/rhorizon-ha-hosts.json \
  CHAOS_URL_BY_UUID=/tmp/rhorizon-ha-urls.json \
  CHAOS_LOAD_PROFILE=medium \
  CHAOS_EXPECTED_WORKERS_PER_NODE=5 \
  bash tools/chaos/k7_random_ha_24h.sh > k7.nohup.log 2>&1 &
disown
```

The Makefile wrapper is the preferred operator entry point:

```
make chaos-k7-init
$EDITOR tools/chaos/k7.env
make chaos-k7-check
make chaos-k7-preflight
make chaos-k7-24h-detached
make chaos-k7-status
```

Use `make chaos-k7-24h` when you want the run in the foreground. Use
`make chaos-k7-24h-high-detached` for the high-load profile.

Use `CHAOS_LOAD_PROFILE=high` for the higher default concurrency. K7 defaults
to Docker-over-SSH stop/start using the `rhorizon-api` label. For VM or PVE
power tests, override the control hooks; templates receive `{uuid}`, `{host}`,
and `{url}`:

```
CHAOS_DOWN_CMD='ssh pve1 qm stop {host}' \
CHAOS_UP_CMD='ssh pve1 qm start {host}' \
CHAOS_NODE_RECOVER_CMD='make unseal RH={host}' \
bash tools/chaos/k7_random_ha_24h.sh
```

Dynamic secrets and alerting are opt-in because they can touch real external
systems:

```
CHAOS_DYNAMIC_ENGINE_ID=<engine-uuid> \
CHAOS_DYNAMIC_ROLE_NAME=<role> \
CHAOS_ALERT_CHANNEL_ID=<channel-uuid> \
bash tools/chaos/k7_random_ha_24h.sh
```

Merkle tamper/recovery is not driven directly by K7 because it requires a
deliberate DB mutation. K7 periodically verifies `audit_lite_intact` through
`/audit/verify`; run the lab tamper/recovery probe alongside the K7 evidence if
you want that destructive proof in the same sign-off bundle.

PID file `tools/chaos/results/k7.pid` refuses a second concurrent run. Each run
uses a unique secret-name prefix, so rerunning in the same namespace does not
overwrite an earlier run's readback oracle. Evidence
lands under `tools/chaos/results/k7-<start_ts>-<run_id>/`:

- `driver.log`, stdout/stderr from the chaos driver,
- `events.jsonl`, selected faults, promotions, convergence elapsed time, and
  cleanup,
- `failures.jsonl`, workload/probe failures with timestamps,
- `written.tsv`, every successful write with a SHA-256 readback oracle,
- `pki.tsv`, `dynamic.tsv`, `alert.tsv`, integration loop evidence,
- `samples/`, raw LB `/metrics`, per-node `/metrics` when direct URLs are
  configured, `/observability`, `/cluster/ha`, `/cluster`, `/audit/verify`,
  `/notifications/`, and per-node `/readiness`,
- `logs/`, Docker logs/inspect and host snapshots from every node,
- `final-summary.json` and `report.md`.

Final `PASS` means final audit chain and audit-lite Merkle verification are
intact, all selected write/read evidence matches, no critical survivor or
recovery assertion failed, and the cluster converged back to a steady three-node
topology. The default final readback is a 10,000-write sample; set
`CHAOS_FINAL_VERIFY_LIMIT=0` for every write. `PASS_TRANSIENT_ERRORS` means the
final integrity checks passed but at least one non-critical live probe failed
during a fault window; inspect `failures.jsonl` before accepting the run. Set
`CHAOS_FAIL_ON_WORKLOAD_ERRORS=1` to make that outcome a hard failure.
