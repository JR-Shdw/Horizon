# Alerting rules and response actions

rhorizon exposes `/metrics` in Prometheus format. This page lists alerts whose
conditions map to a specific operator response. Each has its trigger on the
`prometheus.rules.yml` side; Grafana Alerting uses the same expressions.

The implicit criterion: **every alert must point to a concrete action**. If it
does not tell the operator what to do in the next 5 minutes, it is noise.

---

## Critical - page immediately

### `HoneytokenAccess`
A canary was read. Active intrusion or insider misuse. **Respond in minutes,
not hours.**

```yaml
- alert: HoneytokenAccess
  expr: increase(rhorizon_honey_access_total[5m]) > 0
  for: 0s   # zero tolerance - fire on first increment
  labels:
    severity: critical
    team: security
  annotations:
    summary: "Honeytoken {{ $labels.kind }} read on rhorizon"
    description: "Decoy secret accessed. Pull the audit log immediately for
                  actor + IP + timestamp. Rotate any creds the actor
                  could have read alongside the honey."
```

### `MasterPasswordRotated`
Every master-password rotation must have a ticket / a sec_ops incident report.
Without one: signal of compromise.

```yaml
- alert: MasterPasswordRotated
  expr: increase(rhorizon_master_password_rotated_total[15m]) > 0
  for: 0s
  labels:
    severity: critical
    team: security
  annotations:
    summary: "Master password rotated ({{ $labels.mode }} mode)"
    description: "Cross-check the audit chain entry, then validate
                  there is a corresponding ticket. mode=sec_ops means
                  someone declared a compromise - make sure ALL
                  agents have re-provisioned tokens."
```

### `ClusterFailoverFailed`
Master dead + Shamir reconstruction failed -> vault sealed. All /secrets/*
traffic returns 503. Hard down.

```yaml
- alert: ClusterFailoverFailed
  expr: increase(rhorizon_cluster_failover_total{result!="success"}[5m]) > 0
  for: 0s
  labels:
    severity: critical
    team: ops
  annotations:
    summary: "Cluster failover {{ $labels.result }}"
    description: "Master died and {{ $labels.result }} during
                  reconstruction. Vault is likely sealed. Manual
                  unseal required. Check vault_workers + Shamir
                  share availability."
```

---

## Serious - page within 30 min

### `AuditChainBroken`
Chain integrity lost. Something rewrote the DB outside the API (injection,
privileged attack, or bug).

```yaml
- alert: AuditChainBroken
  expr: rhorizon_audit_chain_breaks_total > 0
  for: 0s
  labels:
    severity: high
    team: security
```

### `AuthFailureSpike`
Brute-force or broken automation. Bursts > 50/min sustained = action.

```yaml
- alert: AuthFailureSpike
  expr: rate(rhorizon_auth_failures_total[5m]) > 1.0
  for: 10m
  labels:
    severity: high
  annotations:
    summary: "Auth failures > 60/min on rhorizon"
    description: "Reason breakdown: {{ $labels.reason }}. Check
                  fail2ban logs (authfail.py emits in fail2ban
                  format) and the rate-limit table."
```

### `VaultSealedUnexpected`
A node that should be serving is **sealed**. This is the expected fail-safe:
under overload/attack (brute-force, scan, congestion collapse) a node seals
rather than degrading open. The seal is safe behavior but still requires
investigation. This gauge is the external observer: it fires even if the node
crashes or is too busy to
self-notify (the in-app notification is best-effort on the node side and can
miss a seal under distress).

`for: 2m` avoids flapping on deliberate re-seal windows (oneshot, rotation,
reboot before operator unseal).

```yaml
- alert: VaultSealedUnexpected
  expr: rhorizon_vault_sealed == 1
  for: 2m
  labels:
    severity: high
    team: ops
  annotations:
    summary: "Node {{ $labels.instance }} is sealed"
    description: "A node that should be serving is sealed >2m. Expected
                  fail-safe under overload/attack; investigate the cause
                  (load knee? brute-force? crash?). Check the audit chain +
                  rhorizon_seal_events_total{trigger} + the node logs, then
                  re-unseal (restart first if /unseal deadlocks on the
                  master socket, see SEAL-DIAGNOSIS.md)."
```

### `VaultSealEventFired`
Fast complement to the gauge: a *non-operator* seal event just happened
(defensive/broadcast/failover, NOT a manual `/seal` nor a clean shutdown).
Page right away, this is the "something forced a seal" signal.

```yaml
- alert: VaultSealEventFired
  expr: increase(rhorizon_seal_events_total{trigger!~"manual|shutdown"}[5m]) > 0
  labels:
    severity: high
    team: ops
  annotations:
    summary: "Non-operator seal on {{ $labels.instance }} (trigger={{ $labels.trigger }})"
    description: "A defensive/broadcast/failover seal just fired. Correlate
                  with load (bench? attack?) and the audit chain."
```

### `SealedOpsSustained`
A service calls the API while the vault is sealed. Either broken automation
(not re-bootstrapped after rotation/reboot), or an attack scan.

```yaml
- alert: SealedOpsSustained
  expr: rate(rhorizon_sealed_op_attempts_total[10m]) > 0.1
  for: 10m
  labels:
    severity: medium
    team: ops
  annotations:
    summary: "Sustained calls to a sealed vault"
    description: "{{ $value }} req/s sustained over 10m. Either an
                  agent has stale config (find it via the audit
                  logs of attempted ops), or the vault wasn't
                  re-unsealed after an event."
```

---

## Capacity - page the next morning

### `DEKKeyStale`
The `dek_key` has not been rotated within the configured window. Hygiene, not
urgency. A missing or invalid rotation timestamp also sets this gauge to `1`;
the separate metadata alert below distinguishes that operational fault.

```yaml
- alert: DEKKeyStale
  expr: rhorizon_dek_key_stale == 1
  for: 24h
  labels:
    severity: low
    team: ops
```

### `DEKKeyMetadataInvalid`
The key age cannot be established. Check `vault_config`, clock synchronization,
and the last DEK rotation before clearing the alert. Rotation remains an
operator decision.

```yaml
- alert: DEKKeyMetadataInvalid
  expr: rhorizon_dek_key_stale == 1 and rhorizon_dek_key_age_seconds < 0
  for: 10m
  labels:
    severity: medium
    team: ops
```

### `ReaperFailure`
At least one cleanup cycle failed. Expired credentials and housekeeping remain
safe to retry, but persistent failures require checking the API warning and its
stack trace.

```yaml
- alert: ReaperFailure
  expr: increase(rhorizon_reaper_failures_total[15m]) > 0
  labels:
    severity: medium
    team: ops
```

### `AuditLiteCheckpointFailure`
The read-audit window could not be sealed into the signed chain. This includes
checkpoint writes and failures while acquiring the cluster-wide lock.

```yaml
- alert: AuditLiteCheckpointFailure
  expr: increase(rhorizon_audit_lite_checkpoints_total{result="failure"}[15m]) > 0
  labels:
    severity: medium
    team: ops
```

### `MasterRPCSaturating`
Master CPU or socket-queue bottleneck. Precursor to p99 on read_secret.

```yaml
- alert: MasterRPCSaturating
  expr: rhorizon_master_rpc_inflight > 50
  for: 5m
  labels:
    severity: medium
```

### `AuditVerifySlow`
The chain grows, /audit/verify slows down. Trigger to archive old entries
(still a future feature).

```yaml
- alert: AuditVerifySlow
  expr: histogram_quantile(0.95, rate(rhorizon_audit_verify_duration_seconds_bucket[1h])) > 5
  for: 1d
  labels:
    severity: low
```

---

## Grafana dashboards - overview

For a minimal "Vault Health" dashboard, 3 panels cover 90% of the diagnosis:

1. **read_secret latency**: `histogram_quantile(0.95,
   rate(rhorizon_secret_decrypt_duration_seconds_bucket[5m]))`
2. **Auth failure rate by reason**: `sum(rate(rhorizon_auth_failures_total[5m])) by (reason)`
3. **Audit events by category**: `sum(rate(rhorizon_audit_events_total[5m])) by (category)`

On the same page, add the counters:
- `rhorizon_honey_access_total` (should stay at 0)
- `rhorizon_sealed_op_attempts_total` (rate > 0 = signal)
- `rhorizon_active_tokens` (gauge - capacity planning)

---

## Routing matrix (ALERTS / SECURITY integration)

A common setup routes alerts to different channels by team. Example mapping:
- `grafana -> ALERTS`: everything ops (capacity, latency)
- security tooling `-> SECURITY`: intrusion (HoneytokenAccess, AuditChainBroken)
- `trivy -> CVE`: not concerned by these alerts
- monitoring `-> SYSTEMS`: SealedOpsSustained if you want to route it there

Suggested rhorizon-specific mapping:
- `HoneytokenAccess`, `MasterPasswordRotated`, `AuditChainBroken` -> SECURITY
- `ClusterFailoverFailed`, `MasterRPCSaturating`, `AuthFailureSpike`,
  `DEKKeyMetadataInvalid`, `ReaperFailure`, `AuditLiteCheckpointFailure`
  -> ALERTS
- `DEKKeyStale`, `AuditVerifySlow`, `SealedOpsSustained` -> SYSTEMS (normal ops)
