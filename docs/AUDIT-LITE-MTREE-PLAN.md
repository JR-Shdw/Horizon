# Audit-lite Merkle checkpoint plan

> **STATUS: shipped.** This is the design record, not outstanding work.
> Implemented in `api/app/audit_mtree.py`, scheduled by
> `_audit_lite_checkpoint_loop` in `api/app/main.py`, verified through
> `GET /audit/verify` (`audit_lite_intact`,
> `audit_lite_uncheckpointed_rows`), and gated in CI by
> `tests/test_audit_mtree.py`. On by default:
> `audit_lite_checkpoint_enabled=true`, 60 s interval, 10 000 rows max per
> checkpoint. User-facing description in
> [concepts/audit.md](docs/concepts/audit.md).

Goal: make `vault_audit_lite` read events tamper-evident without changing the
`vault_audit_lite` table or serializing every read through the signed audit
chain.

## Constraints

- No database schema migration.
- No change to existing `vault_audit_lite` rows.
- No per-read signature or advisory lock.
- No new cryptographic dependency.
- Checkpoints are signed through the existing `vault_audit` chain as action
  `audit_lite_checkpoint`.

## Implementation Checklist

- [x] Add `api/app/audit_mtree.py` for canonical read-row hashing, Merkle roots,
  checkpoint creation, and checkpoint verification.
- [x] Add settings:
  - `audit_lite_checkpoint_enabled`
  - `audit_lite_checkpoint_interval_secs`
  - `audit_lite_checkpoint_max_rows`
- [x] Add a cluster-wide singleton background loop using advisory lock
  `rhorizon:cluster:audit_lite_checkpoint`.
- [x] Extend `/api/v1/vault/audit/verify` with:
  - `evidence_intact`
  - `audit_lite_intact`
  - `audit_lite_checkpoints`
  - `audit_lite_checkpointed_rows`
  - `audit_lite_uncheckpointed_rows`
  - checkpoint break metadata on failure
- [x] Update `rhorizon audit verify` so it fails if either the chained mutation
  audit or checkpointed read audit is broken.
- [x] Add focused host tests in `tests/test_audit_mtree.py`.
- [x] Add a focused mtree pytest command to `.woodpecker/validate.yml` before
  the full Python suite.
- [x] Run focused tests on the host.

## Verification Model

Each checkpoint detail stores a closed ordered window over `vault_audit_lite`:

```json
{
  "schema": "rhorizon.audit_lite_checkpoint.v1",
  "from_timestamp": "...",
  "from_id": "...",
  "to_timestamp": "...",
  "to_id": "...",
  "row_count": 123,
  "merkle_root": "sha256:...",
  "previous_checkpoint_id": "..."
}
```

`/audit/verify` verifies the signed `vault_audit` chain first. Only then does it
trust checkpoint details, recompute each read-log window, and compare root +
count. A final count of every read row at or before the last checkpoint high
water mark detects gaps and backdated inserts.

## Resume Notes

If interrupted, run:

```sh
git status --short
pytest tests/test_audit_mtree.py -v --tb=short --no-cov
```

The signed-commit protection files may already be uncommitted in this tree;
do not remove them while resuming this work.
