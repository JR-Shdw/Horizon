# HA bench (quarantine + failover tuning)

Methodology for benchmarking HA failover and JOIN-at-scale. Runs are produced
by `tests/load_ha_quarantine.py` **in the separate `rhorizon_ha` repository**
(not in this repo - clone it alongside rhorizon to run a campaign), and
visualised with the Grafana dashboard
[`dashboards/ha-bench.json`](dashboards/ha-bench.json). The verdict feeds back
into the defaults in `api/app/config.py`.

## How it works

A campaign records a JSON timeline (`record`), then scores it per scenario
(`assess --scenario N --in <file>`). Each scenario has explicit pass criteria;
a run is green only if all four pass. Reference defaults under test:
`cluster_heartbeat_interval_secs=3`, `cluster_state_machine_interval_secs=2`,
`cluster_primary_lease_ttl_secs=20`, `cluster_join_quarantine_secs=60`,
`cluster_drain_deadline_secs=30`, `cluster_reaper_interval_secs=30`.

## Scenarios

| # | Scenario | Pass criteria |
|---|---|---|
| 1 | Cold JOIN at scale (5/10/20 nodes) | 100% of joiners reach `secondary`; p99 `join_to_secondary_secs` <= `cluster_join_quarantine_secs` + 2s; 0 false promotions (secondary then reaped/re-quarantined within 10s) |
| 2 | Primary kill -9 | a new primary lands within lease expiry + skew (`lease/3`) + jitter (`lease/6`) + one state-machine poll; 0 split-brain seconds (no two `primary` rows overlap) |
| 3 | Primary partition + heal | a different node becomes primary during the partition; the returning ex-primary self-demotes, never re-claims primary directly; 0 split-brain seconds |
| 4 | Rolling restart (5s spacing) | cluster never loses the primary longer than lease expiry + skew + jitter + one state-machine poll; all nodes converge to `primary`/`secondary` within `cluster_join_quarantine_secs` |

## Verdict

Once all four pass on a campaign, any default change to `api/app/config.py`
goes through a PR. The main tunable this bench settles is
`cluster_join_quarantine_secs` (JOIN-at-scale latency vs false-promotion
floor); the failover-speed knobs (`cluster_heartbeat_interval_secs`,
`cluster_state_machine_interval_secs`) are settled by scenarios 2-3.

See [HA-CLUSTER.md](HA-CLUSTER.md) for the state machine and options.
