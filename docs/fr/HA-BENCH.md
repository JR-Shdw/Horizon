# Bench HA (quarantine + tuning failover)

Méthodologie pour benchmarker le failover HA et le JOIN à l'échelle. Les runs
sont produits par `tests/load_ha_quarantine.py` **dans le dépôt séparé
`rhorizon_ha`** (pas dans ce dépôt : le cloner à côté de rhorizon pour lancer
une campagne), et visualisés avec le dashboard Grafana
[`dashboards/ha-bench.json`](../dashboards/ha-bench.json). Le verdict alimente les
défauts dans `api/app/config.py`.

## Comment ça marche

Une campagne enregistre une timeline JSON (`record`), puis la score par
scénario (`assess --scenario N --in <fichier>`). Chaque scénario a des critères
de passage explicites ; un run est vert seulement si les quatre passent.
Défauts de référence sous test : `cluster_heartbeat_interval_secs=3`,
`cluster_state_machine_interval_secs=2`, `cluster_primary_lease_ttl_secs=20`,
`cluster_join_quarantine_secs=60`, `cluster_drain_deadline_secs=30`,
`cluster_reaper_interval_secs=30`.

## Scénarios

| # | Scénario | Critères de passage |
|---|---|---|
| 1 | Cold JOIN à l'échelle (5/10/20 nœuds) | 100% des joiners atteignent `secondary` ; p99 `join_to_secondary_secs` <= `cluster_join_quarantine_secs` + 2s ; 0 fausse promotion (secondary puis reapé/re-quarantine sous 10s) |
| 2 | Primary kill -9 | un nouveau primary arrive avant lease + skew (`lease/3`) + jitter (`lease/6`) + une boucle state-machine ; 0 seconde de split-brain (pas deux rows `primary` simultanées) |
| 3 | Partition primary + heal | un autre nœud devient primary pendant la partition ; l'ex-primary qui revient se rétrograde, ne reprend jamais primary directement ; 0 seconde de split-brain |
| 4 | Rolling restart (espacement 5s) | le cluster ne perd jamais le primary plus de lease + skew + jitter + une boucle state-machine ; tous les nœuds convergent vers `primary`/`secondary` sous `cluster_join_quarantine_secs` |

## Verdict

Une fois les quatre scénarios verts sur une campagne, tout changement de défaut
dans `api/app/config.py` passe par une PR. Le réglage principal que ce bench
tranche est `cluster_join_quarantine_secs` (latence du JOIN à l'échelle vs
plancher de fausses promotions) ; les knobs de vitesse de failover
(`cluster_heartbeat_interval_secs`, `cluster_state_machine_interval_secs`) sont
tranchés par les scénarios 2-3.

Voir [HA-CLUSTER.md](HA-CLUSTER.md) pour la machine à états et les options.
