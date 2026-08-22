# Runbook opérations cluster HA

Procédures opérationnelles pour un déploiement HA : la couche Database HA
neutre vis-à-vis du fournisseur, le bootstrap, le rolling restart et le
recovery. Pour l'architecture et les options voir
[HA-CLUSTER.md](HA-CLUSTER.md).
La topologie normative, les gates de production et le chemin complet de
maintenance/upgrade sont consolidés dans la
[Référence HA de production](HA-PRODUCTION-REFERENCE.md).

## 0. Couche Database HA (prérequis)

La coordination cross-conteneur suppose un PostgreSQL hautement disponible en
dessous. À déployer une fois avant tout JOIN de nœud HA. (Hôte unique, pas de PG
HA ? Sautez cette section, voir [DEPLOYMENT.md](DEPLOYMENT.md).)

Patroni est le fournisseur de référence sous Linux et dans les opérateurs
Kubernetes.
[`rhorizon-pgha`](PGHA.md)
(`pgha`) est le fournisseur natif sous FreeBSD, OpenBSD et NetBSD. Les deux
doivent présenter un endpoint PostgreSQL d'écriture stable et un statut
normalisable dans le composant `database_ha` de `/cluster/health`.

### 0.1 Topologie

```mermaid
flowchart TB
    provider["Fournisseur Database HA<br/>Patroni+DCS ou agents pgha en quorum"]
    subgraph PGL["PostgreSQL (PG 18)"]
        pg["leader de base + replicas"]
    end
    lbpg["endpoint / VIP d'écriture stable<br/>route seulement vers le leader de base"]
    subgraph APP["API rhorizon (scoped par hostname, 5 workers chacun)"]
        rh["hôte A / B / C"]
    end
    lbapi["HAProxy + VIP keepalived<br/>probe /readiness"]
    provider --> pg
    pg --> lbpg
    lbpg --> rh
    rh --> lbapi
    lbapi --> clients["clients"]
```

Trois formes :
- **Multi-VM Linux** (référence) : 3 VMs API, 3 VMs PG+Patroni+etcd, 2 VMs
  HAProxy+keepalived. Le plus simple à debugger.
- **Multi-hôte BSD** : 3 hôtes PG+agents `pgha`, le fournisseur supervisant
  quorum, promotion, réplication et propriété du VIP d'écriture.
- **Docker Swarm** : API en `replicas=3` ; PG+Patroni sur des VMs dédiées **hors**
  Swarm (son rescheduling entre en conflit avec l'identité PG).
- **Kubernetes** : API `Deployment replicas=3` ; PG via un opérateur PG
  StatefulSet (Zalando / CrunchyData / CloudNativePG) - ne jamais bricoler Patroni.

Les trois rôles de leadership sont distincts : le **primary applicatif**
possède les tâches singleton rhorizon, chaque conteneur applicatif a un
**master crypto local**, et le **leader de base de données** possède les
écritures PostgreSQL. Changer un rôle ne change jamais automatiquement les
deux autres.

### 0.2 Fournisseur Patroni de référence

Par nœud : PG 18 + Patroni 4.x, etcd joignable, NTP, ports ouverts (5432 PG,
8008 Patroni REST, 2379 etcd). `/etc/patroni/patroni.yml` minimal :

```yaml
scope: rhorizon-pg
name: pg-1                     # unique par nœud
restapi: { listen: 0.0.0.0:8008, connect_address: 10.0.0.11:8008 }
etcd3:
  hosts: 10.0.0.21:2379,10.0.0.22:2379,10.0.0.23:2379
bootstrap:
  dcs:
    ttl: 30
    loop_wait: 10
    synchronous_mode: true              # les écritures de secrets ont besoin de durabilité
    synchronous_mode_strict: false      # repli en async si pas de replica
    member_slots_ttl: 10min             # libère les slots des membres réellement absents
    postgresql:
      use_pg_rewind: true
      use_slots: true
      parameters:
        wal_level: replica
        wal_keep_size: 1GB
        max_slot_wal_keep_size: 4GB     # borne le risque disque d'un slot périmé
        archive_mode: 'on'
        archive_command: 'pgbackrest --stanza=rhorizon archive-push %p'
  initdb: [ {encoding: UTF8}, data-checksums ]
postgresql:
  listen: 0.0.0.0:5432
  connect_address: 10.0.0.11:5432
  authentication:
    superuser: {username: postgres, password: '{{ PG_SUPERUSER_PASSWORD }}'}
    replication: {username: replicator, password: '{{ PG_REPLICATION_PASSWORD }}'}
  parameters: { ssl: 'on', ssl_cert_file: /etc/patroni/server.crt, ssl_key_file: /etc/patroni/server.key }
```

Répéter pour pg-2/pg-3 (changer `name`, adresses). `synchronous_mode: true`
garde chaque écriture commitée sur >=2 nœuds. Bootstrap : `systemctl enable
--now patroni` sur pg-1 (devient Leader), puis pg-2/pg-3 bootstrappent depuis
lui. Le schéma rhorizon s'applique au démarrage de l'API (idempotent).

Chaque hôte rhorizon pointe `RH_DATABASE_URL` vers l'**URL du LB**, jamais
un nœud PG directement :

```ini
RH_DATABASE_URL=postgresql+asyncpg://rhorizon:${POSTGRES_PASSWORD}@haproxy.local:5432/rhorizon
```

Au failover de base, HAProxy re-pointe vers le nouveau leader de base via
`/master` ; asyncpg se reconnecte avec une erreur retriable.

#### Fournisseur pgha natif BSD

Sous FreeBSD, OpenBSD et NetBSD, configurer
`RH_DATABASE_HA_PROVIDER=pgha` et lister tous les endpoints de statut des
agents dans `RH_DATABASE_HA_STATUS_URLS`. Les agents, et non l'élection
applicative rhorizon, possèdent le quorum de base, la promotion, la supervision
de réplication et le VIP d'écriture. Tous leurs rapports doivent être frais et
s'accorder sur un leader de base unique ; ce leader seul doit posséder le VIP.
Les commandes d'installation et de supervision se trouvent dans
[le design `pgha`](PGHA.md)
et
[le guide de déploiement BSD](PGHA.md)
du dépôt d'infrastructure HA rhorizon.

Ne pas appliquer `patronictl`, Patroni REST ou les procédures DCS à un
déploiement `pgha`. Réciproquement, ne pas utiliser `cluster promote` côté
application pour réparer l'un ou l'autre fournisseur Database HA.

### 0.3 Endpoint d'écriture stable et load balancer API

La configuration de référence suivante utilise deux listeners HAProxy :
PostgreSQL (leader Patroni via `/master`) et API (hôtes ready via
`/readiness`). Avec `pgha`, ses agents possèdent le VIP d'écriture ; conserver
l'invariant que `RH_DATABASE_URL` ne cible jamais un membre directement.

```
# /etc/haproxy/haproxy.cfg
listen rhorizon-pg
    bind *:5432
    mode tcp
    option httpchk OPTIONS /master
    http-check expect status 200
    default-server inter 3s fall 3 rise 2 on-marked-down shutdown-sessions
    server pg-1 10.0.0.11:5432 check port 8008
    server pg-2 10.0.0.12:5432 check port 8008
    server pg-3 10.0.0.13:5432 check port 8008

listen rhorizon-api
    bind *:8200
    mode http
    option httpchk GET /readiness
    http-check expect status 200
    default-server inter 2s fall 2 rise 2 observe layer7 error-limit 10 on-error mark-down
    server rh-a 10.0.1.11:8200 check
    server rh-b 10.0.1.12:8200 check
    server rh-c 10.0.1.13:8200 check
```

Lancer deux instances HAProxy derrière un VIP keepalived. Le contrat
`/readiness` pilote le LB :

| Signal | Code | Sens | Action LB |
|---|---|---|---|
| process vivant | `200` sur `/health` | up (même sealed) | liveness seulement |
| sealed / quarantine | `503` sur `/readiness` | pas de clés / fenced | **éjecter** |
| load-shed / recovering | `429` + Retry-After | transitoire | **back off**, NE PAS éjecter |

k8s : `livenessProbe` sur `/health`, `readinessProbe` sur `/readiness`. Pour
éviter l'angle mort par-worker, un worker par pod (`RH_WORKERS=1`, scale
via `replicas`) ou Envoy/Istio `outlierDetection`.

### 0.4 Backup (pgBackRest)

Repo sur stockage séparé, chiffré au repos, expédié offsite pour le DR :

```ini
# /etc/pgbackrest/pgbackrest.conf
[global]
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=${PGBACKREST_CIPHER_PASS}
[rhorizon]
pg1-path=/var/lib/postgresql/18/main
```

```bash
sudo -u postgres pgbackrest --stanza=rhorizon stanza-create
sudo -u postgres pgbackrest --stanza=rhorizon --type=full backup   # timers : full quotidien, diff horaire
```

### 0.5 Opérations Database HA

| Opération | Patroni | pgha |
|---|---|---|
| Switchover planifié | `patronictl -c /etc/patroni/patroni.yml switchover` ; HAProxy suit `/master` | utiliser la procédure du superviseur BSD ; vérifier consensus des agents et propriété du VIP |
| Failover non planifié | promotion automatique ; vérifier `patronictl list` | promotion automatique seulement avec quorum des agents ; vérifier que tous les rapports frais nomment le même leader |
| Ajouter un replica | provisionner PG 18 + Patroni, puis `systemctl enable --now patroni` ; bootstrap via `pg_basebackup` | provisionner PG 18 + `pgha`, l'inscrire au quorum et attendre `streaming` avant de le rendre éligible |
| Surveiller | lag, timeline, quorum DCS, état de l'archive | lag, timeline, fraîcheur des agents, quorum, propriétaire VIP, état de l'archive |

#### Statut Database HA neutre vis-à-vis du fournisseur

L'onglet HA, `rhorizon cluster health` et `/cluster/health` exposent le
composant `database_ha`, pas un orchestrateur particulier. Configurer
`RH_DATABASE_HA_PROVIDER=patroni` avec les trois URLs REST Patroni, ou
`RH_DATABASE_HA_PROVIDER=pgha` avec les trois URLs de statut des agents
`rhorizon-pgha`.

Le contrat normalisé est volontairement strict :

| État | Sens opérateur |
|---|---|
| vert `●` | un leader de base ; tous les membres rapportés joignables et chaque replica en streaming avec lag connu dans le budget ; pour `pgha`, chaque agent attendu fournit une preuve de quorum fraîche et un seul propriétaire du VIP |
| orange `●` | formation, recovery, supervision périmée, lag inconnu/excessif, replica non streaming ou timeline différente |
| rouge `●` | aucun leader unique, quorum perdu, identité contradictoire, mauvais/multiples propriétaires VIP, ou tous les endpoints fournisseur injoignables |
| noir/gris `○` | fournisseur désactivé, inconnu ou non configuré ; jamais suffisant pour un drill de failover ou le preflight chaos |

Les preuves propres au fournisseur restent étiquetées sous `provider`. Patroni
ne rapporte pas la propriété du VIP dans la sonde normalisée : son vert prouve
un leader unique et une réplication convergée, mais le LB/VIP externe doit être
surveillé séparément. `pgha` rapporte directement la propriété du VIP.

Les anciens déploiements `RH_PATRONI_REST_URLS` restent supportés en mode
`auto`, mais les nouveaux doivent utiliser `RH_DATABASE_HA_*`.

### 0.6 Risque : un slot de réplication périmé remplit `pg_wal`

**Sévérité : risque critique de disponibilité.** Les déploiements Database HA
maintiennent couramment un slot physique par membre. Un replica peut rester
enregistré et annoncer PostgreSQL `running` alors que son WAL receiver est
bloqué sur un segment déjà supprimé. Son slot cesse alors d'avancer. Patroni
ne l'expire pas via `member_slots_ttl` tant que le membre garde un heartbeat
DCS ; un membre `pgha` vivant mais périmé doit également être fenced par sa
supervision. Avec la valeur PostgreSQL par défaut
`max_slot_wal_keep_size=-1`, ce slot peut retenir un WAL illimité et remplir
le disque de chaque leader potentiel.

| Contrôle | Comportement requis |
|---|---|
| `max_slot_wal_keep_size` | valeur finie sous la réserve d'urgence du filesystem ; `4GB` est la référence pour un volume de lab de 20–40 GB |
| `member_slots_ttl` | valeur finie (`10min` de référence) pour libérer les slots des membres réellement absents |
| Archive WAL | `archive_mode=on` seulement avec un `archive_command` testé et supervisé ; une archive en panne empêche aussi le recyclage |
| Santé replica | sain seulement si l'état est `streaming`, le lag connu sous le seuil et la timeline identique au leader |
| Capacité | alerter sur l'usage de `pg_wal`/filesystem avant 70 % et réserver de la place au checkpoint/recovery |
| Preflight chaos | refuser charge et injection tant que `database` et `database_ha` ne sont pas verts avec tous les membres convergés |

`wal_keep_size` est un **minimum**, pas une limite disque. `max_wal_size` est
une cible souple de checkpoint et ne prend pas le dessus sur un slot.

Surveiller le leader :

```sql
SELECT slot_name, active, restart_lsn,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn))
         AS retained_wal
FROM pg_replication_slots
ORDER BY pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) DESC;
```

Si un membre dépasse le budget de lag :

1. Arrêter la charge à forte écriture et vérifier qu'un autre leader/replica
   sain contient les données requises.
2. Déterminer si le replica peut récupérer le WAL depuis l'archive. Si son slot
   physique a `wal_status='lost'`, arrêter et fence le replica périmé, supprimer
   ce slot invalide sur le leader avec `pg_drop_replication_slot()`, puis
   laisser le fournisseur le recréer.
3. Si le WAL est indisponible, réinitialiser le replica. Avec Patroni :
   `patronictl -c /etc/patroni/patroni.yml reinit rhorizon-pg <member>` ; avec
   `pgha`, utiliser sa procédure documentée de rebuild BSD.
4. Ne jamais supprimer manuellement des fichiers de `pg_wal`. Si le filesystem
   est plein, ajouter d'abord de la capacité temporaire, démarrer un leader
   faisant autorité, laisser un checkpoint appliquer la limite du slot, puis
   réinitialiser les replicas périmés.
5. Confirmer `streaming`, timelines et lag convergés, puis
   `/cluster/health` vert avant de rétablir la charge.

La limite finie choisit volontairement de reconstruire un replica devenu
irrécupérable plutôt que de faire tomber le leader d'écriture par `ENOSPC`.

> La HA donne de la disponibilité, pas de l'intégrité : elle ne protège PAS
> contre la perte du master password (utiliser Shamir), un password/token
> compromis (voir [THREAT-MODEL.md](../THREAT-MODEL.md)), ni le DR cross-région
> (expédier pgBackRest offsite + un cold standby).

## 1. Bootstrap

Le chemin courant est dans [HA-CLUSTER.md](HA-CLUSTER.md) "Démarrage rapide"
(`rhorizon cluster init` -> distribuer le `ha_password` -> démarrer les joiners
avec `RH_HA_AUTO_JOIN`). Pre-flight sur chaque nœud : vault unsealed,
`RH_CLUSTER_HA_ENABLED=true`, `/var/lib/rhorizon` persistant, `/run/rhorizon`
tmpfs 0700, TLS activé.

Patterns de distribution du `ha_password` (hors-bande, mode 0400) :
- **Swarm** : `docker secret create ha_password ha_password.b64`, monté à
  `/run/secrets/ha_password`.
- **K8s** : `kubectl create secret generic ha-password
  --from-file=ha_password=./ha_password.b64`, monté en `subPath`.
- **Bare metal** : `scp` vers `/run/ha_password`, `chmod 0400`, `chown 1500:1500`.

`RH_HA_PASSWORD_FILE` lit les **32 octets bruts**
(`base64 -d < ha_password.b64 > ha_password.raw`), pas le base64. Après JOIN,
retirer le secret - le mTLS steady-state ne l'utilise pas. Une alternative
portable age+vault est en section 3.8.

## 2. Rolling restart

Invariants : ne jamais laisser le cluster applicatif sans tête (transférer le
rôle de primary applicatif à un secondary sain avant son restart), attendre
`>= 2 * cluster_join_quarantine_secs` entre nœuds, vérifier la chaîne d'audit
après chaque étape.

```bash
# pre-flight : chaque membre hb < 5s, aucun joining/draining, cert_expiry >= 7j
rhorizon cluster status --json | jq '[.members[] | {uuid, state:.ha_state, hb:.heartbeat_age_secs, expiry:.cert_expiry_days}]'
```

Ordre : **secondaries d'abord** (version la plus basse, puis expiry de cert le
plus proche), **primary applicatif en dernier** (seulement après démotion).

```bash
# chaque secondary :
docker service update --force rhorizon_api      # ou : kubectl rollout restart deployment/rhorizon-api
sleep 120                                        # 2 * cluster_join_quarantine_secs
rhorizon cluster status                          # confirmer hb < 5 + SECONDARY

# le primary applicatif : handover explicite, puis le restart comme un secondary
PRIMARY_UUID=$(rhorizon cluster status --json | jq -r '.primary_uuid')
SUCCESSOR=$(rhorizon cluster status --json | jq -r '.members[]|select(.ha_state=="SECONDARY").node_uuid' | head -n1)
rhorizon cluster demote "$PRIMARY_UUID" && rhorizon cluster promote "$SUCCESSOR"
```

Après restart, la chaîne d'audit doit rester intacte (sinon stop et enquêter) :

```bash
curl -fs -H "Authorization: Bearer $TOKEN" "$RH_API/api/v1/vault/audit/verify" | jq .chain_intact   # true
```

Si un nœud restarté reste `joining` au-delà de `cluster_joining_orphan_ttl_secs`,
le reaper purge la row et il REJOIN via mTLS. S'il reste `null` au-delà de 5
min, suspecter une erreur de cert TLS ou un `cluster-cert.pem` périmé sur le
volume.

## 2.1 Matrice panne/réponse bout-en-bout

Utiliser le nom du rôle et du composant dans les alertes. « Primary down »
n'est pas exploitable tant qu'il ne précise pas primary applicatif ou leader
de base.

| Panne ou pression | Signal et réponse automatique attendus | Réponse opérateur | Interprétation K7 / client |
|---|---|---|---|
| Un worker follower tombe ; le master crypto local reste présent | la couverture workers baisse temporairement ; les siblings continuent de déléguer au master crypto local | inspecter la supervision si la couverture ne revient pas dans le budget d'attachement/convergence | une perte dans la fenêtre injectée peut être attendue ; tout worker stale après convergence est un défaut |
| Master crypto local perdu avec quorum Shamir | les followers élisent un nouveau master crypto local, reconstruisent puis repartagent les clés | normalement observer ; enquêter si le conteneur se seal ou dépasse le budget d'élection | un retry transitoire correctement identifié peut être attendu ; misses silencieux ou échecs post-convergence sont des défauts |
| Secondary applicatif/conteneur perdu | le LB le retire après échec readiness ; les autres nœuds actif/actif servent | récupérer/remplacer le nœud ; vérifier convergence workers et membership | une connexion déjà attachée au nœud mort peut échouer ; les erreurs après convergence LB sont des défauts |
| Primary applicatif perdu | les secondaries élisent un successeur après expiry du lease ; lectures/écritures ordinaires restent actif/actif, les tâches singleton attendent | utiliser `cluster promote` seulement si l'élection automatique échoue et Database HA est saine | isoler la fenêtre d'élection injectée ; ne pas appeler cela un failover de base |
| Leader de base perdu avec quorum fournisseur | Patroni ou `pgha` promeut un replica ; endpoint/VIP d'écriture migre ; les pools applicatifs se reconnectent | vérifier un seul leader de base, replicas streaming, lag acceptable et bon propriétaire VIP quand il est rapporté | le travail DB in-flight peut être retriable dans la fenêtre déclarée ; les erreurs après convergence DB et workers sont des défauts |
| Replica non streaming ou slot retenant trop de WAL | `database_ha` orange ; les guardrails WAL/disque alertent avant remplissage du leader | arrêter chaos/fortes écritures, préserver un leader faisant autorité, réparer ou reconstruire selon 0.6 | ne jamais continuer K7 comme si le cluster était sain ; preflight/guardrail échoué |
| Quorum DB perdu, aucun/plusieurs leaders ou mauvais propriétaire VIP | `database_ha` rouge et `/readiness` ne doit pas déclarer le cluster sûr | fence les écritures et restaurer le quorum fournisseur ; ne pas utiliser la promotion applicative | vraie panne HA, même pendant une fenêtre chaos |
| Supervision Database HA indisponible/non configurée | `database_ha` noir/gris ; santé inconnue | réparer/configurer les endpoints avant un drill | le preflight doit refuser K7 ; gris n'est pas un pass |
| Cluster sain au plafond d'admission | réponse structurée `429 capacity_overloaded` avec `Retry-After` ; readiness reste un signal de santé | tuner la capacité ou faire back off aux clients ; corréler API, DB, WAL et CPU | load-shed attendu au plafond mesuré ; ne pas réécrire en `503` |
| Nœud sealed, quarantined ou fenced volontairement | `/readiness` renvoie `503` ; le LB éjecte le backend | corriger la cause seal/quarantine/fence annoncée | état de disponibilité, pas surcharge de capacité |
| Aucun upstream ready ou connexion upstream cassée | l'edge/gateway peut émettre `502`/`503` ; le message doit signaler l'absence de backend/upstream ready si le proxy le permet | corréler état LB et `/cluster/health`, conserver les preuves proxy/API | ce n'est pas une bonne réponse de surcharge et ne doit jamais devenir `capacity_overloaded` |
| Audit, couverture workers ou requêtes échouent après tous les gates verts | aucune exception HA attendue ne reste | arrêter et enquêter sur l'intégrité, l'attachement ou la charge | vrai défaut ; ne jamais le cacher en `expected_fault` |

Si une requête atteint rhorizon, conserver son erreur structurée et
`Retry-After`. Si aucun backend ne l'accepte, l'edge doit rapporter la vraie
condition upstream ; il ne peut pas inventer un diagnostic applicatif. K7 ne
peut marquer `expected_fault` que dans la fenêtre injection/recovery déclarée
**et** si la sémantique correspond à la matrice. Garder des compteurs séparés
pour rejets contrôlés attendus, pannes transport et défauts post-convergence.

## 2.2 Maintenance planifiée et montée de version

Un restart n'est pas automatiquement un upgrade sûr. Avant un rolling upgrade,
vérifier que la release autorise un cluster mixed-version et que ses migrations
restent backward-compatible. Le preflight complet, l'ordre edge/API/base, les
gates de réadmission des workers, les preuves post-upgrade et les limites de
rollback sont dans
[HA-PRODUCTION-REFERENCE.md](HA-PRODUCTION-REFERENCE.md#maintenance-upgrade).

Invariant court : **un domaine de panne à la fois, secondaries applicatifs
d'abord, primary applicatif après handover explicite, replicas DB d'abord puis
leader après switchover contrôlé par le fournisseur**. Exiger la convergence
workers, membership, réplication, WAL et audit après chaque étape. Si la
compatibilité mixed-version ou downgrade n'est pas explicite, fermer les
écritures et utiliser une fenêtre de maintenance déclarée.

## 3. Scénarios de recovery

### 3.1 Crash du master crypto local avec quorum survivant

`master_watch_loop` détecte le master périmé ; les followers courent pour
`pg_advisory_xact_lock('role:master')`, le gagnant collecte `M-1` shares Shamir
(`M = cluster_shamir_threshold`, défaut `max(2, total//2+1)`), reconstruit les
sous-clés, unseal, et redistribue les shares aux survivants. Opérateur :
généralement rien - tailer `vault_logs` pour `election_won`, confirmer `rhorizon
cluster status`, vérifier que `/audit/verify` reste `chain_intact=true`.

- Cluster applicatif 2 nœuds : élection à l'aveugle seulement si Database HA
  annonce un quorum et que son endpoint d'écriture est writable (la DB est
  l'arbitre externe) ; sinon le survivant passe en mode operator-managed.
  Utiliser `rhorizon cluster promote <uuid>` seulement pour un
  **primary applicatif** absent, jamais pour un leader de base absent.
- Perte de quorum (< `M-1` followers) : le cluster gèle sealed ; recovery avec
  `POST /unseal` (master password + 2FA) sur un nœud.

### 3.2 Fuite de CA suspectée

```bash
rhorizon cluster rotate-ca --yes
```

Mint une CA fraîche, garde la précédente pour la fenêtre de grâce
(`cluster_ca_grace_window_secs`, défaut 7j, vérif dual-CA), et flippe
`force_renew_at` sur chaque nœud ; la boucle de renouvellement de chaque nœud
(poll 12h) rafraîchit son cert via `/cluster/refresh-cert`. La CA précédente est
droppée une fois tous les nœuds tournés, ou à l'expiry de grâce. Pousser le
nouveau bundle vers tout proxy qui le pin :

```bash
rhorizon cluster ca-bundle --output /etc/nginx/ssl/cluster-ca.pem && reload nginx   # imprime le SHA-256
```

### 3.3 Rotation ha_password (planifiée)

Stage -> vérifier -> confirm (ou cancel). Pas de fenêtre de plaintext au repos ;
le nouveau secret est mint dans `confirm` et renvoyé une fois. TTL
`cluster_pending_ha_rotation_ttl_secs` (défaut 3600s) ; un `confirm` post-expiry
renvoie 410.

```bash
B="$RH_API/api/v1/vault/cluster/rotate-ha-password"; H="Authorization: Bearer $TOKEN"
curl -fsS -X POST -H "$H" "$B/stage"
curl -fsS       -H "$H" "$B"              # GET statut (pas de suffixe /status)
curl -fsS -X POST -H "$H" "$B/confirm"    # ou .../cancel
```

Après confirm, redistribuer le nouveau `ha_password` aux nœuds pas encore
JOINés (les membres existants continuent via mTLS) et faire tourner tout
`RH_HA_PASSWORD_FILE` persisté.

### 3.4 Cert de nœud proche de l'expiry

Auto-renouvelé sous `cluster_cert_renewal_threshold_days` (défaut 30j) par la
boucle par-nœud. Forcer maintenant :

```bash
rhorizon cluster rotate-cert <node_uuid>     # un nœud ; --all pour broadcast
```

### 3.5 Perte de nœud (volume wipé, hôte détruit)

Un nœud qui a perdu `/var/lib/rhorizon` boot avec un nouvel UUID et auto-JOIN
comme nouveau ; l'ancienne row devient périmée. L'évincer (ajoute à
`revoked_node_uuids`, donc le cert perdu ne peut jamais re-onboarder) :

```bash
rhorizon cluster status --json | jq '.members[]|select(.heartbeat_age_secs>600).node_uuid'
rhorizon cluster evict <stale_uuid>
```

### 3.6 Évincé par erreur

```bash
rhorizon cluster unrevoke <node_uuid>        # puis restart le nœud pour re-JOIN sous le même UUID
```

### 3.7 La CA cluster signe les certs serveur nginx

La CA cluster signe à la fois le cert d'identité par-nœud (mTLS) et le cert
serveur nginx ; la boucle de renouvellement rafraîchit les deux en un
round-trip. Au premier bootstrap nginx démarre avec un cert self-signed ;
`bootstrap.yml` appelle ensuite `POST /cluster/issue-server-cert` sur le
primary applicatif et hot-swap la paire signée par la CA cluster. Pour
ré-émettre (nouveau SAN / IP) :

```bash
curl -sf -H "Authorization: Bearer $ROOT_TOKEN" \
  -d '{"san_ips":["10.0.1.11"],"san_dns":["rhorizon-1","vault.lab"]}' \
  https://rhorizon-1:8443/api/v1/vault/cluster/issue-server-cert | tee server-cert.json
# déposer server_cert_pem/server_key_pem dans /etc/nginx/ssl/server.{crt,key} ; systemctl reload nginx
```

Réservé au master crypto local (503 retry-after si routé sur un worker
follower), `admin:w`. Le reload nginx passe par
`RH_CLUSTER_NGINX_RELOAD_CMD` (lié sudoers à `systemctl reload nginx`).

#### Vérifier chaque nœud, pas seulement le primary

`issue-server-cert` ne tourne que contre le primary applicatif. Les joiners
récupèrent leur cert serveur signé par la CA cluster via la boucle de
renouvellement par-nœud ; un joiner qui n'en a jamais terminé une garde donc le
cert self-signed avec lequel nginx a démarré. Ce cert **fonctionne** — le TLS
réussit, l'API répond — donc rien n'échoue visiblement ; simplement, les pairs
ne peuvent pas vérifier l'identité de ce nœud.

Interrogez chaque nœud directement, pas à travers le load balancer :

```bash
for h in rhorizon-1 rhorizon-2 rhorizon-3; do
  printf '%s ' "$h"
  echo | openssl s_client -connect "$h:8443" 2>/dev/null \
    | openssl x509 -noout -issuer -subject -enddate
done
```

`issuer` doit être la CA cluster. Si `issuer` est égal à `subject`, le nœud est
encore self-signed. Un second indice est la durée de vie : les certs signés par
la CA cluster portent `cluster_node_cert_validity_days` (90 par défaut), alors
que le placeholder de bootstrap est émis pour 10 ans.

### 3.8 Livraison portable du ha_password (age + vault)

Une alternative cross-platform au flow tmpfs `RH_HA_PASSWORD_FILE`. Une
fois, post-`/cluster/init` : générer une clé age 32 octets, la stocker comme
secret vault `cluster-ha/ha-bootstrap`, et age-chiffrer le `ha_password` avec
elle. Par joiner : mint un token scopé, IP-locké, 24h, et déposer la paire
`{ha-password.age, token}` (mode 0400). Env du joiner :

```ini
RH_HA_PASSWORD_STORAGE=age_vault
RH_HA_PASSWORD_AGE_PATH=/etc/rhorizon/ha-password.age
RH_HA_BOOTSTRAP_TOKEN_FILE=/etc/rhorizon/ha-bootstrap-token
RH_HA_BOOTSTRAP_SECRET_NAME=ha-bootstrap
RH_HA_BOOTSTRAP_NAMESPACE=cluster-ha
RH_HA_PRIMARY_URL=https://<primary-applicatif>:8200
```

Au boot le joiner fetch la clé age (la lecture est auditée avec sa source IP),
déchiffre en RAM mlock'd, exécute le JOIN normal, puis unlink les deux
artefacts. Révoquer le token de bootstrap une fois le nœud JOINé (defense in
depth ; le TTL 24h l'expire de toute façon). Après une rotation de `ha_password`,
re-chiffrer le nouveau password et re-déployer le fichier `.age` aux nœuds pas
encore JOINés (les nœuds déjà JOINés utilisent le REJOIN par cert, non affectés).

### 3.9 Joiner bloqué en PermanentError post-409

La row de membership existe mais la wrapped key du `/cluster/join` original a été
perdue en transit. Le cache d'idempotence JOIN du primary applicatif
(`cluster_join_idempotency_ttl_secs`, défaut 300s) couvre le cas transitoire ;
au-delà, soft-reset (R1) :

```bash
# sur le primary applicatif (admin token), UUID = joiner bloqué
curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$PRIMARY/cluster/evict/$UUID"
curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$PRIMARY/cluster/unrevoke/$UUID"
# sur le joiner : wiper un cert partiel s'il existe, garder node-uuid, restart
rm -f /var/lib/rhorizon/cluster-cert.pem /var/lib/rhorizon/cluster-cert.key
docker compose restart rhorizon-api
```

Garder `/var/lib/rhorizon/node-uuid` pour que le joiner réutilise le même UUID
(R1 reste soft). R2 (dernier recours, plusieurs nœuds bloqués) : seal chaque
nœud, wiper les rows cluster de `vault_cluster_nodes` + `vault_cluster_config`
en psql, re-run `/cluster/init` sur le nouveau primary applicatif,
re-distribuer le `ha_password`, démarrer les joiners depuis des chemins de cert
propres. R2 casse la liaison signée de la chaîne d'audit des JOINs pré-reset -
préférer R1 pour les contextes de conformité.

## 4. Références

- [HA-CLUSTER.md](HA-CLUSTER.md) - architecture, machine à états, options, endpoints
- [HA-BENCH.md](HA-BENCH.md) - timing de failover sous charge
- [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) - backup/restore, réparation de chaîne d'audit
