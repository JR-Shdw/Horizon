# rhorizon-pgha - HA PostgreSQL native BSD

Élection de leader et bascule automatique pour un étage PostgreSQL 18 en
réplication par streaming réparti sur **FreeBSD + NetBSD + OpenBSD**, **sans
etcd/consul/Patroni, sans CARP/multicast, et sans arbitre séparé**.

C'est le fournisseur derrière la ligne `Database HA: rhorizon-pgha` de
[`COMPATIBILITY.md`](COMPATIBILITY.md). Il existe parce que le plan de contrôle
de Patroni suppose etcd ou consul, ce qui s'accorde mal avec les BSD ; le modèle
de santé `database_ha` neutre de rhorizon permet à un autre fournisseur de tenir
ce rôle. Le fournisseur lui-même est développé dans un dépôt séparé ; ce
document en est la conception et les preuves mesurées, gardées ici pour que la
capacité annoncée par la matrice de compatibilité soit documentée au même
endroit qu'elle est annoncée.

Mise en route pas à pas, pièges par OS compris :
[`PGHA-SETUP.md`](../PGHA-SETUP.md) (EN).

## Conception : quorum de pairs à 3

Trois nœuds PostgreSQL 18, un par OS. Le leadership exige une **majorité (>= 2
sur 3)** de membres joignables. Une seule partition réseau peut détenir 2 nœuds
sur 3, donc au plus un côté peut élire ou conserver un primary — **le
primary-unique est garanti sans arbitre externe**. C'est la même garantie qu'un
cluster etcd/raft à 3 nœuds, obtenue depuis la simple joignabilité des pairs.

Chaque nœud fait tourner un agent. Toutes les ~3 s il interroge le rôle et le
LSN WAL de tous les membres via PostgreSQL (comme rôle `pg_monitor`) et :

1. `reachable` = les membres qui ont répondu ; `quorum` = `len(reachable) >= 2`.
2. **Pas de quorum** (minorité) -> si je suis primary, **auto-fencing** : lâcher
   le VIP et arrêter PostgreSQL.
3. **Quorum** -> élire un leader :
   - exactement un primary joignable -> le garder (stable, pas de va-et-vient de
     failback) ;
   - aucun primary joignable -> promouvoir le standby le plus avancé (LSN de
     replay maximal, départage sur l'id de nœud) ;
   - plus d'un primary (un ancien primary revenu) -> le plus bas s'auto-fence.
4. Leader : promouvoir si standby, prendre le **VIP** (`ifconfig alias`), et
   créer un **slot de réplication par pair**. Les slots ne survivent pas à une
   promotion, donc sans ça un standby ne peut pas se reconnecter après une
   bascule.
5. Non-leader : ne détient jamais le VIP ; un primary périmé s'auto-fence.

Le VIP est l'adresse d'écriture PG. Les standbys posent
`primary_conninfo = host=<pg-write-vip>` et suivent donc celui qui le détient à
l'instant présent.

## Supervision et statut

L'agent appartient au gestionnaire de services natif sur chaque OS supporté :

| OS | Activer / démarrer | Statut |
|---|---|---|
| FreeBSD | `sysrc pgha_agent_enable=YES && service pgha_agent start` | `service pgha_agent status` |
| NetBSD | `echo pgha_agent=YES >> /etc/rc.conf && /etc/rc.d/pgha_agent start` | `/etc/rc.d/pgha_agent status` |
| OpenBSD | `rcctl enable pgha_agent && rcctl start pgha_agent` | `rcctl check pgha_agent` |
| Linux | `systemctl enable --now pgha-agent` | `systemctl status pgha-agent` |

Chaque tick de la boucle de contrôle écrit atomiquement
`/var/run/pgha-agent.json` et sert la même topologie non secrète sur
`http://<member-ip>:8010/status`. `GET /health` vérifie seulement que la boucle
de contrôle a publié récemment ; quorum, leader, propriété du VIP d'écriture,
état du receveur et retard se notent depuis `/status`.

rhorizon consomme les trois endpoints comme composant `database_ha` neutre :

```sh
RH_DATABASE_HA_PROVIDER=pgha
RH_DATABASE_HA_STATUS_URLS=http://<db-node-1>:8010,http://<db-node-2>:8010,http://<db-node-3>:8010
```

> N'exposez le port 8010 que sur le réseau d'administration des bases. Il ne
> porte aucune route de mutation ni credential, mais il révèle les noms des
> membres, les rôles, les positions WAL, le quorum et la propriété du VIP.

**Le contrat de statut ne cache délibérément pas la limite de reprise
actuelle.** Un primary qui s'auto-fence est arrêté, pour empêcher des écritures
d'arriver sur son IP directe. L'agent ne lance pas encore `pg_rewind` et ne le
redémarre pas sûrement en standby. La supervision native maintient l'agent
vivant et signale le membre fencé, mais **un opérateur doit le rejoindre** tant
que le rewind automatique n'a pas atterri.

## Pourquoi pas CARP, pourquoi pas un témoin

Les deux conceptions précédentes ont été construites puis écartées pour des
raisons mesurées, et c'est pourquoi l'actuelle n'a aucun arbitre :

- **CARP** (v0) : son multicast VRRP n'est pas délivré entre hôtes hyperviseurs
  (`netstat -sp carp` montrait 0 reçu) -> split-brain à double MASTER. Abandonné.
- **Bail témoin** (v1) : un bail à détenteur unique remplaçait l'élection de
  CARP. Ça marchait, mais le témoin était un **point de défaillance unique** —
  un hoquet passager empêchait l'unique primary de renouveler, donc il
  s'auto-fençait et *la base tombait*. Retiré.
- **Quorum de pairs** (v2, actuel) : dès qu'OpenBSD a livré PostgreSQL 18,
  OpenBSD est devenu un vrai troisième membre de base, donnant un authentique
  quorum à 3 nœuds et supprimant complètement l'arbitre. Le témoin n'est
  conservé que comme repli documenté à 2 nœuds.

## Topologie de référence

| nœud | OS | pgdata | nic |
|---|---|---|---|
| `<db-node-1>` | FreeBSD 14.4 | `/var/db/postgres/data18` | `vtnet0` |
| `<db-node-2>` | OpenBSD 7.9 | `/var/postgresql/data` | `vio0` |
| `<db-node-3>` | NetBSD 10.1 | `/usr/pkg/pgsql/data` | `vioif0` |

Les adresses sont délibérément des placeholders. Chaque nœud a besoin d'une
adresse joignable sur le réseau d'administration des bases et d'une adresse
flottante pour le VIP d'écriture (`<pg-write-vip>` ci-dessous) ; rien dans la
conception ne dépend d'un sous-réseau particulier.

Tous en PostgreSQL 18, `initdb --data-checksums --encoding=UTF8 --locale=C`,
`listen_addresses='*'`, streaming depuis le VIP avec un slot par standby. Le mot
de passe de réplication vient de votre magasin de secrets vers un `.pgpass`
détenu par l'utilisateur PostgreSQL, avec un hôte joker — l'adresse du pair est
le VIP flottant, pas un nœud fixe. L'agent lit les pairs via un rôle à qui
`pg_monitor` a été GRANTé.

## Pièges par OS

Chacun de ceux-ci a été rencontré puis corrigé pendant la mise en route ; ils
font la différence entre un cluster qui marche et un après-midi de débogage :

- **OpenBSD** : la LibreSSL de base ne sait toujours pas charger des certificats
  TLS Ed25519, donc le TLS de l'application a besoin d'un python construit
  contre le port OpenSSL ; la réplication utilise SCRAM et n'est pas affectée.
  PostgreSQL ne démarrera pas tant que les sémaphores SysV ne sont pas relevés —
  `kern.seminfo.semmni=100`, `kern.seminfo.semmns=2048` dans
  `/etc/sysctl.conf`. Le rôle superutilisateur PG est `postgres`, l'utilisateur
  système est `_postgresql`, le script rc.d est `postgresql`.
- **NetBSD** : un alias d'IP flottante est marqué `DUPLICATED` sous un réseau
  d'hyperviseur ponté (réflexion d'ARP gratuit) -> poser
  `net.inet.ip.dad_count=0`. Le shell de `pgsql` est `nologin` par défaut ;
  mettez `/bin/sh` pour `su -l`.
- **Tous** : le catalogue d'un standby est celui du primary, donc connectez-vous
  pour les vérifications de rôle en tant que rôle `postgres` sur `127.0.0.1` en
  trust, et non par auth peer sur l'utilisateur système.

## Comportement mesuré

Sur un cluster de lab à 3 nœuds :

- **Régime établi** : primary OpenBSD détenant le VIP, standbys FreeBSD et
  NetBSD, les trois d'accord sur le leader.
- **Bascule** : le nœud primary a été tué net. La majorité 2-sur-3 a élu le
  standby le plus avancé, l'a promu et a déplacé le VIP en ~10 s ; les écritures
  à travers le VIP ont repris ; un primary unique a été maintenu tout du long.
- **Auto-réparation du standby** : le nouveau leader a créé les slots de pairs,
  et le standby survivant a re-streamé automatiquement.
- **Prévention du split-brain au rejoin** : le nœud redémarré est revenu comme
  primary périmé, a vu un leader de LSN supérieur, s'est **auto-fencé**, puis a
  rejoint comme standby via basebackup.

## Pas encore fait

Annoncé clairement, parce que la matrice de compatibilité en dépend :

- **Rejoin automatique** (`pg_rewind` dans l'agent) au lieu d'un basebackup
  manuel. C'est la raison pour laquelle un membre fencé exige aujourd'hui une
  action de l'opérateur.
- Un **test de propriété** enchaînant de nombreux cycles
  partition/promotion/rejoin et vérifiant l'invariant de primary unique.
- **TLS sur la réplication**, et un VIP `pg-read` ou pgbouncer pour la montée en
  charge en lecture.
- La gestion de configuration des `pgha.env` par nœud, des units rc.d et des
  sysctls.
