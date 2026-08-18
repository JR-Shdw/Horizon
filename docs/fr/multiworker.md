# Multi-worker

L'API tourne N workers uvicorn sur un seul hôte (un **master crypto local**
tient les clés, les autres délèguent la crypto via une socket Unix). C'est
toujours actif - Docker Compose le démarre sans config. Le seul réglage qu'on
touche normalement est le nombre de workers.

## Défaut

`docker-compose.yml` livre 5 workers. Le wrapper de boot de l'image plancher le
compte à 5 (le quorum de failover en a besoin).

## Changer le nombre de workers

`.env` (lu par Docker Compose) :

```ini
RH_WORKERS=8
```

Fichier d'override Compose :

```yaml
services:
  api:
    environment:
      RH_WORKERS: "8"
```

Natif / systemd - exporter avant de démarrer :

```sh
export RH_WORKERS=8
```

## Variables d'env

| Var | Défaut | Sens |
|-----|--------|------|
| `RH_WORKERS` | `5` | workers uvicorn (1 master + N-1 followers). `1` = mono-worker (clés en-process, pas de Shamir/RPC) ; `2`-`4` plancher à 5 pour le quorum ; au-delà de `255` le conteneur refuse de démarrer (limite d'index des parts Shamir). |
| `RH_CLUSTER_SHAMIR_TOTAL` | `0` | shares de clé ; `0` = auto `max(5, RH_WORKERS)`. |
| `RH_CLUSTER_SHAMIR_THRESHOLD` | `0` | quorum de failover ; `0` = auto majorité `max(2, total//2+1)`. |

Laisse les deux vars Shamir à `0` - elles suivent le nombre de workers. Ne les
fixe que pour un quorum asymétrique.

## Sizing

| Workers | Mémoire (réservation mlock) |
|---|---|
| 5 | ~1.25 Go |
| 10 | ~2 Go |

Réservation = workers x 160 Mo + pic Argon2id 256 Mo à l'unseal + marge. Ne
règle que le nombre de workers ; les shares/threshold Shamir s'auto-dérivent.
2-4 sont ramenés à 5.

## Failover

Si le master crypto local meurt, un worker survivant est élu et reconstruit les
clés depuis un quorum de shares. Il faut au moins `THRESHOLD - 1` followers
vivants au moment du crash, sinon le vault reste sealed jusqu'à un unseal
manuel. Ce rôle local n'est ni le primary applicatif ni le leader de base.

## Voir aussi

HA multi-node (Database HA neutre : référence Patroni sous Linux/Kubernetes,
`pgha` sous BSD) : [HA-RUNBOOK.md](HA-RUNBOOK.md) section 0 +
[HA-CLUSTER.md](HA-CLUSTER.md).
