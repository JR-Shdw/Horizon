# Multi-worker

The API runs N uvicorn workers on one host (one **local crypto master** holds
the keys, the rest delegate crypto over a Unix socket). It is always on -
Docker Compose starts it with no config. The only knob you normally touch is
the worker count.

## Default

`docker-compose.yml` ships 5 workers. The image boot wrapper floors the count to
5 (the failover quorum needs it).

## Change the worker count

`.env` (read by Docker Compose):

```ini
RH_WORKERS=8
```

Compose override file:

```yaml
services:
  api:
    environment:
      RH_WORKERS: "8"
```

Native / systemd - export before start:

```sh
export RH_WORKERS=8
```

## Env vars

| Var | Default | Meaning |
|-----|---------|---------|
| `RH_WORKERS` | `5` | uvicorn workers (1 master + N-1 followers). `1` = single-worker (keys in-process, no Shamir/RPC); `2`-`4` floored to 5 for quorum; above `255` the container refuses to boot (Shamir share-index limit). |
| `RH_CLUSTER_SHAMIR_TOTAL` | `0` | key shares; `0` = auto `max(5, RH_WORKERS)`. |
| `RH_CLUSTER_SHAMIR_THRESHOLD` | `0` | failover quorum; `0` = auto majority `max(2, total//2+1)`. |

Leave the two Shamir vars at `0` - they track the worker count. Set them only
for an asymmetric quorum.

## Sizing

| Workers | Memory (mlock reservation) |
|---|---|
| 5 | ~1.25 GB |
| 10 | ~2 GB |

Reservation = workers x 160 MB + 256 MB Argon2id unseal spike + headroom. Set
the worker count only; Shamir shares/threshold auto-derive. 2-4 floor to 5.

## Failover

If the local crypto master process dies, a surviving worker is elected and
rebuilds the keys from a quorum of shares. It needs at least `THRESHOLD - 1`
followers alive at crash time, otherwise the vault stays sealed until someone
unseals it. This local role is not the application primary or database leader.

## See also

Multi-node HA (provider-neutral Database HA: Patroni reference on
Linux/Kubernetes, `pgha` on BSD):
[HA-RUNBOOK.md](HA-RUNBOOK.md) section 0 +
[HA-CLUSTER.md](HA-CLUSTER.md).
