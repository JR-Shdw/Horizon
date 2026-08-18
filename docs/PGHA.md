# rhorizon-pgha - BSD-native PostgreSQL HA

Leader election and automatic failover for a PostgreSQL 18 streaming-replication
tier across **FreeBSD + NetBSD + OpenBSD**, with **no etcd/consul/Patroni, no
CARP/multicast, and no separate arbiter**.

This is the provider behind the `Database HA: rhorizon-pgha` row in
[`COMPATIBILITY.md`](COMPATIBILITY.md). It exists because Patroni's control plane
assumes etcd or consul, which is a poor fit on the BSDs; rhorizon's
provider-neutral `database_ha` health model lets a different provider fill that
role. The provider itself is developed in a separate repository; this document is
the design and the measured evidence, kept here so the capability the
compatibility matrix claims is documented in the same place it is claimed.

Step-by-step bring-up, including the per-OS traps: [`PGHA-SETUP.md`](PGHA-SETUP.md).

## Design: peer-quorum of 3

Three PostgreSQL 18 nodes, one per OS. Leadership requires a **majority (>= 2 of
3)** of members reachable. Only one network partition can ever hold 2 of 3 nodes,
so at most one side can elect or keep a primary - **single-primary is guaranteed
with no external arbiter**. That is the same guarantee a 3-node etcd/raft cluster
gives, obtained from plain peer reachability.

Each node runs one agent. Every ~3s it queries role and WAL LSN of all members
over PostgreSQL (as a `pg_monitor` role) and:

1. `reachable` = members that answered; `quorum` = `len(reachable) >= 2`.
2. **No quorum** (minority) -> if I am primary, **self-fence**: drop the VIP and
   stop PostgreSQL.
3. **Quorum** -> elect a leader:
   - exactly one primary reachable -> keep it (stable, no failback churn);
   - no primary reachable -> promote the most-advanced standby (max replay LSN,
     tie-break on node id);
   - more than one primary (a recovered stale primary) -> the lower one
     self-fences.
4. Leader: promote if standby, take the **VIP** (`ifconfig alias`), and create a
   replication **slot per peer**. Slots do not survive promotion, so without this
   a standby cannot reconnect after a failover.
5. Non-leader: never holds the VIP; a stale primary self-fences.

The VIP is the pg-write address. Standbys set `primary_conninfo = host=<pg-write-vip>` and
therefore follow whoever currently holds it.

## Supervision and status

The agent is owned by the native service manager on every supported OS:

| OS | Enable / start | Status |
|---|---|---|
| FreeBSD | `sysrc pgha_agent_enable=YES && service pgha_agent start` | `service pgha_agent status` |
| NetBSD | `echo pgha_agent=YES >> /etc/rc.conf && /etc/rc.d/pgha_agent start` | `/etc/rc.d/pgha_agent status` |
| OpenBSD | `rcctl enable pgha_agent && rcctl start pgha_agent` | `rcctl check pgha_agent` |
| Linux | `systemctl enable --now pgha-agent` | `systemctl status pgha-agent` |

Every control-loop tick atomically writes `/var/run/pgha-agent.json` and serves
the same non-secret topology at `http://<member-ip>:8010/status`. `GET /health`
checks only that the control loop published recently; quorum, leader, write-VIP
ownership, receiver state and lag are graded from `/status`.

rhorizon consumes all three endpoints as the provider-neutral `database_ha`
component:

```sh
RH_DATABASE_HA_PROVIDER=pgha
RH_DATABASE_HA_STATUS_URLS=http://<db-node-1>:8010,http://<db-node-2>:8010,http://<db-node-3>:8010
```

> Expose port 8010 only on the database-management network. It carries no
> mutation routes and no credentials, but it does reveal member names, roles, WAL
> positions, quorum and VIP ownership.

**The status contract deliberately does not hide the current recovery boundary.**
A primary that self-fences is stopped, to prevent writes arriving on its direct
IP. The agent does not yet run `pg_rewind` or restart it safely as a standby.
Native supervision keeps the agent alive and reports the fenced member, but **an
operator must rejoin it** until automatic rewind lands.

## Why not CARP, why not a witness

Both earlier designs were built and discarded for measured reasons, which is why
the current one has no arbiter at all:

- **CARP** (v0): its VRRP multicast is not delivered across hypervisor hosts
  (`netstat -sp carp` showed 0 received) -> dual-MASTER split-brain. Dropped.
- **Witness lease** (v1): a single-holder lease replaced CARP's election. It
  worked, but the witness was a **single point of failure** - a transient blip
  made the lone primary fail to renew, so it self-fenced and *the database went
  down*. Retired.
- **Peer-quorum** (v2, current): once OpenBSD shipped PostgreSQL 18, OpenBSD
  became a real third DB member, giving a genuine 3-node quorum and removing the
  arbiter entirely. The witness is kept only as a documented 2-node fallback.

## Reference topology

| node | OS | pgdata | nic |
|---|---|---|---|
| `<db-node-1>` | FreeBSD 14.4 | `/var/db/postgres/data18` | `vtnet0` |
| `<db-node-2>` | OpenBSD 7.9 | `/var/postgresql/data` | `vio0` |
| `<db-node-3>` | NetBSD 10.1 | `/usr/pkg/pgsql/data` | `vioif0` |

Addresses are deliberately placeholders. Each node needs a reachable address on
the database-management network and one floating address for the write VIP
(`<pg-write-vip>` below); nothing in the design depends on a particular subnet.

All PostgreSQL 18, `initdb --data-checksums --encoding=UTF8 --locale=C`,
`listen_addresses='*'`, streaming from the VIP with a per-standby slot. The
replication password comes from your secret store into a `.pgpass` owned by the
PostgreSQL user, with a wildcard host - the peer address is the floating VIP, not
a fixed node. The agent reads peers as a role GRANTed `pg_monitor`.

## Per-OS gotchas

Each of these was hit and fixed during bring-up; they are the difference between
a working cluster and an afternoon of debugging:

- **OpenBSD**: base LibreSSL still cannot load Ed25519 TLS certificates, so the
  application's TLS needs a python built against the OpenSSL port; replication
  uses SCRAM and is unaffected. PostgreSQL will not start until SysV semaphores
  are raised - `kern.seminfo.semmni=100`, `kern.seminfo.semmns=2048` in
  `/etc/sysctl.conf`. The PG superuser role is `postgres`, the OS user is
  `_postgresql`, the rc.d script is `postgresql`.
- **NetBSD**: a floating-IP alias is flagged `DUPLICATED` under a bridged
  hypervisor network (gratuitous-ARP reflection) -> set `net.inet.ip.dad_count=0`.
  The `pgsql` shell is `nologin` by default; set `/bin/sh` for `su -l`.
- **All**: a standby's catalog is the primary's, so connect for role checks as the
  `postgres` role over `127.0.0.1` trust, not by OS-user peer auth.

## Measured behaviour

On a 3-node lab cluster:

- **Steady state**: OpenBSD primary holding the VIP, FreeBSD and NetBSD standbys,
  all three agreeing on the leader.
- **Failover**: the primary node was killed outright. The 2-of-3 majority elected
  the most-advanced standby, promoted it and moved the VIP in ~10s; writes through
  the VIP resumed; a single primary was held throughout.
- **Standby self-heal**: the new leader created peer slots, and the surviving
  standby re-streamed automatically.
- **Split-brain prevention on rejoin**: the restarted node came back as a stale
  primary, saw a higher-LSN leader, and **self-fenced**, then rejoined as a
  standby via basebackup.

## Not yet done

Stated plainly because the compatibility matrix depends on it:

- **Automatic rejoin** (`pg_rewind` in-agent) instead of a manual basebackup. This
  is the reason a fenced member currently needs operator action.
- A **property test** driving many partition/promote/rejoin cycles and asserting
  the single-primary invariant.
- **TLS on replication**, and a `pg-read` VIP or pgbouncer for read scaling.
- Configuration management for the per-node `pgha.env`, rc.d units and sysctls.
