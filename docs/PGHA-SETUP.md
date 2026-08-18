# PostgreSQL 18 multi-node HA on BSD - step by step

Bring-up guide for a 3-node PostgreSQL 18 streaming-replication tier (1 primary +
2 standbys) made HA by `rhorizon-pgha`. The design and the reasoning behind it
are in [`PGHA.md`](PGHA.md); this is the procedure.

Mechanism in one line: the agent owns a floating **pg-write VIP** and elects a
leader by **majority of 3** - a minority node self-fences, so dual-primary is
impossible. No etcd, no Patroni, no CARP.

Addresses below are placeholders: `<pg-write-vip>` is the floating write address,
`<db-node-1..3>` are the members, `<db-subnet>` is the database-management
network. The replication password comes from your secret store; it is never
written into a config file in clear.

## Per-OS particularities (read first - this is where the time goes)

| thing | FreeBSD 14.4 | NetBSD 10.1 | OpenBSD 7.9 |
|---|---|---|---|
| PG18 available? | yes (`postgresql18-server`) | yes (pkgsrc) | **only >= 7.9** (7.8 ships PG17.6 and cannot join a PG18 cluster) |
| pkg tool | `pkg install` | `pkg_add` + `PKG_PATH` | `pkg_add -I` + `PKG_PATH` |
| pg OS user | `postgres` | `pgsql` | `_postgresql` |
| pgdata | `/var/db/postgres/data18` | `/usr/pkg/pgsql/data` | `/var/postgresql/data` |
| bin | `/usr/local/bin` | `/usr/pkg/bin` | `/usr/local/bin` |
| rc / service | `service postgresql ...` | `/etc/rc.d/pgsql ...` | `rcctl ... postgresql` |
| NIC (virtio) | `vtnet0` | `vioif0` | `vio0` |

**Failures you will hit, all encountered and fixed during bring-up:**

- **OpenBSD - SysV semaphores.** The default `semmni=10 / semmns=60` is too low
  and PostgreSQL dies at start with `could not create semaphores`. Set
  `kern.seminfo.semmni=100` and `kern.seminfo.semmns=2048`, persist them in
  `/etc/sysctl.conf`, and `sysctl -w` to apply live.
- **NetBSD - duplicate-address false positive.** A floating-IP alias is flagged
  `DUPLICATED` on a bridged hypervisor network (the bridge reflects the node's own
  gratuitous ARP), so the VIP goes silent. Persist
  `net.inet.ip.dad_count=0`. Also `pgsql`'s shell is `nologin`, so `su -l pgsql`
  fails until you give it `/bin/sh`.
- **All BSD - role is not the OS user.** After a basebackup a standby carries the
  *primary's* catalog, so the OS pg-user name is not necessarily a PostgreSQL
  role. Do role and health checks as the `postgres` **role** over `127.0.0.1`
  trust, never via OS-user peer auth.
- **Minimal images may lack rsync.** Move files with `tar | ssh 'tar x'`.

## 1. Install PostgreSQL 18

- **FreeBSD**: `env ASSUME_ALWAYS_YES=yes pkg install -y postgresql18-server postgresql18-client`
- **NetBSD**: `PKG_PATH=https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/x86_64/10.1/All/ pkg_add postgresql18-server`
- **OpenBSD 7.9**: `PKG_PATH=https://cdn.openbsd.org/pub/OpenBSD/7.9/packages/amd64/ pkg_add -I postgresql-server postgresql-client`

Apply the OpenBSD semaphore and NetBSD DAD sysctls now, before first start.

## 2. Initialise the primary (pick one node)

```sh
# FreeBSD shown; on NetBSD/OpenBSD run initdb as that node's pg-user into its pgdata
sysrc postgresql_enable=YES postgresql_data=/var/db/postgres/data18
su -m postgres -c '/usr/local/bin/initdb --data-checksums --encoding=UTF8 --locale=C \
    -D /var/db/postgres/data18'
```

Append to `postgresql.conf`:

```
listen_addresses = '*'
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
hot_standby = on
wal_keep_size = 512MB
ssl = off
```

Append to `pg_hba.conf`, keeping the default local / `127.0.0.1` trust lines:

```
host  replication  replicator  <db-subnet>  scram-sha-256
host  all          rhorizon    <db-subnet>  scram-sha-256
```

Start PostgreSQL, then create the roles and the application database. Take the
passwords from your secret store rather than inventing them here:

```sql
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '<pw>';
CREATE ROLE rhorizon LOGIN PASSWORD '<pw>';
GRANT pg_monitor TO rhorizon;      -- lets the agent read peer role and LSN
CREATE DATABASE rhorizon OWNER rhorizon;
```

## 3. Bring up each standby

```sh
# 3a. .pgpass -- WILDCARD host, because the peer is the floating VIP, not a node.
#     Owned by the pg-user, mode 0600.
umask 077
printf '*:5432:replication:replicator:%s\n*:5432:*:rhorizon:%s\n' "$PW" > <home>/.pgpass
chown <pguser>:<pguser> <home>/.pgpass

# 3b. wipe + basebackup FROM THE VIP (create the slot on the primary first, or -C)
<stop-pg>; rm -rf <pgdata>/*; install -d -o <pguser> -g <pguser> -m 700 <pgdata>
su -l <pguser> -c "PGPASSFILE=<home>/.pgpass pg_basebackup -h <pg-write-vip> \
    -U replicator -D <pgdata> -X stream -S <node> -R -c fast -P"

# 3c. pin primary_conninfo at the VIP (last-wins) and the slot
cat >> <pgdata>/postgresql.auto.conf <<EOF
primary_conninfo = 'host=<pg-write-vip> port=5432 user=replicator passfile=<home>/.pgpass application_name=<node> sslmode=prefer'
primary_slot_name = '<node>'
EOF
<start-pg>
```

`<home>`, `<pguser>`, the bin path and the service command all come from the
per-OS table above.

## 4. Verify replication

- On each standby: `psql "host=127.0.0.1 user=postgres dbname=postgres" -Atc "SELECT pg_is_in_recovery()"` returns `t`.
- On the primary: `SELECT application_name, state FROM pg_stat_replication` shows both standbys `streaming`.

## 5. Deploy the agent on all three nodes

Install the agent, the per-OS service unit, and a per-node `pgha.env` setting
`PGHA_FLAVOR`, `PGHA_MEMBERS`, `PGHA_VIP`, `PGHA_IFACE`, `PGHA_PGDATA`,
`PGHA_PASSFILE` and `PGHA_DBUSER`. Enable and start it with the OS's own service
manager (see [`PGHA.md`](PGHA.md)). Python 3 is the only runtime prerequisite.

Steady state: all three log `quorum=True`; one reports `role=primary vip=True`,
the other two `role=standby`. Set `PGHA_STATUS_LISTEN` to each node's member
address, then check both the native supervision state and the machine status:

```sh
curl -fsS http://<member-ip>:8010/health
curl -fsS http://<member-ip>:8010/status
```

Point every rhorizon API node at all three:

```sh
RH_DATABASE_HA_PROVIDER=pgha
RH_DATABASE_HA_STATUS_URLS=http://<db-node-1>:8010,http://<db-node-2>:8010,http://<db-node-3>:8010
RH_DATABASE_HA_MAX_REPLICA_LAG_BYTES=16777216
```

`/cluster/health` then reports `components.database_ha.provider=pgha`, and
refuses green unless all three agent observations are fresh, quorum and leader
agree, exactly one primary owns the VIP, and both standbys stream within budget.

## 6. Operate

- **Failover is automatic.** Kill the primary node: the 2-of-3 majority promotes
  the most-advanced standby and the VIP moves, holding a single primary. The new
  leader creates a per-peer replication slot so standbys re-stream by themselves.
- **Rejoin** a fenced or stale node as a standby with step 3. A returning stale
  primary self-fences on boot, so there is no split-brain window; in-agent
  `pg_rewind` is not implemented yet.
- **Verify live, never by exit code**: `pg_stat_replication`,
  `pg_is_in_recovery()`, reachability of `<pg-write-vip>`, and all three
  `/status` documents.
- **A fenced member needs you.** Native supervision restarts the agent only. It
  cannot safely restart a stopped stale primary, so rejoin it with step 3 until
  the planned in-agent `pg_rewind` path lands.
