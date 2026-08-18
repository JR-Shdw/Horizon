<!--
-----------------------------------------------------------------------------
Resurgamus Horizon - (c) 2024-2026 shdw <horizon@resurgamus.com> - AGPL-3.0
Self-hosted secrets vault - No AI training license - see LICENSE-AI.md
-----------------------------------------------------------------------------
-->

# Native install (no Docker)

> Status per OS
>
> | OS | Status | Note |
> |----|--------|------|
> | ArchLinux + linux-hardened | **validated** | linux-hardened compatible |
> | Debian 12+ | validated | Same base image as the official Docker build |
> | Ubuntu 22.04+ | validated | Debian-derived |
> | Fedora 39+ | validated | `dnf`; SELinux notes below |
> | RHEL 9 / Rocky 9 / AlmaLinux 9 | validated | EPEL for `python3.12` if not in base |
> | openSUSE Leap 15.6+ / Tumbleweed | validated | `zypper`; AppArmor instead of SELinux. Leap 15.6 is the last suite-green release; 16.0 is the current revalidation lane |
> | FreeBSD 14+ | validated | All IPC primitives shimmed 2026-05. Needs the `memorylocked=unlimited` login class the installer adds - the vault mlocks key material |
> | OpenBSD 7.4+ | validated | Same shim path as FreeBSD. `install-openbsd.sh` builds CPython against the OpenSSL port: base LibreSSL's `ssl` cannot load the Ed25519 cluster certs |
> | NetBSD 10+ | validated | `tools/drivers/netbsd.sh`; golden image built with anita. Only OS whose pkgsrc binary repo is unsigned upstream - pinned versions + HTTPS are the mitigation |
> | macOS (Apple Silicon) | validated | `tools/install-macos.sh --mode user`. Green end-to-end on GitHub-hosted `macos-latest` (`.github/workflows/macos-native.yml`): Homebrew deps, PostgreSQL, venv, Rust extension, LaunchAgent, unseal. User mode only |
> | macOS (Intel) | untested | No free runner: GitHub retired the `macos-13` image, so x86_64 darwin is unverified rather than known-broken |
> | aarch64 Linux stack | validated | Raspberry Pi 4 |
> | AIX / Solaris | not supported | POWER/SPARC + IBM/Oracle proprietary, out of project scope |
>
> Every validated OS above was run end-to-end via its `tools/install-<os>.sh`
> script (BSD lanes also gated in CI, `.cirrus.yml`).
>
> **Universal installer (`tools/install.sh`) -- validated 2026-07-12.** The
> single-entry installer + per-OS drivers (`tools/drivers/<os>.sh`) were run
> end-to-end (pkg -> ssl-capable python -> venv -> Rust ext -> PostgreSQL ->
> boot service -> vault unseal) in **system mode** on clean VMs: FreeBSD 14.4,
> NetBSD 10.1, OpenBSD 7.9, Arch (stock kernel). The legacy Linux/*BSD per-OS
> `install-<os>.sh` scripts remain for the *test* path (they also create the
> `rhorizon_test` DB + install `test-requirements.txt` for pytest); they are
> not superseded by the prod installer.
>
> **Mode selection & security.** Prefer, in order: (1) **docker / podman**
> (`--mode docker`; the laptop default that `auto` picks when a container engine
> is present); (2) **native system** (`--mode system`, root) -- full hardening,
> the vault `mlock`s ~608 MB of key material out of swap. (3) **native user**
> (`--mode user`, non-root) is a LAST RESORT: a non-root process cannot raise
> `RLIMIT_MEMLOCK`, so key pages may reach swap -- a real weakening of the
> at-rest guarantee. Use it only where neither Docker nor root is available.
>
> **Debian/Ubuntu native:** the distro `cargo`/`rustc` (Debian 12 = 1.63) is too
> old for this repo's `Cargo.lock` v4 (needs Rust >= 1.78). Install rustup (see
> 2.2) or use `--mode docker`; the installer fails early with this hint.

## Path layout

`tools/install-native.sh` keeps Linux/*BSD user-mode installs under XDG paths.
`tools/install-macos.sh` uses Apple `Library` paths. System-mode installs follow
the host OS hierarchy instead of forcing Linux paths onto BSD or macOS.

User-mode defaults:

| Purpose | Linux/*BSD user | macOS user |
|---|---|---|
| App prefix / venv | `${XDG_DATA_HOME:-~/.local/share}/rhorizon` | `~/Library/Application Support/rhorizon` |
| Config + env file | `${XDG_CONFIG_HOME:-~/.config}/rhorizon` | `~/Library/Application Support/rhorizon/config` |
| State files | `${XDG_STATE_HOME:-~/.local/state}/rhorizon` | `~/Library/Application Support/rhorizon/state` |
| Runtime sockets | `$XDG_RUNTIME_DIR/rhorizon`, else state `run/` | `$TMPDIR/rhorizon` |
| Audit JSONL files | state `audit/` | `~/Library/Logs/rhorizon` |
| Service | systemd user or nohup fallback | `~/Library/LaunchAgents/com.resurgamus.rhorizon.plist` |

System-mode defaults:

| Purpose | Linux | FreeBSD | OpenBSD | NetBSD | macOS |
|---|---|---|---|---|---|
| App prefix / venv | `/opt/rhorizon` | `/usr/local/rhorizon` | `/usr/local/rhorizon` | `/usr/pkg/rhorizon` | `/Library/Application Support/rhorizon` |
| Config + env file | `/etc/rhorizon` | `/usr/local/etc/rhorizon` | `/etc/rhorizon` | `/usr/pkg/etc/rhorizon` | `/Library/Application Support/rhorizon/config` |
| State files | `/var/lib/rhorizon` | `/var/db/rhorizon` | `/var/db/rhorizon` | `/var/db/rhorizon` | `/Library/Application Support/rhorizon/state` |
| Runtime sockets | `/run/rhorizon` | `/var/run/rhorizon` | `/var/run/rhorizon` | `/var/run/rhorizon` | `/var/run/rhorizon` |
| Audit JSONL files | `/var/log/rhorizon` | `/var/log/rhorizon` | `/var/log/rhorizon` | `/var/log/rhorizon` | `/Library/Logs/rhorizon` |
| Service | systemd unit | `/usr/local/etc/rc.d/rhorizon` | `/etc/rc.d/rhorizon` | `/etc/rc.d/rhorizon` | `/Library/LaunchDaemons/com.resurgamus.rhorizon.plist` |

The generated env file is `rhorizon.env` in the config directory. Secret files
live in `<config-dir>/secrets/` -- the shared layout described below. macOS
system-mode paths are documented as the target convention;
`tools/install-macos.sh` currently implements user mode only.

#### Credentials on disk

By default the installer leaves the vault **sealed** and writes no credentials:
you set the master password with the first unseal (see
section [7. Verify](#7-verify) below).

Credentials are written **only** when you supply a master password
(`--master-password-file FILE`, `--master-password VALUE`, `RH_MASTER_PASSWORD`,
or credentials left by an earlier run). In that case the installer unseals for
you and writes:

```
<config-dir>/secrets/                  # dir mode 0700
  master-password                      # mode 0400
  root-token                           # mode 0400, only on the first-ever unseal
```

One secret per file, so `cat` reads a credential without parsing. This is the
same layout every installer uses -- `tools/install-container.sh` and
`tools/quickstart-laptop.sh` write `~/rhorizon/secrets/` -- so one instruction
covers all of them.

Default config dirs: `~/.config/rhorizon` (user mode), `/etc/rhorizon` (Linux
system mode), `/usr/local/etc/rhorizon` (FreeBSD/OpenBSD),
`/usr/pkg/etc/rhorizon` (NetBSD).

> Installs made before the layouts converged kept both credentials in a single
> `<config-dir>/rhorizon.env-secrets` (`KEY=VALUE`, mode 0600). That file is
> still read, and still written alongside the directory above, so an existing
> install keeps re-running unchanged.

**Those files are enough to take full control of this instance.** Move them
into a password manager and delete them once the backup is verified. Keeping
them is a deliberate trade: they are what let the host reopen the vault
unattended after a restart, because an automatic unseal requires the password
to be readable by the machine. There is no way to have both.

Prefer `--master-password-file` over `--master-password`: a value passed on the
command line is visible in `/proc/<pid>/cmdline` while the installer runs, and
lands in your shell history.

### Portability

The historic Linux-only blockers are now portable or removed:

| Primitive | Linux | macOS | BSD | Used for | Status |
|-----------|:-----:|:-----:|:---:|----------|--------|
| Filesystem-path AF_UNIX sockets | yes | yes | yes | crypto-ops RPC + Shamir share-back | portable since 2026-05 (replaced abstract `\0name`) |
| Peer-UID check (`peer_cred` shim) | `SO_PEERCRED` | `LOCAL_PEERCRED` | `getpeereid()` | UID-based peer auth, fail-closed | shimmed since 2026-05; Linux validated, macOS/BSD via mocks |
| `mlock(2)` | yes | yes | yes | Rust SecureBuffer | POSIX, validated |

Two earlier blockers were eliminated outright:

- `/dev/shm` (legacy key_share flow): removed 2026-05. The RPC path is
  the only multi-worker path.
- Abstract Unix sockets (`\0name`): replaced 2026-05 by filesystem-path
  sockets under `socket_paths.runtime_dir()` (Linux system default
  `/run/rhorizon/`; BSD and macOS system installs set `/var/run/rhorizon`;
  override via `RH_RUNTIME_DIR`, `XDG_RUNTIME_DIR/rhorizon`, or the
  macOS `$TMPDIR/rhorizon` default).

The portability work touched none of the security primitives (peer-UID check,
Shamir, mlock'd Rust buffers); the worker model is identical across all 3 OS
families. See [`multiworker.md`](multiworker.md).

WSL2, and Docker Desktop on macOS, both run a Linux kernel under the
hood and therefore work as if on Linux - that's the recommended path
for users on macOS / Windows hosts who don't want to run rhorizon
natively.

The Docker Compose path (`docker-compose.yml`) is still the recommended
deployment. This document is for operators who cannot or will not run
containers on the vault host (regulated environments, air-gapped
nodes, or infra where the vault is the only service on the box).

The native install **loses two compose-level hardenings** : `read_only`
filesystem and `cap_drop: ALL`. You can rebuild equivalent constraints
via systemd directives - see [Hardening](#9-hardening) below.

---

## 1. System requirements

| Component | Version | Why |
|-----------|---------|-----|
| Linux kernel | 5.10+ | abstract sockets, `mlock`, namespaces |
| Python | **3.12** exactly | `pyo3` Rust extension is built with `abi3-py312` |
| Rust toolchain | 1.79+ stable | builds the `rhorizon_crypto` extension via maturin |
| PostgreSQL | **18** | `pg_advisory_xact_lock`, `gen_random_uuid()`, `hashtext()` |
| `libsodium` | 1.0.18+ | runtime dep of `pynacl` (Argon2id, XChaCha20-Poly1305) |
| `libldap` + `libsasl2` | recent | for `bonsai` (LDAP/AD auth) - runtime dep |
| `git` | any | clone the repo |
| `age` (optional) | 1.1+ | only needed if you also want to run the backup CLI on the host |

`mlock` requires `CAP_IPC_LOCK` or sufficient `RLIMIT_MEMLOCK`. On Linux, the
installer requests it only when it detects unencrypted disk swap. Encrypted
swap, zram, and hosts without swap need no enforcement for this threat. If swap
cannot be classified, installation remains best effort and does not fail.
User-mode services never declare a limit that could prevent startup before the
application can apply this policy. Use `--memory-lock-mode required` only after
configuring the host limit. The active memory and swap states are visible in
the API, Web UI, and `rhorizon status`.

---

## 2. Install dependencies

### 2.1 ArchLinux (validated)

```bash
sudo pacman -S --needed \
    python python-pip python-virtualenv \
    rustup base-devel \
    libsodium libldap libsasl \
    postgresql git
rustup default stable
```

> **linux-hardened** : the project is regularly exercised on Arch with
> `linux-hardened`. No tuning is needed in practice - `mlock` works
> with the default `RLIMIT_MEMLOCK`, abstract sockets are available,
> and the systemd hardening directives below stack cleanly with the
> kernel hardening.

### 2.2 Debian 12+ / Ubuntu 22.04+

```bash
sudo apt update
sudo apt install -y \
    python3.12 python3.12-venv python3.12-dev python3-pip \
    build-essential pkg-config curl \
    libsodium-dev libldap2-dev libsasl2-dev \
    postgresql-18 postgresql-client-18 \
    git
# Rust toolchain (rustup, Debian/Ubuntu rustc is too old as of 2026-05)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

If your distro doesn't ship Python 3.12 yet (Debian 12 has 3.11), use
the [deadsnakes PPA](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa)
on Ubuntu, or build from `python3.12.tar.xz` on Debian. **Do not use
3.11**: the wheel for `rhorizon_crypto` is `abi3-py312`.

If your distro doesn't yet have PostgreSQL 18 in the default repos, use
the [PostgreSQL Apt repository](https://wiki.postgresql.org/wiki/Apt).

### 2.3 Fedora 39+

```bash
sudo dnf install -y \
    python3.12 python3.12-devel python3-pip \
    gcc make pkgconf-pkg-config curl \
    libsodium-devel openldap-devel cyrus-sasl-devel \
    postgresql18-server postgresql18 \
    git
# Rust via rustup (Fedora's `rust` package is sometimes too old)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

> **SELinux** : if `pg_hba.conf` was edited and Postgres won't start,
> run `sudo restorecon -Rv /var/lib/pgsql`. For the systemd unit below,
> if logs show `audit2allow` blocks, generate a local policy with
> `audit2allow -M rhorizon < /var/log/audit/audit.log` and load it with
> `semodule -i rhorizon.pp`.

### 2.4 RHEL 9 / Rocky 9 / AlmaLinux 9

```bash
sudo dnf install -y epel-release
sudo dnf install -y \
    python3.12 python3.12-devel python3-pip \
    gcc make pkgconf-pkg-config curl \
    libsodium-devel openldap-devel cyrus-sasl-devel \
    git
# PostgreSQL 18 via the official PGDG repo (RHEL 9 base ships 13)
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql
sudo dnf install -y postgresql18-server postgresql18
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

### 2.5 openSUSE Leap 15.5+ / Tumbleweed

```bash
sudo zypper install -y \
    python312 python312-devel python312-pip \
    gcc make pkg-config curl \
    libsodium-devel openldap2-devel cyrus-sasl-devel \
    postgresql18-server postgresql18 \
    git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
```

### 2.6 FreeBSD 14+

```sh
# pkg comes bundled with the base system since FreeBSD 10.
sudo pkg install -y \
    python312 py312-pip py312-virtualenv \
    rust \
    libsodium openldap-client cyrus-sasl \
    postgresql18-server postgresql18-client \
    git curl ca_root_nss

# Enable + start postgres (rc.conf)
sudo sysrc postgresql_enable=YES
sudo service postgresql initdb
sudo service postgresql start
```

> **maturin via pip** : FreeBSD's `pkg` doesn't ship `maturin`. Install
> it inside the rhorizon venv (section 4.2). The bundled Rust toolchain
> from `pkg install rust` is recent enough (>= 1.79 since FreeBSD 14.1).
>
> **Runtime dir** : FreeBSD uses `/var/run/rhorizon` by default. `/var/run` is
> tmpfs; `/run` is not portable on FreeBSD.

> **rc.d service unit** : FreeBSD doesn't use systemd. A reference rc.d
> script is in `tools/rc.d/rhorizon` (untested). Adapt the systemd unit
> in section 6 to rc.d idioms : `daemon -P /var/run/rhorizon/rhorizon.pid` to
> background, `procname` for status checks, `command_args` for uvicorn.
> Hardening directives have rough equivalents in `jail(8)` (start
> rhorizon inside a vnet jail with `allow.raw_sockets=0` etc.).

### 2.7 OpenBSD 7.4+

```sh
# pkg_add prompts for the mirror on first run; the FAQ mirror works.
doas pkg_add -v \
    python-3.12 \
    rust \
    libsodium openldap-client cyrus-sasl \
    postgresql-server-18.x \
    git curl

# Postgres
doas /etc/rc.d/postgresql configtest
doas su - _postgresql -c "initdb -D /var/postgresql/data --locale=en_US.UTF-8"
doas rcctl enable postgresql
doas rcctl start postgresql
```

> **OpenBSD specifics** :
>
> - **`pledge(2)` / `unveil(2)`** : OpenBSD's syscall and FS-restriction
>   primitives. rhorizon does not call them currently; a hardened
>   deployment should add them around the uvicorn worker entry point
>   (out of scope for this guide - file an issue).
> - **`mlock(2)`** works without configuration on OpenBSD >= 7.0.
> - **`getpeereid(3)`** is provided by libc.so.96.x ; the peer_cred shim
>   uses `ctypes.util.find_library("c")` so the version doesn't need to
>   be hardcoded.
> - **Runtime dir** : `/var/run` is tmpfs (mfs) by default, so system installs
>   use `RH_RUNTIME_DIR=/var/run/rhorizon`.
> - **rc.d service** : same as FreeBSD, see `tools/rc.d/rhorizon`.

---

## 3. PostgreSQL setup

Initialise and start the cluster (commands vary by distro - adapt to
yours; the names below cover the most common cases).

```bash
# Arch / RHEL family / openSUSE - manual initdb
sudo -u postgres initdb -D /var/lib/postgres/data    # Arch
sudo postgresql-setup --initdb                       # RHEL family
sudo systemctl enable --now postgresql               # everywhere

# Debian/Ubuntu - postgresql-common does it on install
sudo systemctl enable --now postgresql
```

Create the rhorizon role and database :

```bash
sudo -u postgres psql <<SQL
CREATE ROLE rhorizon WITH LOGIN PASSWORD 'CHANGE_ME_LONG_RANDOM';
CREATE DATABASE rhorizon OWNER rhorizon;
SQL
```

> **TLS to Postgres** : the default config sets `RH_DATABASE_SSL=true`.
> If your cluster has TLS enabled (recommended), nothing more to do.
> For local installs without TLS (single-host, loopback only), set
> `RH_DATABASE_SSL=false` in the env file (section 5.2).

### 3.1 *BSD: SysV semaphore / shared-memory limits (SYSTEM-WIDE)

PostgreSQL 18 needs far more SysV semaphores and shared memory than the BSD
kernel defaults (OpenBSD ships `kern.seminfo.semmni=10`, `semmns=60`). Too low
and `initdb`'s bootstrap dies with `FATAL: could not create semaphores: No space
left on device`. These are **kernel-global** — there is *no* per-process
equivalent — so they must be raised for the whole host and persisted to
`/etc/sysctl.conf` (else PG fails to start after a reboot). They only **raise
ceilings**; nothing is restricted. Intended for a dedicated rhorizon host.

```sh
# OpenBSD (runtime-settable; append the same lines to /etc/sysctl.conf to persist)
sysctl kern.seminfo.semmni=256 kern.seminfo.semmns=2048 kern.seminfo.semmnu=256

# NetBSD
sysctl kern.ipc.semmni=256 kern.ipc.semmns=4096 kern.ipc.semmnu=512 \
       kern.ipc.shmmax=1073741824 kern.ipc.shmall=262144

# FreeBSD: base defaults usually suffice; `service postgresql initdb` just works.
```

**Why these numbers.** PostgreSQL allocates about
`ceil((max_connections + autovacuum_max_workers + max_worker_processes + aux) / 16)`
semaphore **sets** of ~17 semaphores each. At PG18 defaults (`max_connections=100`)
that is ~8 sets / ~136 semaphores. We set `semmni=256` (sets) and `semmns=2048`
(total) -> room for ~120 sets ≈ **~1900 backends**, ~18x the default. That covers
the heavy tier (10 workers) many times over and lets an operator raise
`max_connections` without re-tuning the kernel. A SysV semaphore is a tiny kernel
struct (tens of bytes), so a 2048 ceiling costs a few KB -- cheap insurance, which
is why we size for generous headroom rather than a tight per-deployment fit.

`initdb` data dirs differ by OS: OpenBSD `/var/postgresql/data`, FreeBSD
`/var/db/postgres/data18`, NetBSD `/usr/pkg/pgsql/data`.

> Contrast with **memlock**: the app's `mlockall()` budget is set *per service*
> (`ulimit -l` in the rc.d wrapper / systemd `LimitMEMLOCK`), sized to
> `workers*160 + 256 + 192` MB — **not** system-wide. Only the PG SysV limits are
> global (kernel design). Linux uses cgroups, so no global sysctl is needed.

### 3.2 Automated (`tools/install.sh`)

`sh tools/install.sh` (native path = `install-native.sh --mode system|user`) does
all of section 3 for you: installs postgresql-server, applies the *BSD kernel
tuning above, `initdb`s the cluster, creates role + db `rhorizon` with a random
password, and applies `schema.sql`. Point at an existing cluster instead with
`--external-db <sqlalchemy-url>` (no local PG is touched). Worker count / RAM:
`--workers N` (see section 5 / the memlock note above).

---

## 4. Build and install rhorizon

The manual commands in sections 4-6 use the Linux system defaults. On BSD,
substitute the system paths from [Path layout](#path-layout), or use
`tools/install.sh --mode system` so the installer chooses them for you.

### 4.1 Clone and create the venv

```bash
sudo useradd --system --home-dir /opt/rhorizon --shell /usr/sbin/nologin rhorizon
sudo mkdir -p /opt/rhorizon
sudo chown rhorizon:rhorizon /opt/rhorizon

sudo -u rhorizon -H bash <<'EOF'
cd /opt/rhorizon
git clone https://github.com/JR-Shdw/Horizon.git src
cd src
python3.12 -m venv /opt/rhorizon/venv
source /opt/rhorizon/venv/bin/activate
pip install --upgrade pip wheel
pip install --require-hashes -r api/requirements.txt
EOF
```

### 4.2 Build the Rust crypto extension

The Rust wheel must be built **as user `rhorizon`** so its venv site-packages
gets the matching ABI tag :

```bash
sudo -u rhorizon -H bash <<'EOF'
source /opt/rhorizon/venv/bin/activate
pip install maturin
cd /opt/rhorizon/src/api/rust
RUSTFLAGS="--remap-path-prefix=$PWD=." maturin build --release --locked --strip
pip install target/wheels/*.whl
EOF
```

Verify :

```bash
sudo -u rhorizon /opt/rhorizon/venv/bin/python -c \
    "from rhorizon_crypto import secure_zero; print('rhorizon_crypto OK')"
```

#### Fast dev path : skip the Rust toolchain (contributors only)

For contributor iteration on the Python side - no production install - a
pre-built wheel ships under `api/rust/wheel-out/`. Install it directly
into a project-local venv without `rustup` + `maturin` :

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r api/requirements.txt
make rust-wheel-install        # picks the abi3 wheel matching this Python
```

Wheel tags : linux x86_64, glibc >= 2.34, cpython 3.12+ via abi3, and
cpython 3.13 exact. Other targets use the `maturin build` flow above.

### 4.3 Apply the schema

```bash
sudo -u postgres psql -d rhorizon -f /opt/rhorizon/src/schema.sql
```

The schema is idempotent (`IF NOT EXISTS` / `CREATE OR REPLACE`) - safe
to re-run on upgrade.

---

## 5. Configuration

### 5.1 State, runtime, and audit directories

```bash
sudo install -d -o rhorizon -g rhorizon -m 0750 /var/lib/rhorizon
sudo install -d -o rhorizon -g rhorizon -m 0750 /var/log/rhorizon
```

`/run/rhorizon` should be created by systemd with `RuntimeDirectory=rhorizon`
so it is ephemeral and cleaned up on stop/reboot.

### 5.2 Environment file

Install the documented native config (`examples/rhorizon.env.example`,
root-owned, mode 0600 - it holds the DB DSN with the password) and edit it:

```bash
sudo install -d -o root -g root -m 0755 /etc/rhorizon
sudo install -m 0600 examples/rhorizon.env.example /etc/rhorizon/rhorizon.env
sudoedit /etc/rhorizon/rhorizon.env        # set RH_DATABASE_URL password
```

The shipped example is sectioned and commented per option (defaults shown).
Minimal single-host set:

```ini
# DB
RH_DATABASE_URL=postgresql+asyncpg://rhorizon:CHANGE_ME_LONG_RANDOM@127.0.0.1:5432/rhorizon
RH_DATABASE_SSL=false

# Audit
RH_AUDIT_DIR=/var/log/rhorizon
RH_AUDIT_RETENTION_DAYS=365
RH_AUDIT_COMPRESS_DAYS=1

# Runtime/state
RH_RUNTIME_DIR=/run/rhorizon
RH_NODE_UUID_PATH=/var/lib/rhorizon/node-uuid
RH_CLUSTER_CERT_PATH=/var/lib/rhorizon/cluster-cert.pem
RH_CLUSTER_CERT_KEY_PATH=/var/lib/rhorizon/cluster-cert.key

# Auth fail log (fail2ban-ready)
RH_AUTHFAIL_LOG=/var/log/rhorizon/authfail.log

# Vault
RH_AUTO_SEAL_MINUTES=0
RH_DEK_KEY_MAX_AGE_DAYS=30

# Body limits
RH_MAX_BODY_BYTES=1048576
RH_MAX_BODY_BACKUP=104857600

# Trusted proxies (only meaningful if behind a reverse proxy)
RH_PROXY_TRUSTED_IPS=127.0.0.0/8,::1/128

# Metrics (Prometheus) - restrict to your monitoring host
RH_METRICS_ENABLED=true
RH_METRICS_ALLOWED_CIDRS=127.0.0.1/32

# Cluster - leave false for single-host install
RH_CLUSTER_HA_ENABLED=false
```

> **Never** expose rhorizon directly on a public IP. Bind it to localhost
> and put it behind VPN or a reverse proxy on a private VLAN
> (see `SECURITY.md` for the threat model).

---

## 6. systemd unit

Create `/etc/systemd/system/rhorizon.service` :

```ini
[Unit]
Description=Resurgamus Horizon - self-hosted secrets vault
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=exec
User=rhorizon
Group=rhorizon
WorkingDirectory=/opt/rhorizon/src
EnvironmentFile=/etc/rhorizon/rhorizon.env
ExecStart=/opt/rhorizon/venv/bin/uvicorn api.app.main:app \
    --host 127.0.0.1 --port 8200 \
    --workers 4 --no-access-log

# Restart policy
Restart=on-failure
RestartSec=5s
RuntimeDirectory=rhorizon
StateDirectory=rhorizon
LogsDirectory=rhorizon

#, Hardening (mirrors the docker-compose hardening) --
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rhorizon /var/log/rhorizon /run/rhorizon
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @reboot @swap @debug

# Memory protection : allow mlock for the Rust crypto extension
LimitMEMLOCK=infinity
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK

# Limits
TasksMax=50
MemoryMax=512M
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

Enable and start :

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rhorizon
sudo systemctl status rhorizon
sudo journalctl -u rhorizon -f
```

---

## 7. Verify

> **These commands are for the hand-rolled unit above, which serves plain
> HTTP and expects nginx (section 8) to terminate TLS in front.**
> `tools/install-native.sh` does not: it mints a self-signed certificate under
> `<config-dir>/certs`, passes it to uvicorn with
> `--ssl-certfile/--ssl-keyfile`, and the vault answers on **https** only. There
> add `--cacert <config-dir>/certs/cert.pem` to every curl below, or export
> `RH_CA_FILE` for the CLI.
>
> Whichever you run, the API logs a `PLAINTEXT TRANSPORT` warning for every
> authenticated call that arrives unencrypted - loopback included. If you
> terminate at nginx, the `X-Forwarded-Proto` header in section 8 is what
> tells the vault the client hop was in fact encrypted.

```bash
# Health check (no auth required)
curl http://127.0.0.1:8200/health

# Status (vault is sealed at first boot - expected)
curl http://127.0.0.1:8200/api/v1/vault/status
```

You should see `"sealed": true`.

The first unseal needs a master password. Use the CLI installed in the
same venv :

```bash
sudo -u rhorizon /opt/rhorizon/venv/bin/python -m rhorizon.main \
    --url http://127.0.0.1:8200 unseal
```

---

## 8. Frontend (optional)

If you want the SPA UI on the same host, point an nginx vhost at the
content of `frontend/` and proxy `/api/` to the API :

```nginx
server {
    listen 127.0.0.1:8443 ssl http2;
    ssl_certificate     /etc/rhorizon/tls/fullchain.pem;
    ssl_certificate_key /etc/rhorizon/tls/privkey.pem;

    root /opt/rhorizon/src/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:8200;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        # Required, not cosmetic: without it the vault sees a plain-HTTP hop
        # and logs a PLAINTEXT TRANSPORT warning for every authenticated call.
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Headers and CSP are already in `frontend/nginx.conf` - pick what you
need from there.

---

## 9. Hardening

The systemd unit above replicates most of the compose hardening
(`no-new-privileges`, capability drop, namespace restrictions, syscall
filtering). To approach parity :

- **read_only filesystem** : `ProtectSystem=strict` already makes `/usr`,
  `/boot`, `/etc`, and the application prefix read-only. Mutable state lives
  under the explicit `ReadWritePaths` entries only.
- **cap_drop: ALL** : `CapabilityBoundingSet=CAP_IPC_LOCK` keeps only
  the one capability the app actually needs.
- **mlock** : the installer sets `LimitMEMLOCK` to the exact budget
  `workers*160 + 256 + 192` MB (per-worker RSS + the 256 MB Argon2id
  unseal spike + headroom = **608 MB for 1 worker**) + `AmbientCapabilities=CAP_IPC_LOCK`,
  matching the app self-check `mem_hardening.required_memory_mb`.
  Measured on Rocky 10.2 (1 worker): peak locked during unseal
  **≈465 MB** (`VmLck`), steady ≈209 MB — comfortably under the 608 MB
  ceiling. PostgreSQL never `mlock`s (default 8 MB memlock, unused), so
  it does not compete for the budget.
- **noexec /tmp** : `PrivateTmp=true` already gives the process a private
  `/tmp` namespace ; add `tmpfs` mount with `noexec,nosuid` if you also
  manage the host mount setup.

### linux-hardened (Arch) specifics

- `kernel.unprivileged_userns_clone=0` is the default - irrelevant for
  rhorizon (we don't fork user namespaces).
- `kernel.kptr_restrict=2` - irrelevant.
- `mlock` works without extra tuning since systemd grants `CAP_IPC_LOCK`
  via the unit directives. If `journalctl` shows
  `Cannot allocate memory`, raise `LimitMEMLOCK` or check for a
  conflicting per-user limit in `/etc/security/limits.d/`.
- The multiworker RPC layer uses filesystem sockets under `/run/rhorizon/`
  (not the abstract namespace), so these knobs do not affect it.

### SELinux (Fedora / RHEL / Rocky / Alma)

The project ships a **confined SELinux policy module**,
`tools/selinux/rhorizon.te`, that runs the vault as its own domain
`rhorizon_t`. On a **system-mode** install the driver installs it
automatically — but **only when the host is actively enforcing**
(`getenforce` = `Enforcing`). A permissive or disabled host is left
completely untouched. The step is idempotent and safe to re-run.

Validated on **Rocky Linux 10.2** (kernel 6.12, Python 3.12): the
service unseals under `enforcing` with **zero AVC denials** and no
executable-memory grants (`execmem` / `execstack` / `execheap` /
`mmap_zero` are deliberately *not* in the policy — the Rust secure
allocator uses `PROT_NONE` guard pages, never W+X).

What the driver does under enforcing (`_rh_selinux_setup` in
`tools/drivers/linux.sh`):

1. Installs build tooling (`selinux-policy-devel checkpolicy
   policycoreutils-python-utils`) — pulled *only* on enforcing hosts.
2. Builds + loads the module: `make -f
   /usr/share/selinux/devel/Makefile rhorizon.pp` then
   `semodule -i rhorizon.pp`.
3. Labels the API port: `semanage port -a -t rhorizon_port_t -p tcp
   <port>` (default 8200; the stock port map has 8200 as
   `trivnet1_port_t`, so a dedicated type is used).
4. Applies file contexts, then `restorecon`. The specs are kept
   **disjoint** — a broad `WORKDIR(/.*)?` catch-all out-orders the
   `audit/` and `run/` rules under `restorecon`, so each path gets its
   own rule:

   | Path | Type | Access granted to `rhorizon_t` |
   |---|---|---|
   | `/opt/rhorizon/run-app.sh` | `rhorizon_exec_t` | entrypoint (domain transition) |
   | `/opt/rhorizon/.venv/` (native `.so`) + app `api/` | `rhorizon_var_lib_t` | read + execute + mmap, **no write** |
   | `/etc/rhorizon/` | `rhorizon_conf_t` | read only |
   | `/var/lib/rhorizon/` | `rhorizon_var_lib_t` | state files |
   | `/var/log/rhorizon/` | `rhorizon_log_t` | append (audit trail) |
   | `/run/rhorizon/` | `rhorizon_var_run_t` | pid + unix sockets |

The entrypoint is a **`run-app.sh` wrapper** the driver writes in
system mode: `python` is shared `bin_t` and can't be relabelled, so a
dedicated wrapper carries `rhorizon_exec_t` to trigger the transition.
The wrapper also sets `PYTHONDONTWRITEBYTECODE=1` (the app tree is
read-only under the policy, so `.pyc` writes would be denied).

**PostgreSQL under SELinux.** PG runs confined as `postgresql_t`;
tcp/5432 is `postgresql_port_t`. The policy grants `rhorizon_t`
`name_connect` on it (`corenet_tcp_connect_postgresql_port`). This is
*separate* from PG's own optional label MAC (`sepgsql`), which rhorizon
does not use; and separate from the `pg_hba` `ident`→`scram-sha-256`
loopback fix (a PG-auth matter the driver also applies). The booleans
`selinuxuser_postgresql_connect_enabled` / `postgresql_selinux_*` apply
to user domains and `sepgsql`, not to this daemon domain. Reference:
`man postgresql_selinux` (from `selinux-policy-doc`).

**Manual install / re-apply** (idempotent):

```bash
cd tools/selinux
make -f /usr/share/selinux/devel/Makefile rhorizon.pp
sudo semodule -i rhorizon.pp
sudo semanage port -a -t rhorizon_port_t -p tcp 8200 || \
sudo semanage port -m -t rhorizon_port_t -p tcp 8200
# label the app tree (WORKDIR = your --dir), then relabel:
sudo restorecon -RF "$WORKDIR"
```

If you extend the app and hit a new denial, harvest it — do **not**
fall back to `setenforce 0`:

```bash
sudo ausearch -m avc -ts recent | audit2allow   # inspect, then add to rhorizon.te
```

- **AppArmor** (Ubuntu/SUSE) : no profile ships with the project. The
  default unconfined profile is fine ; if your site policy requires a
  profile, base it on `/etc/apparmor.d/abstractions/python` and add
  `/etc/rhorizon/** r,`, `/var/lib/rhorizon/** rw,`,
  `/var/log/rhorizon/** rw,`, `/run/rhorizon/** rw,`, plus
  `/opt/rhorizon/venv/** mr,`.

---

## 10. Upgrade procedure

```bash
sudo systemctl stop rhorizon
sudo -u rhorizon -H bash <<'EOF'
cd /opt/rhorizon/src
git fetch --tags
git checkout vX.Y.Z          # or 'main' for latest
source /opt/rhorizon/venv/bin/activate
pip install --require-hashes -r api/requirements.txt
cd api/rust
maturin build --release --locked --strip
pip install --force-reinstall target/wheels/*.whl
EOF
sudo -u postgres psql -d rhorizon -f /opt/rhorizon/src/schema.sql
sudo systemctl start rhorizon
```

The vault re-seals on stop. The operator must unseal it after each
restart (this is the documented behaviour, not a bug - see SECURITY.md).

---

## 11. Backup

Whatever process you choose to back up `/var/lib/pgsql` (or the
distro-equivalent), include `/etc/rhorizon/`, `/var/lib/rhorizon/`, and
`/var/log/rhorizon/audit-*.jsonl*` so the audit chain and local node state are
preserved. Restic / rsync / `pg_dump` all work - the project's preferred tool is
Restic to a separate datacenter.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `rhorizon_crypto` import fails | wrong Python ABI | rebuild the wheel against the venv's `python3.12` |
| `mlock failed` in logs | `RLIMIT_MEMLOCK` too low | raise `LimitMEMLOCK` in the systemd unit |
| 503 on every API call | vault is sealed | run `unseal` |
| 401 with valid token after restart | vault was sealed and re-unsealed with a different password | rotate the token, fix the unseal flow |
| `connection refused` on Postgres | TLS mismatch | set `RH_DATABASE_SSL=false` for plain TCP, or fix `pg_hba.conf` |
| `address already in use` on port 8200 | previous worker still alive | `systemctl restart rhorizon`, then `ss -tlnp \| grep 8200` |
| audit chain `intact: false` | a row was hand-edited or a prior write crashed | `GET /api/v1/vault/audit/verify` shows the breakpoint ; restore from backup |

Open issues at the project's Gitea ; mention your distro + kernel +
output of `systemctl status rhorizon` and `journalctl -u rhorizon
--since '5 min ago'`.
