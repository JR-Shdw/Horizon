# Ship validation

The compatibility matrix ([COMPATIBILITY.md](COMPATIBILITY.md)) is the trust
gate. Before a release, every row claimed **Tested** must carry fresh evidence
from this run; any row that cannot be proven is honestly downgraded to
Supported / Experimental rather than shipped on faith.

Scope of this run: all **Tested** rows + the integration lane (LDAP, SSO proxy,
Matrix, Prometheus/Grafana, MySQL/MariaDB) + **promotion candidates**: NetBSD
(Experimental) and Rocky/RHEL + openSUSE (Supported), each run at full suite on
target and upgraded to Tested if green. No OS is left at smoke-only, a trust
gate validates the same code path on every Linux distro it ships an installer
for. macOS native and Windows stay out of scope and keep their Planned /
Supported labels.

## Re-baseline note

The pre-ship cleanup that preceded this run changed only comments, docstrings,
and documentation, it was verified to leave the executable token stream of
every source file byte-identical (no logic, identifier, or control-flow change).
So functional revalidation is a re-run of the existing suite on the ship commit,
not a behavioural re-test. The matrix work below proves the *deployment and
integration* surface on top of that.

## Pass-gate per item

Each item lists: how it is validated, the environment class, and the gate that
must pass. Evidence (CI run id, Ansible log, screenshot, suite output) is
recorded in the sign-off table at the bottom.

### Lane 0, functional re-baseline

| Item | Validation | Gate |
|---|---|---|
| Test suite | `pytest` full suite on the ship commit | 0 failures; coverage at or above the recorded baseline |
| Rust crate | `cargo test` + `cargo +nightly miri test` + the constant-time asm gate | all green |
| CI | Woodpecker `validate.yml` on the ship commit | all stages green |
| Reproducibility | agent + wheel byte-reproducible build | digests match |

### Lane 1, operating systems and init (lab VMs)

| Row | Validation | Gate |
|---|---|---|
| Debian / Ubuntu | provision VM, run `install-debian.sh` / `install-ubuntu.sh`, boot, unseal, smoke | service up, vault unseals, secret round-trips |
| Arch Linux | same via `install-arch.sh` | same |
| FreeBSD 14.x | re-run `tools/test-vm.sh freebsd` (full suite) | suite green on target |
| OpenBSD 7.x | re-run `tools/test-vm.sh openbsd` | suite green on target |
| NetBSD (promote from Experimental) | provision a NetBSD VM, add a `netbsd` target to `tools/test-vm.sh` (rc.d service, pkgin deps), run the suite | suite green -> upgrade matrix to Supported/Tested; otherwise keep Experimental with the failure noted |
| systemd unit | native install path, `systemctl` lifecycle (start/seal/stop) | unit healthy, sealed-on-restart honoured |
| BSD `rc.d` | BSD VM service script lifecycle | service managed, sealed-on-restart honoured |
| Rocky / RHEL (promote from Supported) | `install-rocky.sh`, then the full suite **twice**: SELinux `permissive` then `enforcing` (collect `ausearch`/AVC denials in both) | permissive green = code is fine; enforcing green = ships clean -> Tested. Permissive-pass + enforcing-fail = isolated to policy: capture the AVCs, ship a relabel/policy step (documented), keep Supported until that lands. Permissive-fail = real bug. |
| openSUSE (promote from Supported) | `install-opensuse.sh`, then the full suite **twice**: AppArmor disabled then enabled | same diagnosis logic: both green -> Tested; enabled-only failure -> documented profile fix, not a blocker; disabled-fail = real bug. Watch libsodium/openssl/Python version deltas. |

### Lane 2, containers and orchestration

| Row | Validation | Gate |
|---|---|---|
| Docker / Compose | hardened compose up, healthcheck, unseal, secret round-trip | stack healthy, hardening flags present |
| Podman (rootless) | rootless deploy honouring the documented limits (host networking, cgroupfs, no <1024 bind); `RLIMIT_MEMLOCK` raised | mlock locked=true, unseal + round-trip OK |
| Kubernetes / k3s | Helm install on a single-node k3s; `rh-fetch` init-container sidecar | pod ready, secret rendered to tmpfs 0400 |

### Lane 3, datastore and HA "full max"

| Row | Validation | Gate |
|---|---|---|
| PostgreSQL 18 | single-node stack on PG18 | boots, `ssl_groups` negotiated |
| PostgreSQL HA | 3-node cluster (Patroni + etcd + HAProxy + keepalived VIP); kill-primary failover | VIP follows new primary, vault stays unsealed, no data loss |
| Max-load | sustained read load to the single-node ceiling on a rootless host + the HA cluster | throughput matches the recorded ceiling; no errors under load |

### Lane 4, operator auth and integrations

| Row | Validation | Gate |
|---|---|---|
| Master password (Argon2id) | unseal | derives, unseals |
| TOTP | enrol + unseal with code | accepted; replay rejected |
| LDAP / AD bind | `test_dynamic_ldap_real` + login against the lab directory | bind + group mapping OK |
| Dynamic secrets: PostgreSQL | issue + lease + auto-revoke | role created, dropped at TTL |
| Dynamic secrets: LDAP | issue against the lab directory | entry added, removed at TTL |
| Dynamic secrets: MySQL/MariaDB | with `aiomysql` + a MySQL instance | role created, dropped at TTL |
| Dynamic secrets: Redis | Redis 6+ ACL over TLS; mint, authenticate, revoke, deny | pending live validation |
| Dynamic secrets: Cassandra | TLS role-auth cluster; mint, authenticate, revoke, deny | pending live validation |
| Ansible dynamic collection | build collection; protected block + always revoke against a live engine | pending live validation |
| SSO proxy headers | header auth via an Authelia / Authentik / Keycloak front | session token minted from trusted headers only |
| Matrix notify | channel test-send | message delivered |
| Prometheus / Grafana | scrape `/metrics`, load the dashboards | series present, panels render |

### Lane 5, hardware / browser (operator-run, out of automated lanes)

| Row | Validation | Gate |
|---|---|---|
| YubiKey HMAC-SHA1 | physical challenge-response unseal | accepted |
| WebAuthn / FIDO2 | browser registration + auth | accepted |

## Sign-off table

Filled as each item lands. Ship only when every **Tested** row is green or has
been downgraded with a note.

| Lane | Item | Status | Evidence |
|---|---|---|---|
| 0 | suite + CT asm-gate + clippy (local) | green | 1754 passed / 2 skipped on PG18 (node-5 local, 2026-06-19); clippy clean |
| 0 | cargo test / miri / reproducible build / CI | CI | runs in Woodpecker `validate.yml` on every push |
| 1 | Debian / Ubuntu | **green** | full suite 1754 passed, both VMs (node-5 local, 2026-06-19) |
| 1 | Arch | **green** | full suite 1754 passed (node-5 local, 2026-06-19) |
| 1 | FreeBSD | **green** | 1753 passed after the memlock login-class fix (node-5 local, 2026-06-19) |
| 1 | OpenBSD | **green** | **1753 passed** on 7.8 VM, HA cluster mTLS included. Golden via `-no-reboot`; `install-openbsd.sh` builds CPython from source against the OpenSSL port (eopenssl36) so the Ed25519 cluster certs load (base LibreSSL's CPython ssl can't). |
| 1 | NetBSD (promote) | **green** | 1752 passed (node-5 local, 2026-06-19). Chain of harness bugs fixed: tar-push (golden has no rsync) + unpinned deps + cdn.netbsd.org down -> swapped PKG_PATH to ftp.fr.netbsd.org. No source compile needed. |
| 1 | systemd / rc.d | covered | exercised inside each OS VM run; fresh Debian 13 system and Ubuntu 24.04 user installs both built, started, unsealed, and returned healthy on 2026-08-02 |
| 1 | Rocky / RHEL (SELinux, promote) | **green** | full suite 1754 passed in Rocky 9 VM, SELinux enforcing (node-5 local, 2026-06-19) |
| 1 | openSUSE (promote) | **green** | full suite 1754 passed in openSUSE Leap 15.6 VM, AppArmor default (node-5 local, 2026-06-19) |
| 2 | Docker / Compose | partial | `validate.yml` compose-check in CI; the hardened stack runs as the deployed instance |
| 2 | Podman rootless | green | Fresh `tools/install-container.sh` run built current images, started, unsealed, and returned healthy on 2026-08-02. Portable mode reported buffers `mlock`, process `swappable`, swap `unencrypted`; the explicit `required` override then failed closed because the rootless runtime kept `RLIMIT_MEMLOCK=8MB`. |
| 2 | k3s + rh-fetch | pending (lab) | needs the lab k3s; ready-made battery `eso-provider/test-live/b2_rhfetch_real.sh` (export `RH_TOK` + `KUBECONFIG`). NB: local agent `cargo build` needs `cmake` (aws-lc-sys), present in CI, not on node-5 |
| 3 | PG18 single | **green** | every OS suite runs on PG18 (1752-1754 passed x 8 OSes) |
| 3 | PG HA + API failover | manual lab | 2026-07-13 lab run covered API node loss, 3 -> 2 -> 1 convergence, single-survivor promotion, readiness, secret write/read, audit verify, Merkle tamper/recovery, and worker coverage. Repeat with `tools/chaos/k7_random_ha_24h.sh` for 24h API chaos/load evidence; Patroni leader-loss battery still needed before marking green. |
| 3 | max-load | pending (lab) | bench on the HA cluster; use K7 `CHAOS_LOAD_PROFILE=high` for the 24h HA load/chaos run |
| 4 | TOTP | **green** | enrol + unseal in-suite (8 VMs) |
| 4 | LDAP bind + dynamic | **green** | live on a deployed lldap (node-5, 2026-06-19): bind-auth -> scoped token, wrong password denied; + dynamic LDAP |
| 4 | dynamic PG / MySQL / MariaDB | **green** | dynamic PG every OS suite; MySQL+MariaDB full lifecycle (mint->login->revoke->deny) on live servers via aiomysql (node-5, 2026-06-19) |
| 4 | SSO proxy | covered | `test_proxy_auth` + `test_auth_proxy_coverage` on 8 VMs (trusted-header logic; no live SSO front exercised) |
| 4 | notify (Matrix / webhook / email) | **green** | Matrix (suite); webhook SSRF-guard + delivery; email real delivery to mailhog (node-5, 2026-06-19) |
| 4 | Prometheus / Grafana | **green** | `/metrics` scraped; dashboards captured against a live instance |
| 5 | YubiKey | **green** | real YK5 NFC: hardware HMAC-SHA1 response verified by `crypto.verify_yubikey_response()`, negative control rejected (node-5 local, 2026-06-19) |
| 5 | WebAuthn | pending (browser) | needs a browser touch-to-auth (UI register + unseal) |

## Findings & fixes - 2026-06-19 ship run (node-5, local KVM)

Running the OS lanes for real surfaced a chain of genuine bugs - almost all
harness/infra, one real deployment bug. All resolved:

| Area | Symptom | Root cause | Fix |
|---|---|---|---|
| **FreeBSD: vault can't unseal** (real deploy bug) | 22 failed / 189 errors, all `WrapKey()/...: mlock failed` | Rust crypto mlocks key material; the non-root user's hard `RLIMIT_MEMLOCK` is capped by `login.conf` (`ulimit -l` can't raise it; `unprivileged_mlock` already 1). | `install-freebsd.sh`: add an `rhorizon-vault` login class (`memorylocked=unlimited`, `cap_mkdb`). Re-run **1753 passed**. Linux gets this via the unit's `LimitMEMLOCK`. |
| **NetBSD: chain of 4 harness bugs** | rsync-not-found -> no deps -> "no pkg found" -> mirror 000 | golden has no rsync; pinned pkgsrc versions go stale (mirror keeps latest only); scripts used `https` on an HTTP-only CDN; then **cdn.netbsd.org was down**. | `test-vm.sh` tar-over-ssh push; **unpin** deps; `http://`; swap `PKG_PATH` to **`ftp.fr.netbsd.org`**. Re-run **1752 passed**. No source compile needed. |
| **OpenBSD: golden build hangs** | qemu never exits, VM at `login:` | Autoinstall reboots into the installed disk instead of halting. | `openbsd-bootstrap.sh`: qemu **`-no-reboot`**. |
| **OpenBSD: HA cluster mTLS fails** | 5 failed: `ssl.SSLError: UNKNOWN_CERTIFICATE_TYPE` | Base **LibreSSL**'s CPython `ssl` can't load the **Ed25519** TLS certs the cluster CA mints. | `install-openbsd.sh`: **build CPython 3.12 from source against the OpenSSL port** (eopenssl36, via aliased pkg-config) + cryptography against the same OpenSSL. Ed25519 kept. (Plus a test-only `CA:TRUE` fix for one db-ssl fixture LibreSSL's `openssl` CLI didn't flag.) |
| **OpenBSD: pkg_add truncates mid-batch** (recurring, 2026-06-24) | `Premature end of archive` on a cdn tarball -> batch aborts, postgresql uninstalled -> cryptic `install: unknown group _postgresql` (the old `pkg_add ... \|\| true` masked it). | `install-openbsd.sh`: **retry the batch 3x + hard-verify the `_postgresql` group**, fail loud + specific. Bypass: `export PKG_PATH` to a healthier mirror. Same family as the NetBSD rsync `\|\| true` bug - a transient must be retried+verified in-script, not re-run by hand. |

`tools/install-macos.sh` was an untested skeleton at the time of this run --
node-5 has no Apple hardware. It **has since been validated on `macos-latest`**
(`.github/workflows/macos-native.yml`), which runs it end to end in user mode:
Homebrew deps, PostgreSQL, venv, the Rust extension (built, imported, and AEAD
round-tripped -- a wheel that links but computes wrongly on another arch is
worse than one that fails to load), the LaunchAgent, and first unseal.

Apple Silicon only. Intel darwin stays unmeasured: GitHub retired the
`macos-13` image and a job pinned to it now queues indefinitely rather than
failing, so there is no free x86_64 lane to move to.

Gotchas for re-runs on node-5: ports `2222` (forgejo) / `5433` are taken - pass
`SSH_PORT=`/`PG_PORT=`. `/tmp` is RAM-backed tmpfs (clean workdirs as you go).
`VM_RAM=8G VM_CPUS=8` to run lanes in parallel. OpenBSD's small `/` and `/tmp`
partitions need build scratch routed to `/home`.

## Ship criteria

- Lane 0 fully green (functional gate).
- Every matrix **Tested** row in lanes 1-5 green, or relabelled with a one-line
  reason in COMPATIBILITY.md.
- Integration lane green for the paths an adopter is most likely to hit first
  (LDAP, Prometheus, at least one SSO front, Matrix).

## Operator-run lanes (lab / hardware - not runnable from the headless host)

The 8/8 OS sweep + Lane 0 + Podman + YubiKey are done locally. Four lanes need
the lab cluster, real services, or a browser - each is ready to run; tick them
off before publishing.

### Lane 2 - k3s agent e2e (rh-fetch / rh-watch / ESO)
Proves the secret-delivery agents render secrets into pods.
- **Prereqs**: lab k3s reachable (`kubectl` + `KUBECONFIG`); vault reachable
  from pods (`RH_ADDR`); agent image `ghcr.io/jr-shdw/rhorizon-agent:latest`
  pullable; master token `RH_TOK` with `tokens:rw`+`secrets:rw` on the test
  namespaces. (A local agent rebuild also needs `cmake` for aws-lc-sys.)
- **Run**:
  ```sh
  export RH_TOK='rh_...'; export KUBECONFIG=~/dev/k3s/kubeconfig
  bash eso-provider/test-live/b1_api_conformance.sh   # 20
  bash eso-provider/test-live/b2_rhfetch_real.sh      #  9
  bash eso-provider/test-live/b3_rhwatch_rotation.sh  #  5
  bash eso-provider/test-live/b4_eso_contract.sh      # 11
  ```
- **Pass**: `PASS=45 FAIL=0`.

### Lane 3 - PostgreSQL / API HA failover
Manual lab coverage exists for API node loss and single-survivor promotion.
The repeatable lane below proves rhorizon survives a Patroni leader loss.
- **Prereqs**: lab Patroni cluster up (3x PG18 + etcd + HAProxy + keepalived
  VIP); rhorizon pointed at the VIP.
- **Run**: kill the Patroni leader (or `patronictl switchover`), watch a replica
  promote, confirm rhorizon keeps serving reads and the audit chain stays
  intact. Observe `rhorizon cluster status` / `GET /cluster/ha` + the new
  `rhorizon-ha-cluster` Grafana dashboard (`pg_up` / leader / lag).
- **Detail**: `docs/HA-RUNBOOK.md` (section 0 PG-HA layer), `docs/HA-CLUSTER.md`.

### Lane 4 - external integration (LDAP / Matrix / SSO / dynamic)
The real-service tests skip without endpoints; point them at the lab.
- **LDAP bind + dynamic LDAP**: `RH_LLDAP_URL=ldap://<lldap>` ->
  `test_dynamic_ldap_real`, `test_ldap`.
- **Dynamic PG / MySQL**: a target DB + engine config (MySQL needs `aiomysql`).
- **SSO proxy**: Authelia/Authentik in front, `Remote-User`/`Remote-Groups`.
- **Matrix notify**: bot token + room -> `POST /channels/{id}/test`.
- Prometheus/Grafana already green (dashboards captured).

### Lane 5 - WebAuthn (browser)
- In the UI (HTTPS or `localhost`): register a security key
  (`/webauthn/register/begin`->`complete`), set 2FA mode to `yubikey`/`any`,
  then unseal with a touch. (YubiKey HMAC-SHA1 is already hardware-validated.)

Tick these four and the matrix is ship-verified end to end.
