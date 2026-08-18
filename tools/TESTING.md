# Local testing tiers

Three tiers, because the full surface (8-OS VM matrix + arm64 + k8s + multi-node
HA) cannot run on every save. Pick the tier that matches the feedback you need.

> **Full coverage & where each tier runs (canonical):** the complete matrix —
> 8-OS VMs (FreeBSD / OpenBSD / NetBSD + Debian / Ubuntu / Rocky / openSUSE /
> Arch), arm64/aarch64 (`.woodpecker/arch-matrix.yml`), clustering/HA, and which
> node runs what (dev box / `node-1` CI runner / proxmox v9 cluster) — is
> documented in sextant: `rhorizon/shared/test-matrix.md`.

| Tier | Command | Runtime | Scope |
|---|---|---|---|
| **T0 watch** | `make watch` | seconds | On every save: ruff + the affected tests (`*.py` -> pytest, `*.rs` -> cargo test) |
| **T1 verify** | `make verify-local` | minutes | Full pytest + `rust-check-fast` + k8s smoke. Pre-push gate. |
| **T2 matrix** | `make test-matrix` | 30+ min | OS VM matrix (`tools/test-vm.sh`, 8 OSes) + arm64 + k8s smoke. On-demand. |

## T0 — watch (the "test on every modification" loop)

```
make watch
```

Starts an ephemeral test PG once, then watches `api/app`, `cli`, `tests`, and
`api/rust/src`. On each save it runs only what's relevant to the changed file
(`tools/watch_tests.py` maps `api/app/pki_ca.py` -> `tests/test_pki*`, etc.; an
unmapped change falls back to a fast smoke set). Ctrl-C stops it and tears the
PG down. Zero extra deps (uses `watchfiles`, already in the venv).

## Test PG port

The local test DB defaults to **55434** (`RH_TEST_PG_PORT`), not 5434, to avoid
colliding with a forgejo Postgres on the dev host. Override:
`RH_TEST_PG_PORT=5440 make test`.

`make test-matrix` gives each OS a distinct host-forward: `SSH_PORT`+N (base
2222) and `PG_PORT`+N (base 5433), N=1..8, so consecutive OSes can't collide on
a still-releasing qemu's port. If the base range is occupied (qemu fails fast
with `Could not set up host forwarding rule`), move the base:
`SSH_PORT=12230 PG_PORT=15430 make test-matrix`.

## k8s tier (k3d)

```
make k8s-setup     # once: install k3d v5.9.0 (ansible, pinned + sha256-verified)
make k8s-test      # FAST: k3d + server-side validate/apply k8s/ manifests (dry-run)
make k8s-e2e       # FULL: build+load images -> helm install -> unseal -> assert cluster
```

`k8s-test` is image-free (manifests validated against a real API server via
`--dry-run=server`). `k8s-e2e` is the image-loaded deploy e2e: builds the
api+frontend images, helm-installs the chart, unseals, and asserts the stack
serves + the multi-worker cluster forms. `RH_E2E_DB=patroni` additionally
exercises the external Patroni path (Zalando operator) -- see the chart README.

**Requires a reachable Docker API.** k3d/k3s need a Docker daemon (or a
rootless-podman socket via `DOCKER_HOST` + cgroup delegation). On a
rootless-podman host without user-systemd (e.g. **node-5**) there is no usable
socket and k3s will not start, so `make k8s-test` fails fast with guidance --
run this tier on a Docker-capable host or rely on the CI k8s job. The other
tiers (T0/T1 unit, T2 OS matrix) do not need Docker.

## Deploy e2e -- retest after a major change

Two image-loaded checks codify the manual deploy validation so it re-runs
automatically:

| Command | Asserts | Needs |
|---|---|---|
| `make native-smoke` | bare `uvicorn --workers 5` unseals + forms 1 master + 4 followers (the native install path) | container runtime (throwaway PG) + venv |
| `make k8s-e2e` | the Helm chart deploys + unseals + clusters on k3d | k3d + kubectl + helm + docker |
| `make retest` | both (each skips cleanly where its runtime is absent) | -- |

`make retest` is the target CI calls. `.woodpecker/e2e.yml` runs it on
pushes/PRs touching `helm/`, `api/`, `frontend/`, `schema.sql` -- the paths
that can break a deploy -- so the heavy k3d run skips docs/test-only commits.

## Cluster (HA)

Cluster *logic* (multi-worker, RPC, failover, mTLS) is covered locally by
`test_cluster*` / `test_ha_*` in T0/T1. Full **multi-node** HA runs on the
proxmox lab via the separate `rhorizon_ha` project (`make up` + the S1-S6 /
chaos suites -- see `~/dev/rhorizon_ha/RUNBOOK.md`); it is not part of the
on-save loop. After a reboot or reform, `make reverify` there unseals all
nodes and asserts `/cluster/ha` membership (3 fresh members, primary, no
quarantine).

## Cross-arch (arm64)

`validate.yml` runs the Rust crypto on **amd64** for each validation build.
`.woodpecker/arch-matrix.yml` runs the same suite on aarch64 on its weekly
schedule and on manual trigger; `tools/test-arm64.sh` is the local equivalent.
Both run
(`cargo test --release --locked --no-default-features`: NIST ACVP KATs for
AES-256-GCM / ML-DSA-65 / HMAC, Shamir GF(256) + AES-GCM property tests,
Argon2id / XChaCha20 / HKDF / Ed25519) inside an aarch64 container via QEMU.

```bash
# one-time: register aarch64 emulation (F flag, for rootless)
sudo podman run --rm --privileged docker.io/tonistiigi/binfmt --install arm64
tools/test-arm64.sh          # ~30-70 min emulated ; 0 pass / 1 fail / 2 skip
```

Last recorded run: **136/136 pass on aarch64** (2026-07-04). The KATs verify
the expected outputs for the covered algorithms on the emulated aarch64 build.
QEMU does not establish behavior of hardware-specific acceleration paths;
those require a native hardware lane. CI equivalent:
`.woodpecker/arch-matrix.yml` (weekly cron + manual).

This is functional and conformance coverage. The separate
`tools/check-gf-ct.sh` release-assembly branch gate is x86_64-specific; see
[`docs/SIDE-CHANNELS.md`](../docs/SIDE-CHANNELS.md).

**Full stack on arm64.** `tools/test-arm64-stack.sh` goes further: it builds the
api + frontend images for aarch64, pulls `postgres:18` arm64, brings the stack
up in a pod, unseals, and round-trips a secret. Verified 2026-07-04: **pg18 +
api + Rust crypto run on aarch64** (unseal OK, `memory_protection: mlock`, secret
round-trip OK); frontend nginx arm64 builds + runs. `.dockerignore` must exclude
`**/target/` or a host-arch wheel leaks into the emulated build and pip refuses
it.

**Agent crate: multi-arch.** The agent (`agent/rust`, rh-fetch/inject/watch)
pins `aws-lc-rs` for post-quantum TLS (X25519MLKEM768) -- ring does not offer it,
so the provider is not swappable without losing PQ. It builds for arm64 (incl.
under QEMU) via aws-lc-sys's **pre-generated bindings** (`aws-lc-rs` without the
`bindgen` feature); bindgen's libclang was the only thing that panicked under
emulation. PQ TLS is verified at the wire by `tools/pq-verify.sh` (OpenSSL >= 3.5
+ the agent's own aws-lc-rs stack both negotiate X25519MLKEM768).

## CI parity

These tiers mirror the Woodpecker pipelines (`.woodpecker/validate.yml` =
T0+T1 surface, the BSD VM + scan jobs = T2). Run T1 before pushing to catch
what CI would reject.
