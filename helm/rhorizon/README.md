# rhorizon Helm chart

Self-hosted secrets vault on Kubernetes. PostgreSQL + FastAPI + libsodium
+ Rust memory protection. AGPL-3.0-or-later.

## Prepare (one-time, copies schema.sql into the chart)

```bash
cd helm
make prepare    # cp ../schema.sql rhorizon/schema.sql
```

The chart references `schema.sql` via `.Files.Get` ; without this copy
the in-chart PostgreSQL container has nothing to bootstrap from. The
copy step is intentionally explicit (no symlinks - they don't survive
`helm package` cleanly) and is wired into all the other Make targets.

## Quick install (with in-chart PostgreSQL)

```bash
helm install vault ./helm/rhorizon \
  --namespace rhorizon --create-namespace \
  --set image.api.repository=your-registry/rhorizon-api \
  --set image.api.tag=latest \
  --set image.frontend.repository=your-registry/rhorizon-frontend \
  --set image.frontend.tag=latest
```

After the pods are Ready, follow the instructions printed in `helm install`'s
NOTES output to perform the first `/unseal` and capture the root token.

## With managed PostgreSQL

The chart's `existingSecret` must hold the password under key `postgres-password`.
Two things differ from the in-chart PG and matter for a managed/HA backend:

- **`sslMode`** -- managed and Patroni PG almost always *require* TLS. Leave it
  at the default `require` (encrypt, no cert verify), or `verify-full` if you
  pin the DB CA. `disable` only works for a non-TLS PG. (Setting the wrong mode
  shows up as `pg_hba.conf rejects connection` at boot.)
- **`egressCidrs`** -- when `networkPolicy.enabled` (default) and your CNI
  enforces it (k3s, Calico, Cilium), the api needs an egress rule to reach the
  external DB. Leave empty to allow the DB port cluster-wide, or pin the DB
  CIDR(s).

```bash
kubectl -n rhorizon create secret generic my-pg-secret \
  --from-literal=postgres-password='your-managed-pg-password'

helm install vault ./helm/rhorizon \
  -n rhorizon --create-namespace \
  --set postgres.external.enabled=true \
  --set postgres.external.host=my-pg.internal \
  --set postgres.external.port=5432 \
  --set postgres.external.username=rhorizon \
  --set postgres.external.database=rhorizon \
  --set postgres.external.sslMode=require \
  --set postgres.external.existingSecret=my-pg-secret \
  --set image.api.repository=... \
  --set image.frontend.repository=...
```

### Patroni via the Zalando postgres-operator

A worked recipe for an in-cluster HA Postgres (validated on k3s + the
`make k8s-e2e RH_E2E_DB=patroni` path):

```bash
# 1. operator
helm repo add postgres-operator-charts \
  https://opensource.zalando.com/postgres-operator/charts/postgres-operator
helm install postgres-operator postgres-operator-charts/postgres-operator \
  -n rhorizon --create-namespace --wait

# 2. a 2-node Patroni cluster
kubectl -n rhorizon apply -f - <<'YAML'
apiVersion: acid.zalan.do/v1
kind: postgresql
metadata: { name: rhorizon-pg }
spec:
  teamId: rhorizon
  volume: { size: 2Gi }
  numberOfInstances: 2
  users: { rhorizon: [superuser, createdb] }
  databases: { rhorizon: rhorizon }
  postgresql: { version: "17" }
YAML

# 3. bridge the operator-managed password into the chart's secret shape
PW=$(kubectl -n rhorizon get secret \
  rhorizon.rhorizon-pg.credentials.postgresql.acid.zalan.do \
  -o jsonpath='{.data.password}' | base64 -d)
kubectl -n rhorizon create secret generic rhorizon-db \
  --from-literal=postgres-password="$PW"

# 4. install, pointing at the operator's master service (rhorizon-pg)
helm install vault ./helm/rhorizon -n rhorizon \
  --set postgres.external.enabled=true \
  --set postgres.external.host=rhorizon-pg \
  --set postgres.external.sslMode=require \
  --set postgres.external.existingSecret=rhorizon-db \
  --set image.api.repository=... --set image.frontend.repository=...
```

The operator rotates the password from *its* secret, so if you re-run a cluster
reform, re-bridge step 3 before the next api restart.

## Building images

The chart does not ship images. Build them once from the repo root :

```bash
docker build -t your-registry/rhorizon-api:1.0.0 -f api/Dockerfile .
docker build -t your-registry/rhorizon-frontend:1.0.0 -f frontend/Dockerfile frontend
docker push your-registry/rhorizon-api:1.0.0
docker push your-registry/rhorizon-frontend:1.0.0
```

Then point the chart at those tags via `--set image.{api,frontend}.{repository,tag}`.

## Values reference

See [`values.yaml`](values.yaml) - every key is documented inline.

Highlights :

| Key | Default | Notes |
|-----|---------|-------|
| `api.replicas` | 1 | Pods. Each pod is already a 5-worker cluster; 2+ = cross-pod HA (needs `clusterEnabled`) |
| `api.clusterEnabled` | false | Cross-pod (multi-replica) HA. The in-pod multi-worker mesh is always on, independent of this |
| `api.workers` | 5 | uvicorn workers/pod; the image boot wrapper floors this to 5 (Shamir quorum) |
| `api.memoryLockMode` | best-effort | Continue with reported buffer/process degradation; `required` fails closed while swap is exposed |
| `api.requestIpcLockCapability` | false | Add `IPC_LOCK` to the API container when cluster admission policy permits it |
| `api.swapProtection` | unknown | Node swap state; set `protected` only when every eligible node has encrypted swap, zram, or no swap |
| `postgres.external.enabled` | false | Set true to point at managed/Patroni PG |
| `postgres.external.sslMode` | require | `disable\|require\|verify-full` for the external DB |
| `postgres.external.egressCidrs` | [] | NetworkPolicy egress for the external DB; empty = cluster-wide on the DB port |
| `postgres.storage.size` | 10Gi | In-chart PVC size |
| `ingress.enabled` | false | Optional Ingress for frontend |
| `networkPolicy.enabled` | true | Egress lockdown (PG + DNS only) |
| `pdb.api.enabled` | false | Enable when running 2+ replicas |

## Security defaults

The chart applies the following hardening by default:

- API runs as non-root uid 1500 with a read-only root filesystem and all
  capabilities dropped. Secret buffers are always wiped on release.
- Frontend runs nginx with `cap_drop: ALL` + `NET_BIND_SERVICE`/`CHOWN`/`SETUID`/`SETGID`,
  read-only root, dedicated tmpfs for cache/run/conf.
- ServiceAccount `automountServiceAccountToken: false` (no in-pod kube API).
- NetworkPolicy egress restricted to PostgreSQL and CoreDNS only.
- Liveness + readiness probes on `/health` (API) and `/` (frontend).

The default chart is accepted by Baseline and Restricted capability policy:
it does not request `IPC_LOCK`. The API starts in best-effort mode and reports
the effective state through `/api/v1/vault/status`, the Web UI, and
`rhorizon status`. A `zeroize-only` state needs action only when node swap is
unencrypted or cannot be verified. On such a cluster that permits `IPC_LOCK`,
enable locked memory:

```bash
helm upgrade --install vault ./helm/rhorizon \
  --set api.requestIpcLockCapability=true
```

Use `--set api.memoryLockMode=required` as well only when inability to lock
memory must prevent the API from serving.

## End-to-end test

`tools/k8s-e2e.sh` (`make k8s-e2e` from the repo root) spins a throwaway k3d
cluster, builds + loads the images, helm-installs this chart, unseals, and
asserts api + frontend Ready and the multi-worker cluster forms. It's the
deploy regression gate, wired into CI (`.woodpecker/e2e.yml`) on changes to
`helm/`, `api/`, `frontend/`, `schema.sql`.

```bash
make k8s-e2e                    # in-chart Postgres (fast)
make k8s-e2e RH_E2E_DB=patroni  # external Patroni via the Zalando operator
```

## Roadmap

- Built-in Job for first-boot `/unseal` (currently manual)
- HPA (currently fixed replicas)
- ESO `SecretStore` example for in-cluster consumers
