# rhorizon Helm chart

Lightweight self-hosted secrets manager and vault on Kubernetes, for automation,
CI/CD and AI/MCP agents. PostgreSQL + FastAPI + libsodium
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

## Application HA install

Application HA uses an API StatefulSet. Each Pod has its own
`/var/lib/rhorizon` PVC because a node UUID and its mTLS private key must never
move between replicas. Increasing `api.replicas` without enabling and
bootstrapping the cluster is not an HA installation.

Prepare:

- a highly available PostgreSQL write endpoint;
- a `kubernetes.io/tls` Secret for the frontend HTTPS listener;
- a certificate whose SAN covers the hostname in `api.haPrimaryUrl`;
- the frontend Pod CIDR for `api.proxyTrustedIps`;
- when the HTTPS certificate uses private PKI, a Secret containing its CA.

The TLS Secret remains deployment-managed (cert-manager, public PKI or your
private issuer). Horizon independently renews each node's mTLS identity; it
does not attempt to rewrite a read-only Kubernetes Secret.

Install the first Pod only:

```bash
helm upgrade --install vault ./helm/rhorizon -n rhorizon --create-namespace \
  --set api.clusterEnabled=true \
  --set api.replicas=1 \
  --set api.proxyTrustedIps=10.42.0.0/16 \
  --set api.haPrimaryUrl=https://vault-rhorizon-frontend.rhorizon.svc:8443 \
  --set frontend.tls.secretName=rhorizon-frontend-tls \
  --set api.haServerCaSecretName=rhorizon-frontend-ca \
  --set image.api.repository=... --set image.frontend.repository=...
```

Unseal it, run `rhorizon cluster init`, decode the returned one-time
`ha_password` to its raw 32 bytes, and create a temporary Secret:

```bash
kubectl -n rhorizon create secret generic rhorizon-ha-join \
  --from-file=ha-password=./ha_password.raw

helm upgrade vault ./helm/rhorizon -n rhorizon --reuse-values \
  --set api.replicas=3 \
  --set api.haAutoJoin=true \
  --set api.haPasswordSecretName=rhorizon-ha-join
```

After all Pods are `secondary` or `primary`, run
`rhorizon cluster preflight`. Then remove the bootstrap Secret and its mount;
steady state and certificate renewal use mTLS:

```bash
helm upgrade vault ./helm/rhorizon -n rhorizon --reuse-values \
  --set api.haAutoJoin=false --set-string api.haPasswordSecretName=
kubectl -n rhorizon delete secret rhorizon-ha-join
```

The command validates the PVC declaration, proxy trust, certificates, health,
custodian convergence, signed audit anchor and the live HTTPS/mTLS path.

### Upgrade from the former API Deployment

The chart now uses an API StatefulSet so each replica keeps a distinct node
UUID and mTLS key on its own PVC. The former chart used an `emptyDir`, so its
identity cannot survive Pod replacement unless the operator supplied storage
outside the chart. Before upgrading, take a database backup and scale the old
API Deployment to zero; do not let it run beside the new StatefulSet. Treat
the first StatefulSet Pod as a new node: unseal it, JOIN it to the existing
cluster (or initialise it for a standalone vault), then evict the obsolete
membership row. Follow the HA sequence above for additional Pods and run the
live preflight before restoring traffic.

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
| `api.persistence.enabled` | true | Per-Pod identity PVC; mandatory for application HA |
| `api.maxConcurrentRequests` | 0 | Per-worker in-flight cap; set a measured non-zero limit for production admission control |
| `api.proxyTrustedIps` | empty | Exact frontend Pod CIDR(s) allowed to forward mTLS identity |
| `api.haPrimaryUrl` | empty | Stable internal HTTPS URL used by JOIN, renewal and live preflight |
| `api.haServerCaSecretName` | empty | Optional private CA for the internal HTTPS URL; public PKI needs none |
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

Application HA has a separate gate. It performs the documented one-Pod
bootstrap, scales to three Pods using the temporary raw HA-password Secret,
waits for mTLS JOIN, runs the live preflight, removes the Secret, replaces a
secondary and then the primary, and requires bounded automatic failover.

```bash
make k8s-e2e                    # in-chart Postgres (fast)
make k8s-e2e RH_E2E_DB=patroni  # external Patroni via the Zalando operator
make k8s-ha-e2e                 # three-Pod application HA and failover
```
