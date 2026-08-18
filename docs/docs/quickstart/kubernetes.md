# Kubernetes - Helm

The chart at `helm/rhorizon/` deploys rhorizon on any Kubernetes
cluster. Defaults render 11 resources and bring up an in-chart
PostgreSQL StatefulSet ; production knobs let you point at a
managed PG, enable Ingress + TLS, configure NetworkPolicies, and
opt into multi-replica clustering.

## Prerequisites

- Kubernetes 1.24+
- Helm 3
- A container registry where you can push the rhorizon images
- (Optional) cert-manager for ingress TLS
- (Optional) an Ingress controller (nginx, traefik)

## Build & push the images

The chart does not ship images - there is no public registry yet.
Build locally and push to your own :

```bash
cd path/to/rhorizon

docker build -t your-registry.example.com/rhorizon-api:1.0.0 \
  -f api/Dockerfile .
docker build -t your-registry.example.com/rhorizon-frontend:1.0.0 \
  -f frontend/Dockerfile frontend
docker push your-registry.example.com/rhorizon-api:1.0.0
docker push your-registry.example.com/rhorizon-frontend:1.0.0
```

## Prepare the chart

The chart references `schema.sql` via `.Files.Get`. Copy it into the
chart directory before `helm install` :

```bash
cd helm
make prepare    # cp ../schema.sql rhorizon/schema.sql
```

This is a one-time step ; `make lint`, `make template`, and
`make package` all depend on it.

## Install - in-chart PostgreSQL

```bash
helm install vault ./rhorizon \
  --namespace rhorizon --create-namespace \
  --set image.api.repository=your-registry.example.com/rhorizon-api \
  --set image.api.tag=1.0.0 \
  --set image.frontend.repository=your-registry.example.com/rhorizon-frontend \
  --set image.frontend.tag=1.0.0
```

The chart renders :

| Resource | Name | Why |
|----------|------|-----|
| ServiceAccount | `vault-rhorizon` | API + frontend pods, no kube-API token |
| Secret | `vault-rhorizon-postgres` | PG password, stable across upgrades |
| ConfigMap | `vault-rhorizon-schema` | `schema.sql` for first PG init |
| StatefulSet | `vault-rhorizon-postgres` | PG with 10Gi PVC by default |
| Service | `vault-rhorizon-postgres` | ClusterIP for in-namespace access |
| Deployment | `vault-rhorizon-api` | uvicorn x 5 workers per pod (cluster floor), hardened |
| Service | `vault-rhorizon-api` | ClusterIP for frontend + sidecars |
| Deployment | `vault-rhorizon-frontend` | nginx, hardened |
| Service | `vault-rhorizon-frontend` | ClusterIP, exposed via Ingress if enabled |
| NetworkPolicy | `vault-rhorizon-api` | Egress lockdown to PG + DNS only |
| NetworkPolicy | `vault-rhorizon-frontend` | Ingress configurable, egress to API only |

## Install - managed PostgreSQL

For production, use a managed PG (Cloud SQL, RDS, Patroni cluster, etc.) :

```bash
kubectl -n rhorizon create secret generic my-pg-secret \
  --from-literal=postgres-password='your-managed-pg-password'

helm install vault ./rhorizon \
  -n rhorizon --create-namespace \
  --set postgres.external.enabled=true \
  --set postgres.external.host=my-pg.svc.cluster.local \
  --set postgres.external.port=5432 \
  --set postgres.external.username=rhorizon \
  --set postgres.external.database=rhorizon \
  --set postgres.external.existingSecret=my-pg-secret \
  --set image.api.repository=your-registry/rhorizon-api \
  --set image.api.tag=1.0.0 \
  --set image.frontend.repository=your-registry/rhorizon-frontend \
  --set image.frontend.tag=1.0.0
```

The chart skips the in-chart PG StatefulSet / Service / Secret /
ConfigMap when `postgres.external.enabled=true` - you keep a tighter
NetworkPolicy egress rule (the chart can't know your managed-PG IP
at template time, so add a custom rule pointing at it).

## Production knobs

```yaml
# values-prod.yaml
api:
  replicas: 3
  clusterEnabled: true # multi-worker cross-pod
  workers: 5

ingress:
  enabled: true
  className: nginx
  host: vault.example.com
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    enabled: true
    secretName: vault-tls

pdb:
  api:
    enabled: true
    minAvailable: 2
  frontend:
    enabled: true

networkPolicy:
  ingressFrontendCidrs:
    - 10.0.0.1/24       # VPN
    - 192.168.10.0/24    # office VPN
```

```bash
helm install vault ./rhorizon \
  -n rhorizon --create-namespace \
  -f values-prod.yaml \
  --set image.api.repository=your-registry/rhorizon-api \
  --set image.api.tag=1.0.0 \
  --set image.frontend.repository=your-registry/rhorizon-frontend \
  --set image.frontend.tag=1.0.0
```

## First unseal

The chart prints instructions in `helm install`'s NOTES output :

```bash
kubectl -n rhorizon port-forward svc/vault-rhorizon-api 8200:8200 &

RH_ADDR=http://127.0.0.1:8200 rhorizon unseal
# Master password: ********
```

The response includes `root_token` - save it immediately, it's shown
once. The CLI keeps the password out of shell history. After unseal, the vault
stays unsealed until a pod restart ; on
every pod restart you must re-unseal (the master key is never on disk).

## All values

See [`helm/rhorizon/values.yaml`](https://raw.githubusercontent.com/JR-Shdw/Horizon/main/helm/rhorizon/values.yaml)
for every documented knob, or `helm show values ./rhorizon`.

## Uninstall

```bash
helm uninstall vault -n rhorizon
kubectl -n rhorizon delete pvc -l app.kubernetes.io/instance=vault   # drops PG data
kubectl delete namespace rhorizon
```
