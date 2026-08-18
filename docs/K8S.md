# Kubernetes

Two sides to running on Kubernetes:

- **Deploying the vault** - a Helm chart lives at
  [`helm/rhorizon/`](../helm/rhorizon/README.md): api + frontend + PostgreSQL
  (bundled StatefulSet, or an external managed/Database HA endpoint), hardened
  defaults, first `/unseal`, and the multi-worker cluster. **That README is the
  deployment reference** (including the Zalando-operator Patroni recipe and
  `make k8s-e2e`; BSD `pgha` is not a Kubernetes provider).
  The simplest non-k8s alternative is a single hardened VM
  ([`DEPLOYMENT.md`](DEPLOYMENT.md)); for multi-node HA topologies see
  [`HA-RUNBOOK.md`](HA-RUNBOOK.md) + [`HA-CLUSTER.md`](HA-CLUSTER.md).
- **Consuming secrets** - the rest of *this* document: how K8s pods
  authenticate to the vault and receive secrets without leaking them in env or
  images, independent of where the vault itself runs.

For the running vault in containers generally, see [`DOCKER.md`](DOCKER.md).

---

## 1. The agent: rh-fetch / rh-inject / rh-watch

A separate Rust crate (`agent/`) builds three single-binary tools that
ship as a `scratch` image (~5-8 MB):

| Binary | Purpose | Container pattern |
|---|---|---|
| `rh-fetch` | Resolve secrets and **write to files** under a tmpfs | Init container |
| `rh-inject` | Resolve secrets and `exec` your real entrypoint with **env vars** populated | Image entrypoint replacement (PID 1) |
| `rh-watch` | Long-running sidecar that re-fetches secrets on rotation | Sidecar container |

Recommendation: prefer `rh-fetch` (file-based, tmpfs, mode 0400).
`rh-inject` is convenient but the resolved secrets remain visible in
`/proc/PID/environ` to anything running as the same user. Use
`rh-inject` only for development or non-sensitive workloads.

---

## 2. Manifests in `k8s/`

```
k8s/
|-- namespace.yml          # Namespace + ServiceAccount + RBAC + Secret slot
|-- network-policy.yml     # Egress-only NetworkPolicy
`-- examples/
    |-- app-db-creds.yml   # Pod with rh-fetch init -> DB credentials in tmpfs
    |-- inject-env.yml     # Pod with rh-inject -> env vars (legacy, less secure)
    |-- tls-certs.yml      # Nginx Deployment with TLS cert/key from the vault
    |-- sidecar-watch.yml  # Sidecar pattern for rotating secrets
    `-- cronjob.yml        # CronJob backup with ephemeral tokens
```

Apply the namespace + RBAC first:

```bash
kubectl apply -f k8s/namespace.yml
```

Then create the vault token Secret with the actual token your admin
generated (one-time, scoped narrowly):

```bash
kubectl -n rhorizon create secret generic rhorizon-token \
  --from-literal=token="rh_xxxxxxxxxxxxxxxxxxxx"
```

The Secret is consumed by `rh-fetch` / `rh-inject` via env var
`RH_TOKEN` (or via volume mount if you prefer not to put it in
env).

---

## 3. NetworkPolicy

The bundled `network-policy.yml` is **egress-only**: it locks down
which IPs and ports a pod with the `rhorizon-access` label may reach.
The defaults are conservative - DNS plus the vault API.

```yaml
egress:
  - to: []
    ports:
      - protocol: UDP
        port: 53
      - protocol: TCP
        port: 53
  - to:
      - ipBlock:
          cidr: <YOUR-VAULT-IP>/32   # adjust to your VM's VPN-facing IP
    ports:
      - protocol: TCP
        port: 8200
```

Set the CIDR to the IP of the VM that runs the vault (typically a VPN
or private VLAN address - never a public IP).

If you also need outbound to other services (registry, DB, etc.),
extend the `egress:` list. The default is fail-closed.

---

## 4. RBAC for the agent

`namespace.yml` provisions:

- A namespace `rhorizon`
- A `ServiceAccount` `rhorizon-agent` with `automountServiceAccountToken: false` (the agent does **not** call the K8s API)
- A `Role`/`RoleBinding` allowing `get` on the single Secret `rhorizon-token`

Pods that need to talk to the vault should:

```yaml
spec:
  serviceAccountName: rhorizon-agent
  automountServiceAccountToken: false
```

The token in `rhorizon-token` should be the **only** Kubernetes Secret
required for vault integration. Everything else is fetched from
rhorizon at pod startup.

---

## 5. Pattern A - `rh-fetch` init container (recommended)

Best for credentials your app reads from a file (DB URLs, TLS keys,
cloud-provider credentials).

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-db-creds
  namespace: rhorizon
  labels:
    rhorizon-access: "true"        # picked up by NetworkPolicy
spec:
  serviceAccountName: rhorizon-agent
  automountServiceAccountToken: false
  initContainers:
    - name: rh-fetch
      image: rhorizon-agent:latest
      command: ["rh-fetch"]
      env:
        - name: RH_ADDR
          value: "http://<vault-ip>:8200"
        - name: RH_TOKEN
          valueFrom:
            secretKeyRef:
              name: rhorizon-token
              key: token
        - name: RH_SECRETS
          # name-on-vault:path-on-fs ; comma-separated
          value: "prod/db-password:/secrets/db-pw,prod/tls-cert:/secrets/tls.crt"
      volumeMounts:
        - name: secrets
          mountPath: /secrets
  containers:
    - name: app
      image: my-app:1.2.3
      volumeMounts:
        - name: secrets
          mountPath: /secrets
          readOnly: true
  volumes:
    - name: secrets
      emptyDir:
        medium: Memory               # tmpfs in RAM
```

What `rh-fetch` does:

1. Reads `RH_SECRETS` and connects to `RH_ADDR` with `RH_TOKEN`
2. Calls `GET /api/v1/vault/secrets/<name>` for each entry
3. Writes the value to the path with `chmod 0400`
4. Exits 0 on full success, non-zero on any failure (init container fails the pod)

The `emptyDir` `medium: Memory` ensures the secret never hits disk
even if the kubelet happens to cache the file.

---

## 6. Pattern B - `rh-inject` env replacement (legacy)

Drop-in replacement for `entrypoint`. The image of the workload itself
must contain `rh-inject` (or it must be borrowed via a sidecar that
shares a `volumeMount`).

```yaml
spec:
  containers:
    - name: app
      image: my-app:1.2.3
      command: ["/usr/local/bin/rh-inject"]
      args: ["--", "/usr/bin/my-app", "--config", "/etc/my-app.yml"]
      env:
        - name: RH_ADDR
          value: "http://<vault-ip>:8200"
        - name: RH_TOKEN
          valueFrom:
            secretKeyRef: { name: rhorizon-token, key: token }
        - name: DB_URL
          value: "rh://prod/db-url"
        - name: API_KEY
          value: "rh://prod/api-key"
```

`rh-inject` resolves any env value starting with `rh://` then `exec`s
the real binary as PID 1. The `RH_TOKEN` env var is removed from
the child environment to avoid further propagation.

Limitations (see [`THREAT-MODEL.md`](THREAT-MODEL.md#34---agent-rh-inject-limitations)):

- Resolved secrets remain in `/proc/PID/environ` - visible to any
  process running as the same user
- `kubectl describe pod` shows the `rh://` references (not the values),
  but the values appear in `/proc/$PID/environ` once the pod is running

---

## 7. Pattern C - `rh-watch` sidecar (rotating secrets)

For long-running pods where secrets rotate during pod lifetime:

```yaml
spec:
  containers:
    - name: app
      # ... as in Pattern A
    - name: rh-watch
      image: rhorizon-agent:latest
      command: ["rh-watch"]
      env:
        - name: RH_ADDR
          value: "http://<vault-ip>:8200"
        - name: RH_TOKEN
          valueFrom:
            secretKeyRef: { name: rhorizon-token, key: token }
        - name: RH_SECRETS
          value: "prod/db-password:/secrets/db-pw"
        - name: RH_POLL_SECS
          value: "60"               # seconds
        - name: RH_RELOAD_SIGNAL
          value: "HUP"              # SIGHUP to PID 1 of the app container
      volumeMounts:
        - name: secrets
          mountPath: /secrets
```

`rh-watch` polls the vault for changes and rewrites the file when the
DEK or the secret value changes. Pair with an app that reloads on
`SIGHUP`.

---

## 8. Pattern D - Ephemeral tokens for CronJobs

Long-lived static tokens are a poor fit for batch jobs that run once a
day. Use ephemeral tokens (TTL 60s-24h) issued at job start by an
admin:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
  namespace: rhorizon
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            rhorizon-access: "true"
        spec:
          serviceAccountName: rhorizon-agent
          restartPolicy: OnFailure
          initContainers:
            - name: rh-fetch
              image: rhorizon-agent:latest
              command: ["rh-fetch"]
              env:
                - name: RH_ADDR
                  value: "http://<vault-ip>:8200"
                - name: RH_TOKEN
                  valueFrom:
                    secretKeyRef: { name: rhorizon-token, key: token }
                - name: RH_SECRETS
                  value: "backup/passphrase:/secrets/pw"
              volumeMounts:
                - { name: secrets, mountPath: /secrets }
          containers:
            - name: backup
              image: my-backup-tool:latest
              env:
                - name: BACKUP_PASSPHRASE_FILE
                  value: /secrets/pw
              volumeMounts:
                - { name: secrets, mountPath: /secrets, readOnly: true }
          volumes:
            - name: secrets
              emptyDir: { medium: Memory }
```

For an issued-at-job-start ephemeral token, the recommended path is to
provision it via Ansible / your CD pipeline in front of the
`kubectl apply`, so the Secret has a short TTL embedded in its annotations
that triggers automatic rotation.

---

## 9. TLS certificates from the vault

For workloads that need to terminate TLS with a cert stored in the
vault (e.g., an internal nginx that fronts another service), see
`k8s/examples/tls-certs.yml`. The pattern is:

1. `rh-fetch` init writes `tls.crt` and `tls.key` to `/secrets/`
2. The application reads from `/secrets/`
3. On rotation, `rh-watch` overwrites the files and signals the app

For Kubernetes-native TLS (Ingress + cert-manager), you typically do
**not** need the vault - let cert-manager + ACME do its job. Use the
vault only for certificates that don't fit the ACME model
(internal CA, mTLS client certs).

---

## 10. Common pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `rh-fetch` exits with `connection refused` | NetworkPolicy CIDR doesn't match the vault IP | Update `network-policy.yml` |
| `401 Unauthorized` from `rh-fetch` | Token expired / revoked / wrong scope | Re-issue with proper scope; check `rhorizon audit list --filter=actor=<token-id>` |
| Pod starts but app reads empty file | `rh-fetch` ran before the volume was mounted | Init containers + volumes are sequential - verify the `volumeMounts` are in both `initContainers` and `containers` |
| `chmod 0400` on `/secrets/` fails | tmpfs not configured with `Memory` medium | `emptyDir: { medium: Memory }` |
| `memory_protection: zeroize-only` or `process_memory_protection: swappable`, with exposed/unknown swap | `IPC_LOCK` is absent or the node runtime memlock limit is too low | First verify every eligible node and set `api.swapProtection`; if swap is unencrypted, encrypt/disable it or enable `api.requestIpcLockCapability` where admission policy permits it |

---

## 11. Operational notes

- **The vault stays sealed at boot.** Pods will fail to start until the
  vault is unsealed by an operator (or a Shamir quorum). Make the dependency
  explicit in your runbook - K8s does not orchestrate operators.
- **Tokens in K8s Secrets are not encrypted at rest by default.** Use
  KMS provider, encrypt etcd, or accept the trade-off and keep the
  token narrowly scoped + short-TTL.
- **Audit comes from the vault**, not from K8s. If you want
  per-pod attribution, mint a unique token per app/namespace and
  rely on the audit log's `actor` field.
- **NetworkPolicy is enforced by the CNI plugin.** Some CNIs ignore
  `NetworkPolicy` (`flannel` without canal); verify with a deny-all
  test pod before relying on it.
