# Kubernetes sidecar pattern

The `k8s/` directory in the repo ships ready-to-use manifest examples.
This page walks through the three patterns - same as in
[Agents](agents.md) but adapted to Kubernetes primitives.

## Init container with `rh-fetch`

```yaml
# k8s/examples/app-db-creds.yml (excerpt)
apiVersion: v1
kind: Pod
metadata:
  name: app-needs-db
  namespace: rhorizon
spec:
  initContainers:
    - name: rh-fetch
      image: rhorizon-agent:latest
      command: ["/usr/local/bin/rh-fetch"]
      env:
        - name: RH_ADDR
          value: http://vault-rhorizon-api:8200
        - name: RH_TOKEN_FILE
          value: /run/secrets/rh-bootstrap
        - name: RH_SECRETS
          value: prod/db-password:/run/secrets/POSTGRES_PASSWORD
      volumeMounts:
        - name: bootstrap
          mountPath: /run/secrets
          readOnly: true
        - name: app-creds
          mountPath: /run/secrets-app
  containers:
    - name: app
      image: postgres:18
      env:
        - name: POSTGRES_PASSWORD_FILE
          value: /run/secrets/POSTGRES_PASSWORD
      volumeMounts:
        - name: app-creds
          mountPath: /run/secrets
          readOnly: true
  volumes:
    - name: bootstrap
      secret:
        secretName: rh-bootstrap
        defaultMode: 0400
    - name: app-creds
      emptyDir:
        medium: Memory
```

Key points :

- Bootstrap token is a `Secret` mounted read-only at mode 0400.
- App-credentials volume is `emptyDir: medium: Memory` (tmpfs) - never
  hits disk.
- Init container completes before the app container starts (k8s
  semantics, no need for `depends_on`).

## Sidecar with `rh-watch`

```yaml
# k8s/examples/sidecar-rotation.yml (custom)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-rotation
  namespace: rhorizon
spec:
  replicas: 1
  selector:
    matchLabels: {app: app-rotation}
  template:
    metadata:
      labels: {app: app-rotation}
    spec:
      shareProcessNamespace: true   # so rh-watch can signal PID 1
      containers:
        - name: app
          image: nginx:stable
          volumeMounts:
            - name: app-creds
              mountPath: /run/secrets
              readOnly: true
        - name: rh-watch
          image: rhorizon-agent:latest
          command: ["/usr/local/bin/rh-watch"]
          env:
            - name: RH_ADDR
              value: http://vault-rhorizon-api:8200
            - name: RH_TOKEN_FILE
              value: /run/secrets/rh-bootstrap
            - name: RH_SECRETS
              value: prod/tls-cert:/run/secrets/cert.pem,prod/tls-key:/run/secrets/key.pem
            - name: RH_RELOAD_PID
              value: "1"
            - name: RH_RELOAD_SIGNAL
              value: HUP
            - name: RH_EPHEMERAL
              value: "true"
          volumeMounts:
            - name: bootstrap
              mountPath: /run/secrets-bootstrap
              readOnly: true
            - name: app-creds
              mountPath: /run/secrets
      volumes:
        - name: bootstrap
          secret:
            secretName: rh-bootstrap
            defaultMode: 0400
        - name: app-creds
          emptyDir:
            medium: Memory
```

`shareProcessNamespace: true` lets `rh-watch` signal PID 1 (your app)
on change. nginx receives `SIGHUP` and reloads its config + certs.

## Exec wrapper with `rh-inject`

For pods that only consume secrets via env vars, build a custom image
that bakes `rh-inject` in (see the n8n example in [Agents](agents.md))
and use it as the entrypoint :

```yaml
spec:
  containers:
    - name: app
      image: localhost/n8n-rh:custom
      env:
        - name: RH_ADDR
          value: http://vault-rhorizon-api:8200
        - name: RH_TOKEN_FILE
          value: /run/secrets/rh-bootstrap
        - name: N8N_ENCRYPTION_KEY
          value: rh://prod/n8n-encryption-key
      volumeMounts:
        - name: bootstrap
          mountPath: /run/secrets
          readOnly: true
```

## NetworkPolicy for the agents

The Helm chart's `vault-rhorizon-api` NetworkPolicy already accepts
ingress from same-namespace pods. For agents in **other** namespaces,
add a custom ingress rule :

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rhorizon-allow-from-app-ns
  namespace: rhorizon
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: api
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: my-app-namespace
      ports:
        - port: 8200
          protocol: TCP
```

## External Secrets Operator (planned)

A native ESO provider is on the [roadmap](../index.md). Once shipped,
the `ExternalSecret` CRD will let you sync vault -> k8s `Secret`
without managing the agent images yourself. Track progress in the
upstream PR.
