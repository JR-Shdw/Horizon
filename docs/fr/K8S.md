# Kubernetes

Le chart Helm livré sous
[`helm/rhorizon/`](../../helm/rhorizon/README.md) déploie API, frontend et
PostgreSQL (StatefulSet inclus ou endpoint externe), avec defaults durcis,
premier `/unseal` et cluster multi-worker. Son README est la référence de
déploiement Kubernetes, y compris la recette Patroni via opérateur Zalando et
`make k8s-e2e`. `pgha` est natif BSD et n'est pas un fournisseur Kubernetes.

Le déploiement non-Kubernetes le plus simple reste une VM durcie
([`DEPLOYMENT.md`](DEPLOYMENT.md)). Pour les topologies HA multi-nœuds, voir
[`HA-RUNBOOK.md`](HA-RUNBOOK.md) section 0 et
[`HA-CLUSTER.md`](HA-CLUSTER.md).

Ce document parle du **côté consommateur** : comment les pods K8s
s'authentifient au vault, comment ils reçoivent les secrets sans les
fuiter en env ou en image, et comment câbler tout ça - indépendamment
de l'endroit où le vault lui-même tourne.

Pour le vault en containers de façon générale, voir [`DOCKER.md`](DOCKER.md).

---

## 1. L'agent : rh-fetch / rh-inject / rh-watch

Un crate Rust séparé (`agent/`) construit trois outils single-binary
livrés en image `scratch` (~5-8 Mo) :

| Binaire | Rôle | Pattern container |
|---|---|---|
| `rh-fetch` | Résout les secrets et **écrit dans des fichiers** sur tmpfs | Init container |
| `rh-inject` | Résout les secrets et `exec` votre vrai entrypoint avec **env vars** populées | Remplacement d'entrypoint d'image (PID 1) |
| `rh-watch` | Sidecar long-running qui re-fetche les secrets à la rotation | Sidecar container |

Recommandation : préférer `rh-fetch` (file-based, tmpfs, mode 0400).
`rh-inject` est pratique mais les secrets résolus restent visibles
dans `/proc/PID/environ` pour tout ce qui tourne sous le même user.
Utiliser `rh-inject` uniquement pour le dev ou les workloads non-
sensibles.

---

## 2. Manifests dans `k8s/`

```
k8s/
|-- namespace.yml          # Namespace + ServiceAccount + RBAC + emplacement Secret
|-- network-policy.yml     # NetworkPolicy egress-only
`-- examples/
    |-- app-db-creds.yml   # Pod avec init rh-fetch -> credentials DB en tmpfs
    |-- inject-env.yml     # Pod avec rh-inject -> env vars (legacy, moins safe)
    |-- tls-certs.yml      # Deployment Nginx avec cert/key TLS depuis le vault
    |-- sidecar-watch.yml  # Pattern sidecar pour secrets en rotation
    `-- cronjob.yml        # CronJob backup avec tokens éphémères
```

Appliquer le namespace + RBAC en premier :

```bash
kubectl apply -f k8s/namespace.yml
```

Puis créer le Secret token vault avec le token réel généré par votre
admin (one-time, scope étroit) :

```bash
kubectl -n rhorizon create secret generic rhorizon-token \
  --from-literal=token="rh_xxxxxxxxxxxxxxxxxxxx"
```

Le Secret est consommé par `rh-fetch` / `rh-inject` via env var
`RH_TOKEN` (ou via volume mount si vous préférez ne pas le
mettre en env).

---

## 3. NetworkPolicy

Le `network-policy.yml` bundle est **egress-only** : il verrouille
quelles IPs et ports un pod avec le label `rhorizon-access` peut
joindre. Les défauts sont conservatifs - DNS plus l'API vault.

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
          cidr: <YOUR-VAULT-IP>/32   # ajustez à l'IP VPN-facing de votre VM
    ports:
      - protocol: TCP
        port: 8200
```

Mettez le CIDR à l'IP de la VM qui fait tourner le vault (typiquement
une adresse VPN ou VLAN privé - jamais une IP publique).

Si vous avez aussi besoin de sortir vers d'autres services (registry,
DB, etc.), étendez la liste `egress:`. Le défaut est fail-closed.

---

## 4. RBAC pour l'agent

`namespace.yml` provisionne :

- Un namespace `rhorizon`
- Un `ServiceAccount` `rhorizon-agent` avec `automountServiceAccountToken: false` (l'agent n'appelle **pas** l'API K8s)
- Un `Role`/`RoleBinding` autorisant `get` sur l'unique Secret `rhorizon-token`

Les pods qui doivent parler au vault devraient :

```yaml
spec:
  serviceAccountName: rhorizon-agent
  automountServiceAccountToken: false
```

Le token dans `rhorizon-token` devrait être l'**unique** Secret
Kubernetes requis pour l'intégration vault. Tout le reste est fetché
depuis rhorizon au démarrage du pod.

---

## 5. Pattern A - init container `rh-fetch` (recommandé)

Idéal pour les credentials que votre app lit depuis un fichier (URLs
DB, clés TLS, credentials cloud-provider).

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-db-creds
  namespace: rhorizon
  labels:
    rhorizon-access: "true"        # picked up par la NetworkPolicy
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
          # nom-vault:chemin-fs ; séparés par virgule
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
        medium: Memory               # tmpfs en RAM
```

Ce que `rh-fetch` fait :

1. Lit `RH_SECRETS` et se connecte à `RH_ADDR` avec `RH_TOKEN`
2. Appelle `GET /api/v1/vault/secrets/<name>` pour chaque entrée
3. Écrit la valeur au chemin avec `chmod 0400`
4. Sort 0 en cas de succès complet, non-zero en cas d'échec (l'init container fait échouer le pod)

Le `medium: Memory` de l'emptyDir garantit que le secret ne touche
jamais le disque même si le kubelet venait à cacher le fichier.

---

## 6. Pattern B - remplacement d'env `rh-inject` (legacy)

Drop-in replacement pour `entrypoint`. L'image du workload elle-même
doit contenir `rh-inject` (ou il doit être emprunté via un sidecar qui
partage un `volumeMount`).

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

`rh-inject` résout toute valeur d'env qui commence par `rh://` puis
`exec`s le vrai binaire en PID 1. La var d'env `RH_TOKEN` est
retirée de l'environnement enfant pour éviter une propagation plus
loin.

Limitations (voir [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md#34---agent-rh-inject-limitations)) :

- Les secrets résolus restent dans `/proc/PID/environ` - visibles à
  tout process qui tourne sous le même user
- `kubectl describe pod` montre les références `rh://` (pas les
  valeurs), mais les valeurs apparaissent dans `/proc/$PID/environ`
  une fois que le pod tourne

---

## 7. Pattern C - sidecar `rh-watch` (secrets en rotation)

Pour les pods long-running où les secrets tournent durant le cycle de
vie du pod :

```yaml
spec:
  containers:
    - name: app
      # ... comme dans le Pattern A
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
          value: "60"               # secondes
        - name: RH_RELOAD_SIGNAL
          value: "HUP"              # SIGHUP au PID 1 du container app
      volumeMounts:
        - name: secrets
          mountPath: /secrets
```

`rh-watch` poll le vault pour les changements et réécrit le fichier
quand la DEK ou la valeur du secret change. Pairez avec une app qui
reload sur `SIGHUP`.

---

## 8. Pattern D - Tokens éphémères pour CronJobs

Les tokens statiques à longue vie sont peu adaptés aux jobs batch qui
tournent une fois par jour. Utilisez des tokens éphémères (TTL
60s-24h) émis au démarrage du job par un admin :

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

Pour un token éphémère émis-au-démarrage-du-job, le chemin recommandé
est de le provisionner via Ansible / votre pipeline CD avant le
`kubectl apply`, de sorte que le Secret porte un TTL court intégré
dans ses annotations qui déclenche la rotation automatique.

---

## 9. Certificats TLS depuis le vault

Pour les workloads qui doivent terminer du TLS avec un cert stocké
dans le vault (ex. un nginx interne qui fronte un autre service),
voir `k8s/examples/tls-certs.yml`. Le pattern :

1. L'init `rh-fetch` écrit `tls.crt` et `tls.key` dans `/secrets/`
2. L'application lit depuis `/secrets/`
3. À la rotation, `rh-watch` écrase les fichiers et signale l'app

Pour le TLS Kubernetes-natif (Ingress + cert-manager), vous n'avez
typiquement **pas** besoin du vault - laissez cert-manager + ACME
faire son boulot. Utilisez le vault uniquement pour les certificats
qui ne rentrent pas dans le modèle ACME (CA interne, certs client
mTLS).

---

## 10. Pièges courants

| Symptôme | Cause | Fix |
|---|---|---|
| `rh-fetch` sort en `connection refused` | CIDR de la NetworkPolicy ne match pas l'IP vault | Mettre à jour `network-policy.yml` |
| `401 Unauthorized` depuis `rh-fetch` | Token expiré / révoqué / mauvais scope | Réémettre avec scope correct ; vérifier `rhorizon audit list --filter=actor=<token-id>` |
| Pod démarre mais l'app lit un fichier vide | `rh-fetch` a tourné avant que le volume soit monté | Init containers + volumes sont séquentiels - vérifier que les `volumeMounts` sont dans `initContainers` ET `containers` |
| `chmod 0400` sur `/secrets/` échoue | tmpfs pas configuré avec `Memory` medium | `emptyDir: { medium: Memory }` |
| `memory_protection: zeroize-only` ou `process_memory_protection: swappable`, avec du swap exposé/inconnu | `IPC_LOCK` est absent, ou la limite memlock du runtime du nœud est trop basse | Vérifier d'abord chaque nœud éligible et poser `api.swapProtection` ; si le swap n'est pas chiffré, le chiffrer/désactiver, ou activer `api.requestIpcLockCapability` là où la politique d'admission le permet |

---

## 11. Notes opérationnelles

- **Le vault reste sealed au boot.** Les pods échoueront à démarrer
  jusqu'à ce que le vault soit unsealed par un opérateur (ou un quorum
  Shamir). Rendez la dépendance explicite dans votre runbook - K8s
  n'orchestre pas les opérateurs.
- **Les tokens dans les Secrets K8s ne sont pas chiffrés au repos par
  défaut.** Utilisez un provider KMS, chiffrez etcd, ou acceptez le
  trade-off et gardez le token narrow-scope + short-TTL.
- **L'audit vient du vault**, pas de K8s. Si vous voulez l'attribution
  per-pod, mintez un token unique par app/namespace et appuyez-vous
  sur le champ `actor` du log d'audit.
- **La NetworkPolicy est appliquée par le plugin CNI.** Certains CNIs
  ignorent `NetworkPolicy` (`flannel` sans canal) ; vérifiez avec un
  pod test deny-all avant de vous y fier.
