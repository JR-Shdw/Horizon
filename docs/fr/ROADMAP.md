# Resurgamus Horizon - Roadmap v1.0 -> v2.0

## Vue d'ensemble

10 fonctionnalites reparties sur 3 tiers, ordonnees par impact d'adoption.

```
Beta (maintenant)  ->  v1.0 (CLI+UI+versioning)  ->  v1.1 (LDAP+RBAC)  ->  v1.2 (import+inject)  ->  v2.0 (dynamic)
```

---

## Tier 1 - Bloquants adoption

### 1. Web UI complete

**Objectif** : un sysadmin gere le vault au quotidien sans curl.

**Etat actuel** : un frontend en JS vanilla existe mais ne couvre pas tous les endpoints.

**Ecrans requis** :

| Ecran | Fonctionnalites |
|--------|----------|
| Dashboard | Sealed/unsealed, uptime, nombre de secrets/tokens, dernieres actions d'audit |
| Secrets | Liste avec filtre namespace, create/read/update/delete, copie valeur, voir versions |
| Tokens | Liste, create (permissions JSON : scope + namespaces), revoke, delete |
| Namespaces | Liste avec compteurs, creation namespace (implicite via secret), delete |
| Audit | Table paginee, filtres (acteur, action, plage de dates), indicateur chain intact |
| Unseal | Formulaire password + 2FA, progression Shamir (barre M/N) |
| Shamir | Init (slider threshold/total), affichage unique des shares |
| 2FA | Setup TOTP (QR code), enregistrement YubiKey, selecteur de mode |
| Settings | Infos vault (version, uptime), rotation DEK en masse, export/import |

**Principes UI** :
- JS vanilla (pas de build step, pas de framework)
- Pattern existant : `renderXxx(el)`, routage par hash, helper `api()`
- Valeurs sensibles masquees par defaut, bouton "reveal" avec copie presse-papiers
- Aucun secret en clair dans le DOM sauf demande explicite de l'utilisateur

**Estimation** : 2-3 jours

---

### 2. CLI (`rhorizon`)

**Objectif** : utiliser rhorizon dans les scripts, les pipelines CI/CD, et le terminal au quotidien.

**Stack** : Python + typer (coherent avec le reste du projet)

**Commandes** :

```
rhorizon login URL                     # Authentifie, stocke le token dans ~/.config/rhorizon/
rhorizon status                        # Sealed/unsealed, version, mode 2FA
rhorizon unseal                        # Prompt password (+ TOTP/YubiKey si configure)
rhorizon seal                          # Scelle le vault

# Secrets
rhorizon get NAME                      # Affiche la valeur (stdout, pipeable)
rhorizon get NAME --json               # JSON complet (name, value, version, namespace)
rhorizon set NAME VALUE                # Cree ou met a jour
rhorizon set NAME --file=path          # Valeur depuis un fichier
rhorizon set NAME --stdin              # Valeur depuis stdin
rhorizon delete NAME                   # Supprime
rhorizon list                          # Liste (noms uniquement)
rhorizon list --namespace=prod         # Filtre par namespace
rhorizon rotate NAME                   # Rotation DEK
rhorizon rotate --all                  # Rotation en masse

# Tokens
rhorizon token create NAME --perms '{"secrets":"rw"}'
rhorizon token list
rhorizon token revoke ID

# Namespaces
rhorizon ns list
rhorizon ns delete NAME

# Import/Migration (voir feature 5)
rhorizon import --from=dotenv .env
rhorizon migrate vault --dry-run

# Shamir
rhorizon shamir init --threshold=3 --total=5
rhorizon shamir unseal                 # Prompt pour chaque share
```

**Configuration** (`~/.config/rhorizon/config.toml`) :
```toml
[default]
url = "https://vault.internal:8200"
token_file = "~/.config/rhorizon/token"
# token stocke mode 0600, pas dans le TOML
```

**Livrable** : paquet pip-installable (`pip install rhorizon-cli` ou script standalone)

**Estimation** : 2-3 jours

---

### 3. LDAP / Active Directory

**Objectif** : les utilisateurs se connectent avec leurs credentials AD/LDAP. Les groupes AD mappent vers les permissions rhorizon.

**Modes supportes** :
1. **Bind LDAP direct** - rhorizon contacte LDAP pour verifier les credentials
2. **Headers SSO proxy** - Authelia/Authentik/Keycloak en frontal (`Remote-User` + `Remote-Groups`)
Les deux modes sont implementes. Le bind LDAP ne necessite pas de reverse proxy. Le mode SSO proxy necessite un reverse proxy de confiance (Traefik + Authelia/Authentik/Keycloak) et `RH_PROXY_AUTH_ENABLED=true`.

**Flux LDAP** :
```
User -> POST /api/v1/vault/auth/ldap {"username":"jdoe","password":"..."}
  -> rhorizon bind sur LDAP avec les credentials
  -> recherche les groupes de l'utilisateur
  -> mappe les groupes -> role rhorizon (admin/ops/viewer)
  -> cree un token de session (TTL configurable)
  -> retourne le token
```

**Configuration** (table `vault_config` ou env vars) :
```
LDAP_URL=ldaps://dc.corp.local:636
LDAP_BIND_DN=cn=rhorizon,ou=services,dc=corp,dc=local
LDAP_BIND_PASSWORD=...
LDAP_USER_BASE=ou=users,dc=corp,dc=local
LDAP_USER_FILTER=(sAMAccountName={username})
LDAP_GROUP_BASE=ou=groups,dc=corp,dc=local
LDAP_GROUP_FILTER=(member={user_dn})
LDAP_GROUP_ATTR=cn
LDAP_TLS_VERIFY=true
```

**Mapping groupe -> role** (configurable via API/UI) :
```json
{
  "vault-admins": {"admin": "rw"},
  "vault-ops": {"secrets": "rw", "audit": "r"},
  "vault-readers": {"secrets": "r"},
  "dba-team": {"secrets": "rw", "namespaces": ["prod/db", "staging/db"]}
}
```

**Estimation** : 3-4 jours

---

### 4. Secret versioning + rollback

**Objectif** : conserver l'historique des N dernieres versions d'un secret. Permettre le rollback.

**Etat actuel** : l'historique des versions et le rollback sont implementes.
Les valeurs courantes vivent dans `vault_secrets`; les anciennes versions
retenues vivent dans `vault_secret_versions`.

**Forme implementee** :

**Schema** - nouvelle table `vault_secret_versions` :
```sql
CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id   uuid NOT NULL REFERENCES vault_secrets(id) ON DELETE CASCADE,
    version     integer NOT NULL,
    ciphertext  bytea NOT NULL,
    nonce       bytea NOT NULL,
    dek_id      uuid NOT NULL REFERENCES vault_dek(id),
    created_at  timestamptz DEFAULT now(),
    created_by  text,
    UNIQUE (secret_id, version)
);
```

**Flux** :
- `POST /secrets/` - cree la version 1, insere dans `vault_secret_versions`
- `PUT /secrets/{name}` - incremente la version, insere la nouvelle, garde les anciennes
- `GET /secrets/{name}` - retourne la version courante (comme aujourd'hui)
- `GET /secrets/{name}/versions` - liste les versions (sans les valeurs)
- `GET /secrets/{name}/versions/{v}` - lit une version specifique
- `POST /secrets/{name}/rollback/{v}` - restaure une ancienne version (cree une nouvelle version avec l'ancienne valeur)

**Retention** : configurable, defaut 10 versions. Les plus anciennes sont purgees automatiquement.

**Estimation** : 1-2 jours

---

## Tier 2 - Differenciateurs

### 5. Import migration / backup

**Objectif** : faciliter la migration vers rhorizon sans réintroduire d'export bulk en clair.

**Formats supportes** :

| Source / format | Import | Export | Usage |
|--------|--------|--------|-------|
| `.env` (dotenv) | Oui | Non | Migration depuis des fichiers .env |
| JSON | Oui | Non | Import de migration côté client seulement |
| HashiCorp Vault | Oui | Non | Migration de vault externe via le CLI |
| Infisical | Expérimental | Non | Migration de vault externe via le CLI |
| backup age | Restore | Oui | Backup / restore logique chiffré |

**Estimation** : 2-3 jours

---

### 6. Injection de secrets dans les containers

**Objectif** : les containers recuperent leurs secrets au demarrage sans les hardcoder dans docker-compose.yml.

**Deux mecanismes** :

#### 6a. Init container (simple)

Un container qui tire les secrets et les ecrit comme fichiers dans un volume partage :

```yaml
services:
  secrets-init:
    image: rhorizon-agent:latest
    environment:
      RH_ADDR: https://vault.internal:8200
      RH_TOKEN: rh_xxx
      RH_SECRETS: "prod/db-password:/secrets/db-pass,prod/api-key:/secrets/api-key"
    volumes:
      - secrets:/secrets

  app:
    image: myapp
    depends_on:
      secrets-init:
        condition: service_completed_successfully
    volumes:
      - secrets:/secrets:ro

volumes:
  secrets:
    driver_opts:
      type: tmpfs
      device: tmpfs  # RAM uniquement, jamais sur disque
```

#### 6b. Injection en env var (avance)

Un wrapper qui resout les references rhorizon dans les env vars :

```yaml
services:
  app:
    image: myapp
    entrypoint: ["/usr/local/bin/rh-inject", "--", "/app/start.sh"]
    environment:
      RH_ADDR: https://vault.internal:8200
      RH_TOKEN: rh_xxx
      DB_PASSWORD: "rh://prod/db-password"
      API_KEY: "rh://prod/api-key"
    # rh-inject resout rh:// avant d'exec l'app
```

**Estimation** : 2-3 jours

---

### 7. Groupes / RBAC simple

**Objectif** : gerer les permissions par groupe (LDAP ou local), pas par token individuel.

**Estimation** : 2 jours

---

### 8. Notifications

**Objectif** : alerter quand un secret est modifie, un token revoque, ou un unseal echoue.

**Canaux** :
- Matrix (natif)
- Webhook generique (Slack, Mattermost, Discord, ntfy)
- Email (SMTP)

**Estimation** : 1-2 jours

---

## Tier 3 - Credibilite enterprise

### 9. Backup / Restore chiffre

**Objectif** : deux chemins explicites de recuperation : `pg_dump | age` pour
la DR full-fidelity (tokens, 2FA, moteurs dynamiques et audit inclus), et le
backup age API pour une migration logique partielle vers une instance vierge.

**Estimation** : 2 jours

---

### 10. Dynamic secrets modulaires

**Objectif** : generer des credentials temporaires de base de donnees ou
d'annuaire avec TTL.

**Scope livre** : PostgreSQL, MySQL/MariaDB, LDAP, Redis ACL et Cassandra, plus
une collection Ansible separee. Chaque backend a son dossier et son lock de
dependances ; l'INI choisit le code importe et le build peut retirer les drivers
optionnels. Les preuves live restent distinguees du simple statut implemente
dans `docs/COMPATIBILITY.md`. Pas d'AWS IAM, pas de PKI, pas de SSH.

**Estimation** : 4-5 jours

---

## Resume estimations

| # | Fonctionnalite | Jours | Phase |
|---|---------|------|-------|
| 1 | Web UI complete | 2-3 | v1.0 |
| 2 | CLI (`rhorizon`) | 2-3 | v1.0 |
| 3 | LDAP / Active Directory | 3-4 | v1.1 |
| 4 | Secret versioning + rollback | 1-2 | v1.0 |
| 5 | Import migration / backup | 2-3 | v1.2 |
| 6 | Injection container | 2-3 | v1.2 |
| 7 | Groupes / RBAC | 2 | v1.1 |
| 8 | Notifications | 1-2 | v1.1 |
| 9 | Backup / restore chiffre | 2 | v1.2 |
| 10 | Dynamic secrets modulaires | 4-5 | v2.0 |
| | **Total** | **~25 jours** | |

## Ordre d'implementation recommande

```
v1.0-beta (maintenant)
  +-- Publication GitHub, retours early adopters

v1.0
  +-- #4  Secret versioning (fondation, impacte le schema)
  +-- #1  Web UI complete
  +-- #2  CLI (rhorizon)

v1.1
  +-- #3  LDAP / AD
  +-- #7  Groupes / RBAC
  +-- #8  Notifications

v1.2
  +-- #5  Import migration / backup
  +-- #6  Injection container
  +-- #9  Backup / Restore

v2.0
  +-- #10 Dynamic secrets modulaires
```
