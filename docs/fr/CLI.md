# CLI

La commande `rhorizon` est la façon canonique de piloter le vault
depuis un terminal opérateur ou un script. Elle wrap la même API HTTP
que celle qui anime l'UI web, avec des formes de sortie adaptées à la
fois à l'usage interactif et aux pipelines shell.

Pour l'API sous-jacente et le modèle d'auth, voir
[`SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md). Pour le contexte de
déploiement, voir [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## 1. Installation

Le CLI vit dans `cli/` du repo rhorizon et c'est un package Python
ordinaire.

```bash
cd ~/dev/tools/rhorizon/cli
python -m venv .venv
source .venv/bin/activate
pip install -e .

rhorizon --help     # vérifier qu'il est dans le PATH
```

Dépendances minimales : `typer` (commandes), `httpx` (client HTTP),
`tomlkit` (lecteur config). Python 3.12+.

---

## 2. Configuration

```bash
rhorizon login http://10.0.0.20:8200
# Connected to rhorizon 0.9.0-beta (sealed=False)
# Token (rh_...): ********
# Token saved.
```

Ça écrit :

| Fichier | Mode | Contenu |
|---|---|---|
| `~/.config/rhorizon/config.toml` | 0600 | Profil actif, URL vault |
| `~/.config/rhorizon/token.<profil>` | 0600 | Le token, en clair (profil default -> `token.default`) |

Les appels `rhorizon` suivants lisent les deux. Pour switcher de
vault, relancer `rhorizon login <autre-url>`. Pour effacer, supprimer
les fichiers.

Overrides via env (utile pour CI / scripts) :

| Var | Effet |
|---|---|
| `RH_ADDR` (ou `RH_URL`) | URL vault (override le fichier config) |
| `RH_TOKEN` | Token (override le fichier token) |
| `RH_TOKEN_STDIN=1` | Lit le token sur une ligne de stdin (ne touche jamais le disque) |
| `RH_CONFIG_DIR` | Repertoire config (defaut `~/.config/rhorizon`) |

---

## 3. Commandes vault

### `rhorizon status` - état du vault

```bash
rhorizon status
# Status:   UNSEALED
# Version:  0.9.0-beta
# Uptime:   10h27m
# 2FA:      none

rhorizon status --json    # machine-readable
```

Pas d'authentification requise.

### `rhorizon whoami` - introspection du token

```bash
rhorizon whoami
# Token:        ansible-prod
# ID:           a1b2c3d4-...
# Scopes:       secrets:r
# Namespaces:   prod, staging
# Active:       true
# Ephemeral:    false
# Created at:   2026-04-15T10:23:00Z
# Last used:    2026-04-29T07:45:00Z
# Expires at:   (no expiry)

rhorizon whoami --json
```

Utile pour un agent ou script qui veut vérifier ce qu'il peut faire
avant de tenter une opération. N'importe quel token valide peut
appeler ça.

### `rhorizon unseal` - mettre le vault online

```bash
rhorizon unseal
# Master password: ********
# (code TOTP si 2FA activée)
# Status: unsealed
```

Prompt interactif. Pour un usage non-interactif, taper l'API
directement ou utiliser `oneshot` (voir section 10).

### `rhorizon seal` - mettre le vault offline

```bash
rhorizon seal
# Status: sealed
```

Requiert un token avec `admin:rw`. Force la zéroïsation de toutes les
sous-clés en RAM. Le vault doit être ré-unseal manuellement (ou via
quorum Shamir) après.

---

## 4. Secrets

### `rhorizon set` - créer ou mettre à jour

```bash
# Valeur interactive sans historique ni argument de processus
read -rsp 'Valeur du secret : ' RH_SECRET; echo
printf '%s' "$RH_SECRET" | rhorizon set prod/db-password --stdin
unset RH_SECRET

# Depuis un fichier
rhorizon set prod/tls-cert --file ./fullchain.pem

# Depuis stdin (pipeline-friendly)
openssl rand -hex 32 | rhorizon set ci/build-token --stdin

# Update un secret existant (crée une nouvelle version)
read -rsp 'Nouvelle valeur : ' RH_SECRET; echo
printf '%s' "$RH_SECRET" | rhorizon set prod/db-password --stdin --update
unset RH_SECRET

# Namespace personnalisé, depuis un fichier protégé
rhorizon set my-key --file ./value.txt --namespace mcp/demo
# rhorizon set -n mcp/demo my-key --file ./value.txt  (forme courte)
```

Évitez l'argument positionnel `VALUE` pour un vrai secret : l'historique, la
liste des processus ou les logs du job peuvent le capturer. Préférez `--stdin`
ou `--file`.

### `rhorizon get` - lire un secret

```bash
rhorizon get prod/db-password
# s3cure-p4ssw0rd

rhorizon get prod/db-password --json
# {"name": "prod/db-password", "value": "...", "version": 3, ...}
```

La sortie plain est **juste la valeur** - pensé pour `$(rhorizon get
foo)` et `--password "$(rhorizon get foo)"`. Utiliser `--json` quand
tu veux les metadata.

### `rhorizon list` - noms uniquement

```bash
rhorizon list
#   prod/db-password         v3  [prod]
#   prod/redis-password      v1  [prod]
#   default/test             v1
# 3 secret(s)

rhorizon list --namespace mcp/demo
```

Les valeurs ne sont jamais retournées par `list` - seulement noms,
versions et namespaces.

### `rhorizon delete` - supprimer un secret

```bash
rhorizon delete prod/old-key
# Deleted: prod/old-key
```

Drop toutes les versions du secret. La chaîne d'audit le référence
toujours ; la valeur est irrécupérable.

### `rhorizon rotate` - re-chiffrer avec une nouvelle DEK

```bash
# Un secret
rhorizon rotate prod/db-password

# Tous les secrets
rhorizon rotate --all
# Rotated 47 secret(s)
```

Rotation interne : la valeur du secret est inchangée, seule la DEK
qui le chiffre est remplacée. Transparent pour les consommateurs.

Cette action reste explicitement déclenchée par l'opérateur ; aucune tâche de
fond ne rechiffre les secrets selon un calendrier. Rhorizon surveille
séparément l'âge de la `dek_key` hiérarchique et alerte lorsqu'une rotation
autorisée via `/admin/rotate-dek-key` devient nécessaire.
Une opération explicite reste scriptable. Regroupez les contrôles de readiness,
une sauvegarde chiffrée vérifiée, l'appel de rotation et les contrôles suivants
dans un même workflow de maintenance piloté par l'opérateur ; ne placez pas le
mot de passe maître dans les arguments ou les logs.

### `rhorizon versions` - lister les versions passées

```bash
rhorizon versions prod/db-password
#   v3  2026-04-29T07:45:00Z  by alice
#   v2  2026-03-12T12:01:00Z  by bob
#   v1  2026-02-01T09:30:00Z  by alice
```

L'historique est retenu jusqu'à `RH_SECRET_MAX_VERSIONS`
(défaut 10).

### `rhorizon rollback` - restaurer une version passée

```bash
rhorizon rollback prod/db-password 2
# Restored v2 -> v4
```

Crée une nouvelle version avec la valeur de la version choisie. Ne
supprime pas les versions intermédiaires - tu peux roll forward avec
un autre `rollback` si besoin.

### `rhorizon generate` - générateur de clés aléatoires

```bash
# Clé 32 caractères, tous les charsets (défaut)
rhorizon generate 32

# 64 chars, alphanumérique uniquement (pas de spéciaux)
rhorizon generate 64 --no-special

# 10 clés de 16 chars
rhorizon generate 16 -c 10

# Générer et stocker directement
rhorizon generate 48 --store prod/api-key --namespace prod
```

Charsets :

| Flag | Quoi |
|---|---|
| `-a / --no-alpha` | A-Z a-z |
| `-n / --no-numeric` | 0-9 |
| `-s / --no-special` | Ponctuation ASCII (33-47, 58-64, 91-96, 123-126) |
| `-c / --count` | Nombre de clés à générer |
| `--store NAME` | Générer, puis stocker la dernière comme `NAME` |
| `--namespace NS` | Namespace pour `--store` |

Utilise `secrets.choice` (CSPRNG) - sûr pour des credentials prod.

---

## 5. Tokens

### `rhorizon token create` - token long-lived

```bash
# Recommandé : flags --scope et --namespace
rhorizon token create my-bot --scope secrets:r --namespace mcp/mail

# Plusieurs scopes, plusieurs namespaces (répétables)
rhorizon token create deploy \
    --scope secrets:rw \
    --scope tokens:r \
    --namespace prod \
    --namespace staging

# Token: rh_xxxxxxxxxxxx
# Name:  deploy
# Perms: {"secrets":"rw","tokens":"r","namespaces":["prod","staging"]}
# (shown once - save it now)

# Fallback JSON pour permissions inhabituelles
rhorizon token create admin '{"admin":"rw"}'
```

La chaîne du token est affichée **une seule fois**. La DB ne stocke
que le hash HMAC-SHA512. Sauvegarder immédiatement ou re-créer.

### `rhorizon token list` - voir les tokens existants

```bash
rhorizon token list
#   a1b2c3d4  ansible-prod   [active]    {"secrets":"r","namespaces":["prod"]}
#   e5f6g7h8  ci-frontend    [active]    {"secrets":"r","namespaces":["ci/frontend"]}
#   i9j0k1l2  old-deploy     [REVOKED]   {"secrets":"rw"}
```

### `rhorizon token show` - détails complets

```bash
rhorizon token show a1b2c3d4    # par préfixe d'ID
rhorizon token show ansible-prod  # par nom

# ID:           a1b2c3d4-...
# Name:         ansible-prod
# Active:       true
# Permissions:  {"secrets":"r","namespaces":["prod"]}
# Created by:   alice
# Created at:   2026-04-15T10:23:00Z
# Last used:    2026-04-29T07:45:00Z
# Expires at:   (no expiry)
# Revoked at:   (not revoked)
```

### `rhorizon token revoke` - kill switch

```bash
rhorizon token revoke a1b2c3d4
# Revoked: ansible-prod
```

Effectif à la prochaine requête API - pas de délai de propagation.

### `rhorizon token renew` - étendre un éphémère

```bash
rhorizon token renew a1b2c3d4 --ttl 7200
# Renewed:  ci-build-eph
# Expires:  2026-04-29T11:00:00Z
# TTL:      7200s
```

Refuse les tokens long-lived (pas d'expiry à étendre). À utiliser
seulement pour les éphémères quand tu dois pousser la deadline.

### `rhorizon token ephemeral` - token court-lived

```bash
# Minter un token read-only de 5 min sur le namespace mcp/mail
rhorizon token ephemeral \
    --ttl 300 \
    --scope secrets:r \
    --namespace mcp/mail \
    --label claude-mail-session

# Token:    rh_eph_xxxxxx
# Name:     eph-xxxxxx
# Expires:  2026-04-29T08:30:00Z (300s)
# Perms:    {"secrets":"r","namespaces":["mcp/mail"]}
# Label:    claude-mail-session

# Pipeline-friendly : afficher seulement le token
TOK=$(rhorizon token ephemeral -q --ttl 300 -s secrets:r -n demo)
```

Contraintes (server-enforced) :

| Limite | Défaut |
|---|---|
| TTL min | 60s |
| TTL max | `RH_EPHEMERAL_MAX_TTL` (défaut 24h) |
| Scope `admin` | **interdit** |

Le reaper purge les rows expirés toutes les 5 minutes. Voir
[`SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md#25-tokens-ephemeres)
pour le rationale complet.

---

## 6. Namespaces

Helpers de regroupement légers (le namespace lui-même est implicite -
c'est juste la chaîne que tu mets dans le champ `namespace` d'un
secret).

```bash
rhorizon ns list
#   default       12 secrets
#   prod          47 secrets
#   ci/frontend   8 secrets
#   mcp/mail      3 secrets

rhorizon ns delete old-namespace
# Refuse si non-vide - drop les secrets d'abord.
```

---

## 7. Import / export

### Import depuis `.env`

```bash
rhorizon import dotenv ./prod.env --namespace prod
#   db-password
#   redis-password
#   api-key
# 3 secret(s) imported into namespace 'prod'
```

Lignes commentées (`#`) et lignes vides ignorées. `export FOO=...`
accepté. Valeurs quotées dé-quotées.

### Import depuis JSON

```bash
rhorizon import json ./backup.json
# Lit {"secrets": [...]} ou un [...] top-level
```

### Migration depuis Vault

```bash
export VAULT_ADDR=https://vault.example
export VAULT_TOKEN=...

# Dry-run par défaut. Les conflits sont renommés, jamais écrasés.
rhorizon migrate vault

# Appliquer après revue du plan.
rhorizon migrate vault --apply
```

### Migration depuis Infisical (expérimental)

```bash
export INFISICAL_ADDR=https://us.infisical.com
export INFISICAL_TOKEN=...
export INFISICAL_PROJECT_ID=...
export INFISICAL_ENVIRONMENT=prod

# Dry-run par défaut. Cet adaptateur est expérimental tant qu'il
# n'a pas été validé contre un tenant réel.
rhorizon migrate infisical --dry-run
```

Universal Auth est aussi supporté avec `INFISICAL_CLIENT_ID` et
`INFISICAL_CLIENT_SECRET`. Les conflits sont renommés par défaut.

L'export bulk en clair a été supprimé. Utilisez `rhorizon backup export`
pour les sauvegardes chiffrées age.

---

## 8. Audit

### `rhorizon audit tail` - N dernières entrées

```bash
# Défaut : 20 dernières
rhorizon audit tail

# Filtré
rhorizon audit tail -n 100 --actor mcp-agent
rhorizon audit tail --action read_secret --since 2026-04-29T00:00:00Z
rhorizon audit tail --until 2026-04-28T23:59:59Z

# Format de sortie :
#   [OK]  2026-04-29T07:45:00Z   ansible-prod              read_secret             prod/db-password
#   [OK]  2026-04-29T07:44:55Z   ci-frontend               create_secret           ci/frontend/build-id
#   [OK]  2026-04-29T07:44:30Z   alice                     unseal
#   [FAIL]  2026-04-29T07:43:00Z   bob                       login_failed
```

Le marqueur en tête est le statut d'intégrité de la chaîne :

| Marqueur | Sens |
|---|---|
| `[OK]` | Vérifié |
| `[BROKEN]` | La chaîne est cassée entre cette entrée et la précédente - investiguer |
| `[UNSIGNED]` | L'entrée n'a pas de signature (très vieille donnée, pré-feature audit-chain) |

### `rhorizon audit follow` - live tail

```bash
rhorizon audit follow
# Poll toutes les 2 secondes, affiche les nouvelles entrées au fil de l'eau
# Ctrl-C pour arrêter

rhorizon audit follow --interval 1     # poll plus rapide
```

### `rhorizon audit verify` - check intégrité chaîne

```bash
rhorizon audit verify
# [OK] Chain intact: 12,453 entries verified
```

Ou en cas d'échec :

```bash
rhorizon audit verify
# [FAIL] Chain BROKEN at entry 8,432 (timestamp 2026-04-12T15:30:00Z)
# Run `rhorizon audit tail --since 2026-04-12T14:00:00Z` to investigate
# Exit code: 2
```

À planifier quotidiennement via cron / job CI et alerter en cas de
sortie non-zero.

### `rhorizon audit export` - preuve signée portable

```bash
rhorizon audit export preuve-audit.tar.gz \
  --since 2026-08-01T00:00:00Z \
  --until 2026-08-18T00:00:00Z
```

Le seul format pris en charge est `.tar.gz`. Il contient les mutations, les
lectures, les archives scellées qui recouvrent la période, les clés publiques
des signataires, les preuves Merkle et les sceaux, ainsi qu'un manifeste
Ed25519 qui engage la taille et le SHA-256 de chaque membre. Le fichier final
n'apparaît qu'après la fin complète du téléchargement ; `--force` est requis
pour remplacer un fichier existant.

Vérification hors ligne :

```bash
rhorizon audit verify-export preuve-audit.tar.gz \
  --trusted-signer "$EMPREINTE_SIGNATAIRE_AUDIT"
```

L'empreinte de confiance doit être conservée hors du bundle. Sans cette
empreinte, la cohérence cryptographique est vérifiée mais le CLI signale que la
clé publique incluse fonctionne en trust-on-first-use.

### `rhorizon audit files` - lister les archives JSONL

```bash
rhorizon audit files
#   audit-2026-04-29.jsonl    (current, 1.2 MB)
#   audit-2026-04-28.jsonl    (yesterday, 4.8 MB)
#   audit-2026-04-22.jsonl.gz (compressed, 880 KB)
```

Le reaper compresse les fichiers plus vieux que
`RH_AUDIT_COMPRESS_DAYS` (défaut 1).

### `rhorizon audit read` - lire un jour

```bash
rhorizon audit read 2026-04-29
# Sortie JSONL, une entrée par ligne, gzip-décompressé de manière transparente
```

---

## 9. Master password

### `rhorizon master rotate` - changer le master password

```bash
# Rotation routinière (lazy migration des tokens existants)
rhorizon master rotate
# Current master password: ********
# New master password: ********
# Confirm new master password: ********
# [OK] Rotated (lazy mode)
#   DEKs re-encrypted: 47
#   Active tokens at rotation time: 12
#   prev_hmac_key stored - existing tokens keep working for ~15 days

# Rotation d'urgence (invalidation immédiate des tokens)
rhorizon master rotate --emergency
# Type 'rotate-emergency' to confirm: rotate-emergency
# [OK] Rotated (emergency mode)
#   All tokens are now invalid - re-authenticate via rhorizon login + create new tokens.
```

Deux modes - choisir le bon :

| Mode | Quand | Tokens après rotation |
|---|---|---|
| Défaut (lazy) | Hygiène routinière, pas de compromission soupçonnée | Les tokens existants continuent de marcher pendant ~15 jours ; le reaper drop le fallback ensuite |
| `--emergency` | Token / password leaké, réponse à incident | Tous les tokens invalidés immédiatement, y compris le tien - re-minter tout |

Voir [`SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md#27-rotation-de-token)
pour la discussion complète.

---

## 10. `rhorizon oneshot` - decrypt-and-die

```bash
# Le vault doit être SEALED au moment de l'appel
rhorizon oneshot prod/api-key
# Master password: ********
# La sortie est la valeur du secret sur stdout (le reste sur stderr).

rhorizon oneshot api-token --namespace mcp/linkedin --totp 123456
```

Un seul appel : unseal -> lire un secret -> re-seal. Le vault est
re-sealed **avant que la réponse soit retournée**, donc la fenêtre
unsealed est bornée par la dérivation Argon2id (~500 ms). Tout après
est sealed.

Cas d'usage : un job one-shot (CI runner, script de récup, CronJob)
qui a vraiment besoin de *un* secret sans interaction supplémentaire.
La sortie va sur stdout (script-friendly) ; les diagnostics vont sur
stderr.

Après ça, le vault est sealed. Un opérateur doit re-unseal pour que
l'opération ordinaire reprenne.

---

## 11. Cluster (inspection + cycle de vie)

Pour les déploiements HA. `rhorizon cluster status` est une vue read-only du
membership et du cycle de vie des certificats (`admin:r`), pas un control
panel.

```bash
rhorizon cluster status          # table compacte
rhorizon cluster status --json   # payload /cluster/ha complet
rhorizon cluster health          # santé live bout-en-bout par composant
rhorizon cluster health --json   # fournisseur, leader, replicas, lag, preuves
```

```text
cluster_id:        prod-7f3a
primary_uuid:      a1b2c3d4-...
ha_loaded:         true
uuid_ip_conflicts: 0

  UUID           IP                 STATE        HEARTBEAT       CERT
  a1b2c3d4       10.0.0.1         primary           3s ago     88d
  e5f6a7b8       10.0.0.1         secondary         2s ago     88d
```

Les colonnes décrivent le UUID court, l'IP source, l'état HA, l'âge du
heartbeat et l'expiry du certificat. Cette vue identifie le **primary
applicatif**, pas le leader PostgreSQL.

`cluster health` combine `database`, `database HA`, `node` et `application HA`
sans confondre leurs rôles. Contrat couleur/point :

```text
  ● vert        santé vérifiée
  ● orange      formation, recovery ou dégradation
  ● rouge       état vérifié dangereux ou indisponible
  ○ noir/gris   inconnu, désactivé ou non configuré ; jamais sain
```

La couche Database HA est observée via le fournisseur Patroni ou
`rhorizon-pgha` configuré et apparaît sous `database_ha`. Utiliser `--json`
pour les preuves propres au fournisseur : nombre de leaders, membres,
streaming, lag et timelines. Patroni fournit le nombre de leaders vérifié mais
pas l'identité du membre ; `pgha` ajoute identité du leader, fraîcheur des
agents, quorum et propriété du VIP d'écriture. Les trois termes distincts sont
**master crypto local**, **primary applicatif** et **leader de base de
données**.

Actions de cycle de vie :

```bash
rhorizon cluster init
rhorizon cluster join <addr>
rhorizon cluster promote <uuid>  # / demote / drain / evict <uuid>
rhorizon cluster rotate-cert --all   # / rotate-ca / ca-bundle
```

L'UI Web sous **Cluster -> HA** combine membership, topologie locale des
workers, locks cluster, cycle des certificats et preuves Database HA
normalisées. Ses points suivent le même contrat que le CLI.

---

## 12. Recettes

### Utiliser un secret en one-liner

```bash
DB_URL=$(rhorizon get prod/db-url) psql "$DB_URL"
```

### Minter un token éphémère pour un job CI

```bash
TOK=$(rhorizon token ephemeral -q --ttl 900 \
        --scope secrets:r --namespace ci/frontend \
        --label "ci-build-${BUILD_ID}")
RH_TOKEN=$TOK rhorizon get ci/frontend/registry-token
```

### Vérifier la chaîne en CI nightly

```bash
#!/bin/bash
# Retourne non-zero si la chaîne d'audit est cassée.
rhorizon audit verify || {
    curl -X POST "$ALERT_WEBHOOK" -d "rhorizon audit chain BROKEN"
    exit 1
}
```

### Générer, stocker et lire immédiatement un credential frais

```bash
rhorizon generate 48 --store prod/new-api-key
rhorizon get prod/new-api-key | ./register-with-third-party.sh
```

### Migrer un `.env` vers le vault

```bash
# 1. Déplacer les secrets
rhorizon import dotenv ./.env --namespace prod
# 2. Minter un token pour l'app consommatrice
rhorizon token create app-prod --scope secrets:r --namespace prod
# 3. Reconfigurer l'app pour lire depuis rhorizon (cf. USE-CASES.md)
# 4. Supprimer .env de l'hôte (pas juste .gitignore)
shred -u ./.env
```

---

## 13. Fichiers de configuration

### `~/.config/rhorizon/config.toml`

```toml
[default]
url = "http://10.0.0.20:8200"

[other-vault]
url = "http://192.168.50.10:8200"
```

Le CLI lit et écrit uniquement le profil `default`. Tu peux définir des
profils supplémentaires dans le fichier à la main, mais en sélectionner
un depuis le CLI n'est pas encore câblé.

### `~/.config/rhorizon/token.<profil>`

Le token, en clair, mode 0600 (profil default -> `token.default`). Lu à
chaque invocation du CLI selon l'ordre de résolution de la section 2 :
env `RH_TOKEN`, puis `RH_TOKEN_STDIN=1` (une ligne de stdin, jamais sur
disque), puis ce fichier.

Il n'y a pas d'override de chemin par fichier. Pour passer un token sans
ce fichier, utilise `RH_TOKEN` ou `RH_TOKEN_STDIN` ; pour relocaliser
tout le dossier config (`config.toml` et `token.<profil>`), mets
`RH_CONFIG_DIR`.

---

## 14. Codes de sortie

| Code | Sens |
|---|---|
| 0 | Succès |
| 1 | Erreur opérationnelle (réseau, vault sealed, token invalide, argument manquant, etc.) |
| 2 | Violation d'intégrité de la chaîne d'audit (émis uniquement par `audit verify`) |

---

## 15. Caveats

- **Pas de retry / backoff dans le CLI lui-même.** Une coupure réseau => exit 1. Wrap avec `until rhorizon ... do sleep 2; done` si tu en as besoin.
- **Le fichier token est ton maillon faible.** Le mode 0600 protège contre les autres users ; pas contre root ni contre ton propre historique shell si tu `cat ~/.config/rhorizon/token.default`.
- **`rhorizon get` affiche la valeur sur stdout.** C'est l'objectif - mais `set -x` dans ton script va la fuiter. Sois explicite sur ce que tu echo.
- **`oneshot` seal le vault.** Ne pas l'utiliser sur un vault qu'autre chose utilise ; tu vas embêter le reste de tes opérateurs.
