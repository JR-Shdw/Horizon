# Reprise après sinistre - rhorizon

Deux chemins de reprise existent. Ils ne sont pas interchangeables.

| Chemin | Cas d'usage | Couverture | Charge opérateur |
|------|----------|----------|-------------------|
| **`pg_dump` / `pg_restore`** | DR complet : crash de nœud, perte de datacenter, corruption de schéma, reprise à un instant donné, migration du vault vers un nouvel hôte. | **Tout** : chaque table, chaque relation, la chaîne d'audit dans son intégralité. | Du SQL brut - aucune logique applicative. Le conteneur vault est arrêté, la base restaurée, le conteneur redémarré. |
| **`/backup/restore` (API)** | Migration sélective : transporter secrets, namespaces, groupes et métadonnées de tokens d'une installation vault à une autre, par exemple pour amorcer un nouvel environnement depuis un état connu bon. | **Restauration logique partielle** : lignes de secrets courantes + DEK + namespaces + groupes + membres de groupes + config restaurable + stubs de métadonnées de tokens. **Pas** : credentials 2FA, notifications, moteurs dynamiques et leases, chaîne d'audit, historique des versions, hashes de tokens vivants ou plaintexts. | Un bouton dans l'UI. Suivi manuel ensuite : revue ou ré-enrôlement 2FA là où c'est nécessaire, recréation des canaux de notification, rotation des tokens. |

`pg_dump` est le chemin recommandé pour le DR. `/backup/restore` est un outil de migration avec des limites explicites.

---

## Chemin 1 - `pg_dump` (recommandé)

Arrêtez l'API, dumpez la base sous chiffrement symétrique `age`, et stockez l'artefact hors site.

### Sauvegarde

```bash
# Sur un hôte qui peut joindre le postgres de rhorizon
docker compose stop api
docker compose exec postgres \
    pg_dump -U rhorizon -d rhorizon --no-owner --no-privileges \
    | age -p > rhorizon-$(date +%Y%m%d-%H%M).sql.age
# saisissez une passphrase forte (32+ caractères, stockée dans votre gestionnaire de mots de passe secondaire)
docker compose start api
```

L'artefact est un fichier age-chiffré ordinaire, déchiffrable avec le seul CLI `age` ; aucune instance rhorizon n'est nécessaire pour l'inspecter.

### Restauration

```bash
# Sur l'hôte cible (vault neuf, ou existant à écraser)
docker compose down -v                          # efface le volume PG
docker compose up -d postgres
age -d rhorizon-YYYYMMDD-HHMM.sql.age \
    | docker compose exec -T postgres \
        psql -U rhorizon -d rhorizon
docker compose up -d api
```

Le vault revient exactement dans l'état du dump : même `argon2_salt`, même `master_check`, même `hmac_key` une fois descellé, chaque token détenu par un client encore valide, chaque credential 2FA enrôlé, chaque canal de notification fonctionnel, et chaque ligne d'audit chaînée comme avant.

### Cadence

- Cron quotidien via Restic vers un datacenter séparé - un RPO d'environ 24 h est acceptable selon la doctrine `~/dev/sextant/rhorizon/...`.
- Vérifiez chaque semaine que le dump se déchiffre, en passant le premier Ko dans `age -d`.
- Faites tourner la passphrase chaque trimestre et re-chiffrez le dernier dump.

---

## Chemin 2 - `/backup/restore` (migration partielle)

Déclenché depuis l'UI dans **Accretion -> Backup Vault (encrypted)** / **Restore Vault (from encrypted backup)**, ou via l'API (`POST /api/v1/vault/backup/create` / `POST /api/v1/vault/backup/restore`).

### Ce que `/backup/create` exporte

| Table | Champs transportés |
|---|---|
| `vault_secrets` | name, namespace, ciphertext, nonce, aad_version, dek_id, metadata, version, created_by, created_at, updated_at, expires_at, is_honey, deleted_at, purge_after. `dek_rotated_at` est délibérément remis à zéro par la restauration, parce que chaque secret reçoit une DEK fraîche au moment de la restauration. |
| `vault_dek` | encrypted_key, nonce (lié par AAD au dek_id) |
| `vault_namespaces` | name, owner_group_id, enforce_membership, delete_protection, archived_at |
| `vault_groups` | name, permissions, source, ldap_dn |
| `vault_group_members` | Principaux externes : group_name, principal_type, principal_id qualifié par source, added_at. Les appartenances de tokens natifs voyagent avec les métadonnées de tokens et sont rattachées au nouvel UUID de token après la rotation post-restauration. |
| `vault_config` | chaque clé/valeur restaurable. L'identité du vault en cours et les intégrations liées à la DEK ne sont **pas** écrasées : `argon2_salt`, `master_check`, `dek_key_version`, `vault_initialized`, `prev_hmac_key`, `pending_restore_*`, clés TOTP / 2FA, clés LDAP et clés d'identité d'audit restent courantes ou sont reconfigurées après la restauration. La sauvegarde porte sa propre copie d'`argon2_salt` + `master_check` + `dek_key_version` ; ils décrivent comment lire la sauvegarde, pas comment remplacer l'identité du vault courant. |
| `vault_tokens` | **métadonnées uniquement** - name, namespace, permissions, allowed_ips, expires_at, is_honey. Le hash n'est **pas** transporté : chaque restauration efface `vault_tokens` et insère les métadonnées dans `vault_pending_token_rotations`, pour qu'un admin minte explicitement un plaintext frais par token. |

Le payload est sérialisé en JSON, checksummé (SHA-256), et chiffré avec la passphrase `age` que l'opérateur saisit dans l'UI.

### La restauration exige deux credentials, pas un

L'opérateur saisit **les deux** au moment de la restauration :

- la **passphrase age** - déchiffre l'enveloppe `.age` (scrypt + ChaCha20-Poly1305) ;
- le **mot de passe maître du vault utilisé au moment de la sauvegarde** - dérive la `dek_key` côté SAUVEGARDE, pour que les DEK contenues dans le payload puissent être déballées.

Les deux credentials sont indépendants. La passphrase age seule ne suffit pas à lire un secret ; le mot de passe maître seul ne suffit pas à ouvrir l'enveloppe. Les deux doivent être conservés avec le même soin.

### Ce que la restauration *fait* - crypto à double contexte

1. Déchiffre l'enveloppe age, vérifie le checksum SHA-256 du payload JSON, et lit la version de schéma / le manifeste de couverture.
2. Construit un **contexte crypto SAUVEGARDE** à partir de l'`argon2_salt` + `master_check` + `dek_key_version` du payload et du `master_password_backup` fourni par l'opérateur. Le contexte dérive les `hmac_key` + `dek_key` de la sauvegarde par Argon2id + HKDF-SHA512 dans un `LockedBuf` Rust (mlock'd, zeroizé au `Drop`). Un mauvais mot de passe maître est détecté ici comme un désaccord de `master_check` et l'appel retourne `401` avant toute mutation de la base.
3. Efface `vault_leases`, `vault_dynamic_roles`, `vault_dynamic_engines`, `vault_secret_versions`, `vault_secrets`, `vault_notification_channels`, `vault_tokens`, `vault_dek`, `vault_pending_token_rotations`, `vault_group_members`, `vault_namespaces`, `vault_groups` - dans cet ordre sûr vis-à-vis des clés étrangères.
4. Ré-insère groupes + namespaces (`namespace.owner_group_id` est re-résolu **par nom**, parce que chaque groupe restauré reçoit un UUID frais) + principaux externes de groupes. Les principaux de tokens natifs restent sur leurs stubs de rotation en attente et sont rattachés au moment où chaque UUID de token frais est minté.
5. Pour chaque secret du payload : `BackupCryptoContext.decrypt_secret()` enchaîne déballage-de-DEK-puis-déchiffrement-du-secret en un seul appel Rust ; le format de sauvegarde v4 fournit `aad_version`, tandis que les payloads plus anciens retombent sur v1 ; une DEK fraîche est générée et enveloppée sous la `dek_key` **COURANTE** (AES-256-GCM) ; le secret est re-chiffré avec l'AAD v2 sous la nouvelle DEK (XChaCha20-Poly1305) ; les deux lignes sont insérées dans la même transaction ; le bytearray en clair est passé à `secure_zero()` dans la clause `finally`.
6. Insère chaque ligne de token comme stub dans `vault_pending_token_rotations` (le plaintext historique est perdu, seul un admin peut en minter un frais).
7. Pose deux drapeaux dans `vault_config` :
   - `pending_restore_bootstrap` - consommé par le prochain `/unseal`, qui minte un token frais `root-restore-<ts>` avec TTL = `RH_RECOVERY_TOKEN_TTL_DAYS` (7 par défaut).
   - `pending_restore_review` - pilote le panneau UI dans Settings / Core.
8. Appelle `stop_master_services()` + `vault.seal()`. Le serveur RPC est démonté, le KeyServer de share-back Shamir est fermé, et les sous-clés en RAM sont mises à zéro. Le prochain `/unseal` redémarre proprement le câblage cluster sous le mot de passe maître **COURANT** - l'opérateur n'a pas besoin de retaper le mot de passe de la sauvegarde pour rendre les données restaurées lisibles.

```mermaid
flowchart TD
    subgraph BACKUP["Contexte SAUVEGARDE (en mémoire, dans Rust)"]
        bpw["master_password_backup<br/>(saisie opérateur)"]
        bmk["master_key de sauvegarde<br/>(LockedBuf, mlock'd)"]
        bhmac["hmac_key de sauvegarde<br/>vérifie master_check -> désaccord ? lève 401"]
        bdek["dek_key de sauvegarde"]
        pdek["DEK_i en clair<br/>(pile Rust, zeroizée avant retour)"]
        psec["secret_i en clair<br/>(PyByteArray, secure_zero dans finally)"]
        bpw -->|"Argon2id(argon2_salt de la sauvegarde)"| bmk
        bmk -->|"HKDF-SHA512 info=hmac-tokens"| bhmac
        bmk -->|"HKDF-SHA512 info=dek-encrypt[-vN]"| bdek
        bdek -->|"déballage AES-256-GCM (une DEK par secret)"| pdek
        pdek -->|"déchiffrement XChaCha20-Poly1305"| psec
    end
    subgraph CURRENT["Contexte COURANT (persisté)"]
        cmk["master_key courante<br/>(déjà en RAM)"]
        cdek["dek_key courante"]
        cmk --> cdek
    end
    psec -->|"re-chiffrement sous une DEK_i' fraîche enveloppée par la dek_key courante"| ins["INSERT vault_dek + vault_secrets"]
    cdek --> ins
    ins -.->|"à la sortie : del backup_ctx"| z["Le Drop Rust zeroize master_key + hmac_key + dek_key, démlock les pages"]
```

Trois propriétés découlent du fait de faire tourner la restauration dans deux contextes :

- **Rotation crypto gratuite de chaque secret.** Chaque restauration re-tire chaque DEK et chaque nonce XChaCha20. Un cycle sauvegarde-restauration équivaut à une rotation complète en masse, sans coût supplémentaire.
- **La dérive du mot de passe maître est supportée.** Restaurer une sauvegarde prise il y a six mois, sous un mot de passe maître différent, sur un vault qui a depuis fait tourner le sien, est un cas d'usage normal. Aucun des deux côtés n'écrase l'autre.
- **Le plaintext n'entre jamais dans Python sur le chemin rapide.**
  `rotate_secret()` enchaîne déchiffrer-sous-SAUVEGARDE et chiffrer-sous-COURANT
  en un seul appel Rust, donc ni le secret en clair ni aucune des deux DEK ne
  traverse la frontière. Le `LockedBuf` du `BackupCryptoContext` met quand même
  à zéro master_key + hmac_key + dek_key au `Drop`, et le plaintext transitoire
  est zeroizé à l'intérieur de Rust sur tous les chemins de sortie, chemins
  d'erreur compris. Voir [les deux chemins de restauration](#les-deux-chemins-de-restauration)
  plus bas pour le seul cas qui repasse encore par Python.

### Déroulé de reprise pour l'opérateur

```mermaid
flowchart TD
    a["/backup/restore retourne sealed=true"]
    b["/unseal avec le mot de passe maître COURANT du vault<br/>(PAS celui de la sauvegarde - le mot de passe de sauvegarde n'était nécessaire<br/>que pendant l'appel de restauration lui-même, pour déballer les DEK côté SAUVEGARDE)"]
    c["la réponse porte un root_token frais (root-restore-&lt;ts&gt;)<br/>affiché une fois, TTL 7 jours, scope admin:rw"]
    d["Quasar -> Pending rotations : Show & Rotate chaque token<br/>dont vous avez encore besoin, Revoke le reste"]
    e["Reconfigurer : YubiKeys, WebAuthn, TOTP, canaux de notification,<br/>moteurs dynamiques (voir la checklist du panneau Settings)"]
    f["Créer un root token frais de longue durée"]
    g["Settings -> Mark as reviewed -> le root token de reprise est révoqué,<br/>le drapeau pending_restore_review est effacé"]
    a --> b --> c --> d --> e --> f --> g
```

### À reconfigurer après une restauration

Ces tables et surfaces de config sont hors de la sauvegarde logique par l'API.
Sur une cible neuve elles sont absentes ; sur une restauration en place, des
lignes côté cible qui ne sont pas dans la liste d'effacement peuvent subsister,
mais elles ne sont jamais importées depuis la sauvegarde. Passez chacune en
revue délibérément :

| Table | Pourquoi | Ce que vous faites |
|---|---|---|
| `vault_yubikeys` | Non importée depuis la sauvegarde. Les secrets HMAC côté sauvegarde sont liés à la DEK et exigeraient un re-keying explicite ; des lignes existantes côté cible peuvent subsister sur une restauration en place. | Vérifiez les enregistrements courants de la cible ; ré-enrôlez via Settings -> Two-Factor Authentication quand vous passez sur une cible neuve. |
| `vault_webauthn` | Non importée depuis la sauvegarde. Les clés publiques pourraient en principe être déplacées, mais l'opérateur devrait ré-attester depuis la vraie clé de sécurité pour maintenir la chaîne de possession. Des lignes existantes côté cible peuvent subsister sur une restauration en place. | Vérifiez les enregistrements courants de la cible ; ré-enregistrez depuis chaque périphérique FIDO2 quand vous passez sur une cible neuve. |
| Clés `vault_config` du secret TOTP | Non importées depuis la sauvegarde. La matière TOTP côté sauvegarde est liée à la DEK ; le mode 2FA courant du vault cible est laissé intact, pour qu'une restauration ne puisse jamais vous verrouiller hors du descellement. | Vérifiez la 2FA courante de la cible ; reconfigurez TOTP quand vous passez sur une cible neuve. |
| Clés `vault_config` de LDAP (`ldap_config`, `ldap_group_mappings`) | Non importées depuis la sauvegarde. La matière de bind LDAP côté sauvegarde est liée à la DEK et sa DEK autonome n'est pas transportée. | Reconfigurez LDAP dans Settings. |
| Identité de chaîne d'audit dans `vault_config` (`audit_identity_seed_enc`, `audit_identity_pub`, `key_epoch`) | Appartient à la chaîne d'audit du vault courant, qui n'est pas importée depuis la sauvegarde (voir `vault_audit` plus bas). | Conservée sur une cible en place ; amorcée automatiquement au prochain descellement si absente. |
| `vault_notification_channels` | Effacée par la restauration logique. La config d'un canal peut contenir des URLs de livraison externes ou des tokens, et n'est pas transportée dans la sauvegarde par API. | Recréez les canaux Matrix / webhook / email dans Pulsar, puis envoyez une alerte de test. |
| `vault_dynamic_engines` / `vault_dynamic_roles` / `vault_leases` | `connection_url` et les credentials sont chiffrés sous `dek_key`. Des leases actifs pointeraient vers des utilisateurs qui n'existent plus sur les bases cibles. | Redéclarez moteurs et rôles ; laissez les nouveaux credentials se propager naturellement dans vos applications. |
| `vault_secret_versions` | Historique des versions passées de chaque secret, chiffrées sous leurs DEK d'origine. Les transporter gonflerait substantiellement la sauvegarde pour peu de bénéfice opérationnel ; la version courante suffit au basculement. | S'il vous faut une version historique précise, restaurez depuis un `pg_dump` de cette date-là. |
| `vault_audit` | La sauvegarde par API ne transporte pas les lignes d'audit. Une cible neuve démarre sa propre chaîne ; une cible en place garde sa chaîne existante et enregistre l'événement de restauration sous l'identité d'audit courante. | Conservez les logs JSONL archivés comme preuve pré-migration et lancez `/audit/verify` après le descellement. |
| Revue de la campagne honey | Les métadonnées `is_honey` des secrets et des tokens sont préservées, mais le catalogue de leurres reste spécifique à l'environnement. | Passez en revue et re-semez les leurres manquants via `tools/seed_honey.py`. |

### Rotations de tokens en attente - cycle de vie

- Un stub reste dans `vault_pending_token_rotations` jusqu'à ce qu'un admin le fasse tourner ou le révoque via l'UI.
- Le reaper purge tout stub plus vieux que `RH_RESTORE_ROTATION_GRACE_DAYS` (30 par défaut, borné 7-90). Passé ce délai, l'identifiant historique est perdu - équivalent à une révocation tardive. L'admin doit recréer un token sous ce nom s'il en a encore besoin.
- La rotation supplante tout token actif préexistant de `vault_tokens` portant le nom du stub : l'ancienne ligne est révoquée (`active=false`, `revoked_at=NOW()`) et le nouveau plaintext prend sa place.
- Le token fraîchement minté porte un badge vert `NEW` dans l'onglet Tokens pendant 7 jours, jusqu'à sa première utilisation (`last_used_at` posé).

### Matrice de permissions sur les nouveaux endpoints

| Endpoint | Scope requis | Contrôle de namespace |
|---|---|---|
| `GET /tokens/pending/` | `tokens:r` | filtré sur la claim `namespaces` de l'appelant, s'il y en a une |
| `POST /tokens/pending/{id}/rotate` | `tokens:w` | `check_namespace` sur le namespace du stub |
| `DELETE /tokens/pending/{id}` | `tokens:w` | `check_namespace` sur le namespace du stub |
| `POST /vault/post-restore-review/dismiss` | `admin:w` | aucun (opération globale) |

Un sous-admin de namespace se représente avec les scopes existants :

```json
{"secrets": "rw", "tokens": "rw", "namespaces": ["prod"]}
```

Ce token peut faire tourner ou révoquer les stubs en attente scopés sur `prod` et faire du CRUD de secrets dans `prod`, mais ne peut ni sceller, ni desceller, ni écarter le panneau de revue post-restauration.

### Si le mot de passe maître de la sauvegarde est perdu

Il n'y a aucun chemin de reprise. La `dek_key` côté SAUVEGARDE est dérivée du mot de passe maître via Argon2id ; sans le mot de passe, les DEK contenues dans le payload ne peuvent pas être déballées, et les secrets ne peuvent pas être lus. La passphrase age déchiffre l'*enveloppe*, pas les secrets eux-mêmes - les deux credentials sont requis, indépendamment.

C'est voulu, et ça correspond au modèle de menace de `pg_dump | age -p` sans la passphrase. Une sauvegarde dont le mot de passe maître est irrécupérable équivaut à du charabia chiffré. Stockez le mot de passe maître dans le même coffre hors ligne que la passphrase age.

Si seule la **passphrase age** est perdue, la même conclusion s'applique en sens inverse : l'enveloppe ne peut pas être ouverte, et le reste de la chaîne ne tourne jamais.

### Les deux chemins de restauration

`BackupCryptoContext.rotate_secret()` est **livré**. La restauration prend l'un
de deux chemins par secret, décidé par le fait que le worker qui traite la
requête détienne ou non les sous-clés :

| | Chemin rapide | Repli |
|---|---|---|
| Quand | Le worker est le master crypto local (ou en mode mono-worker) | Le worker est un follower - `rotate_secret_from_backup()` retourne `None` |
| Comment | `rotate_secret()` enchaîne déchiffrer-sous-SAUVEGARDE + chiffrer-sous-COURANT en **un seul appel Rust** | `decrypt_secret()` retourne un `PyByteArray`, Python ré-enveloppe sous le contexte COURANT |
| Plaintext dans le tas CPython | **Jamais** | Le temps d'une itération de boucle, puis `secure_zero()` dans un `finally` |

Le chemin rapide supprime le résidu que cette section décrivait autrefois : un
dump du tas Python pendant la fenêtre de restauration ne fuite rien, parce que
le plaintext et les deux DEK restent du côté Rust.

Le repli existe parce que seul le master détient les sous-clés. Le dispatcher
par RPC aurait signifié payer la dérivation Argon2id par secret plutôt que par
restauration, donc le cas follower conserve l'aller-retour Python avec une
zeroization explicite. Les restaurations pilotées contre le master - le cas
normal, et toujours vrai en mode mono-worker - prennent le chemin rapide de
bout en bout.

---

## Break-glass - `tools/emergency_root_token.py`

Si le flux de restauration lui-même échoue à mi-parcours (réseau interrompu, crash du conteneur en pleine restauration, `argon2_salt` modifié à la main, ...), l'opérateur peut se retrouver verrouillé dehors sans root token utilisable.

`tools/emergency_root_token.py` re-dérive la `hmac_key` courante depuis le mot de passe maître et l'`argon2_salt` en base, génère un plaintext de root token frais, calcule son hash, et l'INSERT directement dans `vault_tokens`. Le script a besoin de :

- le mot de passe maître (saisi sur stdin),
- un accès PostgreSQL direct (typiquement en `docker cp`-iant le fichier dans le conteneur API).

Il refuse de tourner si un root token actif existe déjà, sauf si `--force` est passé, pour ne pas doubler silencieusement la surface d'attaque. L'opération est journalisée en audit comme `recovery-token-mint`.

```bash
docker cp tools/emergency_root_token.py rhorizon_api:/tmp/recovery.py
docker exec -it rhorizon_api env \
    RH_DB_URL="postgresql://rhorizon:${POSTGRES_PASSWORD}@postgres:5432/rhorizon" \
    python3 /tmp/recovery.py
```

Ce chemin est un dernier recours. La route normale est `/backup/restore` -> `/unseal` (qui minte le root token de reprise automatiquement).

### Second facteur de break-glass (optionnel)

Par défaut l'outil n'a besoin que du mot de passe maître + d'un accès base. C'est le secret racine du vault, donc ce n'est pas un contournement de privilège -- mais ça réduit « mot de passe maître + périphérique 2FA » à « mot de passe maître + écriture en base » : quiconque détient les deux minte un token admin sans second facteur. Si votre modèle de menace en demande plus, armez un second facteur de break-glass.

Armez-le en posant `vault_config.break_glass_2fa` à l'une des valeurs `totp | yubikey | fido2 | shamir`. Une fois armé il n'y a **aucun contournement** -- un facteur valide est obligatoire. C'est le but, et c'est le risque : gardez une sauvegarde du facteur (une graine de rechange, une clé FIDO2 de secours, M détenteurs de parts joignables) ou vous vous verrouillez aussi hors de la reprise. Si la valeur est posée mais que le facteur n'est pas encore implémenté dans l'outil, l'outil **refuse de minter** plutôt que de le sauter -- fail-closed, jamais fall-open.

Un facteur n'ajoute une protection contre un attaquant qui a le mot de passe
maître plus la base que si son vérifieur est stocké **hors de portée de cet
attaquant** :

| Facteur | Protège contre mot de passe maître + base ? | Automatisable (HA non assistée) ? | Notes |
|---|---|---|---|
| **totp** | Seulement si la graine est stockée indépendamment de la clé maître (voir plus bas) ; la graine enrôlée dans le vault est déchiffrable par le master | **Oui** -- un code se calcule depuis la graine | Le plus simple ; le seul facteur automatisable -> permet à un contrôleur HA de piloter le break-glass sans assistance |
| **yubikey** (HMAC-SHA1) | Seulement si le secret vérifieur est stocké indépendamment | Non -- exige le token physique | Hors ligne/CLI ; *(prévu)* |
| **fido2 / webauthn** | **Oui**, si l'authentificateur et le processus d'enrôlement restent de confiance -- clé publique en base, clé privée dans le matériel | Non -- exige la présence de l'utilisateur | Résistant à une compromission base-plus-mot-de-passe ; exige la clé présente là où l'outil tourne ; *(prévu)* |
| **shamir** (M-parmi-N) | **Oui**, si les parts sont indépendantes et que le seuil reste non compromis | Partiellement (seulement si des agents détiennent des parts) | Réutilise le Shamir du vault et supprime la décision de reprise à détenteur unique ; *(prévu)* |

`totp` est câblé aujourd'hui. Sa graine est lue dans cet ordre :

1. **`RH_BREAK_GLASS_TOTP_SECRET`** (env) -- une graine hors-bande qui n'est **pas** en base. C'est la seule source qui résiste à un attaquant mot-de-passe-maître+base, et celle qu'un contrôleur HA injecte pour se rétablir sans assistance. À utiliser pour le cas durci / automatisé.
2. **`vault_config.totp_secret`** -- le TOTP de descellement enrôlé, déchiffré avec la `dek_key` dérivée du mot de passe. Confort/réutilisation : ça bloque un mésusage mot-de-passe-seul et ça active le chemin d'automatisation HA, mais un attaquant mot-de-passe-maître+base peut aussi le déchiffrer, donc ce **n'est pas** une preuve contre cet attaquant plus fort. Pour ça, utilisez `fido2` ou `shamir`.

`totp` est le seul facteur listé qu'une machine peut fournir. Un contrôleur HA
peut donc utiliser une graine TOTP détenue séparément pour une reprise non
assistée ; `fido2`/`yubikey` exigent la présence d'un utilisateur et bloquent
cette automatisation. Choisissez le facteur d'après le modèle de menace :
`totp` pour une reprise automatisable, `fido2` pour une présence utilisateur
adossée au matériel, ou `shamir` quand la reprise doit exiger un quorum.

Le facteur vérifié est enregistré dans la ligne d'audit du break-glass (`second_factor`).
