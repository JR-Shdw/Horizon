# Matrice de compatibilité

Ce sur quoi rhorizon tourne et ce avec quoi il s'intègre. Légende des statuts :

- **Testé** : exercé en CI ou sur une VM/hôte réel, fait partie de la surface de support.
- **Supporté** : construit et censé fonctionner ; hors de la boucle de tests automatisée.
- **Expérimental** : utilisable, aspérités, aucune garantie.
- **Prévu** : pas encore, suivi.

Ce qui n'est pas listé n'est ni bloqué ni promis — ouvrez une issue.

Comment chaque affirmation **Testé** est prouvée avant une release :
[SHIP-VALIDATION.md](../SHIP-VALIDATION.md) (EN). La checklist de composants
par-OS utilisée pour réévaluer le support vit dans
[`os-validation/`](../os-validation/) (EN).

## Systèmes d'exploitation

| OS | Statut | Notes |
|---|---|---|
| Debian / Ubuntu | Testé | Debian 13 est la voie de validation stable actuelle ; Debian 12 gardée comme référence oldstable. `tools/install-debian.sh`, `install-ubuntu.sh` ; la CI tourne sur Debian |
| Arch Linux | Testé | `tools/install-arch.sh` |
| Rocky / famille RHEL | Testé | l'install native descelle sous SELinux **enforcing** avec la politique confinée `tools/selinux/rhorizon.te` livrée, 0 AVC (Rocky 10.2, 2026-07-12) ; suite complète verte aussi sur Rocky 9 (2026-06-19) ; `tools/install-rocky.sh` |
| openSUSE | Testé | suite complète verte dans une VM openSUSE Leap 15.6 (AppArmor, 2026-06-19) ; Leap 16.0 est la voie de revalidation actuelle. `tools/install-opensuse.sh` |
| FreeBSD 14.x | Testé | suite complète verte (1753 passed) sur une VM 14.x après le correctif de login-class `memorylocked=unlimited` dans `install-freebsd.sh` (le vault mlock la matière clé) ; `tools/install-freebsd.sh` |
| OpenBSD 7.x | Testé | **1753 passed** sur une VM 7.8, mTLS du cluster HA compris. Le module `ssl` de CPython contre la LibreSSL de base ne sait pas charger les certs cluster Ed25519, donc `install-openbsd.sh` construit CPython 3.12 depuis les sources contre le port OpenSSL (eopenssl36), Ed25519 conservé. `tools/install-openbsd.sh` |
| NetBSD 10.x | Testé | suite complète verte sur une VM 10.1 (golden construite par anita) ; `tools/install-netbsd.sh` |
| Windows (WSL2) | Supporté | via le conteneur Linux ou le chemin natif sous WSL2 |
| macOS (Apple Silicon) | Testé | `tools/install-macos.sh --mode user` tourne vert de bout en bout sur le `macos-latest` hébergé par GitHub (`.github/workflows/macos-native.yml`) : dépendances Homebrew, PostgreSQL, venv, wheel de l'extension Rust (construite, importée, AEAD round-trippé), LaunchAgent, premier descellement. Mode utilisateur uniquement |
| macOS (Intel) | Non testé | Pas connu comme cassé, mais non mesuré : GitHub a retiré l'image `macos-13` et il n'existe pas de runner darwin x86_64 gratuit pour la remplacer |
| Stack Linux aarch64 | Validé | matériel Raspberry Pi 4 ; stack complète : PostgreSQL 18 + API + crypto Rust + frontend |
| Agent arm64 (rh-fetch/inject/watch) | Vérifié (émulé) | Se construit pour arm64 (y compris sous QEMU) via les bindings pré-générées d'aws-lc-sys (`aws-lc-rs` sans `bindgen` — pas de panique libclang). TLS post-quantique (X25519MLKEM768) préservé, vérifié sur le fil par `tools/pq-verify.sh` (OpenSSL 3.5 et aws-lc-rs le négocient tous les deux). Construit en multi-arch dans la CI (`build.yml`). |

## Gestion des services / init

| Gestionnaire | Statut | Notes |
|---|---|---|
| systemd | Testé | unit native (`rhorizon-api`) sur Linux |
| OpenRC / `rc.d` BSD | Testé | scripts `rc.d` pour FreeBSD/OpenBSD |
| Repli nohup | Supporté | quand aucun gestionnaire de services n'est présent (quickstart laptop/natif) |

## Conteneurs et orchestration

| Plateforme | Statut | Notes |
|---|---|---|
| Docker / Docker Compose | Testé | déploiement principal ; compose durci livré |
| Podman (rootless) | Testé | tourne en rootless ; relever `RLIMIT_MEMLOCK` pour mlock |
| Kubernetes | Testé | chart Helm (`helm/rhorizon`) : api + frontend + Postgres se déploient, descellent, et prennent la forme cluster multi-worker sur un vrai cluster. `make k8s-e2e` (k3d) le garde ; également joué contre un Patroni externe |
| k3s | Testé | même chart Helm, validé sur k3s (le palier `make k8s-e2e` monte k3d/k3s) |

## Datastore (le stockage propre du vault)

| Backend | Statut | Notes |
|---|---|---|
| PostgreSQL 18 | Testé | le seul store supporté, et le seul majeur capable de négocier le KEM hybride post-quantique (X25519MLKEM768) sur le lien API-vers-base — `ssl_groups` est un GUC PG18+. Sur un majeur plus ancien le compose démarre quand même, mais ce lien retombe sur un échange de clés classique. |
| Database HA : Patroni | Testé | topologie de référence Linux/Kubernetes : PostgreSQL 18 + Patroni + etcd + HAProxy + VIP keepalived, multi-nœuds |
| Database HA : `rhorizon-pgha` | Supporté | fournisseur BSD-natif à quorum de pairs pour FreeBSD/OpenBSD/NetBSD ; son `/status` s'intègre à la santé `database_ha` neutre de rhorizon. Le fournisseur a des preuves de lab, mais ce dépôt ne le fait pas encore tourner dans la voie de release automatisée ; un membre fencé/périmé exige aujourd'hui un rejoin opérateur. Voir [la conception et les preuves `pgha`](PGHA.md). |

## Authentification opérateur

| Mécanisme | Statut | Notes |
|---|---|---|
| Master password (Argon2id) | Testé | toujours requis |
| TOTP (RFC 6238) | Testé | second facteur |
| YubiKey HMAC-SHA1 | Testé | second facteur, adapté CLI/automatisation |
| WebAuthn / FIDO2 | Testé | second facteur, natif navigateur |
| Bind LDAP / AD | Testé | bind-auth en direct contre un lldap déployé (node-5, 2026-06-19) : vrai bind -> mapping de groupe (lldap_admin) -> token de session scopé ; mauvais mot de passe refusé |
| En-têtes SSO proxy | Testé | IP de confiance + `Remote-User` / `Remote-Groups` -> mapping de groupe -> token de session, exercé en CI (`test_proxy_auth.py`). Fonctionne avec Authelia / Authentik / Keycloak |

## Livraison des secrets (vers les applications consommatrices)

| Pattern | Statut | Notes |
|---|---|---|
| `rh-fetch` (init container + `*_FILE`) | Testé | logique du binaire ; fichier tmpfs en mode 0400 ; pour les apps qui honorent `*_FILE` |
| `rh-watch` (sidecar, rotation + reload) | Testé | logique du binaire ; swap atomique + signal de reload optionnel |
| `rh-inject` (variables d'env) | Testé | logique du binaire ; wrapper exec pour les apps env-only |
| ESO (External Secrets Operator) | Expérimental | fournisseur Go dans `eso-provider/`, destiné à une PR upstream external-secrets ; PQ-capable par défaut (Go 1.25, pas de `CurvePreferences`) ; non mergé, pas encore de test de handshake PQ |
| MCP (agents LLM) | Testé | surface d'outils en lecture seule ; **policy fail-closed validée** (9 tests, `mcp/tests/test_policy.py`), refuse tout ce qui n'est pas whitelisté, gating par-appel dans `call_tool` ; les tools sont des wrappers policy-gated au-dessus de l'API vault testée |

> **Caveat sur le statut des `rh-*`.** « Testé » ci-dessus désigne la **logique
> du binaire** — `tests/test_agent.py` plus les scripts live dans
> `eso-provider/test-live/` (`b2_rhfetch_real.sh`, `b3_rhwatch_rotation.sh`).
> Le déploiement de bout en bout sur **Docker / Podman / k3s** n'est **pas
> encore dans la boucle automatisée** (voie 2 de SHIP-VALIDATION, en attente).

## Secrets dynamiques (générés à la demande, avec lease)

| Backend | Statut | Notes |
|---|---|---|
| PostgreSQL 18 | Testé | CREATE/DROP ROLE, TTL avec lease |
| MySQL / MariaDB | Testé | cycle de vie complet du lease prouvé sur MariaDB 11 + MySQL 8.x en direct : le credential émis se connecte et exécute une requête, puis la connexion est refusée après révocation (node-5, 2026-06-19) |
| LDAP / lldap | Testé | validé contre lldap ; add LDIF + Password-Modify RFC 3062. Les autres produits LDAP sont acceptés comme connectés mais non validés. |
| Redis 6+ ACL | Implémenté | module isolé, cycle de vie des commandes ACL contraint et tests unitaires ; une validation sur cible live reste nécessaire avant promotion en Testé |
| Auth par rôle Apache Cassandra | Implémenté | module isolé TLS-par-défaut et tests unitaires ; une validation sur cible live reste nécessaire avant promotion en Testé |
| Collection Ansible | Implémenté | modules mint/revoke séparés, vérification TLS et tests d'erreurs secret-safe ; le packaging de la collection et un play live restent à valider |

## Observabilité

| Outil | Statut | Notes |
|---|---|---|
| Prometheus | Testé | exposition `/metrics`, IP-allow-listée |
| Grafana | Testé | les dashboards overview, cluster et HA-bench ont été capturés contre une instance 5-workers vivante. Le dashboard opérations HA/WAL neutre est livré et validé structurellement ; ses panneaux Patroni/PostgreSQL/WAL profonds exigent les entrées de scrape documentées dans `docs/dashboards/README.md` et ne sont pas couverts par la capture mono-instance. |

## Notifications

| Canal | Statut | Notes |
|---|---|---|
| Matrix | Testé | canal natif |
| Webhook (générique) | Testé | POST JSON vers n'importe quel endpoint ; **protégé contre le SSRF** : refuse les destinations loopback/privées/link-local/metadata (y compris les astuces `127.1` / IP décimale), vérifié en direct ; logique de livraison testée unitairement |
| Email (SMTP) | Testé | livraison réelle vérifiée vers un serveur SMTP vivant (mailhog) via le chemin d'envoi SMTP ; `smtp_host` est protégé contre le SSRF (node-5, 2026-06-19) |
