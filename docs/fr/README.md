<!--
-----------------------------------------------------------------------------
Resurgamus Horizon - (c) 2024-2026 shdw <horizon@resurgamus.com> - AGPL-3.0
Vault de secrets self-hosted
-----------------------------------------------------------------------------
-->

<h1>
  <img src="../img/icon.png" alt="" height="40" valign="middle">
  Resurgamus Horizon
</h1>

**Gestionnaire de secrets et vault self-hosted, open source et léger. Pas de
SaaS, pas de télémétrie, pas de lock-in.**

Resurgamus Horizon (`rhorizon` pour faire court) garde vos mots de
passe, tokens d'API, clés TLS, credentials de bases de données et clés
SSH chiffrés au repos, servis par une petite API HTTP qui s'intègre
avec Ansible, la CI/CD, Kubernetes, les scripts et les agents IA.

Il embarque un serveur MCP natif et un MCP Hub : il sert donc aussi de **vault
IA** et de **vault MCP**. Un agent peut détenir des credentials scopés,
auditables et révocables, ou en utiliser un via Horizon sans jamais pouvoir le
lire. Toutes les fonctionnalités sont publiques ; il n'y a pas d'édition
Enterprise qui en retienne une partie.

> **Tu utilises Cursor, Cline, Claude Desktop ou opencode avec des
> credentials client ?** Le quickstart local sort ces credentials du
> chat et des fichiers `.env` lisibles, puis donne à l'assistant un
> accès explicite, limité et audité :
>
> ```bash
> # Path container (Docker - Mac + Windows + Linux) :
> curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop.sh | bash
>
> # Path natif (sans Docker - Linux + WSL2 uniquement) :
> curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/quickstart-laptop-native.sh | bash
> ```
>
> Lis le script avant de l'exécuter. Le setup et ses frontières de
> confiance sont décrits dans [`QUICKSTART-AI.md`](QUICKSTART-AI.md).

> 🇬🇧 English documentation: [`README.md`](../../README.md)
> Les pages françaises sont un sous-ensemble maintenu ; les liens marqués
> _(EN)_ restent les références canoniques tant qu'ils ne sont pas traduits.

---

## Objectifs de conception

- **Auto-hébergeable sur une seule VM** avec Docker Compose. Pas de cluster multi-nœuds en prérequis.
- **Aucune dépendance SaaS.** Pas de phone-home, pas de control plane sous licence, pas de clé d'API tierce dans le chemin de vos autres secrets.
- **Sealed par défaut.** Après chaque reboot, le vault ne tient rien en RAM. Un opérateur (ou un quorum d'opérateurs, via Shamir Secret Sharing) le remet en ligne.
- **AGPL-3.0.** Toute modification doit être publiée ; le rehosting closed-source n'est pas autorisé. Une licence commerciale existe pour les cas où l'AGPL est incompatible.

---

## Fonctionnalités en un coup d'œil

- **Chiffrement au repos** - chaque secret a sa propre Data Encryption Key (DEK), wrappée sous une clé dérivée du master. Un dump de la DB tout seul ne sert à rien.
- **Machine d'état sealed-by-default** - les clés vivent en RAM uniquement, dérivées d'un master password à l'unseal.
- **2FA à l'unseal** - WebAuthn/FIDO2 (browser), YubiKey HMAC-SHA1 (CLI), TOTP (RFC 6238). Mix and match.
- **Shamir Secret Sharing** - découpage de la master key M-sur-N pour éviter le point unique opérateur.
- **Auth tokens HMAC-SHA512** - lookup O(1), hashés en DB, révocation immédiate. Scoping namespace optionnel (`{"secrets": "rw", "namespaces": ["prod"]}`).
- **Tokens éphémères** - TTL de 60s à 24h, scopés, jamais réutilisables. Pensés pour les CI runners et les jobs one-shot.
- **Audit tamper-evident** - chaîne de mutations signée Ed25519 (HMAC-SHA512 legacy/fallback) et lectures protégées par des checkpoints Merkle signés et des archives scellées.
- **Multi-worker, optionnellement clusterisé** - RPC locale via socket Unix
  sous `/run/rhorizon`, shares Shamir distribuées et failover automatique. Le
  cluster applicatif s'appuie sur une couche Database HA supervisée :
  Patroni est la référence Linux/Kubernetes testée ;
  [`rhorizon-pgha`](PGHA.md)
  est supporté nativement sous BSD.
- **Containers durcis** - filesystem read-only, non-root uid 1500, `cap_drop ALL`, `no-new-privileges`, tmpfs `noexec/nosuid`, limites pids/mémoire.
- **Protection mémoire** - extension Rust avec `mlock` (pas de swap) et `zeroize` au drop garanti par le compilateur. La wrap key n'entre jamais dans le heap Python.
- **HTTPS natif** - nginx bundle + montage cert/key. Pas de reverse proxy requis (mais supporté via labels génériques).
- **Auth externe** - LDAP/AD bind, SSO via headers de reverse-proxy (compatible Authelia / Authentik / Keycloak / oauth2-proxy).
- **MCP (Model Context Protocol)** - intégration agent fail-closed avec policy whitelist, pour les assistants IA et agents autonomes.
- **Sauvegarde & restauration** - DR PostgreSQL complète plus backups logiques chiffrés age pour les stacks vierges.
- **fail2ban-friendly** - chaque échec d'authentification est logué dans un format parseable.
- **Posture de sécurité documentée** - mappings MITRE ATT&CK + OWASP ASVS L2, matrice de contrôles NIS2 Art. 21, provenance de build SLSA, releases signées reproductibles et tests sécurité dans le gate de release.

---

## Essai local

```bash
git clone https://github.com/JR-Shdw/Horizon.git rhorizon
cd rhorizon
sh tools/install.sh
```

Ça prend le chemin conteneur, monte un stack limité à localhost, et affiche
l'URL et l'étape suivante. **Le TLS est obligatoire et mis en place pour
vous** : l'installeur génère un certificat auto-signé, donc l'UI est sur
`https://127.0.0.1:8443`. Le navigateur affiche donc une alerte à la première
visite. **Ce n'est pas un échec de chiffrement :** HTTPS est actif, mais le
certificat est auto-signé et le navigateur ne le connaît pas encore. Comparez
son empreinte SHA-256 à celle affichée
par l'installeur avant de l'accepter. Voir [la confiance TLS selon la
plateforme](TLS.md#premiere-visite-dans-le-navigateur-installation-home).
Choisissez ensuite le mot de passe maître et effectuez le premier descellement.
Stockez le root token à usage unique dans un gestionnaire de mots de passe ; ne
le mettez ni dans un chat, ni dans l'historique du shell, ni dans le contrôle de
version.

Pour supprimer l'alerte, importez ce certificat vérifié dans le magasin de
confiance du navigateur ou du système. L'autre possibilité, adaptée à une
instance partagée, est d'utiliser un domaine contrôlé et un certificat d'une CA
publique telle que Let's Encrypt. Le certificat peut être gratuit, mais une CA
publique ne peut pas certifier `localhost` ni une adresse IP privée.

L'installeur affiche aussi deux lignes à ajouter à votre profil shell. Le
chemin du certificat est ce qui rend le certificat généré digne de confiance
pour le CLI et les agents `rh-*`. Sans lui ils refusent de se connecter, à
juste titre, et il n'existe pas d'option skip-verify :

```bash
export RH_ADDR=https://127.0.0.1:8443
export RH_CA_FILE=~/rhorizon/certs/cert.pem
```

Guide complet : [`docs/fr/QUICKSTART.md`](QUICKSTART.md). La référence
d'installation complète (tous les chemins, vérification, mise à jour,
désinstallation) est dans [`docs/fr/INSTALL.md`](INSTALL.md).

---

## Descellement automatique

Le vault ne garde sa clé maîtresse qu'en RAM : il revient donc **scellé** après
chaque redémarrage, et quelqu'un doit fournir à nouveau le mot de passe
maître. Par défaut les installeurs le laissent scellé et n'écrivent rien sur
disque -- tu choisis le mot de passe au premier descellement.

Si une machine doit repartir seule après un reboot, passe le mot de passe à
l'installation :

```bash
sh tools/install.sh --master-password-file /chemin/vers/passphrase
```

L'installeur descelle alors pour toi et stocke les deux credentials, un secret
par fichier :

```
<repertoire-install>/secrets/master-password   # 0400
<repertoire-install>/secrets/root-token        # 0400, premier descellement seulement
```

Les installs container utilisent `~/rhorizon/secrets/` ; les installs natives
`<config-dir>/secrets/` (`~/.config/rhorizon/secrets/` en mode user). Relancer
l'installeur après un reboot ou un changement de `--tier` réutilise ce fichier
et rouvre le vault sans rien demander.

Préfère `--master-password-file` à `--master-password` : une valeur passée en
ligne de commande est lisible dans `/proc/<pid>/cmdline` pendant que
l'installeur tourne, et atterrit dans ton historique shell.

**Comprends ce que tu échanges.** Descellement automatique et protection au
repos sont le même fait vu des deux côtés : la machine peut rouvrir le vault
sans surveillance *précisément parce que* le mot de passe est lisible sur cette
machine. Quiconque -- ou quoi que ce soit -- capable de lire ces deux fichiers
possède le vault. Aucune configuration ne donne les deux à la fois.

### Garder les credentials hors de portée d'un agent IA

`0400` veut dire « seul l'utilisateur propriétaire peut lire ». Ça arrête les
autres utilisateurs non privilégiés de la machine. Ça n'arrête **pas** ce qui
tourne *en tant que* cet utilisateur, et un assistant de code IA avec accès
shell sur ton compte est exactement ça : il hérite de ton uid, donc
`cat ~/rhorizon/secrets/master-password` fonctionne. Le mode n'est pas la
frontière. Le compte l'est.

Si tu fais tourner des agents, assistants ou automatisations sur la même
machine :

- **Fais tourner le vault sous un compte que l'agent n'est pas.** `--mode
  system` installe en root : ses credentials vivent sous `/etc/rhorizon`,
  possédés par root, et un agent sous ton login ne peut pas les lire quel que
  soit le mode du fichier. C'est la frontière qui compte ici. (Le service
  lui-même tourne encore en root plutôt que sous un utilisateur `rhorizon`
  dédié ; ça limite une compromission de Horizon, pas l'agent, et c'est suivi
  séparément.) Une install en mode user ne donne aucune frontière de ce type :
  ses credentials appartiennent au compte sous lequel l'agent tourne.
- **Ne laisse pas de credentials dans un répertoire vers lequel un agent est
  pointé.** Mets-les dans un gestionnaire de mots de passe et supprime les
  fichiers ; le vault n'a besoin du mot de passe qu'au descellement, pas en
  permanence sur disque.
- **Ne les colle pas dans un prompt, une issue ou un chat.** Tout ce qui part
  vers un modèle hébergé quitte la machine, et peut être conservé ou journalisé.
- **Donne à l'automatisation un token scopé, jamais le root token.** Les tokens
  par service, à scope étroit et avec allowlist d'IP, sont révocables ; le mot
  de passe maître ne l'est pas, sauf rotation.
- Si tu veux à la fois le redémarrage sans surveillance *et* un agent sur la
  même machine, considère les deux comme incompatibles sur un seul compte et
  sépare-les par utilisateur.

---

## Carte de la documentation

### Démarrer

- [`docs/fr/QUICKSTART-AI.md`](QUICKSTART-AI.md) - setup MCP local pour un accès IA limité et audité
- [`docs/fr/AI-PROMPTS.md`](AI-PROMPTS.md) - prompts relus pour l'accès, la révocation, le diagnostic, la rotation et la sauvegarde
- [`docs/fr/QUICKSTART.md`](QUICKSTART.md) - booter le stack et stocker votre premier secret en 5 minutes
- [`docs/fr/AI-INSTALL-GUIDE.md`](AI-INSTALL-GUIDE.md) - instructions contraintes d'installation locale pour un assistant IA
- [`docs/fr/USE-CASES.md`](USE-CASES.md) - Ansible, CI/CD, Kubernetes, agents IA - patterns copiables-collables

### Déployer

- [`docs/fr/INSTALL.md`](INSTALL.md) - référence d'installation complète : tous les chemins d'entrée, vérification, mise à jour, désinstallation
- [`docs/fr/COMPATIBILITY.md`](COMPATIBILITY.md) - ce sur quoi rhorizon tourne et ce avec quoi il s'intègre (OS, init, orchestration, auth, livraison de secrets, observabilité) avec niveaux de support
- [`docs/fr/INSTALL-NATIVE.md`](INSTALL-NATIVE.md) - installation sans Docker : tableau de statut par OS, mode système vs utilisateur, units systemd, build source `--pq-nginx`
- [`docs/fr/DEPLOYMENT.md`](DEPLOYMENT.md) - local, privé/VPN, reverse proxy + SSO, LDAP/AD, clustering, backup, checklist de durcissement
- [`docs/fr/DOCKER.md`](DOCKER.md) - anatomie du stack compose, Dockerfile multi-stage, volumes/réseaux, patterns d'override, rootless/Podman
- [`docs/fr/K8S.md`](K8S.md) - patterns agent (rh-fetch / rh-inject / rh-watch / cronjob), NetworkPolicy, RBAC, TLS depuis le vault
- [`docs/fr/HA-CLUSTER.md`](HA-CLUSTER.md) - haute disponibilité - membership applicatif, masters crypto locaux, Database HA, identité, JOIN, auto-promote et mTLS par nœud
- [`docs/fr/HA-PRODUCTION-REFERENCE.md`](HA-PRODUCTION-REFERENCE.md) - cible HA de production - un endpoint HTTPS stable, deux edges redondants, trois API, trois membres DB, convergence workers, sécurité des retries, audit/WAL et chemin maintenance/upgrade
- [`docs/fr/HA-RUNBOOK.md`](HA-RUNBOOK.md) - opérations HA - Database HA neutre (référence Patroni / `pgha` BSD), réplication et garde-fous WAL, bootstrap, rolling restart et recovery

### Opérer

- [`docs/fr/CLI.md`](CLI.md) - référence complète des commandes `rhorizon` (vault / secrets / tokens / audit / master / oneshot) avec recettes
- [`docs/fr/TLS.md`](TLS.md) - HTTPS natif, sources de certificats, contextes de déploiement
- [`docs/fr/FAIL2BAN.md`](FAIL2BAN.md) - protection brute-force au niveau IP
- [`docs/fr/DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md) - les deux chemins de reprise (`pg_dump` complet, restauration logique partielle), rotations de tokens en attente, break-glass
- [`docs/docs/howto/observability-alerts.md`](../docs/howto/observability-alerts.md) - cookbook d'alerting Prometheus (critique / sérieux / capacité) + routing Matrix _(EN)_
- [`docs/fr/ROADMAP.md`](ROADMAP.md) - ce qui est stable, ce qui arrive

### Intégrer

- [`docs/docs/reference/api.md`](../docs/reference/api.md) - référence REST : endpoints, authentification, probes, audit, PKI et opérations HA _(EN)_
- [`docs/fr/SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md) - cycle de vie des secrets, scopes des tokens, patterns éphémère / oneshot, modes de rotation master-password
- [`docs/fr/MCP.md`](MCP.md) - serveur Model Context Protocol (Cursor / Cline / Claude Desktop / Continue / opencode)
- [`docs/fr/N8N.md`](N8N.md) - sécuriser tes workflows n8n : protéger `N8N_ENCRYPTION_KEY` + injection par-secret en env, avec journal d'audit par credential

### Audit, conformité & supply chain

- [`docs/fr/SECURITY.md`](SECURITY.md) - politique de sécurité, signalement de vulnérabilités, références croisées frameworks
- [`docs/THREAT-MODEL.md`](../THREAT-MODEL.md) - mapping MITRE ATT&CK + OWASP ASVS L2 complet, limitations explicites _(EN)_
- [`docs/NIS2-COMPLIANCE.md`](../NIS2-COMPLIANCE.md) - matrice des contrôles NIS2 Art. 21
- [`docs/SECURITY-AUDIT.md`](../SECURITY-AUDIT.md) - tracker de remédiation vivant (findings courants + statut) _(EN)_
- [`docs/slsa-compliance.md`](../slsa-compliance.md) - provenance de build SLSA (niveau) _(EN)_
- [`docs/verifying-releases.md`](../verifying-releases.md) - [`docs/verifying-images.md`](../verifying-images.md) - vérifier signatures + builds reproductibles _(EN)_

### Développer

- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) - setup dev, stack de tests, style de code

---

## Statut du projet

**Beta.** Les fonctionnalités listées sont implémentées et exercées par
les suites de tests Python et Rust ; `make test` est le gate local
canonique.
La surface d'API est stable ; les
breaking changes seront annoncés dans le CHANGELOG.

---

## Stack (en une ligne)

FastAPI - SQLAlchemy async - PostgreSQL 18 - PyNaCl (libsodium) -
`cryptography` (pyca) - `python-fido2` (Yubico) - `pyotp` - `bonsai`
(LDAP) - `pyrage` (age) - extension Rust (PyO3, `aes-gcm`, `memsec`,
`zeroize`) - UI Vanilla JS - nginx (Alpine).

Pourquoi celles-là et pas d'autres : voir [`docs/fr/SECURITY.md`](SECURITY.md#choix-logiciels-et-primitives).

---

## Soutenir le projet

Resurgamus Horizon est en AGPL-3.0 et gratuit pour tout usage
self-hosted. Le projet vit grâce à trois canaux, dans l'ordre où la
plupart des utilisateurs les rencontrent :

- **L'utiliser gratuitement.** Pas d'inscription, pas de télémétrie,
  pas d'upsell. La totalité des fonctionnalités est dans ce repository.
- **Licence commerciale** ([LICENSE-COMMERCIAL.md](../../LICENSE-COMMERCIAL.md))
  pour les organisations qui ont besoin de redistribuer en closed-source,
  veulent rebrander dans leur propre offre SaaS, ou ne peuvent pas
  accepter les exigences de source-availability de l'AGPL.
- **Services professionnels** - déploiement production (HA multi-VM /
  Swarm / K8s avec la topologie Patroni de référence, ou Database HA BSD avec
  `pgha` selon le contexte), audits sécurité, formations, retainers
  d'incident. Contacter les mainteneurs pour les packages courants.
- **Sponsoring** - voir [`.github/FUNDING.yml`](../../.github/FUNDING.yml).
  Pour les individus et organisations qui veulent financer la
  maintenance continue sans engagement contractuel.

L'AGPL plus une licence commerciale = même modèle dual-license que
MariaDB, Sentry (pré-BSL), ou Grafana Labs : le projet reste
totalement ouvert et forkable ; les usages commerciaux qui l'intègrent
dans un produit closed-source ou une offre hébergée financent le
développement via la licence.

---

## Licence

> **Licence et marque**
>
> - Sous licence **AGPL-3.0-or-later** ([LICENSE](../../LICENSE)). Source-available ; les modifications doivent rester AGPL.
> - **Relicensing closed-source interdit.** Une licence commerciale est disponible - voir [LICENSE-COMMERCIAL.md](../../LICENSE-COMMERCIAL.md).
> - **"Resurgamus Horizon"** est un nom de projet ; l'AGPL n'accorde aucun droit de marque.
