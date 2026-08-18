# Resurgamus Horizon - Conformite NIS2 (Directive (UE) 2022/2555)

Version: 1.0
Date: 2026-04-15
Scope: Resurgamus Horizon en tant que composant de gestion des secrets dans une infrastructure soumise a NIS2

---

## Contexte

La directive NIS2 (Network and Information Security 2) impose aux entites essentielles
et importantes de l'UE des mesures de cybersecurite renforcees depuis octobre 2024.
Les PME/ETI de secteurs critiques (energie, transports, sante, numerique, etc.) doivent
demontrer la conformite de leur gestion des risques cyber.

Resurgamus Horizon adresse directement plusieurs exigences de l'**Article 21** (mesures de gestion
des risques) en tant que **composant central de gestion des secrets et du chiffrement**.

Ce document mappe les exigences NIS2 aux fonctionnalites implementees dans Resurgamus Horizon.

> **Pendant cote produit.** NIS2 oblige l'*exploitant* ; le **Cyber Resilience
> Act (CRA)** oblige le *fabricant* du logiciel et regit le **marquage CE**. Voir
> [CRA-COMPLIANCE.md](CRA-COMPLIANCE.md) pour l'analyse d'ecart cote produit, la
> classification FOSS « produit important, classe I », l'auto-evaluation selon
> le module A de l'article 32(5) et la feuille de route vers le CE.

### Statuts

- **CONFORME** - Resurgamus Horizon repond a l'exigence directement
- **CONTRIBUE** - Resurgamus Horizon couvre partiellement; des mesures complementaires sont necessaires
- **HORS PERIMETRE** - L'exigence releve de l'organisation, pas d'un outil technique

---

## Article 21 - Mesures de gestion des risques cyber

### (a) Politiques d'analyse des risques et de securite des systemes d'information

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Analyse des risques documentee | **CONTRIBUE** | Threat model MITRE ATT&CK publie (docs/THREAT-MODEL.md). 37 techniques evaluees, 21 couvertes, 16 partielles. Modele de menace specifique au vault de secrets. |
| Checklist securite formalisee | **CONTRIBUE** | OWASP ASVS Level 2 : 42 MET, 1 PARTIAL sur 45 exigences. Couvre authentification, crypto, controle d'acces, communications, journalisation. |
| Politique de chiffrement documentee | **CONFORME** | 5 couches crypto documentees : Argon2id, HKDF-SHA512, XChaCha20-Poly1305, AES-256-GCM, HMAC-SHA512. Aucun algorithme custom. |

**Mesures complementaires requises** : politique de securite globale de l'organisation, registre des actifs (Constellation CAASM peut couvrir ce besoin).

---

### (b) Gestion des incidents

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Detection des incidents | **CONFORME** | Chaîne de mutations signée et checkpoints Merkle signés pour les lectures. Un échec d'intégrité signale une compromission. |
| Journalisation des evenements | **CONFORME** | Chaque événement enregistre acteur, action, cible, détail, horodatage et adresse IP dans PostgreSQL. Les mutations sont signées et recopiées en JSONL ; les lectures sont regroupées dans des checkpoints Merkle signés puis archivées avant élagage de la base. |
| Integrite des journaux | **CONFORME** | Les mutations forment une chaîne Ed25519 (HMAC-SHA512 legacy/fallback). Les enregistrements de lecture complets sont couverts par des checkpoints Merkle signés ; les archives ont checksum, racine Merkle et chaîne de sceaux signée. `/audit/verify` détecte les altérations. |
| Conservation des preuves | **CONFORME** | Retention configurable (defaut 365 jours, min 365, max 3650). Compression automatique apres 7 jours. Suppression uniquement au-dela de la retention par un admin. |
| Notification ANSSI sous 24h | **CONTRIBUE** | Canaux de notification integres (Matrix, webhook, email via Pulsar). Alertes automatiques sur evenements critiques (seal/unseal, echecs d'auth, rupture de chaine). |

**Mesures complementaires requises** : procedure de notification ANSSI/CSIRT, plan de reponse aux incidents, integration SIEM pour correlation.

---

### (c) Continuite d'activite et gestion de crise

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Sauvegarde des donnees | **CONFORME** | DR complete via `pg_dump \| age` ; backups logiques API via age/pyrage pour les artefacts de migration. Les deux s'integrent dans Restic (RPO configurable). Volume PostgreSQL separable pour backup independant. |
| Restauration | **CONFORME** | Restore complet via PostgreSQL ; restore de backup age API = migration logique partielle. Schema SQL idempotent (IF NOT EXISTS). Procedure de restauration documentee. |
| Disponibilite du service | **CONTRIBUE** | Multi-worker uvicorn (compartimentation RPC crypto locale + failover Shamir ; preset home mono-worker disponible) et santé Database HA neutre. Patroni est la topologie de référence testée ; `pgha` BSD est supporté mais pas encore dans la lane de release automatisée de ce dépôt. Sealed par défaut au reboot (sécurité > disponibilité). |
| Plan de reprise | **CONTRIBUE** | Procedure de restauration : deploy nouveau container, restore PostgreSQL ou backup logique API selon l'incident, puis unseal. Temps de reprise estime : < 15 minutes pour le chemin logique (single operator). |

**Mesures complementaires requises** : plan de continuite d'activite (PCA)
global, tests de restauration periodiques documentes et fournisseur Database
HA supporté avec drills réguliers de failover/rejoin.

---

### (d) Securite de la chaine d'approvisionnement

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Audit des dependances | **CONFORME** | Pipeline CI/CD : pip-audit (vulnerabilites Python), cargo test (Rust), Trivy (CVE sur images Docker). Execution quotidienne. |
| Dependances tracees | **CONFORME** | requirements.txt (Python, versions pinees), Cargo.toml (Rust, versions pinees). SBOM genere par syft, signe par cosign. |
| Images conteneurs verifiees | **CONFORME** | Trivy scan 3 images (API, frontend, agent). Scan config + secrets. Version Trivy pinnee a 0.71.2 (0.69.4-6 compromis - supply chain attack mars 2026 ; >= 0.70.0 = releases propres post-incident). |
| Detection de secrets dans le code | **CONFORME** | detect-secrets en pipeline CI. Scan automatique a chaque push. |
| Analyse statique (SAST) | **CONFORME** | Bandit (Python SAST) en pipeline CI. Aucun finding critique tolere. |
| Code open source auditable | **CONFORME** | Code source complet accessible. Pas de dependance SaaS ou proprietaire. |

**Mesures complementaires requises** : politique de gestion des fournisseurs (pour les dependances indirectes), verification des signatures de packages.

---

### (e) Securite dans l'acquisition, le developpement et la maintenance

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Developpement securise | **CONFORME** | Pipeline CI obligatoire : lint (ruff) + SAST (bandit) + audit deps (pip-audit) + scan secrets (detect-secrets) + tests (pytest 1800+ tests) + scan CVE (Trivy). |
| Gestion des vulnerabilites | **CONFORME** | Trivy scan quotidien (cron 4h UTC). pip-audit a chaque push. Versions des dependances pinees et documentees avec procedure de bump. |
| Tests de securite | **CONFORME** | Suite de tests dediee securite (test_security.py) : bypass auth (6 vecteurs), escalade de privileges, etat scelle, validation d'entrees, replay de challenges, revocation de tokens. |
| Correction des vulnerabilites | **CONTRIBUE** | Pipeline CI bloque le merge si SAST ou audit echoue. Notification Matrix sur echec. Mais : pas de SLA formel de correction. |

**Mesures complementaires requises** : SLA de correction des vulnerabilites (critique < 24h, haute < 7j), processus de disclosure responsable.

---

### (f) Evaluation de l'efficacite des mesures

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Metriques de securite | **CONTRIBUE** | OWASP ASVS 42/43 MET, MITRE ATT&CK 21/37 COVERED. Couverture de tests 94%. Scan CVE quotidien avec historique. |
| Audit de conformite | **CONTRIBUE** | Verification de chaine d'audit integree (endpoint API). Threat model et checklist ASVS maintenus a jour dans le depot. |
| Tests periodiques | **CONFORME** | Pipeline CI a chaque push (tests securite + SAST + deps). Trivy quotidien. Mais : pas de pentest externe planifie. |

**Mesures complementaires requises** : audit externe annuel, pentest periodique, revue de conformite NIS2 trimestrielle.

---

### (g) Pratiques de base en matiere de cyber-hygiene

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Principe du moindre privilege | **CONFORME** | Scopes granulaires : secrets:r, secrets:w, tokens:r, tokens:w, audit:r, admin:rw. Isolation par namespace. Tokens ephemeres pour operations ponctuelles. |
| Containers non-root | **CONFORME** | API : uid 1500, frontend : nginx (cap NET_BIND_SERVICE seule), PostgreSQL : non-root recommande. `cap_drop: ALL` + `no-new-privileges` sur tous les containers. |
| Filesystem read-only | **CONFORME** | Containers API et frontend en read-only. tmpfs pour /tmp et /dev/shm (noexec, nosuid). Limites memoire par container. |
| Pas de credentials par defaut | **CONFORME** | Pas de compte par defaut. Premier unseal cree la master key. Root token affiche une seule fois. |
| Mise a jour des composants | **CONTRIBUE** | Procedure de bump documentee (Python, Rust, Docker images). Mais : pas de mise a jour automatique. |

**Mesures complementaires requises** : formation cybersecurite des operateurs, politique de mots de passe (longueur minimum du master password recommandee).

---

### (h) Politiques et procedures relatives a la cryptographie et au chiffrement

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Chiffrement au repos | **CONFORME** | Double enveloppe : XChaCha20-Poly1305 (secret -> DEK) + AES-256-GCM (DEK -> master key). Base de donnees inutile sans master key. |
| Chiffrement en transit | **CONFORME** | TLS 1.2+1.3 via Nginx. VPN (IPsec / OpenVPN) pour acces externe. TLS API-vers-PostgreSQL. |
| Algorithmes approuves | **CONFORME** | Argon2id (RFC 9106), AES-256-GCM (NIST), HMAC-SHA512 (FIPS 198-1), HKDF (RFC 5869), XChaCha20-Poly1305 (IETF). Aucun algorithme proprietaire ou custom. |
| Gestion des cles | **CONFORME** | Master key jamais sur disque (derivee en RAM, Argon2id 256MB). Rotation automatique des DEK (configurable, defaut quotidien). Master password rotation re-chiffre toutes les DEK. |
| Protection des cles en memoire | **CONFORME** | Extension Rust (PyO3) : mlock (pas de swap), zeroize-on-drop (garanti par le compilateur). Wrap key dans le heap Rust, hors du GC Python. |
| Nonces uniques | **CONFORME** | CSPRNG (os.urandom / OsRng). Nonce 24 octets (XChaCha20) ou 12 octets (AES-GCM). Probabilite de collision negligeable. |
| Resilience post-quantique | **CONTRIBUE** | Crypto symetrique (AES-256, XChaCha20, HMAC-SHA512) : resistante (Grover reduit a 128-bit, toujours infaisable). WebAuthn ECDSA P-256 : vulnerable a Shor. Migration necessaire quand disponible. |

**Ce point est le coeur de la conformite Resurgamus Horizon.** La cryptographie est entierement documentee, utilise exclusivement des standards publics, et l'implementation est auditable (< 3000 LOC).

---

### (i) Securite des ressources humaines, controle d'acces et gestion des actifs

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| Controle d'acces | **CONFORME** | Authentification par token HMAC-SHA512 avec scopes. 2FA obligatoire pour unseal (WebAuthn/TOTP/YubiKey). Revocation immediate des tokens. |
| Segregation des droits | **CONFORME** | Scopes granulaires (secrets:r/w, tokens:r/w, audit:r, admin). Namespaces pour isolation des secrets. Tokens ephemeres pour operations ponctuelles (TTL 60s-24h). |
| Gestion des actifs secrets | **CONTRIBUE** | Resurgamus Horizon gere les secrets. Integration Constellation (CAASM/CMDB) pour la cartographie secrets-vers-actifs. |
| Tracabilite des acces | **CONFORME** | Chaque acces a un secret est journalise (acteur, action, cible, IP, timestamp). Chaine d'audit verifiable. |
| Revocation des acces | **CONFORME** | Revocation de token immediate. Master password rotation invalide tous les tokens. Seal coupe tout acces aux secrets. |

**Mesures complementaires requises** : politique RH (depart d'un operateur = revocation des acces), inventaire des tokens actifs, revue periodique des droits.

---

### (j) Authentification multifacteur

| Exigence | Statut | Implementation Resurgamus Horizon |
|----------|--------|----------------------|
| MFA sur les interfaces d'administration | **CONFORME** | 4 modes 2FA : WebAuthn/FIDO2 (resistant au phishing), TOTP (RFC 6238), YubiKey HMAC-SHA1, mode `any` (choix de l'utilisateur). |
| MFA resistant au phishing | **CONFORME** | WebAuthn/FIDO2 : challenge lie a l'origine (origin-bound), cle privee dans le hardware. Resistant aux proxys de phishing en temps reel. |
| Challenges single-use | **CONFORME** | Challenges stockes en base (pas en memoire), supprimes apres usage (DELETE+RETURNING), TTL 60 secondes. Cross-worker safe. |
| Fallback en cas de perte | **CONFORME** | Fallback automatique : si derniere security key supprimee -> bascule vers TOTP ou none. Shamir shares pour unseal d'urgence (M-of-N). |

**Ce point est un atout majeur de Resurgamus Horizon.** L'authentification est entierement self-contained - pas de dependance a un fournisseur d'identite externe (IdP), pas d'OIDC, pas de SAML. Cela simplifie la conformite et elimine un vecteur de defaillance.

---

## Synthese Article 21

| Mesure | Statut | Points forts Resurgamus Horizon | A completer |
|--------|--------|---------------------|-------------|
| **(a)** Analyse des risques | CONTRIBUE | Threat model ATT&CK + ASVS documente | Politique de securite globale |
| **(b)** Gestion des incidents | CONFORME | Audit chaine, retention 1-10 ans, notification | Procedure ANSSI, SIEM |
| **(c)** Continuite d'activite | CONTRIBUE | Backup age, restore < 15min, santé Database HA neutre | PCA global, drills de failover Database HA |
| **(d)** Chaine d'approvisionnement | CONFORME | CI/CD complet, SBOM, Trivy, pip-audit | Politique fournisseurs |
| **(e)** Dev et maintenance securises | CONFORME | Pipeline CI obligatoire, tests secu | SLA correction vulns |
| **(f)** Evaluation des mesures | CONTRIBUE | ASVS 42/43, coverage 94% | Audit externe, pentest |
| **(g)** Cyber-hygiene | CONFORME | Moindre privilege, non-root, read-only | Formation operateurs |
| **(h)** Cryptographie | **CONFORME** | 5 couches, standards publics, Rust mlock | Migration post-quantique |
| **(i)** Controle d'acces | CONFORME | Scopes, namespaces, revocation, audit | Politique RH, revue droits |
| **(j)** MFA | **CONFORME** | WebAuthn + TOTP + YubiKey, self-contained | - |

**Resultat : 6 CONFORME, 4 CONTRIBUE, 0 NON CONFORME**

---

## Mapping NIS2 x OWASP ASVS x MITRE ATT&CK

Resurgamus Horizon maintient trois referentiels de securite croises :

| Referentiel | Couverture | Document |
|-------------|-----------|----------|
| **NIS2 Article 21** | 6/10 conforme, 4/10 contribue | Ce document |
| **OWASP ASVS Level 2** | 42 MET, 1 PARTIAL sur 45 | docs/THREAT-MODEL.md |
| **MITRE ATT&CK** | 21 COVERED, 16 PARTIAL sur 37 | docs/THREAT-MODEL.md |

Ce triple mapping permet de demontrer la conformite aux auditeurs sous differents angles :
- **NIS2** : conformite reglementaire (obligatoire)
- **OWASP ASVS** : conformite technique applicative
- **MITRE ATT&CK** : couverture des menaces reelles

---

## Recommandations pour la conformite complete

### Priorite haute (requis NIS2)

| Action | Effort | Mesure NIS2 |
|--------|--------|-------------|
| Rediger une politique de securite globale | Moyen | (a) |
| Etablir une procedure de notification ANSSI (24h/72h) | Faible | (b) |
| Rediger un PCA incluant la restauration vault | Moyen | (c) |
| Definir un SLA de correction des vulnerabilites | Faible | (e) |
| Planifier un audit externe annuel | Moyen | (f) |

### Priorite moyenne (renforcement)

| Action | Effort | Mesure NIS2 |
|--------|--------|-------------|
| Déployer et exercer un fournisseur Database HA supporté (référence Patroni, ou `pgha` sous BSD) | Moyen | (c) |
| Integrer un SIEM (Wazuh) pour correlation | Moyen | (b) |
| Longueur minimale du master password (16 caracteres) | Faible | (g) |
| Token inactivity timeout (ASVS V3.3.2) | Faible | (i) |
| Integration Constellation pour cartographie secrets-actifs | Moyen | (i) |

### Priorite basse (evolution)

| Action | Effort | Impact |
|--------|--------|--------|
| Mutual TLS pour clients API | Moyen | Renforcement (d) |
| HSM/PKCS#11 pour la wrap key | Eleve | FIPS 140-2 si necessaire |
| Migration post-quantique WebAuthn | Futur | Anticipation (h) |

---

## References

- [Directive (UE) 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555)
- [ANSSI - Transposition NIS2 en droit francais](https://www.ssi.gouv.fr/directive-nis-2/)
- [ENISA - NIS2 Implementation Guidance](https://www.enisa.europa.eu/topics/nis-directive)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106)
