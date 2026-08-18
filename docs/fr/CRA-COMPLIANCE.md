# Resurgamus Horizon - preparation au CRA (Reglement (UE) 2024/2847)

Version : 1.0
Date : 2026-07-24
Perimetre : Resurgamus Horizon en tant que **produit comportant des elements
numeriques** mis sur le marche de l'UE par un fabricant commercial (Resurgamus)

---

## Contexte

Le **Cyber Resilience Act** (CRA, Reglement (UE) 2024/2847) est un reglement
*produit* : il fait de la cybersecurite une condition d'apposition du **marquage
CE** sur tout « produit comportant des elements numeriques » mis a disposition
sur le marche de l'UE. C'est le pendant de NIS2 - NIS2 oblige l'*exploitant*
(mesures de gestion des risques, article 21) ; le CRA oblige le *fabricant* du
logiciel lui-meme.

Dates cles :

| Jalon | Date |
|---|---|
| Entree en vigueur | 10 decembre 2024 |
| Notification des organismes d'evaluation (chapitre IV) | 11 juin 2026 |
| **Signalement des vulnerabilites & incidents graves a l'ENISA (art. 14)** | **11 septembre 2026** |
| **Obligations completes + marquage CE requis (art. 71)** | **11 decembre 2027** |

### Position CRA retenue pour Horizon

Horizon est un seul produit et un seul code source public. La licence
commerciale accorde des conditions alternatives sur le meme logiciel et ajoute
du support commercial ; elle ne constitue pas une edition proprietaire separee.

| Question | Position Horizon | Fondement |
|---|---|---|
| Le produit entre-t-il dans le perimetre du CRA ? | **Oui.** Resurgamus propose des licences commerciales et du support/SLA payant. | Articles 3(13), 3(22) et considerant 15 |
| Quel est l'operateur economique ? | **Resurgamus est le fabricant**, pas un gestionnaire de logiciels libres. | Article 3(13) ; l'article 3(14) reserve le role de gestionnaire a une personne morale autre que le fabricant |
| Horizon est-il un logiciel libre et open source ? | **Oui.** Son code source est partage publiquement et le produit est disponible sous AGPL-3.0. La licence commerciale alternative ne retire pas la distribution AGPL. | Article 3(48) |
| Categorie du produit | **Produit important, classe I — annexe III, categorie 3 : gestionnaires de mots de passe.** Horizon stocke et partage des justificatifs et des secrets, notamment en entreprise. | Annexe III et reglement d'execution (UE) 2025/2392 |
| Procedure de conformite | **Controle interne, module A.** Resurgamus utilise la voie FOSS de l'article 32(5) et publie la documentation technique de l'article 31 lors de la mise sur le marche. | Articles 32(1)(a), 32(5), 31 et annexe VIII |
| Organisme externe d'evaluation | **Non requis pour la voie retenue.** | L'article 32(5) autorise les procedures de l'article 32(1), dont le module A |
| Travail fabricant restant | Evaluation des risques, documentation technique publique, declaration UE de conformite, marquage CE, traitement des vulnerabilites et signalement article 14. | Articles 13-14, 28-32 et annexes I, V, VII et VIII |

Cette position suppose de conserver la distribution AGPL publique du meme
produit Horizon et de publier la documentation technique complete de l'article
31. Elle doit etre revue si Resurgamus publie plus tard une edition proprietaire
distincte ou ne repond plus a la definition FOSS de l'article 3(48).

### Statuts

- **CONFORME** - le produit satisfait deja l'exigence (code / configuration)
- **CONTRIBUE** - partiellement satisfait ; une mesure complementaire est requise
- **A PRODUIRE** - un artefact ou processus fabricant reste a creer (dossier
  technique, declaration, politique) - c'est « ou nous en sommes » pour le CE

---

## Annexe I, partie I - Exigences de cybersecurite (proprietes du produit)

| # | Exigence | Statut | Mise en oeuvre Resurgamus Horizon |
|---|---|---|---|
| (1) | Niveau de cybersecurite approprie fonde sur les risques | **CONTRIBUE** | Modele de menace MITRE ATT&CK + STRIDE (docs/THREAT-MODEL.md), OWASP ASVS L2 42/45. Manque l'evaluation des risques formelle art. 13(2) dans le dossier technique. |
| (2) | Mis a disposition sans vulnerabilite exploitable connue | **CONFORME** | CI : pip-audit, cargo audit/deny, Bandit SAST, detect-secrets, Trivy CVE (cron quotidien). Deps epinglees par hash. Merge bloque en cas d'echec. |
| (3a) | Configuration securisee par defaut + reinitialisation | **CONFORME** | Scelle par defaut au boot ; bind 127.0.0.1 par defaut ; aucun compte par defaut (le 1er unseal cree la master key) ; root token affiche une seule fois. Reinit = redeploiement + nouveau unseal. |
| (3b) | Protection contre l'acces non autorise + signalement | **CONFORME** | Tokens HMAC-SHA512, scopes granulaires, allowlist IP par token, 2FA obligatoire (WebAuthn/TOTP/YubiKey). Log authfail compatible fail2ban + `rhorizon_auth_failures_total`. |
| (3c) | Confidentialite (chiffrement au repos / en transit) | **CONFORME** | Double enveloppe XChaCha20-Poly1305 -> AES-256-GCM ; master key derivee en RAM (Argon2id 256 Mo), jamais sur disque ; TLS 1.2/1.3 avec KEM hybride post-quantique X25519MLKEM768 ; verify-full vers PostgreSQL. |
| (3d) | Integrite des donnees / commandes / config + signalement | **CONFORME** | Chaîne de mutations Ed25519, checkpoints Merkle signés et archives de lectures scellées (`GET /audit/verify`) ; tags AEAD ; certificat PG épinglé ; images cosign. |
| (3e) | Minimisation des donnees | **CONFORME** | Ne stocke que les secrets + metadonnees minimales ; l'audit n'enregistre que les champs necessaires (acteur, action, cible, IP, horodatage). Aucune PII superflue. |
| (3f) | Disponibilite des fonctions essentielles ; resilience DoS | **CONTRIBUE** | Controle d'admission (plafond en vol -> 429), rate-limit par IP, failover Shamir local et Database HA neutre (Patroni testé ; `pgha` BSD supporté), plus limites pids/memoire. Scelle-par-defaut = disponibilite echangee contre securite (documente). |
| (3g) | Minimiser l'impact negatif sur d'autres services | **CONFORME** | Plafonds memoire/pids par conteneur ; reseau DB interne uniquement ; `/metrics` en allowlist IP (pas d'amplification) ; aucun effet de bord sortant. |
| (3h) | Limiter la surface d'attaque, interfaces externes incluses | **CONFORME** | Image d'execution minimale ; Swagger/ReDoc desactives ; API unique authentifiee ; `cap_drop: ALL`, fs read-only, `/dev/shm` 1 Mo ; MCP fail-closed (deny_all sans policy). |
| (3i) | Reduire l'impact d'un incident (attenuation d'exploitation) | **CONFORME** | Rust `mlock` + effacement memoire via `zeroize` ; `no-new-privileges` ; non-root (uid 1500) ; rootfs read-only ; CSP `'self'` ; compartimentation des cles par worker (RPC). |
| (3j) | Journalisation / surveillance de securite avec opt-out | **CONFORME** | Chaîne de mutations signée (DB + JSONL quotidien) et journal de lectures protégé par checkpoints Merkle signés et archives scellées ; `/metrics` Prometheus (25+ séries) + vue Nova ; canaux Matrix/webhook/email. Répertoire et rétention configurables. |
| (3k) | Suppression permanente securisee + transfert securise | **CONTRIBUE** | `secure_zero` (Rust) + le seal zeroise les cles ; suppression secret/namespace ; `pg_dump \| age` pour la DR complete et backup logique API age pour migration. « Tout supprimer » = `compose down -v` ; une procedure de decommissionnement documentee est le complement. |

**Resultat partie I : 10 CONFORME, 3 CONTRIBUE, 0 non conforme (sur 13
proprietes).** Le volet produit du CRA est pour l'essentiel satisfait - Horizon
est par conception un produit cryptographique durci.

---

## Annexe I, partie II - Traitement des vulnerabilites (processus fabricant)

| # | Exigence | Statut | Ou nous en sommes |
|---|---|---|---|
| (1) | Identifier + documenter les composants ; SBOM (lisible machine, >= deps de 1er niveau) | **CONFORME** | SBOM syft signe cosign ; `requirements.txt` + `Cargo.toml` epingles par hash. A confirmer : publier le SBOM (SPDX/CycloneDX) avec chaque artefact de release. |
| (2) | Remedier sans delai ; mises a jour separees des fonctionnalites | **CONFORME** | CI bloque sur SAST/audit ; Trivy quotidien ; les commits `fix:` sont publies independamment des features. `SECURITY.md` documente les deux horloges : premiere reponse 48h (sponsor payant) / 96h (tous les autres), et remediation par **severite, pas par rapporteur** - critique 7j, elevee 30j, moyenne a la prochaine release. Correctifs gratuits pour tous les utilisateurs AGPL, avec un avis par faille ; le sponsoring achete du delai d'attention, jamais un acces privilegie au correctif. |
| (3) | Tests + revues de securite reguliers et efficaces | **CONFORME** | 1815 tests Python + 136 Rust, `test_security.py` dedie, cargo-fuzz (4 cibles), miri, clippy `-D warnings` ; CI a chaque push, couverture 94%. La couverture fonctionnelle et KAT crypto s'exécute sur les deux architectures livrées : amd64 (`validate.yml`) et aarch64 (`arch-matrix.yml` / `tools/test-arm64.sh`, 136/136). Le gate assembleur GF(256) reste spécifique à x86_64. |
| (4) | Divulguer publiquement les vulns corrigees (description, produit, impact, severite, remediation) | **A PRODUIRE** | Pas de canal d'avis formel. Adopter GitHub Security Advisories / identifiants CVE + section securite du `CHANGELOG` par correctif. |
| (5) | Politique de divulgation coordonnee (CVD) | **CONFORME** | `SECURITY.md` : divulgation coordonnee, fenetre 90 jours, premiere reponse 48h/96h selon la classe de rapporteur, cibles de remediation par severite, perimetre defini, contacts OSS et commercial separes. |
| (6) | Faciliter le signalement ; adresse de contact | **CONTRIBUE** | `SECURITY.md` fournit un email de signalement. Manques : publier `/.well-known/security.txt` (RFC 9116) et utiliser un contact Resurgamus (fabricant commercial) plutot qu'interne. |
| (7) | Diffuser les mises a jour de maniere securisee, automatique si applicable | **CONFORME** | Images multi-arch signees cosign + provenance SLSA + doc de verification ; les mises a jour agent suivent les images signees. |
| (8) | Correctifs diffuses sans delai, gratuits, avec avis | **CONTRIBUE** | AGPL - mises a jour gratuites et publiques. Manque : un canal d'avis formel lie a (4) + la liste de notification. |

**Resultat partie II : 5 CONFORME, 2 CONTRIBUE, 1 A PRODUIRE.** Les manques sont
de la documentation et de la publication, pas de l'ingenierie.

---

## Annexe II - Informations et instructions a l'utilisateur

| Exigence | Statut | Note |
|---|---|---|
| Identite + contact du fabricant | **A PRODUIRE** | Ajouter l'entite legale Resurgamus + adresse postale/email + point de contact a la doc. |
| Point de contact unique pour le signalement + emplacement CVD | **CONFORME** | `SECURITY.md` (aligner sur le contact commercial + `security.txt`). |
| Identification nom / type / version du produit | **CONFORME** | `version` dans `/status`, tags d'image, artefacts de release. |
| Finalite prevue, fonctions essentielles + de securite | **CONFORME** | README + CLAUDE.md + doc (modele de securite reseau, couches crypto). |
| Mauvais usage previsible menant a un risque cyber | **CONFORME** | Documente : « ne jamais exposer sur Internet », VPN uniquement, hypotheses du modele de menace. |
| Ou le SBOM est disponible | **CONFORME** | Deja livre : des SBOM CycloneDX par module sont publies comme assets de release signes (`<module>.sbom.cdx.json`, `release.yml`) et attaches a chaque image via une attestation cosign `cyclonedx` (`build.yml`). Recettes de verification dans `docs/verifying-releases.md` et `docs/verifying-images.md`. Reste : exposer le lien sur la page de release elle-meme. |
| Comment installer les mises a jour | **CONFORME** | `docker compose pull` / re-run `install.sh` / git pull natif ; documente par voie. |
| Ou la declaration UE de conformite est disponible | **A PRODUIRE** | Produire la DoC (annexe V) et la lier. |
| Periode de support / fin de support (EOL) | **CONFORME** | `SECURITY.md` : mise sur le marche septembre 2026, cinq ans, fin **septembre 2031** (mois + annee, comme l'exige l'article 13(8)). Perimetre = artefact canonique, avec une matrice de plateformes graduee ; les deux migrations internes a la fenetre (fin de vie securite de Python 3.12 le 31 oct. 2028, cadence 6 mois d'OpenBSD) sont assumees comme engagements. Les cinq ans sont inconditionnels ; seule une prolongation au-dela depend du financement. |
| Mise en service / exploitation / decommissionnement securises | **CONFORME** | Quickstart, deploiement, TLS, reprise apres sinistre, notes de suppression securisee. |

---

## Obligations du fabricant (articles 13-14, conformite)

| Obligation | Article | Statut | Note |
|---|---|---|---|
| Evaluation des risques cyber | 13(2) | **A PRODUIRE** | Formaliser depuis le modele de menace existant au format art. 13(2). |
| Documentation technique | 31 + annexe VII | **A PRODUIRE** | Assembler : evaluation des risques, preuves annexe I, SBOM, rapports de tests, DoC. La plupart des entrees existent deja dans le depot. |
| Evaluation de conformite | 32 + annexe VIII | **A PRODUIRE** | Achever et publier la documentation technique de l'article 31, puis consigner l'evaluation par controle interne du module A au titre de l'article 32(5). |
| Declaration UE de conformite | 28 + annexe V | **A PRODUIRE** | Rediger apres l'evaluation selon le module A. |
| Marquage CE | 29-30 | **A PRODUIRE** | Apposer apres la DoC. |
| Signaler vulns activement exploitees + incidents graves a l'ENISA/CSIRT | 14 | **A PRODUIRE** | **Echeance 11 sept. 2026.** Mettre en place la procedure alerte 24h / notification 72h (les canaux de notification existent deja comme base technique). |
| Diligence sur les composants tiers integres | 13(5) | **CONTRIBUE** | pip-audit / cargo audit / Trivy + doc upstream-trust ; formaliser la diligence fournisseur. |

---

## Synthese

| Volet CRA | Resultat |
|---|---|
| **Annexe I partie I** (proprietes produit, 13) | 10 CONFORME, 3 CONTRIBUE, 0 manque |
| **Annexe I partie II** (traitement vulns) | 5 CONFORME, 2 CONTRIBUE, 1 a produire |
| **Annexe II** (information utilisateur) | 8 CONFORME, 2 a produire (identite legale du fabricant, emplacement de la DoC) |
| **Obligations fabricant** | 1 CONTRIBUE, 6 a produire |

**Lecture pour le marquage CE :** la substance *technique* du CRA est pour
l'essentiel faite - Horizon est securise par conception, chiffre, audite, durci,
teste, avec une politique CVD et une chaine d'approvisionnement signee. Reste le
**dossier et le processus de conformite du fabricant** : la redaction de
l'evaluation des risques, le dossier de documentation technique, la voie
d'evaluation de conformite selon le module A, la DoC UE, et la procedure de signalement
art. 14 (a faire en premier, 11 sept. 2026).

---

## Tableau de correspondance - fonction Horizon x NIS2 art. 21 x CRA annexe I

Argumentaire : un controle, deux reglements. Chaque capacite d'Horizon repond a
une mesure NIS2 article 21 (obligation exploitant) **et** a une exigence CRA
annexe I (obligation produit).

| Fonction Horizon | NIS2 art. 21 | CRA annexe I |
|---|---|---|
| Chiffrement au repos double enveloppe (XChaCha20 -> AES-256-GCM) | (h) | Partie I (3)(c) |
| TLS 1.2/1.3 + KEM hybride post-quantique en transit | (h) | Partie I (3)(c) |
| Master key en RAM mlock, jamais sur disque (Argon2id) | (h) | Partie I (3)(c), (3)(i) |
| Chaîne de mutations signée + preuves de lecture Merkle | (b) | Partie I (3)(d), (3)(j) |
| 2FA WebAuthn / TOTP / YubiKey (resistant au phishing) | (j) | Partie I (3)(b) |
| Tokens HMAC scopes + allowlist IP par token | (i) | Partie I (3)(b) |
| Scelle par defaut + aucun identifiant par defaut | (g) | Partie I (3)(a) |
| Non-root, fs read-only, cap_drop ALL, no-new-privileges | (g) | Partie I (3)(h), (3)(i) |
| Controle d'admission + rate-limit par IP | (c) | Partie I (3)(f) |
| Failover Shamir M-of-N local + Database HA neutre | (c) | Partie I (3)(f) |
| /metrics Prometheus + Nova + canaux de notification | (b), (f) | Partie I (3)(j) |
| Sauvegarde / restauration chiffrees age | (c) | Partie I (3)(k) |
| secure_zero Rust + le seal zeroise les cles | (h) | Partie I (3)(k) |
| SBOM (syft) + signatures cosign + provenance SLSA | (d) | Partie II (1), (7) |
| CI pip-audit / cargo audit / Trivy / Bandit | (d), (e) | Partie I (2), Partie II (2), (3) |
| Politique de divulgation coordonnee SECURITY.md | (e) | Partie II (5), (6) |

---

## Feuille de route vers le marquage CE

### A faire en premier - signalement article 14 (avant le 11 septembre 2026)

| Action | Effort |
|---|---|
| Documenter la procedure alerte 24h / notification 72h vers ENISA/CSIRT | Faible |
| Cabler les canaux de notification existants dans cette procedure | Faible |

### Pour la declaration de conformite (avant le 11 decembre 2027)

| Action | Effort | Reference CRA |
|---|---|---|
| Rediger l'evaluation des risques art. 13(2) (depuis le modele de menace) | Moyen | 13(2) |
| Assembler le dossier de documentation technique | Moyen | 31 + annexe VII |
| Publier le SBOM signe (SPDX/CycloneDX) par release | Faible | Partie II (1), annexe II |
| Adopter GitHub Security Advisories / CVE + canal d'avis | Faible | Partie II (4), (8) |
| Ajouter `/.well-known/security.txt` + contact commercial | Faible | Partie II (6), annexe II |
| Definir + publier la politique de periode de support / EOL | Faible | Annexe II |
| ~~Definir un SLA de remediation des vulnerabilites~~ - **fait** : reponse 48h/96h, remediation critique 7j / elevee 30j (`SECURITY.md`) | - | Partie II (2) |
| Publier la documentation technique et achever l'evaluation du module A selon l'article 32(5) | Moyen | 31, 32(1)(a), 32(5) + annexe VIII |
| Rediger la declaration UE de conformite + apposer le CE | Moyen | 28-30 + annexe V |

### Renforcement (deja CONTRIBUE)

| Action | Effort | Exigence |
|---|---|---|
| Documenter la procedure de decommissionnement / effacement securise | Faible | Partie I (3)(k) |
| Durcir la posture DoS au-dela du rate-limit | Moyen | Partie I (3)(f) |
| Formaliser la diligence fournisseur | Faible | Art. 13(5) |

---

## References

- [Reglement (UE) 2024/2847 (Cyber Resilience Act)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [Reglement d'execution (UE) 2025/2392 - descriptions techniques des categories CRA](https://eur-lex.europa.eu/eli/reg_impl/2025/2392/oj/fra)
- [Commission europeenne - resume du CRA](https://digital-strategy.ec.europa.eu/en/policies/cra-summary)
- [Commission europeenne - CRA et open source](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source)
- [ENISA - divulgation des vulnerabilites](https://www.enisa.europa.eu/topics/vulnerability-disclosure)
- [RFC 9116 - security.txt](https://www.rfc-editor.org/rfc/rfc9116)
- [Conformite NIS2](NIS2-COMPLIANCE.md) - le pendant cote exploitant
- [Modele de menace (MITRE ATT&CK + OWASP ASVS)](../THREAT-MODEL.md)
