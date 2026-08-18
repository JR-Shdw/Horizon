# Politique de sécurité

> Version EN faisant autorité : [`SECURITY.md`](../../SECURITY.md) à la racine.
> Cette page est un miroir, mise à jour avec un léger décalage.

## Versions supportées

| Version | Supportée |
|---|---|
| 1.0.x (beta) | Oui |

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une vulnérabilité de sécurité.**

Email : **security@example.com**

À inclure :
- Description de la vulnérabilité
- Étapes de reproduction
- Évaluation d'impact
- Correctif suggéré (si vous en avez un)

### Delais de reponse et de correction

Deux horloges distinctes. La premiere est le delai avant qu'un humain vous
reponde ; la seconde est le delai de correction, et elle **ne depend pas** de
qui a signale.

| | Premiere reponse | Adresse |
|---|---|---|
| Sponsor payant / membre commercial | 48 heures | `horizon@resurgamus.com` |
| Toute autre personne | 96 heures | `security@example.com` |

La correction est pilotee par la severite, pas par le rapporteur : critique
sous 7 jours, elevee sous 30 jours, moyenne à la prochaine release planifiee.
Les correctifs de securite sont publies separement des features, gratuitement,
pour tous les utilisateurs sous AGPL, avec un avis par faille corrigee. Le
sponsoring achete du **delai d'attention et du support**, jamais un acces
privilegie a un correctif ni une prolongation d'embargo.

## Politique de divulgation

- Divulgation coordonnée (fenêtre 90 jours)
- Crédit accordé dans le CHANGELOG sauf demande d'anonymat
- Pas de programme de bug bounty pour le moment

## Périmètre

Dans le périmètre :
- Bypass d'authentification ou d'autorisation
- Fuite de secret (cleartext dans les logs, réponses ou base)
- Faiblesse cryptographique
- Bypass ou forge de la chaîne d'audit
- Évasion de container ou élévation de privilèges

Hors périmètre :
- Attaques nécessitant un accès physique à l'hôte
- Ingénierie sociale
- DoS (le rate limiting est implémenté mais pas durci pour DDoS)
- Problèmes dans les dépendances tierces (à reporter en amont, mais
  prévenez-nous quand même)

---

## Standards & frameworks - références croisées

Resurgamus Horizon ne vise pas une "conformité" par cases à cocher ; le
design sécurité est mappé sur les frameworks reconnus pour qu'un
auditeur puisse tracer chaque contrôle vers une primitive, un endpoint
ou une partie du code.

| Framework | Document | Couverture |
|---|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) (Enterprise v15) | [docs/THREAT-MODEL.md](../THREAT-MODEL.md#1-threat-model---mitre-attck-mapping) | Initial Access, Persistence, Privilege Escalation, Credential Access, Defense Evasion, Lateral Movement, Collection - couvert ou partiel avec gaps explicites |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) Level 2 (v4.0.3) | [docs/THREAT-MODEL.md](../THREAT-MODEL.md#2-owasp-asvs-level-2-checklist) | V2 Auth, V3 Sessions, V4 Access Control, V6 Crypto, V7 Errors, V8 Data Protection, V9 Comms, V13 API - 42/45 MET |
| [NIS2](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) (UE 2022/2555) Art. 21 | [docs/NIS2-COMPLIANCE.md](../NIS2-COMPLIANCE.md) | Gestion des risques, chiffrement au repos & en transit, contrôle d'accès, journalisation incident, rotation des secrets, supply chain |
| [OWASP Top 10](https://owasp.org/Top10/) (2021) | [docs/THREAT-MODEL.md](../THREAT-MODEL.md) (couvert transitivement via ASVS) | A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A07 ID&A Failures, A08 Software & Data Integrity, A09 Logging & Monitoring |
| [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) (niveaux d'authentificateurs) | présent document, section "Choix logiciels et primitives" | AAL2 via WebAuthn/FIDO2 + multi-facteur (master password + 2FA) |
| [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) | [docs/THREAT-MODEL.md](../THREAT-MODEL.md) (implicite via MITRE+ASVS) | Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege |

[docs/SECURITY-AUDIT.md](../SECURITY-AUDIT.md) est le **tracker de
remédiation vivant** - findings courants, statut, et le travail en
cours pour les adresser. Il bouge entre les releases ; consultez-le
pour la posture à jour, pas pour un rapport d'audit figé.

---

## Design sécurité - vue d'ensemble

Stack crypto (voir README pour le diagramme, [docs/THREAT-MODEL.md](../THREAT-MODEL.md) pour les mappings) :

- Argon2id (256 Mo, t=3, p=1) pour password -> master key
- HKDF-SHA512 pour dériver les sous-clés `hmac`, `dek`, `audit`
- XChaCha20-Poly1305 pour les secrets, chacun avec sa propre DEK
- AES-256-GCM pour wrap les DEK (la wrap key vit dans le heap Rust, mlock'd)
- HMAC-SHA512 pour le lookup des tokens (index B-tree O(1)) et les signatures chaînées d'audit

Contrôles supplémentaires :

- Shamir Secret Sharing (M-of-N) pour le master password / unseal key
- 2FA à l'unseal : WebAuthn/FIDO2, YubiKey HMAC-SHA1, ou TOTP (RFC 6238)
- Chaîne des mutations double-écrite en PostgreSQL + JSONL ; lectures protégées
  par checkpoints Merkle signés et archives scellées
- Container read-only, non-root (uid 1500), toutes capabilities droppées, `no-new-privileges`, limites pids/mémoire
- Les clés sont zéroïsées au seal - Rust `zeroize` effectue le wipe sur `Drop`
- Custody multi-worker des clés: seul le process master détient les sous-clés; les followers délèguent chaque op crypto sur un socket Unix filesystem `0700` (peer-UID vérifié via `SO_PEERCRED`, fail-closed) et ne détiennent qu'une share Shamir chacun. Le chemin legacy `/dev/shm` a été supprimé

---

## Choix logiciels et primitives

Resurgamus Horizon utilise des primitives connues et des bibliothèques
auditées.

### Primitives cryptographiques

| Primitive | Choix | Pourquoi celle-ci |
|---|---|---|
| **KDF mot de passe** | Argon2id (256 Mo, t=3, p=1) | Vainqueur de la [PHC](https://password-hashing.net/) et standardisé par RFC 9106. Son coût mémoire augmente le coût des tentatives parallèles. rhorizon fixe un profil applicatif de 256 Mo au lieu d'exposer un réglage plus faible à l'exécution. |
| **AEAD symétrique (secrets)** | XChaCha20-Poly1305 | Son nonce aléatoire de 24 octets rend les collisions accidentelles négligeables au volume prévu ; la réutilisation reste interdite. Ne dépend pas d'une accélération AES matérielle. |
| **AEAD symétrique (wrap DEK)** | AES-256-GCM | Souvent accéléré par AES-NI et standardisé par NIST SP 800-38D. Il wrappe les DEK avec la `dek_key` ; chaque opération exige toujours un nonce unique. |
| **HMAC** | HMAC-SHA512 | Standardisé (FIPS 198-1, RFC 2104). Sortie 512 bits = résistance aux collisions ample. SHA512 plus rapide que SHA256 sur CPU 64-bit. Utilisé pour lookup token (index DB de hashes HMAC) et signatures chaînées d'audit. |
| **Dérivation de clé** | HKDF-SHA512 | Standard extract-and-expand (RFC 5869). Sépare proprement la master key en sous-clés purpose-specific (`hmac`, `dek`, `audit`) avec séparation de domaine via `info=`. |
| **Asymétrique (WebAuthn)** | ECDSA P-256 / EdDSA | Selon ce que l'authentificateur choisit - les deux sont largement supportés par les tokens hardware. ECDSA P-256 = baseline FIDO2 ; Ed25519 = offert par YubiKeys récentes. |

### Bibliothèques (et pourquoi)

| Préoccupation | Lib | Pourquoi celle-ci |
|---|---|---|
| **Bindings libsodium** | [PyNaCl](https://pynacl.readthedocs.io/) | Bindings Python de [libsodium](https://doc.libsodium.org/), dont les API haut niveau fournissent l'implémentation XChaCha20-Poly1305 utilisée ici. |
| **AES-GCM, HKDF, ECDSA** | [cryptography (pyca)](https://cryptography.io/) | Bibliothèque cryptographique Python maintenue et adossée à OpenSSL. |
| **WebAuthn / FIDO2** | [python-fido2](https://github.com/Yubico/python-fido2) | Maintenue par Yubico et implémente les opérations serveur CTAP2 / WebAuthn. |
| **TOTP** | [pyotp](https://github.com/pyauth/pyotp) | Implémente RFC 4226 (HOTP) et RFC 6238 (TOTP) en Python. |
| **age (backups)** | [pyrage](https://github.com/woodruffw/pyrage) | Bindings vers [rage](https://github.com/str4d/rage), une implémentation Rust du format de chiffrement de fichiers [age](https://age-encryption.org/). |
| **Protection mémoire** | Extension Rust (`rhorizon_crypto`) avec [`memsec`](https://crates.io/crates/memsec) (`mlock`) + [`zeroize`](https://crates.io/crates/zeroize) (wipe au `Drop`) | `zeroize` impose un wipe conservé par le compilateur. `mlock(2)` garde les pages de clés hors swap lorsque l'hôte autorise leur verrouillage. La custody Rust garde ces clés hors de l'introspection des objets Python. |
| **LDAP** | [bonsai](https://bonsai.readthedocs.io/) | Client LDAP async avec bindings libldap natifs pour les binds, TLS, referrals et retries. |

### Pourquoi pas ...

- **bcrypt** - Coût mémoire fixé à ~4 Ko quel que soit `cost`. Bruteforce GPU faisable à grande échelle. Argon2id explicitement conçu pour défaire ça.
- **scrypt** - Précède Argon2 et partage son objectif memory-hard, mais le réglage des paramètres est plus dur à bien faire et la standardisation (RFC 7914) n'a jamais été mise à jour pour matcher les recommandations modernes. Argon2 est le [vainqueur PHC](https://password-hashing.net/).
- **PBKDF2** - KDF iteration-only. Pas de dureté mémoire. OK pour un flow de reset password AAL1, pas pour la creds racine d'un vault.
- **Crypto custom** - Resurgamus Horizon implémente **zéro** primitive custom. Chaque algorithme de la chaîne est standardisé (RFC / NIST / IETF) et fourni par une lib auditée.
- **Token de session maison** - Les tokens sont 32 octets random hashés HMAC-SHA512. Pas de JWT, pas de cookie signé, pas de danse refresh-token. La DB est l'unique source de vérité ; la révocation est un `UPDATE ... SET active=false`.
- **mTLS comme seul auth** - mTLS est *complémentaire* (l'opérateur peut ajouter un reverse proxy qui fait la vérif client-cert), pas un remplacement de l'auth applicative.

### Couches de defense-in-depth

| Couche | Objectif | Implémentation |
|---|---|---|
| Réseau | Ne pas être joignable depuis Internet | Responsabilité de l'opérateur - VPN (IPsec / OpenVPN) ou VLAN privé. Bind addresses par défaut à `127.0.0.1`. |
| Reverse proxy (optionnel) | Terminaison TLS, WAF, SSO | Labels génériques pour ingress Traefik / Caddy / nginx ; SSO via headers (compatible Authelia / Authentik / Keycloak / oauth2-proxy) |
| Application | Auth + scope + audit | Self-contained (master password + 2FA), tokens HMAC-SHA512, ACL scope+namespace, audit chaîné |
| Container | Réduire le rayon d'impact si l'app est compromise | `read_only`, non-root uid 1500, `cap_drop ALL`, `no-new-privileges`, tmpfs `noexec/nosuid`, limites pids/mémoire |
| Mémoire | Réduire l'exposition par introspection Python et swap | Rust `mlock` + `zeroize`-on-drop pour la master key et les sous-clés ; les opérations crypto utilisent les clés détenues en Rust |
| Stockage | Empêcher qu'un dump DB suffise au déchiffrement | Double enveloppe (secret XChaCha20-Poly1305 + wrap AES-256-GCM de la DEK) ; le matériel dérivé de la master key reste séparé en mémoire |
| Audit | Détecter la falsification a posteriori | Chaîne de mutations Ed25519 (HMAC-SHA512 legacy/fallback) en DB + JSONL, avec checkpoints Merkle signés et archives scellées pour les lectures |

### Posture de résistance quantique

Le coeur de stockage utilise des primitives symétriques 256 bits, Shamir à
sûreté informationnelle et des sauvegardes protégées par passphrase.
L'algorithme de Shor ne casse pas ces primitives ;
Grover réduit la marge de recherche exhaustive des clés symétriques. Le
transport préfère ML-KEM hybride (`X25519MLKEM768`) sur TLS UI/inter-noeud et
PostgreSQL, mais l'opérateur doit vérifier la négociation sur chaque connexion.
Les signatures d'audit Ed25519, WebAuthn et ECDSA restent classiques. Voir
[docs/POST-QUANTUM.md](../POST-QUANTUM.md).

---

## Voir aussi

- [docs/THREAT-MODEL.md](../THREAT-MODEL.md) - mapping MITRE ATT&CK + OWASP ASVS Level 2 complet, limitations explicites
- [docs/SIDE-CHANNELS.md](../SIDE-CHANNELS.md) - conception constant-time, tests fonctionnels amd64/aarch64, gate assembleur x86_64, protection mémoire et risques résiduels
- [docs/POST-QUANTUM.md](../POST-QUANTUM.md) - posture post-quantique : transport hybride ML-KEM + coeur de stockage PQ par construction
- [docs/NIS2-COMPLIANCE.md](../NIS2-COMPLIANCE.md) - matrice des contrôles NIS2 Art. 21
- [docs/SECURITY-AUDIT.md](../SECURITY-AUDIT.md) - résultats de l'audit sécurité interne + journal de remédiation
- [docs/FAIL2BAN.md](FAIL2BAN.md) - protection brute-force au niveau IP
- [docs/TLS.md](TLS.md) - configuration HTTPS native
