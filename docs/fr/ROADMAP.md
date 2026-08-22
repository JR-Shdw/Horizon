# Resurgamus Horizon - Roadmap

**Statut : bêta, cœur fonctionnellement complet.** Tout ce qui figure sous
« Livré » est implémenté et exercé par les suites de tests Python + Rust
(`make test` fait foi). La surface d'API est stable ; les ruptures sont
annoncées dans le CHANGELOG. Ce document suit ce qui existe, le durcissement
d'avant-release encore en vol, et la direction du projet.

Règle de release (vaut pour chaque point ci-dessous) : ne jamais imposer aux
utilisateurs existants une migration de schéma destructrice ni un ré-import des
secrets. Les colonnes de chiffré stockées et les tailles de nonce restent
compatibles octet à octet. Un changement de métadonnées versionnées doit
conserver un chemin de lecture pour les lignes et sauvegardes existantes.

---

## Livré

### Cœur du vault
| Domaine | Quoi |
|---|---|
| Crypto | Pile à 5 couches (Argon2id -> HKDF-SHA512 -> XChaCha20-Poly1305 -> AES-256-GCM -> HMAC-SHA512), double enveloppe avec DEK par secret, seal/unseal, rotation hiérarchique de `dek_key` autorisée par l'opérateur avec surveillance de l'âge |
| Secrets | CRUD, versioning + rollback, rotation par secret avec fenêtre de grâce, namespaces |
| Tokens | Scopes, allowlist d'IP par token (CIDR), éphémères (TTL court), rotate/renew, `whoami` |
| Oneshot | Scellé par défaut : unseal -> lecture d'un secret -> re-seal en un seul appel |

### Authentification et accès
| Domaine | Quoi |
|---|---|
| 2FA | WebAuthn/FIDO2 (navigateur), YubiKey HMAC-SHA1 (CLI), TOTP ; modes none/yubikey/totp/any avec repli automatique |
| Auth externe | Bind LDAP/AD + mapping de groupes ; en-têtes SSO proxy (Authelia/Authentik/Keycloak) |
| RBAC | Groupes (locaux + mappés LDAP), sous-admin de namespace par composition de scopes |

### Interfaces et exploitation
| Domaine | Quoi |
|---|---|
| Web UI | Frontend vanilla-JS complet : dashboard, secrets, tokens, audit, groupes, backup, notifications, réglages, observabilité, PKI |
| CLI | `rhorizon` (typer) : unseal/seal, secrets, tokens, audit, PKI |
| Notifications | Matrix, webhook générique, email (SMTP) |
| Backup/restore | Export/restore logique chiffré age + `pg_dump | age` pour un DR fidèle |

### Automatisation et livraison
| Domaine | Quoi |
|---|---|
| Agents | `rh-fetch` (init container), `rh-inject` (wrapper d'env), `rh-watch` (sidecar + rotation de token éphémère), binaires musl statiques |
| MCP | Serveur stdio zéro-dépendance ; **hub gateway** optionnel avec identité par agent, chaîne d'audit MCP côté serveur (`vault_audit_mcp`) et sidecar PQ-TLS |
| Secrets dynamiques | Credentials modulaires PostgreSQL, MySQL/MariaDB, LDAP, Redis ACL et Cassandra avec leases et auto-révocation ; collection Ansible séparée |

### Cryptographie et PKI
| Domaine | Quoi |
|---|---|
| Moteur PKI | CA dédiée émettant des feuilles X.509 courtes ; algorithme de signature sélectionnable : Ed25519, ML-DSA-65 (FIPS 204), ou **composite Ed25519 + ML-DSA-65** |
| Certificats KEM PQ | Certificats KEM **hybrides X25519 + ML-KEM-768** |
| Transport PQ | TLS 1.3 post-quantique (X25519MLKEM768) sur le chemin agent <-> vault |

### Haute disponibilité
| Domaine | Quoi |
|---|---|
| Database HA | Clustering neutre vis-à-vis du fournisseur (basé Patroni), gating de santé des réplicas en streaming, rétention WAL bornée |
| Coordination | Couche inter-conteneurs : identité cluster/nœud, JOIN bootstrap HMAC, machine à états de quarantaine, drain/evict/promote |
| Partage de clé | Parts Shamir du master distribuées, workers master/follower par rôle, reconstruction automatique au failover |
| Modèle d'autorité | Deux deadlines indépendantes, pas une : la **fraîcheur d'autorité DB** (tout nœud — un secondaire incapable de lire l'état canonique ne peut plus prouver qu'il est encore secondaire) et le **bail primary** (la revendication d'écriture singleton, primary uniquement). Les deux évaluées contre le `clock_timestamp()` de PostgreSQL, jamais contre une horloge hôte |
| État FROZEN | Perdre l'autorité DB suspend le service sans larguer les clés. Exprimé comme une deadline recalculée à la lecture, donc une boucle de rafraîchissement morte échoue fermé au lieu de laisser un nœud servir. Un hard fence scelle à `lease_ttl + frozen_max`, bornant le temps qu'un nœud possiblement périmé passe assis sur de la matière clé. Ce fence tourne dans sa propre boucle, ne lisant qu'une horloge monotone : évalué en fin de tick base de données, il n'était jamais *atteint* quand la requête pendait, et une boucle pendue n'est pas une boucle morte, donc la supervision ne l'attrapait pas. Les pairs peuvent acheter du temps à un nœud gelé, jamais le droit de servir |
| Transport | CA de cluster avec mTLS par nœud ; `/internal/ha/status` répond avec PostgreSQL injoignable (aucune I/O, aucune auth — un endpoint qui a besoin de l'autorité ne peut pas rendre compte de sa perte) |
| Prévu | Classification peer-aware : aujourd'hui un nœud ne peut pas distinguer une panne DB **partagée** de son **propre** isolement, qui appellent des réactions opposées (tenir vs sceller). Les pairs contribuent des observations, jamais de l'autorité |

### Durcissement mémoire et audit
| Domaine | Quoi |
|---|---|
| Hygiène des clés | Cœur crypto en Rust (PyO3) : master / `dek_key` / `hmac_key` / `audit_key` tenus mlock'd et zeroize-on-drop ; la wrap key n'existe jamais en Python |
| Crypto en volume | CRUD de secrets, lectures de versions, rollback, rotation et backup/restore chaînés en Rust ; les DEK en clair restent dans Rust |
| Audit | Signatures versionnées de lignes complètes ; journal de lecture à haut débit avec checkpoints Merkle signés ; racines conscientes du pruning ; vérification complète durable et ancres de préflight incrémentales signées |

### Chaîne d'approvisionnement
Images multi-arch (amd64 + arm64), signatures cosign + provenance SLSA + SBOM,
Trivy / bandit / pip-audit / detect-secrets, `cargo audit` / `deny` / `clippy` /
`miri`, cibles cargo-fuzz. Le nombre de tests bouge chaque semaine ; `make test`
fait foi, pas cette page.

---

## Durcissement avant release

Suivi en détail dans
[`SECURITY-HARDENING-ROADMAP.md`](../SECURITY-HARDENING-ROADMAP.md) (EN). Le
durcissement mémoire et audit est terminé. Le travail restant se limite à la
validation plateforme et release :

| Point | Portée | Priorité |
|---|---|---|
| Install macOS native | Valider `quickstart-laptop-native.sh` sur du matériel Apple (ou un runner CI macOS). Aujourd'hui, sur macOS, chemin conteneur seulement. | Moyenne |
| Binaires de release agent multi-arch | Le blocage du build arm64 est levé ; publier les binaires musl `rh-*` pour aarch64 dans `release.yml`. | Moyenne |

---

## Suite

### Vaisseau amiral : unseal adossé au matériel (seal-wrap / racine de confiance matérielle)

La seule dimension où les vaults commerciaux mènent réellement, c'est une
**racine de confiance matérielle pour la master key**. Aujourd'hui rhorizon
dérive la master key du mot de passe via Argon2id et la tient mlock'd dans le
tas Rust. Cette fonctionnalité permet à la master (ou à une clé de chiffrement
de clé qui l'enveloppe) de vivre dans du matériel, donc d'être déballée *par le
périphérique* et de ne pas être dérivable d'un mot de passe fuité seul.

**Limite honnête (annoncée d'emblée) :** ça protège la **racine**. Ça ne rend
*pas* la mémoire du process immunisée — les clés de travail dérivées
(`dek_key`, etc.) doivent toujours entrer en RAM pour chiffrer/déchiffrer à
débit ; router chaque opération par secret à travers un HSM est trop lent pour
un vault généraliste. C'est la même limite que le seal-wrap dans les vaults
commerciaux. Le gain, c'est l'ancrage matériel et la suppression de l'exposition
« la master key est en RAM comme unique racine » — pas « aucune matière clé
jamais en RAM ».

**Backends open-source auto-hébergés uniquement** (pas de KMS cloud — une
dépendance SaaS est hors doctrine). Implémenté comme un fournisseur de seal
enfichable, comme les modes 2FA, et **composable avec Shamir** (présence
matérielle *et* M-parmi-N) :

| Backend | Matériel | Outillage |
|---|---|---|
| TPM 2.0 | présent sur la plupart des hôtes modernes | `tpm2-tss` / `tpm2-tools` ; sceller une KEK à des PCR -> l'unseal exige cette machine + le mot de passe |
| HSM PKCS#11 | Nitrokey HSM 2 / YubiHSM 2 | `cryptoki` (Rust), OpenSC ; KEK tenue dans le périphérique, master déballée dans le HSM |
| YubiKey PIV | réutilise les YubiKeys existantes | OpenSC/PIV ; une clé de slot enveloppe la master |

**Interface de fournisseur de seal proposée** (esquisse — vit dans la frontière
crypto Rust pour que les octets de clé déballés ne remontent jamais en Python) :

```python
class SealProvider(Protocol):
    name: str                                  # "password" | "tpm2" | "pkcs11" | "yubikey-piv"

    def present(self) -> bool: ...             # périphérique disponible + authentifié
    def wrap(self, kek: bytes) -> bytes: ...   # protéger la KEK du vault via le périphérique
    def unwrap(self, wrapped: bytes) -> bytes: ...  # la relâcher via le périphérique (dans le HW pour un HSM)
    def rotate(self) -> None: ...              # re-keyer le secret tenu par le matériel
```

Le défaut reste `seal_mode = password` ; le matériel est opt-in et compatible
octet à octet (seule change la façon dont la master/KEK est protégée — le
chiffré des secrets stockés est intact).

**Les deux parties difficiles (travail de conception, pas de plomberie) :**
- **Récupération.** Un périphérique mort ou perdu ne doit pas faire perdre le
  vault. Le matériel est *un* facteur, branché sur le chemin Shamir + recovery
  handle existant — jamais un point de défaillance unique.
- **CI sans matériel.** `swtpm` (TPM logiciel) + `SoftHSM2` donnent une
  couverture TPM/PKCS#11 dans le pipeline ; valider contre une vraie
  Nitrokey/YubiKey avant de livrer.

**Phasage :** (1) abstraction de fournisseur de seal + TPM 2.0 (gratuit,
universel) ; (2) PKCS#11 (Nitrokey/YubiHSM, le vrai HSM amovible) ; (3) YubiKey
PIV (réutiliser le matériel existant).

### Directions candidates (non engagées)

Emplacement pour les priorités post-lancement — à remplir à partir des retours
des premiers utilisateurs.

---

## Validation plateforme

| Cible | Statut | Étape suivante |
|---|---|---|
| Linux x86-64 | Principal, gardé par la CI | - |
| Linux aarch64 | Validé sur du matériel Raspberry Pi 4 | Garder la voie matérielle dans la validation de release |
| FreeBSD / OpenBSD | Suite de tests validée en VM | Garder dans la matrice VM BSD |
| macOS natif (Apple Silicon) | Gardé par la CI sur `macos-latest` | Garder `macos-native.yml` dans la voie release |
| macOS natif (Intel) | Non mesuré | Nécessite un runner x86_64 auto-hébergé ou un vrai Mac : plus aucune image `macos-13` gratuite |
