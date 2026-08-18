# Posture de résistance quantique

Les données au repos de rhorizon utilisent des primitives symétriques 256 bits
et un partage de secret à sûreté informationnelle. L'algorithme de Shor ne
casse pas ces primitives ; l'algorithme de Grover réduit la marge de recherche
exhaustive des clés symétriques. Le transport préfère un KEM hybride, tandis
que l'authentification interactive et les signatures de certificats restent
classiques.

Deux contraintes encadrent l'évaluation :

- **La cryptographie symétrique et l'échange à clé publique n'ont pas la même
  marge quantique.** Les primitives symétriques 256 bits configurées conservent
  une marge estimée à 128 bits sous Grover. Un mécanisme d'encapsulation hybride
  combine ML-KEM et X25519 classique pour l'échange TLS.
- **Une vieille version de protocole ou un échange de clés purement classique
  est un risque harvest-now-decrypt-later.** Un attaquant enregistre le
  handshake aujourd'hui et pourrait déchiffrer la session si un ordinateur
  quantique casse ensuite l'échange classique. L'opérateur doit vérifier la
  négociation hybride sur chaque chemin ; les fallbacks classiques configurés
  ne sont pas résistants au quantique.

## Primitives applicatives (données au repos, interne)

Évaluation aux tailles de clés configurées :

| Primitive | Rôle | Statut quantique |
|---|---|---|
| Argon2id | dérivation de la master key depuis le password | dépend toujours de l'entropie du mot de passe et du coût KDF |
| HKDF-SHA512 | dérivation des sous-clés | construction symétrique, non cassée par Shor |
| XChaCha20-Poly1305 | chiffrement des secrets (secret vers DEK), 256-bit | marge exhaustive estimée à 128 bits sous Grover |
| AES-256-GCM | double enveloppe (DEK vers dek_key) | marge exhaustive estimée à 128 bits sous Grover |
| HMAC-SHA512 | auth des tokens | construction symétrique, non cassée par Shor |
| Chaîne HMAC | tamper-evidence de l'audit | construction symétrique, sans dépendance à une signature publique |
| Shamir GF(256) | shares de failover cluster | sûreté informationnelle si les parts restent indépendantes et le seuil non compromis |
| HMAC bootstrap (ha_password) | JOIN HA cross-nœud | construction symétrique ; l'entropie du mot de passe reste déterminante |
| age passphrase (scrypt + ChaCha20-Poly1305) | backups chiffrés | dépend toujours de l'entropie du mot de passe et du coût KDF |

Le chiffrement stocké ne dépend pas d'un handshake à clé publique enregistré :
il utilise AES-256 / XChaCha20 sous une clé dérivée du mot de passe, et les
sauvegardes age utilisent le destinataire scrypt-passphrase plutôt qu'un
destinataire X25519. L'authenticité d'audit utilise actuellement Ed25519, avec
HMAC-SHA512 pour les lignes legacy/fallback ; Ed25519 n'est pas post-quantique.

## Primitives clients et périmètre (actuel)

Versions concrètes dans l'image livrée : OpenSSL 3.5.x, TLS 1.3, PostgreSQL 18,
Go 1.25, rustls avec aws-lc-rs.

| Surface | Primitive (actuel) | Type | Statut quantique |
|---|---|---|---|
| TLS UI / client (nginx) | TLS 1.3 `X25519MLKEM768` préféré | KEM hybride avec fallback classique | résistant seulement si le groupe hybride est négocié |
| PG vers API (asyncpg) | TLS 1.3 `ssl_groups=X25519MLKEM768:...` (PG 18 + OpenSSL 3.5) | KEM hybride avec fallback classique | résistant seulement si le groupe hybride est négocié |
| HA inter-nœud (mTLS cluster) | KEM hybride via nginx + cert client ECDSA | KEM hybride, signature classique | échange résistant si la négociation hybride aboutit |
| Connecteurs Go (providers terraform / ESO) | `X25519MLKEM768` par défaut (Go 1.25) | KEM hybride | vérifier la négociation contre la cible |
| Agent Rust rh-* (fetch/inject/watch) | `X25519MLKEM768` via aws-lc-rs rustls | KEM hybride | vérifier la négociation contre la cible |
| WebAuthn / FIDO2 | ECDSA / EdDSA P-256 | signature | classique (interactif, non harvestable) |

L'agent Rust porte des valeurs de secrets en clair sur son hop, c'est donc le
plus critique : il construit son client HTTP Rust `reqwest` sur le provider
rustls aws-lc-rs (ring, le provider précédent, n'a pas ML-KEM). La preuve est au
fil : `tools/pq-verify.sh [host:port]` passe seulement si deux stacks
indépendantes (OpenSSL 3.5 et aws-lc-rs) négocient toutes deux `X25519MLKEM768`
contre la cible.

## Symétrique vs asymétrique

| Classe | Sert à | Exemples | Statut quantique |
|---|---|---|---|
| Symétrique | données au repos, auth, KDF | AES-256-GCM, XChaCha20, HMAC-SHA512, Argon2id | clés 256 bits : marge Grover estimée à 128 bits |
| KEM (échange de clés) | handshakes TLS | `X25519MLKEM768` (ML-KEM-768 hybride, FIPS 203) | résistant au quantique lorsqu'il est négocié |
| Signature | certs TLS, WebAuthn | ECDSA / EdDSA P-256 | classique, mais auth uniquement (MITM live, non harvestable) |
| Partage de secret | failover HA | Shamir GF(256) | sûreté informationnelle sous ses hypothèses de partage |

Seul le **KEM** protège contre le harvest-now-decrypt-later. Une signature
classique n'affecte que la forge MITM live, qui demande un ordinateur quantique
au moment du handshake ; une signature PQ (ML-DSA) là serait cosmétique.

## Configuration et vérification

`frontend/nginx-tls.conf` épingle l'échange de clés TLS 1.3 sur le groupe
hybride :

```
ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;
```

`X25519MLKEM768` est l'hybride IETF du X25519 classique et de ML-KEM-768. Le
lister en premier fait négocier les clients PQ-capables ; le fallback X25519 /
P-256 garde les clients plus anciens fonctionnels. PostgreSQL 18 reflète ça avec
`ssl_groups=X25519MLKEM768:X25519:secp256r1` (poser `PG_SSL_GROUPS` dans `.env`).

Prérequis, tous tenus par l'image épinglée : OpenSSL 3.5 ou plus récent (expose
`X25519MLKEM768` ; nginx rejette le groupe au démarrage sur un libssl plus
ancien) et TLS 1.3 (le KEM hybride est un groupe TLS 1.3 ; TLS 1.2 retombe sur
l'ECDHE classique).

Vérifier qu'un endpoint live a négocié le groupe PQ :

```bash
openssl s_client -connect HOST:8443 -tls1_3 -groups X25519MLKEM768 </dev/null 2>/dev/null \
  | grep -i 'Negotiated TLS1.3 group'
```
