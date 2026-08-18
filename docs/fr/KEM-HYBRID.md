# Certificats KEM hybrides (X25519 + ML-KEM-768)

Ce document spécifie le format de certificat KEM hybride que rhorizon émet sous
`kem_mode=x25519-ml-kem` et montre comment un détenteur récupère un secret
partagé. C'est le pendant, sur l'axe confidentialité, des certificats de
*signature* composites décrits dans [PKI.md](PKI.md). Pour la justification du
« pourquoi hybride » (obligation ANSSI/BSI, harvest-now-decrypt-later), voir la
section [Certificats KEM hybrides](PKI.md#certificats-kem-hybrides-x25519-ml-kem-768)
de PKI.md.

## Pourquoi deux jambes

Un KEM hybride combine un mécanisme d'établissement de clé **classique** (X25519,
un Diffie-Hellman sur courbe elliptique) avec un mécanisme **post-quantique**
(ML-KEM-768, FIPS 203). Le secret dérivé reste sûr tant qu'*au moins une* jambe
n'est pas cassée :

- si un ordinateur quantique casse X25519, la jambe ML-KEM protège encore le
  secret ;
- si une faille est trouvée dans le jeune code ML-KEM (ou dans le standard), la
  jambe classique X25519 le protège encore.

L'ANSSI et le BSI **exigent** tous deux cette combinaison pour l'axe
confidentialité ; le ML-KEM pur (`kem_mode=ml-kem`) est post-quantique mais pas
hybride et ne satisfait pas cette barre à lui seul.

## Forme du certificat

Un cert KEM hybride est un certificat X.509 v3 ordinaire dont la **clé publique
de sujet** est la clé hybride et dont la **signature** est produite par la CA du
namespace sous son propre algorithme (`ed25519`, `ml-dsa-65`, ou
`ed25519-mldsa65`). Algorithme de sujet != algorithme de signature — la
séparation du Workstream 2.

```
subjectPublicKeyInfo
  AlgorithmIdentifier  OID 1.3.6.1.4.1.62841.3.1   -- x25519-ml-kem-768 (arc privé)
  subjectPublicKey BIT STRING
    SEQUENCE SIZE (2) OF BIT STRING
      BIT STRING  x25519_pub    (32 octets)         -- jambe 0 (classique)
      BIT STRING  mlkem768_pub  (1184 octets)       -- jambe 1 (post-quantique)
KeyUsage         keyEncipherment (bit 2), critique
ExtendedKeyUsage absent  -- une clé KEM ne fait pas serverAuth/clientAuth
```

- **L'ordre des jambes est fixe** (X25519 d'abord, ML-KEM ensuite) et fait
  partie de la séparation de domaine du combineur — ne jamais réordonner.
- L'OID est un **placeholder d'arc privé** (`62841.3.x` = branche KEM hybride),
  interchangeable avec l'OID assigné de `draft-ietf-lamps-pq-composite-kem` une
  fois qu'il sera un RFC. Ces certs sont en interop interne uniquement ;
  l'outillage X.509 générique ne parsera pas la clé de sujet composite.

### Clé privée rendue une seule fois

À l'émission, le champ `private_key` de la réponse porte **deux** blocs PEM PKCS8
standard, affichés une seule fois et jamais stockés côté serveur :

```
-----BEGIN PRIVATE KEY-----      <- X25519 (RFC 8410)
...
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----      <- ML-KEM-768 expandedKey (FIPS 203)
...
-----END PRIVATE KEY-----
```

Chaque bloc est chargeable indépendamment (pas d'OID PKCS8 composite inventé). Le
bloc X25519 se charge avec n'importe quel outil RFC 8410 ; le bloc ML-KEM est la
forme `expandedKey` de FIPS 203 (interne tant que les drafts LAMPS n'ont pas
assigné d'encodage).

## Le combineur

Les deux parties dérivent le même secret partagé de 32 octets à partir des deux
secrets de jambe :

```
IKM  = ss_x25519 || ss_mlkem                       (jambe x25519 EN PREMIER = séparateur de domaine)
salt = "rhorizon-hybrid-kem-v1"
info = SHA512( label || ct_x25519 || ct_mlkem || pk_x25519 || pk_mlkem )
ss   = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )     -- HKDF-SHA512
```

- `label` = `"x25519-ml-kem-768"` (l'id de la construction ; un jeu de paramètres
  différent ou un futur changement de jambe reçoit un label frais pour que les
  secrets n'entrent jamais en collision).
- `pk_x25519` / `pk_mlkem` sont les clés publiques **statiques du destinataire**
  (les jambes de sujet du cert). `ct_x25519` est la clé publique X25519 éphémère
  de l'émetteur ; `ct_mlkem` est le ciphertext ML-KEM.
- Lier les deux ciphertexts et les deux clés publiques dans `info` donne la
  résistance à la ré-encapsulation / au transcript (forme ETSI TS 103 744 /
  Giacon-Heuer-Poettering). Le salt est suffixé par version pour que toute la
  construction soit remplaçable atomiquement.

Le combineur est la seule nouvelle étape cryptographique et il tourne dans
l'extension Rust (`rhorizon_crypto.hybrid_kdf`), verrouillé par un test à réponse
connue (KAT) dont la valeur attendue est calculée indépendamment par le
HKDF-SHA512 d'OpenSSL — un vrai KAT inter-implémentations, plus un test de parité
côté Python contre le wheel vivant. La jambe X25519 (keygen/DH/PKCS8) est OpenSSL
via `cryptography` ; le ML-KEM est `fips203`. Aucune primitive maison.

## Encapsuler / décapsuler

Émetteur (a le cert ; public seulement, n'a besoin d'aucun secret) :

```
paire X25519 éphémère (eph_sk, ct_x25519)
ss_x25519 = X25519(eph_sk, pk_x25519)              # DH avec la jambe statique du destinataire
ss_mlkem, ct_mlkem = ML-KEM-768.Encaps(pk_mlkem)
ss = hybrid_kdf(ss_x25519, ss_mlkem, ct_x25519, ct_mlkem, pk_x25519, pk_mlkem, label)
# transmettre (ct_x25519, ct_mlkem) au destinataire
```

Destinataire (détient la clé privée rendue-une-fois + son propre cert) :

```
ss_x25519 = X25519(x25519_sk, ct_x25519)           # même valeur DH
ss_mlkem  = ML-KEM-768.Decaps(mlkem_dk, ct_mlkem)
ss = hybrid_kdf(ss_x25519, ss_mlkem, ct_x25519, ct_mlkem, pk_x25519, pk_mlkem, label)
```

Les deux côtés calculent le `ss` identique. Le rejet implicite de ML-KEM signifie
qu'un `ct_mlkem` altéré produit un `ss_mlkem` pseudo-aléatoire déterministe
(jamais une erreur), donc un ciphertext manipulé fait simplement diverger les
deux parties — ce qui se révèle à la première utilisation de la clé dérivée.

### Helper Python

`api/app/pki_kem.py` compose les primitives :

```python
from api.app import pki_asn1, pki_kem

# --- émetteur : parser le sujet du cert en ses deux jambes, puis encapsuler
subject = pki_asn1.extract_subject_pubkey(pki_asn1.pem_to_der(cert_pem))
x25519_pub, mlkem_ek = pki_kem.split_hybrid_subject_key(subject)
ss_send, ct_x, ct_m = pki_kem.hybrid_encaps(x25519_pub, mlkem_ek)

# --- destinataire : charger la clé privée en deux blocs, puis décapsuler
x25519_priv, mlkem_dk = pki_kem.load_hybrid_private_pem(private_key_pem)
ss_recv = pki_kem.hybrid_decaps(
    x25519_priv, mlkem_dk, x25519_pub, mlkem_ek, ct_x, ct_m
)
assert ss_send == ss_recv          # secret partagé identique de 32 octets
```

## Vérifier la signature de la CA

La clé de sujet hybride ne change pas la manière dont la signature de la CA est
vérifiée — vérifiez-la avec le même vérifieur interne que n'importe quel autre
leaf de cet algorithme de CA (`ed25519` via `cryptography`, `ml-dsa-65` via
`verify_ml_dsa`, composite via `pki_ca.verify_composite_cert`). Voir
[PKI.md](PKI.md#vérifier-un-leaf).

## Limites

- Seul `x25519-ml-kem-768` est câblé (correspond au jeu TLS `X25519MLKEM768`).
  Les autres jeux de paramètres ML-KEM sont connus de la couche ASN.1 mais rejetés
  par le build.
- Interop interne uniquement tant que `draft-ietf-lamps-pq-composite-kem` n'est
  pas un RFC ; à ce moment-là, échanger l'OID privé + l'encodage et garder le
  combineur (ou adopter le KDF du draft s'il diverge) derrière une nouvelle
  version de `HYBRID_KEM_SALT`.
- Une troisième jambe à base de code (Classic McEliece) pour une couverture
  BSI/ISO reste un Cut 3 différé et optionnel.
