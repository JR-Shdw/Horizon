# Moteur PKI

Émet des certificats X.509 courts depuis une CA privée hébergée dans le coffre.
La clé privée de la CA est chiffrée au repos sous une sous-clé dédiée et ne signe
que sur le process maître ; les clés privées des leaves sont rendues une seule
fois et jamais stockées.

**Une CA par namespace.** Chaque namespace a sa propre CA émettrice indépendante
(son algorithme, sa racine de confiance), donc `prod` et `staging` sont isolés :
faire tourner ou révoquer l'une ne touche jamais l'autre. `init`/`ca`/`issue`/
`rotate` prennent un `namespace` (défaut `default`) ; `GET /pki/cas` liste les
namespaces qui ont une CA. Les exemples ci-dessous utilisent le namespace par
défaut ; ajoutez `namespace` pour en cibler un autre.

L'algorithme de signature de la CA est choisi une fois par namespace, à l'init :

| Algorithme | Type | Quand le choisir |
|---|---|---|
| `ed25519-mldsa65` | hybride composite (classique + PQ) | **Défaut.** Identités longue durée qui doivent satisfaire l'hybridation ANSSI/BSI : une signature Ed25519 **et** une signature ML-DSA-65, toutes deux requises pour vérifier. Survit à une cassure classique ou à une cassure par réseau euclidien. Vérifieurs internes uniquement (voir plus bas). |
| `ed25519` | classique | À choisir explicitement quand le leaf doit être vérifié par des stacks TLS ordinaires. Supporté partout aujourd'hui. |
| `ml-dsa-65` | post-quantique (FIPS 204) | Identités de service que vous voulez résistantes au quantique. Nécessite un vérifieur ML-DSA (OpenSSL 3.5+, tout ce qui implémente FIPS 204). PQ mais *pas* hybride, donc ne satisfait pas ANSSI/BSI à lui seul. |

Le défaut est délibérément l'hybride : c'est le seul des trois à satisfaire
l'hybridation ANSSI/BSI. La contrepartie, c'est que les certs composites se
vérifient **en interne uniquement** (OID privé) — si le consommateur est une
stack TLS standard, initialisez ce namespace en `ed25519` à la place.

Les certificats ML-DSA sont produits par le signeur Rust intégré (`fips204`) et
sont interopérables avec OpenSSL 3.5+/`cryptography` 49+ : le cert CA, les certs
leaf et les clés privées PKCS8 ML-DSA se chargent et se vérifient avec l'outillage
standard.

### Signatures hybrides composites (`ed25519-mldsa65`)

L'ANSSI et le BSI **exigent l'hybridation** pour les signatures post-quantiques :
un algorithme classique combiné à un algorithme PQ, parce que la PQC « n'est pas
assez mature pour assurer seule la sécurité » (une CA `ml-dsa-65` pure est PQ mais
*pas* hybride, donc ne les satisfait pas ; une CA `ed25519` pure n'est pas PQ).
L'algorithme composite signe chaque cert avec **à la fois** une clé Ed25519 et une
clé ML-DSA-65 sur le TBS identique, et un vérifieur **n'accepte que si les deux
signatures composantes vérifient** (combineur par concaténation ANSSI sec 3.2,
prouvé EUF-CMA ; une seule composante valide est un trou de downgrade et est
rejetée).

- **Encodage.** La clé publique de sujet est une `CompositePublicKey`
  (`SEQUENCE SIZE (2) OF BIT STRING` = clé Ed25519, clé ML-DSA) et la signature
  une `CompositeSignatureValue` (`SEQUENCE OF BIT STRING`), calquée sur
  draft-ietf-lamps-pq-composite-sigs mais émise sous un **arc d'OID privé**
  (`1.3.6.1.4.1.62841.2.1`, placeholder).
- **Réserve d'interop.** Parce que l'OID est privé et que les standards de certs
  composites bougent encore, ces certs sont pour **vérifieurs internes uniquement**
  (le CLI du coffre / `pki_ca.verify_composite_cert`) — ils **n'interopèrent pas**
  avec l'outillage X.509/TLS externe. L'OID est interchangeable avec l'
  `id-MLDSA65-Ed25519` assigné du draft une fois qu'il sera un RFC.
- **Custody.** La CA détient les deux clés privées (PKCS8 Ed25519 + la seed
  ML-DSA de 32 octets), length-framed et wrappées en un seul blob sous
  `pki_wrap_key` ; la rotation et le re-wrap du master password le gèrent tel
  quel. La clé privée du leaf émis est rendue une fois sous forme de deux blocs
  PEM PKCS8 standard.

### Certificats KEM (`ml-kem-768`)

L'axe signature ci-dessus protège l'*authenticité*. Un axe séparé protège la
*confidentialité* : un **certificat KEM** porte une clé publique de mécanisme
d'encapsulation de clé comme clé de sujet, utilisée pour établir un secret
partagé. Les deux axes sont indépendants — la clé de sujet d'un cert KEM est une
clé ML-KEM, tandis que sa signature est produite par la CA du namespace sous *son*
algorithme (`ed25519`, `ml-dsa-65`, ou l'hybride composite). Donc **algorithme de
clé de sujet != algorithme de signature**, contrairement aux certs de signature
ci-dessus où ils coïncident.

- **Ce que c'est.** `POST /pki/kem/issue` (CLI `rhorizon pki kem-issue`) émet un
  cert dont la clé de sujet est une clé d'encapsulation **ML-KEM-768** (FIPS 203,
  catégorie NIST 3), avec `KeyUsage=keyEncipherment` et **pas** d'EKU (une clé KEM
  ne fait pas serverAuth/clientAuth). ML-KEM-768 correspond au jeu
  `X25519MLKEM768` déjà utilisé dans le handshake TLS de l'agent.
- **Pourquoi un KEM et pas juste une signature PQ.** `X25519` est un KEM et
  `ML-DSA` une signature — fonctions différentes, ils ne peuvent pas être
  hybridés ensemble, et une *signature* PQ ne rend pas un *échange de clé*
  résistant au quantique. La confidentialité face à un futur adversaire quantique
  (« harvest now, decrypt later ») nécessite un **KEM** PQ ; c'est ce que ce cert
  fournit. Le ML-KEM pur (`kem_mode=ml-kem`) est PQ mais *pas hybride* ; pour
  l'hybridation ANSSI/BSI complète, ajoutez la jambe classique avec
  `kem_mode=x25519-ml-kem` (voir [Certificats KEM hybrides](#certificats-kem-hybrides-x25519-ml-kem-768)
  ci-dessous).
- **Crypto.** Le keygen/encaps/decaps ML-KEM tourne dans l'extension Rust via
  `fips203` (IntegrityChain, le frère direct du `fips204` déjà livré), verrouillé
  par les vecteurs à réponse connue NIST ACVP ML-KEM-768 keyGen/encaps/decaps. La
  clé de décapsulation du keygen est mlock'd + zeroizée comme la seed ML-DSA.
- **Custody.** Aucune nouvelle surface côté serveur : la CA ne détient toujours
  que sa clé de *signature*. La **clé de décapsulation (secrète) ML-KEM du leaf
  est rendue une fois** à l'émission (forme PKCS8 `expandedKey`) pour que le
  demandeur la détienne, et n'est jamais stockée. Le détenteur décapsule le
  ciphertext d'un pair pour récupérer le secret partagé.
- **Réserve d'interop.** Comme les certs composites : les OID ML-KEM sont ceux du
  NIST CSOR, mais l'outillage KEM-dans-X.509 se stabilise encore, donc traitez-les
  comme internes tant que les drafts LAMPS n'ont pas atterri. Vérifiez la signature
  de la CA sur un cert KEM avec le même vérifieur interne que n'importe quel autre
  leaf de cet algorithme de CA.

### Certificats KEM hybrides (`x25519-ml-kem-768`)

`kem_mode=x25519-ml-kem` fait passer le cert KEM à une clé de sujet **hybride** :
une jambe `X25519` classique **et** la jambe `ML-KEM-768`, combinées pour que le
secret partagé reste sûr tant qu'*une* des jambes n'est pas cassée. C'est
l'exigence ANSSI/BSI — les deux agences imposent l'hybridation parce que la PQC
seule « n'est pas assez mature pour assurer seule la sécurité », et le ML-KEM seul
tomberait face à une future cassure classique du standard (ou une faille
d'implémentation dans le jeune code PQ).

- **Clé de sujet.** Un `SEQUENCE SIZE (2) OF BIT STRING` — `(x25519_pub 32 o,
  mlkem768_pub 1184 o)`, même forme DER que la clé publique de signature
  composite. L'ordre des jambes est fixe (X25519 d'abord) et *est* le séparateur
  de domaine du combineur. Son propre OID vit sous l'arc privé
  `1.3.6.1.4.1.62841.3.1` (`62841.3.x` = branche KEM hybride), interchangeable
  avec l'OID assigné de `draft-ietf-lamps-pq-composite-kem` au RFC.
- **Combineur.** `ss = HKDF-SHA512(ss_x25519 || ss_mlkem)` avec
  `salt = "rhorizon-hybrid-kem-v1"` et
  `info = SHA512(label || ct_x25519 || ct_mlkem || pk_x25519 || pk_mlkem)`
  (forme ETSI TS 103 744 / Giacon-Heuer-Poettering). Lier les deux ciphertexts et
  les deux clés publiques du destinataire dans `info` donne la résistance à la
  ré-encapsulation / au transcript. Le combineur tourne dans l'extension Rust
  (`hybrid_kdf`), verrouillé par un test à réponse connue recoupé contre le HKDF
  d'OpenSSL ; aucune primitive maison.
- **Sourcing crypto.** La jambe X25519 (keygen, DH, PKCS8) utilise `cryptography`
  (OpenSSL) — la même bibliothèque auditée que le chemin `ed25519`, **aucun
  nouveau crate Rust**. La jambe ML-KEM réutilise les bindings `fips203` du Cut 1.
- **Custody.** Toujours aucune nouvelle surface côté serveur. Le leaf porte
  **deux** blocs de clé privée rendus-une-fois — un bloc PKCS8 X25519 suivi du
  bloc `expandedKey` ML-KEM — affichés seulement à l'émission, jamais stockés. Le
  détenteur repasse le `(ct_x25519, ct_mlkem)` d'un pair dans le combineur pour
  récupérer le secret.
- **Lequel utiliser.** `ml-kem` suffit là où vous n'avez besoin que de
  confidentialité PQ et contrôlez les deux bouts ; préférez `x25519-ml-kem` dès
  qu'une politique externe (ANSSI/BSI) ou la défense en profondeur contre du code
  PQ immature compte. Voir [KEM-HYBRID.md](KEM-HYBRID.md) pour le format wire et
  une démonstration d'interop.

## Démarrage rapide (CLI)

```bash
# 1. Initialiser la CA une fois. Le défaut est l'hybride composite ANSSI/BSI.
rhorizon pki init --cn rhorizon-pki                    # ed25519-mldsa65 (défaut)
# ou :  rhorizon pki init --algorithm ml-dsa-65        # post-quantique pur
# ou :  rhorizon pki init --algorithm ed25519          # classique

# 2. Distribuer le cert CA à ce qui doit faire confiance aux leaves
rhorizon pki ca --out rhorizon-ca.pem

# 3. Émettre un leaf pour un service (keygen côté serveur)
rhorizon pki issue svc.internal \
  --dns svc.internal --ip 10.0.0.1 \
  --ttl-days 30 -n default \
  --cert-out svc.pem --key-out svc.key   # fichier clé écrit en mode 0600

# 3b. Émettre un cert KEM pour la confidentialité (clé de sujet ML-KEM, signée par la CA)
rhorizon pki kem-issue kem.internal \
  --dns kem.internal --ttl-days 30 -n default \
  --cert-out kem.pem --key-out kem.decaps.key   # clé de decaps écrite en mode 0600

# 3c. Cert KEM hybride X25519+ML-KEM (hybridation ANSSI/BSI)
rhorizon pki kem-issue hybrid.internal --mode x25519-ml-kem \
  --dns hybrid.internal --ttl-days 30 -n default \
  --cert-out hybrid.pem --key-out hybrid.decaps.key   # deux blocs PKCS8

# 4. Lister + révoquer
rhorizon pki certs
rhorizon pki revoke <serial> --reason superseded

# 5. Rotation de la CA (l'ancienne reste valide en fenêtre de grâce)
rhorizon pki rotate
```

## API

Préfixe `/api/v1/vault/pki`. Le coffre doit être déverrouillé.

| Méthode | Endpoint | Scope | Rôle |
|---|---|---|---|
| `POST` | `/init` | `admin:w` | Initialiser la CA une fois par namespace (409 si déjà fait) |
| `GET`  | `/cas` | `secrets:r` | Lister les namespaces qui ont une CA |
| `GET`  | `/ca` | `secrets:r` | Cert CA PEM (+ cert précédent pendant la grâce) |
| `POST` | `/issue` | `secrets:w` | Émettre un leaf ; rend cert + clé UNE fois (namespace-checké) |
| `POST` | `/kem/issue` | `secrets:w` | Émettre un cert KEM (clé de sujet ML-KEM, signée par la CA) ; rend cert + clé de decaps UNE fois |
| `GET`  | `/certs` | `secrets:r` | Lister les certs émis (filtré namespace, sans clés) |
| `POST` | `/revoke` | `admin:w` | Marquer un cert révoqué par serial |
| `POST` | `/rotate` | `admin:w` | Rotation CA, ancien cert gardé en fenêtre de grâce |

```bash
# init
curl -X POST https://vault/api/v1/vault/pki/init \
  -H "Authorization: Bearer $ADMIN" \
  -d '{"algorithm":"ml-dsa-65","common_name":"rhorizon-pki","validity_days":3650}'

# issue
curl -X POST https://vault/api/v1/vault/pki/issue \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"common_name":"svc.internal","san_dns":["svc.internal"],
       "san_ips":["10.0.0.1"],"ttl_days":30,"namespace":"default"}'
# -> { "serial", "certificate", "private_key", "ca_chain", "fingerprint",
#      "algorithm", "not_after" }   (private_key affichée seulement ici)

# kem/issue (clé de sujet = ML-KEM-768, signée par la CA)
curl -X POST https://vault/api/v1/vault/pki/kem/issue \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"common_name":"kem.internal","san_dns":["kem.internal"],
       "kem_algorithm":"ml-kem-768","kem_mode":"ml-kem",
       "ttl_days":30,"namespace":"default"}'
# kem_mode "x25519-ml-kem" -> subject_algorithm hybride "x25519-ml-kem-768"
# -> { "serial", "certificate", "private_key", "ca_chain", "fingerprint",
#      "algorithm", "subject_algorithm", "kem_mode", "not_after" }
#    private_key = la/les clé(s) de décapsulation, affichée(s) seulement ici
```

## UI

Eclipse (Secrets) a un onglet **PKI**. Avant l'init il montre le sélecteur
d'algorithme ; après, le statut de la CA, un formulaire d'émission de leaf, un
**formulaire d'émission KEM** (avec un sélecteur de mode : `x25519-ml-kem` hybride
ou `ml-kem` pur), et le tableau des certs émis avec révocation. Le tableau fait
apparaître l'algorithme de sujet KEM pour les certs KEM. Le cert + clé(s) émis
sont révélés une seule fois avec des boutons de copie.

## Vérifier un leaf

La recette dépend de l'algorithme de la CA. **Le défaut (`ed25519-mldsa65`)
n'est pas vérifiable par `openssl`** — il utilise un OID privé, donc
l'outillage standard ne sait pas analyser la signature composite. Pour
celui-là, utilisez le vérifieur interne.

```bash
# ed25519-mldsa65 (DÉFAUT) -- interne uniquement, pas d'OpenSSL
python - <<'PY'
from app import pki_ca
ca = open('rhorizon-ca.pem','rb').read()
leaf = open('svc.pem','rb').read()
ed_pub, mldsa_pub = pki_ca.composite_component_pubs(ca)
# Accepte si et seulement si les DEUX signatures composantes vérifient (une
# seule jambe valide est un trou de downgrade, et elle est rejetée).
print('ok' if pki_ca.verify_composite_cert(leaf, ed_pub, mldsa_pub) else 'FAIL')
PY

# ed25519 (n'importe quel OpenSSL)
openssl verify -CAfile rhorizon-ca.pem svc.pem

# ml-dsa-65 (OpenSSL 3.5+ ou cryptography 49+)
openssl verify -CAfile rhorizon-ca.pem svc.pem
python -c "from cryptography import x509; \
  ca=x509.load_pem_x509_certificate(open('rhorizon-ca.pem','rb').read()); \
  lf=x509.load_pem_x509_certificate(open('svc.pem','rb').read()); \
  ca.public_key().verify(lf.signature, lf.tbs_certificate_bytes); print('ok')"
```

## Notes de conception

- **Séparée de la cluster CA.** Sa propre wrap key (`pki_wrap_key`), ses tables
  (`vault_pki_config`, `vault_pki_certs`), son AAD. Aucun couplage au mTLS cluster.
- **Custody de la clé CA.** Le matériel privé est wrappé sous `pki_wrap_key`
  (dérivé HKDF, domain-separated). Pour ML-DSA la clé est une seed FIPS 204 de
  32 octets, mlock'd en Rust, reconstruite en clé étendue uniquement sur le
  maître au moment de signer puis zeroizée. La rotation du master password la
  re-wrappe.
- **Failover-safe.** `pki_wrap_key` voyage dans le bundle de sous-clés
  Shamir/rekey, donc un failover maître garde la CA utilisable sans re-unseal.
- **Fenêtre de grâce de rotation.** `pki rotate` génère une nouvelle CA et garde
  l'ancien cert (`pki_ca_cert_prev`) pour que les leaves en vol restent
  vérifiables ; `GET /ca` retourne les deux pendant la fenêtre.
- **Audit.** Chaque init / issue / revoke / rotate est enregistré dans la chaîne.

## Limites (v1)

- Algorithmes de signature : `ed25519`, `ml-dsa-65`, et `ed25519-mldsa65`
  (hybride composite). `ml-dsa-87` (niveau NIST 5) nécessite un signeur Rust
  séparé et est un suivi. Les certs composites sont en vérification interne
  uniquement (OID privé).
- Clés de sujet KEM : `ml-kem-768` uniquement (les OID 512/1024 sont connus de la
  couche ASN.1 mais non câblés dans l'extension Rust). `kem_mode` accepte `ml-kem`
  (pur) et `x25519-ml-kem` (hybride X25519 + ML-KEM, confidentialité ANSSI/BSI) ;
  une troisième jambe Classic McEliece reste un Cut différé et optionnel.
- Révocation en registre seulement / consultative (`advisory:true` dans la
  réponse `/revoke`) : elle bloque la ré-émission et marque la ligne, mais sans
  CRL/OCSP les vérifieurs externes ne la voient pas. Le vrai contrôle est la
  durée de vie courte, d'où le plafond d'émission à 398 jours. Un répondeur
  CRL/OCSP est à venir.
- Le keygen côté serveur rend la clé privée du leaf une seule fois (elle transite
  la réponse comme tout secret servi). Un mode signature-seule (CSR) est à venir.
- ML-DSA est **post-quantique mais le crate `fips204` n'est pas encore audité
  indépendamment** ; il est verrouillé par les vecteurs NIST ACVP + vérifié
  contre OpenSSL. Voir [Post-quantique](POST-QUANTUM.md) et
  [Canaux auxiliaires](../SIDE-CHANNELS.md).
