# TLS - HTTPS natif pour Resurgamus Horizon

rhorizon peut servir du HTTPS directement via nginx, sans reverse proxy externe.
Utile quand il n'y a pas de VPN ou de load balancer TLS en amont.

## Architecture

```mermaid
flowchart LR
    C[Client<br/>browser, curl, K8s pod]
    C -->|:8443 HTTPS| N[nginx<br/>TLS termination]
    N -->|HTTP :8200<br/>Docker internal| A[API :8200]
    C -->|:8200 HTTP<br/>healthcheck, reverse-proxy backend| N2[nginx] --> A
```

Le port HTTP :8200 reste toujours actif (healthcheck Docker, backend Traefik).
Le port HTTPS :8443 est activé uniquement si `TLS_ENABLED=true`.

## Installations natives (sans conteneur)

`tools/install-native.sh` n'a pas d'image nginx sur laquelle s'appuyer, donc il
décide à l'installation où TLS se termine. Les deux issues sont du TLS ; elles
diffèrent par la version HTTP et par ce que l'échange de clés peut offrir.

```mermaid
flowchart TB
    subgraph A["nginx devant (préféré)"]
        C1[Client] -->|HTTPS + HTTP/2| N[nginx<br/>TLS + PQ + CSP + SPA]
        N -->|HTTP/1.1 loopback| U1[uvicorn 127.0.0.1]
    end
    subgraph B["uvicorn devant (repli)"]
        C2[Client] -->|HTTPS, HTTP/1.1 seulement| U2[uvicorn --ssl-certfile]
    end
```

nginx est choisi quand le driver de l'OS peut en superviser un, et seulement
s'il sait faire HTTP/2 — c'est toute la justification du saut supplémentaire,
puisque uvicorn sert déjà du HTTPS. Sinon uvicorn termine directement : il n'a
aucune implémentation HTTP/2 et n'annonce même pas d'ALPN, donc tous les
clients retombent en HTTP/1.1.

**Le post-quantique est par-voie et dépend de ce que chaque binaire lie, pas de
la réputation de l'OS.** ML-KEM exige OpenSSL >= 3.5. uvicorn hérite sa liste
de groupes de l'OpenSSL contre lequel son interpréteur a été construit —
hérité, pas configuré, donc impossible à affirmer comme on peut le faire avec
le `ssl_ecdh_curve` de nginx.

| Voie | Termine à | HTTP/2 | Post-quantique |
|---|---|---|---|
| OpenBSD, nginx packagé | uvicorn | non | **oui** — eopenssl 3.5 via CPython [^obsd] |
| FreeBSD, nginx packagé | nginx | oui | **non** — OpenSSL de base 3.0.20 [^fbsd] |
| N'importe quel BSD, `tools/build-nginx-bsd.sh` | nginx | oui | **oui** — les trois mesurés |
| Debian 13 (trixie) | nginx | oui | **oui** — OpenSSL 3.5.6 [^deb] |
| Autre Linux | nginx | oui | si la libssl de la distro >= 3.5 (non mesuré) |
| NetBSD 10.1, nginx packagé | nginx | oui | **non** — OpenSSL de base 3.0.12 [^nbsd] |
| N'importe quelle voie, `--no-nginx` | uvicorn | non | ce que l'interpréteur lie |

[^obsd]: Mesuré, pas supposé. Sur une install complète sur OpenBSD 7.8, le
nginx packagé acceptait `listen ... http2` (avertissement de dépréciation
seulement) mais échouait sur `SSL_CTX_set1_curves_list`, donc il n'est jamais
devenu le front. Même en omettant la directive il serait décliné, parce que
LibreSSL n'a pas ML-KEM et que cette voie exige le post-quantique.

[^fbsd]: Mesuré aussi, sur 14.4-RELEASE-p8, et c'est un défaut de packaging de
notre côté plutôt qu'une limite de FreeBSD. La base est OpenSSL 3.0.20 et le
nginx du pkg la lie (`ldd` -> `/usr/lib/libssl.so.30`) ; ML-KEM exige 3.5+.
Mais `openssl35-3.5.7` est dans pkg et liste bien `X25519MLKEM768`. nginx est
quand même retenu ici plutôt que décliné, parce que le `python312` packagé lie
la même libssl de base — donc uvicorn n'a pas non plus de post-quantique, et
refuser nginx perdrait HTTP/2 sans rien gagner. Lancez
`tools/build-nginx-bsd.sh` pour obtenir les deux. À comparer avec OpenBSD, où
décliner nginx préserve réellement le PQ.

[^deb]: Mesuré sur une install système complète : OpenSSL 3.5.6 liste
X25519MLKEM768, la sonde a sélectionné la liste de groupes PQ, et le vault
s'est descellé à travers nginx en TLS. La seule voie native qui obtient HTTP/2
et post-quantique sans étape supplémentaire.

[^nbsd]: Mesuré sur 10.1. La base est OpenSSL 3.0.12 sans ML-KEM, donc le nginx
packagé sert HTTP/2 avec un échange de clés classique ; pkgsrc livre 3.6.3, qui
liste bien X25519MLKEM768. Comme FreeBSD et contrairement à OpenBSD, il ne pose
pas `RH_NGINX_REQUIRE_PQ`, parce que le venv lie la base lui aussi. Construire
nginx contre l'OpenSSL de pkgsrc a ensuite été vérifié sur cette voie : `ldd`
-> `/usr/pkg/lib/libssl.so.3`, ALPN `h2`, groupe `X25519MLKEM768`. Notez que
l'install a besoin de bien plus que les 13 Go de root de la golden pour les
builds Rust, d'où le routage de `CARGO_HOME` et `CARGO_TARGET_DIR` vers
`TMPDIR` par le driver.

L'installeur ne devine pas quelle liste de groupes un nginx donné supporte. Il
rend la config avec `X25519MLKEM768` en tête, lance `nginx -t`, et en cas de
rejet retombe sur la liste classique, puis sur l'omission complète de
`ssl_ecdh_curve`. Analyser les versions serait faux exactement là où ça compte,
parce que nginx peut lier une libssl sans rapport avec l'`openssl(1)` du `PATH`.

La troisième étape n'est pas de la paranoïa : le nginx packagé d'OpenBSD lie
LibreSSL et rejette même la liste classique, nommément —
`SSL_CTX_set1_curves_list("X25519:secp256r1") failed`. La *syntaxe* des groupes
n'est pas portable, donc omettre la directive est la seule forme universellement
valide. Si tous les rendus sont rejetés, l'installeur garde TLS au niveau
d'uvicorn plutôt que d'échouer.

### Obtenir le post-quantique sur les BSD

Aucun des nginx packagés des BSD ne sait faire ML-KEM, pour des raisons
différentes, et sur un vault ça compte dès maintenant — harvest-now-decrypt-later
est une menace présente.

Le nginx packagé d'OpenBSD lie la LibreSSL de base, qui n'a pas ML-KEM du tout,
alors que son uvicorn l'a (le driver installe le port eopenssl et construit
CPython contre lui). Prendre ce nginx échangerait le post-quantique contre
HTTP/2, donc le driver pose `RH_NGINX_REQUIRE_PQ=1` et l'installeur le décline.

FreeBSD est le piège inverse : là-bas nginx a HTTP/2 mais lie l'OpenSSL 3.0 de
base, et son python aussi, donc *rien* sur cette voie n'a de post-quantique par
défaut. Il ne pose délibérément pas `RH_NGINX_REQUIRE_PQ` — décliner nginx
abandonnerait HTTP/2 pour un repli tout aussi non-PQ.

Les deux se corrigent de la même façon, en liant nginx contre un OpenSSL qui a
ML-KEM (eopenssl sur OpenBSD, `openssl35` sur FreeBSD, l'`openssl` de pkgsrc sur
NetBSD). Passez `--pq-nginx` et l'installeur le fait pour vous :

```sh
sh tools/install-native.sh --mode system --pq-nginx
```

Ou construisez d'abord et laissez le driver récupérer le binaire via
`RH_NGINX_BIN` :

```sh
sh tools/build-nginx-bsd.sh              # source épinglée, vérifiée PGP
sh tools/install-native.sh --mode system
```

### Choisir : HTTP/2, post-quantique, ou les deux

Les deux sont indépendants, et sur plusieurs voies le logiciel packagé n'en
donne qu'un. Décidez à partir de la menace et de la charge, pas de l'OS :

| Vous avez besoin de | Parce que | Prenez |
|---|---|---|
| Post-quantique | Harvest-now-decrypt-later : un handshake enregistré **aujourd'hui** est cassé plus tard par un ordinateur quantique. Ça protège le trafic déjà passé sur le fil, pas seulement le futur. | `--pq-nginx`, ou une voie qui l'a par défaut |
| HTTP/2 | Latence plus basse pour un navigateur qui émet des requêtes concurrentes sur une seule connexion. **Pas** une exigence de débit : la course keep-alive à c=500 est réglée par l'inégalité de timeouts du pool amont (nginx 25 s < uvicorn 30 s), qui vaut aussi pour le 1.1. Voir `frontend/nginx-tls.conf`. | nginx devant (le défaut là où c'est supporté) |
| Les deux | Un vault qui est aussi sur un chemin chaud | `--pq-nginx` |

`--pq-nginx` est opt-in plutôt que défaut parce que c'est un build source de
quelques minutes, pas une install de paquet. C'est un no-op sur les voies qui
ont déjà le post-quantique, et il avertit au lieu d'échouer si le build ne
réussit pas — le nginx packagé sert quand même HTTP/2 dans ce cas.

Vérifié sur OpenBSD 7.8 avec eopenssl 3.5.4 et nginx 1.30.4 : `ldd` montre
`eopenssl35/libssl.so.37.0`, ALPN négocie `h2`, et le groupe TLS 1.3 est
`X25519MLKEM768`. C'est la ligne `ldd` qui compte et le script l'asserte : `-L`
ne satisfait que l'éditeur de liens, et sans le rpath le binaire charge la
libssl de base à l'exécution et perd ML-KEM sans la moindre erreur.

## Activation

### 1. Préparer les certificats

Placer les fichiers dans un dossier (par défaut `./certs/`) :

```
certs/
  cert.pem     # certificat serveur + chain (fullchain)
  key.pem      # clé privée
```

### 2. Configurer le .env

```bash
TLS_ENABLED=true
TLS_CERT_DIR=./certs
# Chemins dans le container (montés en :ro)
TLS_CERT=/certs/cert.pem
TLS_KEY=/certs/key.pem
```

### 3. Redémarrer

```bash
docker compose up -d --build frontend
```

nginx affiche au démarrage :
```
[tls-setup] TLS enabled on :8443 (cert: /certs/cert.pem)
```

## Format des certificats

### cert.pem - fullchain (obligatoire)

Le fichier `cert.pem` doit contenir le **certificat serveur + la chaîne intermédiaire**,
dans cet ordre (PEM concatené) :

```
-----BEGIN CERTIFICATE-----
(certificat du serveur - leaf)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(certificat intermédiaire - issuer)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(certificat intermédiaire racine - si applicable)
-----END CERTIFICATE-----
```

**Ne pas inclure le certificat racine (root CA)** - les clients l'ont déjà
dans leur trust store. L'inclure ne casse rien mais alourdit le handshake.

| Source | Fichier à utiliser |
|--------|--------------------|
| Let's Encrypt (certbot) | `fullchain.pem` |
| Let's Encrypt (acme.sh) | `fullchain.cer` ou `ca.cer` + `cert.cer` concatenés |
| cert-manager (K8s) | `tls.crt` (contient déjà la fullchain) |
| Achat CA (DigiCert, Sectigo...) | Concatener : `server.crt` + `intermediate.crt` |
| Auto-signé | `cert.pem` (pas de chain, le client doit ajouter la CA) |

#### Vérifier la chaîne

```bash
# Afficher les certificats dans le fichier
openssl crl2pkcs7 -nocrl -certfile certs/cert.pem | \
    openssl pkcs7 -print_certs -noout

# Vérifier que la chaîne est complète
openssl verify -untrusted certs/cert.pem certs/cert.pem
```

### key.pem - clé privée

Clé RSA ou ECDSA, format PEM, **non chiffrée** (pas de passphrase) :

```
-----BEGIN PRIVATE KEY-----
(clé privée)
-----END PRIVATE KEY-----
```

ou format legacy RSA :

```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

| Source | Fichier à utiliser |
|--------|--------------------|
| Let's Encrypt (certbot) | `privkey.pem` |
| Let's Encrypt (acme.sh) | `domain.key` |
| cert-manager (K8s) | `tls.key` |
| openssl | `server.key` (si `-nodes` utilisé à la génération) |

**Permissions** : la clé est montée en `:ro` dans le container. Sur l'hôte :

```bash
chmod 600 certs/key.pem
chown root:root certs/key.pem
```

#### Vérifier la correspondance cert/key

```bash
# Les deux doivent afficher le même hash
openssl x509 -noout -modulus -in certs/cert.pem | openssl md5
openssl rsa -noout -modulus -in certs/key.pem | openssl md5
```

Pour ECDSA :
```bash
openssl x509 -noout -pubkey -in certs/cert.pem | openssl md5
openssl ec -pubout -in certs/key.pem | openssl md5
```

## Génération de certificats

### Auto-signé (dev/test)

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout certs/key.pem -out certs/cert.pem \
    -days 365 -nodes -subj "/CN=vault.local"
```

### Let's Encrypt (certbot)

```bash
certbot certonly --standalone -d vault.example.com
cp /etc/letsencrypt/live/vault.example.com/fullchain.pem certs/cert.pem
cp /etc/letsencrypt/live/vault.example.com/privkey.pem certs/key.pem
```

### cert-manager (Kubernetes)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: rhorizon-tls
spec:
  secretName: rhorizon-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - vault.example.com
```

Le Secret K8s `rhorizon-tls` contient `tls.crt` et `tls.key`,
montables comme volume dans le pod.

## Contextes de déploiement

| Contexte | TLS_ENABLED | Certificat | Notes |
|----------|-------------|------------|-------|
| VPN + reverse proxy | `false` | Le proxy amont gère TLS | Pas besoin, réseau chiffré |
| LAN entreprise (pas de VPN) | `true` | CA interne ou auto-signé | Distribuer la CA aux clients |
| Kubernetes | `true` | cert-manager | Secret monté en volume |
| GitLab CI / réseau backend | `true` | Let's Encrypt ou CA interne | HTTPS requis pour les API calls |
| Dev local | `false` | - | HTTP suffit sur localhost |

## Configuration TLS nginx

Le server block HTTPS utilise :

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
# Echange de cles post-quantique (TLS 1.3), prefere en premier.
ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

- **TLS 1.2 minimum** - TLS 1.0/1.1 désactivés (obsolètes)
- **AEAD ciphers uniquement** - AES-GCM, pas de CBC
- **Forward secrecy** - ECDHE obligatoire
- **Echange de cles post-quantique** - `X25519MLKEM768`, un KEM hybride (X25519
  classique + ML-KEM-768 / FIPS 203) negocie en premier sur le handshake
  TLS 1.3, donc une session enregistree ne peut pas etre cassee plus tard par un
  ordinateur quantique (harvest-now-decrypt-later). Repli X25519 / P-256 pour
  les clients non-PQ. Requiert OpenSSL >= 3.5 (l'image frontend embarque
  libssl 3.5.x).
- **HSTS** - `max-age=63072000; includeSubDomains; preload` (2 ans)

### Tester la configuration

```bash
# Depuis un poste sur le réseau
curl -v https://vault.example.com:8443/health

# Vérifier les ciphers
nmap --script ssl-enum-ciphers -p 8443 vault.example.com

# Test complet (si exposé)
# https://www.ssllabs.com/ssltest/
```

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `TLS_ENABLED` | `false` | Active le server block HTTPS :8443 |
| `TLS_CERT` | `/certs/cert.pem` | Chemin du certificat (fullchain) dans le container |
| `TLS_KEY` | `/certs/key.pem` | Chemin de la clé privée dans le container |
| `TLS_CERT_DIR` | `./certs` | Dossier hôte monté en `/certs:ro` |

## Rotation des certificats

nginx relit les certificats à chaque reload :

```bash
# Copier les nouveaux certs
cp /path/to/new/fullchain.pem certs/cert.pem
cp /path/to/new/privkey.pem certs/key.pem

# Reload sans downtime
docker exec rhorizon_frontend nginx -s reload
```

Pour Let's Encrypt, ajouter un cron post-renew :

```bash
# /etc/letsencrypt/renewal-hooks/deploy/rhorizon.sh
#!/bin/sh
cp /etc/letsencrypt/live/vault.example.com/fullchain.pem /path/to/rhorizon/certs/cert.pem
cp /etc/letsencrypt/live/vault.example.com/privkey.pem /path/to/rhorizon/certs/key.pem
docker exec rhorizon_frontend nginx -s reload
```
