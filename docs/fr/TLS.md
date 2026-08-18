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
