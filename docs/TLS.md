# TLS - Native HTTPS for Resurgamus Horizon

Resurgamus Horizon can serve HTTPS directly via nginx, without an external reverse proxy.
Useful when there is no VPN or upstream TLS load balancer in front.

## Architecture

```mermaid
flowchart LR
    C[Client<br/>browser, curl, K8s pod]
    C -->|:8443 HTTPS| N[nginx<br/>TLS termination]
    N -->|HTTP :8200<br/>Docker internal| A[API :8200]
    C -->|:8200 HTTP<br/>healthcheck, reverse-proxy backend| N2[nginx] --> A
```

HTTP port :8200 is always active (Docker healthcheck, Traefik backend).
HTTPS port :8443 is only activated when `TLS_ENABLED=true`.

## Native installs (no container)

`tools/install-native.sh` has no nginx image to rely on, so it decides where TLS
terminates at install time. Both outcomes are TLS; they differ in HTTP version
and in what the key exchange can offer.

```mermaid
flowchart TB
    subgraph A["nginx front (preferred)"]
        C1[Client] -->|HTTPS + HTTP/2| N[nginx<br/>TLS + PQ + CSP + SPA]
        N -->|HTTP/1.1 loopback| U1[uvicorn 127.0.0.1]
    end
    subgraph B["uvicorn front (fallback)"]
        C2[Client] -->|HTTPS, HTTP/1.1 only| U2[uvicorn --ssl-certfile]
    end
```

nginx is chosen when the OS driver can supervise one, and only when it can do
HTTP/2 -- that is the entire justification for the extra hop, since uvicorn
already serves HTTPS. Otherwise uvicorn terminates directly: it has no HTTP/2
implementation and does not even advertise ALPN, so every client falls back to
HTTP/1.1.

**Post-quantum is per-lane and depends on what each binary links, not on the
OS's reputation.** ML-KEM needs OpenSSL >= 3.5. uvicorn inherits its group list
from whatever OpenSSL its interpreter was built against -- inherited, not
configured, so it cannot be asserted the way nginx's `ssl_ecdh_curve` can.

| Lane | Terminates at | HTTP/2 | Post-quantum |
|---|---|---|---|
| OpenBSD, packaged nginx | uvicorn | no | **yes** -- eopenssl 3.5 via CPython [^obsd] |
| FreeBSD, packaged nginx | nginx | yes | **no** -- base OpenSSL 3.0.20 [^fbsd] |
| Any BSD, `tools/build-nginx-bsd.sh` | nginx | yes | **yes** -- all three measured |
| Debian 13 (trixie) | nginx | yes | **yes** -- OpenSSL 3.5.6 [^deb] |
| Other Linux | nginx | yes | if the distro's libssl >= 3.5 (unmeasured) |
| NetBSD 10.1, packaged nginx | nginx | yes | **no** -- base OpenSSL 3.0.12 [^nbsd] |
| Any lane, `--no-nginx` | uvicorn | no | whatever the interpreter links |

[^obsd]: Measured, not assumed. On a full install on OpenBSD 7.8 the packaged
nginx accepted `listen ... http2` (deprecation warning only) but failed
`SSL_CTX_set1_curves_list`, so it never became the front. Even with the
directive omitted it would still be declined, because LibreSSL has no ML-KEM
and this lane requires post-quantum.

[^fbsd]: Also measured, on 14.4-RELEASE-p8, and it is a packaging failure on our
side rather than a FreeBSD limitation. Base is OpenSSL 3.0.20 and the pkg nginx
links it (`ldd` -> `/usr/lib/libssl.so.30`); ML-KEM needs 3.5+. But
`openssl35-3.5.7` sits in pkg and does list `X25519MLKEM768`. nginx is still
taken here rather than declined, because the packaged `python312` links that
same base libssl -- so uvicorn has no post-quantum either and refusing nginx
would lose HTTP/2 while gaining nothing. Run `tools/build-nginx-bsd.sh` to get
both. Contrast OpenBSD, where declining nginx genuinely preserves PQ.

[^deb]: Measured on a full system install: OpenSSL 3.5.6 lists X25519MLKEM768,
the probe selected the PQ group list, and the vault unsealed through nginx over
TLS. The only native lane that gets HTTP/2 and post-quantum with no extra step.

[^nbsd]: Measured on 10.1. Base is OpenSSL 3.0.12 with no ML-KEM, so the
packaged nginx serves HTTP/2 with a classical key exchange; pkgsrc ships 3.6.3,
which does list X25519MLKEM768. Like FreeBSD and unlike OpenBSD it does not set
`RH_NGINX_REQUIRE_PQ`, because the venv links base too. Building nginx against
pkgsrc OpenSSL was then verified on this lane: `ldd` -> `/usr/pkg/lib/libssl.so.3`,
ALPN `h2`, group `X25519MLKEM768`. Note the install needs well over the golden's
13G root for the Rust builds, which is why the driver routes `CARGO_HOME` and
`CARGO_TARGET_DIR` to `TMPDIR`.

The installer does not guess which group list a given nginx supports. It renders
the config with `X25519MLKEM768` first, runs `nginx -t`, and on rejection falls
back to the classical list, then to omitting `ssl_ecdh_curve` altogether.
Version parsing would be wrong exactly where it matters, because nginx can link
a libssl unrelated to the `openssl(1)` on `PATH`.

The third step is not paranoia: OpenBSD's packaged nginx links LibreSSL and
rejects even the classical list, by name --
`SSL_CTX_set1_curves_list("X25519:secp256r1") failed`. The group *syntax* is not
portable, so omitting the directive is the only universally valid form. If every
render is rejected, the installer keeps TLS at uvicorn rather than failing.

### Getting post-quantum on the BSDs

Neither BSD's packaged nginx can do ML-KEM, for different reasons, and on a
vault that matters now -- harvest-now-decrypt-later is a present threat.

OpenBSD's packaged nginx links base LibreSSL, which has no ML-KEM at all, while
its uvicorn *does* have it (the driver installs the eopenssl port and builds
CPython against it). Taking that nginx would trade post-quantum for HTTP/2, so
the driver sets `RH_NGINX_REQUIRE_PQ=1` and the installer declines it.

FreeBSD is the opposite trap: nginx there has HTTP/2 but links base OpenSSL 3.0,
and so does its python, so *nothing* on that lane has post-quantum by default.
It deliberately does not set `RH_NGINX_REQUIRE_PQ` -- declining nginx would give
up HTTP/2 for a fallback that is equally non-PQ.

Both are fixed the same way, by linking nginx against an OpenSSL that has ML-KEM
(eopenssl on OpenBSD, `openssl35` on FreeBSD, pkgsrc `openssl` on NetBSD). Pass
`--pq-nginx` and the installer does it for you:

```sh
sh tools/install-native.sh --mode system --pq-nginx
```

Or build first and let the driver pick the binary up via `RH_NGINX_BIN`:

```sh
sh tools/build-nginx-bsd.sh              # pinned source, PGP-verified
sh tools/install-native.sh --mode system
```

### Choosing: HTTP/2, post-quantum, or both

The two are independent, and on several lanes the packaged software gives only
one. Decide from the threat and the load, not from the OS:

| You need | Because | Take |
|---|---|---|
| Post-quantum | Harvest-now-decrypt-later: a handshake recorded **today** is broken later by a quantum computer. This protects traffic already on the wire, not just future traffic. | `--pq-nginx`, or a lane that has it by default |
| HTTP/2 | Lower latency for a browser issuing concurrent requests on one connection. **Not** a throughput requirement: the c=500 keep-alive race is fixed by the upstream pool's timeout inequality (nginx 25s < uvicorn 30s), which holds for 1.1 too. See `frontend/nginx-tls.conf`. | nginx front (the default where supported) |
| Both | A vault that is also on a hot path | `--pq-nginx` |

`--pq-nginx` is opt-in rather than default because it is a source build of a
couple of minutes, not a package install. It is a no-op on lanes that already
have post-quantum, and it warns rather than fails if the build does not succeed
-- the packaged nginx still serves HTTP/2 in that case.

Verified on OpenBSD 7.8 with eopenssl 3.5.4 and nginx 1.30.4: `ldd` shows
`eopenssl35/libssl.so.37.0`, ALPN negotiates `h2`, and the TLS 1.3 group is
`X25519MLKEM768`. The `ldd` line is the one that matters and the script asserts
it: `-L` only satisfies the linker, and without the rpath the binary loads the
base libssl at run time and loses ML-KEM with no error at all.

## Setup

### 1. Prepare certificates

Place files in a directory (default `./certs/`):

```
certs/
+-- cert.pem     # server certificate + chain (fullchain)
+-- key.pem      # private key
```

### 2. Configure .env

```bash
TLS_ENABLED=true
TLS_CERT_DIR=./certs
# Paths inside the container (mounted as :ro)
TLS_CERT=/certs/cert.pem
TLS_KEY=/certs/key.pem
```

### 3. Restart

```bash
docker compose up -d --build frontend
```

nginx logs at startup:
```
[tls-setup] TLS enabled on :8443 (cert: /certs/cert.pem)
```

## First browser visit (home install)

The home installer creates a self-signed **server certificate** so HTTPS works
without a domain name or external CA. The connection is encrypted immediately.
The warning is not an encryption failure: it only means that the certificate is
self-signed and therefore not yet known to the browser's trust store. Switching
to HTTP is not a fix.

The installer prints the certificate's SHA-256 fingerprint before the URL. In
the browser, open the warning's certificate details and compare the complete
fingerprint. Continue only when every byte matches. You can also calculate it
from the installed file:

```sh
openssl x509 -in "$HOME/rhorizon/certs/cert.pem" \
  -noout -fingerprint -sha256
```

The container home path is normally `~/rhorizon/certs/cert.pem`. Native user
installs use `${XDG_CONFIG_HOME:-$HOME/.config}/rhorizon/certs/cert.pem`; macOS
uses `~/Library/Application Support/rhorizon/config/certs/cert.pem`. Use the
exact path printed by the installer when a custom location was selected.

There are two trust levels:

- **Horizon clients only (recommended):** set `RH_CA_FILE` to the certificate
  path. The CLI and `rh-*` agents trust this one certificate without changing
  the machine-wide trust store.
- **Browser or system trust:** first verify the fingerprint, then accept a
  site-specific browser exception or import this exact certificate. Remove the
  old trust entry if Horizon's certificate is regenerated.

### macOS

Import `cert.pem` into the **login** keychain with Keychain Access, open the
certificate, expand **Trust**, and set **Secure Sockets Layer (SSL)** to
**Always Trust**. This changes trust for the current user and exact certificate;
it may ask for the account password. Restart the browser. The hostname used in
the URL must still be present in the certificate SAN (the default includes
`localhost` and `127.0.0.1`).

For the CLI, prefer the narrower setting:

```sh
export RH_CA_FILE="$HOME/Library/Application Support/rhorizon/config/certs/cert.pem"
```

### Linux

For the CLI and agents, export `RH_CA_FILE`; no root access is required. To make
system clients trust the certificate, copy it with a `.crt` extension and
refresh the distribution's trust store:

```sh
# Debian, Ubuntu, Alpine
sudo install -m 0644 "$HOME/rhorizon/certs/cert.pem" \
  /usr/local/share/ca-certificates/rhorizon-local.crt
sudo update-ca-certificates

# Fedora, RHEL, Arch (p11-kit)
sudo trust anchor "$HOME/rhorizon/certs/cert.pem"
sudo update-ca-trust
```

Some Firefox installations use their own certificate store. If the warning
remains, accept the verified site exception in Firefox or enable its operating
system trust-store support. Do not disable certificate verification.

### BSD

`RH_CA_FILE` is the portable, unprivileged choice on FreeBSD, OpenBSD and
NetBSD. Firefox can also keep a site-specific exception after you verify the
fingerprint.

For system OpenSSL clients, FreeBSD can copy the certificate to
`/usr/local/share/certs/` and run `sudo certctl rehash`. NetBSD can place it in
a directory listed by `/etc/openssl/certs.conf` (for example
`/etc/openssl/certs.local`) and run `sudo certctl rehash`. OpenBSD has no single
portable system-wide import command for every TLS consumer; configure the
client with `RH_CA_FILE` or use that application's certificate store.

### WSL

WSL and Windows have separate trust stores:

- Commands running **inside WSL** follow the Linux instructions for that WSL
  distribution, or simply use `RH_CA_FILE`.
- A browser running on **Windows** uses the Windows certificate store. After
  checking the fingerprint, open `certmgr.msc` as the current user and import
  `cert.pem` into **Trusted People**. Do not place this server certificate in
  **Trusted Root Certification Authorities**; it is not a CA certificate.

The file is reachable from Windows through `\\wsl$\<distribution>\...`, or it
can be copied to `/mnt/c/...` from WSL before import.

### Docker and Podman

Docker and Podman do not change browser trust. A browser on the host follows the
host's macOS, Linux, BSD or Windows procedure above. A client running **inside a
container** has its own filesystem and usually its own trust store. Mount the
certificate read-only and point the client at it:

```yaml
services:
  client:
    volumes:
      - ./certs/cert.pem:/run/rhorizon/cert.pem:ro
    environment:
      RH_CA_FILE: /run/rhorizon/cert.pem
```

The same Compose mount works with Docker Compose and Podman Compose. For a
generic image whose application only reads the system store, add the certificate
to the image and run that distribution's trust refresh command at build time;
do not modify a running container, because the change disappears when the
container is recreated.

### Replace it with a public certificate

A public certificate removes the warning without changing every client trust
store. It does not require a paid certificate: Let's Encrypt and other ACME CAs
issue them for free. For the usual private-network setup, you need a domain you
control, DNS resolving it to the Horizon endpoint, and a certificate whose SAN
contains the exact hostname used in the URL. Some public CAs now also issue
short-lived certificates for eligible **public** IP addresses, but not for
`localhost` or RFC1918 private addresses.

DNS-01 validation also works when Horizon stays on a private network: only the
DNS proof must be public. Configure split DNS so clients resolve the public name
to Horizon's private address, obtain `fullchain.pem` and `privkey.pem`, then:

- container home install: replace `~/rhorizon/certs/cert.pem` and `key.pem`,
  preserve the permissions, and restart `frontend`;
- native Linux/BSD: rerun `tools/install-native.sh` with `--tls-cert
  /path/fullchain.pem --tls-key /path/privkey.pem`;
- native macOS: replace the generated pair under the printed config directory
  and restart the LaunchAgent.

Automate ACME renewal and restart or reload the TLS endpoint after renewal. The
hostname must keep matching the certificate; using the old private-IP URL will
still cause a name-mismatch warning.

## Certificate format

### cert.pem - fullchain (required)

The `cert.pem` file must contain the **server certificate + intermediate chain**,
in this order (concatenated PEM):

```
-----BEGIN CERTIFICATE-----
(server certificate - leaf)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(intermediate certificate - issuer)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(root intermediate certificate - if applicable)
-----END CERTIFICATE-----
```

**Do not include the root CA certificate** - clients already have it
in their trust store. Including it is harmless but increases handshake size.

| Source | File to use |
|--------|-------------|
| Let's Encrypt (certbot) | `fullchain.pem` |
| Let's Encrypt (acme.sh) | `fullchain.cer` or `ca.cer` + `cert.cer` concatenated |
| cert-manager (K8s) | `tls.crt` (already contains the fullchain) |
| Commercial CA (DigiCert, Sectigo...) | Concatenate: `server.crt` + `intermediate.crt` |
| Self-signed | `cert.pem` (no chain; client must explicitly trust this server certificate) |

#### Verify the chain

```bash
# Display certificates in the file
openssl crl2pkcs7 -nocrl -certfile certs/cert.pem | \
    openssl pkcs7 -print_certs -noout

# Verify the chain is complete
openssl verify -untrusted certs/cert.pem certs/cert.pem
```

### key.pem - private key

RSA or ECDSA key, PEM format, **unencrypted** (no passphrase):

```
-----BEGIN PRIVATE KEY-----
(private key)
-----END PRIVATE KEY-----
```

or legacy RSA format:

```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

| Source | File to use |
|--------|-------------|
| Let's Encrypt (certbot) | `privkey.pem` |
| Let's Encrypt (acme.sh) | `domain.key` |
| cert-manager (K8s) | `tls.key` |
| openssl | `server.key` (if `-nodes` was used at generation) |

**Permissions**: the key is mounted as `:ro` in the container. On the host:

```bash
chmod 600 certs/key.pem
chown root:root certs/key.pem
```

#### Verify cert/key match

```bash
# Both must output the same hash
openssl x509 -noout -modulus -in certs/cert.pem | openssl md5
openssl rsa -noout -modulus -in certs/key.pem | openssl md5
```

For ECDSA:
```bash
openssl x509 -noout -pubkey -in certs/cert.pem | openssl md5
openssl ec -pubout -in certs/key.pem | openssl md5
```

## Certificate generation

### Self-signed (dev/test)

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

The K8s Secret `rhorizon-tls` contains `tls.crt` and `tls.key`,
mountable as a volume in the pod.

## Deployment contexts

> This table describes a **hand-driven compose deployment**. Both installers
> (`tools/install.sh` and `tools/install-native.sh`) now set `TLS_ENABLED=true`
> and generate a certificate unconditionally -- there is no plaintext install
> path. The vault also logs a `PLAINTEXT TRANSPORT` warning for every
> authenticated call that arrives unencrypted, loopback included.

| Context | TLS_ENABLED | Certificate | Notes |
|---------|-------------|-------------|-------|
| VPN + reverse proxy | `false` | Upstream proxy handles TLS | Not needed, encrypted network |
| Corporate LAN (no VPN) | `true` | Internal CA or self-signed | Distribute CA to clients |
| Kubernetes | `true` | cert-manager | Secret mounted as volume |
| GitLab CI / backend network | `true` | Let's Encrypt or internal CA | HTTPS required for API calls |
| Local dev | `false` | none | HTTP is fine on localhost |

## TLS nginx configuration

The HTTPS server block uses:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
# Post-quantum hybrid key exchange (TLS 1.3), preferred first.
ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

- **TLS 1.2 minimum** - TLS 1.0/1.1 disabled (deprecated)
- **AEAD ciphers only** - AES-GCM, no CBC
- **Forward secrecy** - ECDHE required
- **Post-quantum key exchange** - `X25519MLKEM768`, a hybrid KEM (classical
  X25519 + ML-KEM-768 / FIPS 203) negotiated first on the TLS 1.3 handshake, so
  a recorded session cannot be broken later by a quantum computer
  (harvest-now-decrypt-later). X25519 / P-256 fallback keeps non-PQ clients
  working. Requires OpenSSL >= 3.5 (the frontend image ships libssl 3.5.x).
- **HSTS** - `max-age=63072000; includeSubDomains; preload` (2 years)

### Test the configuration

```bash
# From a host on the network
curl -v https://vault.example.com:8443/health

# Check ciphers
nmap --script ssl-enum-ciphers -p 8443 vault.example.com

# Full test (if exposed)
# https://www.ssllabs.com/ssltest/
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TLS_ENABLED` | `false` | Activate HTTPS server block on :8443 |
| `TLS_CERT` | `/certs/cert.pem` | Certificate path (fullchain) inside the container |
| `TLS_KEY` | `/certs/key.pem` | Private key path inside the container |
| `TLS_CERT_DIR` | `./certs` | Host directory mounted as `/certs:ro` |

## Certificate rotation

nginx reloads certificates on each reload:

```bash
# Copy new certs
cp /path/to/new/fullchain.pem certs/cert.pem
cp /path/to/new/privkey.pem certs/key.pem

# Reload without downtime
docker exec rhorizon_frontend nginx -s reload
```

For Let's Encrypt, add a post-renew cron:

```bash
# /etc/letsencrypt/renewal-hooks/deploy/rhorizon.sh
#!/bin/sh
cp /etc/letsencrypt/live/vault.example.com/fullchain.pem /path/to/rhorizon/certs/cert.pem
cp /etc/letsencrypt/live/vault.example.com/privkey.pem /path/to/rhorizon/certs/key.pem
docker exec rhorizon_frontend nginx -s reload
```
