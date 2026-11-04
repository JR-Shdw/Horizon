# Native TLS (HTTPS without a reverse proxy)

rhorizon's bundled nginx can terminate TLS directly, so you get HTTPS
without standing up Traefik / Caddy / a load balancer in front. Useful
when there's no VPN or upstream TLS terminator on the path.

```
Client (browser / curl / pod)
  +-- :8443 HTTPS --> nginx (TLS termination) --> API :8200 HTTP (internal)
  +-- :8200 HTTP  --> nginx --> API :8200 HTTP (healthcheck, proxy backend)
```

Port `:8200` (HTTP) is always up for the Docker healthcheck. Port
`:8443` (HTTPS) activates only when `TLS_ENABLED=true`.

## Setup

Place the certificate and key in a directory (default `./certs/`):

```
certs/
  cert.pem     # server certificate + chain (fullchain)
  key.pem      # private key
```

Configure `.env`:

```bash
TLS_ENABLED=true
TLS_CERT_DIR=./certs
TLS_CERT=/certs/cert.pem     # path inside the container (mounted :ro)
TLS_KEY=/certs/key.pem
```

Restart the frontend:

```bash
docker compose up -d --build frontend
```

## Private certificate

`rhorizon-tls` creates a certificate for a vault on a private network and
trusts it on your machines, including Brave and Chrome. It is one file and
needs `python3` and `openssl`.

```bash
install -D -m 0755 tools/rhorizon-tls ~/.local/bin/rhorizon-tls
```

### On the vault host

List every address clients use to reach the vault, for example its LAN and
WireGuard addresses:

```bash
rhorizon-tls generate --ip 192.0.2.10 --ip 198.51.100.30 --dns vault.example --out certs
docker compose up -d --build frontend
```

`127.0.0.1` and `localhost` are always included. Give exact addresses, because
a certificate cannot list a subnet.

| File | Purpose | Copy it? |
|---|---|---|
| `certs/cert.pem` | Server certificate and chain | Stays on the vault host |
| `certs/key.pem` | Server private key | Stays on the vault host |
| `certs/ca.pem` | Public certificate clients trust | Yes, to each client |

Existing files are kept as `*.bak`, and they keep their owner and mode. The
command prints the `ca.pem` fingerprint.

The one-time CA is limited to these addresses, and its key is deleted after
signing. To add an address later, run `generate` again and trust the new
`ca.pem`.

### On each client

```bash
scp vault-host:deployment/certs/ca.pem .
rhorizon-tls trust ca.pem --name vault
rhorizon-tls check https://192.0.2.10:8443
```

`trust` shows the certificate and its fingerprint, then updates the system
store with `sudo` and your user's Brave and Chrome store. Run it as your own
user, once per user. Quit the browser and reopen it afterwards.

| Command | Effect |
|---|---|
| `rhorizon-tls trust ca.pem --name vault --system` | System store only |
| `rhorizon-tls trust ca.pem --name vault --browser` | Brave and Chrome only, no `sudo` |
| `rhorizon-tls trust ca.pem --name vault --fingerprint AA:BB:...` | Unattended, checks the fingerprint |
| `rhorizon-tls untrust --name vault` | Remove from both stores |
| `rhorizon-tls check https://192.0.2.10:8443 --ca-file ca.pem` | Test with a file, without installing it |

The browser step needs `certutil`, from the `nss` package on Arch and
`libnss3-tools` on Debian. Firefox keeps its own store, and Flatpak or Snap
browsers use a sandboxed one. For those, import `ca.pem` in the browser's
certificate settings.

### Browser errors

| Error | Fix |
|---|---|
| `ERR_CERT_AUTHORITY_INVALID` | Run `trust`, then fully restart the browser |
| `ERR_CERT_COMMON_NAME_INVALID` | Use a listed address, or run `generate` with this one |

## Enabled controls

- **TLS 1.2 + 1.3** only; legacy protocols disabled.
- **Post-quantum KEM** when the trixie image is used - the TLS
  handshake offers the hybrid `X25519MLKEM768` group, so the wire is
  resistant to harvest-now-decrypt-later. See
  [Security](../security.md) and the repo's `POST-QUANTUM.md`.
- The same security headers as the proxied setup (CSP, HSTS-ready,
  `X-Frame-Options: DENY`, `nosniff`).

## Certificates

Any PEM cert/key works - Let's Encrypt, an internal CA, or self-signed
for a lab. For an internal CA, ship the full chain in `cert.pem` so
clients can build the trust path. Rotation is a file swap plus
`docker compose up -d --build frontend`; no secret in the vault is
involved.

> Still keep rhorizon off the public internet. TLS protects the wire;
> it is not an authorization layer. Access stays VPN / private-network
> only - the API auth model (bearer tokens, IP allow-lists) is what
> gates callers.
