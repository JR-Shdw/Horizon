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
