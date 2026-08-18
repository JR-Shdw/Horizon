# PKI engine

Issue short-lived X.509 certificates from a private CA that lives inside the
vault. The CA private key is wrapped at rest under a dedicated sub-key and only
ever signs on the master process; issued leaf private keys are returned once and
never stored.

**One CA per namespace.** Each namespace has its own independent issuing CA
(own algorithm, own trust root), so `prod` and `staging` are isolated: rotating
or revoking one never touches the other. `init`/`ca`/`issue`/`rotate` take a
`namespace` (default `default`); `GET /pki/cas` lists the namespaces that have a
CA. The examples below use the default namespace; add `namespace` to target
another.

The CA's signature algorithm is chosen once per namespace, at init:

| Algorithm | Type | When to pick it |
|---|---|---|
| `ed25519-mldsa65` | composite hybrid (classical + PQ) | **Default.** Long-lived identities that must satisfy ANSSI/BSI hybridation: both an Ed25519 **and** an ML-DSA-65 signature, both required to verify. Survives either a classical or a lattice break. In-house verifiers only (see below). |
| `ed25519` | classical | Pick explicitly when the leaf must be verified by ordinary TLS stacks. Universally supported today. |
| `ml-dsa-65` | post-quantum (FIPS 204) | Service identities you want quantum-resistant. Needs an ML-DSA-aware verifier (OpenSSL 3.5+, anything that ships FIPS 204). PQ but *not* hybrid, so it does not satisfy ANSSI/BSI on its own. |

The default is deliberately the hybrid: it is the only one of the three that
meets ANSSI/BSI hybridation. The trade is that composite certs verify
**in-house only** (private OID) - if the consumer is a stock TLS stack, init
that namespace with `ed25519` instead.

ML-DSA certificates are produced by the in-vault Rust signer (`fips204`) and are
interoperable with OpenSSL 3.5+/`cryptography` 49+: the CA cert, the leaf certs,
and the leaf PKCS8 private keys all load and verify with standard tooling.

### Composite hybrid signatures (`ed25519-mldsa65`)

ANSSI and BSI both **require hybridation** for post-quantum signatures: a
classical algorithm combined with a PQ one, because PQC "is not mature enough to
solely ensure the security" (a pure `ml-dsa-65` CA is PQ but *not* hybrid, so it
does not satisfy them; a pure `ed25519` CA is not PQ). The composite algorithm
signs every cert with **both** an Ed25519 and an ML-DSA-65 key over the identical
TBS, and a verifier **accepts only if both component signatures verify** (ANSSI
sec 3.2 concatenation combiner, EUF-CMA-secure; a single valid component is a
downgrade hole and is rejected).

- **Encoding.** The subject public key is a `CompositePublicKey` (`SEQUENCE SIZE
  (2) OF BIT STRING` = Ed25519 key, ML-DSA key) and the signature a
  `CompositeSignatureValue` (`SEQUENCE OF BIT STRING`), shaped after
  draft-ietf-lamps-pq-composite-sigs but issued under a **private OID arc**
  (`1.3.6.1.4.1.62841.2.1`, placeholder).
- **Interop caveat.** Because the OID is private and composite-cert standards are
  still moving, these certs are for **in-house verifiers only** (the vault CLI /
  `pki_ca.verify_composite_cert`) — they do **not** interoperate with external
  X.509/TLS tooling. The OID is swappable to the draft's assigned
  `id-MLDSA65-Ed25519` once it is an RFC.
- **Custody.** The CA holds both private keys (Ed25519 PKCS8 + the 32-byte ML-DSA
  seed), length-framed and wrapped as one blob under `pki_wrap_key`; rotation and
  master-password re-wrap handle it unchanged. The issued leaf private key is
  returned once as two standard PKCS8 PEM blocks.

### KEM certificates (`ml-kem-768`)

The signature axis above protects *authenticity*. A separate axis protects
*confidentiality*: a **KEM certificate** carries a Key-Encapsulation-Mechanism
public key as its subject key, used to establish a shared secret. The two axes
are independent — a KEM cert's subject key is an ML-KEM key, while its signature
is produced by the namespace CA under *its* algorithm (`ed25519`, `ml-dsa-65`, or
the composite hybrid). So **subject-key algorithm != signature algorithm**, unlike
the signature certs above where they coincide.

- **What it is.** `POST /pki/kem/issue` (CLI `rhorizon pki kem-issue`) mints a cert
  whose subject key is an **ML-KEM-768** (FIPS 203, NIST category 3) encapsulation
  key, with `KeyUsage=keyEncipherment` and **no** EKU (a KEM key does not do
  serverAuth/clientAuth). ML-KEM-768 matches the `X25519MLKEM768` set already used
  in the agent's TLS handshake.
- **Why a KEM and not just a PQ signature.** `X25519` is a KEM and `ML-DSA` a
  signature — different functions, they cannot be hybridised together, and a PQ
  *signature* does not make a *key exchange* quantum-safe. Confidentiality against
  a future quantum adversary ("harvest now, decrypt later") needs a PQ **KEM**;
  that is what this cert provides. Pure ML-KEM (`kem_mode=ml-kem`) is PQ but *not
  hybrid*; for the full ANSSI/BSI hybridation add the classical leg with
  `kem_mode=x25519-ml-kem` (see [Hybrid KEM certificates](#hybrid-kem-certificates-x25519-ml-kem-768)
  below).
- **Crypto.** ML-KEM keygen/encaps/decaps run in the Rust extension via `fips203`
  (IntegrityChain, the direct sibling of the shipped `fips204`), gated by NIST ACVP
  ML-KEM-768 keyGen/encaps/decaps known-answer vectors. The keygen decapsulation
  key is mlock'd + zeroized like the ML-DSA seed.
- **Custody.** No new server-side surface: the CA still holds only its *signing*
  key. The leaf's ML-KEM **decapsulation (secret) key is returned once** on issue
  (PKCS8 `expandedKey` form) for the requester to hold, and is never stored. The
  holder decapsulates a peer's ciphertext to recover the shared secret.
- **Interop caveat.** Same as the composite certs: the ML-KEM OIDs are the NIST
  CSOR ones, but KEM-in-X.509 tooling is still stabilising, so treat these as
  in-house until the LAMPS drafts land. Verify the CA signature over a KEM cert
  with the same in-house verifier as any other leaf of that CA algorithm.

### Hybrid KEM certificates (`x25519-ml-kem-768`)

`kem_mode=x25519-ml-kem` upgrades the KEM cert to a **hybrid** subject key: a
classical `X25519` leg **and** the `ML-KEM-768` leg, combined so the shared
secret stays secure as long as *either* leg is unbroken. This is the ANSSI/BSI
requirement — both agencies mandate hybridation because PQC alone is "not mature
enough to solely ensure security", and pure ML-KEM alone would fall to a future
classical break of the standard (or an implementation flaw in the young PQ code).

- **Subject key.** A `SEQUENCE SIZE (2) OF BIT STRING` — `(x25519_pub 32 B,
  mlkem768_pub 1184 B)`, same DER shape as the composite signature public key.
  Leg order is fixed (X25519 first) and *is* the combiner's domain separator.
  Its own OID lives under the private arc `1.3.6.1.4.1.62841.3.1`
  (`62841.3.x` = hybrid-KEM branch), swappable to
  `draft-ietf-lamps-pq-composite-kem`'s assigned OID at RFC.
- **Combiner.** `ss = HKDF-SHA512(ss_x25519 || ss_mlkem)` with
  `salt = "rhorizon-hybrid-kem-v1"` and
  `info = SHA512(label || ct_x25519 || ct_mlkem || pk_x25519 || pk_mlkem)`
  (ETSI TS 103 744 / Giacon-Heuer-Poettering shape). Binding both ciphertexts and
  both recipient public keys into `info` gives re-encapsulation / transcript
  resistance. The combiner runs in the Rust extension (`hybrid_kdf`), gated by a
  known-answer test cross-checked against OpenSSL's HKDF; no home-made primitive.
- **Crypto sourcing.** The X25519 leg (keygen, DH, PKCS8) uses `cryptography`
  (OpenSSL) — the same audited library as the `ed25519` path, **no new Rust
  crate**. The ML-KEM leg reuses the Cut-1 `fips203` bindings.
- **Custody.** Still no new server-side surface. The leaf carries **two** return-
  once private key blocks — an X25519 PKCS8 block followed by the ML-KEM
  `expandedKey` block — shown only on issue, never stored. The holder feeds a
  peer's `(ct_x25519, ct_mlkem)` back through the combiner to recover the secret.
- **When to use which.** `ml-kem` is enough where you only need PQ confidentiality
  and control both ends; prefer `x25519-ml-kem` whenever an external policy
  (ANSSI/BSI) or defence-in-depth against immature PQ code matters. See
  [KEM-HYBRID.md](KEM-HYBRID.md) for the wire format and an interop walkthrough.

## Quick start (CLI)

```bash
# 1. Initialise the CA once. Default is the ANSSI/BSI composite hybrid.
rhorizon pki init --cn rhorizon-pki                    # ed25519-mldsa65 (default)
# or:  rhorizon pki init --algorithm ml-dsa-65         # pure post-quantum
# or:  rhorizon pki init --algorithm ed25519           # classical

# 2. Distribute the CA cert to whatever needs to trust the leaves
rhorizon pki ca --out rhorizon-ca.pem

# 3. Issue a leaf for a service (server-side keygen)
rhorizon pki issue svc.internal \
  --dns svc.internal --ip 10.0.0.1 \
  --ttl-days 30 -n default \
  --cert-out svc.pem --key-out svc.key   # key file written mode 0600

# 3b. Issue a KEM cert for confidentiality (ML-KEM subject key, CA-signed)
rhorizon pki kem-issue kem.internal \
  --dns kem.internal --ttl-days 30 -n default \
  --cert-out kem.pem --key-out kem.decaps.key   # decaps key written mode 0600

# 3c. Hybrid X25519+ML-KEM KEM cert (ANSSI/BSI hybridation)
rhorizon pki kem-issue hybrid.internal --mode x25519-ml-kem \
  --dns hybrid.internal --ttl-days 30 -n default \
  --cert-out hybrid.pem --key-out hybrid.decaps.key   # two PKCS8 blocks

# 4. List + revoke
rhorizon pki certs
rhorizon pki revoke <serial> --reason superseded

# 5. Rotate the CA (old CA stays valid in a grace window)
rhorizon pki rotate
```

## API

Base path `/api/v1/vault/pki`. The vault must be unsealed.

| Method | Endpoint | Scope | Role |
|---|---|---|---|
| `POST` | `/init` | `admin:w` | Mint the CA once per namespace (409 if already initialised) |
| `GET`  | `/cas` | `secrets:r` | List the namespaces that have a CA |
| `GET`  | `/ca` | `secrets:r` | CA cert PEM (+ previous cert during a rotation grace window) |
| `POST` | `/issue` | `secrets:w` | Issue a leaf; returns cert + private key ONCE (namespace-checked) |
| `POST` | `/kem/issue` | `secrets:w` | Issue a KEM cert (ML-KEM subject key, CA-signed); returns cert + decaps key ONCE |
| `GET`  | `/certs` | `secrets:r` | List issued certs (namespace-filtered, no private keys) |
| `POST` | `/revoke` | `admin:w` | Mark a cert revoked by serial |
| `POST` | `/rotate` | `admin:w` | Rotate the CA, keeping the old cert in a grace window |

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
#      "algorithm", "not_after" }   (private_key shown only here)

# kem/issue (subject key = ML-KEM-768, signed by the CA)
curl -X POST https://vault/api/v1/vault/pki/kem/issue \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"common_name":"kem.internal","san_dns":["kem.internal"],
       "kem_algorithm":"ml-kem-768","kem_mode":"ml-kem",
       "ttl_days":30,"namespace":"default"}'
# kem_mode "x25519-ml-kem" -> hybrid subject_algorithm "x25519-ml-kem-768"
# -> { "serial", "certificate", "private_key", "ca_chain", "fingerprint",
#      "algorithm", "subject_algorithm", "kem_mode", "not_after" }
#    private_key is the decapsulation key(s), shown only here
```

## UI

Eclipse (Secrets) has a **PKI** tab. Before init it shows the algorithm picker;
after init it shows the CA status, a leaf-issue form, a **KEM-issue form** (with a
mode selector: `x25519-ml-kem` hybrid or `ml-kem` pure), and the issued-cert table
with revoke. The table surfaces the KEM subject algorithm for KEM certs. The
issued cert + key(s) are revealed once with copy buttons.

## Verifying a leaf

Which recipe applies depends on the CA's algorithm. **The default
(`ed25519-mldsa65`) is not verifiable by `openssl`** - it uses a private OID,
so stock tooling cannot parse the composite signature. Use the in-house
verifier for it.

```bash
# ed25519-mldsa65 (DEFAULT) -- in-house only, no OpenSSL
python - <<'PY'
from app import pki_ca
ca = open('rhorizon-ca.pem','rb').read()
leaf = open('svc.pem','rb').read()
ed_pub, mldsa_pub = pki_ca.composite_component_pubs(ca)
# Accepts iff BOTH component signatures verify (a single valid leg is a
# downgrade hole and is rejected).
print('ok' if pki_ca.verify_composite_cert(leaf, ed_pub, mldsa_pub) else 'FAIL')
PY

# ed25519 (any OpenSSL)
openssl verify -CAfile rhorizon-ca.pem svc.pem

# ml-dsa-65 (OpenSSL 3.5+ or cryptography 49+)
openssl verify -CAfile rhorizon-ca.pem svc.pem
python -c "from cryptography import x509; \
  ca=x509.load_pem_x509_certificate(open('rhorizon-ca.pem','rb').read()); \
  lf=x509.load_pem_x509_certificate(open('svc.pem','rb').read()); \
  ca.public_key().verify(lf.signature, lf.tbs_certificate_bytes); print('ok')"
```

## Design notes

- **Separate from the cluster CA.** Its own wrap key (`pki_wrap_key`), tables
  (`vault_pki_config`, `vault_pki_certs`), and AAD. No coupling to cluster mTLS.
- **CA key custody.** The CA private material is wrapped under `pki_wrap_key`
  (HKDF-derived, domain-separated). For ML-DSA the key is a 32-byte FIPS 204
  seed held mlock'd in Rust; it is rebuilt into the expanded key only on the
  master at sign time and zeroized after. Master-password rotation re-wraps it.
- **Failover-safe.** `pki_wrap_key` rides the Shamir/rekey sub-key bundle, so a
  master failover keeps the CA usable without an operator re-unseal.
- **Rotation grace window.** `pki rotate` mints a fresh CA and keeps the old
  cert as `pki_ca_cert_prev` so in-flight leaves still chain-verify; `GET /ca`
  returns both during the window.
- **Audit.** Every init / issue / revoke / rotate is recorded in the audit chain.

## Limits (v1)

- Signature algorithms: `ed25519`, `ml-dsa-65`, and `ed25519-mldsa65` (composite
  hybrid). `ml-dsa-87` (NIST level 5) needs a separate Rust signer and is a
  follow-up. Composite certs are in-house-verify only (private OID).
- KEM subject keys: `ml-kem-768` only (the 512/1024 OIDs are known to the ASN.1
  layer but not wired in the Rust extension). `kem_mode` accepts `ml-kem` (pure)
  and `x25519-ml-kem` (hybrid X25519 + ML-KEM, ANSSI/BSI confidentiality); a third
  Classic McEliece leg remains a deferred, optional Cut.
- Revocation is record-only / advisory (`advisory:true` in the `/revoke`
  response): it stops re-issue and flags the row, but there is no CRL/OCSP, so
  relying parties cannot see it. The real control is the short lifetime, which is
  why issuance is capped at 398 days. A CRL/OCSP responder is a follow-up.
- Server-side keygen returns the leaf private key once (it transits the response
  like any served secret). A CSR sign-only mode is a follow-up.
- ML-DSA is **post-quantum but the `fips204` crate is not yet independently
  audited**. What is automated in CI is conformance: NIST ACVP ML-DSA-65
  sigver and Project Wycheproof known-answer vectors
  (`ml_dsa_65_nist_acvp_sigver_kat`, `ml_dsa_65_wycheproof_external_verify`).
  The OpenSSL 3.5+ / `cryptography` 49+ interop above is an
  operator-runnable check, **not** a build-time gate - the only OpenSSL
  cross-check that runs in CI is `hybrid_kdf_openssl_kat`, which covers the
  hybrid-KEM combiner, not ML-DSA signatures. See
  [Post-quantum](POST-QUANTUM.md) and [Side-channels](SIDE-CHANNELS.md).
