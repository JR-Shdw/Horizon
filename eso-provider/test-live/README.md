# rhorizon - ESO publication battery

Validation battery before publishing the ESO provider upstream
(`external-secrets/external-secrets`). Each script is idempotent, cleans up
its own resources (vault secrets + tokens, K8s pods + secrets), and prints a
PASS/FAIL per case.

## Prerequisites

- `RH_TOK` exported (master `claude-ns` token, `tokens:rw` + `secrets:rw` on
  `claude`, `forgejo`, `chronolion_local`).
- rhorizon vault reachable at `http://192.168.10.1:8200` (LAN).
- B2/B3: `KUBECONFIG` points at the lab k3s cluster + `kubectl` on the PATH.
- Image `ghcr.io/jr-shdw/rhorizon-agent:latest` pullable (anonymously via
  the standard OCI flow).

## Run

```bash
export RH_TOK='rh_...'
export KUBECONFIG=~/dev/k3s/kubeconfig

# 4 batteries, ~3-4 min total
bash b1_api_conformance.sh   # 20 tests
bash b2_rhfetch_real.sh      # 9 tests
bash b3_rhwatch_rotation.sh  # 5 tests
bash b4_eso_contract.sh      # 11 tests
```

Expected result: **PASS=45 FAIL=0**.

## Coverage per battery

### B1 - API conformance (20 tests)

CRUD + auth + namespace endpoints that ESO will use. Confirms:
- Namespace filter post-fix 2026-05-21 (ambiguous 409 / wrong-ns 404)
- POLA grant (a token's scope cannot escape the declared subset)
- Mint token + revocation by id

### B2 - real rh-fetch init-container (9 tests)

Deploys a Pod with an `rh-fetch` init-container + an `alpine sleep` app,
`emptyDir` volumes (secrets) + a K8s Secret `defaultMode: 0444` (token).
Confirms:
- Init container terminates exit=0
- Files written to `/secrets/sec_a`, `/secrets/sec_b` match the vault values
- File mode 0400 (atomic_write, owner-only)
- Clean app env (no `RH_TOKEN` leak)
- App mount readOnly
- Token volume absent from the app spec
- Bad token -> init exits non-zero (fail-loud)

### B3 - rh-watch live rotation (5 tests)

Deploys a Pod with an `rh-watch` sidecar (POLL=5s) + an `alpine sleep` app.
Confirms:
- Initial poll writes V1
- PUT to vault -> sidecar propagates V2 within 3*POLL seconds
- rh-watch logs trace the activity
- Fast PUTs -> convergence to the last value

### B4 - ESO provider contract (11 tests)

Reproduces the exact call path of `eso-provider/client.go`:
- `ns/name` prefix resolution from `remoteRef.Key`
- GetSecret (200, 404 mappable to `NoSecretErr`)
- GetSecretMap on multi-field JSON
- GetAllSecrets (listSecrets by namespace)
- PushSecret (PUT) + read-back
- DeleteSecret
- Validate() store reconcile (whoami)

## Next steps toward the upstream PR

1. Run the provider's Go unit tests: add Go to the workstation (via Ansible),
   fork `external-secrets/external-secrets`, drop the `eso-provider/` files at
   their target paths, `go test ./pkg/provider/rhorizon/...`.
2. Build a custom ESO image including the provider, push to `gitea.example.com`,
   deploy on the lab k3s cluster, create real `SecretStore` + `ExternalSecret`,
   verify that a native K8s Secret is synthesized correctly.
3. Submit the upstream PR (process documented in `eso-provider/README.md`).

Batteries B1-B4 validate the server contract. The upstream PR will be gated on
the provider-side Go unit tests (step 1) - that is the next risk reduction
before publication.

## Location and scope

These scripts live in `eso-provider/test-live/` of the rhorizon repo. They are
NOT part of the upstream `external-secrets/external-secrets` PR (only the `.go`
files of the `eso-provider/` folder are copied there, see the mapping table in
`../README.md`). They serve to validate the server contract + the sidecars
before publication.

Idempotent re-run: each script cleans up the vault secrets and tokens it
created + the test's K8s pods/secrets. You can re-run without manual cleanup
after an interruption.

## Environment variables

| Var | Default | Role |
|---|---|---|
| `RH_TOK` | _none_ (required) | Master token scoped to claude/forgejo/chronolion_local. Provided out-of-band by the user. |
| `RH_ADDR` | `http://192.168.10.1:8200` | Vault endpoint from the workstation. |
| `RH_ADDR_POD` | same as `RH_ADDR` | Vault endpoint from the k3s pods. Same values in the local lab. |
| `KUBECONFIG` | `~/.kube/config` | Points at the lab cluster. B2/B3 only. |
