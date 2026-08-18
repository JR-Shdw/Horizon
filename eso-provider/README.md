# rhorizon - External Secrets Operator provider

Source files for an upstream ESO provider for Resurgamus Horizon.
Written as if it lived under `pkg/provider/rhorizon/` in the
[external-secrets/external-secrets](https://github.com/external-secrets/external-secrets)
monorepo - that's the PR target.

## Why a provider

ESO is the de-facto k8s pattern for "sync vault -> native Secret".
Operators define an `ExternalSecret` CRD that points at a `SecretStore`
backed by a provider. With a rhorizon provider merged upstream, any
ESO-using cluster can adopt rhorizon by adding 10 lines of YAML -
no operator-image to maintain, no custom CRDs.

## Files (PR target paths)

| Source path here | Goes to in `external-secrets/external-secrets` |
|------------------|------------------------------------------------|
| `eso-provider/types.go` | `apis/externalsecrets/v1beta1/secretstore_rhorizon_types.go` |
| `eso-provider/rhorizon.go` | `pkg/provider/rhorizon/rhorizon.go` |
| `eso-provider/client.go` | `pkg/provider/rhorizon/client.go` |
| `eso-provider/api.go` | `pkg/provider/rhorizon/api.go` |
| `eso-provider/rhorizon_test.go` | `pkg/provider/rhorizon/rhorizon_test.go` |
| `eso-provider/init.go` | imported by `pkg/provider/register/register.go` |

The provider is registered via the standard `init()` block - once a
maintainer drops these files in `pkg/provider/rhorizon/` and adds the
import to `pkg/provider/register/register.go`, the compile chain
picks it up automatically.

## Example SecretStore + ExternalSecret

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: rhorizon-prod
  namespace: my-app
spec:
  provider:
    rhorizon:
      address: https://vault.example.com
      auth:
        tokenSecretRef:
          name: rhorizon-bootstrap
          key:  token
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-creds
  namespace: my-app
spec:
  refreshInterval: 30m
  secretStoreRef:
    name: rhorizon-prod
    kind: SecretStore
  target:
    name: db-creds-secret
  data:
    - secretKey: password
      remoteRef:
        key: prod/postgres-app
```

## PR workflow

1. Fork [external-secrets/external-secrets](https://github.com/external-secrets/external-secrets).
2. Drop the files in their target paths (see table above).
3. Add the import to `pkg/provider/register/register.go`:
   ```go
   _ "github.com/external-secrets/external-secrets/pkg/provider/rhorizon"
   ```
4. Add CRD field validation: run `make manifests` to regenerate the
   Helm CRD bundles + their JSON schema.
5. Add an entry to `docs/snippets/provider-rhorizon.yaml` for the
   provider catalog page.
6. `go test ./pkg/provider/rhorizon/...` to verify the unit tests.
7. PR, follow their template, expect 2-6 weeks of review (CNCF
   maintainers are responsive but careful).

## Live validation battery

Before submitting the upstream PR, `test-live/` holds a battery of 45 tests
that validate the server contract + the `rh-fetch`/`rh-watch` sidecars against
a real rhorizon vault and a lab k3s cluster. 4 idempotent shell scripts,
auto-cleanup:

| Script | Tests | Coverage |
|---|---|---|
| `b1_api_conformance.sh` | 20 | CRUD secrets, auth, namespace filter, POLA grant |
| `b2_rhfetch_real.sh` | 9 | Init-container writes files, app reads RO, token non-leak |
| `b3_rhwatch_rotation.sh` | 5 | Polling + live rotation, convergence on fast PUTs |
| `b4_eso_contract.sh` | 11 | Reproduces exactly the call path of `client.go` |

Launch and prereqs: see `test-live/README.md`.

## Capabilities

| Capability | Supported |
|-----------|-----------|
| GetSecret (read one) | yes |
| GetSecretMap (read multi) | yes - JSON-encoded values are unwrapped |
| GetAllSecrets (find by label / name pattern) | yes - uses `vault_secrets.namespace` filter |
| PushSecret | yes |
| DeleteSecret | yes - respects the namespace's `delete_protection` mode |
| SecretExists | yes |
| Lifecycle / capabilities | `ReadWrite` |

## Known gaps for follow-up

- 2FA-gated `delete_protection: protected` namespaces: the
  controller has no way to obtain a fresh /challenge + 2FA proof.
  Recommendation: leave protected namespaces out of ESO scope for
  now, manage them via the rhorizon UI.
- Lease tracking for dynamic engines (PG/MySQL/LDAP): not in v1.
  Could be a follow-up provider extension.

## License

AGPL-3.0-or-later (same as the rhorizon repo). Once merged in
external-secrets/external-secrets, the upstream's Apache-2.0 license
applies to the merged copy; the AGPL applies to any standalone
distribution.
