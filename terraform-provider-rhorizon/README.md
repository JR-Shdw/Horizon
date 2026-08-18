# terraform-provider-rhorizon

Manage a [Resurgamus Horizon](https://github.com/JR-Shdw/Horizon) vault
as Terraform code.

## Resources

| Type | Purpose |
|------|---------|
| `rhorizon_secret` | Create / update / delete secrets. |
| `rhorizon_namespace` | Manage RBAC-owned namespaces. One-way ratchets enforced client-side. |

## Data sources

| Type | Purpose |
|------|---------|
| `rhorizon_secret` | Read a secret managed outside this run. |
| `rhorizon_namespace` | Look up an existing namespace's metadata. |

## Provider configuration

```hcl
terraform {
  required_providers {
    rhorizon = {
      source  = "shdw/rhorizon"
      version = "~> 0.1"
    }
  }
}

provider "rhorizon" {
  address = "https://vault.example.com"     # or RH_ADDR env
  token   = var.rhorizon_token              # or RH_TOKEN env
}
```

Grant the provider only the scopes required by the managed resources. Secret
resources need `secrets:rw` on their named namespaces. Namespace resources may
require `admin:rw`; use a separate provider configuration for those operations
instead of making an administrative token the default. Do not use a root token
for routine plans.

## Example - create a secret

```hcl
resource "rhorizon_secret" "db_password" {
  name      = "prod/postgres-app"
  value     = random_password.pg.result
  namespace = "prod"
}

resource "random_password" "pg" {
  length  = 32
  special = true
}
```

The `value` attribute is marked sensitive, so Terraform redacts it from normal
CLI output. **Sensitive values are still stored in Terraform state in
plaintext.** Use an encrypted remote backend with strict access controls,
locking, version-retention policy, and audited access. Avoid the secret data
source when a downstream system can fetch the value directly from rhorizon.
The provider sends the plaintext over TLS; rhorizon then encrypts it at rest
with a per-secret DEK (XChaCha20-Poly1305) wrapped under the master key.

## Example - manage a namespace

```hcl
resource "rhorizon_namespace" "prod" {
  name           = "prod"
  owner_group_id = data.rhorizon_namespace.vault_admins.owner_group_id  # bootstrap group
  enforce_membership = true     # strict RBAC mode
  delete_protection  = "soft"   # soft-delete + retention
}
```

**Both flags are one-way ratchets** - once raised, the API rejects
any relax attempt with 423 Locked. The provider also refuses to plan
a relax change client-side so you get a nicer error than the raw API
response.

## Example - read an external secret

```hcl
data "rhorizon_secret" "shared_jwt" {
  name = "platform/jwt-signing-key"
}

resource "kubernetes_secret" "app_secrets" {
  metadata { name = "app-secrets" }
  data = {
    JWT_SECRET = data.rhorizon_secret.shared_jwt.value
  }
}
```

## Build

```bash
cd terraform-provider-rhorizon
go build -o terraform-provider-rhorizon
```

## Local install

Drop the binary in your Terraform plugin cache :

```bash
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/shdw/rhorizon/0.1.0/linux_amd64
cp terraform-provider-rhorizon ~/.terraform.d/plugins/registry.terraform.io/shdw/rhorizon/0.1.0/linux_amd64/
```

Then `terraform init` will pick it up.

## License

AGPL-3.0-or-later.
