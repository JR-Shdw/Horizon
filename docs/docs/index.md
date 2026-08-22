# rhorizon - self-hosted secrets vault

A self-hosted secrets manager with an HTTP API, PostgreSQL storage,
and no Consul, etcd, or Raft dependency.

## At a glance

- **AGPL-3.0-or-later** - no surprise BSL switch, no commercial licence
  required to run, modify, or fork.
- **Sealed by default** - at every restart the master key is gone ;
  operator unseals once, vault stays unsealed for cron / agents.
- **Memory-protected by Rust** - wrap keys live in `mlock`'d heap with
  `zeroize` on drop. Tokens follow the same path in the agent (`SecureToken`).
- **Five-layer crypto** - Argon2id master key derivation -> HKDF subkeys
  -> XChaCha20-Poly1305 secret cipher -> AES-256-GCM DEK envelope ->
  HMAC-SHA512 token hashes (O(1) lookup).
- **RBAC namespaces** - UUID-keyed containers with `enforce_membership`
  and `delete_protection` flags. Both are one-way ratchets at the DB
  level - a compromised root token cannot relax them.
- **Tamper-evident audit** - Ed25519-signed mutation chain plus signed Merkle
  checkpoints and sealed archives for reads.
- **Multi-worker compartmentalisation** - only the master
  process holds sub-keys ; followers each hold one Shamir share.
- **Agent in Rust musl scratch (~5 MB)** - `rh-fetch`, `rh-inject`,
  `rh-watch` for init / exec / sidecar patterns.

## Pick your install path

<div class="grid cards" markdown>

-   :material-docker:{ .lg .middle } **Docker - single host**

    ---

    Single binary, ~5 minutes :

    ```bash
    curl -fsSL https://raw.githubusercontent.com/JR-Shdw/Horizon/main/tools/install.sh | bash
    ```

    [:octicons-arrow-right-24: Quickstart](quickstart/docker.md)

-   :material-kubernetes:{ .lg .middle } **Kubernetes - Helm chart**

    ---

    11 resources, NetworkPolicy egress lockdown, optional managed PG :

    ```bash
    helm install vault ./helm/rhorizon \
      -n rhorizon --create-namespace
    ```

    [:octicons-arrow-right-24: Helm install](quickstart/kubernetes.md)

-   :material-source-branch:{ .lg .middle } **From source**

    ---

    Build the API + frontend images yourself, run pytest, hack on it.

    [:octicons-arrow-right-24: Build](quickstart/source.md)

-   :material-book-open-variant:{ .lg .middle } **Concepts**

    ---

    Architecture, sealed/unsealed, RBAC namespaces, memory protection.

    [:octicons-arrow-right-24: Read concepts](concepts/index.md)

</div>

## Status

| | |
|---|---|
| Validation | Python and Rust tests, lint, dependency audit, image scan, and OS release lanes |
| Platforms | Linux and BSD; see the [compatibility matrix](https://github.com/JR-Shdw/Horizon/blob/main/docs/COMPATIBILITY.md) for current evidence |
| Latest stable | `v0.9.0-beta` |
| License | AGPL-3.0-or-later |
| Maintainer | [shdw](mailto:horizon@resurgamus.com) |
