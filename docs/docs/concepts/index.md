# Concepts

Six pages that cover the design choices that make rhorizon what it is :

- [**Architecture**](architecture.md) - how API, frontend, PostgreSQL,
  agents, and the multi-worker cluster fit together.
- [**Seal / Unseal lifecycle**](seal-unseal.md) - the sealed-by-default
  model, master password, root token bootstrap, automation patterns.
- [**Cryptography (5 layers)**](crypto.md) - Argon2id -> HKDF ->
  XChaCha20-Poly1305 -> AES-256-GCM -> HMAC-SHA512. Why each layer.
- [**RBAC & namespaces**](rbac.md) - UUID-keyed namespaces with
  `enforce_membership` (live group check) and `delete_protection`
  (free / soft / protected) modes. One-way ratchets.
- [**Memory protection**](memory-protection.md) - `mlock` + `zeroize`
  via Rust + PyO3. Master key never reaches Python.
- [**Audit evidence**](audit.md) - Ed25519-signed mutation chain with
  HMAC-SHA512 legacy/fallback verification, plus signed Merkle checkpoints and
  sealed archives for high-volume reads.
