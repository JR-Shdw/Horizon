# OS validation catalog

This catalog is the support checklist for native OS validation. It is not an
install guide; it is the minimum evidence profile an OS lane must satisfy before
`docs/COMPATIBILITY.md` can honestly call that OS supported or tested.

Each target lives under:

```text
docs/os-validation/<os>/<version>/
```

Each target has three TSV files:

- `packages.tsv` - package/runtime components and version floors.
- `hardware.tsv` - architecture, memory, disk, and hardware assumptions.
- `parameters.tsv` - kernel/service/runtime parameters that must be checked.

Schema for every TSV file:

```text
key	relation	value	check	notes
```

Rules:

- One line per requirement.
- Keep values short and grep-friendly.
- Use short relation values such as `required`, `optional`, `tested`,
  `supported`, `target`, `min`, `exact`, `formula`, `path`, `default`,
  `excluded`, `unsigned`, `user-mode`, or `note`.
- If a row is hard to automate, keep the `check` column as the manual command
  the tester should run.
- When a lane is revalidated, update the matching target files first, then
  update `docs/COMPATIBILITY.md` or `docs/SHIP-VALIDATION.md`.

Common project floors used by all native lanes:

- Python: `>= 3.12`.
- Rust: `>= 1.79` preferred for reproducible builds; `>= 1.78` is the hard
  Cargo.lock v4 floor. A distro Rust package is acceptable only when the
  target OS/arch passes the locked vault and agent Rust gates.
- PostgreSQL: major `18`.
- libsodium: `>= 1.0.18`.
- Post-quantum TLS: OpenSSL `>= 3.5` wherever `X25519MLKEM768` is required.
- Native service memory/memlock budget: `workers * 160 + 256 + 192 MB`.

Rust support proof:

- Vault crypto extension: `bash tools/check-rust.sh --skip-miri`.
- Agent binaries: `cd agent/rust && cargo build --release --locked --bins`.
- Full release validation may add nightly Miri/fuzzing, but native OS support
  should not be claimed unless the stable locked build/test gates pass on that
  OS and CPU architecture.
