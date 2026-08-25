# `cargo-fuzz` harnesses for rhorizon_crypto

This sub-crate hosts the libFuzzer-based fuzz targets that
complement the property tests in `api/rust/src/`. Where property
tests randomise inputs across ~256 cases and stop after the test
returns, fuzz targets keep mutating forever, learn from coverage
feedback, and persist a corpus of interesting inputs across runs.

## Quick start

```bash
# one-time setup on the host (nightly toolchain required)
rustup toolchain install nightly --profile minimal
cargo install --locked cargo-fuzz

# list all defined fuzz targets
cd api/rust
cargo +nightly fuzz list

# short smoke run (1 minute per target - adequate for CI / pre-push)
cargo +nightly fuzz run shamir_combine    -- -max_total_time=60
cargo +nightly fuzz run shamir_split      -- -max_total_time=60
cargo +nightly fuzz run aes_gcm_roundtrip -- -max_total_time=60
cargo +nightly fuzz run aes_gcm_decrypt   -- -max_total_time=60

# real fuzzing run - leave it going overnight or on a dedicated
# machine, kill with Ctrl-C when satisfied
cargo +nightly fuzz run shamir_combine
```

Crashes (if any) are saved under `fuzz/artifacts/<target>/` as
binary files. To reproduce one :

```bash
cargo +nightly fuzz run shamir_combine \
    fuzz/artifacts/shamir_combine/crash-<hex>
```

## Targets and the invariants they protect

| Target | Function under test | Property checked |
|---|---|---|
| `shamir_combine` | `key_share::shamir_combine(&[&[u8]])` | Never panics on malformed shares (mismatched lengths, duplicate indices, oversized, undersized, zero shares). Always returns `Result`, never garbage. |
| `shamir_split` | `key_share::shamir_split(&[u8], u8, u8)` | Returns shares with the documented length + distinct x-coordinates + count equal to `total` whenever `Ok`. Bad parameters yield `Err`, never a corrupted `Ok`. |
| `aes_gcm_roundtrip` | `aes_gcm_encrypt_aad` + `aes_gcm_decrypt_aad` | Encrypt-then-decrypt is identity. AAD binding holds (flipping AAD makes decrypt fail). Vault data corruption bug if violated. |
| `aes_gcm_decrypt` | `aes_gcm_decrypt_aad` on adversarial wrapped bytes | Never panics. Returns `Err` on truncated / tag-corrupted input. Tiny chance of false `Ok` on a random tag collision (2⁻¹²⁸), acceptable. |

## Why this and not just more property tests

Property tests in `cargo test` stop after a fixed `proptest!`
case budget (256 by default). Fuzzing :

- Keeps mutating forever and grows a coverage-guided corpus,
  i.e. it remembers which inputs reached new code paths and
  preferentially mutates those. After a few hours, fuzz inputs
  reach corners that random property generation never finds.
- Catches panics on real inputs, not just falsifications of a
  named property. Useful against arithmetic overflow,
  indexing OOB, infinite loops, and other "implementation bugs"
  that aren't tied to a clean mathematical invariant.
- Persists a corpus under `fuzz/corpus/<target>/` (git-ignored)
  that future runs start from - bug-finding speed grows over time.

## Why nightly Rust

`libfuzzer-sys` binds LLVM's libFuzzer via instrumentation flags
that only stable in nightly. There is no plan in the Rust roadmap
to stabilise them on the regular channel. Fuzzing therefore lives
outside the stable validate pipeline ; in CI you'd run it as a
scheduled cron job, not on every push.

## Integration with the regular pipeline

The `validate.yml` Woodpecker pipeline does not run fuzz targets on every push.
Two dedicated pipelines provide complementary architecture coverage:

- `.woodpecker/fuzz.yml` runs each target for 30 minutes nightly on x86_64,
  keeps a persistent corpus, and alerts on crash artifacts.
- `.github/workflows/crypto-arm64.yml` runs natively on aarch64: 30 seconds per
  target on relevant pushes and pull requests, five minutes per target weekly,
  or a caller-selected budget through manual dispatch. Its corpus is restored
  through the GitHub Actions cache.

On a 64-bit Raspberry Pi 4, `tools/check-arm64-native.sh` runs the release test
suite, the aarch64 assembly gate, and this fuzzing smoke in one command.
