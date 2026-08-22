// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Common helpers shared by rh-fetch / rh-inject / rh-watch.
//!
//! Two themes :
//!   - **Token hygiene** : the bearer token never lives in a Python `bytes`
//!     or a plain `String`, `SecureToken` mlocks its buffer and zeroises
//!     on drop. Source can be `RHORIZON_TOKEN` (legacy / dev) or
//!     `RHORIZON_TOKEN_FILE` (production : podman / docker / k8s
//!     secret mounted at mode 0400).
//!   - **Atomic file writes** : .tmp + rename + mode 0400 so the consumer
//!     never reads a partially-written file. Shared between rh-fetch
//!     (init) and rh-watch (sidecar).

pub mod http;

use std::env;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::ptr::NonNull;

use zeroize::Zeroize;

// `serde_json` is pulled in by the binaries already ; we re-use it here for the
// EphemeralMinter HTTP path. The HTTP client itself is `http.rs` -- see there
// for why reqwest was dropped.

/// Build the blocking HTTP client every rh-* binary uses to reach the vault.
///
/// TLS provider is **aws-lc-rs**, whose default rustls provider offers the
/// post-quantum hybrid group `X25519MLKEM768` (FIPS 203 ML-KEM-768 + X25519).
/// The agent->vault hop carries plaintext secret values, so a classical-only
/// handshake is a harvest-now-decrypt-later target ; the hybrid KEM closes it
/// (falls back to X25519 for non-PQ servers). Server certs are verified against
/// the Mozilla webpki roots -- same trust anchor as the previous reqwest
/// default, just a different KEM. 10 s timeout, shared by all binaries.
pub fn build_client() -> Result<http::HttpClient, Box<dyn std::error::Error>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // The TLS config above is unchanged; only the HTTP layer on top of it moved
    // off reqwest, which was dragging hyper, h2, tokio, url and idna's whole
    // ICU stack into a binary that talks to one fixed endpoint.
    Ok(http::HttpClient::new(
        tls,
        std::time::Duration::from_secs(10),
    ))
}

/// SecureToken wraps the bearer token in a mlock'd heap buffer that
/// zeroises on drop. Use `as_bearer()` to obtain a borrowed `&str` for
/// the HTTP `Authorization: Bearer` header, the slice lives only for
/// the call and never escapes the wrapper.
///
/// Why : a plain `String` token may sit in the heap until GC, gets
/// copied on `String::clone`, and shows up in `/proc/PID/mem` dumps.
/// SecureToken pins the byte buffer in physical RAM (no swap, no
/// /proc fallback), and the destructor wipes the bytes before
/// returning the pages to libc.
pub struct SecureToken {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    // Stashed at construction so Drop never has to recompute (and
    // fallibly re-derive) it -- see the ANSSI-PA-074 R25 note below.
    layout: std::alloc::Layout,
}

impl SecureToken {
    /// Allocate a mlock'd buffer and copy `bytes` into it. The source
    /// `bytes` is left to the caller, typically zeroised right after.
    ///
    /// `bytes` must be valid UTF-8 (checked here, not just documented):
    /// `as_bearer` hands it back out via `from_utf8_unchecked`, and the
    /// caller closest to the trust boundary -- `load_token()` reading an
    /// operator-controlled `RH_TOKEN_FILE` -- cannot otherwise guarantee
    /// the file contents are text. Rejecting invalid UTF-8 here, once,
    /// is what makes that later `unsafe` sound instead of merely documented.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let cap = bytes.len();
        if cap == 0 {
            return Err("empty token".into());
        }
        std::str::from_utf8(bytes).map_err(|e| format!("token is not valid UTF-8: {e}"))?;
        let layout =
            std::alloc::Layout::from_size_align(cap, 1).map_err(|e| format!("layout: {e}"))?;
        // SAFETY: alloc returns null on failure (handled below) ; we own
        // the allocation until Drop frees it ; we never read past `len`.
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            return Err("alloc failed".into());
        }
        // SAFETY: we just allocated `cap` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, cap);
            // mlock the page(s) so the bytes never hit swap. memsec::mlock
            // returns false on failure (e.g. RLIMIT_MEMLOCK exhausted) ;
            // we proceed regardless, best effort, not fatal.
            let _ = memsec::mlock(ptr, cap);
        }
        // `alloc` returning a non-null pointer is guaranteed by its own
        // contract once we've reached here (the null case returned above),
        // so this can never actually fail; NonNull::new still needs the
        // Option unwrapped. `expect` on a provably-true condition, not a
        // fallible one -- unlike the Drop-side rebuild this replaces, there
        // is no allocator or panic surface being introduced.
        let nn = NonNull::new(ptr).expect("alloc returned non-null");
        Ok(Self {
            ptr: nn,
            len: cap,
            cap,
            layout,
        })
    }

    pub fn as_bearer(&self) -> &str {
        // SAFETY: `from_bytes` rejects non-UTF-8 input before this buffer
        // is ever constructed (see the check above), so every byte in
        // [ptr, ptr+len) is guaranteed valid UTF-8, not just assumed to be.
        unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(self.ptr.as_ptr(), self.len))
        }
    }
}

impl Drop for SecureToken {
    fn drop(&mut self) {
        // Wipe the bytes before returning the pages. `layout` was computed
        // once in `from_bytes` and stashed on the struct (see field comment)
        // specifically so this destructor never needs a fallible call --
        // ANSSI-PA-074 R25 forbids panics inside `Drop`, and with this
        // crate's `panic = "abort"` release profile a panic here would
        // abort mid-teardown, after `zeroize()` but before `dealloc`.
        unsafe {
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap);
            slice.zeroize();
            let _ = memsec::munlock(self.ptr.as_ptr(), self.cap);
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// Read the canonical `RH_<name>` env var, falling back to the deprecated
/// `RHORIZON_<name>` alias. RH_* is the product-wide prefix; RHORIZON_* still
/// works so existing deployments keep running.
pub fn env_var(name: &str) -> Result<String, env::VarError> {
    env::var(format!("RH_{name}")).or_else(|_| env::var(format!("RHORIZON_{name}")))
}

/// Load the bearer token from the most secure source available.
///
/// Order (each name falls back to its deprecated `RHORIZON_*` alias):
/// 1. `RH_TOKEN_FILE` env points at a path containing the token.
///    The file should be `chmod 0400` and supplied via `podman secret`,
///    `docker secret`, or kubernetes Secret volume. We read, trim, and
///    zero the read buffer before constructing `SecureToken`.
/// 2. `RH_TOKEN` env (legacy / dev), visible to `podman inspect`,
///    `/proc/PID/environ`, and journald if the process is verbose, so
///    we strongly recommend the file path. After read we wipe the env
///    via `unsetenv` to remove it from `/proc/PID/environ`.
///
/// Both paths return a SecureToken. The original String/Vec backing the
/// read is zeroised before this function returns.
pub fn load_token() -> Result<SecureToken, String> {
    if let Ok(path) = env_var("TOKEN_FILE") {
        let mut data =
            fs::read(&path).map_err(|e| format!("RH_TOKEN_FILE: cannot read {path}: {e}"))?;
        // Trim trailing whitespace / newlines (common from `echo "rh_..." > file`).
        while let Some(&b) = data.last() {
            if b == b'\n' || b == b'\r' || b == b' ' || b == b'\t' {
                data.pop();
            } else {
                break;
            }
        }
        let tok = SecureToken::from_bytes(&data)?;
        data.zeroize();
        return Ok(tok);
    }
    if let Ok(mut s) = env_var("TOKEN") {
        // SAFETY: unsetenv has well-known thread-safety caveats but at
        // this point the program has not spawned any threads (we are
        // in `fn main` setup). Scrub BOTH the canonical and alias names
        // so neither lingers in `/proc/PID/environ`; the Rust side has
        // its own SecureToken copy.
        unsafe {
            env::remove_var("RH_TOKEN");
            env::remove_var("RHORIZON_TOKEN");
        }
        let tok = SecureToken::from_bytes(s.as_bytes())?;
        s.zeroize();
        return Ok(tok);
    }
    Err("Set RH_TOKEN_FILE (preferred) or RH_TOKEN".into())
}

/// Owned parsed spec extracted from `RHORIZON_SECRETS` (`[ns/]name:/path`).
/// Owned strings keep the type independent of the source `&str` lifetime -
/// the caller can iterate over a Vec<SecretSpec> after dropping the env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSpec {
    pub namespace: Option<String>,
    pub name: String,
    pub path: String,
}

/// Parse `RHORIZON_SECRETS` into typed specs.
///
/// Format : `[ns/]name:/path,[ns/]name:/path,...`
///: Empty entries between commas are skipped (trailing comma OK).
///: Surrounding whitespace per entry is trimmed.
///: Entries without `:` are dropped silently, caller decides whether
///   to warn (rh-fetch logs per-entry, rh-watch fails fast on empty).
///: `name` half may be `ns/name` to scope the lookup to a namespace.
///
/// Returns the specs in input order, no dedup (caller may want to dedup
/// or treat duplicates as errors depending on UX).
pub fn parse_secrets_spec(spec: &str) -> Vec<SecretSpec> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| {
            let (left, path) = entry.split_once(':')?;
            let (namespace, name) = match left.split_once('/') {
                Some((ns, n)) => (Some(ns.to_string()), n.to_string()),
                None => (None, left.to_string()),
            };
            Some(SecretSpec {
                namespace,
                name,
                path: path.to_string(),
            })
        })
        .collect()
}

/// Owned parsed reference extracted from an `rh://[ns/]name` env value
/// (used by rh-inject).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhRef {
    pub namespace: Option<String>,
    pub name: String,
}

/// Parse an `rh://[ns/]name` reference. Returns `None` if the prefix is
/// missing or the remainder is empty (`rh://` alone or `rh:///foo`).
pub fn parse_rh_reference(value: &str) -> Option<RhRef> {
    let rest = value.strip_prefix("rh://")?;
    if rest.is_empty() {
        return None;
    }
    let (namespace, name) = match rest.split_once('/') {
        Some((ns, n)) if !ns.is_empty() && !n.is_empty() => (Some(ns.to_string()), n.to_string()),
        // Either `rh:///name` (empty ns), `rh://ns/` (empty name), or
        // a multi-slash variant, reject. Same as `rh://` alone above :
        // the caller should not silently fall back on a half-parsed ref.
        Some(_) => return None,
        None => (None, rest.to_string()),
    };
    Some(RhRef { namespace, name })
}

/// Atomic write : write to `<path>.tmp`, fsync, rename to `path`, mode 0400.
/// The consumer never observes a partially-written file. Caller is the
/// owner ; the file is read-only to its uid only.
pub fn atomic_write(path: &str, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = format!("{path}.tmp");
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(&tmp)
        .map_err(|e| format!("open {tmp}: {e}"))?;
    file.write_all(data)
        .map_err(|e| format!("write {tmp}: {e}"))?;
    file.sync_all().map_err(|e| format!("sync {tmp}: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename -> {path}: {e}"))?;
    Ok(())
}

// ============================================================================
// Ephemeral token rotation (rh-watch, opt-in via RHORIZON_EPHEMERAL=true).
//
// The bootstrap token (long-lived, held in mlock'd RAM via `SecureToken`) is
// used **only** to mint short-lived ephemerals via POST /tokens/ephemeral.
// Every fetch in the watch loop uses the active ephemeral, which gets
// refreshed at TTL/2. If the refresh window is missed, the ephemeral stays
// valid for another TTL/2, that's the retry budget on comm loss.
//
// Permissions are forced to `secrets:r` (no foot-gun via env). allowed_ips
// is inherited from the bootstrap via /tokens/whoami, so a leaked ephemeral
// can't be replayed from outside the bootstrap's allowlist.
// ============================================================================

#[derive(serde::Deserialize)]
struct WhoamiResponse {
    allowed_ips: Option<String>,
    namespaces: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct EphemeralResponse {
    token: String,
    ttl_seconds: u64,
}

/// Holds the bootstrap token + the inherited allowed_ips/namespaces so
/// we can mint ephemerals on demand. `bootstrap` stays in mlock'd RAM
/// for the lifetime of the minter.
pub struct EphemeralMinter {
    bootstrap: SecureToken,
    addr: String,
    ttl_seconds: u64,
    allowed_ips: Option<String>,
    namespaces: Option<Vec<String>>,
}

impl EphemeralMinter {
    /// Build a minter from a bootstrap token. Calls /tokens/whoami once
    /// to inherit `allowed_ips`, fail fast if the bootstrap is not
    /// usable (wrong scope, expired, IP-blocked).
    pub fn new(
        client: &http::HttpClient,
        bootstrap: SecureToken,
        addr: String,
        ttl_seconds: u64,
    ) -> Result<Self, String> {
        let url = format!("{addr}/api/v1/vault/tokens/whoami");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", bootstrap.as_bearer()))
            .send()
            .map_err(|e| format!("whoami request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("whoami HTTP {}", resp.status()));
        }
        let info: WhoamiResponse = resp.json().map_err(|e| format!("whoami parse: {e}"))?;
        let allowed_ips = info.allowed_ips.filter(|s| !s.is_empty());
        let namespaces = info.namespaces.filter(|v| !v.is_empty());
        Ok(Self {
            bootstrap,
            addr,
            ttl_seconds,
            allowed_ips,
            namespaces,
        })
    }

    pub fn allowed_ips(&self) -> Option<&str> {
        self.allowed_ips.as_deref()
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// Mint a fresh ephemeral. Forces `permissions: {"secrets": "r"}`
    /// (no foot-gun via env). Inherits `allowed_ips` so a leaked
    /// ephemeral can't be replayed from outside the bootstrap's
    /// allowlist. The returned `SecureToken` is mlock'd ; the
    /// SystemTime is the absolute expiry deadline.
    pub fn mint(
        &self,
        client: &http::HttpClient,
    ) -> Result<(SecureToken, std::time::SystemTime), String> {
        let url = format!("{}/api/v1/vault/tokens/ephemeral", self.addr);
        // Force `secrets:r` only, no foot-gun via env. If the bootstrap
        // is namespace-restricted, we MUST include the same `namespaces`
        // subset in the request, otherwise POLA grant-check returns 403.
        let mut perms = serde_json::json!({"secrets": "r"});
        if let Some(ns) = &self.namespaces {
            perms["namespaces"] = serde_json::Value::Array(
                ns.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            );
        }
        let mut body = serde_json::json!({
            "permissions": perms,
            "ttl_seconds": self.ttl_seconds,
            "label": "rh-watch",
            // Always opt-in to group inheritance from the bootstrap.
            // Without this, strict-RBAC namespaces would block every
            // freshly-minted ephemeral until the operator manually
            // declared its (random) name in vault_group_members.
            "inherit_group_membership": true,
        });
        if let Some(ips) = &self.allowed_ips {
            body["allowed_ips"] = serde_json::Value::String(ips.clone());
        }
        let resp = client
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.bootstrap.as_bearer()),
            )
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| format!("mint request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("mint HTTP {}", resp.status()));
        }
        let mut parsed: EphemeralResponse = resp.json().map_err(|e| format!("mint parse: {e}"))?;
        let token = SecureToken::from_bytes(parsed.token.as_bytes())?;
        // Wipe the plaintext copy in the parsed struct.
        parsed.token.zeroize();
        let expires_at =
            std::time::SystemTime::now() + std::time::Duration::from_secs(parsed.ttl_seconds);
        Ok((token, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // load_token() touches process env. cargo test runs in parallel by
    // default: without serialization, RHORIZON_TOKEN/RHORIZON_TOKEN_FILE
    // tests would race. atomic_write tests are filesystem-scoped (unique
    // paths) and need no global lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn unique_path(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}/rhorizon-agent-test-{}-{}-{}",
            std::env::temp_dir().display(),
            prefix,
            std::process::id(),
            n
        )
    }

    // ------------------------------------------------------------------
    // SecureToken
    // ------------------------------------------------------------------

    #[test]
    fn secure_token_round_trip() {
        let t = SecureToken::from_bytes(b"rh_abc123").expect("alloc");
        assert_eq!(t.as_bearer(), "rh_abc123");
    }

    #[test]
    fn secure_token_rejects_empty() {
        // SecureToken intentionally does not implement Debug (would leak
        // bytes in panic messages), so we can't use unwrap_err() ; pull
        // the error out manually instead.
        let err = SecureToken::from_bytes(b"")
            .err()
            .expect("from_bytes(b\"\") should fail");
        assert!(err.contains("empty"), "want 'empty' in {err}");
    }

    #[test]
    fn secure_token_rejects_non_utf8() {
        // Regression test for the ANSSI-PA-074 R10 soundness fix: an
        // operator-controlled RH_TOKEN_FILE could contain arbitrary bytes
        // (wrong file, truncated write, binary garbage). from_bytes must
        // reject that before construction, since as_bearer() later hands
        // the buffer back out via from_utf8_unchecked.
        let invalid = [0x80, 0x81, 0x82, 0xff];
        let err = SecureToken::from_bytes(&invalid)
            .err()
            .expect("from_bytes(non-UTF-8) should fail");
        assert!(err.contains("UTF-8"), "want 'UTF-8' in {err}");
    }

    #[test]
    fn secure_token_handles_long_input() {
        let big = vec![b'x'; 4096];
        let t = SecureToken::from_bytes(&big).expect("alloc 4k");
        assert_eq!(t.as_bearer().len(), 4096);
        assert!(t.as_bearer().chars().all(|c| c == 'x'));
    }

    #[test]
    fn secure_token_drop_runs_without_panic() {
        // Smoke test : exercising Drop on a fresh allocation should not
        // panic (munlock + dealloc path). True zeroize verification needs
        // miri, which runs on api/rust only.
        {
            let _t = SecureToken::from_bytes(b"transient").expect("alloc");
        }
        let _t2 = SecureToken::from_bytes(b"after-drop").expect("alloc");
    }

    // ------------------------------------------------------------------
    // parse_secrets_spec
    // ------------------------------------------------------------------

    #[test]
    fn parse_secrets_spec_single_no_namespace() {
        let got = parse_secrets_spec("api-key:/run/secrets/api");
        assert_eq!(
            got,
            vec![SecretSpec {
                namespace: None,
                name: "api-key".into(),
                path: "/run/secrets/api".into(),
            }]
        );
    }

    #[test]
    fn parse_secrets_spec_with_namespace() {
        let got = parse_secrets_spec("prod/db-pass:/run/secrets/db");
        assert_eq!(
            got,
            vec![SecretSpec {
                namespace: Some("prod".into()),
                name: "db-pass".into(),
                path: "/run/secrets/db".into(),
            }]
        );
    }

    #[test]
    fn parse_secrets_spec_multiple_entries() {
        let got = parse_secrets_spec("a:/p1,prod/b:/p2,c:/p3");
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].name, "a");
        assert_eq!(got[0].namespace, None);
        assert_eq!(got[1].name, "b");
        assert_eq!(got[1].namespace.as_deref(), Some("prod"));
        assert_eq!(got[2].name, "c");
    }

    #[test]
    fn parse_secrets_spec_trims_whitespace() {
        let got = parse_secrets_spec("  api-key:/p  ,  prod/db:/q  ");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "api-key");
        assert_eq!(got[1].name, "db");
        assert_eq!(got[1].namespace.as_deref(), Some("prod"));
    }

    #[test]
    fn parse_secrets_spec_skips_empty_entries() {
        // Trailing/leading commas and doubled commas are tolerated -
        // common when entries are built by string concatenation.
        let got = parse_secrets_spec(",,a:/p1,,b:/p2,");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "a");
        assert_eq!(got[1].name, "b");
    }

    #[test]
    fn parse_secrets_spec_drops_entries_without_colon() {
        // `bogus` has no `:`, silently dropped (caller decides how loud
        // to be ; rh-fetch logs, rh-watch fails fast on empty result).
        let got = parse_secrets_spec("a:/p1,bogus,b:/p2");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "a");
        assert_eq!(got[1].name, "b");
    }

    #[test]
    fn parse_secrets_spec_empty_input_returns_empty() {
        assert!(parse_secrets_spec("").is_empty());
        assert!(parse_secrets_spec("   ").is_empty());
        assert!(parse_secrets_spec(",,,").is_empty());
    }

    #[test]
    fn parse_secrets_spec_preserves_order() {
        let got = parse_secrets_spec("z:/1,y:/2,x:/3");
        assert_eq!(
            got.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["z", "y", "x"]
        );
    }

    #[test]
    fn parse_secrets_spec_does_not_dedup() {
        let got = parse_secrets_spec("a:/p1,a:/p2");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].path, "/p1");
        assert_eq!(got[1].path, "/p2");
    }

    // ------------------------------------------------------------------
    // parse_rh_reference
    // ------------------------------------------------------------------

    #[test]
    fn parse_rh_reference_no_namespace() {
        let got = parse_rh_reference("rh://api-key").unwrap();
        assert_eq!(
            got,
            RhRef {
                namespace: None,
                name: "api-key".into()
            }
        );
    }

    #[test]
    fn parse_rh_reference_with_namespace() {
        let got = parse_rh_reference("rh://prod/db-pass").unwrap();
        assert_eq!(
            got,
            RhRef {
                namespace: Some("prod".into()),
                name: "db-pass".into()
            }
        );
    }

    #[test]
    fn parse_rh_reference_rejects_missing_prefix() {
        assert!(parse_rh_reference("api-key").is_none());
        assert!(parse_rh_reference("http://foo").is_none());
        assert!(parse_rh_reference("").is_none());
    }

    #[test]
    fn parse_rh_reference_rejects_empty_remainder() {
        assert!(parse_rh_reference("rh://").is_none());
    }

    #[test]
    fn parse_rh_reference_rejects_half_parsed() {
        // `rh:///name` (empty namespace) and `rh://ns/` (empty name) are
        // both ambiguous, reject rather than silently treating ns as
        // empty-string or name as empty-string.
        assert!(parse_rh_reference("rh:///name").is_none());
        assert!(parse_rh_reference("rh://ns/").is_none());
    }

    // ------------------------------------------------------------------
    // atomic_write
    // ------------------------------------------------------------------

    #[test]
    fn atomic_write_creates_file_with_content() {
        let path = unique_path("aw-create");
        atomic_write(&path, b"hello").expect("write");
        let got = std::fs::read(&path).expect("read");
        assert_eq!(got, b"hello");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_write_sets_mode_0400() {
        use std::os::unix::fs::PermissionsExt;
        let path = unique_path("aw-mode");
        atomic_write(&path, b"x").expect("write");
        let meta = std::fs::metadata(&path).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, 0o400);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let path = unique_path("aw-overwrite");
        atomic_write(&path, b"first").expect("write 1");
        atomic_write(&path, b"second-longer").expect("write 2");
        let got = std::fs::read(&path).expect("read");
        assert_eq!(got, b"second-longer");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_write_cleans_up_tmp_file() {
        let path = unique_path("aw-tmp-cleanup");
        atomic_write(&path, b"x").expect("write");
        let tmp = format!("{path}.tmp");
        assert!(
            !std::path::Path::new(&tmp).exists(),
            "tmp file {tmp} should be renamed away"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_write_empty_content_is_allowed() {
        let path = unique_path("aw-empty");
        atomic_write(&path, b"").expect("write empty");
        let got = std::fs::read(&path).expect("read");
        assert!(got.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn atomic_write_returns_error_on_unwritable_parent() {
        // /proc/1 is a kernel-managed directory: any attempt to create a
        // file inside fails with EROFS / EACCES on Linux. Portable enough
        // for our CI matrix (Linux only, BSD/macOS would need a different
        // path).
        let path = "/proc/1/should-fail-to-write";
        let err = atomic_write(path, b"x").unwrap_err();
        assert!(
            err.contains("open") || err.contains("write") || err.contains("rename"),
            "want a useful error message, got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // load_token
    // ------------------------------------------------------------------

    fn clear_token_env() {
        // SAFETY: tests serialize via ENV_LOCK ; no other threads touch
        // these vars during the test body. remove_var is unsafe on Rust
        // 2024 edition because it's racy in multi-threaded programs.
        unsafe {
            std::env::remove_var("RH_TOKEN");
            std::env::remove_var("RH_TOKEN_FILE");
            std::env::remove_var("RHORIZON_TOKEN");
            std::env::remove_var("RHORIZON_TOKEN_FILE");
        }
    }

    #[test]
    fn load_token_errors_when_no_source() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        let err = load_token().err().expect("no token source -> err");
        assert!(
            err.contains("RH_TOKEN_FILE") || err.contains("RH_TOKEN"),
            "want a hint about the env vars, got: {err}"
        );
    }

    #[test]
    fn load_token_reads_from_env() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        // SAFETY: lock held, no concurrent env mutation.
        unsafe { std::env::set_var("RHORIZON_TOKEN", "rh_env_secret") };
        let tok = load_token().expect("load");
        assert_eq!(tok.as_bearer(), "rh_env_secret");
        // load_token unsets the token var after copy to keep
        // /proc/PID/environ clean, verify the side effect (the RHORIZON_
        // alias still works, and is scrubbed).
        assert!(std::env::var("RHORIZON_TOKEN").is_err());
    }

    #[test]
    fn load_token_prefers_rh_and_scrubs_both() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        // SAFETY: lock held, no concurrent env mutation.
        unsafe {
            std::env::set_var("RH_TOKEN", "rh_canonical");
            std::env::set_var("RHORIZON_TOKEN", "rh_legacy");
        }
        let tok = load_token().expect("load");
        // RH_* is canonical, so it wins over the RHORIZON_* alias.
        assert_eq!(tok.as_bearer(), "rh_canonical");
        // Both names are scrubbed from the environ.
        assert!(std::env::var("RH_TOKEN").is_err());
        assert!(std::env::var("RHORIZON_TOKEN").is_err());
    }

    #[test]
    fn load_token_reads_from_file_preferred() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        let path = unique_path("token-file");
        std::fs::write(&path, "rh_from_file\n").expect("write tmp token");
        // SAFETY: lock held, no concurrent env mutation.
        unsafe {
            std::env::set_var("RHORIZON_TOKEN_FILE", &path);
            std::env::set_var("RHORIZON_TOKEN", "rh_should_be_ignored");
        }
        let tok = load_token().expect("load");
        // FILE wins over env even when both are set.
        assert_eq!(tok.as_bearer(), "rh_from_file");
        let _ = std::fs::remove_file(&path);
        unsafe { std::env::remove_var("RHORIZON_TOKEN") };
        unsafe { std::env::remove_var("RHORIZON_TOKEN_FILE") };
    }

    #[test]
    fn load_token_trims_trailing_whitespace_from_file() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        let path = unique_path("token-trim");
        // Trailing newline + tab + space, `echo "rh_x" > file` adds \n.
        std::fs::write(&path, "rh_trimmed\n\t ").expect("write");
        unsafe { std::env::set_var("RHORIZON_TOKEN_FILE", &path) };
        let tok = load_token().expect("load");
        assert_eq!(tok.as_bearer(), "rh_trimmed");
        let _ = std::fs::remove_file(&path);
        unsafe { std::env::remove_var("RHORIZON_TOKEN_FILE") };
    }

    #[test]
    fn load_token_errors_on_empty_file() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        let path = unique_path("token-empty");
        std::fs::write(&path, "").expect("write empty");
        unsafe { std::env::set_var("RHORIZON_TOKEN_FILE", &path) };
        let err = load_token().err().expect("empty file -> err");
        assert!(err.contains("empty"), "want 'empty' in {err}");
        let _ = std::fs::remove_file(&path);
        unsafe { std::env::remove_var("RHORIZON_TOKEN_FILE") };
    }

    #[test]
    fn load_token_errors_on_missing_file() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_token_env();
        let path = unique_path("token-missing");
        // Don't create the file, load_token must surface the io error.
        unsafe { std::env::set_var("RHORIZON_TOKEN_FILE", &path) };
        let err = load_token().err().expect("missing file -> err");
        assert!(
            err.contains("RHORIZON_TOKEN_FILE") || err.contains("cannot read"),
            "want file-source hint, got: {err}"
        );
        unsafe { std::env::remove_var("RHORIZON_TOKEN_FILE") };
    }

    #[test]
    fn percent_encode_keeps_the_unreserved_set_verbatim() {
        // RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~".
        // Ordinary secret names must survive untouched, or every existing
        // deployment's URLs change shape on upgrade.
        let plain = "abcXYZ019-._~";
        assert_eq!(http::encode_component(plain), plain);
    }

    #[test]
    fn percent_encode_neutralises_path_traversal_and_query_injection() {
        // The point of the fix. Each of these silently changed WHICH url was
        // requested when interpolated raw.
        assert_eq!(http::encode_component("a/b"), "a%2Fb");
        assert_eq!(http::encode_component("../admin"), "..%2Fadmin");
        assert_eq!(
            http::encode_component("x?namespace=prod"),
            "x%3Fnamespace%3Dprod"
        );
        assert_eq!(http::encode_component("x#frag"), "x%23frag");
        assert_eq!(http::encode_component("a b"), "a%20b");
        assert_eq!(http::encode_component("100%"), "100%25");
    }

    #[test]
    fn percent_encode_is_byte_wise_for_non_ascii() {
        // Encodes UTF-8 bytes, not chars: "é" is two bytes and must become two
        // escapes, not one mangled char.
        assert_eq!(http::encode_component("é"), "%C3%A9");
    }
}
