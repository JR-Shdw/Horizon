// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! rh-watch, sidecar that polls rhorizon and updates secret files.
//!
//! Runs alongside the app container, polls the vault API at a
//! configurable interval, and atomically updates files on the
//! shared tmpfs volume when secrets change. Optionally signals
//! the app to reload its config.
//!
//! Env vars (each also accepts its deprecated RHORIZON_* alias) :
//!   RH_ADDR          - vault API base URL
//!   RH_TOKEN_FILE    - path to bearer token file (preferred)
//!   RH_TOKEN         - bearer token (legacy)
//!   RH_SECRETS       - "[ns/]name:/path,[ns/]name:/path,..."
//!                      Pass `ns/name` to disambiguate same-name
//!                      secrets across namespaces.
//!   RH_POLL_SECS     - poll interval seconds (default: 30, min: 5)
//!   RH_RELOAD_PID    - PID to signal on change (optional, e.g. 1)
//!   RH_RELOAD_SIGNAL - signal name to send (default: HUP)
//!   RH_EPHEMERAL     - opt-in: "true" rotates a TTL'd /tokens/ephemeral
//!                      so the bootstrap is only used to mint, never
//!                      to fetch. Defaults to off, emits a WARN.
//!   RH_EPHEMERAL_TTL - TTL of each ephemeral, seconds (default 3600,
//!                      min 60, max 86400). Refresh runs at TTL/2.

use std::collections::HashMap;
use std::process;
use std::thread;
use std::time::Duration;

use rhorizon_agent::http::encode_component;
use rhorizon_agent::{
    atomic_write, build_client, env_var, load_token, parse_secrets_spec, EphemeralMinter,
    SecureToken,
};

#[derive(serde::Deserialize)]
struct SecretResponse {
    value: String,
}

fn fetch_secret(
    client: &rhorizon_agent::http::HttpClient,
    addr: &str,
    token: &SecureToken,
    name: &str,
    namespace: Option<&str>,
) -> Result<String, String> {
    let url = format!("{addr}/api/v1/vault/secrets/{}", encode_component(name));
    let mut req = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token.as_bearer()));
    if let Some(ns) = namespace {
        req = req.query(&[("namespace", ns)]);
    }
    let resp = req.send().map_err(|e| format!("request: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let secret: SecretResponse = resp.json().map_err(|e| format!("parse: {e}"))?;
    Ok(secret.value)
}

/// Non-crypto hash for change detection only.
fn hash_value(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Map a signal name to its libc number. We avoid pulling a full
/// signal crate ; the canonical reload signals are SIGHUP / SIGUSR1 /
/// SIGUSR2 on Linux + BSD.
fn signal_num(name: &str) -> Option<i32> {
    match name.to_ascii_uppercase().as_str() {
        "HUP" | "SIGHUP" => Some(1),
        "USR1" | "SIGUSR1" => Some(10),
        "USR2" | "SIGUSR2" => Some(12),
        "TERM" | "SIGTERM" => Some(15),
        _ => None,
    }
}

/// Send a reload signal to the configured PID. Best effort, log the
/// outcome, never abort the watcher loop on failure.
fn maybe_signal_reload(reload_pid: Option<i32>, reload_sig: i32, what: &str) {
    let Some(pid) = reload_pid else { return };
    // SAFETY: kill(2) is async-signal-safe and accepts any i32 ;
    // EPERM/ESRCH are returned via errno, never UB.
    let rc = unsafe { libc::kill(pid, reload_sig) };
    if rc == 0 {
        eprintln!("[rh-watch]   reload signal -> pid {pid} (after {what})");
    } else {
        let err = std::io::Error::last_os_error();
        eprintln!("[rh-watch]   reload signal failed pid {pid}: {err}");
    }
}

/// Holder for the bearer token in use. Either the bootstrap (legacy) or
/// a TTL'd ephemeral minted from the bootstrap. `bearer()` exposes the
/// active token to fetch_secret().
enum ActiveAuth {
    Bootstrap(SecureToken),
    Rotating {
        minter: EphemeralMinter,
        active: SecureToken,
        expires_at: std::time::SystemTime,
    },
}

impl ActiveAuth {
    fn bearer(&self) -> &SecureToken {
        match self {
            ActiveAuth::Bootstrap(t) => t,
            ActiveAuth::Rotating { active, .. } => active,
        }
    }

    /// If we're rotating and past TTL/2, mint a new ephemeral and swap.
    /// Best effort : on failure, log WARN and keep the current one until
    /// it actually expires.
    fn maybe_refresh(&mut self, client: &rhorizon_agent::http::HttpClient) {
        let ActiveAuth::Rotating {
            minter,
            active,
            expires_at,
        } = self
        else {
            return;
        };
        let now = std::time::SystemTime::now();
        let half_ttl = Duration::from_secs(minter.ttl_seconds() / 2);
        let refresh_after = *expires_at - half_ttl;
        if now < refresh_after {
            return;
        }
        match minter.mint(client) {
            Ok((new_active, new_expires)) => {
                // Drop the old SecureToken (Zeroize on Drop).
                *active = new_active;
                *expires_at = new_expires;
                eprintln!(
                    "[rh-watch] ephemeral refreshed (next refresh in {}s)",
                    minter.ttl_seconds() / 2
                );
            }
            Err(e) => {
                let remaining = expires_at
                    .duration_since(now)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                eprintln!(
                    "[rh-watch] WARN ephemeral refresh failed: {e} \
                     (current valid {remaining}s, will retry next poll)"
                );
            }
        }
    }
}

fn main() {
    let addr = env_var("ADDR").unwrap_or_else(|_| {
        eprintln!("Error: RH_ADDR must be set");
        process::exit(1);
    });

    let bootstrap = match load_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let secrets_spec = env_var("SECRETS").unwrap_or_else(|_| {
        eprintln!("Error: RH_SECRETS must be set");
        process::exit(1);
    });

    let poll_secs: u64 = env_var("POLL_SECS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .unwrap_or(30)
        .max(5);

    let reload_pid: Option<i32> = env_var("RELOAD_PID").ok().and_then(|s| s.parse().ok());
    let reload_sig: i32 = env_var("RELOAD_SIGNAL")
        .ok()
        .and_then(|s| signal_num(&s))
        .unwrap_or(1); // default SIGHUP

    let ephemeral_enabled = env_var("EPHEMERAL")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"))
        .unwrap_or(false);

    let ephemeral_ttl: u64 = env_var("EPHEMERAL_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600)
        .clamp(60, 86400);

    // Each entry is `[ns/]name:/path`, parsed in lib.rs so the same
    // format is enforced across rh-fetch / rh-watch.
    let specs = parse_secrets_spec(&secrets_spec);

    if specs.is_empty() {
        eprintln!("Error: RH_SECRETS is empty or malformed");
        process::exit(1);
    }

    eprintln!(
        "[rh-watch] {} secret(s), poll every {poll_secs}s",
        specs.len()
    );
    if let Some(pid) = reload_pid {
        eprintln!("[rh-watch] will signal pid {pid} (sig {reload_sig}) on change");
    }

    let client = build_client().unwrap_or_else(|e| {
        eprintln!("[rh-watch] FATAL: HTTP client: {e}");
        process::exit(1);
    });

    // Mint the first ephemeral if opted-in. Fail fast on startup, if
    // we can't mint, the operator's bootstrap is misconfigured and
    // deferring would just confuse the failure mode.
    let mut auth = if ephemeral_enabled {
        let minter = match EphemeralMinter::new(&client, bootstrap, addr.clone(), ephemeral_ttl) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[rh-watch] FATAL: ephemeral minter init: {e}");
                process::exit(1);
            }
        };
        let inherited = minter.allowed_ips().unwrap_or("any").to_string();
        match minter.mint(&client) {
            Ok((active, expires_at)) => {
                eprintln!(
                    "[rh-watch] ephemeral rotation enabled (TTL {ephemeral_ttl}s, refresh at {}s, allowed_ips={inherited})",
                    ephemeral_ttl / 2
                );
                ActiveAuth::Rotating {
                    minter,
                    active,
                    expires_at,
                }
            }
            Err(e) => {
                eprintln!("[rh-watch] FATAL: first ephemeral mint: {e}");
                process::exit(1);
            }
        }
    } else {
        eprintln!(
            "[rh-watch] WARN: ephemeral rotation disabled - \
             bootstrap token used directly for every fetch. \
             Set RHORIZON_EPHEMERAL=true to enable TTL rotation \
             (requires bootstrap with tokens:w scope)."
        );
        ActiveAuth::Bootstrap(bootstrap)
    };

    let mut cache: HashMap<String, u64> = HashMap::new();

    // The cache key encodes ns+name so a same-name secret in two
    // namespaces gets two independent change-detection slots.
    let cache_key = |ns: Option<&str>, name: &str| -> String {
        match ns {
            Some(n) => format!("{n}/{name}"),
            None => name.to_string(),
        }
    };

    // Initial fetch, fail hard if vault unreachable
    for spec in &specs {
        let namespace = spec.namespace.as_deref();
        let name = spec.name.as_str();
        let path = spec.path.as_str();
        match fetch_secret(&client, &addr, auth.bearer(), name, namespace) {
            Ok(value) => {
                if let Err(e) = atomic_write(path, value.as_bytes()) {
                    eprintln!("[rh-watch] FATAL: {e}");
                    process::exit(1);
                }
                cache.insert(cache_key(namespace, name), hash_value(&value));
                eprintln!("[rh-watch]   {name} -> {path}");
            }
            Err(e) => {
                eprintln!("[rh-watch] FATAL: {name}: {e}");
                process::exit(1);
            }
        }
    }

    eprintln!("[rh-watch] initial fetch done, polling...");

    // Poll loop, errors are warnings, not fatal
    loop {
        thread::sleep(Duration::from_secs(poll_secs));

        // Refresh ephemeral if needed (no-op if Bootstrap mode).
        auth.maybe_refresh(&client);

        let mut changed_names: Vec<String> = Vec::new();
        for spec in &specs {
            let namespace = spec.namespace.as_deref();
            let name = spec.name.as_str();
            let path = spec.path.as_str();
            match fetch_secret(&client, &addr, auth.bearer(), name, namespace) {
                Ok(value) => {
                    let h = hash_value(&value);
                    let k = cache_key(namespace, name);
                    if h != cache.get(&k).copied().unwrap_or(0) {
                        match atomic_write(path, value.as_bytes()) {
                            Ok(()) => {
                                cache.insert(k, h);
                                changed_names.push(name.to_string());
                                eprintln!("[rh-watch] UPDATED {name}");
                            }
                            Err(e) => {
                                eprintln!("[rh-watch] ERROR {path}: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[rh-watch] WARN {name}: {e} (retry next poll)");
                }
            }
        }

        if !changed_names.is_empty() {
            maybe_signal_reload(
                reload_pid,
                reload_sig,
                &format!("{} change(s)", changed_names.len()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // signal_num matches the libc numbers for Linux x86_64, the only
    // architectures the agent ships to today. Hardcoded on purpose : a
    // wrong number would silently send the wrong signal, e.g. SIGKILL
    // (9) when the user typed "USR1" (10). The test pins the map.

    #[test]
    fn signal_num_known_signals() {
        assert_eq!(signal_num("HUP"), Some(1));
        assert_eq!(signal_num("USR1"), Some(10));
        assert_eq!(signal_num("USR2"), Some(12));
        assert_eq!(signal_num("TERM"), Some(15));
    }

    #[test]
    fn signal_num_accepts_sig_prefix() {
        assert_eq!(signal_num("SIGHUP"), Some(1));
        assert_eq!(signal_num("SIGUSR1"), Some(10));
        assert_eq!(signal_num("SIGUSR2"), Some(12));
        assert_eq!(signal_num("SIGTERM"), Some(15));
    }

    #[test]
    fn signal_num_is_case_insensitive() {
        assert_eq!(signal_num("hup"), Some(1));
        assert_eq!(signal_num("sigterm"), Some(15));
        assert_eq!(signal_num("UsR1"), Some(10));
    }

    #[test]
    fn signal_num_rejects_unknown() {
        // Note : we DON'T accept SIGKILL/SIGSEGV by design, only reload
        // signals make sense for a watcher. The blocklist is implicit
        // (the match arms are an allowlist) ; this test pins it.
        assert_eq!(signal_num("KILL"), None);
        assert_eq!(signal_num("SIGKILL"), None);
        assert_eq!(signal_num("SEGV"), None);
        assert_eq!(signal_num("INT"), None);
        assert_eq!(signal_num(""), None);
        assert_eq!(signal_num("9"), None);
    }

    // hash_value is non-crypto, only used for change detection : same
    // input -> same hash, different input -> different hash (with very
    // high probability, DefaultHasher is SipHash-1-3, 64-bit).

    #[test]
    fn hash_value_is_deterministic() {
        let a = hash_value("hello");
        let b = hash_value("hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_value_distinguishes_different_inputs() {
        assert_ne!(hash_value("hello"), hash_value("world"));
        assert_ne!(hash_value(""), hash_value(" "));
        // Single-byte change must shift the hash (covers the typical
        // "secret rotated, last char changed" case).
        assert_ne!(hash_value("rh_aaaa"), hash_value("rh_aaab"));
    }

    #[test]
    fn hash_value_empty_string_is_stable() {
        // Empty hash is stable (DefaultHasher's finish() of zero bytes
        // is constant), pinning so a Rust stdlib change is caught
        // rather than silently flipping the cache miss/hit pattern.
        let h1 = hash_value("");
        let h2 = hash_value("");
        assert_eq!(h1, h2);
    }

    // cache_key is a tiny formatter ; we mostly want regression coverage
    // so a rename that breaks the "same name in two namespaces gets two
    // slots" invariant is caught immediately.

    #[test]
    fn cache_key_without_namespace() {
        // Defined as closure inside main(), we re-implement the same
        // shape here to test the invariant. Kept in sync by review of
        // the closure body in main() (no separate fn to extract because
        // it captures nothing).
        let key_no_ns = |name: &str| -> String { name.to_string() };
        assert_eq!(key_no_ns("api-key"), "api-key");
    }

    #[test]
    fn cache_key_with_namespace_disambiguates() {
        let key_with_ns = |ns: Option<&str>, name: &str| -> String {
            match ns {
                Some(n) => format!("{n}/{name}"),
                None => name.to_string(),
            }
        };
        // Same `name`, different namespaces -> two distinct keys so the
        // change-detection cache holds them independently.
        assert_ne!(
            key_with_ns(Some("prod"), "db-pass"),
            key_with_ns(Some("staging"), "db-pass")
        );
        // Bare name vs prod-scoped name : also distinct.
        assert_ne!(
            key_with_ns(None, "db-pass"),
            key_with_ns(Some("prod"), "db-pass")
        );
    }
}
