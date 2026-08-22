// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! rh-podman, podman external secret driver backend for rhorizon.
//!
//! Implements podman's `shell` driver protocol so podman can use
//! rhorizon as the source of truth for secrets without ever caching
//! them on disk. Each operation is invoked by podman as a subcommand
//! of this binary :
//!
//!   list    : print JSON [{id, name}, ...] of available secrets
//!   lookup  : env SECRET_ID, write the raw secret value to stdout
//!   store   : env SECRET_ID, read value from stdin, push to vault
//!   delete  : env SECRET_ID, remove the secret from vault
//!
//! Setup (once per host) :
//!
//!   # RH_* is canonical; the RHORIZON_* aliases still work.
//!   export RH_ADDR=https://vault.example.com
//!   export RH_TOKEN_FILE=/etc/rhorizon/podman.token   # mode 0400
//!   export RH_NAMESPACE=podman                        # default
//!
//!   # Tell podman to use rh-podman as the secret driver. Once. The
//!   # 4 driver-opts are passed as separate flags ; podman concatenates
//!   # them into one map.
//!   alias podman-secret-rhorizon='podman secret create \
//!     --driver shell \
//!     --driver-opts list="rh-podman list" \
//!     --driver-opts lookup="rh-podman lookup" \
//!     --driver-opts store="rh-podman store" \
//!     --driver-opts delete="rh-podman delete"'
//!
//!   echo 's3kr3t' | podman-secret-rhorizon db-password -
//!   podman run --secret db-password,target=/run/db-password myapp:latest
//!
//! Trust model :
//!   - rh-podman holds a vault token (mode 0400 file). The host must
//!     therefore be considered an extension of the vault's trust
//!     boundary, same posture as the operator's CLI on the same host.
//!   - For untrusted hosts (multi-tenant Podman, CI runners, etc.),
//!     mint a per-host ephemeral token scoped tightly (e.g.
//!     `secrets:r` namespace=podman, allowed_ips=this-host/32, TTL
//!     short, rotated by rh-watch).
//!   - rhorizon's audit chain logs every read/write/delete with the
//!     vault token name as actor, so per-host token names give you a
//!     traceable host attribution.
//!
//! IMPORTANT, RH_NAMESPACE is the AUTHORITY SCOPE for this host.
//!   Anyone on the host with execute access to rh-podman can perform
//!   list / lookup / store / delete on EVERY secret inside
//!   RH_NAMESPACE (subject to the token's vault-side scope).
//!   Pick the namespace tightly :
//!     - DO use `podman-<hostname>` (one namespace per host)
//!     - DO NOT use `prod` or any shared namespace
//!     - DO restrict the vault token to that single namespace
//!   This way, a misuse of rh-podman on host A cannot reach host B's
//!   secrets, even if the vault token leaks.

use std::env;
use std::io::{self, Read, Write};
use std::process;

use rhorizon_agent::http::encode_component;
use rhorizon_agent::{build_client, env_var, load_token};

#[derive(serde::Serialize)]
struct PodmanSecret {
    id: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct ListEntry {
    name: String,
}

#[derive(serde::Deserialize)]
struct ListResponse {
    items: Vec<ListEntry>,
}

#[derive(serde::Deserialize)]
struct SecretResponse {
    value: String,
}

fn vault_addr() -> String {
    env_var("ADDR").unwrap_or_else(|_| {
        eprintln!("[rh-podman] FATAL: RH_ADDR not set");
        process::exit(2);
    })
}

fn namespace() -> String {
    env_var("NAMESPACE").unwrap_or_else(|_| "podman".to_string())
}

fn http_client() -> rhorizon_agent::http::HttpClient {
    build_client().unwrap_or_else(|e| {
        eprintln!("[rh-podman] FATAL: HTTP client init failed: {e}");
        process::exit(2);
    })
}

fn cmd_list() -> i32 {
    let addr = vault_addr();
    let ns = namespace();
    let token = match load_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[rh-podman] FATAL: {e}");
            return 2;
        }
    };
    let client = http_client();
    let url = format!(
        "{addr}/api/v1/vault/secrets/?namespace={}",
        encode_component(&ns)
    );
    let resp = match client.get(&url).bearer_auth(token.as_bearer()).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[rh-podman] list: HTTP error: {e}");
            return 1;
        }
    };
    if !resp.status().is_success() {
        eprintln!("[rh-podman] list: HTTP {}", resp.status());
        return 1;
    }
    let body: ListResponse = match resp.json() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[rh-podman] list: parse error: {e}");
            return 1;
        }
    };
    // podman expects [{id, name}, ...]. We use the rhorizon name as both
    // id and name, names are unique within a namespace, so that's a stable
    // identifier from podman's point of view.
    let pods: Vec<PodmanSecret> = body
        .items
        .into_iter()
        .map(|s| PodmanSecret {
            id: s.name.clone(),
            name: s.name,
        })
        .collect();
    match serde_json::to_string(&pods) {
        Ok(out) => {
            println!("{out}");
            0
        }
        Err(e) => {
            eprintln!("[rh-podman] list: serialize error: {e}");
            1
        }
    }
}

fn cmd_lookup() -> i32 {
    let id = match env::var("SECRET_ID") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[rh-podman] lookup: SECRET_ID env not set");
            return 1;
        }
    };
    let addr = vault_addr();
    let ns = namespace();
    let token = match load_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[rh-podman] FATAL: {e}");
            return 2;
        }
    };
    let client = http_client();
    let url = format!(
        "{addr}/api/v1/vault/secrets/{}?namespace={}",
        encode_component(&id),
        encode_component(&ns)
    );
    let resp = match client.get(&url).bearer_auth(token.as_bearer()).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[rh-podman] lookup: HTTP error: {e}");
            return 1;
        }
    };
    if !resp.status().is_success() {
        eprintln!("[rh-podman] lookup: HTTP {} for {id}", resp.status());
        return 1;
    }
    let body: SecretResponse = match resp.json() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[rh-podman] lookup: parse error: {e}");
            return 1;
        }
    };
    // podman captures stdout verbatim as the secret value. We write
    // the bytes raw, no trailing newline so binary or json-as-string
    // payloads round-trip cleanly. Caller scripts that rely on a
    // trailing newline should use `printf %s | rh-podman store`.
    if let Err(e) = io::stdout().write_all(body.value.as_bytes()) {
        eprintln!("[rh-podman] lookup: stdout write failed: {e}");
        return 1;
    }
    0
}

fn cmd_store() -> i32 {
    let id = match env::var("SECRET_ID") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[rh-podman] store: SECRET_ID env not set");
            return 1;
        }
    };
    let mut buf = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut buf) {
        eprintln!("[rh-podman] store: stdin read failed: {e}");
        return 1;
    }
    // rhorizon secrets are typed as text (UTF-8). Binary blobs need
    // base64 wrapping at the caller, surface this as a clear error
    // rather than silently corrupting via lossy decode.
    let value = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "[rh-podman] store: secret value is not valid UTF-8 - \
                 rhorizon stores text values. Base64-encode binary blobs \
                 before piping into podman secret create."
            );
            return 1;
        }
    };
    let addr = vault_addr();
    let ns = namespace();
    let token = match load_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[rh-podman] FATAL: {e}");
            return 2;
        }
    };
    let client = http_client();
    let url = format!("{addr}/api/v1/vault/secrets/");
    let body = serde_json::json!({
        "name": id,
        "value": value,
        "namespace": ns,
    });
    let resp = match client
        .post(&url)
        .bearer_auth(token.as_bearer())
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[rh-podman] store: HTTP error: {e}");
            return 1;
        }
    };
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let txt = resp.text().unwrap_or_default();
        eprintln!("[rh-podman] store: HTTP {code} for {id} - {txt}");
        return 1;
    }
    0
}

fn cmd_delete() -> i32 {
    let id = match env::var("SECRET_ID") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[rh-podman] delete: SECRET_ID env not set");
            return 1;
        }
    };
    let addr = vault_addr();
    let ns = namespace();
    let token = match load_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[rh-podman] FATAL: {e}");
            return 2;
        }
    };
    let client = http_client();
    let url = format!(
        "{addr}/api/v1/vault/secrets/{}?namespace={}",
        encode_component(&id),
        encode_component(&ns)
    );
    let resp = match client.delete(&url).bearer_auth(token.as_bearer()).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[rh-podman] delete: HTTP error: {e}");
            return 1;
        }
    };
    if !resp.status().is_success() {
        eprintln!("[rh-podman] delete: HTTP {} for {id}", resp.status());
        return 1;
    }
    0
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = match args.next() {
        Some(c) => c,
        None => {
            eprintln!("Usage: rh-podman <list|lookup|store|delete>");
            eprintln!();
            eprintln!("Podman shell-driver backend for rhorizon. See the");
            eprintln!("module-level rustdoc / agent/README.md for setup.");
            process::exit(2);
        }
    };
    let exit = match cmd.as_str() {
        "list" => cmd_list(),
        "lookup" => cmd_lookup(),
        "store" => cmd_store(),
        "delete" => cmd_delete(),
        other => {
            eprintln!("Unknown command: {other}. Use list|lookup|store|delete.");
            2
        }
    };
    process::exit(exit);
}
