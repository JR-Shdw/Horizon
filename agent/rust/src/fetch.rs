// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! rh-fetch, pull secrets from rhorizon and write them as files.
//!
//! Init container pattern: fetch secrets to a shared tmpfs volume,
//! then the app container reads them as files. No runtime dependency
//! on the vault.
//!
//! Env vars (each also accepts its deprecated RHORIZON_* alias) :
//!   RH_ADDR        - vault API base URL (e.g. https://vault.example.com)
//!   RH_TOKEN_FILE  - path to a file containing the bearer token (preferred,
//!                    supplied via `podman secret` or k8s Secret volume)
//!   RH_TOKEN       - bearer token (legacy, visible in `podman inspect`)
//!   RH_SECRETS     - "[ns/]name:/path,[ns/]name:/path,..."
//!                    Pass `ns/name` to disambiguate same-name secrets
//!                    across namespaces (the API 409s otherwise).

use std::fs;
use std::process;

use rhorizon_agent::http::encode_component;
use rhorizon_agent::{atomic_write, build_client, env_var, load_token, parse_secrets_spec};

#[derive(serde::Deserialize)]
struct SecretResponse {
    value: String,
}

fn main() {
    let addr = env_var("ADDR").unwrap_or_else(|_| {
        eprintln!("Error: RH_ADDR must be set");
        process::exit(1);
    });

    let token = match load_token() {
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

    let specs = parse_secrets_spec(&secrets_spec);

    if specs.is_empty() {
        eprintln!("Error: RH_SECRETS is empty");
        process::exit(1);
    }

    eprintln!("[rh-fetch] Fetching {} secret(s)...", specs.len());

    let client = build_client().unwrap_or_else(|e| {
        eprintln!("[rh-fetch] FATAL: cannot create HTTP client: {e}");
        process::exit(1);
    });

    let mut errors = 0;

    for spec in &specs {
        let secret_name = spec.name.as_str();
        let dest_path = spec.path.as_str();
        let namespace = spec.namespace.as_deref();

        let url = format!(
            "{addr}/api/v1/vault/secrets/{}",
            encode_component(secret_name)
        );
        let mut req = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.as_bearer()));
        if let Some(ns) = namespace {
            req = req.query(&[("namespace", ns)]);
        }
        let resp = req.send();

        match resp {
            Ok(r) if r.status().is_success() => {
                let secret: SecretResponse = match r.json() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[rh-fetch] ERROR: invalid response for {secret_name}: {e}");
                        errors += 1;
                        continue;
                    }
                };

                if let Some(parent) = std::path::Path::new(dest_path).parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            eprintln!("[rh-fetch] ERROR: cannot create {}: {e}", parent.display());
                            errors += 1;
                            continue;
                        }
                    }
                }

                match atomic_write(dest_path, secret.value.as_bytes()) {
                    Ok(()) => eprintln!("[rh-fetch]   {secret_name} -> {dest_path}"),
                    Err(e) => {
                        eprintln!("[rh-fetch] ERROR: {e}");
                        errors += 1;
                    }
                }
            }
            Ok(r) => {
                eprintln!("[rh-fetch] ERROR: {secret_name} -> {}", r.status());
                errors += 1;
            }
            Err(e) => {
                eprintln!("[rh-fetch] FATAL: cannot connect to {addr}: {e}");
                process::exit(1);
            }
        }
    }

    if errors > 0 {
        eprintln!("[rh-fetch] {errors} error(s)");
        process::exit(1);
    }

    eprintln!("[rh-fetch] {} secret(s) written successfully", specs.len());
}
