// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! rh-inject, resolve rh:// env var references, then exec.
//!
//! Scans environment for rh:// prefixed values, fetches each secret
//! from the rhorizon API, replaces the value in-memory, then execs
//! the real command as PID 1. No secrets touch disk.
//!
//! Env vars (each also accepts its deprecated RHORIZON_* alias) :
//!   RH_ADDR         - vault API base URL
//!   RH_TOKEN_FILE   - path to bearer token file (preferred)
//!   RH_TOKEN        - bearer token (legacy)

use std::collections::HashMap;
use std::env;
use std::os::unix::process::CommandExt;
use std::process;

use rhorizon_agent::{build_client, env_var, load_token, parse_rh_reference};
use zeroize::Zeroize;

const RH_PREFIX: &str = "rh://";

#[derive(serde::Deserialize)]
struct SecretResponse {
    value: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let sep = args.iter().position(|a| a == "--").unwrap_or_else(|| {
        eprintln!("Usage: rh-inject -- COMMAND [ARGS...]");
        process::exit(1);
    });

    let command = &args[sep + 1..];
    if command.is_empty() {
        eprintln!("Error: no command after --");
        process::exit(1);
    }

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

    let to_fetch: HashMap<String, String> = env::vars()
        .filter(|(_, v)| v.starts_with(RH_PREFIX))
        .collect();

    let mut resolved_env: HashMap<String, String> = env::vars().collect();

    if !to_fetch.is_empty() {
        eprintln!("[rh-inject] Resolving {} secret(s)...", to_fetch.len());

        let client = build_client().unwrap_or_else(|e| {
            eprintln!("[rh-inject] FATAL: cannot create HTTP client: {e}");
            process::exit(1);
        });

        for (var_name, reference) in &to_fetch {
            let parsed = match parse_rh_reference(reference) {
                Some(p) => p,
                None => {
                    eprintln!(
                        "[rh-inject] FATAL: malformed reference for {var_name}: \
                         '{reference}' (expected rh://[ns/]name)"
                    );
                    process::exit(1);
                }
            };
            let secret_name = parsed.name.as_str();
            let namespace = parsed.namespace.as_deref();

            let url = format!("{addr}/api/v1/vault/secrets/{secret_name}");
            let mut builder = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token.as_bearer()));
            if let Some(ns) = namespace {
                builder = builder.query(&[("namespace", ns)]);
            }
            let resp = builder.send();

            match resp {
                Ok(r) if r.status().is_success() => {
                    let secret: SecretResponse = r.json().unwrap_or_else(|e| {
                        eprintln!("[rh-inject] FATAL: invalid response for {secret_name}: {e}");
                        process::exit(1);
                    });
                    resolved_env.insert(var_name.clone(), secret.value);
                    eprintln!("[rh-inject]   {var_name} <- {secret_name}");
                }
                Ok(r) => {
                    eprintln!(
                        "[rh-inject] FATAL: cannot fetch {var_name} ({secret_name}): {}",
                        r.status()
                    );
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!("[rh-inject] FATAL: cannot connect to {addr}: {e}");
                    process::exit(1);
                }
            }
        }

        eprintln!("[rh-inject] {} secret(s) resolved", to_fetch.len());
    }

    // Strip vault credentials from the child env, both the canonical RH_*
    // names and the deprecated RHORIZON_* aliases (load_token already scrubbed
    // the token var from our own environ, but the child map is a fresh
    // env::vars() snapshot, so remove every variant here).
    for var in [
        "RH_TOKEN",
        "RHORIZON_TOKEN",
        "RH_TOKEN_FILE",
        "RHORIZON_TOKEN_FILE",
        "RH_ADDR",
        "RHORIZON_ADDR",
    ] {
        resolved_env.remove(var);
    }

    // Drop our SecureToken now (Zeroize on Drop), we no longer need it.
    drop(token);

    // Exec the real command (replaces this process, env entries are passed
    // to the child kernel-side and the resolved_env map is freed when
    // execve() takes over). We zeroise our local map's plaintext secret
    // values just before exec, defense in depth in case execve fails and
    // we fall through.
    let mut cmd = process::Command::new(&command[0]);
    cmd.args(&command[1..]).envs(&resolved_env);
    let err = cmd.exec();

    // Only reached if exec failed.
    for v in resolved_env.values_mut() {
        v.zeroize();
    }
    eprintln!("[rh-inject] FATAL: exec failed: {err}");
    process::exit(1);
}
