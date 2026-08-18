// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// rh-mcp-gateway: loopback unix-socket sidecar for the OPTIONAL MCP hub. It is
// the ONLY leg that speaks HTTP/2 + PQ TLS 1.3 (X25519MLKEM768) to the vault,
// reusing the agent's build_client() + SecureToken. The pure-stdlib Python hub
// speaks a tiny line-JSON protocol over the socket, carrying the PER-AGENT bearer
// on each request (so the vault audit attributes work to the real agent token).
// The bearer lives in a mlock'd SecureToken only for the header's lifetime.
//
// Protocol (one JSON object per line in, one per line out):
//   -> {"bearer":"rh_...","method":"GET","path":"/api/v1/vault/tokens/whoami"}
//   <- {"status":200,"body":{...}}          or   {"error":"..."}
//   POST with a JSON body: add "body": {...}.
//   Optional "client_ip": forwarded to the vault as X-Forwarded-For, so a
//   per-token allowed_ips ACL can bind to the real MCP agent's IP instead of
//   this sidecar's own connecting address. The vault only trusts this header
//   from peers listed in its own xff_trusted_ips/proxy_trusted_ips config
//   (api/app/client_ip.py) -- unconfigured, it is ignored and the vault sees
//   this sidecar's real IP exactly as before, so forwarding an unvalidated
//   value here cannot itself grant trust the vault operator hasn't opted into.
//
// Security: the socket is created 0700 inside a 0700 runtime dir, so only the
// same uid (the hub process) can connect. It holds no token itself.
//
// Env:
//   RH_VAULT_URL          vault base URL (default https://127.0.0.1:8443)
//   RH_VAULT_CAFILE       PEM of the vault's private CA / self-signed cert (rhorizon
//                         vaults are private-CA; public roots alone reject them)
//   RH_MCP_GATEWAY_SOCK   socket path (default $XDG_RUNTIME_DIR/rhorizon/mcp-gateway.sock)

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;

use rhorizon_agent::SecureToken;
use serde_json::{json, Value};

fn vault_url() -> String {
    std::env::var("RH_VAULT_URL").unwrap_or_else(|_| "https://127.0.0.1:8443".into())
}

/// Minimal standard-alphabet base64 decoder (skips whitespace/padding). Avoids a
/// new crate for the tiny amount of PEM decoding the CA loader needs.
fn b64_decode(s: &str) -> Vec<u8> {
    let mut rev = [255u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        rev[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        let v = rev[c as usize];
        if v == 255 {
            continue; // newline / '=' padding / stray char
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// Extract each PEM CERTIFICATE block from `pem` as DER bytes.
fn parse_pem_certs(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        if let Some(end) = after.find("-----END CERTIFICATE-----") {
            out.push(b64_decode(&after[..end]));
            rest = &after[end + "-----END CERTIFICATE-----".len()..];
        } else {
            break;
        }
    }
    out
}

/// Blocking HTTP/1.1 client with the agent's PQ-TLS 1.3 config (aws-lc-rs ->
/// X25519MLKEM768) plus an OPTIONAL private-CA anchor (RH_VAULT_CAFILE) on top of
/// the Mozilla webpki roots -- rhorizon vaults use a private CA / self-signed cert,
/// which public roots would reject.
fn build_client_with_ca(
    cafile: Option<&str>,
) -> Result<rhorizon_agent::http::HttpClient, Box<dyn std::error::Error>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = cafile {
        let pem = std::fs::read_to_string(path)?;
        let mut added = 0;
        for der in parse_pem_certs(&pem) {
            roots.add(rustls::pki_types::CertificateDer::from(der))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!("no certificates found in RH_VAULT_CAFILE {path}").into());
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(rhorizon_agent::http::HttpClient::new(
        tls,
        std::time::Duration::from_secs(15),
    ))
}

fn sock_path() -> PathBuf {
    if let Ok(p) = std::env::var("RH_MCP_GATEWAY_SOCK") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    let dir = PathBuf::from(base).join("rhorizon");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    dir.join("mcp-gateway.sock")
}

fn handle_request(client: &rhorizon_agent::http::HttpClient, base: &str, req: &Value) -> Value {
    let bearer = match req.get("bearer").and_then(|v| v.as_str()) {
        Some(b) if !b.is_empty() => b,
        _ => return json!({"error": "missing bearer"}),
    };
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let path = match req.get("path").and_then(|v| v.as_str()) {
        // Only allow absolute vault API paths; never let the hub reach an
        // arbitrary host (the base URL is fixed to the vault).
        Some(p) if p.starts_with('/') => p,
        _ => return json!({"error": "invalid path"}),
    };
    let url = format!("{}{}", base.trim_end_matches('/'), path);

    // Bearer pinned in mlock'd memory for the header's lifetime.
    let tok = match SecureToken::from_bytes(bearer.as_bytes()) {
        Ok(t) => t,
        Err(e) => return json!({"error": format!("token: {e}")}),
    };
    let mut rb = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        other => return json!({"error": format!("method {other} not allowed")}),
    };
    rb = rb.bearer_auth(tok.as_bearer());
    // Best-effort: an invalid/unparseable client_ip (should never happen --
    // the hub sources it from the real socket peer address -- but never
    // trust a value that crossed a process boundary) is silently dropped
    // rather than failing the whole vault call. Worst case the vault falls
    // back to seeing this sidecar's own IP, exactly like before this field
    // existed.
    if let Some(ip) = req.get("client_ip").and_then(|v| v.as_str()) {
        // is_valid_header_value already rejects the empty string.
        if rhorizon_agent::http::is_valid_header_value(ip) {
            rb = rb.header("X-Forwarded-For", ip);
        }
    }
    if let Some(body) = req.get("body") {
        if !body.is_null() {
            rb = rb.json(body);
        }
    }
    match rb.send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            let body: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
            json!({"status": status, "body": body})
        }
        Err(e) => json!({"error": format!("request failed: {e}")}),
    }
}

fn handle_conn(client: Arc<rhorizon_agent::http::HttpClient>, base: String, stream: UnixStream) {
    let reader = match stream.try_clone() {
        Ok(s) => BufReader::new(s),
        Err(_) => return,
    };
    let mut writer = stream;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle_request(&client, &base, &req),
            Err(e) => json!({"error": format!("bad json: {e}")}),
        };
        let mut out = resp.to_string();
        out.push('\n');
        if writer.write_all(out.as_bytes()).is_err() {
            break;
        }
        let _ = writer.flush();
    }
}

fn main() {
    let base = vault_url();
    let cafile = std::env::var("RH_VAULT_CAFILE").ok();
    let client = Arc::new(build_client_with_ca(cafile.as_deref()).expect("build PQ-TLS client"));
    let path = sock_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind unix socket");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("chmod socket 0700");
    eprintln!("rh-mcp-gateway listening on {} -> {}", path.display(), base);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let c = Arc::clone(&client);
                let b = base.clone();
                std::thread::spawn(move || handle_conn(c, b, s));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}
