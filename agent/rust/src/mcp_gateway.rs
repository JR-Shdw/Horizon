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
// Second request kind, `"kind":"proxy"` -- the credential proxy behind the hub's
// vault_call_api tool. The sidecar reads the named credential from the vault
// with the agent's own bearer, attaches it, calls the third-party API and
// returns only the upstream reply, so the plaintext never enters the Python hub:
//   -> {"kind":"proxy","bearer":"rh_...","namespace":"mcp","credential":"github-prod",
//       "url":"https://api.github.com/user/repos","method":"GET",
//       "inject":{"type":"header","name":"Authorization","format":"Bearer {value}"}}
//   <- {"status":200,"body":{...},"truncated":false}   or   {"error":"..."}
// Three checks are the sidecar's own, so a bug in the hub's policy layer cannot
// bypass them: the destination must match RH_MCP_EGRESS_ALLOW (empty -> no
// egress at all), the upstream leg is anchored on the public roots (plus
// RH_MCP_EGRESS_CAFILE, never the vault's CA), and a response echoing the
// credential is refused rather than returned.
//
// Security: the socket is created 0700 inside a 0700 runtime dir, so only the
// same uid (the hub process) can connect. It holds no token itself.
//
// Env:
//   RH_VAULT_URL          vault base URL (default https://127.0.0.1:8443)
//   RH_VAULT_CAFILE       PEM of the vault's private CA, or of a self-signed vault
//                         certificate issued with basicConstraints CA:FALSE.
//                         rustls refuses a CA-flagged certificate as a server's
//                         own leaf, where OpenSSL and Python's ssl accept it.
//   RH_MCP_GATEWAY_SOCK   socket path (default $XDG_RUNTIME_DIR/rhorizon/mcp-gateway.sock)
//   RH_MCP_EGRESS_ALLOW   comma-separated https base URLs the credential proxy may
//                         reach (default empty = the proxy refuses every call).
//                         An entry naming the vault itself is refused: this
//                         process holds a vault token, so an agent that could
//                         name the vault as a destination would borrow it.
//   RH_MCP_EGRESS_CAFILE  optional extra CA anchor for the UPSTREAM leg (an internal
//                         API on a private CA). Separate from RH_VAULT_CAFILE on
//                         purpose: the vault's CA must not certify an upstream.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;

use rhorizon_agent::SecureToken;
use serde_json::{json, Value};
use zeroize::Zeroize;

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
    build_client(cafile, "RH_VAULT_CAFILE")
}

/// Client for the credential proxy's upstream leg.
///
/// Anchored on the public roots plus, optionally, RH_MCP_EGRESS_CAFILE -- for an
/// internal API served by a private CA, which is a normal thing to proxy a
/// credential to. Deliberately a SEPARATE variable from RH_VAULT_CAFILE: the
/// vault's CA must not become able to certify the API being called just because
/// the sidecar happens to trust it for the vault.
fn build_public_client(
    cafile: Option<&str>,
) -> Result<rhorizon_agent::http::HttpClient, Box<dyn std::error::Error>> {
    build_client(cafile, "RH_MCP_EGRESS_CAFILE")
}

/// Public roots, plus every certificate in `cafile` when one is given. An
/// unreadable or certificate-free file is an error, not a silent fallback to
/// the public roots alone: the operator asked for an anchor.
fn build_client(
    cafile: Option<&str>,
    var: &str,
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
            return Err(format!("no certificates found in {var} {path}").into());
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

/// host:port of a URL with the scheme's default port filled in, lowercased.
/// None when the shape is anything this has no business reasoning about.
fn authority_of(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "https" => 443u16,
        "http" => 80u16,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None; // userinfo changes which host is really contacted
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (h, tail) = stripped.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => (h, p.parse().ok()?),
            None => (h, default_port),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (authority, default_port),
        }
    };
    Some((host.to_ascii_lowercase(), port))
}

/// Where the credential proxy may send a credential.
struct EgressPolicy {
    /// Normalised bases, each ending in '/' so a prefix match cannot straddle a
    /// hostname boundary ("https://api.example.com" must not permit
    /// "https://api.example.com.evil.test").
    bases: Vec<String>,
    /// The vault's own host:port. A credential must never be proxied back at
    /// the vault: this process holds a token for it, so an agent able to name
    /// the vault as a destination would be asking the sidecar to make
    /// authenticated vault calls on its behalf. Not possessing the token stops
    /// mattering the moment you can borrow the thing that holds it.
    vault: Option<(String, u16)>,
    /// Bases dropped for pointing at the vault, kept so startup can say so.
    /// A silently shorter allow-list is how a refusal goes unnoticed.
    refused: Vec<String>,
}

impl EgressPolicy {
    fn parse(raw: &str, vault_url: &str) -> Self {
        let vault = authority_of(vault_url);
        let (mut bases, mut refused) = (Vec::new(), Vec::new());
        for entry in raw
            .split(',')
            .map(str::trim)
            .filter(|e| e.starts_with("https://") && e.len() > "https://".len())
        {
            if vault.is_some() && authority_of(entry) == vault {
                refused.push(entry.to_string());
            } else {
                bases.push(format!("{}/", entry.trim_end_matches('/')));
            }
        }
        Self {
            bases,
            vault,
            refused,
        }
    }

    fn from_env(vault_url: &str) -> Self {
        Self::parse(
            &std::env::var("RH_MCP_EGRESS_ALLOW").unwrap_or_default(),
            vault_url,
        )
    }

    fn is_empty(&self) -> bool {
        self.bases.is_empty()
    }

    fn permits(&self, url: &str) -> bool {
        if !url.starts_with("https://") || has_traversal(url) {
            return false;
        }
        // Re-checked here and not only at parse time: the allow-list is one way
        // to name the vault, a base that merely prefixes it would be another.
        if self.vault.is_some() && authority_of(url) == self.vault {
            return false;
        }
        let probe = format!("{}/", url.trim_end_matches('/'));
        self.bases.iter().any(|base| probe.starts_with(base))
    }
}

/// Whether a URL's path could climb out of a base that pins a path prefix
/// ("https://gitlab.example/api/v4" would otherwise accept ".../v4/../admin").
/// Percent-encoded dots count: servers disagree on when they normalise.
fn has_traversal(url: &str) -> bool {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches("https://");
    if path.to_ascii_lowercase().contains("%2e") {
        return true;
    }
    path.split('/').any(|seg| seg == "." || seg == "..")
}

/// Render an inject format ("Bearer {value}") against the credential. None when
/// the result is not a legal header value, so CR/LF cannot split the request.
fn render_inject(format: &str, value: &str) -> Option<String> {
    if !format.contains("{value}") {
        return None;
    }
    let rendered = format.replace("{value}", value);
    rhorizon_agent::http::is_valid_header_value(&rendered).then_some(rendered)
}

/// Turn one rustls verdict into an actionable message.
///
/// `CaUsedAsEndEntity` means the server presented a certificate carrying the CA
/// bit. rustls refuses that as an end-entity certificate where OpenSSL and
/// Python's `ssl` accept it, so a certificate that works everywhere else fails
/// only here -- and `openssl req -x509` sets CA:TRUE by default on OpenSSL 3.x,
/// which is the incantation most people reach for. The shipped installers set
/// CA:FALSE, so this only bites a hand-rolled certificate.
fn tls_hint(err: &str) -> &'static str {
    if err.contains("CaUsedAsEndEntity") {
        " -- that certificate carries basicConstraints CA:TRUE, which cannot \
also serve as an end-entity certificate. Re-issue it with CA:FALSE, or serve a \
leaf signed by that CA and anchor the CA instead."
    } else {
        ""
    }
}

/// Whether an upstream reply hands the credential back. APIs echo the token
/// they rejected often enough to matter. Verbatim echoes only: an upstream that
/// re-encodes the value is not one to attach a credential for in the first
/// place.
fn echoes_credential(body: &str, value: &str) -> bool {
    !value.is_empty() && body.contains(value)
}

/// Cut `text` to at most `cap` BYTES, backing up to the nearest char boundary.
fn truncate_utf8(mut text: String, cap: usize) -> String {
    let mut end = cap.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
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

/// The vault leg, the upstream leg and the destination allow-list. Both clients
/// are built once at startup so a proxied call reuses their connection pools.
struct Gateway {
    vault: rhorizon_agent::http::HttpClient,
    upstream: rhorizon_agent::http::HttpClient,
    egress: EgressPolicy,
    base: String,
}

/// Header names a binding may not set: they frame the request or pick the host.
const RESERVED_HEADERS: [&str; 5] = [
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "x-forwarded-for",
];

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

/// Read a credential from the vault, attach it, call the upstream API, return
/// only the upstream's reply. Every check runs BEFORE the vault read, so a
/// denied call never decrypts the credential.
fn handle_proxy(gw: &Gateway, req: &Value) -> Value {
    if gw.egress.is_empty() {
        return json!({"error": "egress not configured (RH_MCP_EGRESS_ALLOW is empty)"});
    }
    let bearer = match req.get("bearer").and_then(|v| v.as_str()) {
        Some(b) if !b.is_empty() => b,
        _ => return json!({"error": "missing bearer"}),
    };
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    if method != "GET" {
        // Read-only ceiling; the hub's per-credential list narrows it further.
        return json!({
            "error": format!("method {method} not allowed by the proxy; it performs GET only")
        });
    }
    let url = match req.get("url").and_then(|v| v.as_str()) {
        Some(u) if gw.egress.permits(u) => u,
        Some(u) => {
            return json!({
                "error": format!(
                    "destination {u} is not in RH_MCP_EGRESS_ALLOW (sidecar allows: {})",
                    gw.egress.bases.join(" ")
                )
            })
        }
        None => return json!({"error": "missing url"}),
    };
    let credential = match req.get("credential").and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c,
        _ => return json!({"error": "missing credential"}),
    };
    let namespace = req
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let inject = req.get("inject").cloned().unwrap_or(Value::Null);
    let header_name = inject
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Authorization");
    if inject
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("header")
        != "header"
    {
        return json!({"error": "only header injection is supported"});
    }
    if !valid_header_name(header_name) {
        return json!({"error": format!("illegal inject header {header_name:?}")});
    }
    let format = inject
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer {value}");
    if !format.contains("{value}") {
        // Checked here rather than at injection time: otherwise a typo in the
        // operator's table spends a vault read -- decrypting and auditing a
        // credential for a call that was never going to happen.
        return json!({"error": "inject format has no {value} placeholder"});
    }
    let client_ip = req.get("client_ip").and_then(|v| v.as_str());

    // The AGENT's bearer: reachable only if its own token could read it.
    let mut value = match read_secret(gw, bearer, namespace, credential, client_ip) {
        Ok(v) => v,
        Err(e) => return json!({"error": e}),
    };
    let injected = match render_inject(format, &value) {
        Some(h) => SecureToken::from_bytes(h.as_bytes()),
        None => {
            value.zeroize();
            return json!({
                "error": "the credential does not render to a legal header value \
            (it likely contains a newline or a control character)"
            });
        }
    };
    let injected = match injected {
        Ok(t) => t,
        Err(e) => {
            value.zeroize();
            return json!({"error": format!("token: {e}")});
        }
    };

    let cap = req
        .get("max_response_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(262_144) as usize;
    let out = match gw
        .upstream
        .get(url)
        .header(header_name, injected.as_bearer())
        .send()
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            if echoes_credential(&text, &value) {
                json!({"error": "upstream echoed the credential; response withheld"})
            } else {
                let truncated = text.len() > cap;
                let text = if truncated {
                    truncate_utf8(text, cap)
                } else {
                    text
                };
                let body: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
                json!({"status": status, "body": body, "truncated": truncated})
            }
        }
        Err(e) => {
            let e = e.to_string();
            json!({"error": format!("upstream request failed: {e}{}", tls_hint(&e))})
        }
    };
    value.zeroize();
    out
}

/// GET one secret's plaintext from the vault with the caller's bearer.
fn read_secret(
    gw: &Gateway,
    bearer: &str,
    namespace: &str,
    name: &str,
    client_ip: Option<&str>,
) -> Result<String, String> {
    let url = format!(
        "{}/api/v1/vault/secrets/{}?namespace={}",
        gw.base.trim_end_matches('/'),
        rhorizon_agent::http::encode_component(name),
        rhorizon_agent::http::encode_component(namespace),
    );
    let tok = SecureToken::from_bytes(bearer.as_bytes()).map_err(|e| format!("token: {e}"))?;
    let mut rb = gw.vault.get(&url).bearer_auth(tok.as_bearer());
    if let Some(ip) = client_ip {
        if rhorizon_agent::http::is_valid_header_value(ip) {
            rb = rb.header("X-Forwarded-For", ip);
        }
    }
    let resp = rb.send().map_err(|e| {
        let e = e.to_string();
        format!("vault request failed: {e}{}", tls_hint(&e))
    })?;
    let status = resp.status().as_u16();
    if status != 200 {
        // Never echo the vault's body; this reply goes back to the model.
        return Err(format!(
            "the vault refused the credential read (HTTP {status}); the agent's own \
token needs secrets:r on that namespace"
        ));
    }
    #[derive(serde::Deserialize)]
    struct SecretResponse {
        value: String,
    }
    let parsed: SecretResponse = resp
        .json()
        .map_err(|_| "vault returned an unexpected secret shape".to_string())?;
    Ok(parsed.value)
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
        Err(e) => {
            let e = e.to_string();
            json!({"error": format!("request failed: {e}{}", tls_hint(&e))})
        }
    }
}

fn dispatch(gw: &Gateway, req: &Value) -> Value {
    match req.get("kind").and_then(|v| v.as_str()).unwrap_or("vault") {
        // No "kind" means the original vault-relay request, unchanged.
        "vault" => handle_request(&gw.vault, &gw.base, req),
        "proxy" => handle_proxy(gw, req),
        other => json!({"error": format!("unknown request kind {other:?}")}),
    }
}

fn handle_conn(gw: Arc<Gateway>, stream: UnixStream) {
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
            Ok(req) => dispatch(&gw, &req),
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
    let egress_cafile = std::env::var("RH_MCP_EGRESS_CAFILE").ok();
    let egress = EgressPolicy::from_env(&base);
    let gw = Arc::new(Gateway {
        vault: build_client_with_ca(cafile.as_deref()).expect("build PQ-TLS client"),
        upstream: build_public_client(egress_cafile.as_deref()).expect("build upstream client"),
        base: base.clone(),
        egress,
    });
    let path = sock_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind unix socket");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("chmod socket 0700");
    eprintln!("rh-mcp-gateway listening on {} -> {}", path.display(), base);
    for bad in &gw.egress.refused {
        eprintln!(
            "rh-mcp-gateway: REFUSED egress entry {bad} -- it is the vault itself; \
proxying a credential back at the vault would let an agent borrow this \
process's token"
        );
    }
    if gw.egress.is_empty() {
        eprintln!("rh-mcp-gateway: credential proxy DISABLED (RH_MCP_EGRESS_ALLOW unset)");
    } else {
        eprintln!(
            "rh-mcp-gateway: credential proxy may reach {}",
            gw.egress.bases.join(" ")
        );
    }
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let g = Arc::clone(&gw);
                std::thread::spawn(move || handle_conn(g, s));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::parse("https://api.github.com, https://gitlab.example/api/v4", "")
    }

    #[test]
    fn empty_allow_list_permits_nothing() {
        let p = EgressPolicy::parse("", "");
        assert!(p.is_empty());
        assert!(!p.permits("https://api.github.com/user"));
    }

    #[test]
    fn plaintext_and_non_https_are_refused() {
        assert!(!policy().permits("http://api.github.com/user"));
        assert!(!policy().permits("file:///etc/passwd"));
    }

    #[test]
    fn a_listed_base_permits_its_own_paths() {
        let p = policy();
        assert!(p.permits("https://api.github.com/user/repos"));
        assert!(p.permits("https://api.github.com/user/repos?per_page=1"));
        assert!(p.permits("https://api.github.com"));
        assert!(p.permits("https://gitlab.example/api/v4/projects"));
    }

    #[test]
    fn prefix_lookalikes_do_not_match() {
        let p = policy();
        // The trailing-slash boundary is what stops each of these.
        assert!(!p.permits("https://api.github.com.evil.test/user"));
        assert!(!p.permits("https://api.github.comevil.test/"));
        assert!(!p.permits("https://api.github.com@evil.test/"));
        assert!(!p.permits("https://gitlab.example/api/v4beta/projects"));
        assert!(!p.permits("https://gitlab.example/admin"));
    }

    #[test]
    fn traversal_cannot_climb_out_of_a_pinned_base_path() {
        let p = policy();
        assert!(!p.permits("https://gitlab.example/api/v4/../../admin"));
        assert!(!p.permits("https://gitlab.example/api/v4/%2e%2e/%2e%2e/admin"));
        assert!(!p.permits("https://gitlab.example/api/v4/%2E%2E/admin"));
        // A dot inside a segment is ordinary and stays allowed.
        assert!(p.permits("https://gitlab.example/api/v4/projects/x.y"));
    }

    #[test]
    fn inject_format_must_carry_the_placeholder() {
        assert_eq!(
            render_inject("Bearer {value}", "abc").as_deref(),
            Some("Bearer abc")
        );
        assert_eq!(
            render_inject("token {value}", "abc").as_deref(),
            Some("token abc")
        );
        assert!(render_inject("Bearer static", "abc").is_none());
    }

    #[test]
    fn a_credential_with_crlf_cannot_split_the_request() {
        assert!(render_inject("Bearer {value}", "abc\r\nX-Evil: 1").is_none());
        assert!(render_inject("Bearer {value}", "abc\n").is_none());
    }

    #[test]
    fn reserved_and_malformed_header_names_are_refused() {
        assert!(valid_header_name("Authorization"));
        assert!(valid_header_name("X-Api-Key"));
        assert!(!valid_header_name(""));
        assert!(!valid_header_name("Host"));
        assert!(!valid_header_name("content-length"));
        assert!(!valid_header_name("X-Evil: injected"));
    }

    #[test]
    fn the_vault_itself_is_never_a_legal_destination() {
        // Not possessing the token stops mattering the moment you can borrow
        // the process that holds it, so naming the vault must be refused --
        // both when the operator lists it and when a call reaches for it.
        let p = EgressPolicy::parse(
            "https://api.github.com, https://127.0.0.1:8443",
            "https://127.0.0.1:8443",
        );
        assert_eq!(p.refused, vec!["https://127.0.0.1:8443"]);
        assert!(!p.permits("https://127.0.0.1:8443/api/v1/vault/secrets/foo"));
        assert!(p.permits("https://api.github.com/user"));
    }

    #[test]
    fn the_vault_is_matched_by_authority_not_by_string() {
        // Same host:port, different scheme and spelling, still the vault.
        assert!(EgressPolicy::parse("https://127.0.0.1:8200", "http://127.0.0.1:8200").is_empty());
        // The default port counts: https://v.lab and https://v.lab:443 are one.
        assert!(EgressPolicy::parse("https://V.Lab:443", "https://v.lab").is_empty());
    }

    #[test]
    fn a_different_port_on_the_vault_host_stays_allowed() {
        // Only the vault's own endpoint is off limits; an unrelated service on
        // the same host is a legitimate destination.
        let p = EgressPolicy::parse("https://127.0.0.1:9000", "https://127.0.0.1:8443");
        assert!(p.permits("https://127.0.0.1:9000/x"));
    }

    #[test]
    fn authority_parsing_refuses_shapes_it_cannot_judge() {
        assert_eq!(authority_of("https://h:8443/x"), Some(("h".into(), 8443)));
        assert_eq!(authority_of("https://h/x"), Some(("h".into(), 443)));
        assert_eq!(authority_of("http://h"), Some(("h".into(), 80)));
        assert_eq!(
            authority_of("https://[::1]:8443/"),
            Some(("::1".into(), 8443))
        );
        assert_eq!(authority_of("https://user@h/"), None); // userinfo
        assert_eq!(authority_of("ftp://h/"), None);
        assert_eq!(authority_of("https://h:notaport/"), None);
    }

    #[test]
    fn a_ca_flagged_server_certificate_is_explained() {
        // rustls says only "CaUsedAsEndEntity", and the same certificate works
        // under OpenSSL and Python, so the bare verdict sends an operator
        // looking in the wrong place.
        let hint = tls_hint("invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))");
        assert!(hint.contains("CA:FALSE"), "{hint}");
        assert_eq!(tls_hint("connection refused"), "");
    }

    #[test]
    fn a_body_echoing_the_credential_is_detected() {
        assert!(echoes_credential(
            r#"{"message":"bad token ghp_secret"}"#,
            "ghp_secret"
        ));
        assert!(!echoes_credential(r#"{"login":"octocat"}"#, "ghp_secret"));
        // An empty credential must not make every body look like an echo.
        assert!(!echoes_credential("anything", ""));
    }
}
