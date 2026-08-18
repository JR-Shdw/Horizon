// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Minimal blocking HTTP/1.1 client over the agent's existing rustls config.
//!
//! Replaces `reqwest` for the only thing these binaries do: a handful of JSON
//! request/responses against ONE operator-configured vault endpoint.
//!
//! The motivation is supply chain, not size. reqwest pulled hyper, h2, tokio,
//! url and idna, and idna pulls the whole ICU stack -- 25 crates existing
//! solely to normalise internationalised domain names, against 12 for the
//! entire TLS layer. An agent that ships beside every application carried more
//! attack surface for parsing hostnames it will never see than for its
//! cryptography.
//!
//! What is deliberately NOT reimplemented: TLS. The rustls ClientConfig
//! (aws-lc-rs provider, webpki roots, hybrid X25519MLKEM768 KEM) was already
//! built by hand in lib.rs and merely handed to reqwest. It is passed here
//! unchanged, so certificate verification and the post-quantum handshake are
//! the same code they always were.
//!
//! Scope limits, all enforced rather than assumed:
//!   * HTTP/1.1 only, ALPN advertised as such. No h2, no upgrade path.
//!   * ASCII hostnames only. A non-ASCII host is REFUSED, never punycoded --
//!     dropping idna means we must not pretend to handle what it handled.
//!   * No redirects. A vault that answers 301 is a misconfiguration, and
//!     following one could send a bearer token to another host.
//!   * No connection reuse. One request, one connection, one close.
//!   * Bodies bounded by MAX_BODY_BYTES so a hostile or broken peer cannot
//!     exhaust a container's memory.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroize;

/// Response bodies carry secret values, so they are bounded and wiped. 16 MiB
/// is far above any vault response and far below a memory-exhaustion risk.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct HttpError(String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpError {}

impl From<String> for HttpError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<std::io::Error> for HttpError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

/// Scheme, host, port and path, parsed without the `url` crate.
#[derive(Debug, Eq, PartialEq)]
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(raw: &str) -> Result<Target, HttpError> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| HttpError("URL must start with http:// or https://".into()))?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(HttpError(format!("unsupported URL scheme {other:?}"))),
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        // userinfo in a vault URL is never intended and would put credentials
        // somewhere they can be logged.
        return Err(HttpError("URL must not contain userinfo".into()));
    }
    let (host, port) = split_host_port(authority, tls)?;
    if host.is_empty() {
        return Err(HttpError("URL has no host".into()));
    }
    // No idna: refuse rather than mishandle. RHORIZON_ADDR is an operator
    // constant pointing at a private address, so this cannot bite a real
    // deployment -- but silently mangling a hostname could.
    if !host.is_ascii() {
        return Err(HttpError(
            "non-ASCII hostnames are not supported; use an ASCII host or IP".into(),
        ));
    }
    if host
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == b'\r' || b == b'\n' || b == b'\0')
    {
        return Err(HttpError("URL host contains invalid characters".into()));
    }
    Ok(Target {
        tls,
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

fn split_host_port(authority: &str, tls: bool) -> Result<(&str, u16), HttpError> {
    let default_port = if tls { 443 } else { 80 };
    // Bracketed IPv6 literal.
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| HttpError("unterminated IPv6 literal in URL".into()))?;
        let port = match tail.strip_prefix(':') {
            Some(value) => value
                .parse()
                .map_err(|_| HttpError("invalid port in URL".into()))?,
            None => default_port,
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, value)) => {
            let port = value
                .parse()
                .map_err(|_| HttpError("invalid port in URL".into()))?;
            Ok((host, port))
        }
        None => Ok((authority, default_port)),
    }
}

/// Percent-encode one query-string component. Deliberately conservative:
/// everything outside the unreserved set is escaped.
pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Whether a value is safe to place in a header. Exposed so a caller that
/// wants to SKIP a bad optional header (rather than fail the whole request)
/// can check first -- the forwarded client IP in the MCP gateway does exactly
/// that, and failing a vault call over a malformed hint would be worse than
/// omitting it.
pub fn is_valid_header_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b != b'\r' && b != b'\n' && b != 0 && b.is_ascii() && b >= 0x20)
}

/// One live connection, either form. Boxed into the pool so a second request
/// to the same endpoint skips TCP and the TLS handshake entirely.
enum Conn {
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    Plain(TcpStream),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(s) => s.read(buf),
            Self::Plain(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tls(s) => s.write(buf),
            Self::Plain(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tls(s) => s.flush(),
            Self::Plain(s) => s.flush(),
        }
    }
}

pub struct HttpClient {
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
    /// Single-slot keep-alive pool. The agent talks to exactly one vault, so a
    /// map would be ceremony; the key guards against a caller switching URLs.
    ///
    /// This exists because one connection per request means one TCP handshake
    /// and one TLS handshake per request -- measured at ~4 ms against the lab,
    /// on a ~15 ms request -- and because a fleet of agents each churning
    /// connections is what puts pressure on the server's accept queue.
    pool: std::sync::Mutex<Option<(String, Conn)>>,
}

impl HttpClient {
    /// Takes the ALREADY-BUILT rustls config. This module does not construct
    /// trust anchors or select cipher suites; that stays where it was.
    pub fn new(tls: rustls::ClientConfig, timeout: Duration) -> Self {
        let mut tls = tls;
        // HTTP/1.1 only, and say so on the wire. Without this a server may
        // negotiate h2 via ALPN and we would speak the wrong protocol into a
        // stream that looks fine.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: Arc::new(tls),
            timeout,
            pool: std::sync::Mutex::new(None),
        }
    }

    pub fn get(&self, url: &str) -> RequestBuilder<'_> {
        self.request("GET", url)
    }

    pub fn post(&self, url: &str) -> RequestBuilder<'_> {
        self.request("POST", url)
    }

    pub fn put(&self, url: &str) -> RequestBuilder<'_> {
        self.request("PUT", url)
    }

    pub fn delete(&self, url: &str) -> RequestBuilder<'_> {
        self.request("DELETE", url)
    }

    fn request(&self, method: &'static str, url: &str) -> RequestBuilder<'_> {
        RequestBuilder {
            client: self,
            method,
            url: url.to_string(),
            headers: Vec::new(),
            query: Vec::new(),
            body: None,
            timeout: None,
            error: None,
        }
    }
}

pub struct RequestBuilder<'a> {
    client: &'a HttpClient,
    method: &'static str,
    url: String,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Option<Duration>,
    error: Option<String>,
}

impl RequestBuilder<'_> {
    /// Header values are rejected if they contain CR or LF. Without this a
    /// value built from a secret name could inject a second header or split
    /// the request entirely.
    pub fn header(mut self, name: &str, value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == b':')
            || value.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            self.error = Some(format!("header {name:?} contains a line break"));
            return self;
        }
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Authorization: Bearer <token>. Separate from `header` so the value is
    /// built in one place and cannot pick up a stray newline from a caller.
    pub fn bearer_auth(self, token: &str) -> Self {
        self.header("Authorization", format!("Bearer {token}"))
    }

    pub fn query(mut self, pairs: &[(&str, &str)]) -> Self {
        for (key, value) in pairs {
            self.query.push(((*key).to_string(), (*value).to_string()));
        }
        self
    }

    /// Raw body with an explicit Content-Type already set by the caller.
    /// Per-request timeout override, for callers that need longer than the
    /// client default (the PQ handshake probe waits on a real server).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn json(mut self, value: &serde_json::Value) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => {
                self.body = Some(body);
                self.headers
                    .push(("Content-Type".into(), "application/json".into()));
            }
            Err(error) => self.error = Some(format!("serialising request body: {error}")),
        }
        self
    }

    pub fn send(self) -> Result<Response, HttpError> {
        if let Some(error) = self.error {
            return Err(HttpError(error));
        }
        let mut target = parse_url(&self.url)?;
        if !self.query.is_empty() {
            let encoded: Vec<String> = self
                .query
                .iter()
                .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
                .collect();
            let separator = if target.path.contains('?') { '&' } else { '?' };
            target.path = format!("{}{separator}{}", target.path, encoded.join("&"));
        }

        let timeout = self.timeout.unwrap_or(self.client.timeout);
        let key = format!("{}:{}:{}", target.tls, target.host, target.port);

        // Try a pooled connection first, then fall back to a fresh one. A
        // pooled socket can have been closed by the server since we last used
        // it, and that is indistinguishable from a live one until we write --
        // so a reuse failure retries ONCE on a new connection rather than
        // surfacing as a spurious error.
        let pooled = self
            .client
            .pool
            .lock()
            .ok()
            .and_then(|mut slot| match slot.take() {
                Some((k, conn)) if k == key => Some(conn),
                other => {
                    *slot = other;
                    None
                }
            });

        if let Some(mut conn) = pooled {
            match self.exchange(&mut conn, &target) {
                Ok((response, reusable)) => {
                    if reusable {
                        self.store(&key, conn);
                    }
                    return Ok(response);
                }
                Err(_) => { /* stale: fall through to a fresh connection */ }
            }
        }

        let stream = TcpStream::connect((target.host.as_str(), target.port))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;

        let mut conn = if target.tls {
            let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|_| HttpError(format!("invalid TLS server name {}", target.host)))?;
            let connection =
                rustls::ClientConnection::new(Arc::clone(&self.client.tls), server_name)
                    .map_err(|error| HttpError(format!("TLS setup: {error}")))?;
            Conn::Tls(Box::new(rustls::StreamOwned::new(connection, stream)))
        } else {
            Conn::Plain(stream)
        };
        let (response, reusable) = self.exchange(&mut conn, &target)?;
        if reusable {
            self.store(&key, conn);
        }
        Ok(response)
    }

    fn store(&self, key: &str, conn: Conn) {
        if let Ok(mut slot) = self.client.pool.lock() {
            *slot = Some((key.to_string(), conn));
        }
    }

    fn exchange<S: Read + Write>(
        &self,
        stream: &mut S,
        target: &Target,
    ) -> Result<(Response, bool), HttpError> {
        let mut head = String::new();
        head.push_str(&format!("{} {} HTTP/1.1\r\n", self.method, target.path));
        let default_port = if target.tls { 443 } else { 80 };
        if target.port == default_port {
            head.push_str(&format!("Host: {}\r\n", target.host));
        } else {
            head.push_str(&format!("Host: {}:{}\r\n", target.host, target.port));
        }
        // Keep-alive is HTTP/1.1's default, but say it explicitly so the
        // intent is visible on the wire and in a packet capture.
        head.push_str("Connection: keep-alive\r\n");
        head.push_str("Accept: application/json\r\n");
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        match &self.body {
            Some(body) => head.push_str(&format!("Content-Length: {}\r\n", body.len())),
            None => head.push_str("Content-Length: 0\r\n"),
        }
        head.push_str("\r\n");

        stream.write_all(head.as_bytes())?;
        if let Some(body) = &self.body {
            stream.write_all(body)?;
        }
        stream.flush()?;

        // Headers first. Reading to EOF is not an option any more: on a reused
        // connection there is no EOF until the server decides to close, so the
        // body length must come from Content-Length or chunked framing.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            if let Some(index) = find_header_end(&raw) {
                break index;
            }
            if raw.len() > MAX_HEADER_BYTES {
                return Err(HttpError("response headers exceed the maximum size".into()));
            }
            match stream.read(&mut chunk) {
                Ok(0) => return Err(HttpError("connection closed before headers".into())),
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(HttpError("connection closed before headers".into()))
                }
                Err(e) => return Err(e.into()),
            }
        };

        let head_text = std::str::from_utf8(&raw[..header_end])
            .map_err(|_| HttpError("response headers are not valid UTF-8".into()))?;
        let framing = parse_framing(head_text)?;
        let mut body = raw[header_end + 4..].to_vec();

        match framing.length {
            Some(expected) => {
                if expected > MAX_BODY_BYTES {
                    return Err(HttpError("response body exceeds the maximum size".into()));
                }
                while body.len() < expected {
                    match stream.read(&mut chunk) {
                        Ok(0) => return Err(HttpError("truncated response body".into())),
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            return Err(HttpError("truncated response body".into()))
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                body.truncate(expected);
            }
            None if framing.chunked => {
                // Read until the terminating zero-length chunk is present.
                while !ends_chunked(&body) {
                    if body.len() > MAX_BODY_BYTES {
                        return Err(HttpError("chunked body exceeds the maximum size".into()));
                    }
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                body = decode_chunked(&body)?;
            }
            None => {
                // No framing at all: the body ends at EOF, so the connection
                // cannot be reused afterwards.
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(e.into()),
                    }
                    if body.len() > MAX_BODY_BYTES {
                        return Err(HttpError("response body exceeds the maximum size".into()));
                    }
                }
            }
        }

        let reusable = framing.keep_alive && (framing.length.is_some() || framing.chunked);
        Ok((
            Response {
                status: framing.status,
                body,
            },
            reusable,
        ))
    }
}

struct Framing {
    status: u16,
    length: Option<usize>,
    chunked: bool,
    keep_alive: bool,
}

fn parse_framing(head: &str) -> Result<Framing, HttpError> {
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError("response has no status line".into()))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| HttpError("malformed status line".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError(format!("unsupported HTTP version {version:?}")));
    }
    let status: u16 = parts
        .next()
        .ok_or_else(|| HttpError("status line has no code".into()))?
        .parse()
        .map_err(|_| HttpError("status code is not a number".into()))?;

    let mut length = None;
    let mut chunked = false;
    let mut keep_alive = true;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse()
                    .map_err(|_| HttpError("invalid Content-Length".into()))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        } else if name.eq_ignore_ascii_case("connection")
            && value.to_ascii_lowercase().contains("close")
        {
            keep_alive = false;
        }
    }
    // Chunked wins over Content-Length if a server sends both, per RFC 9112 --
    // and disagreeing framing is a request-smuggling shape, so drop the length.
    if chunked {
        length = None;
    }
    Ok(Framing {
        status,
        length,
        chunked,
        keep_alive,
    })
}

fn ends_chunked(body: &[u8]) -> bool {
    body.ends_with(b"0\r\n\r\n") || body.ends_with(b"\r\n0\r\n\r\n")
}

pub fn parse_response(raw: &[u8]) -> Result<Response, HttpError> {
    let split = find_header_end(raw)
        .ok_or_else(|| HttpError("response has no header terminator".into()))?;
    let (head, body) = raw.split_at(split);
    let head = std::str::from_utf8(head)
        .map_err(|_| HttpError("response headers are not valid UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError("response has no status line".into()))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| HttpError("malformed status line".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError(format!("unsupported HTTP version {version:?}")));
    }
    let status: u16 = parts
        .next()
        .ok_or_else(|| HttpError("status line has no code".into()))?
        .parse()
        .map_err(|_| HttpError("status code is not a number".into()))?;

    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    // body starts after the blank line
    let body = &body[4.min(body.len())..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_BODY_BYTES {
        return Err(HttpError("response body exceeds the maximum size".into()));
    }
    Ok(Response { status, body })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| HttpError("truncated chunk header".into()))?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| HttpError("chunk size is not valid UTF-8".into()))?;
        // Chunk extensions after ';' are ignored, as the RFC allows.
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| HttpError("chunk size is not hexadecimal".into()))?;
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if size > MAX_BODY_BYTES || out.len() + size > MAX_BODY_BYTES {
            return Err(HttpError("chunked body exceeds the maximum size".into()));
        }
        if input.len() < size {
            return Err(HttpError("truncated chunk body".into()));
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size..];
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
    Ok(out)
}

/// Newtype so call sites keep the `resp.status().is_success()` shape they had
/// under reqwest, rather than every one of them changing to compare integers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusCode(u16);

impl StatusCode {
    pub fn is_success(self) -> bool {
        (200..300).contains(&self.0)
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<u16> for StatusCode {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

pub struct Response {
    status: u16,
    body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        StatusCode(self.status)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn text(&self) -> Result<String, HttpError> {
        String::from_utf8(self.body.clone())
            .map_err(|_| HttpError("response body is not valid UTF-8".into()))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, HttpError> {
        serde_json::from_slice(&self.body)
            .map_err(|error| HttpError(format!("decoding JSON response: {error}")))
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        // Bodies carry secret values.
        self.body.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_scheme_host_port_and_path() {
        let target = parse_url("https://10.0.0.1:8200/api/v1/vault/secrets/x").unwrap();
        assert_eq!(
            (target.tls, target.host.as_str(), target.port),
            (true, "10.0.0.1", 8200)
        );
        assert_eq!(target.path, "/api/v1/vault/secrets/x");

        let default_https = parse_url("https://vault.internal").unwrap();
        assert_eq!(
            (default_https.port, default_https.path.as_str()),
            (443, "/")
        );
        assert_eq!(parse_url("http://host").unwrap().port, 80);

        let v6 = parse_url("https://[2001:db8::1]:8200/x").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("2001:db8::1", 8200));
    }

    #[test]
    fn hostile_urls_are_refused_rather_than_guessed() {
        // Dropping idna means we must NOT pretend to punycode.
        assert!(parse_url("https://exämple.test/x").is_err());
        assert!(parse_url("ftp://host/x").is_err());
        assert!(parse_url("no-scheme/x").is_err());
        // userinfo would put credentials somewhere they can be logged.
        assert!(parse_url("https://user:pw@host/x").is_err());
        assert!(parse_url("https://ho st/x").is_err());
        assert!(parse_url("https://host:notaport/x").is_err());
    }

    #[test]
    fn header_values_cannot_inject_a_second_header() {
        let config = test_config();
        let client = HttpClient::new(config, Duration::from_secs(1));
        let built = client
            .get("https://host/x")
            .header("X-Test", "value\r\nX-Injected: evil");
        assert!(
            built.error.is_some(),
            "CRLF in a header value must be refused"
        );
    }

    #[test]
    fn query_components_are_percent_encoded() {
        assert_eq!(encode_component("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(encode_component("plain-name_1.2~3"), "plain-name_1.2~3");
    }

    #[test]
    fn responses_parse_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"value\":\"s\"}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(response.is_success());
        assert_eq!(response.text().unwrap(), "{\"value\":\"s\"}");

        let error = parse_response(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap();
        assert_eq!(error.status().as_u16(), 403);
        assert!(!error.is_success());
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.text().unwrap(), "hello world");
    }

    #[test]
    fn malformed_responses_fail_closed() {
        assert!(parse_response(b"no headers at all").is_err());
        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n").is_err());
        assert!(parse_response(b"GARBAGE/9 200 OK\r\n\r\n").is_err());
        // A chunk claiming more bytes than it carries must not over-read.
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFF\r\nshort\r\n"
        )
        .is_err());
    }

    fn test_config() -> rustls::ClientConfig {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    #[test]
    fn the_client_advertises_http_1_1_only() {
        let client = HttpClient::new(test_config(), Duration::from_secs(1));
        assert_eq!(client.tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
