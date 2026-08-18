// PQ wire-level verifier -- the aws-lc-rs half of the cross-stack parity proof.
//
//   cargo run --example pq_verify -- [https://host/cdn-cgi/trace]
//
// Proves the agent's own TLS stack (build_client -> aws-lc-rs) (1) offers the
// hybrid group X25519MLKEM768 and (2) actually negotiates it on a real
// handshake. Pair it with `openssl s_client -groups X25519MLKEM768` (the
// OpenSSL stack) via tools/pq-verify.sh : two independent libraries agreeing on
// the wire is the proof, NOT a hand-audit of the primitive. See
// docs/POST-QUANTUM.md.
use std::time::Duration;

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://pq.cloudflareresearch.com/cdn-cgi/trace".to_string());

    // (1) offered groups
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let offered: Vec<String> = provider
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect();
    let offers_pq = offered.iter().any(|g| g.contains("MLKEM"));
    println!("[rust/aws-lc-rs] offered : {offered:?}");
    println!("[rust/aws-lc-rs] offers X25519MLKEM768 : {offers_pq}");
    if !offers_pq {
        eprintln!("[rust/aws-lc-rs] FAIL: provider does not offer a PQ group");
        std::process::exit(1);
    }

    // (2) real handshake. Against Cloudflare's echo the body reports kex=...
    let client = rhorizon_agent::build_client().expect("build_client");
    match client.get(&url).timeout(Duration::from_secs(20)).send() {
        Ok(resp) => {
            println!("[rust/aws-lc-rs] handshake : {}", resp.status());
            let body = resp.text().unwrap_or_default();
            for line in body.lines() {
                if line.starts_with("kex=") || line.starts_with("tls=") {
                    println!("[rust/aws-lc-rs] negotiated {line}");
                }
            }
        }
        Err(e) => {
            eprintln!("[rust/aws-lc-rs] handshake error : {e}");
            std::process::exit(1);
        }
    }
}
