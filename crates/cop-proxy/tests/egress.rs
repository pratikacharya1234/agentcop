use cop_proxy::{serve, EgressPolicy, MAX_BODY_BYTES};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Obviously fake secrets only. No real keys anywhere in this file.
const FAKE_AWS_KEY: &str = "AKIAFAKEFAKEFAKEFAKE";
const FAKE_KEY_HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----";

fn policy_text(allowed_extra: &str) -> String {
    format!(
        r#"
allow_domains = ["github.com", "127.0.0.1"{allowed_extra}]

[[secret_patterns]]
name = "aws-access-key"
regex = 'AKIA[0-9A-Z]{{16}}'

[[secret_patterns]]
name = "private-key"
regex = '-----BEGIN [A-Z ]*PRIVATE KEY-----'
"#
    )
}

fn policy() -> EgressPolicy {
    EgressPolicy::from_toml(&policy_text("")).expect("test policy must load")
}

/// Fake upstream: counts requests, answers "ok" with 200.
fn start_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, hits)
}

fn start_proxy(policy: EgressPolicy) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || serve(listener, Arc::new(policy)));
    port
}

/// Send raw bytes to the proxy and return everything it answers before closing.
fn talk(proxy: u16, raw: &[u8]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn status(response: &str) -> &str {
    response.split_whitespace().nth(1).unwrap_or("")
}

fn post(upstream: u16, body: &str) -> Vec<u8> {
    format!(
        "POST http://127.0.0.1:{upstream}/upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// ---- policy: host matching and loading ----

#[test]
fn host_match_is_exact_or_subdomain_case_insensitive() {
    let p = policy();
    assert!(p.check_host("github.com").is_ok());
    assert!(p.check_host("API.github.com").is_ok());
    assert!(p.check_host("evilgithub.com").is_err());
    assert!(p.check_host("github.com.evil.io").is_err());
    assert!(p.check_host("").is_err());
}

#[test]
fn empty_allowlist_is_refused_at_load() {
    let r = EgressPolicy::from_toml("allow_domains = []\n");
    assert!(r.is_err());
}

#[test]
fn bad_secret_regex_is_refused_at_load() {
    let text = "allow_domains = [\"github.com\"]\n[[secret_patterns]]\nname = \"x\"\nregex = '('\n";
    assert!(EgressPolicy::from_toml(text).is_err());
}

#[test]
fn shipped_policy_file_loads() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../policy/egress.toml"
    ))
    .unwrap();
    assert!(EgressPolicy::from_toml(&text).is_ok());
}

#[test]
fn secret_text_is_reported_with_pattern_name() {
    let p = policy();
    let err = p.check_text(FAKE_AWS_KEY).unwrap_err();
    assert!(err.contains("aws-access-key"), "reason was: {err}");
    assert!(p.check_text("hello world").is_ok());
}

// ---- server: blocked domains ----

#[test]
fn plain_http_to_blocked_host_is_403() {
    let proxy = start_proxy(policy());
    let r = talk(
        proxy,
        b"GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
    );
    assert_eq!(status(&r), "403", "response: {r}");
}

#[test]
fn connect_to_blocked_host_is_403() {
    let proxy = start_proxy(policy());
    let r = talk(
        proxy,
        b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
    );
    assert_eq!(status(&r), "403", "response: {r}");
}

// ---- server: secret uploads ----

#[test]
fn secret_in_plain_http_body_is_blocked_and_never_sent_upstream() {
    let (up, hits) = start_upstream();
    let proxy = start_proxy(policy());
    let body = format!("key={FAKE_AWS_KEY}");
    let r = talk(proxy, &post(up, &body));
    assert_eq!(status(&r), "403", "response: {r}");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn private_key_header_in_body_is_blocked() {
    let (up, hits) = start_upstream();
    let proxy = start_proxy(policy());
    let r = talk(proxy, &post(up, FAKE_KEY_HEADER));
    assert_eq!(status(&r), "403", "response: {r}");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn clean_plain_http_body_is_forwarded() {
    let (up, hits) = start_upstream();
    let proxy = start_proxy(policy());
    let r = talk(proxy, &post(up, "just some text"));
    assert_eq!(status(&r), "200", "response: {r}");
    assert!(r.ends_with("ok"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[test]
fn secret_in_url_is_blocked() {
    let (up, hits) = start_upstream();
    let proxy = start_proxy(policy());
    let raw = format!(
        "GET http://127.0.0.1:{up}/?k={FAKE_AWS_KEY} HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\n\r\n"
    );
    let r = talk(proxy, raw.as_bytes());
    assert_eq!(status(&r), "403", "response: {r}");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn chunked_body_is_refused_fail_closed() {
    let (up, hits) = start_upstream();
    let proxy = start_proxy(policy());
    let raw = format!(
        "POST http://127.0.0.1:{up}/ HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nAKIA\r\n0\r\n\r\n"
    );
    let r = talk(proxy, raw.as_bytes());
    assert!(
        status(&r) == "400" || status(&r) == "403" || status(&r) == "411",
        "response: {r}"
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn oversized_body_is_413_and_never_sent() {
    let (up, hits) = start_upstream();
    let proxy = start_proxy(policy());
    let big = "a".repeat(MAX_BODY_BYTES + 1);
    let r = talk(proxy, &post(up, &big));
    assert_eq!(
        status(&r),
        "413",
        "response head: {}",
        &r[..r.len().min(80)]
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_request_line_is_400() {
    let proxy = start_proxy(policy());
    let r = talk(proxy, b"BLAH\r\n\r\n");
    assert_eq!(status(&r), "400", "response: {r}");
}

// ---- server: CONNECT tunnel ----

#[test]
fn connect_to_allowed_host_tunnels_bytes() {
    let (up, _hits) = start_upstream();
    let proxy = start_proxy(policy());
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\nHost: 127.0.0.1:{up}\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut head = [0u8; 39];
    s.read_exact(&mut head).unwrap();
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert!(out.ends_with("ok"), "tunnel answer: {out}");
}
