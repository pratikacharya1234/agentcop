//! Socket side of the egress proxy.
//!
//! PLAN:
//! 1. Accept a connection, one thread each, with 10 s socket timeouts so a silent client cannot hang us.
//! 2. Read the request head (max 16 KiB) and parse "METHOD TARGET VERSION".
//! 3. CONNECT: host check, then tunnel bytes both ways (no body scan).
//! 4. Absolute http:// URL: host check, read body (Content-Length only, capped), scan URL and body, forward with Connection: close.
//! 5. Anything else: 400. Every decision is one stderr line.

use crate::{EgressPolicy, MAX_BODY_BYTES};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEAD_BYTES: usize = 16 * 1024;

pub fn serve(listener: TcpListener, policy: Arc<EgressPolicy>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let policy = policy.clone();
        thread::spawn(move || {
            if let Err(e) = handle(stream, &policy) {
                eprintln!("cop-proxy: connection error: {e}");
            }
        });
    }
}

fn handle(mut client: TcpStream, policy: &EgressPolicy) -> io::Result<()> {
    client.set_read_timeout(Some(TIMEOUT))?;
    client.set_write_timeout(Some(TIMEOUT))?;
    let Some((head, rest)) = read_head(&mut client)? else {
        return reply(&mut client, 400, "Bad Request");
    };
    let Ok(head) = std::str::from_utf8(&head) else {
        return reply(&mut client, 400, "Bad Request");
    };
    let Some((method, target, version)) = request_line(head) else {
        return reply(&mut client, 400, "Bad Request");
    };
    if method.eq_ignore_ascii_case("CONNECT") {
        return tunnel(client, target, policy);
    }
    match target.strip_prefix("http://") {
        Some(rest_of_url) => forward(client, head, method, rest_of_url, version, rest, policy),
        None => reply(
            &mut client,
            400,
            "Only CONNECT and absolute http:// URLs are allowed",
        ),
    }
}

/// Read until the blank line that ends the head. Returns (head bytes, bytes read after it).
fn read_head(stream: &mut TcpStream) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok(Some((buf, rest)));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Ok(None);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// "METHOD TARGET HTTP/1.x" with exactly three parts.
fn request_line(head: &str) -> Option<(&str, &str, &str)> {
    let mut parts = head.lines().next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    Some((method, target, version))
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn tunnel(mut client: TcpStream, target: &str, policy: &EgressPolicy) -> io::Result<()> {
    let Some((host, port)) = split_host_port(target) else {
        return reply(&mut client, 400, "Bad Request");
    };
    if let Err(why) = policy.check_host(host) {
        log("DENY", target, &why);
        return reply(&mut client, 403, "Forbidden");
    }
    let Ok(mut upstream) = connect_upstream(host, port) else {
        return reply(&mut client, 502, "Bad Gateway");
    };
    log("ALLOW", target, "CONNECT tunnel");
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    let mut back_up = upstream.try_clone()?;
    let mut back_client = client.try_clone()?;
    let back = thread::spawn(move || {
        let _ = io::copy(&mut back_up, &mut back_client);
        let _ = back_client.shutdown(Shutdown::Both);
    });
    let _ = io::copy(&mut client, &mut upstream);
    let _ = upstream.shutdown(Shutdown::Both);
    let _ = back.join();
    Ok(())
}

fn forward(
    mut client: TcpStream,
    head: &str,
    method: &str,
    rest_of_url: &str,
    version: &str,
    rest: Vec<u8>,
    policy: &EgressPolicy,
) -> io::Result<()> {
    let (authority, path) = match rest_of_url.find('/') {
        Some(i) => (&rest_of_url[..i], &rest_of_url[i..]),
        None => (rest_of_url, "/"),
    };
    if authority.contains('@') {
        return reply(&mut client, 400, "Bad Request");
    }
    let Some((host, port)) = split_host_port_or_default(authority, 80) else {
        return reply(&mut client, 400, "Bad Request");
    };
    if let Err(why) = policy.check_host(host) {
        log("DENY", authority, &why);
        return reply(&mut client, 403, "Forbidden");
    }
    if header(head, "transfer-encoding").is_some() {
        log("DENY", authority, "chunked bodies cannot be scanned");
        return refuse_and_drain(&mut client, 411, "Length Required", MAX_BODY_BYTES);
    }
    let len = match header(head, "content-length") {
        None => 0,
        Some(v) => match v.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return reply(&mut client, 400, "Bad Request"),
        },
    };
    if len > MAX_BODY_BYTES {
        log("DENY", authority, "body over size cap");
        return refuse_and_drain(&mut client, 413, "Payload Too Large", len);
    }

    let mut body = rest;
    body.truncate(len);
    (&mut client)
        .take((len - body.len()) as u64)
        .read_to_end(&mut body)?;
    if body.len() != len {
        return reply(&mut client, 400, "Bad Request");
    }
    if let Err(why) = policy
        .check_text(path)
        .and_then(|_| policy.check_text(&String::from_utf8_lossy(&body)))
    {
        log("DENY", authority, &why);
        return reply(&mut client, 403, "Forbidden");
    }

    let Ok(mut upstream) = connect_upstream(host, port) else {
        return reply(&mut client, 502, "Bad Gateway");
    };
    log("ALLOW", authority, method);
    let mut message = origin_head(head, method, path, version).into_bytes();
    message.extend_from_slice(&body);
    upstream.write_all(&message)?;
    io::copy(&mut upstream, &mut client)?;
    Ok(())
}

/// Rewrite the request line to origin form and force one request per connection.
fn origin_head(head: &str, method: &str, path: &str, version: &str) -> String {
    let mut out = format!("{method} {path} {version}\r\n");
    for line in head.split("\r\n").skip(1).take_while(|l| !l.is_empty()) {
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

fn split_host_port(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    Some((host, port.parse().ok()?))
}

fn split_host_port_or_default(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    match authority.rsplit_once(':') {
        Some(_) => split_host_port(authority),
        None if !authority.is_empty() => Some((authority, default_port)),
        None => None,
    }
}

fn connect_upstream(host: &str, port: u16) -> io::Result<TcpStream> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for host"))?;
    let upstream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    upstream.set_read_timeout(Some(TIMEOUT))?;
    upstream.set_write_timeout(Some(TIMEOUT))?;
    Ok(upstream)
}

fn reply(client: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}",
        reason.len()
    )
}

/// Reply, then read the unread body. Closing with unread data makes Linux send a reset,
/// and that reset can destroy the reply before the client reads it.
fn refuse_and_drain(
    client: &mut TcpStream,
    code: u16,
    reason: &str,
    body_len: usize,
) -> io::Result<()> {
    reply(client, code, reason)?;
    client.shutdown(Shutdown::Write)?;
    io::copy(&mut (&mut *client).take(body_len as u64), &mut io::sink())?;
    Ok(())
}

fn log(verdict: &str, target: &str, why: &str) {
    eprintln!("cop-proxy: {verdict} {target} ({why})");
}
