//! A minimal HTTP/1.1 listener for the one thing the request edge needs: a
//! `POST` of a webhook to one configured path, plus a health check that
//! reveals nothing (ADR 0123).
//!
//! # What it is not
//!
//! It is not a general web server and it does not terminate TLS. TLS is the
//! deployer's reverse proxy; this listener binds loopback unless the
//! configuration explicitly allows another address, and the documentation
//! says what enabling the webhook would need. It never assumes the transport
//! is encrypted or that the peer is who it says it is: authenticity is the
//! HMAC signature `custodian_intake::webhook::Intake::handle` verifies.
//!
//! # Limits (all configurable, all with a hard default)
//!
//! * request line, whole head (request line and headers) and header count are
//!   bounded; overlong input is refused as soon as the bound is crossed, not
//!   after it has been read;
//! * the head must arrive within `head_timeout` of the connection being
//!   accepted (a total deadline, not a per-read timeout, so trickling one byte
//!   at a time earns no extra time), the first byte within `first_byte_timeout`,
//!   and the body within `body_timeout` of the head;
//! * `Content-Length` is required for `POST`, must be plain digits, is
//!   checked against the body cap before a single body byte is read, and
//!   duplicate security-relevant headers are refused;
//! * `Transfer-Encoding` of any kind (so chunked bodies), `Expect`, and any
//!   `Content-Encoding` other than `identity` are refused;
//! * every response carries `Connection: close` and the connection is closed
//!   after one request: no keep-alive, and any bytes pipelined after the first
//!   request are never parsed;
//! * at most `max_connections` connections are served at once; the next one
//!   gets `503 busy` and is closed;
//! * only `POST` on the configured path and `GET /healthz` exist; every other
//!   method or path is `405`/`404` with a fixed code;
//! * a response body is `{"code":"<fixed word>"}` and nothing else. No
//!   request header, body, signature, token or path is ever echoed, logged or
//!   counted by value.

use std::io::{Read, Write};
use std::net::{Shutdown as TcpShutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use custodian_contracts::types::Timestamp;
use custodian_intake::webhook::{response, Delivery, Intake};
use custodian_store::Clock;

use crate::log::EventLog;
use crate::reason::DaemonReason;
use crate::shutdown::Shutdown;

/// Path of the health check. Fixed; it is not configurable and it answers the
/// same two words whatever the daemon's state.
pub const HEALTH_PATH: &str = "/healthz";

/// Hard ceilings a configuration may not exceed.
pub const MAX_CONNECTIONS_CEILING: usize = 256;
pub const MAX_HEAD_BYTES_CEILING: usize = 64 * 1024;
pub const MAX_HEADERS_CEILING: usize = 128;
pub const MAX_BODY_BYTES_CEILING: usize = 1024 * 1024;
pub const TIMEOUT_CEILING: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    /// A non-loopback address is refused unless this is set. Loopback is the
    /// default: the deployer's reverse proxy terminates TLS and forwards.
    pub allow_non_loopback: bool,
    /// The one path a webhook may be posted to.
    pub path: String,
    pub max_connections: usize,
    pub max_request_line_bytes: usize,
    /// Request line plus headers, including the final blank line.
    pub max_head_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    pub first_byte_timeout: Duration,
    pub head_timeout: Duration,
    pub body_timeout: Duration,
    pub write_timeout: Duration,
}

impl ListenerConfig {
    /// Loopback, ephemeral-friendly defaults for `path` and `max_body_bytes`.
    pub fn new(bind: SocketAddr, path: &str, max_body_bytes: usize) -> Self {
        Self {
            bind,
            allow_non_loopback: false,
            path: path.to_owned(),
            max_connections: 32,
            max_request_line_bytes: 2048,
            max_head_bytes: 16 * 1024,
            max_headers: 48,
            max_body_bytes,
            first_byte_timeout: Duration::from_secs(5),
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(5),
        }
    }

    /// Reject anything outside the ceilings or an unsafe bind.
    pub fn validate(&self) -> Result<(), DaemonReason> {
        let path_ok = self.path.starts_with('/')
            && self.path.len() <= 128
            && self.path != "/"
            && self.path != HEALTH_PATH
            && self
                .path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
            && !self.path.contains("//")
            && !self.path.contains("..");
        let timeouts_ok = [
            self.first_byte_timeout,
            self.head_timeout,
            self.body_timeout,
            self.write_timeout,
        ]
        .iter()
        .all(|t| !t.is_zero() && *t <= TIMEOUT_CEILING);
        if !path_ok
            || !timeouts_ok
            || self.max_connections == 0
            || self.max_connections > MAX_CONNECTIONS_CEILING
            || self.max_request_line_bytes < 64
            || self.max_head_bytes < self.max_request_line_bytes
            || self.max_head_bytes > MAX_HEAD_BYTES_CEILING
            || self.max_headers == 0
            || self.max_headers > MAX_HEADERS_CEILING
            || self.max_body_bytes == 0
            || self.max_body_bytes > MAX_BODY_BYTES_CEILING
        {
            return Err(DaemonReason::ConfigInvalid);
        }
        if !self.bind.ip().is_loopback() && !self.allow_non_loopback {
            return Err(DaemonReason::BindRefused);
        }
        Ok(())
    }
}

// ---- the request ---------------------------------------------------------------

/// A parsed request head. Header names are lowercase; values are trimmed.
#[derive(Debug)]
pub struct Head {
    pub method: String,
    pub target: String,
    headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    /// Bytes read past the blank line (the start of the body, or pipelined
    /// input that is never parsed).
    leftover: Vec<u8>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request was refused before the handler saw it: a status and a fixed
/// code, or a silent close (the peer sent nothing usable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Closed,
    Status(u16, &'static str),
}

const fn bad(code: &'static str) -> Reject {
    Reject::Status(400, code)
}

/// The slice of a connection the parser needs: bytes, and a way to bound how
/// long the next read may wait. A trait so the parser is tested without
/// sockets.
pub trait Conn: Read {
    fn limit_read(&mut self, remaining: Duration) -> std::io::Result<()>;
}

impl Conn for TcpStream {
    fn limit_read(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
    }
}

/// Header names that may appear at most once, because the handler or the
/// parser acts on them and two values would be ambiguous.
const SINGLE: [&str; 9] = [
    "content-length",
    "content-type",
    "transfer-encoding",
    "content-encoding",
    "expect",
    "host",
    "x-hub-signature-256",
    "x-github-event",
    "x-github-delivery",
];

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Read and parse the request head within the deadlines. Never reads past
/// what the head and the first read happened to contain, and never reads a
/// body.
pub fn read_head<C: Conn>(
    conn: &mut C,
    cfg: &ListenerConfig,
    accepted: Instant,
) -> Result<Head, Reject> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(pos) = find_head_end(&buf) {
            break pos;
        }
        // Bounds are enforced as the bytes arrive, before the next read.
        let line_probe = cfg.max_request_line_bytes + 2;
        if buf.len() >= line_probe && !buf[..line_probe].windows(2).any(|w| w == b"\r\n") {
            return Err(Reject::Status(414, "request_line_too_long"));
        }
        if buf.len() >= cfg.max_head_bytes {
            return Err(Reject::Status(431, "header_too_large"));
        }
        let elapsed = accepted.elapsed();
        // An idle connection that never says anything is dropped silently.
        if buf.is_empty() && elapsed >= cfg.first_byte_timeout {
            return Err(Reject::Closed);
        }
        let Some(mut remaining) = cfg.head_timeout.checked_sub(elapsed) else {
            return Err(Reject::Status(408, "request_timeout"));
        };
        if buf.is_empty() {
            remaining = remaining.min(cfg.first_byte_timeout - elapsed);
        }
        if conn.limit_read(remaining).is_err() {
            return Err(Reject::Closed);
        }
        let mut chunk = [0u8; 1024];
        match conn.read(&mut chunk) {
            Ok(0) => return Err(Reject::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if is_timeout(&e) => {
                return Err(if buf.is_empty() {
                    Reject::Closed
                } else {
                    Reject::Status(408, "request_timeout")
                });
            }
            Err(_) => return Err(Reject::Closed),
        }
    };
    if head_end + 4 > cfg.max_head_bytes {
        return Err(Reject::Status(431, "header_too_large"));
    }
    let leftover = buf[head_end + 4..].to_vec();
    let head = &buf[..head_end];
    // Structure: CRLF line endings only, printable ASCII (and tab) only.
    for (i, &b) in head.iter().enumerate() {
        let ok = match b {
            b'\r' => head.get(i + 1) == Some(&b'\n'),
            b'\n' => i > 0 && head[i - 1] == b'\r',
            b'\t' => true,
            0x20..=0x7e => true,
            _ => false,
        };
        if !ok {
            return Err(bad("bad_request"));
        }
    }
    let text = std::str::from_utf8(head).map_err(|_| bad("bad_request"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(bad("bad_request"))?;
    if request_line.len() > cfg.max_request_line_bytes {
        return Err(Reject::Status(414, "request_line_too_long"));
    }
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => return Err(bad("bad_request")),
    };
    if method.is_empty()
        || method.len() > 16
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !target.starts_with('/')
        || target.len() > cfg.max_request_line_bytes
    {
        return Err(bad("bad_request"));
    }
    match version {
        "HTTP/1.1" => {}
        v if v.starts_with("HTTP/") => return Err(Reject::Status(505, "version_unsupported")),
        _ => return Err(bad("bad_request")),
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if headers.len() >= cfg.max_headers {
            return Err(Reject::Status(431, "header_too_large"));
        }
        // Obsolete line folding and whitespace before the colon are refused.
        if line.starts_with([' ', '\t']) {
            return Err(bad("bad_request"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("bad_request"));
        };
        if name.is_empty() || !name.bytes().all(token_byte) {
            return Err(bad("bad_request"));
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    for s in SINGLE {
        if headers.iter().filter(|(n, _)| n == s).count() > 1 {
            return Err(bad("header_duplicate"));
        }
    }
    let get = |n: &str| {
        headers
            .iter()
            .find(|(h, _)| h == n)
            .map(|(_, v)| v.as_str())
    };
    if get("transfer-encoding").is_some() {
        return Err(bad("transfer_encoding_unsupported"));
    }
    if get("expect").is_some() {
        return Err(Reject::Status(417, "expectation_unsupported"));
    }
    if get("content-encoding").is_some_and(|v| !v.eq_ignore_ascii_case("identity")) {
        return Err(Reject::Status(415, "content_encoding_unsupported"));
    }
    let content_length = match get("content-length") {
        None => None,
        Some(v) => {
            if v.is_empty() || v.len() > 10 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("content_length_invalid"));
            }
            Some(
                v.parse::<usize>()
                    .map_err(|_| bad("content_length_invalid"))?,
            )
        }
    };
    Ok(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        content_length,
        leftover,
    })
}

/// Read exactly `len` body bytes within `body_timeout` of `head_done`. Bytes
/// past `len` that arrived with the head are dropped, never parsed.
pub fn read_body<C: Conn>(
    conn: &mut C,
    head: &mut Head,
    len: usize,
    body_timeout: Duration,
    head_done: Instant,
) -> Result<Vec<u8>, Reject> {
    let mut body = std::mem::take(&mut head.leftover);
    body.truncate(len);
    while body.len() < len {
        let Some(remaining) = body_timeout.checked_sub(head_done.elapsed()) else {
            return Err(Reject::Status(408, "request_timeout"));
        };
        if conn.limit_read(remaining).is_err() {
            return Err(Reject::Closed);
        }
        let mut chunk = [0u8; 4096];
        let want = (len - body.len()).min(chunk.len());
        match conn.read(&mut chunk[..want]) {
            Ok(0) => return Err(Reject::Closed),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if is_timeout(&e) => return Err(Reject::Status(408, "request_timeout")),
            Err(_) => return Err(Reject::Closed),
        }
    }
    Ok(body)
}

// ---- the handler --------------------------------------------------------------

/// What the handler receives: the raw body and the four headers the intake
/// uses, still untrusted.
pub struct WebhookRequest<'a> {
    pub signature: Option<&'a str>,
    pub event: Option<&'a str>,
    pub delivery_id: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

/// Turns a webhook request into a status and one fixed code.
pub trait WebhookHandler: Send + Sync {
    fn handle(&self, request: &WebhookRequest<'_>) -> (u16, &'static str);
}

/// The real handler: `Intake::handle`, mapped with `webhook::response`. The
/// signature is verified there; this adapter adds nothing and decides nothing.
pub struct IntakeHandler {
    intake: Intake,
    clock: Arc<dyn Clock>,
}

impl IntakeHandler {
    pub fn new(intake: Intake, clock: Arc<dyn Clock>) -> Self {
        Self { intake, clock }
    }
}

impl WebhookHandler for IntakeHandler {
    fn handle(&self, r: &WebhookRequest<'_>) -> (u16, &'static str) {
        let Ok(now) = Timestamp::new(self.clock.now()) else {
            return (503, "store_unavailable");
        };
        let result = self.intake.handle(
            &Delivery {
                signature: r.signature,
                event: r.event,
                delivery_id: r.delivery_id,
                content_type: r.content_type,
                body: r.body,
            },
            now,
        );
        response(&result)
    }
}

// ---- the server -----------------------------------------------------------------

/// Counters. Counts only; never a value from a request.
#[derive(Debug, Default)]
pub struct ListenerStats {
    pub accepted: AtomicU64,
    pub served: AtomicU64,
    pub refused_busy: AtomicU64,
    pub active: AtomicUsize,
}

pub struct HttpServer {
    local: SocketAddr,
    stats: Arc<ListenerStats>,
    stop: Shutdown,
    accept: Option<JoinHandle<()>>,
    drain: Duration,
}

struct ActiveGuard(Arc<ListenerStats>);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

fn respond(stream: &mut TcpStream, cfg: &ListenerConfig, status: u16, code: &str, allow: bool) {
    let body = format!("{{\"code\":\"{code}\"}}");
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n{}\r\n",
        reason_phrase(status),
        body.len(),
        if allow { "Allow: POST\r\n" } else { "" },
    );
    let _ = stream.set_write_timeout(Some(cfg.write_timeout));
    if stream.write_all(head.as_bytes()).is_ok() {
        let _ = stream.write_all(body.as_bytes());
    }
    let _ = stream.flush();
}

/// Close politely: stop sending, then discard what the peer still sends for a
/// moment, so a response to an early refusal is not destroyed by a reset. The
/// drain is bounded in bytes and in time.
fn close(mut stream: TcpStream) {
    let _ = stream.shutdown(TcpShutdown::Write);
    let end = Instant::now() + Duration::from_millis(300);
    let mut left = 64 * 1024usize;
    let mut chunk = [0u8; 4096];
    while left > 0 {
        let Some(t) = end.checked_duration_since(Instant::now()) else {
            break;
        };
        if stream
            .set_read_timeout(Some(t.max(Duration::from_millis(1))))
            .is_err()
        {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
}

fn serve(
    mut stream: TcpStream,
    cfg: &ListenerConfig,
    handler: &dyn WebhookHandler,
    log: &dyn EventLog,
    accepted: Instant,
) -> &'static str {
    let _ = stream.set_nodelay(true);
    let mut head = match read_head(&mut stream, cfg, accepted) {
        Ok(h) => h,
        Err(Reject::Closed) => return "closed",
        Err(Reject::Status(s, code)) => {
            respond(&mut stream, cfg, s, code, false);
            close(stream);
            log.event("listener", code);
            return code;
        }
    };
    let head_done = Instant::now();
    let (status, code, allow) = if head.target == HEALTH_PATH {
        match (head.method.as_str(), head.content_length) {
            ("GET", None | Some(0)) => (200, "ok", false),
            ("GET", Some(_)) => (400, "bad_request", false),
            _ => (405, "method_not_allowed", false),
        }
    } else if head.target == cfg.path {
        if head.method != "POST" {
            (405, "method_not_allowed", true)
        } else {
            match head.content_length {
                None => (411, "length_required", false),
                Some(n) if n > cfg.max_body_bytes => (413, "body_too_large", false),
                Some(n) => {
                    match read_body(&mut stream, &mut head, n, cfg.body_timeout, head_done) {
                        Ok(body) => {
                            let (s, c) = handler.handle(&WebhookRequest {
                                signature: head.header("x-hub-signature-256"),
                                event: head.header("x-github-event"),
                                delivery_id: head.header("x-github-delivery"),
                                content_type: head.header("content-type"),
                                body: &body,
                            });
                            (s, c, false)
                        }
                        Err(Reject::Closed) => return "closed",
                        Err(Reject::Status(s, c)) => (s, c, false),
                    }
                }
            }
        }
    } else {
        (404, "not_found", false)
    };
    respond(&mut stream, cfg, status, code, allow);
    close(stream);
    log.event("listener", code);
    code
}

impl HttpServer {
    /// Bind and start accepting. The handler is called on connection threads;
    /// at most `max_connections` exist at once.
    pub fn start(
        cfg: ListenerConfig,
        handler: Arc<dyn WebhookHandler>,
        log: Arc<dyn EventLog>,
    ) -> Result<Self, DaemonReason> {
        cfg.validate()?;
        let listener = TcpListener::bind(cfg.bind).map_err(|_| DaemonReason::BindRefused)?;
        // Re-check what was actually bound (a wildcard resolves to a real
        // address): the loopback rule is about the socket, not the string.
        let local = listener
            .local_addr()
            .map_err(|_| DaemonReason::BindRefused)?;
        if !local.ip().is_loopback() && !cfg.allow_non_loopback {
            return Err(DaemonReason::BindRefused);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| DaemonReason::BindRefused)?;
        let stats = Arc::new(ListenerStats::default());
        let stop = Shutdown::new();
        let drain =
            cfg.head_timeout + cfg.body_timeout + cfg.write_timeout + Duration::from_secs(1);
        let cfg = Arc::new(cfg);
        let accept = {
            let (stats, stop, cfg) = (stats.clone(), stop.clone(), cfg.clone());
            std::thread::Builder::new()
                .name("listener-accept".to_owned())
                .spawn(move || accept_loop(listener, cfg, handler, log, stats, stop))
                .map_err(|_| DaemonReason::BindRefused)?
        };
        Ok(Self {
            local,
            stats,
            stop,
            accept: Some(accept),
            drain,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn stats(&self) -> &ListenerStats {
        &self.stats
    }

    /// Stop accepting, then wait (bounded by the configured timeouts) for
    /// in-flight requests to finish.
    pub fn stop(mut self) {
        self.stop.request();
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
        let end = Instant::now() + self.drain;
        while self.stats.active.load(Ordering::SeqCst) > 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.request();
    }
}

fn accept_loop(
    listener: TcpListener,
    cfg: Arc<ListenerConfig>,
    handler: Arc<dyn WebhookHandler>,
    log: Arc<dyn EventLog>,
    stats: Arc<ListenerStats>,
    stop: Shutdown,
) {
    while !stop.is_requested() {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let _ = stream.set_nonblocking(false);
                stats.accepted.fetch_add(1, Ordering::SeqCst);
                if stats.active.load(Ordering::SeqCst) >= cfg.max_connections {
                    stats.refused_busy.fetch_add(1, Ordering::SeqCst);
                    let mut s = stream;
                    respond(&mut s, &cfg, 503, "busy", false);
                    let _ = s.shutdown(TcpShutdown::Both);
                    log.event("listener", "busy");
                    continue;
                }
                stats.active.fetch_add(1, Ordering::SeqCst);
                let guard = ActiveGuard(stats.clone());
                let (cfg, handler, conn_log, stats2) =
                    (cfg.clone(), handler.clone(), log.clone(), stats.clone());
                let accepted = Instant::now();
                let spawned = std::thread::Builder::new()
                    .name("listener-conn".to_owned())
                    .spawn(move || {
                        let _guard = guard;
                        let code =
                            serve(stream, &cfg, handler.as_ref(), conn_log.as_ref(), accepted);
                        if code != "closed" {
                            stats2.served.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                if spawned.is_err() {
                    // The guard moved into the closure that never ran; the
                    // closure was dropped with the error, so it was released.
                    log.event("listener", "spawn_failed");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection that yields scripted chunks, then reports a timeout (or
    /// EOF) as chosen.
    struct Mock {
        chunks: Vec<Vec<u8>>,
        eof_at_end: bool,
        limits: Vec<Duration>,
    }

    impl Mock {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().rev().map(|c| c.to_vec()).collect(),
                eof_at_end: false,
                limits: Vec::new(),
            }
        }
    }

    impl Read for Mock {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.chunks.pop() {
                Some(mut c) => {
                    let n = c.len().min(buf.len());
                    buf[..n].copy_from_slice(&c[..n]);
                    if n < c.len() {
                        self.chunks.push(c.split_off(n));
                    }
                    Ok(n)
                }
                None if self.eof_at_end => Ok(0),
                None => Err(std::io::ErrorKind::WouldBlock.into()),
            }
        }
    }

    impl Conn for Mock {
        fn limit_read(&mut self, remaining: Duration) -> std::io::Result<()> {
            self.limits.push(remaining);
            Ok(())
        }
    }

    fn cfg() -> ListenerConfig {
        ListenerConfig::new("127.0.0.1:0".parse().unwrap(), "/hook", 1024)
    }

    fn head(raw: &[u8]) -> Result<Head, Reject> {
        read_head(&mut Mock::new(&[raw]), &cfg(), Instant::now())
    }

    const OK: &[u8] = b"POST /hook HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";

    #[test]
    fn a_valid_head_parses_and_keeps_the_start_of_the_body() {
        let h = head(OK).unwrap();
        assert_eq!((h.method.as_str(), h.target.as_str()), ("POST", "/hook"));
        assert_eq!(h.content_length, Some(5));
        assert_eq!(h.header("host"), Some("x"));
        assert_eq!(h.leftover, b"hello");
    }

    #[test]
    fn header_names_are_case_insensitive_and_values_are_trimmed() {
        let h = head(b"POST /hook HTTP/1.1\r\nX-GitHub-Event:   ping \t\r\n\r\n").unwrap();
        assert_eq!(h.header("x-github-event"), Some("ping"));
    }

    #[test]
    fn malformed_heads_are_refused_with_fixed_codes() {
        let cases: &[(&[u8], Reject)] = &[
            (b"POST /hook HTTP/1.1\nHost: x\n\n", Reject::Closed),
            (b"POST /hook HTTP/1.1\r\nHost x\r\n\r\n", bad("bad_request")),
            (
                b"POST /hook HTTP/1.1\r\n Host: x\r\n\r\n",
                bad("bad_request"),
            ),
            (
                b"POST /hook HTTP/1.1\r\nHost : x\r\n\r\n",
                bad("bad_request"),
            ),
            (
                b"POST /hook HTTP/1.1\r\nHo st: x\r\n\r\n",
                bad("bad_request"),
            ),
            (b"POST /hook HTTP/1.1\r\n: x\r\n\r\n", bad("bad_request")),
            (b"POST  /hook HTTP/1.1\r\n\r\n", bad("bad_request")),
            (b"POST /hook HTTP/1.1 extra\r\n\r\n", bad("bad_request")),
            (b"post /hook HTTP/1.1\r\n\r\n", bad("bad_request")),
            (b"POST hook HTTP/1.1\r\n\r\n", bad("bad_request")),
            (b"POST http://x/hook HTTP/1.1\r\n\r\n", bad("bad_request")),
            (b"POST /hook FTP/1.1\r\n\r\n", bad("bad_request")),
            (
                b"POST /hook HTTP/1.0\r\n\r\n",
                Reject::Status(505, "version_unsupported"),
            ),
            (
                b"POST /hook HTTP/2.0\r\n\r\n",
                Reject::Status(505, "version_unsupported"),
            ),
            (
                b"POST /hook HTTP/1.1\r\nA: \x01\r\n\r\n",
                bad("bad_request"),
            ),
            (
                b"POST /hook HTTP/1.1\r\nA: \xc3\xa9\r\n\r\n",
                bad("bad_request"),
            ),
            (
                b"POST /hook HTTP/1.1\r\nA: b\rc\r\n\r\n",
                bad("bad_request"),
            ),
        ];
        for (raw, want) in cases {
            let got = head(raw);
            // The bare-LF head never terminates, so it ends as a silent close
            // on a scripted EOF; the others are refused by code.
            match (got, want) {
                (Err(g), w) if g == *w => {}
                (Err(Reject::Status(408, _)), Reject::Closed) => {}
                (g, w) => panic!("{:?}: got {g:?}, want {w:?}", String::from_utf8_lossy(raw)),
            }
        }
    }

    #[test]
    fn framing_headers_that_could_smuggle_a_second_request_are_refused() {
        let cases: &[(&str, Reject)] = &[
            (
                "Transfer-Encoding: chunked",
                bad("transfer_encoding_unsupported"),
            ),
            (
                "Transfer-Encoding: identity",
                bad("transfer_encoding_unsupported"),
            ),
            (
                "Content-Length: 5\r\nContent-Length: 5",
                bad("header_duplicate"),
            ),
            (
                "Content-Length: 5\r\nTransfer-Encoding: chunked",
                bad("transfer_encoding_unsupported"),
            ),
            ("Content-Length: +5", bad("content_length_invalid")),
            ("Content-Length: 5 5", bad("content_length_invalid")),
            ("Content-Length: -1", bad("content_length_invalid")),
            ("Content-Length: ", bad("content_length_invalid")),
            ("Content-Length: 99999999999", bad("content_length_invalid")),
            ("Content-Length: 0x10", bad("content_length_invalid")),
            (
                "Expect: 100-continue",
                Reject::Status(417, "expectation_unsupported"),
            ),
            (
                "Content-Encoding: gzip",
                Reject::Status(415, "content_encoding_unsupported"),
            ),
            (
                "X-Hub-Signature-256: a\r\nX-Hub-Signature-256: b",
                bad("header_duplicate"),
            ),
            (
                "X-GitHub-Delivery: a\r\nx-github-delivery: b",
                bad("header_duplicate"),
            ),
            ("Host: a\r\nHost: b", bad("header_duplicate")),
        ];
        for (hdr, want) in cases {
            let raw = format!("POST /hook HTTP/1.1\r\n{hdr}\r\n\r\n");
            assert_eq!(head(raw.as_bytes()).unwrap_err(), *want, "{hdr}");
        }
        // Identity content encoding is fine.
        assert!(head(b"POST /hook HTTP/1.1\r\nContent-Encoding: identity\r\n\r\n").is_ok());
    }

    #[test]
    fn size_limits_are_enforced_as_bytes_arrive() {
        // A request line with no end in sight.
        let mut long = b"POST /".to_vec();
        long.extend(std::iter::repeat_n(b'a', 4000));
        assert_eq!(
            read_head(&mut Mock::new(&[&long]), &cfg(), Instant::now()).unwrap_err(),
            Reject::Status(414, "request_line_too_long")
        );
        // A terminated but overlong request line.
        let mut line = b"POST /".to_vec();
        line.extend(std::iter::repeat_n(b'a', 3000));
        line.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        assert_eq!(
            head(&line).unwrap_err(),
            Reject::Status(414, "request_line_too_long")
        );
        // Endless headers: refused once the head cap is crossed, without a
        // terminator ever arriving.
        let mut flood = b"POST /hook HTTP/1.1\r\n".to_vec();
        while flood.len() < 40_000 {
            flood.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        assert_eq!(
            head(&flood).unwrap_err(),
            Reject::Status(431, "header_too_large")
        );
        // Too many small headers.
        let mut many = b"POST /hook HTTP/1.1\r\n".to_vec();
        for i in 0..200 {
            many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(
            head(&many).unwrap_err(),
            Reject::Status(431, "header_too_large")
        );
    }

    #[test]
    fn a_head_that_trickles_in_hits_the_total_deadline_not_a_per_read_one() {
        let mut c = cfg();
        c.head_timeout = Duration::from_millis(50);
        c.first_byte_timeout = Duration::from_millis(50);
        // The script yields a byte, then the mock times out; the elapsed
        // clock is already past the deadline on the next loop.
        let mut m = Mock::new(&[b"P"]);
        let accepted = Instant::now() - Duration::from_millis(60);
        assert_eq!(
            read_head(&mut m, &c, accepted).unwrap_err(),
            Reject::Closed,
            "past the first-byte deadline with nothing read"
        );
        let mut m = Mock::new(&[b"POST /hook HT"]);
        let accepted = Instant::now() - Duration::from_millis(30);
        // Partial head, then the peer goes quiet: 408, not a hang.
        assert_eq!(
            read_head(&mut m, &c, accepted).unwrap_err(),
            Reject::Status(408, "request_timeout")
        );
        // Each read is bounded by what is left of the total deadline.
        assert!(m.limits.iter().all(|d| *d <= Duration::from_millis(50)));
    }

    #[test]
    fn a_silent_peer_is_closed_without_a_response() {
        let mut m = Mock::new(&[]);
        assert_eq!(
            read_head(&mut m, &cfg(), Instant::now()).unwrap_err(),
            Reject::Closed
        );
        let mut m = Mock::new(&[]);
        m.eof_at_end = true;
        assert_eq!(
            read_head(&mut m, &cfg(), Instant::now()).unwrap_err(),
            Reject::Closed
        );
    }

    #[test]
    fn the_body_is_exactly_content_length_and_pipelined_bytes_are_dropped() {
        let raw =
            b"POST /hook HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloPOST /hook HTTP/1.1\r\n\r\n";
        let mut m = Mock::new(&[raw]);
        let mut h = read_head(&mut m, &cfg(), Instant::now()).unwrap();
        let body = read_body(&mut m, &mut h, 5, Duration::from_secs(1), Instant::now()).unwrap();
        assert_eq!(body, b"hello");
        // A body that arrives in pieces.
        let mut m = Mock::new(&[
            b"POST /hook HTTP/1.1\r\nContent-Length: 6\r\n\r\nab",
            b"cd",
            b"ef",
        ]);
        let mut h = read_head(&mut m, &cfg(), Instant::now()).unwrap();
        let body = read_body(&mut m, &mut h, 6, Duration::from_secs(1), Instant::now()).unwrap();
        assert_eq!(body, b"abcdef");
        // A body that stalls: 408.
        let mut m = Mock::new(&[b"POST /hook HTTP/1.1\r\nContent-Length: 6\r\n\r\nab"]);
        let mut h = read_head(&mut m, &cfg(), Instant::now()).unwrap();
        assert_eq!(
            read_body(&mut m, &mut h, 6, Duration::from_secs(1), Instant::now()).unwrap_err(),
            Reject::Status(408, "request_timeout")
        );
        // A peer that hangs up mid-body: silent close.
        let mut m = Mock::new(&[b"POST /hook HTTP/1.1\r\nContent-Length: 6\r\n\r\nab"]);
        m.eof_at_end = true;
        let mut h = read_head(&mut m, &cfg(), Instant::now()).unwrap();
        assert_eq!(
            read_body(&mut m, &mut h, 6, Duration::from_secs(1), Instant::now()).unwrap_err(),
            Reject::Closed
        );
    }

    #[test]
    fn the_configuration_rejects_unsafe_values() {
        let ok = cfg();
        assert!(ok.validate().is_ok());
        let mut c = cfg();
        c.bind = "0.0.0.0:0".parse().unwrap();
        assert_eq!(c.validate(), Err(DaemonReason::BindRefused));
        c.allow_non_loopback = true;
        assert!(c.validate().is_ok());
        for mutate in [
            (|c: &mut ListenerConfig| c.path = "no-slash".into()) as fn(&mut ListenerConfig),
            |c| c.path = "/".into(),
            |c| c.path = HEALTH_PATH.into(),
            |c| c.path = "/a b".into(),
            |c| c.path = "/a/../b".into(),
            |c| c.path = "/a?x=1".into(),
            |c| c.max_connections = 0,
            |c| c.max_connections = MAX_CONNECTIONS_CEILING + 1,
            |c| c.max_body_bytes = 0,
            |c| c.max_body_bytes = MAX_BODY_BYTES_CEILING + 1,
            |c| c.max_headers = 0,
            |c| c.max_head_bytes = MAX_HEAD_BYTES_CEILING + 1,
            |c| c.max_head_bytes = 10,
            |c| c.head_timeout = Duration::ZERO,
            |c| c.write_timeout = TIMEOUT_CEILING + Duration::from_secs(1),
        ] {
            let mut c = cfg();
            mutate(&mut c);
            assert_eq!(c.validate(), Err(DaemonReason::ConfigInvalid));
        }
    }
}
