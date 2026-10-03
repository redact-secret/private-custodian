//! The HTTP listener over real loopback sockets: forged, replayed, oversized,
//! malformed, slow and pipelined requests, the connection cap, the bind rule
//! and a log that never carries request content. Synthetic only.

#![allow(clippy::duplicate_mod)]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{intake_config, pr_payload, uuid, REQUESTER_USER};
use custodian_daemon::http::{
    HttpServer, IntakeHandler, ListenerConfig, WebhookHandler, WebhookRequest, HEALTH_PATH,
};
use custodian_daemon::log::RecordingLog;
use custodian_daemon::reason::DaemonReason;
use custodian_intake::config::WebhookSecret;
use custodian_intake::signature::sign_body;
use custodian_intake::testing::random_bytes;
use custodian_intake::webhook::Intake;
use custodian_store::{ManualClock, SqliteStore, StoreConfig};

const PATH: &str = "/webhooks/github";

fn cfg() -> ListenerConfig {
    let mut c = ListenerConfig::new("127.0.0.1:0".parse().unwrap(), PATH, 4096);
    c.first_byte_timeout = Duration::from_millis(400);
    c.head_timeout = Duration::from_millis(600);
    c.body_timeout = Duration::from_millis(600);
    c.write_timeout = Duration::from_millis(600);
    c
}

/// Counts how many requests reached the handler.
struct Counting(AtomicUsize);

impl WebhookHandler for Counting {
    fn handle(&self, _: &WebhookRequest<'_>) -> (u16, &'static str) {
        self.0.fetch_add(1, Ordering::SeqCst);
        (202, "queued")
    }
}

fn counting_server(c: ListenerConfig) -> (HttpServer, Arc<Counting>, Arc<RecordingLog>) {
    let h = Arc::new(Counting(AtomicUsize::new(0)));
    let log = Arc::new(RecordingLog::new());
    let s = HttpServer::start(c, h.clone(), log.clone()).unwrap();
    (s, h, log)
}

/// Send raw bytes, read the whole response (the server always closes).
fn exchange(addr: SocketAddr, bytes: &[u8]) -> (String, Duration) {
    let t = Instant::now();
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = s.write_all(bytes);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    (String::from_utf8_lossy(&out).into_owned(), t.elapsed())
}

fn status(resp: &str) -> u16 {
    resp.split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn code(resp: &str) -> String {
    resp.rsplit("\r\n\r\n")
        .next()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
        .and_then(|v| v["code"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn post(body: &[u8], extra: &str) -> Vec<u8> {
    let mut v = format!(
        "POST {PATH} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    v.extend_from_slice(body);
    v
}

// ---- the real intake behind the real listener ----------------------------------------

struct Real {
    server: HttpServer,
    store: Arc<SqliteStore>,
    secret: Vec<u8>,
    log: Arc<RecordingLog>,
    _dir: std::path::PathBuf,
}

fn real() -> Real {
    let dir = std::env::temp_dir().join(format!(
        "custodian-daemon-listener-{}-{}",
        std::process::id(),
        random_bytes(4)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let store = Arc::new(
        SqliteStore::open_with_config(
            dir.join("store.db"),
            StoreConfig::enforced().with_clock(Arc::new(ManualClock::new(1_800_000_000))),
        )
        .unwrap(),
    );
    let secret = random_bytes(32);
    let intake = Intake::new(
        intake_config(),
        WebhookSecret::new(secret.clone()).unwrap(),
        store.clone(),
        store.clone(),
        store.clone(),
    );
    let log = Arc::new(RecordingLog::new());
    let mut c = cfg();
    c.max_body_bytes = intake_config().max_body_bytes();
    c.head_timeout = Duration::from_secs(5);
    c.body_timeout = Duration::from_secs(5);
    c.first_byte_timeout = Duration::from_secs(5);
    let server = HttpServer::start(
        c,
        Arc::new(IntakeHandler::new(
            intake,
            Arc::new(ManualClock::new(1_800_000_000)),
        )),
        log.clone(),
    )
    .unwrap();
    Real {
        server,
        store,
        secret,
        log,
        _dir: dir,
    }
}

impl Real {
    fn signed(&self, event: &str, delivery: u64, body: &[u8]) -> Vec<u8> {
        let sig = sign_body(&WebhookSecret::new(self.secret.clone()).unwrap(), body);
        post(
            body,
            &format!(
                "X-Hub-Signature-256: {sig}\r\nX-GitHub-Event: {event}\r\nX-GitHub-Delivery: {}\r\n",
                uuid(delivery)
            ),
        )
    }
}

impl Drop for Real {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

#[test]
fn a_signed_delivery_is_queued_and_the_response_is_a_fixed_code() {
    let r = real();
    let addr = r.server.local_addr();
    let (resp, _) = exchange(addr, &r.signed("ping", 1, b"{\"zen\":\"synthetic\"}"));
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (200, "ignored"),
        "{resp}"
    );
    let body = serde_json::to_vec(&pr_payload("opened", REQUESTER_USER, "User", 'a')).unwrap();
    let (resp, _) = exchange(addr, &r.signed("pull_request", 2, &body));
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (202, "queued"),
        "{resp}"
    );
    assert_eq!(r.store.queue_depth().unwrap(), 1);
    // The response says nothing but the code.
    assert!(resp.ends_with("{\"code\":\"queued\"}"));
    assert!(resp.contains("Connection: close"));
    assert!(!resp.to_ascii_lowercase().contains("server:"));
}

#[test]
fn forged_missing_and_replayed_deliveries_are_refused_and_queue_nothing() {
    let r = real();
    let addr = r.server.local_addr();
    let body = serde_json::to_vec(&pr_payload("opened", REQUESTER_USER, "User", 'a')).unwrap();
    // A signature from another secret.
    let other = sign_body(&WebhookSecret::new(random_bytes(32)).unwrap(), &body);
    let forged = post(
        &body,
        &format!(
            "X-Hub-Signature-256: {other}\r\nX-GitHub-Event: pull_request\r\nX-GitHub-Delivery: {}\r\n",
            uuid(1)
        ),
    );
    let (resp, _) = exchange(addr, &forged);
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (401, "signature_invalid")
    );
    // No signature at all.
    let bare = post(
        &body,
        &format!(
            "X-GitHub-Event: pull_request\r\nX-GitHub-Delivery: {}\r\n",
            uuid(1)
        ),
    );
    let (resp, _) = exchange(addr, &bare);
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (401, "signature_invalid")
    );
    // A tampered body under a good signature.
    let mut tampered = r.signed("pull_request", 3, &body);
    let n = tampered.len();
    tampered[n - 5] ^= 1;
    let (resp, _) = exchange(addr, &tampered);
    assert_eq!(status(&resp), 401);
    assert_eq!(r.store.queue_depth().unwrap(), 0);
    // A genuine delivery, then the same delivery again.
    let genuine = r.signed("pull_request", 4, &body);
    let (resp, _) = exchange(addr, &genuine);
    assert_eq!(status(&resp), 202, "{resp}");
    let (resp, _) = exchange(addr, &genuine);
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (409, "delivery_replay")
    );
    assert_eq!(r.store.queue_depth().unwrap(), 1, "queued once");
    // An actor who is not on the allowlist.
    let stranger = serde_json::to_vec(&pr_payload("opened", 700_999, "User", 'a')).unwrap();
    let (resp, _) = exchange(addr, &r.signed("pull_request", 5, &stranger));
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (403, "actor_not_authorized")
    );
    // A fork-shaped payload and a comment event.
    let mut fork = pr_payload("opened", REQUESTER_USER, "User", 'a');
    fork["pull_request"]["head"]["repo"]["id"] = serde_json::json!(999_999);
    fork["pull_request"]["head"]["repo"]["fork"] = serde_json::json!(true);
    let (resp, _) = exchange(
        addr,
        &r.signed("pull_request", 6, &serde_json::to_vec(&fork).unwrap()),
    );
    assert_eq!((status(&resp), code(&resp).as_str()), (403, "fork_denied"));
    let (resp, _) = exchange(addr, &r.signed("issue_comment", 7, b"{}"));
    assert_eq!(code(&resp), "comment_trigger_denied");
    assert_eq!(r.store.queue_depth().unwrap(), 1);
}

#[test]
fn oversized_bodies_are_refused_before_they_are_read() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    // The declared length alone is enough: no body is sent at all.
    let head = format!("POST {PATH} HTTP/1.1\r\nContent-Length: 4097\r\n\r\n");
    let (resp, took) = exchange(addr, head.as_bytes());
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (413, "body_too_large")
    );
    assert!(
        took < Duration::from_millis(400),
        "answered at once: {took:?}"
    );
    // An actual oversized body.
    let (resp, _) = exchange(addr, &post(&vec![b'x'; 4097], ""));
    assert_eq!(status(&resp), 413);
    // Exactly at the cap is accepted by the listener.
    let (resp, _) = exchange(addr, &post(&vec![b'x'; 4096], ""));
    assert_eq!(status(&resp), 202);
    assert_eq!(h.0.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_and_smuggling_shaped_requests_never_reach_the_handler() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    let cases: Vec<(Vec<u8>, u16, &str)> = vec![
        (b"\x00\x01\x02garbage\r\n\r\n".to_vec(), 400, "bad_request"),
        (b"POST /webhooks/github HTTP/1.0\r\n\r\n".to_vec(), 505, "version_unsupported"),
        (b"POST http://x/webhooks/github HTTP/1.1\r\n\r\n".to_vec(), 400, "bad_request"),
        (b"post /webhooks/github HTTP/1.1\r\n\r\n".to_vec(), 400, "bad_request"),
        (
            b"POST /webhooks/github HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
            400,
            "transfer_encoding_unsupported",
        ),
        (
            b"POST /webhooks/github HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd".to_vec(),
            400,
            "header_duplicate",
        ),
        (
            b"POST /webhooks/github HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nabcd".to_vec(),
            400,
            "transfer_encoding_unsupported",
        ),
        (b"POST /webhooks/github HTTP/1.1\r\nContent-Length: abc\r\n\r\n".to_vec(), 400, "content_length_invalid"),
        (b"POST /webhooks/github HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n".to_vec(), 417, "expectation_unsupported"),
        (b"POST /webhooks/github HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), 411, "length_required"),
        (b"POST /webhooks/github HTTP/1.1\r\n Folded: header\r\n\r\n".to_vec(), 400, "bad_request"),
        (b"GET /webhooks/github HTTP/1.1\r\n\r\n".to_vec(), 405, "method_not_allowed"),
        (b"PUT /webhooks/github HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(), 405, "method_not_allowed"),
        (b"POST /elsewhere HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(), 404, "not_found"),
        (b"POST /webhooks/github?x=1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(), 404, "not_found"),
        (b"POST /webhooks/github/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(), 404, "not_found"),
        (b"POST /../webhooks/github HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(), 404, "not_found"),
    ];
    for (raw, want_status, want_code) in cases {
        let (resp, _) = exchange(addr, &raw);
        assert_eq!(
            (status(&resp), code(&resp).as_str()),
            (want_status, want_code),
            "{:?} -> {resp}",
            String::from_utf8_lossy(&raw)
        );
    }
    assert_eq!(h.0.load(Ordering::SeqCst), 0);
}

#[test]
fn huge_heads_are_refused_with_fixed_codes() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    let mut big = format!("POST {PATH} HTTP/1.1\r\n").into_bytes();
    while big.len() < 70_000 {
        big.extend_from_slice(
            b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n",
        );
    }
    let (resp, _) = exchange(addr, &big);
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (431, "header_too_large")
    );
    let mut many = format!("POST {PATH} HTTP/1.1\r\n").into_bytes();
    for i in 0..200 {
        many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    many.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    let (resp, _) = exchange(addr, &many);
    assert_eq!(status(&resp), 431);
    let mut line = b"POST /".to_vec();
    line.extend(std::iter::repeat_n(b'a', 9000));
    line.extend_from_slice(b" HTTP/1.1\r\n\r\n");
    let (resp, _) = exchange(addr, &line);
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (414, "request_line_too_long")
    );
    assert_eq!(h.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_slowloris_trickle_is_cut_off_at_the_total_deadline() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    let t = Instant::now();
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // One byte every 50 ms never completes a head and never resets the clock.
    let head = format!("POST {PATH} HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    let mut closed_at = None;
    for b in head.bytes() {
        if c.write_all(&[b]).is_err() {
            closed_at = Some(t.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        if t.elapsed() > Duration::from_secs(3) {
            break;
        }
    }
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let took = t.elapsed();
    assert!(
        took < Duration::from_millis(2500),
        "the trickle outlived the 600 ms head deadline: {took:?} ({closed_at:?})"
    );
    let resp = String::from_utf8_lossy(&out);
    if !resp.is_empty() {
        assert_eq!(status(&resp), 408, "{resp}");
        assert_eq!(code(&resp), "request_timeout");
    }
    assert_eq!(h.0.load(Ordering::SeqCst), 0);
}

#[test]
fn an_idle_connection_and_a_stalled_body_are_cut_off() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    // Says nothing: dropped silently after the first-byte timeout.
    let t = Instant::now();
    let mut idle = TcpStream::connect(addr).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut out = Vec::new();
    let _ = idle.read_to_end(&mut out);
    assert!(out.is_empty(), "no response to silence");
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
    // A body that stalls halfway.
    let t = Instant::now();
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(format!("POST {PATH} HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly-part").as_bytes())
        .unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let resp = String::from_utf8_lossy(&out);
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (408, "request_timeout"),
        "{resp}"
    );
    assert!(
        t.elapsed() < Duration::from_millis(2000),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(h.0.load(Ordering::SeqCst), 0);
}

#[test]
fn pipelined_requests_are_answered_once_and_the_second_is_never_parsed() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    let mut two = post(b"{\"n\":1}", "");
    two.extend_from_slice(&post(b"{\"n\":2}", ""));
    let (resp, _) = exchange(addr, &two);
    assert_eq!(status(&resp), 202);
    assert_eq!(
        resp.matches("HTTP/1.1").count(),
        1,
        "exactly one response, then the connection closes: {resp}"
    );
    assert_eq!(h.0.load(Ordering::SeqCst), 1);
}

#[test]
fn the_connection_cap_refuses_the_next_connection_and_recovers() {
    let mut c = cfg();
    c.max_connections = 2;
    c.first_byte_timeout = Duration::from_secs(10);
    c.head_timeout = Duration::from_secs(10);
    let (s, h, log) = counting_server(c);
    let addr = s.local_addr();
    let hold1 = TcpStream::connect(addr).unwrap();
    let hold2 = TcpStream::connect(addr).unwrap();
    // Let the accept loop register both.
    let deadline = Instant::now() + Duration::from_secs(2);
    while s.stats().active.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let (resp, took) = exchange(addr, &post(b"{}", ""));
    assert_eq!(
        (status(&resp), code(&resp).as_str()),
        (503, "busy"),
        "{resp}"
    );
    assert!(took < Duration::from_millis(500));
    assert_eq!(h.0.load(Ordering::SeqCst), 0);
    assert!(s.stats().refused_busy.load(Ordering::SeqCst) >= 1);
    // The refusal is written to the peer first and logged after it, so the
    // log line can land a moment after the reply (seen on a loaded CI runner).
    let deadline = Instant::now() + Duration::from_secs(5);
    while log.count("listener", "busy") < 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(log.count("listener", "busy") >= 1);
    // Freeing a slot lets the next one in.
    drop(hold1);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut ok = false;
    while Instant::now() < deadline {
        let (resp, _) = exchange(addr, &post(b"{}", ""));
        if status(&resp) == 202 {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ok, "served again after a slot freed");
    drop(hold2);
}

#[test]
fn health_reveals_nothing_and_only_get_reaches_it() {
    let (s, _, _) = counting_server(cfg());
    let addr = s.local_addr();
    let (resp, _) = exchange(
        addr,
        format!("GET {HEALTH_PATH} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
    );
    assert_eq!((status(&resp), code(&resp).as_str()), (200, "ok"));
    assert!(resp.ends_with("{\"code\":\"ok\"}"), "{resp}");
    let (resp, _) = exchange(
        addr,
        format!("POST {HEALTH_PATH} HTTP/1.1\r\nContent-Length: 0\r\n\r\n").as_bytes(),
    );
    assert_eq!(status(&resp), 405);
    let (resp, _) = exchange(
        addr,
        format!("GET {HEALTH_PATH} HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde").as_bytes(),
    );
    assert_eq!(status(&resp), 400);
}

#[test]
fn the_listener_binds_loopback_unless_the_configuration_says_otherwise() {
    let mut c = cfg();
    c.bind = "0.0.0.0:0".parse().unwrap();
    let h = Arc::new(Counting(AtomicUsize::new(0)));
    let log = Arc::new(RecordingLog::new());
    assert_eq!(
        HttpServer::start(c.clone(), h.clone(), log.clone()).err(),
        Some(DaemonReason::BindRefused)
    );
    c.allow_non_loopback = true;
    let s = HttpServer::start(c, h, log).unwrap();
    s.stop();
}

#[test]
fn stopping_finishes_what_is_in_flight_and_stops_accepting() {
    let (s, h, _) = counting_server(cfg());
    let addr = s.local_addr();
    let (resp, _) = exchange(addr, &post(b"{}", ""));
    assert_eq!(status(&resp), 202);
    let t = Instant::now();
    s.stop();
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err()
            || exchange(addr, &post(b"{}", "")).0.is_empty()
    );
    assert_eq!(h.0.load(Ordering::SeqCst), 1);
}

#[test]
fn nothing_a_request_carries_reaches_the_log() {
    let r = real();
    let addr = r.server.local_addr();
    const CANARY: &str = "SYNTHETIC-CANARY-REQUEST-CONTENT-77";
    let body = format!("{{\"leak\":\"{CANARY}\"}}");
    let hdr = format!("X-Evil: {CANARY}\r\nAuthorization: Bearer {CANARY}\r\n");
    for raw in [
        post(body.as_bytes(), &hdr),
        r.signed("pull_request", 9, body.as_bytes()),
        format!("GET /{CANARY} HTTP/1.1\r\n\r\n").into_bytes(),
        format!("POST {PATH} HTTP/1.1\r\nX-Hub-Signature-256: sha256={CANARY}\r\nContent-Length: 0\r\n\r\n")
            .into_bytes(),
    ] {
        let (resp, _) = exchange(addr, &raw);
        assert!(!resp.contains(CANARY), "echoed: {resp}");
    }
    for line in r.log.lines() {
        assert!(!line.contains(CANARY), "{line}");
        assert!(line.starts_with("component=listener code="), "{line}");
    }
    assert!(!r.log.lines().is_empty());
}
