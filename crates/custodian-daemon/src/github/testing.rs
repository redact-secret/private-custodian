//! Offline doubles for the GitHub side. They contact nothing.
//!
//! [`FakeGithub`] answers the three calls the adapters make from scripted
//! state and records every request it receives, so a test can assert the exact
//! method, path and body of each call and that no secret appears in anything
//! the adapters logged or returned. [`FakeGithub::serve`] runs the same
//! script behind a real loopback socket, for the wire-format tests of
//! [`PlainHttp`](super::plain::PlainHttp).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use custodian_intake::IntakeReason;

use super::api::{ApiRequest, ApiResponse, HttpExecutor, Method};

/// What the fake saw. The bearer is kept so a test can prove it was the right
/// kind of credential; the type that holds it here is the test's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub method: Method,
    pub path: String,
    pub bearer: String,
    pub body: Option<String>,
}

#[derive(Debug)]
struct State {
    seen: Vec<Seen>,
    /// Head commit returned for any pull request.
    head_sha: String,
    full_name: String,
    next_run: u64,
    /// Fail every call with this status (instead of the script).
    force_status: Option<u16>,
    /// Make `execute` itself fail (a transport error).
    offline: bool,
    /// Token expiry returned, as RFC 3339.
    token_expires_at: String,
    token_value: String,
}

/// A scripted GitHub. Cloning shares the state.
#[derive(Clone, Debug)]
pub struct FakeGithub {
    state: Arc<Mutex<State>>,
}

impl FakeGithub {
    pub fn new(head_sha: &str) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                seen: Vec::new(),
                head_sha: head_sha.to_owned(),
                full_name: "synthetic-org/synthetic-repo".to_owned(),
                next_run: 1000,
                force_status: None,
                offline: false,
                token_expires_at: "2099-01-01T00:00:00Z".to_owned(),
                token_value: "ghs_SYNTHETICinstallationTOKEN0000000000".to_owned(),
            })),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.with(|s| s.seen.clone())
    }
    pub fn set_head(&self, sha: &str) {
        self.with(|s| s.head_sha = sha.to_owned());
    }
    pub fn set_offline(&self, down: bool) {
        self.with(|s| s.offline = down);
    }
    pub fn force_status(&self, status: Option<u16>) {
        self.with(|s| s.force_status = status);
    }
    pub fn set_full_name(&self, name: &str) {
        self.with(|s| s.full_name = name.to_owned());
    }
    pub fn token_value(&self) -> String {
        self.with(|s| s.token_value.clone())
    }
    pub fn set_token_expiry(&self, rfc3339: &str) {
        self.with(|s| s.token_expires_at = rfc3339.to_owned());
    }

    fn answer(&self, r: &ApiRequest) -> Result<ApiResponse, IntakeReason> {
        self.with(|s| {
            if s.offline {
                return Err(IntakeReason::TokenUnavailable);
            }
            s.seen.push(Seen {
                method: r.method,
                path: r.path.clone(),
                bearer: r.bearer.expose_secret().to_owned(),
                body: r
                    .json_body
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned()),
            });
            if let Some(status) = s.force_status {
                return Ok(ApiResponse {
                    status,
                    body: b"{}".to_vec(),
                });
            }
            let json = |status: u16, v: serde_json::Value| ApiResponse {
                status,
                body: serde_json::to_vec(&v).unwrap_or_default(),
            };
            let p = r.path.as_str();
            Ok(match (r.method, p) {
                (Method::Post, p) if p.starts_with("/app/installations/") && p.ends_with("/access_tokens") => {
                    json(
                        201,
                        serde_json::json!({
                            "token": s.token_value,
                            "expires_at": s.token_expires_at,
                            "permissions": {"metadata": "read", "pull_requests": "read", "checks": "write"},
                        }),
                    )
                }
                (Method::Get, p) if p.starts_with("/repositories/") => {
                    json(200, serde_json::json!({"full_name": s.full_name}))
                }
                (Method::Get, p) if p.contains("/pulls/") => {
                    json(200, serde_json::json!({"head": {"sha": s.head_sha}}))
                }
                (Method::Post, p) if p.ends_with("/check-runs") => {
                    s.next_run += 1;
                    json(201, serde_json::json!({"id": s.next_run}))
                }
                (Method::Patch, p) if p.contains("/check-runs/") => {
                    json(200, serde_json::json!({"id": 1}))
                }
                _ => json(404, serde_json::json!({})),
            })
        })
    }

    /// Serve the script on an ephemeral loopback port until the returned
    /// handle is dropped. One request per connection, `Connection: close`.
    pub fn serve(&self) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let fake = self.clone();
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut raw = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let mut body_at = None;
                        while let Ok(n) = s.read(&mut chunk) {
                            if n == 0 {
                                break;
                            }
                            raw.extend_from_slice(&chunk[..n]);
                            if body_at.is_none() {
                                body_at =
                                    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
                            }
                            if let Some(at) = body_at {
                                let head = String::from_utf8_lossy(&raw[..at]).to_ascii_lowercase();
                                let want = head
                                    .lines()
                                    .find_map(|l| l.strip_prefix("content-length:"))
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                if raw.len() >= at + want {
                                    break;
                                }
                            }
                        }
                        let text = String::from_utf8_lossy(&raw).into_owned();
                        let mut lines = text.lines();
                        let first = lines.next().unwrap_or("");
                        let mut it = first.split(' ');
                        let method = match it.next() {
                            Some("GET") => Method::Get,
                            Some("POST") => Method::Post,
                            Some("PATCH") => Method::Patch,
                            _ => Method::Get,
                        };
                        let path = it.next().unwrap_or("/").to_owned();
                        let bearer = text
                            .lines()
                            .find_map(|l| l.strip_prefix("Authorization: Bearer "))
                            .unwrap_or("")
                            .trim()
                            .to_owned();
                        let body = body_at
                            .map(|at| raw[at..].to_vec())
                            .filter(|b| !b.is_empty());
                        let req = ApiRequest {
                            method,
                            path,
                            bearer: super::api::Bearer::new(&bearer),
                            json_body: body,
                        };
                        let resp = fake.answer(&req).unwrap_or(ApiResponse {
                            status: 503,
                            body: Vec::new(),
                        });
                        let head = format!(
                            "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            resp.status,
                            resp.body.len()
                        );
                        let _ = s.write_all(head.as_bytes());
                        let _ = s.write_all(&resp.body);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        FakeServer {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl HttpExecutor for FakeGithub {
    fn execute(&self, request: &ApiRequest) -> Result<ApiResponse, IntakeReason> {
        self.answer(request)
    }
}

/// A [`FakeGithub`] behind a loopback socket.
pub struct FakeServer {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
