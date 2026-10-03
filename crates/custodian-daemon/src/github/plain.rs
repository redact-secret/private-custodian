//! Plain HTTP/1.1 to a loopback address, as an [`HttpExecutor`].
//!
//! This exists so the real request and response wire format of the API
//! adapters is exercised end to end against an in-process fake server in the
//! tests. It cannot reach GitHub: the constructor refuses any address that is
//! not loopback, there is no TLS, no name resolution, no redirect following,
//! and the response is read within a bound in time and size.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use custodian_intake::IntakeReason;

use super::api::{ApiRequest, ApiResponse, HttpExecutor, MAX_RESPONSE_BYTES};

#[derive(Debug)]
pub struct PlainHttp {
    addr: SocketAddr,
    timeout: Duration,
}

impl PlainHttp {
    /// `None` unless `addr` is a loopback address.
    pub fn loopback(addr: SocketAddr, timeout: Duration) -> Option<Self> {
        (addr.ip().is_loopback() && !timeout.is_zero() && timeout <= Duration::from_secs(60))
            .then_some(Self { addr, timeout })
    }
}

impl HttpExecutor for PlainHttp {
    fn execute(&self, r: &ApiRequest) -> Result<ApiResponse, IntakeReason> {
        let fail = IntakeReason::TokenUnavailable;
        let deadline = Instant::now() + self.timeout;
        let mut s = TcpStream::connect_timeout(&self.addr, self.timeout).map_err(|_| fail)?;
        s.set_write_timeout(Some(self.timeout)).map_err(|_| fail)?;
        let body = r.json_body.as_deref().unwrap_or(&[]);
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: private-custodian-daemon\r\n\
             Accept: application/vnd.github+json\r\nAuthorization: Bearer {}\r\n\
             Connection: close\r\n",
            r.method.as_str(),
            r.path,
            r.bearer.expose_secret(),
        );
        if r.json_body.is_some() {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes()).map_err(|_| fail)?;
        s.write_all(body).map_err(|_| fail)?;

        // Read until the peer closes (`Connection: close`), bounded in size
        // and by one total deadline.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or(fail)?;
            s.set_read_timeout(Some(left.max(Duration::from_millis(1))))
                .map_err(|_| fail)?;
            match s.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > MAX_RESPONSE_BYTES + 8192 {
                        return Err(fail);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(fail),
            }
        }
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or(fail)?;
        let head = std::str::from_utf8(&raw[..split]).map_err(|_| fail)?;
        let status_line = head.lines().next().ok_or(fail)?;
        let mut parts = status_line.split(' ');
        if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
            return Err(fail);
        }
        let status: u16 = parts.next().and_then(|c| c.parse().ok()).ok_or(fail)?;
        let body = raw[split + 4..].to_vec();
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(fail);
        }
        Ok(ApiResponse { status, body })
    }
}
