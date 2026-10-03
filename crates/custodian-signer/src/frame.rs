//! The framed protocol on the signer socket (ADR 0111).
//!
//! Request frame (client to signer), 18-byte header then body:
//!
//! | bytes | field |
//! | --- | --- |
//! | 0..4 | magic `PCSG` |
//! | 4 | protocol version (`1`) |
//! | 5 | kind (`1` = sign) |
//! | 6..14 | `issued_at`, unix seconds, big endian |
//! | 14..18 | body length, big endian, at most [`MAX_BODY`] |
//!
//! The body is the ledger crate's `WireRequest` JSON (domain, base64url
//! canonical payload, optional release digest). Response frame (signer to
//! client), 10-byte header then body: magic `PCSR`, version, status byte,
//! body length. Status `0` carries the ledger `WireResponse` JSON (a signature
//! or a fixed `sign_*` refusal); any other status is a [`Reject`] with an empty
//! body. The length is checked before any body byte is read or allocated, and
//! every read and write runs under one overall deadline.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub const REQUEST_MAGIC: [u8; 4] = *b"PCSG";
pub const RESPONSE_MAGIC: [u8; 4] = *b"PCSR";
pub const PROTOCOL_VERSION: u8 = 1;
pub const KIND_SIGN: u8 = 1;
pub const REQUEST_HEADER_LEN: usize = 18;
pub const RESPONSE_HEADER_LEN: usize = 10;
/// Largest body either side accepts. Equal to the ledger's wire limit.
pub const MAX_BODY: usize = custodian_ledger::signer::MAX_WIRE_BYTES;

/// Transport-level rejection. Fixed vocabulary; never carries payload text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reject {
    Malformed,
    UnsupportedVersion,
    TooLarge,
    Timeout,
    Busy,
    PeerDenied,
    StaleRequest,
}

impl Reject {
    pub const ALL: [Reject; 7] = [
        Self::Malformed,
        Self::UnsupportedVersion,
        Self::TooLarge,
        Self::Timeout,
        Self::Busy,
        Self::PeerDenied,
        Self::StaleRequest,
    ];

    pub fn status(self) -> u8 {
        match self {
            Self::Malformed => 1,
            Self::UnsupportedVersion => 2,
            Self::TooLarge => 3,
            Self::Timeout => 4,
            Self::Busy => 5,
            Self::PeerDenied => 6,
            Self::StaleRequest => 7,
        }
    }

    pub fn from_status(s: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.status() == s)
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "frame_malformed",
            Self::UnsupportedVersion => "frame_version_unsupported",
            Self::TooLarge => "frame_too_large",
            Self::Timeout => "frame_timeout",
            Self::Busy => "signer_busy",
            Self::PeerDenied => "peer_denied",
            Self::StaleRequest => "request_stale",
        }
    }
}

impl core::fmt::Display for Reject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

/// I/O outcome that is not a protocol violation by the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoFail {
    Timeout,
    Closed,
}

fn read_exact_by(
    s: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), IoFail> {
    let mut off = 0;
    while off < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(IoFail::Timeout);
        }
        // Some platforms (macOS) refuse setsockopt on a socket whose peer has
        // already closed; a closed peer cannot make the read block, and the
        // initial timeout was set while the connection was live (`arm`).
        let _ = s.set_read_timeout(Some(deadline - now));
        match s.read(&mut buf[off..]) {
            Ok(0) => return Err(IoFail::Closed),
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(IoFail::Timeout)
            }
            Err(_) => return Err(IoFail::Closed),
        }
    }
    Ok(())
}

/// Set both timeouts while the connection is known to be live.
pub fn arm(s: &UnixStream, timeout: Duration) -> Result<(), IoFail> {
    let t = Some(timeout.max(Duration::from_millis(1)));
    s.set_read_timeout(t).map_err(|_| IoFail::Closed)?;
    s.set_write_timeout(t).map_err(|_| IoFail::Closed)
}

fn write_all_by(s: &mut UnixStream, bytes: &[u8], timeout: Duration) -> Result<(), IoFail> {
    let _ = s.set_write_timeout(Some(timeout.max(Duration::from_millis(1))));
    s.write_all(bytes).and_then(|_| s.flush()).map_err(|e| {
        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            IoFail::Timeout
        } else {
            IoFail::Closed
        }
    })
}

/// A parsed request.
#[derive(Debug)]
pub struct Request {
    pub issued_at: u64,
    pub body: Vec<u8>,
}

/// What reading a request produced: a request, a protocol rejection to send
/// back, or a dead/slow peer to drop silently.
#[derive(Debug)]
pub enum ReadOutcome {
    Request(Request),
    Reject(Reject),
    Drop(IoFail),
}

pub fn read_request(s: &mut UnixStream, timeout: Duration) -> ReadOutcome {
    let deadline = Instant::now() + timeout;
    let mut h = [0u8; REQUEST_HEADER_LEN];
    if let Err(f) = read_exact_by(s, &mut h, deadline) {
        return match f {
            IoFail::Timeout => ReadOutcome::Reject(Reject::Timeout),
            IoFail::Closed => ReadOutcome::Drop(f),
        };
    }
    if h[0..4] != REQUEST_MAGIC {
        return ReadOutcome::Reject(Reject::Malformed);
    }
    if h[4] != PROTOCOL_VERSION {
        return ReadOutcome::Reject(Reject::UnsupportedVersion);
    }
    if h[5] != KIND_SIGN {
        return ReadOutcome::Reject(Reject::Malformed);
    }
    let issued_at = u64::from_be_bytes([h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13]]);
    let len = u32::from_be_bytes([h[14], h[15], h[16], h[17]]) as usize;
    if len > MAX_BODY {
        return ReadOutcome::Reject(Reject::TooLarge);
    }
    let mut body = vec![0u8; len];
    if let Err(f) = read_exact_by(s, &mut body, deadline) {
        return match f {
            IoFail::Timeout => ReadOutcome::Reject(Reject::Timeout),
            IoFail::Closed => ReadOutcome::Reject(Reject::Malformed),
        };
    }
    ReadOutcome::Request(Request { issued_at, body })
}

pub fn write_request(
    s: &mut UnixStream,
    issued_at: u64,
    body: &[u8],
    timeout: Duration,
) -> Result<(), IoFail> {
    let mut out = Vec::with_capacity(REQUEST_HEADER_LEN + body.len());
    out.extend_from_slice(&REQUEST_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(KIND_SIGN);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    write_all_by(s, &out, timeout)
}

pub fn write_response(
    s: &mut UnixStream,
    result: Result<&[u8], Reject>,
    timeout: Duration,
) -> Result<(), IoFail> {
    let (status, body): (u8, &[u8]) = match result {
        Ok(b) => (0, b),
        Err(r) => (r.status(), &[]),
    };
    let mut out = Vec::with_capacity(RESPONSE_HEADER_LEN + body.len());
    out.extend_from_slice(&RESPONSE_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(status);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    write_all_by(s, &out, timeout)
}

/// Client side: read one response frame. `Err(None)` is a dead or slow signer
/// or a response that violates the framing; `Err(Some(r))` is a signer
/// rejection.
pub fn read_response(
    s: &mut UnixStream,
    timeout: Duration,
) -> Result<Vec<u8>, Option<Reject>> {
    let deadline = Instant::now() + timeout;
    let mut h = [0u8; RESPONSE_HEADER_LEN];
    read_exact_by(s, &mut h, deadline).map_err(|_| None)?;
    if h[0..4] != RESPONSE_MAGIC || h[4] != PROTOCOL_VERSION {
        return Err(None);
    }
    let len = u32::from_be_bytes([h[6], h[7], h[8], h[9]]) as usize;
    if len > MAX_BODY {
        return Err(None);
    }
    if h[5] != 0 {
        return Err(Reject::from_status(h[5]));
    }
    let mut body = vec![0u8; len];
    read_exact_by(s, &mut body, deadline).map_err(|_| None)?;
    Ok(body)
}
