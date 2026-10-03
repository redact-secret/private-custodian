//! Client side: a [`SignerTransport`] over the signer's Unix socket (ADR 0111).
//!
//! Wrap it in `custodian_ledger::RemoteSigner` to get a `Signer` that holds no
//! key. Every failure (no socket, refused connection, wrong server uid, slow or
//! malformed response, signer rejection) is `sign_signer_unavailable`, so the
//! exporter errors and writes nothing.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use custodian_ledger::{SignRefusal, SignerTransport};

use crate::engine::{Clock, SystemClock};
use crate::frame;
use crate::platform::peer_uid;

pub struct UnixSocketTransport {
    path: PathBuf,
    timeout: Duration,
    expected_signer_uid: Option<u32>,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for UnixSocketTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnixSocketTransport(<path omitted>)")
    }
}

impl UnixSocketTransport {
    pub fn new(path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            path: path.into(),
            timeout,
            expected_signer_uid: None,
            clock: Arc::new(SystemClock),
        }
    }

    /// Refuse to talk to a socket whose server runs as any other uid, so a
    /// process that can bind the path does not become the signer.
    pub fn expecting_signer_uid(mut self, uid: u32) -> Self {
        self.expected_signer_uid = Some(uid);
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl SignerTransport for UnixSocketTransport {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, SignRefusal> {
        let unavailable = SignRefusal::SignerUnavailable;
        if request.len() > frame::MAX_BODY {
            return Err(SignRefusal::PayloadInvalid);
        }
        let mut s = UnixStream::connect(&self.path).map_err(|_| unavailable)?;
        frame::arm(&s, self.timeout).map_err(|_| unavailable)?;
        if let Some(uid) = self.expected_signer_uid {
            if peer_uid(&s) != Some(uid) {
                return Err(unavailable);
            }
        }
        frame::write_request(&mut s, self.clock.now_secs(), request, self.timeout)
            .map_err(|_| unavailable)?;
        frame::read_response(&mut s, self.timeout).map_err(|_| unavailable)
    }
}
