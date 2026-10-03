//! Shared synthetic fixtures for the signer tests. Keys are generated inside
//! each test from operating-system randomness, written only into a private
//! temporary directory that removes itself, and never printed.
#![allow(dead_code)]
#![allow(clippy::duplicate_mod)]

#[path = "../../../custodian-contracts/tests/common/mod.rs"]
pub mod cc;

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use custodian_contracts::types::KeyId;
use custodian_ledger::{
    ApprovedPayload, KeyEntry, Keyring, LedgerRecord, RemoteSigner, SignDomain, SignedLedgerRecord,
    Signer, Verifier,
};
use custodian_signer::{
    start, EventSink, FileKeyProvider, ManualClock, RunningServer, ServerConfig, SignerSetup,
    SigningEngine, UnixSocketTransport,
};
use custodian_store::Checkpoint;

pub const NOW: u64 = cc::NOW;
/// The signer's and the client's clock in most tests.
pub const T0: u64 = NOW + 100;

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn key_id() -> KeyId {
    KeyId::parse(&cc::id("key_", 1)).unwrap()
}

pub fn random_seed_hex() -> String {
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    let mut b = [0u8; 32];
    f.read_exact(&mut b).expect("read");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A private temporary directory (mode 0700) holding a key file and the
/// socket. Paths are kept short: Unix socket paths are limited to about 100
/// bytes on macOS.
pub struct Env {
    pub root: PathBuf,
    pub key_path: PathBuf,
    pub sock: PathBuf,
    pub seed_hex: String,
    pub clock: Arc<ManualClock>,
    pub events: Arc<Mutex<Vec<&'static str>>>,
}

impl Env {
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("pcsg-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key_path = root.join("k");
        let seed_hex = random_seed_hex();
        std::fs::write(&key_path, format!("{seed_hex}\n")).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            sock: root.join("s"),
            root,
            key_path,
            seed_hex,
            clock: Arc::new(ManualClock::new(T0)),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn sink(&self) -> EventSink {
        let ev = self.events.clone();
        Arc::new(move |c| ev.lock().unwrap().push(c))
    }

    pub fn setup(&self) -> SignerSetup {
        SignerSetup {
            key_id: key_id(),
            purposes: SignDomain::ALL.into_iter().collect::<BTreeSet<_>>(),
            valid_from: NOW - 1000,
            not_after: None,
            max_request_skew_secs: 120,
        }
    }

    pub fn engine_with(&self, setup: SignerSetup) -> Arc<SigningEngine> {
        Arc::new(
            SigningEngine::new(
                &FileKeyProvider::new(self.key_path.clone()),
                setup,
                self.clock.clone(),
                self.sink(),
            )
            .expect("engine"),
        )
    }

    pub fn engine(&self) -> Arc<SigningEngine> {
        self.engine_with(self.setup())
    }

    pub fn server_config(&self) -> ServerConfig {
        ServerConfig {
            socket_path: self.sock.clone(),
            allowed_peer_uid: custodian_signer::effective_uid(),
            io_timeout: Duration::from_secs(3),
            max_concurrent: 8,
        }
    }

    pub fn server(&self, engine: Arc<SigningEngine>) -> RunningServer {
        start(self.server_config(), engine).expect("server")
    }

    pub fn transport(&self) -> UnixSocketTransport {
        UnixSocketTransport::new(self.sock.clone(), Duration::from_secs(3))
            .with_clock(self.clock.clone())
    }

    pub fn client(&self) -> RemoteSigner<UnixSocketTransport> {
        RemoteSigner::new(key_id(), self.transport())
    }

    pub fn verifier(&self, engine: &SigningEngine) -> Verifier {
        let entry = KeyEntry::root(
            key_id(),
            engine.public_key_hex(),
            SignDomain::ALL,
            cc::ts(NOW - 1000),
        )
        .unwrap();
        Verifier::new(Keyring::new().with_root(entry))
    }

    pub fn raw(&self) -> UnixStream {
        let s = UnixStream::connect(&self.sock).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s
    }

    pub fn event_text(&self) -> String {
        self.events.lock().unwrap().join("\n")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn checkpoint_record(at: u64) -> LedgerRecord {
    LedgerRecord::store_checkpoint(
        &Checkpoint {
            seq: 3,
            chain: "b".repeat(64),
        },
        at,
    )
    .unwrap()
}

pub fn sign_record(s: &dyn Signer, r: &LedgerRecord) -> SignedLedgerRecord {
    let sig = s.sign(&ApprovedPayload::ledger_record(r).unwrap()).unwrap();
    SignedLedgerRecord {
        payload: r.clone(),
        signature: sig,
    }
}

/// base64url without padding, as the ledger wire protocol uses.
pub fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        let chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for ch in chars.iter().take(c.len() + 1) {
            out.push(A[*ch as usize] as char);
        }
    }
    out
}

/// A hand-built ledger `WireRequest` body.
pub fn wire(domain: &str, canonical: &[u8], release_digest: Option<&str>) -> Vec<u8> {
    let mut v = serde_json::json!({"domain": domain, "payload": b64(canonical)});
    if let Some(d) = release_digest {
        v["release_digest"] = serde_json::json!(d);
    }
    serde_json::to_vec(&v).unwrap()
}

/// Header bytes of a request frame.
pub fn header(magic: &[u8; 4], version: u8, kind: u8, issued_at: u64, len: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(magic);
    h.push(version);
    h.push(kind);
    h.extend_from_slice(&issued_at.to_be_bytes());
    h.extend_from_slice(&len.to_be_bytes());
    h
}

pub fn wait_until(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

pub fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
