//! Shared synthetic fixtures. Keys are generated inside each test from
//! operating-system randomness and never written anywhere. Every identity is
//! an obviously synthetic placeholder.
#![allow(dead_code)]

#[path = "../../../custodian-contracts/tests/common/mod.rs"]
pub mod cc;
#[path = "../../../custodian-corpus/tests/common/mod.rs"]
pub mod corpus;
#[path = "../../../custodian-store/tests/common/mod.rs"]
pub mod sc;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::types::KeyId;
use custodian_core::ReasonCode;
use custodian_ledger::{
    KeyEntry, Keyring, SignDomain, SignerService, Sleeper, SoftwareSigner, Verifier,
};
use custodian_store::{OutboxEvent, SqliteStore, StartCommand};

#[allow(unused_imports)]
pub use sc::{actor, fixture, open, provision, reserve, status, Fx, TempDb, NOW};

/// 32 random bytes from the OS, generated in the test.
pub fn random_seed() -> [u8; 32] {
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    let mut b = [0u8; 32];
    f.read_exact(&mut b).expect("read");
    b
}

pub fn key_id(n: u32) -> KeyId {
    KeyId::parse(&cc::id("key_", n)).unwrap()
}

pub const LEDGER_DOMAINS: [SignDomain; 7] = [
    SignDomain::LedgerAuditEvent,
    SignDomain::LedgerStoreCheckpoint,
    SignDomain::LedgerRegistryCheckpoint,
    SignDomain::LedgerPolicy,
    SignDomain::LedgerPublication,
    SignDomain::LedgerReconciliation,
    SignDomain::LedgerKeyEvent,
];

pub fn all_domains() -> Vec<SignDomain> {
    SignDomain::ALL.to_vec()
}

pub struct TestKey {
    pub signer: SoftwareSigner,
    pub entry: KeyEntry,
}

/// A fresh key with the given purposes, valid from `valid_from`.
pub fn test_key(n: u32, purposes: &[SignDomain], valid_from: u64) -> TestKey {
    let signer = SoftwareSigner::from_seed(key_id(n), &random_seed(), purposes.iter().copied());
    let entry = KeyEntry::root(
        key_id(n),
        &signer.public_key_hex(),
        purposes.iter().copied(),
        cc::ts(valid_from),
    )
    .unwrap();
    TestKey { signer, entry }
}

/// One all-purpose key, pinned as the only root.
pub struct Setup {
    pub key: TestKey,
    pub keyring: Keyring,
    pub verifier: Verifier,
}

pub fn setup() -> Setup {
    let key = test_key(1, &all_domains(), NOW - 10_000);
    let keyring = Keyring::new().with_root(key.entry.clone());
    let verifier = Verifier::new(keyring.clone());
    Setup {
        key,
        keyring,
        verifier,
    }
}

pub fn service(
    key: &TestKey,
    seed_purposes: &[SignDomain],
    n: u32,
) -> SignerService<SoftwareSigner> {
    let _ = key;
    SignerService::new(SoftwareSigner::from_seed(
        key_id(n),
        &random_seed(),
        seed_purposes.iter().copied(),
    ))
}

/// Drive one attempt to a settled `completed` terminal state, producing the
/// full set of outbox events.
pub fn complete(store: &SqliteStore, fx: &Fx) -> custodian_store::Settlement {
    let o = reserve(store, fx).unwrap();
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &o.attempt,
            owner: "worker-a",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: sc::LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: sc::MAX_AGE,
        })
        .unwrap();
    store.record_exposure(&lease, &actor(), NOW + 2).unwrap();
    store.begin_validation(&lease, &actor(), NOW + 3).unwrap();
    store
        .finish(
            &lease,
            ExecutionOutcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 4,
        )
        .unwrap()
}

/// A store with one provisioned budget and one completed attempt.
pub fn populated_store(db: &TempDb) -> (SqliteStore, Fx, custodian_store::Settlement) {
    let store = open(db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let s = complete(&store, &fx);
    (store, fx, s)
}

/// Records requested sleeps instead of waiting.
#[derive(Default)]
pub struct RecordingSleeper(Mutex<Vec<u64>>);

impl RecordingSleeper {
    pub fn delays(&self) -> Vec<u64> {
        self.0.lock().unwrap().clone()
    }
}

impl Sleeper for RecordingSleeper {
    fn sleep(&self, secs: u64) {
        self.0.lock().unwrap().push(secs);
    }
}

/// A plain temporary directory that removes itself.
pub struct TempDir(PathBuf);

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "custodian-ledger-test-{}-{label}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A synthetic outbox event that does not need a store.
pub fn synthetic_event(seq: u64, payload: &str) -> OutboxEvent {
    use sha2::{Digest, Sha256};
    let digest: String = Sha256::digest(payload.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    OutboxEvent {
        seq,
        event_id: format!("synthetic:{seq}"),
        kind: "attempt.started".to_owned(),
        request_id: None,
        attempt_id: None,
        payload: payload.to_owned(),
        payload_digest: digest,
        chain: "a".repeat(64),
        created_at: NOW + seq,
        exported_at: None,
        export_ref: None,
    }
}
