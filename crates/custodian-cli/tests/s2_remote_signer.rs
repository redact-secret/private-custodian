//! S2: the operator CLI's export path through the isolated signer's real Unix
//! socket. Keys are generated inside each test, written only into a private
//! temporary directory and never printed. Synthetic data only; a valid
//! signature here attests origin and binding of project-maintained records, it
//! is not independent validation.

mod c12;

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use c12::*;
use custodian_cli::command::RepairCommand;
use custodian_cli::deploy::{ConfiguredSigner, UnavailableSigner};
use custodian_cli::Command;
use custodian_ledger::{
    ApprovedPayload, KeyEntry, Keyring, LedgerRecord, RemoteSigner, SignDomain, SignRefusal, Signer,
};
use custodian_signer::{
    start, FileKeyProvider, RunningServer, ServerConfig, SignerSetup, SigningEngine, SystemClock,
    UnixSocketTransport,
};

static N: AtomicU32 = AtomicU32::new(0);

/// A real signer server in a private temp directory.
struct SignerHost {
    dir: PathBuf,
    sock: PathBuf,
    engine: Arc<SigningEngine>,
    server: Option<RunningServer>,
    setup: SignerSetup,
    key_path: PathBuf,
}

impl SignerHost {
    fn new(key_id: &custodian_contracts::types::KeyId) -> Self {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("pcs2-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut b = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut b)
            .unwrap();
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let key_path = dir.join("k");
        std::fs::write(&key_path, hex).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let setup = SignerSetup {
            key_id: key_id.clone(),
            purposes: SignDomain::ALL.into_iter().collect::<BTreeSet<_>>(),
            valid_from: 1,
            not_after: None,
            max_request_skew_secs: 120,
        };
        let engine = Arc::new(
            SigningEngine::new(
                &FileKeyProvider::new(key_path.clone()),
                setup.clone(),
                Arc::new(SystemClock),
                custodian_signer::silent_sink(),
            )
            .unwrap(),
        );
        Self {
            sock: dir.join("s"),
            dir,
            engine,
            server: None,
            setup,
            key_path,
        }
    }

    fn up(&mut self) {
        self.server = Some(
            start(
                ServerConfig {
                    socket_path: self.sock.clone(),
                    allowed_peer_uid: custodian_signer::effective_uid(),
                    io_timeout: Duration::from_secs(3),
                    max_concurrent: 4,
                },
                self.engine.clone(),
            )
            .unwrap(),
        );
    }

    fn down(&mut self) {
        if let Some(s) = self.server.take() {
            s.shutdown();
        }
    }

    /// The harness's pinned roots plus this signer's public key.
    fn roots(&self, base: &Keyring) -> Keyring {
        base.clone().with_root(
            KeyEntry::root(
                self.setup.key_id.clone(),
                self.engine.public_key_hex(),
                SignDomain::ALL,
                cc::ts(1),
            )
            .unwrap(),
        )
    }

    fn remote(&self) -> RemoteSigner<UnixSocketTransport> {
        RemoteSigner::new(
            self.setup.key_id.clone(),
            UnixSocketTransport::new(self.sock.clone(), Duration::from_secs(3)),
        )
    }
}

impl Drop for SignerHost {
    fn drop(&mut self) {
        self.down();
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = &self.key_path;
    }
}

fn export_with(p: &Pipe, signer: &dyn Signer, roots: &Keyring) -> custodian_cli::Output {
    let mut parts = p.w.parts();
    parts.signer = signer;
    parts.roots = roots;
    custodian_cli::Control::new(parts).execute(
        &p.w.principal(Who::Operator),
        &Command::Repair(RepairCommand::Export {
            confirm_store_id: p.w.rw.store.store_id().unwrap(),
        }),
        false,
    )
}

/// A key id distinct from the harness's own, so the combined roots can verify
/// records the harness signed earlier and records the real signer signs.
fn signer_key_id() -> custodian_contracts::types::KeyId {
    custodian_contracts::types::KeyId::parse(&cc::id("key_", 2)).unwrap()
}

fn spent_pipe() -> Pipe {
    let p = Pipe::new(5, 4);
    let (attempt, _) = p.reserve(1);
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    assert!(p.dispatch(&svc, 1, &attempt).unwrap().result.is_some());
    p
}

#[test]
fn export_through_the_real_signer_socket_writes_a_ledger_that_verifies_under_its_public_key() {
    let p = spent_pipe();
    let mut host = SignerHost::new(&signer_key_id());
    host.up();
    let roots = host.roots(&p.w.roots);
    let remote = host.remote();
    assert!(p.w.rw.store.outbox_pending_count().unwrap() > 0);

    let o = export_with(&p, &remote, &roots);
    assert_eq!(o.code(), "exported", "{}", o.render());
    assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), 0);
    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &roots).unwrap();
    assert!(walk.is_trustworthy(), "{:?}", walk.findings);
    assert!(!p.w.ledger.paths().is_empty());
    assert!(host.engine.stats().snapshot().signed > 0);
}

#[test]
fn an_unreachable_signer_makes_export_fail_closed_with_nothing_written_then_it_drains() {
    let p = spent_pipe();
    let mut host = SignerHost::new(&signer_key_id());
    let roots = host.roots(&p.w.roots);
    let remote = host.remote();
    let pending = p.w.rw.store.outbox_pending_count().unwrap();
    assert!(pending > 0);
    let files = p.w.ledger.paths().len();

    // Never started, then started and killed: both fail closed.
    for round in 0..2 {
        let o = export_with(&p, &remote, &roots);
        assert_eq!(
            (o.code(), o.exit_code()),
            ("signer_unavailable", 7),
            "round {round}"
        );
        assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), pending);
        assert_eq!(p.w.ledger.paths().len(), files, "nothing was written");
        if round == 0 {
            host.up();
            host.down();
        }
    }

    // A signer that refuses the key's domains also writes nothing.
    // (A different key id on the client: the signer's answer is not accepted.)
    host.up();
    let other_id = custodian_contracts::types::KeyId::parse(&cc::id("key_", 77)).unwrap();
    let mismatched = RemoteSigner::new(
        other_id,
        UnixSocketTransport::new(host.sock.clone(), Duration::from_secs(3)),
    );
    let o = export_with(&p, &mismatched, &roots);
    assert_eq!(o.code(), "signer_unavailable");
    assert_eq!(p.w.ledger.paths().len(), files);

    // Restored: one pass drains.
    let o = export_with(&p, &remote, &roots);
    assert_eq!(o.code(), "exported", "{}", o.render());
    assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), 0);
}

#[test]
fn a_server_on_the_socket_that_runs_as_the_wrong_uid_is_not_trusted() {
    let p = spent_pipe();
    let mut host = SignerHost::new(&signer_key_id());
    host.up();
    let roots = host.roots(&p.w.roots);
    let me = custodian_signer::effective_uid();
    let strict = RemoteSigner::new(
        host.setup.key_id.clone(),
        UnixSocketTransport::new(host.sock.clone(), Duration::from_secs(3))
            .expecting_signer_uid(me.wrapping_add(1)),
    );
    let files = p.w.ledger.paths().len();
    let o = export_with(&p, &strict, &roots);
    assert_eq!(o.code(), "signer_unavailable");
    assert_eq!(p.w.ledger.paths().len(), files);
}

#[test]
fn the_configured_signer_is_remote_only_when_a_socket_is_configured() {
    let kid = custodian_contracts::types::KeyId::parse(&cc::id("key_", 1)).unwrap();
    let mut host = SignerHost::new(&kid);
    let payload = ApprovedPayload::ledger_record(
        &LedgerRecord::store_checkpoint(
            &custodian_store::Checkpoint {
                seq: 1,
                chain: "c".repeat(64),
            },
            1,
        )
        .unwrap(),
    )
    .unwrap();

    // Absent: refuses with the same fixed code the stub always used.
    let absent = ConfiguredSigner::Unavailable(UnavailableSigner::new(kid.clone()));
    assert!(!absent.is_remote());
    assert_eq!(
        absent.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );

    // Configured but down: the same code.
    let configured = ConfiguredSigner::Remote(host.remote());
    assert!(configured.is_remote());
    assert_eq!(configured.key_id(), &kid);
    assert_eq!(
        configured.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );

    // Configured and up: a signature.
    host.up();
    assert!(configured.sign(&payload).is_ok());
}
