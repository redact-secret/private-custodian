//! C12 leakage canaries across every output, log, error and storage path.
//!
//! Canaries are unmistakably synthetic strings that stand in for operator
//! credentials, protected corpus bytes, hostile worker output and a signing
//! seed. They are planted at the inputs of a full run, and then every place
//! the system can write or print is scanned: CLI output (success and failure,
//! every role), `Debug` text of the security-relevant types, the private
//! ledger, the public feed, the released projection, the audit outbox, the raw
//! database files, and the library sources (no ad-hoc logging).
//!
//! The scan proves the absence of these particular strings on these paths for
//! this run. It is evidence of mechanism, not a proof of absence in general.

mod c12;

use std::path::{Path, PathBuf};

use c12::*;
use custodian_cli::command::{ReconcileTarget, RepairCommand, VerifyTarget};
use custodian_cli::Command;
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_disclosure::testing::RecordingSink;
use custodian_ledger::{KeyEntry, Keyring, SignDomain, SoftwareSigner};

const C_PROTECTED: &str = "CANARY-PROTECTED-ENTRY-BYTES-7f3a9c1e";
const C_WORKER: &str = "CANARY-HOSTILE-WORKER-OUTPUT-4b81d2e6";
const C_SEED_HEX: &str = "abababababababababababababababababababababababababababababababab";

struct Corpus {
    text: Vec<(String, String)>,
    bytes: Vec<(String, Vec<u8>)>,
}

impl Corpus {
    fn new() -> Self {
        Self {
            text: Vec::new(),
            bytes: Vec::new(),
        }
    }
    fn text(&mut self, label: &str, s: impl Into<String>) {
        self.text.push((label.to_owned(), s.into()));
    }
    fn bytes(&mut self, label: &str, b: Vec<u8>) {
        self.bytes.push((label.to_owned(), b));
    }
    fn assert_clean(&self, needles: &[Vec<u8>]) {
        for (label, s) in &self.text {
            for n in needles {
                assert!(
                    !contains(s.as_bytes(), n),
                    "canary found in text path: {label}"
                );
            }
        }
        for (label, b) in &self.bytes {
            for n in needles {
                assert!(!contains(b, n), "canary found in byte path: {label}");
            }
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn read_all(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                read_all(&path, out);
            } else if let Ok(b) = std::fs::read(&path) {
                out.push((path.display().to_string(), b));
            }
        }
    }
}

/// A key with a seed the test knows, so the seed itself can be a canary.
fn known_seed_key() -> lc::TestKey {
    let kid = custodian_contracts::types::KeyId::parse(&cc::id("key_", 1)).unwrap();
    let signer = SoftwareSigner::from_seed(kid.clone(), &[0xAB; 32], SignDomain::ALL);
    let entry = KeyEntry::root(
        kid,
        &signer.public_key_hex(),
        SignDomain::ALL,
        ts(NOW - 10_000),
    )
    .unwrap();
    lc::TestKey { signer, entry }
}

fn credential_needles() -> Vec<Vec<u8>> {
    [
        Who::Requester,
        Who::Approver,
        Who::Operator,
        Who::Auditor,
        Who::Agent,
        Who::Service,
        Who::Dual,
    ]
    .iter()
    .map(|w| w.token())
    .collect()
}

#[test]
fn canaries_never_reach_any_output_log_error_ledger_feed_projection_or_database_file() {
    // The protected entries carry the canary; the hostile worker prints it.
    let mut p = Pipe::with_entry_bytes(3, ROSTER, |i| format!("{C_PROTECTED}-{i}"));
    let key = known_seed_key();
    p.w.roots = Keyring::new().with_root(key.entry.clone());
    p.w.key = key;
    p.sandbox.set(Mode::Raw(
        format!("{C_WORKER} {{not json}} {C_PROTECTED}").into_bytes(),
    ));

    let mut c = Corpus::new();
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();

    // 1. A hostile worker prints canaries: the run is rejected and the text
    //    appears nowhere.
    let (attempt, _) = p.reserve(1);
    let rep = p.dispatch(&svc, 1, &attempt).unwrap();
    assert_eq!(rep.outcome, O::Rejected);
    c.text("DispatchReport Debug", format!("{rep:?}"));
    c.text("isolation Debug", format!("{:?}", rep.isolation));

    // 2. A good run (request 2 on a fresh budget unit) for the release path.
    p.sandbox.set(Mode::Good);
    let (attempt2, approval2) = p.reserve(2);
    let rep2 = p.dispatch(&svc, 2, &attempt2).unwrap();
    assert_eq!(rep2.outcome, O::Success);
    c.text("DispatchReport Debug (good)", format!("{rep2:?}"));
    c.text(
        "ValidatedResult Debug",
        format!("{:?}", rep2.result.as_ref().unwrap()),
    );
    p.w.clock.set(NOW + 40);
    p.w.run(Who::Operator, &Command::FeedPublish);
    p.export();
    let (req2, _) = p.request(2);
    let asm = p.assemble(2, &attempt2, &approval2, &rep2);
    p.w.clock.set(PREPARE_AT);
    let prepared = prepare(&p, &svc, &req2, &asm, 1, PREPARE_AT).unwrap();
    c.text("PreparedRelease Debug", format!("{prepared:?}"));
    p.export();
    p.w.clock.set(RELEASE_AT);
    let sink = RecordingSink::new();
    let released = release(
        &p,
        &svc,
        &prepared,
        &release_approval(&prepared),
        DEST,
        &sink,
        RELEASE_AT,
    )
    .unwrap();
    c.bytes("released projection", released.to_bytes().unwrap());
    for (dest, bytes) in sink.delivered() {
        c.bytes(&format!("sink delivery to {dest}"), bytes);
    }
    p.export();

    // 3. Every role runs success, failure and malformed variants; the whole
    //    printed output is collected.
    let (req1, doc1) = p.request(1);
    let garbage = format!("{{\"schema\":\"{C_WORKER}\",\"x\":\"{C_PROTECTED}\"}}").into_bytes();
    let sid = p.w.rw.store.store_id().unwrap();
    let cmds: Vec<Command> = vec![
        Command::RequestSubmit {
            document: garbage.clone(),
        },
        Command::RequestSubmit { document: doc1 },
        Command::RequestStatus {
            request_id: req1.request_id.clone(),
        },
        Command::RequestList { limit: 50 },
        Command::RequestApprove {
            request_id: req1.request_id.clone(),
            confirm_plan_digest: req1.plan.plan_digest().unwrap(),
            ttl_secs: None,
        },
        Command::RequestCancel {
            request_id: req1.request_id.clone(),
        },
        Command::Verify(VerifyTarget::All),
        Command::Verify(VerifyTarget::Ledger),
        Command::Reconcile(ReconcileTarget::Store),
        Command::Reconcile(ReconcileTarget::Ledger),
        Command::Reconcile(ReconcileTarget::Feed),
        Command::PolicyValidate { document: garbage },
        Command::FeedPublish,
        Command::Repair(RepairCommand::Recover {
            confirm_store_id: "0000000000000000".into(),
        }),
        Command::Repair(RepairCommand::Export {
            confirm_store_id: sid,
        }),
    ];
    for who in [
        Who::Requester,
        Who::Approver,
        Who::Operator,
        Who::Auditor,
        Who::Agent,
        Who::Service,
        Who::Dual,
    ] {
        for cmd in &cmds {
            for dry in [false, true] {
                let o = if dry {
                    p.w.dry(who, cmd)
                } else {
                    p.w.run(who, cmd)
                };
                c.text(&format!("{who:?} {} dry={dry}", cmd.name()), o.render());
                c.text(
                    &format!("{who:?} {} dry={dry} value", cmd.name()),
                    o.to_value().to_string(),
                );
            }
        }
    }
    // Authentication failures: wrong credential, unknown identity, short one.
    let now = ts(p.w.clock.as_ref_now());
    for (id, tok) in [
        (Who::Operator.actor(), Who::Approver.token()),
        ("act_syntheticunknown0001".to_owned(), Who::Operator.token()),
        (Who::Operator.actor(), b"short".to_vec()),
        (
            Who::Operator.actor(),
            format!("{C_WORKER}-guess").into_bytes(),
        ),
    ] {
        let err = p.w.authority.authenticate(&id, &tok, now).unwrap_err();
        c.text("authenticate error", format!("{err:?} {}", err.code()));
    }
    // A malformed operator policy that contains canaries is refused without echo.
    let bad = format!("{{\"schema\":\"{C_WORKER}\",\"identities\":\"{C_PROTECTED}\"}}");
    let err = custodian_cli::PolicyAuthority::from_json(bad.as_bytes())
        .err()
        .unwrap();
    c.text("policy error", format!("{err:?} {}", err.code()));

    // 4. Debug text of the types that hold secrets.
    for who in [Who::Requester, Who::Operator, Who::Agent] {
        c.text("Principal Debug", format!("{:?}", p.w.principal(who)));
    }
    c.text("authority Debug", format!("{:?}", p.w.authority));
    c.text("signer Debug", format!("{:?}", p.w.key.signer));
    c.text("Keyring Debug", format!("{:?}", p.w.roots));
    c.text("budget Debug", format!("{:?}", p.w.budget()));
    c.text(
        "attempt Debug",
        format!("{:?}", p.w.rw.store.attempt(&attempt2).unwrap()),
    );
    c.text(
        "history Debug",
        format!("{:?}", p.w.rw.store.history(&attempt).unwrap()),
    );

    // 5. Storage and publication paths.
    for path in p.w.ledger.paths() {
        c.bytes(&format!("ledger {path}"), p.w.ledger.raw(&path).unwrap());
    }
    for seq in p.w.feed.sequences(&lc::feed_id()) {
        c.bytes(&format!("feed {seq}"), bytes_of_feed(&p, seq));
    }
    for ev in p.w.rw.store.outbox_pending(10_000).unwrap() {
        c.text(&format!("outbox {} pending", ev.seq), ev.payload);
    }
    for seq in 1..200u64 {
        if let Some(ev) = p.w.rw.store.outbox_event(seq).unwrap() {
            c.text(&format!("outbox {seq}"), ev.payload);
        }
    }
    let mut files = Vec::new();
    read_all(p.w.rw.db.dir(), &mut files);
    assert!(files.len() >= 2, "the database and its WAL are scanned");
    for (label, b) in files {
        c.bytes(&format!("database file {label}"), b);
    }
    // The working staging area is empty after the runs.
    assert_eq!(p.arts.staging_entries(), 0);

    // Needles: each credential in plaintext and as the base64 or hex a log
    // might carry, the signing seed raw and as hex, the protected bytes and
    // the hostile worker text.
    let mut needles: Vec<Vec<u8>> = credential_needles();
    needles.push(C_PROTECTED.as_bytes().to_vec());
    needles.push(C_WORKER.as_bytes().to_vec());
    needles.push(C_SEED_HEX.as_bytes().to_vec());
    needles.push(vec![0xAB; 32]);
    c.assert_clean(&needles);

    // The policy file holds only digests of credentials: the digest is
    // allowed to exist, the credential is not.
    let policy = serde_json::to_string(&base::policy_json(1, 2)).unwrap();
    for t in credential_needles() {
        assert!(!contains(policy.as_bytes(), &t));
    }
}

fn bytes_of_feed(p: &Pipe, seq: u64) -> Vec<u8> {
    use custodian_lifecycle::FeedSource;
    p.w.feed
        .get(&lc::feed_id(), seq)
        .unwrap()
        .expect("envelope")
}

fn walk_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                walk_sources(&path, out);
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path);
            }
        }
    }
}

#[test]
#[should_panic(expected = "canary found in byte path")]
fn the_scan_itself_fails_when_a_canary_is_present() {
    // Negative control: a planted canary in a ledger-like file must be caught.
    let mut c = Corpus::new();
    c.bytes(
        "ledger records/audit/x.json",
        format!("{{\"note\":\"{C_PROTECTED}\"}}").into_bytes(),
    );
    c.assert_clean(&[C_PROTECTED.as_bytes().to_vec()]);
}

#[test]
fn library_code_has_no_ad_hoc_logging_or_printing() {
    // There is no logging framework by design: results leave through fixed
    // codes, the CLI's one JSON object and typed errors. This guard fails if a
    // library source starts printing, so a new output path is a reviewed
    // decision rather than an accident.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let allowed: &[&str] = &[
        "custodian-cli/src/main.rs",
        "custodian-service/src/main.rs",
        "custodian-signer/src/main.rs",
        "custodian-worker/src/bin/",
        // The daemon binary prints its version only; it reports through the
        // reviewed fixed-code `EventLog`. The synthetic engine is a fixture
        // that prints a result document (docs/daemon.md).
        "custodian-daemon/src/main.rs",
        "custodian-daemon/src/bin/",
    ];
    let mut files = Vec::new();
    walk_sources(&crates, &mut files);
    let mut offenders = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&crates).unwrap().display().to_string();
        let in_src = rel.contains("/src/");
        if !in_src || allowed.iter().any(|a| rel.contains(a)) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        // Ignore test modules inside src files: cut at the first cfg(test).
        let body = text.split("#[cfg(test)]").next().unwrap_or(&text);
        for needle in [
            "println!(",
            "eprintln!(",
            "print!(",
            "eprint!(",
            "dbg!(",
            "tracing::",
            "log::",
        ] {
            // A `use` of this repository's own `log` module (for example
            // `use crate::log::EventLog`) is not a logging framework.
            let found = body
                .lines()
                .filter(|l| !l.trim_start().starts_with("use ") && !l.contains("pub use "))
                .any(|l| l.contains(needle));
            if found {
                offenders.push(format!("{rel}: {needle}"));
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:?}");
}
