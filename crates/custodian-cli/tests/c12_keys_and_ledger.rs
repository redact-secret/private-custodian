//! C12: ledger rollback and tamper, export and signer outages, and the signing
//! key rotation and revocation flow, end to end with test-generated keys.
//!
//! Keys are generated inside each test and are never written down. Synthetic
//! data only. A valid signature here attests origin and binding of
//! project-maintained records; it is not independent validation.

mod c12;

use std::collections::BTreeSet;

use c12::*;
use custodian_cli::command::{ReconcileTarget, RepairCommand, VerifyTarget};
use custodian_cli::{CliReason, Command, Service};
use custodian_contracts::types::KeyId;
use custodian_ledger::record::{KeyAction, KeyEventBody};
use custodian_ledger::{
    ApprovedPayload, Exporter, Keyring, LedgerRecord, SignDomain, SignRefusal, Signer,
    SoftwareSigner, Verifier,
};

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn spend(p: &Pipe, n: u32) {
    let (attempt, _) = p.reserve(n);
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    assert!(p.dispatch(&svc, n, &attempt).unwrap().result.is_some());
    assert_eq!(code(&p.export()), "exported");
}

fn audit_file_count(p: &Pipe) -> usize {
    p.w.ledger
        .paths()
        .iter()
        .filter(|f| f.starts_with("records/audit/"))
        .count()
}

/// The audit record file with the lowest sequence number.
fn lowest_audit_path(p: &Pipe) -> String {
    let mut all: Vec<(u64, String)> = p
        .w
        .ledger
        .paths()
        .into_iter()
        .filter(|f| f.starts_with("records/audit/"))
        .map(|f| {
            let rec = custodian_ledger::SignedLedgerRecord::decode_canonical(&p.w.ledger.raw(&f).unwrap()).unwrap();
            match rec.payload.body {
                custodian_ledger::record::RecordBody::AuditEvent(b) => (b.seq, f),
                _ => unreachable!(),
            }
        })
        .collect();
    all.sort();
    all.remove(0).1
}

fn snapshot(p: &Pipe) -> BTreeSet<String> {
    p.w.ledger.paths().into_iter().collect()
}

// ---- ledger rollback and tamper ------------------------------------------------------

#[test]
fn a_ledger_rolled_back_to_an_older_state_is_found_by_the_independent_copy_and_repaired() {
    let p = Pipe::new(5, 4);
    spend(&p, 1);
    let old = snapshot(&p);
    spend(&p, 2);
    // The independent checkpoint copy, recorded where neither the ledger
    // writer nor this host can change it (here: a local value).
    let independent = p.w.rw.store.latest_checkpoint().unwrap().unwrap();

    // A history rewrite: everything exported after the first snapshot is gone,
    // and what remains still verifies on its own.
    for path in p.w.ledger.paths() {
        if !old.contains(&path) {
            p.w.ledger.remove(&path);
        }
    }
    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    assert!(walk.is_trustworthy(), "a clean prefix looks trustworthy by itself");
    let ledger_head = walk.store_checkpoint.unwrap();
    assert!(
        ledger_head.seq < independent.seq,
        "only the independent copy shows the rollback"
    );

    // The runtime store is ahead of the rolled-back ledger, which startup
    // accepts (the store is not behind), but `reconcile ledger` does not call
    // it consistent: the store holds acknowledgements for records the ledger
    // no longer has.
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::Checkpoint))),
        "verified"
    );
    let rec = p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger));
    assert_ne!(code(&rec), "consistent", "{}", rec.render());

    // The designed repair re-writes identical bytes (signatures are
    // deterministic) and acknowledges; a conflicting record is never touched.
    let fix = p.w.run(
        Who::Operator,
        &Command::Repair(RepairCommand::LedgerReconcile {
            confirm_store_id: p.w.rw.store.store_id().unwrap(),
        }),
    );
    assert!(fix.is_ok(), "{}", fix.render());
    assert_eq!(code(&p.export()), "exported");
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger))),
        "consistent"
    );
    let after = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    assert!(after.is_trustworthy());
    assert!(after.store_checkpoint.unwrap().seq >= independent.seq);
    assert!(
        !p.w.ledger.paths().iter().any(|f| f.starts_with("quarantine/")),
        "nothing conflicted"
    );
}

#[test]
fn a_hole_a_forged_record_or_a_foreign_signature_in_the_ledger_blocks_the_store() {
    // Remove one audit record from the middle: a sequence gap.
    let p = Pipe::new(5, 4);
    spend(&p, 1);
    let victim = lowest_audit_path(&p);
    p.w.ledger.remove(&victim);
    let o = p.submit(2);
    assert_eq!((code(&o), o.exit_code()), ("ledger_untrusted", 8));
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    let acts = p.activations();
    let err = Service::start(p.w.parts(), &startup_config(), &acts).err().unwrap();
    assert_eq!(
        err.reason,
        CliReason::LedgerUntrusted,
        "the ledger is checked before the block is even consulted"
    );

    // A record signed by an unknown key is a finding, not a prefix.
    let q = Pipe::new(5, 4);
    spend(&q, 1);
    let foreign = lc::test_key(9, &SignDomain::ALL);
    let rec = LedgerRecord::store_checkpoint(
        &custodian_store::Checkpoint {
            seq: 1,
            chain: "a".repeat(64),
        },
        NOW,
    )
    .unwrap();
    let sig = foreign
        .signer
        .sign(&ApprovedPayload::ledger_record(&rec).unwrap())
        .unwrap();
    let signed = custodian_ledger::SignedLedgerRecord {
        payload: rec,
        signature: sig,
    };
    q.w.ledger.inject(
        &format!("records/store-checkpoint/{}.json", signed.payload.record_id),
        &signed.canonical_bytes().unwrap(),
    );
    let o = q.submit(2);
    assert_eq!((code(&o), o.exit_code()), ("ledger_untrusted", 8));
}

// ---- export and signer outages --------------------------------------------------------

struct RefusingSigner(KeyId);

impl Signer for RefusingSigner {
    fn key_id(&self) -> &KeyId {
        &self.0
    }
    fn sign(
        &self,
        _: &ApprovedPayload,
    ) -> Result<custodian_contracts::common::Signature, SignRefusal> {
        Err(SignRefusal::SignerUnavailable)
    }
}

#[test]
fn export_and_signer_outages_keep_events_pending_and_disclosure_closed_then_drain() {
    let p = Pipe::new(5, 4);
    let (attempt, _) = p.reserve(1);
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    assert!(p.dispatch(&svc, 1, &attempt).unwrap().result.is_some());

    // The ledger is down for several passes: nothing is lost, nothing is
    // acknowledged, and the disclosure precondition stays closed.
    p.w.ledger.set_available(false);
    let pending = p.w.rw.store.outbox_pending_count().unwrap();
    assert!(pending > 0);
    for _ in 0..3 {
        let o = p.export();
        assert_eq!((code(&o), o.exit_code()), ("ledger_unavailable", 7));
        assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), pending);
    }
    assert!(p.w.rw.store.check_disclosure_precondition(&attempt).is_err());
    // The budget is exactly what the run spent; an outage resets nothing.
    let b = p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
    p.w.ledger.set_available(true);

    let files_before = audit_file_count(&p);
    // The signer is unreachable: the export errors, nothing is written, the
    // events stay pending.
    let refusing = RefusingSigner(p.w.key.signer.key_id().clone());
    let mut parts = p.w.parts();
    parts.signer = &refusing;
    let o = custodian_cli::Control::new(parts).execute(
        &p.w.principal(Who::Operator),
        &Command::Repair(RepairCommand::Export {
            confirm_store_id: p.w.rw.store.store_id().unwrap(),
        }),
        false,
    );
    assert_eq!((code(&o), o.exit_code()), ("signer_unavailable", 7));
    assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), pending);
    assert_eq!(audit_file_count(&p), files_before, "nothing was written");

    // Everything is restored: one pass drains, in order, and the gate opens.
    assert_eq!(code(&p.export()), "exported");
    assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), 0);
    p.w.rw.store.check_disclosure_precondition(&attempt).unwrap();
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified"
    );
}

// ---- signing key rotation and revocation -------------------------------------------------

fn publish_key(p: &Pipe, signer_of_event: &SoftwareSigner, new: &lc::TestKey, at: u64) {
    let verifier = Verifier::new(p.w.roots.clone());
    let exporter = Exporter::new(&p.w.ledger, signer_of_event, &verifier);
    let record = LedgerRecord::key_event(
        KeyEventBody {
            key_id: new.signer.key_id().clone(),
            action: KeyAction::Published,
            public_key: Some(new.signer.public_key_hex()),
            purposes: SignDomain::ALL.to_vec(),
            effective_at: ts(at),
        },
        at,
    )
    .unwrap();
    exporter.write_record(&record).unwrap();
}

fn key_event(p: &Pipe, signer: &SoftwareSigner, key_id: &KeyId, action: KeyAction, at: u64) {
    // The signing key must be trusted by the ledger as it stands: build the
    // verifier from the walked keyring, as the control plane does.
    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    let verifier = Verifier::new(walk.keyring);
    let exporter = Exporter::new(&p.w.ledger, signer, &verifier);
    let record = LedgerRecord::key_event(
        KeyEventBody {
            key_id: key_id.clone(),
            action,
            public_key: None,
            purposes: vec![],
            effective_at: ts(at),
        },
        at,
    )
    .unwrap();
    exporter.write_record(&record).unwrap();
}

#[test]
fn key_rotation_continues_the_chain_of_trust_from_the_one_pinned_root() {
    let mut p = Pipe::new(5, 4);
    spend(&p, 1);
    let root_key_id = p.w.key.signer.key_id().clone();

    // On the signer host (here: in the test) a second key is generated and
    // published by a key event signed by the pinned root.
    let next = lc::test_key(2, &SignDomain::ALL);
    p.w.clock.set(NOW + 1_000);
    publish_key(&p, &p.w.key.signer, &next, NOW + 1_000);
    // The signer switches to the new key. The pinned roots are unchanged:
    // the verifier learns the new key only from the verified key event.
    let old_signer_seed_owner = std::mem::replace(&mut p.w.key, next);
    // Retire the old key at the switch time, signed by the new key.
    key_event(
        &p,
        &p.w.key.signer,
        &root_key_id,
        KeyAction::Retired,
        NOW + 1_001,
    );
    p.w.clock.set(NOW + 1_100);

    // Work continues under the new key; the whole ledger, old and new
    // records, verifies against the single pinned root.
    spend(&p, 2);
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified"
    );
    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    assert!(walk.is_trustworthy(), "{:?}", walk.findings);
    assert_eq!(walk.keyring.len(), 2);

    // The retired key can no longer produce records that verify for later
    // times: a late record signed by it is a finding.
    let late = LedgerRecord::store_checkpoint(
        &custodian_store::Checkpoint { seq: 1, chain: "b".repeat(64) },
        NOW + 2_000,
    )
    .unwrap();
    let sig = old_signer_seed_owner
        .signer
        .sign(&ApprovedPayload::ledger_record(&late).unwrap())
        .unwrap();
    let signed = custodian_ledger::SignedLedgerRecord { payload: late, signature: sig };
    p.w.ledger.inject(
        &format!("records/store-checkpoint/{}.json", signed.payload.record_id),
        &signed.canonical_bytes().unwrap(),
    );
    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    assert!(!walk.is_trustworthy(), "a retired key cannot sign later records");
}

#[test]
fn publishing_and_retiring_in_the_same_second_fails_closed_so_rotation_needs_distinct_times() {
    // Observed during the C12 drill and recorded as register entry G-R5: the
    // walker applies key events in (issued_at, record id) order and a retire
    // whose effective time equals the publish record's own issue time also
    // invalidates that publish record. Either way the result is a finding and
    // the control plane refuses to start: it fails closed. The rotation
    // procedure therefore separates publish, switch and retire in time.
    let mut p = Pipe::new(5, 4);
    spend(&p, 1);
    let first_id = p.w.key.signer.key_id().clone();
    let next = lc::test_key(2, &SignDomain::ALL);
    publish_key(&p, &p.w.key.signer, &next, NOW + 1_000);
    let _old = std::mem::replace(&mut p.w.key, next);
    key_event(&p, &p.w.key.signer, &first_id, KeyAction::Retired, NOW + 1_000);
    let o = p.submit(2);
    assert_eq!((code(&o), o.exit_code()), ("ledger_untrusted", 8));
}

#[test]
fn events_still_pending_when_the_signer_switches_cannot_be_signed_by_the_new_key() {
    // Register entry G-R6: a key signs only records issued at or after its
    // own start. Audit events keep the time they happened, so an outbox
    // backlog that is exported after the switch is refused by the exporter's
    // self-check. The rotation procedure therefore drains the outbox first
    // (or declares the new key valid from before the oldest pending event).
    let mut p = Pipe::new(5, 4);
    p.reserve(1);
    assert!(p.w.rw.store.outbox_pending_count().unwrap() > 0);
    let next = lc::test_key(2, &SignDomain::ALL);
    publish_key(&p, &p.w.key.signer, &next, NOW + 1_000);
    p.w.key = next;
    p.w.clock.set(NOW + 1_100);
    let o = p.export();
    assert!(!o.is_ok(), "{}", o.render());
    assert!(p.w.rw.store.outbox_pending_count().unwrap() > 0, "nothing is lost, only blocked");
}

#[test]
fn a_key_known_only_from_the_ledger_is_not_trusted_without_a_pinned_root_or_a_chain() {
    let p = Pipe::new(5, 4);
    spend(&p, 1);
    // A stranger publishes a key event signed by a key nobody pinned.
    let stranger = lc::test_key(7, &SignDomain::ALL);
    let evil = lc::test_key(8, &SignDomain::ALL);
    let verifier = Verifier::new(Keyring::new().with_root(stranger.entry.clone()));
    let exporter = Exporter::new(&p.w.ledger, &stranger.signer, &verifier);
    let record = LedgerRecord::key_event(
        KeyEventBody {
            key_id: evil.signer.key_id().clone(),
            action: KeyAction::Published,
            public_key: Some(evil.signer.public_key_hex()),
            purposes: SignDomain::ALL.to_vec(),
            effective_at: ts(NOW),
        },
        NOW,
    )
    .unwrap();
    exporter.write_record(&record).unwrap();
    let o = p.submit(2);
    assert_eq!((code(&o), o.exit_code()), ("ledger_untrusted", 8));
}

#[test]
fn revoking_the_signing_key_makes_its_history_untrusted_until_it_is_reissued() {
    // Documented consequence (ADR 0050, docs/ledger.md): a revocation rejects
    // every signature by the key, past ones included. The control plane then
    // refuses to start on that ledger. There is no bulk re-issue tool yet;
    // recorded as register entry G-R4 in docs/release-readiness.md.
    let mut p = Pipe::new(5, 4);
    spend(&p, 1);
    let first_id = p.w.key.signer.key_id().clone();
    let next = lc::test_key(2, &SignDomain::ALL);
    publish_key(&p, &p.w.key.signer, &next, NOW + 1_000);
    let _old = std::mem::replace(&mut p.w.key, next);
    key_event(&p, &p.w.key.signer, &first_id, KeyAction::Revoked, NOW + 1_001);

    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    assert!(!walk.is_trustworthy());
    assert!(walk.findings.iter().all(|f| matches!(
        f.code,
        custodian_ledger::FindingCode::BadSignature(custodian_ledger::VerifyError::KeyRevoked)
            | custodian_ledger::FindingCode::SeqGap
            | custodian_ledger::FindingCode::ChainMismatch
    )), "{:?}", walk.findings);
    let o = p.submit(2);
    assert_eq!((code(&o), o.exit_code()), ("ledger_untrusted", 8));
    assert!(p.w.rw.store.needs_reconcile().unwrap());
}
