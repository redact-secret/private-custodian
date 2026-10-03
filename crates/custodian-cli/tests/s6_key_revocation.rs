//! S6 (ADR 0131): recovering from a compromised signing key (R-4) through the
//! operator CLI: record the revocation, re-attest the history under the new
//! key without rewriting anything, clear the audited block, and start again.
//!
//! Keys are generated inside each test and never written down. Synthetic data
//! only; functional verification, not an independent protected evaluation.

mod c12;

use std::collections::BTreeMap;

use c12::*;
use custodian_cli::command::{RepairCommand, VerifyTarget};
use custodian_cli::{CliReason, Command, Service};
use custodian_contracts::types::KeyId;
use custodian_ledger::{Exporter, Keyring, LedgerRecord, SignDomain, Signer, Verifier};
use serde_json::Value;

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn text(o: &custodian_cli::Output, key: &str) -> String {
    o.field(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn spend(p: &Pipe, n: u32) {
    let (attempt, _) = p.reserve(n);
    let acts = p.activations();
    let svc = p.start(&acts).unwrap();
    assert!(p.dispatch(&svc, n, &attempt).unwrap().result.is_some());
    assert_eq!(code(&p.export()), "exported");
}

fn snapshot(p: &Pipe) -> BTreeMap<String, Vec<u8>> {
    p.w.ledger
        .paths()
        .into_iter()
        .map(|f| {
            let b = p.w.ledger.raw(&f).unwrap();
            (f, b)
        })
        .collect()
}

fn revoke(key: &KeyId) -> Command {
    Command::Repair(RepairCommand::RevokeKey {
        key: key.clone(),
        confirm_key: key.clone(),
    })
}

fn reissue(old: &KeyId, new: &KeyId, digest: &str) -> Command {
    Command::Repair(RepairCommand::ReissueLedger {
        confirm_revoked_key: old.clone(),
        confirm_new_key: new.clone(),
        confirm_plan_digest: digest.to_owned(),
    })
}

/// The compromise, at the point the procedure starts: the history is signed
/// by the old key; a new key was generated on the signer host and pinned out
/// of band next to the old root, and the signer now signs as the new key.
fn compromised() -> (Pipe, KeyId, KeyId) {
    let mut p = Pipe::new(5, 4);
    spend(&p, 1);
    let old = p.w.key.signer.key_id().clone();
    let next = lc::test_key(2, &SignDomain::ALL);
    let new = next.signer.key_id().clone();
    p.w.roots = Keyring::new()
        .with_root(p.w.key.entry.clone())
        .with_root(next.entry.clone());
    p.w.key = next;
    p.w.clock.set(NOW + 1_000);
    (p, old, new)
}

#[test]
fn a_compromised_key_is_revoked_reissued_and_the_control_plane_starts_again() {
    let (p, old, new) = compromised();

    // Containment: only a human operator can record the revocation, the
    // confirmation must name the same key, and the signer must be the new key.
    assert_eq!(code(&p.w.run(Who::Approver, &revoke(&old))), "forbidden");
    assert_eq!(
        code(&p.w.run(Who::Agent, &revoke(&old))),
        "agent_not_permitted"
    );
    let mismatch = Command::Repair(RepairCommand::RevokeKey {
        key: old.clone(),
        confirm_key: new.clone(),
    });
    assert_eq!(
        code(&p.w.run(Who::Operator, &mismatch)),
        "confirmation_mismatch"
    );
    assert_eq!(code(&p.w.dry(Who::Operator, &revoke(&old))), "would_revoke");
    assert_eq!(code(&p.w.run(Who::Operator, &revoke(&old))), "revoked");
    assert_eq!(
        code(&p.w.run(Who::Operator, &revoke(&old))),
        "already_revoked"
    );

    // The old lineage is untrusted: the control plane refuses to start and
    // the store is write-blocked (the documented consequence).
    let o = p.submit(2);
    assert_eq!((code(&o), o.exit_code()), ("ledger_untrusted", 8));
    assert!(p.w.rw.store.needs_reconcile().unwrap());

    // The plan: every record signed by the old key, all corroborated by the
    // store, none rewritten yet.
    let plan =
        p.w.run(Who::Operator, &Command::Repair(RepairCommand::ReissuePlan));
    assert_eq!(code(&plan), "planned", "{}", plan.render());
    assert_eq!(
        plan.field("uncorroborated").and_then(Value::as_u64),
        Some(0)
    );
    let n = plan
        .field("records_to_reissue")
        .and_then(Value::as_u64)
        .unwrap();
    assert!(n >= 5);
    let digest = text(&plan, "plan_digest");

    // Exact confirmations: wrong digest, wrong keys, wrong role.
    let refused = |cmd: &Command, who: Who| {
        let o = p.w.run(who, cmd);
        (code(&o), text(&o, "refusal"))
    };
    assert_eq!(
        refused(&reissue(&old, &new, "sha256:nope"), Who::Operator),
        ("reissue_refused", "reissue_confirmation_mismatch".into())
    );
    assert_eq!(
        refused(&reissue(&new, &old, &digest), Who::Operator),
        ("reissue_refused", "reissue_confirmation_mismatch".into())
    );
    assert_eq!(
        refused(&reissue(&old, &new, &digest), Who::Approver).0,
        "forbidden"
    );

    // Re-attest. Nothing that existed is touched; the old files stay.
    let before = snapshot(&p);
    let done = p.w.run(Who::Operator, &reissue(&old, &new, &digest));
    assert_eq!(code(&done), "reissued", "{}", done.render());
    assert_eq!(
        done.field("reissued").and_then(Value::as_u64),
        Some(n),
        "every planned record"
    );
    let after = snapshot(&p);
    for (path, bytes) in &before {
        assert_eq!(after.get(path), Some(bytes), "{path} was altered");
    }
    assert!(after.len() > before.len());

    // The verifier walks both lineages. The old records are marked; the
    // ledger is trustworthy again.
    let v =
        p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::Ledger));
    assert_eq!(code(&v), "verified", "{}", v.render());
    let codes = v
        .field("ledger_finding_codes")
        .and_then(Value::as_array)
        .unwrap();
    assert!(codes.iter().any(|c| c == "revoked_superseded"));
    assert_eq!(v.field("ledger_trustworthy"), Some(&Value::Bool(true)));

    // The block set by the refusal is cleared only by the audited exact
    // confirmation (the store really contains the checkpoint).
    assert!(p.w.rw.store.needs_reconcile().unwrap());
    let clear = Command::Repair(RepairCommand::ClearReconcile {
        confirm_store_id: p.w.rw.store.store_id().unwrap(),
        confirm_checkpoint_seq: p.w.rw.store.latest_checkpoint().unwrap().unwrap().seq,
    });
    assert_eq!(code(&p.w.run(Who::Operator, &clear)), "cleared");

    // The control plane starts, writes resume under the new key, and the
    // whole verification passes.
    {
        let acts = p.activations();
        p.start(&acts).expect("starts after the re-issue");
    }
    spend(&p, 2);
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified"
    );
    // Nothing is left to re-issue.
    let again =
        p.w.run(Who::Operator, &Command::Repair(RepairCommand::ReissuePlan));
    assert_eq!(text(&again, "refusal"), "reissue_nothing_to_reissue");
}

#[test]
fn a_record_made_with_the_stolen_key_that_the_store_never_produced_is_not_laundered() {
    let mut q = Pipe::new(5, 4);
    spend(&q, 1);
    let old_id = q.w.key.signer.key_id().clone();
    // The attacker, holding the old key, appends an audit record the store
    // never produced, before the compromise is noticed.
    let payload = r#"{"event":"attempt.terminal","units":1}"#;
    let forged = LedgerRecord::audit_event(&custodian_store::OutboxEvent {
        seq: 900,
        event_id: "forged:900".to_owned(),
        kind: "attempt.terminal".to_owned(),
        request_id: None,
        attempt_id: None,
        payload: payload.to_owned(),
        payload_digest: sha_hex(payload.as_bytes()),
        chain: "a".repeat(64),
        created_at: NOW + 500,
        exported_at: None,
        export_ref: None,
    })
    .unwrap();
    let verifier = Verifier::new(q.w.roots.clone());
    Exporter::new(&q.w.ledger, &q.w.key.signer, &verifier)
        .write_record(&forged)
        .unwrap();
    // The procedure: pin a new key, sign as it, revoke the old one.
    let next = lc::test_key(2, &SignDomain::ALL);
    let new_id = next.signer.key_id().clone();
    q.w.roots = Keyring::new()
        .with_root(q.w.key.entry.clone())
        .with_root(next.entry.clone());
    q.w.key = next;
    q.w.clock.set(NOW + 1_000);
    assert_eq!(code(&q.w.run(Who::Operator, &revoke(&old_id))), "revoked");

    let plan =
        q.w.run(Who::Operator, &Command::Repair(RepairCommand::ReissuePlan));
    assert_eq!(code(&plan), "reissue_refused");
    assert_eq!(text(&plan, "refusal"), "reissue_contradicted_by_store");
    let n = q.w.ledger.file_count();
    let done =
        q.w.run(Who::Operator, &reissue(&old_id, &new_id, "sha256:nope"));
    assert_eq!(code(&done), "reissue_refused");
    assert_eq!(q.w.ledger.file_count(), n, "a refused step writes nothing");
    // The control plane stays down.
    let acts = q.activations();
    let err = Service::start(q.w.parts(), &startup_config(), &acts)
        .err()
        .unwrap();
    assert_eq!(err.reason, CliReason::LedgerUntrusted);
}

#[test]
fn a_new_key_valid_only_from_now_cannot_reattest_older_history() {
    // R-6, enforced by the tool: the new key was pinned with a start time
    // after the oldest record, so the revocation itself is refused.
    let mut p = Pipe::new(5, 4);
    spend(&p, 1);
    let old = p.w.key.signer.key_id().clone();
    let late = custodian_cli_test_key_valid_from(NOW + 5_000);
    p.w.roots = Keyring::new()
        .with_root(p.w.key.entry.clone())
        .with_root(late.entry.clone());
    p.w.key = late;
    p.w.clock.set(NOW + 6_000);
    // The revocation is a key event dated now, which the late key may sign:
    assert_eq!(code(&p.w.run(Who::Operator, &revoke(&old))), "revoked");
    // But re-attesting history dated before its start is refused.
    let plan =
        p.w.run(Who::Operator, &Command::Repair(RepairCommand::ReissuePlan));
    assert_eq!(code(&plan), "planned");
    let new = p.w.key.signer.key_id().clone();
    let digest = text(&plan, "plan_digest");
    let o = p.w.run(Who::Operator, &reissue(&old, &new, &digest));
    assert_eq!(code(&o), "reissue_refused");
    assert_eq!(text(&o, "refusal"), "reissue_new_key_not_valid_for_history");
    assert!(!custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots)
        .unwrap()
        .is_trustworthy());
}

/// A test key that is valid only from `from`.
fn custodian_cli_test_key_valid_from(from: u64) -> lc::TestKey {
    use custodian_ledger::{KeyEntry, SoftwareSigner};
    let base = lc::test_key(3, &SignDomain::ALL);
    let kid = base.signer.key_id().clone();
    let entry = KeyEntry::root(
        kid,
        &base.signer.public_key_hex(),
        SignDomain::ALL,
        lc::ts(from),
    )
    .unwrap();
    let _: &SoftwareSigner = &base.signer;
    lc::TestKey {
        signer: base.signer,
        entry,
    }
}
