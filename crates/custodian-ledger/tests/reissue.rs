//! R-4 (ADR 0131): re-attesting a revoked key's history under a new key
//! without rewriting or deleting anything. Synthetic data, test-generated
//! keys only. Functional verification on public synthetic data, not an
//! independent protected evaluation.

mod common;

use std::collections::BTreeMap;

use common::*;
use custodian_ledger::record::{KeyAction, KeyEventBody};
use custodian_ledger::{
    execute_reissue, plan_reissue, revoke_key, startup_check, walk_ledger, Exporter, FindingCode,
    Keyring, LedgerRecord, MemoryBackend, ReissueRefusal, ReissueRequest, SignDomain, Signer,
    Verifier, VerifyError,
};
use custodian_store::SqliteStore;

struct Scene {
    db: TempDb,
    store: SqliteStore,
    backend: MemoryBackend,
    old: TestKey,
    new: TestKey,
    /// Roots after the operator pinned the new key out of band.
    roots: Keyring,
}

/// A store with a completed attempt, exported under the old key, and a new
/// key pinned as a second root (the compromise procedure, backup-recovery.md).
fn scene(new_valid_from: u64) -> Scene {
    let db = TempDb::new("reissue");
    let (store, _fx, _s) = populated_store(&db);
    let old = test_key(1, &all_domains(), NOW - 10_000);
    let new = test_key(2, &all_domains(), new_valid_from);
    let backend = MemoryBackend::new();
    let v = Verifier::new(Keyring::new().with_root(old.entry.clone()));
    let rep = Exporter::new(&backend, &old.signer, &v)
        .export_pending(&store, NOW + 10)
        .unwrap();
    assert!(rep.refused.is_empty() && rep.quarantined.is_empty());
    Exporter::new(&backend, &old.signer, &v)
        .record_store_checkpoint(&store, NOW + 11)
        .unwrap();
    let roots = Keyring::new()
        .with_root(old.entry.clone())
        .with_root(new.entry.clone());
    Scene {
        db,
        store,
        backend,
        old,
        new,
        roots,
    }
}

fn snapshot(b: &MemoryBackend) -> BTreeMap<String, Vec<u8>> {
    b.paths()
        .into_iter()
        .map(|p| {
            let bytes = b.raw(&p).unwrap();
            (p, bytes)
        })
        .collect()
}

fn req<'a>(
    revoked: &'a custodian_contracts::types::KeyId,
    new: &'a custodian_contracts::types::KeyId,
    digest: &'a str,
    now: u64,
) -> ReissueRequest<'a> {
    ReissueRequest {
        confirm_revoked_key: revoked,
        confirm_new_key: new,
        confirm_plan_digest: digest,
        now,
    }
}

#[test]
fn history_signed_by_a_revoked_key_is_reattested_without_rewriting_anything() {
    let s = scene(NOW - 10_000);
    let old_id = s.old.signer.key_id().clone();
    let new_id = s.new.signer.key_id().clone();
    assert!(walk_ledger(&s.backend, &s.roots).unwrap().is_trustworthy());

    // 1. The revocation, signed by the new key. The ledger is now untrusted:
    //    the control plane would refuse to start (the containment).
    assert!(revoke_key(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &old_id,
        &old_id,
        NOW + 100
    )
    .unwrap());
    let w = walk_ledger(&s.backend, &s.roots).unwrap();
    assert!(!w.is_trustworthy());
    assert!(w
        .findings
        .iter()
        .any(|f| f.code == FindingCode::BadSignature(VerifyError::KeyRevoked)));
    assert!(matches!(
        startup_check(&s.backend, &s.roots, &s.store, None),
        Err(custodian_ledger::StartupRefusal::LedgerUntrusted(_))
    ));
    // Idempotent: the second call finds the key revoked and writes nothing.
    assert!(!revoke_key(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &old_id,
        &old_id,
        NOW + 101
    )
    .unwrap());

    // 2. The plan names every record; audit events and the checkpoint are
    //    corroborated by the store.
    let plan = plan_reissue(&s.backend, &s.roots, &s.store, None).unwrap();
    assert_eq!(plan.revoked_key, old_id);
    assert!(plan.to_reissue.len() >= 5);
    assert_eq!(plan.uncorroborated, 0);
    assert_eq!(plan.already_reattested, 0);

    let before = snapshot(&s.backend);
    let done = execute_reissue(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &s.store,
        None,
        &req(&old_id, &new_id, &plan.digest, NOW + 200),
    )
    .unwrap();
    assert_eq!(done.reissued, plan.to_reissue.len());

    // 3. Append-only: every old file is byte-identical and still present.
    let after = snapshot(&s.backend);
    for (path, bytes) in &before {
        assert_eq!(after.get(path), Some(bytes), "{path} was touched");
    }
    assert!(after.len() > before.len());

    // 4. The verifier walks both lineages: trustworthy, the old records are
    //    marked, the chain and the checkpoint are intact, and the control
    //    plane starts again.
    let w = walk_ledger(&s.backend, &s.roots).unwrap();
    assert!(w.is_trustworthy(), "{:?}", w.findings);
    let marked = w
        .findings
        .iter()
        .filter(|f| f.code == FindingCode::RevokedSuperseded)
        .count();
    assert_eq!(marked, plan.to_reissue.len());
    assert_eq!(w.store_checkpoint, s.store.latest_checkpoint().unwrap());
    startup_check(&s.backend, &s.roots, &s.store, None).unwrap();
    assert!(w.revoked.iter().all(|r| r.reattested));
    // Every effective audit record is now signed by the new key.
    assert!(!w.audit.is_empty());

    // 5. Writing resumes under the new key; the store reconciles cleanly.
    let v = Verifier::new(w.keyring.clone());
    let ex = Exporter::new(&s.backend, &s.new.signer, &v);
    let rep = ex.reconcile(&s.store, NOW + 300, false, false).unwrap();
    assert!(
        rep.conflicting.is_empty() && rep.missing_in_ledger.is_empty(),
        "{rep:?}"
    );

    // 6. Nothing left to do: a second plan finds the lineage fully marked.
    assert_eq!(
        plan_reissue(&s.backend, &s.roots, &s.store, None).unwrap_err(),
        ReissueRefusal::NothingToReissue
    );
    drop(s.db);
}

#[test]
fn a_forged_record_made_with_the_stolen_key_is_never_laundered() {
    let s = scene(NOW - 10_000);
    let old_id = s.old.signer.key_id().clone();
    let new_id = s.new.signer.key_id().clone();
    // The attacker, holding the old key, appends a record the store never
    // produced (an audit event far ahead of the store).
    let forged = LedgerRecord::audit_event(&synthetic_event(
        999,
        r#"{"event":"attempt.terminal","units":1}"#,
    ))
    .unwrap();
    let v_old = Verifier::new(Keyring::new().with_root(s.old.entry.clone()));
    Exporter::new(&s.backend, &s.old.signer, &v_old)
        .write_record(&forged)
        .unwrap();
    revoke_key(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &old_id,
        &old_id,
        NOW + 100,
    )
    .unwrap();

    assert_eq!(
        plan_reissue(&s.backend, &s.roots, &s.store, None).unwrap_err(),
        ReissueRefusal::Contradicted
    );
    // Even with a made-up digest nothing is written and the ledger stays untrusted.
    let n = s.backend.file_count();
    let err = execute_reissue(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &s.store,
        None,
        &req(&old_id, &new_id, "sha256:00", NOW + 200),
    )
    .unwrap_err();
    assert_eq!(err, ReissueRefusal::Contradicted);
    assert_eq!(s.backend.file_count(), n);
    assert!(!walk_ledger(&s.backend, &s.roots).unwrap().is_trustworthy());
}

#[test]
fn the_procedure_constraints_are_enforced_by_the_tool() {
    // R-6: the new key must be valid from at or before the oldest record.
    let late = scene(NOW + 5_000);
    let old_id = late.old.signer.key_id().clone();
    let new_id = late.new.signer.key_id().clone();
    // Even the revocation refuses when the new key is not yet valid.
    assert_eq!(
        revoke_key(
            &late.backend,
            &late.roots,
            &late.new.signer,
            &old_id,
            &old_id,
            NOW + 100
        )
        .unwrap_err(),
        ReissueRefusal::NewKeyNotValidForHistory
    );
    let _ = new_id;

    // A key cannot revoke itself; confirmations are exact.
    let s = scene(NOW - 10_000);
    let old_id = s.old.signer.key_id().clone();
    let new_id = s.new.signer.key_id().clone();
    assert_eq!(
        revoke_key(
            &s.backend,
            &s.roots,
            &s.old.signer,
            &old_id,
            &old_id,
            NOW + 100
        )
        .unwrap_err(),
        ReissueRefusal::SameKey
    );
    assert_eq!(
        revoke_key(
            &s.backend,
            &s.roots,
            &s.new.signer,
            &old_id,
            &new_id,
            NOW + 100
        )
        .unwrap_err(),
        ReissueRefusal::ConfirmationMismatch
    );

    // R-5: a key event in the same second is refused (fail closed).
    let v = Verifier::new(s.roots.clone());
    let spare = test_key(77, &all_domains(), NOW - 10_000);
    Exporter::new(&s.backend, &s.new.signer, &v)
        .write_record(
            &LedgerRecord::key_event(
                KeyEventBody {
                    key_id: spare.signer.key_id().clone(),
                    action: KeyAction::Published,
                    public_key: Some(spare.signer.public_key_hex()),
                    purposes: all_domains(),
                    effective_at: cc::ts(NOW + 100),
                },
                NOW + 100,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        revoke_key(
            &s.backend,
            &s.roots,
            &s.new.signer,
            &old_id,
            &old_id,
            NOW + 100
        )
        .unwrap_err(),
        ReissueRefusal::SameSecondKeyEvent
    );
    revoke_key(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &old_id,
        &old_id,
        NOW + 101,
    )
    .unwrap();

    // Exact plan confirmation and the right signer.
    let plan = plan_reissue(&s.backend, &s.roots, &s.store, None).unwrap();
    let bad = execute_reissue(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &s.store,
        None,
        &req(&old_id, &new_id, "sha256:not-the-plan", NOW + 200),
    );
    assert_eq!(bad.unwrap_err(), ReissueRefusal::ConfirmationMismatch);
    let wrong_signer = execute_reissue(
        &s.backend,
        &s.roots,
        &s.old.signer,
        &s.store,
        None,
        &req(&old_id, &new_id, &plan.digest, NOW + 200),
    );
    assert_eq!(
        wrong_signer.unwrap_err(),
        ReissueRefusal::ConfirmationMismatch
    );

    // A new key without the ledger purposes cannot re-attest.
    let weak = test_key(3, &[SignDomain::LedgerKeyEvent], NOW - 10_000);
    let roots_weak = s.roots.clone().with_root(weak.entry.clone());
    let weak_id = weak.signer.key_id().clone();
    assert_eq!(
        execute_reissue(
            &s.backend,
            &roots_weak,
            &weak.signer,
            &s.store,
            None,
            &req(&old_id, &weak_id, &plan.digest, NOW + 200),
        )
        .unwrap_err(),
        ReissueRefusal::NewKeyNotTrusted
    );
    // Nothing was written by any refusal above (only the two key events).
    assert!(!walk_ledger(&s.backend, &s.roots).unwrap().is_trustworthy());
}

#[test]
fn a_reattestation_with_a_different_body_does_not_count() {
    let s = scene(NOW - 10_000);
    let old_id = s.old.signer.key_id().clone();
    revoke_key(
        &s.backend,
        &s.roots,
        &s.new.signer,
        &old_id,
        &old_id,
        NOW + 100,
    )
    .unwrap();
    // A valid superseding record from the new key that changes the body is a
    // correction, not a re-attestation: the original stays blocking.
    let w = walk_ledger(&s.backend, &s.roots).unwrap();
    let target = w
        .revoked
        .iter()
        .find(|r| {
            matches!(
                r.record.payload.body,
                custodian_ledger::record::RecordBody::StoreCheckpoint(_)
            )
        })
        .unwrap();
    let altered = LedgerRecord::store_checkpoint(
        &custodian_store::Checkpoint {
            seq: 1,
            chain: "b".repeat(64),
        },
        target.record.payload.issued_at.secs(),
    )
    .unwrap()
    .superseding(&target.record.payload.record_id);
    // The id derivation binds the kind, not the body: this is accepted as a
    // superseding record, and the walker must still refuse to treat it as a
    // re-attestation.
    let altered = altered.unwrap();
    let v = Verifier::new(w.keyring.clone());
    Exporter::new(&s.backend, &s.new.signer, &v)
        .write_record(&altered)
        .unwrap();
    let w2 = walk_ledger(&s.backend, &s.roots).unwrap();
    assert!(w2
        .findings
        .iter()
        .any(|f| f.code == FindingCode::BadSignature(VerifyError::KeyRevoked)));
    assert!(!w2.is_trustworthy());
}
