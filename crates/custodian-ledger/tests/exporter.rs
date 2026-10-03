//! Outbox exporter: idempotency, quarantine, unavailability, crash windows,
//! reconciliation and the budget-neutrality of retries. Real store, in-memory
//! ledger, test-generated keys.

mod common;

use common::*;
use custodian_contracts::common::BudgetKind;
use custodian_ledger::record::ReconcileOutcome;
use custodian_ledger::{
    walk_ledger, CrashOnce, ExportError, ExportFaultPoint, ExportStatus, Exporter, ExporterConfig,
    FindingCode, KeyEntry, Keyring, LedgerRecord, MemoryBackend, OutboxSource, RecordError,
    RetryPolicy, SignRefusal, SignedLedgerRecord, Verifier, VerifyError, WriteOutcome,
};
use custodian_store::{AckOutcome, Checkpoint, OutboxEvent, SqliteStore, StoreError};

const CANARY: &str = "canary-9d2e41b07c35";

fn pending_count(store: &SqliteStore) -> usize {
    store.outbox_pending(1000).unwrap().len()
}

fn cfg(max_attempts: u32) -> ExporterConfig {
    ExporterConfig {
        batch: 3,
        retry: RetryPolicy {
            max_attempts,
            base_delay_secs: 1,
            max_delay_secs: 60,
        },
    }
}

#[test]
fn export_drains_outbox_acks_after_durable_write_and_opens_disclosure() {
    let db = TempDb::new("ex-drain");
    let (store, _fx, settle) = populated_store(&db);
    let total = pending_count(&store);
    assert!(total >= 4);
    // Disclosure is closed until the terminal event is exported.
    assert!(store
        .check_disclosure_precondition(&settle.attempt)
        .is_err());

    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_config(cfg(3));
    let report = ex.export_pending(&store, NOW + 10).unwrap();
    assert_eq!(report.status, ExportStatus::Drained);
    assert_eq!(report.exported.len(), total);
    assert!(report.already_present.is_empty());
    assert_eq!(pending_count(&store), 0);
    assert!(store.check_disclosure_precondition(&settle.attempt).is_ok());

    // Every event has a record, and the whole ledger verifies.
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w.is_trustworthy(), "{:?}", w.findings);
    assert_eq!(w.records, total);
    let cp = store.latest_checkpoint().unwrap().unwrap();
    assert_eq!(w.store_checkpoint, Some(cp));
}

#[test]
fn export_ref_in_store_names_the_ledger_record() {
    let db = TempDb::new("ex-ref");
    let (store, _fx, settle) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    Exporter::new(&backend, &s.key.signer, &s.verifier)
        .export_pending(&store, NOW + 10)
        .unwrap();
    let ev = store.outbox_event(settle.outbox_seq).unwrap().unwrap();
    let r = ev.export_ref.unwrap();
    assert!(r.starts_with("ledger/rec-audit-"));
    assert!(backend
        .paths()
        .iter()
        .any(|p| p.ends_with(&format!("{}.json", r.trim_start_matches("ledger/")))));
}

#[test]
fn identical_retry_is_idempotent() {
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let rec = LedgerRecord::store_checkpoint(
        &Checkpoint {
            seq: 4,
            chain: "c".repeat(64),
        },
        NOW,
    )
    .unwrap();
    assert_eq!(ex.write_record(&rec).unwrap(), WriteOutcome::Created);
    let before = backend.raw(&rec.path()).unwrap();
    assert_eq!(ex.write_record(&rec).unwrap(), WriteOutcome::Identical);
    assert_eq!(ex.write_record(&rec).unwrap(), WriteOutcome::Identical);
    assert_eq!(backend.raw(&rec.path()).unwrap(), before);
    assert_eq!(backend.file_count(), 1);
}

#[test]
fn second_export_pass_has_nothing_to_do() {
    let db = TempDb::new("ex-twice");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    ex.export_pending(&store, NOW + 10).unwrap();
    let puts = backend.put_count();
    let again = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(again.status, ExportStatus::Drained);
    assert!(again.exported.is_empty() && again.already_present.is_empty());
    assert_eq!(backend.put_count(), puts);
}

#[test]
fn export_conflict_is_quarantined_not_overwritten_and_event_stays_pending() {
    let db = TempDb::new("ex-conflict");
    let (store, _fx, settle) = populated_store(&db);
    // Pre-place different bytes under the id the terminal event maps to.
    let terminal = store.outbox_event(settle.outbox_seq).unwrap().unwrap();
    let rec = LedgerRecord::audit_event(&terminal).unwrap();
    let backend = MemoryBackend::new();
    backend.inject(&rec.path(), b"someone else wrote this");

    let s = setup();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let report = ex.export_pending(&store, NOW + 10).unwrap();
    assert_eq!(report.status, ExportStatus::Blocked);
    assert_eq!(report.quarantined.len(), 1);
    assert_eq!(report.quarantined[0].0, settle.outbox_seq);

    // The original is untouched, the new bytes are in quarantine, the event
    // is still pending and disclosure stays closed.
    assert_eq!(
        backend.raw(&rec.path()).unwrap(),
        b"someone else wrote this".to_vec()
    );
    let quarantined: Vec<_> = backend
        .paths()
        .into_iter()
        .filter(|p| p.starts_with(&format!("quarantine/{}/", rec.record_id)))
        .collect();
    assert_eq!(quarantined.len(), 1);
    assert!(store
        .outbox_pending(1000)
        .unwrap()
        .iter()
        .any(|e| e.seq == settle.outbox_seq));
    assert!(store
        .check_disclosure_precondition(&settle.attempt)
        .is_err());

    // The walker reports both the unreadable record and the quarantine.
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(!w.is_trustworthy());
    assert_eq!(w.quarantined, vec![rec.record_id.clone()]);
    assert!(w
        .findings
        .iter()
        .any(|f| f.code == FindingCode::QuarantinePresent));

    // Retrying changes nothing: same quarantine file, still blocked.
    let again = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(again.status, ExportStatus::Blocked);
    let q2 = backend
        .paths()
        .into_iter()
        .filter(|p| p.starts_with("quarantine/"))
        .count();
    assert_eq!(q2, 1);
}

#[test]
fn ledger_unavailable_retries_with_backoff_then_defers_without_acking() {
    let db = TempDb::new("ex-unavail");
    let (store, _fx, settle) = populated_store(&db);
    let total = pending_count(&store);
    let s = setup();
    let backend = MemoryBackend::new();
    backend.set_available(false);
    let sleeper = RecordingSleeper::default();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier)
        .with_config(cfg(5))
        .with_sleeper(&sleeper);

    let report = ex.export_pending(&store, NOW + 10).unwrap();
    assert!(matches!(report.status, ExportStatus::Deferred { .. }));
    assert!(report.exported.is_empty());
    assert_eq!(sleeper.delays(), vec![1, 2, 4, 8]);
    assert_eq!(report.backoff_secs, 15);
    assert_eq!(pending_count(&store), total);
    assert!(store
        .check_disclosure_precondition(&settle.attempt)
        .is_err());

    // Recovery: everything exports, nothing was lost.
    backend.set_available(true);
    let report = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(report.status, ExportStatus::Drained);
    assert_eq!(report.exported.len(), total);
    assert!(store.check_disclosure_precondition(&settle.attempt).is_ok());
}

#[test]
fn transient_failures_within_the_retry_budget_succeed() {
    let db = TempDb::new("ex-transient");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    backend.fail_next_puts(2);
    let sleeper = RecordingSleeper::default();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier)
        .with_config(cfg(5))
        .with_sleeper(&sleeper);
    let report = ex.export_pending(&store, NOW + 10).unwrap();
    assert_eq!(report.status, ExportStatus::Drained);
    assert_eq!(sleeper.delays(), vec![1, 2]);
}

#[test]
fn write_landed_but_response_lost_is_recovered_by_retry() {
    let db = TempDb::new("ex-lost");
    let (store, _fx, _s) = populated_store(&db);
    let total = pending_count(&store);
    let s = setup();
    let backend = MemoryBackend::new();
    backend.lose_next_responses(1);
    // One attempt only: the first event is stored, the caller sees failure.
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_config(cfg(1));
    let report = ex.export_pending(&store, NOW + 10).unwrap();
    assert!(matches!(report.status, ExportStatus::Deferred { .. }));
    assert_eq!(backend.file_count(), 1);
    assert_eq!(pending_count(&store), total);

    let report = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(report.status, ExportStatus::Drained);
    assert_eq!(report.already_present.len(), 1);
    assert_eq!(report.exported.len(), total - 1);
    assert_eq!(backend.file_count(), total);
}

#[test]
fn crash_between_ledger_write_and_ack_is_recovered_idempotently() {
    let db = TempDb::new("ex-crash-write");
    let (store, fx, settle) = populated_store(&db);
    let total = pending_count(&store);
    let budget_before = status(&store, &fx);
    let last_before = store.latest_checkpoint().unwrap().unwrap();

    let s = setup();
    let backend = MemoryBackend::new();
    let crash = CrashOnce::new(ExportFaultPoint::AfterWrite);
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_fault(&crash);
    let err = ex.export_pending(&store, NOW + 10).unwrap_err();
    assert_eq!(
        err,
        ExportError::InjectedCrash(ExportFaultPoint::AfterWrite)
    );
    assert!(crash.fired());
    // The record is durable, the event is still pending (not acked).
    assert_eq!(backend.file_count(), 1);
    assert_eq!(pending_count(&store), total);

    // "Restart": a fresh exporter, no fault. The first event is found
    // identical in the ledger and acked; the rest export normally.
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let report = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(report.status, ExportStatus::Drained);
    assert_eq!(report.already_present, vec![1]);
    assert_eq!(report.exported.len(), total - 1);
    assert_eq!(backend.file_count(), total);
    assert!(store.check_disclosure_precondition(&settle.attempt).is_ok());

    // Export neither measured nor charged anything.
    assert_eq!(status(&store, &fx), budget_before);
    assert_eq!(store.latest_checkpoint().unwrap().unwrap(), last_before);
}

#[test]
fn crash_before_write_and_after_ack_leave_a_consistent_prefix() {
    let db = TempDb::new("ex-crash-others");
    let (store, _fx, _s) = populated_store(&db);
    let total = pending_count(&store);
    let s = setup();
    let backend = MemoryBackend::new();

    let before = CrashOnce::nth(ExportFaultPoint::BeforeWrite, 3);
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_fault(&before);
    assert!(ex.export_pending(&store, NOW + 10).is_err());
    assert_eq!(backend.file_count(), 2);
    assert_eq!(pending_count(&store), total - 2);

    let after = CrashOnce::nth(ExportFaultPoint::AfterAck, 1);
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_fault(&after);
    assert!(ex.export_pending(&store, NOW + 20).is_err());
    assert_eq!(pending_count(&store), total - 3);

    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let r = ex.export_pending(&store, NOW + 30).unwrap();
    assert_eq!(r.status, ExportStatus::Drained);
    assert_eq!(backend.file_count(), total);
    assert!(walk_ledger(&backend, &s.keyring).unwrap().is_trustworthy());
}

#[test]
fn export_retries_never_charge_budget_or_create_events() {
    let db = TempDb::new("ex-budget");
    let (store, fx, _s) = populated_store(&db);
    let budget = status(&store, &fx);
    let cp = store.latest_checkpoint().unwrap().unwrap();
    let s = setup();
    let backend = MemoryBackend::new();
    for round in 0..4u32 {
        if round % 2 == 0 {
            backend.set_available(false);
        } else {
            backend.set_available(true);
        }
        let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_config(cfg(2));
        let _ = ex
            .export_pending(&store, NOW + 10 + u64::from(round))
            .unwrap();
        assert_eq!(status(&store, &fx), budget);
        assert_eq!(store.latest_checkpoint().unwrap().unwrap(), cp);
    }
    // Only acknowledgements changed; no reservation was made.
    let st = store
        .budget_status(BudgetKind::Run, &fx.scope())
        .unwrap()
        .unwrap();
    assert_eq!(st.available(), budget.available());
}

#[test]
fn different_ack_reference_in_the_store_is_a_conflict() {
    let db = TempDb::new("ex-ackconf");
    let (store, _fx, _s) = populated_store(&db);
    assert_eq!(
        store
            .outbox_ack(1, "ledger/some-other-record", NOW)
            .unwrap(),
        AckOutcome::Acked
    );
    // Event 1 is no longer pending, so the exporter skips it; to provoke the
    // conflict, present it through a source that still lists it.
    struct Replay<'a>(&'a SqliteStore, OutboxEvent);
    impl OutboxSource for Replay<'_> {
        fn pending(&self, _: u32) -> Result<Vec<OutboxEvent>, StoreError> {
            Ok(vec![self.1.clone()])
        }
        fn event(&self, s: u64) -> Result<Option<OutboxEvent>, StoreError> {
            self.0.outbox_event(s)
        }
        fn ack(&self, s: u64, r: &str, n: u64) -> Result<AckOutcome, StoreError> {
            self.0.outbox_ack(s, r, n)
        }
        fn latest_checkpoint(&self) -> Result<Option<Checkpoint>, StoreError> {
            self.0.latest_checkpoint()
        }
        fn verify_external_checkpoint(&self, c: &Checkpoint) -> Result<(), StoreError> {
            self.0.verify_external_checkpoint(c)
        }
        fn needs_reconcile(&self) -> Result<bool, StoreError> {
            self.0.needs_reconcile()
        }
    }
    let ev = store.outbox_event(1).unwrap().unwrap();
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let err = ex.export_pending(&Replay(&store, ev), NOW + 5).unwrap_err();
    assert_eq!(err, ExportError::AckConflict);
}

#[test]
fn key_rotation_between_retries_does_not_quarantine_the_same_record() {
    let db = TempDb::new("ex-rotate");
    let (store, _fx, _s) = populated_store(&db);
    let total = pending_count(&store);
    let k1 = test_key(1, &all_domains(), NOW - 10_000);
    let k2 = test_key(2, &all_domains(), NOW - 10_000);
    let ring = Keyring::new()
        .with_root(k1.entry.clone())
        .with_root(k2.entry.clone());
    let verifier = Verifier::new(ring.clone());
    let backend = MemoryBackend::new();

    let crash = CrashOnce::new(ExportFaultPoint::AfterWrite);
    let ex = Exporter::new(&backend, &k1.signer, &verifier).with_fault(&crash);
    assert!(ex.export_pending(&store, NOW + 10).is_err());

    // Retry under the new key: the existing record has the same payload and
    // a valid signature, so it is kept and the event is acked.
    let ex = Exporter::new(&backend, &k2.signer, &verifier);
    let r = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(r.status, ExportStatus::Drained);
    assert!(r.quarantined.is_empty());
    assert_eq!(r.already_present, vec![1]);
    assert_eq!(backend.file_count(), total);
    assert!(walk_ledger(&backend, &ring).unwrap().is_trustworthy());
}

#[test]
fn exporter_refuses_to_write_with_a_key_the_verifier_does_not_trust() {
    let db = TempDb::new("ex-selfcheck");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let rogue = test_key(9, &all_domains(), NOW - 10_000);
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &rogue.signer, &s.verifier);
    assert_eq!(
        ex.export_pending(&store, NOW + 10).unwrap_err(),
        ExportError::SelfCheck(VerifyError::UnknownKey)
    );
    assert_eq!(backend.file_count(), 0);

    // A key whose purposes exclude audit events: the signer itself refuses.
    let narrow = test_key(1, &[SignDomain::LedgerPolicy], NOW - 10_000);
    let ring = Keyring::new().with_root(narrow.entry.clone());
    let v = Verifier::new(ring);
    let ex = Exporter::new(&backend, &narrow.signer, &v);
    assert_eq!(
        ex.export_pending(&store, NOW + 10).unwrap_err(),
        ExportError::Sign(SignRefusal::WrongDomain)
    );
    let _: Option<KeyEntry> = None;
}

use custodian_ledger::SignDomain;

struct FakeSource(Vec<OutboxEvent>);

impl OutboxSource for FakeSource {
    fn pending(&self, _: u32) -> Result<Vec<OutboxEvent>, StoreError> {
        Ok(self.0.clone())
    }
    fn event(&self, s: u64) -> Result<Option<OutboxEvent>, StoreError> {
        Ok(self.0.iter().find(|e| e.seq == s).cloned())
    }
    fn ack(&self, _: u64, _: &str, _: u64) -> Result<AckOutcome, StoreError> {
        Ok(AckOutcome::Acked)
    }
    fn latest_checkpoint(&self) -> Result<Option<Checkpoint>, StoreError> {
        Ok(None)
    }
    fn verify_external_checkpoint(&self, _: &Checkpoint) -> Result<(), StoreError> {
        Ok(())
    }
    fn needs_reconcile(&self) -> Result<bool, StoreError> {
        Ok(false)
    }
}

#[test]
fn raw_fields_and_worker_text_never_enter_records() {
    let s = setup();
    for (label, payload) in [
        (
            "unknown key",
            format!(r#"{{"event":"x","worker_note":"{CANARY}"}}"#),
        ),
        (
            "free text in an allowed key",
            format!(r#"{{"event":"x","reason":"{CANARY} with spaces"}}"#),
        ),
        (
            "oversized value",
            format!(r#"{{"event":"x","reason":"{}"}}"#, CANARY.repeat(20)),
        ),
        (
            "nested object",
            format!(r#"{{"event":"x","reason":{{"a":"{CANARY}"}}}}"#),
        ),
        ("array", format!(r#"{{"event":"x","reason":["{CANARY}"]}}"#)),
        ("float", r#"{"event":"x","units":1.5}"#.to_owned()),
        ("non-ascii", r#"{"event":"x","reason":"café"}"#.to_owned()),
        ("not an object", format!(r#""{CANARY}""#)),
        ("empty", "{}".to_owned()),
    ] {
        let ev = synthetic_event(1, &payload);
        assert_eq!(
            LedgerRecord::audit_event(&ev).unwrap_err(),
            RecordError::PayloadNotExportable,
            "{label}"
        );
        // Through the exporter: refused, blocked, nothing written.
        let backend = MemoryBackend::new();
        let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
        let r = ex.export_pending(&FakeSource(vec![ev]), NOW).unwrap();
        assert_eq!(r.status, ExportStatus::Blocked, "{label}");
        assert_eq!(r.refused.len(), 1);
        assert_eq!(backend.file_count(), 0, "{label}");
    }
}

#[test]
fn an_event_that_disagrees_with_its_own_digest_is_not_signed() {
    let mut ev = synthetic_event(1, r#"{"event":"x"}"#);
    ev.payload_digest = "0".repeat(64);
    assert_eq!(
        LedgerRecord::audit_event(&ev).unwrap_err(),
        RecordError::EventInconsistent
    );
}

#[test]
fn null_members_are_omitted_and_flagged_not_exact() {
    let ev = synthetic_event(1, r#"{"authorization_ref":null,"event":"attempt.started"}"#);
    let rec = LedgerRecord::audit_event(&ev).unwrap();
    let custodian_ledger::RecordBody::AuditEvent(b) = &rec.body else {
        panic!()
    };
    assert!(!b.payload_exact);
    assert!(!b.payload.contains_key("authorization_ref"));
    let ev = synthetic_event(1, r#"{"event":"attempt.started"}"#);
    let rec = LedgerRecord::audit_event(&ev).unwrap();
    let custodian_ledger::RecordBody::AuditEvent(b) = &rec.body else {
        panic!()
    };
    assert!(b.payload_exact);
}

#[test]
fn exported_ledger_contains_no_candidate_population_or_canary_text() {
    let db = TempDb::new("ex-canary");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    ex.export_pending(&store, NOW + 10).unwrap();
    ex.record_store_checkpoint(&store, NOW + 11).unwrap();
    for path in backend.paths() {
        let text = String::from_utf8(backend.raw(&path).unwrap()).unwrap();
        for forbidden in [
            "synthetic-candidate",
            "synthetic-population",
            "cor_synthetic",
            "epo_synthetic",
            CANARY,
            "stderr",
            "password",
        ] {
            assert!(!text.contains(forbidden), "{path} contains {forbidden}");
        }
        // Closed vocabulary: every top-level field is a known one.
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<_> = v["payload"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["body", "issued_at", "record_id", "schema"]);
    }
}

#[test]
fn corrections_append_superseding_records_and_forks_are_flagged() {
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);

    let original = LedgerRecord::policy(cc_activation(), cc_digest(1), NOW).unwrap();
    ex.write_record(&original).unwrap();
    // Correction: same kind, new content, names the original.
    let fix = LedgerRecord::policy(cc_activation(), cc_digest(2), NOW + 1)
        .unwrap()
        .superseding(&original.record_id)
        .unwrap();
    assert_ne!(fix.record_id, original.record_id);
    assert_eq!(ex.write_record(&fix).unwrap(), WriteOutcome::Created);
    // The original is byte-for-byte untouched and both verify.
    assert!(backend.raw(&original.path()).is_some());
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w.is_trustworthy(), "{:?}", w.findings);
    assert_eq!(w.records, 2);

    // A second correction of the same original is a fork.
    let fix2 = LedgerRecord::policy(cc_activation(), cc_digest(3), NOW + 2)
        .unwrap()
        .superseding(&original.record_id)
        .unwrap();
    ex.write_record(&fix2).unwrap();
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w
        .findings
        .iter()
        .any(|f| f.code == FindingCode::SupersessionFork));

    // Superseding a record that does not exist is flagged.
    let ghost = format!("rec-policy-{}", "1".repeat(32));
    let orphan = LedgerRecord::policy(cc_activation(), cc_digest(4), NOW + 3)
        .unwrap()
        .superseding(&ghost)
        .unwrap();
    ex.write_record(&orphan).unwrap();
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w
        .findings
        .iter()
        .any(|f| f.code == FindingCode::SupersedesMissing));

    // A correction must be of the same kind.
    let wrong_kind = format!("rec-audit-{}", "1".repeat(32));
    assert_eq!(
        LedgerRecord::policy(cc_activation(), cc_digest(5), NOW)
            .unwrap()
            .superseding(&wrong_kind)
            .unwrap_err(),
        RecordError::Inconsistent
    );
}

fn cc_activation() -> custodian_contracts::common::ActivationRef {
    serde_json::from_value(cc::activation_ref()).unwrap()
}

fn cc_digest(n: u32) -> custodian_contracts::types::DocumentDigest {
    custodian_contracts::types::DocumentDigest::from_raw([n as u8; 32])
}

#[test]
fn reconcile_repairs_unacked_and_missing_and_refuses_to_repair_conflicts() {
    let db = TempDb::new("ex-reconcile");
    let (store, _fx, _s) = populated_store(&db);
    let total = pending_count(&store) as u64;
    let s = setup();

    // (a) crash after write: ledger has event 1, store still lists it pending.
    let backend = MemoryBackend::new();
    let crash = CrashOnce::new(ExportFaultPoint::AfterWrite);
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier).with_fault(&crash);
    let _ = ex.export_pending(&store, NOW + 10);
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    let dry = ex.reconcile(&store, NOW + 11, false, false).unwrap();
    assert_eq!(dry.unacked_in_ledger, vec![1]);
    assert_eq!(dry.outcome, ReconcileOutcome::Divergent);
    assert_eq!(pending_count(&store) as u64, total);
    let fixed = ex.reconcile(&store, NOW + 12, true, true).unwrap();
    assert_eq!(fixed.repaired, vec![1]);
    assert_eq!(fixed.outcome, ReconcileOutcome::Repaired);
    assert_eq!(pending_count(&store) as u64, total - 1);
    // A reconciliation record is in the ledger and verifies.
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w.is_trustworthy());

    // Finish exporting, then lose the ledger entirely: store says exported,
    // ledger lacks everything.
    ex.export_pending(&store, NOW + 13).unwrap();
    assert_eq!(pending_count(&store), 0);
    let empty = MemoryBackend::new();
    let ex2 = Exporter::new(&empty, &s.key.signer, &s.verifier);
    let r = ex2.reconcile(&store, NOW + 14, false, false).unwrap();
    assert_eq!(r.missing_in_ledger.len() as u64, total);
    assert_eq!(r.outcome, ReconcileOutcome::Divergent);
    let r = ex2.reconcile(&store, NOW + 15, true, true).unwrap();
    assert_eq!(r.repaired.len() as u64, total);
    assert_eq!(r.outcome, ReconcileOutcome::Repaired);
    let again = ex2.reconcile(&store, NOW + 16, true, false).unwrap();
    assert_eq!(again.outcome, ReconcileOutcome::Consistent);
    assert!(walk_ledger(&empty, &s.keyring).unwrap().is_trustworthy());

    // (c) a conflicting record is reported and never repaired automatically.
    let ev = store.outbox_event(2).unwrap().unwrap();
    let path = LedgerRecord::audit_event(&ev).unwrap().path();
    empty.inject(&path, b"tampered");
    let r = ex2.reconcile(&store, NOW + 17, true, false).unwrap();
    assert_eq!(r.conflicting, vec![2]);
    assert_eq!(r.outcome, ReconcileOutcome::Divergent);
    assert_eq!(empty.raw(&path).unwrap(), b"tampered".to_vec());
}

#[test]
fn reconciliation_record_is_idempotent_for_the_same_observation() {
    let db = TempDb::new("ex-reconcile-idem");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    ex.export_pending(&store, NOW + 10).unwrap();
    ex.reconcile(&store, NOW + 20, true, true).unwrap();
    let n = backend.file_count();
    ex.reconcile(&store, NOW + 20, true, true).unwrap();
    assert_eq!(backend.file_count(), n);
}

#[test]
fn walker_detects_forged_gapped_and_unsigned_records() {
    let db = TempDb::new("ex-walk");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let backend = MemoryBackend::new();
    let ex = Exporter::new(&backend, &s.key.signer, &s.verifier);
    ex.export_pending(&store, NOW + 10).unwrap();

    // Gap: remove event 2's record.
    let ev2 = store.outbox_event(2).unwrap().unwrap();
    let p2 = LedgerRecord::audit_event(&ev2).unwrap().path();
    let saved = backend.raw(&p2).unwrap();
    backend.remove(&p2);
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w.findings.iter().any(|f| f.code == FindingCode::SeqGap));
    backend.inject(&p2, &saved);
    assert!(walk_ledger(&backend, &s.keyring).unwrap().is_trustworthy());

    // Forged: re-signed by an untrusted key.
    let rogue = test_key(9, &all_domains(), NOW - 10_000);
    let mut signed = SignedLedgerRecord::decode_canonical(&saved).unwrap();
    signed.signature = custodian_ledger::Signer::sign(
        &rogue.signer,
        &custodian_ledger::ApprovedPayload::ledger_record(&signed.payload).unwrap(),
    )
    .unwrap();
    backend.inject(&p2, &signed.canonical_bytes().unwrap());
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w
        .findings
        .iter()
        .any(|f| matches!(f.code, FindingCode::BadSignature(VerifyError::UnknownKey))));
    assert!(!w.is_trustworthy());

    // Edited payload with the old signature.
    backend.inject(&p2, &saved);
    let mut edited = SignedLedgerRecord::decode_canonical(&saved).unwrap();
    if let custodian_ledger::RecordBody::AuditEvent(b) = &mut edited.payload.body {
        b.chain = "d".repeat(64);
    }
    backend.inject(&p2, &edited.canonical_bytes().unwrap());
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w
        .findings
        .iter()
        .any(|f| matches!(f.code, FindingCode::BadSignature(VerifyError::BadSignature))));

    // A record at the wrong path.
    backend.inject(&p2, &saved);
    backend.inject(
        "records/audit/rec-audit-00000000000000000000000000000000.json",
        &saved,
    );
    let w = walk_ledger(&backend, &s.keyring).unwrap();
    assert!(w
        .findings
        .iter()
        .any(|f| f.code == FindingCode::PathMismatch));
}

#[test]
fn unavailable_ledger_makes_the_walk_fail_closed() {
    let s = setup();
    let backend = MemoryBackend::new();
    backend.set_available(false);
    assert!(walk_ledger(&backend, &s.keyring).is_err());
}
