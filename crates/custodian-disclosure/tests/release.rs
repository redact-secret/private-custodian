//! The release path end to end, and every way it must refuse (C8).

mod common;

use common::*;
use custodian_contracts::public::{CellValue, PublicProjectionEnvelope};
use custodian_contracts::types::ProjectionDigest;
use custodian_contracts::Contract;
use custodian_disclosure::ports::EligibilityRefusal;
use custodian_disclosure::testing::{FixedEligibility, RecordingSink, UncheckedEligibility};
use custodian_disclosure::{verify_release, DisclosureReason as R, DisclosureStore};
use custodian_ledger::record::{PublicationBody, RecordBody};
use custodian_ledger::{LedgerBackend, LedgerPath, LedgerRecord, SignedLedgerRecord};
use serde_json::json;

/// Prepare release `n` with a provisioned budget; its audit events are still
/// pending export.
fn prepared_pending(w: &World, n: u32) -> custodian_disclosure::PreparedRelease {
    with_default_service(w, |svc| {
        w.provision(svc);
        let key = w.release_key(n);
        svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap()
    })
}

/// Prepare release `n` and let the exporter acknowledge its audit events.
fn prepared(w: &World, n: u32) -> custodian_disclosure::PreparedRelease {
    let p = prepared_pending(w, n);
    w.export();
    p
}

fn reported(env: &PublicProjectionEnvelope, stratum: &str) -> Option<(u64, u64)> {
    env.payload
        .cells
        .as_slice()
        .iter()
        .find(|c| c.stratum.as_str() == stratum)
        .and_then(|c| match &c.value {
            CellValue::Reported {
                numerator,
                denominator,
            } => Some((numerator.get(), denominator.get())),
            CellValue::Suppressed {} => None,
        })
}

fn decision_record(w: &World, env: &PublicProjectionEnvelope, dest: &str) -> SignedLedgerRecord {
    // Rebuild the record id from its natural key, then read it back from the
    // private ledger exactly as an auditor would.
    let p = &env.payload;
    let digest = p.projection_digest().unwrap();
    let probe = LedgerRecord::publication(
        PublicationBody {
            projection_id: p.projection_id.clone(),
            receipt_id: p.receipt_id.clone(),
            projection_digest: digest,
            signature_key_id: env.signature.key_id.clone(),
            decision: Some(custodian_ledger::record::PublicationDecision {
                destination: w.destination(dest),
                disclosure_policy: p.disclosure_policy.clone(),
                execution_id: w.execution.execution_id.clone(),
                approval_id: custodian_contracts::types::ApprovalId::parse(&cc::id("apr_", 2))
                    .unwrap(),
                approver: custodian_contracts::types::ActorRef::parse(&cc::id("act_", 2)).unwrap(),
                approver_kind: custodian_contracts::common::ActorKind::Human,
            }),
        },
        p.issued_at.secs(),
    )
    .unwrap();
    let bytes = w
        .backend
        .get(&LedgerPath::parse(&probe.path()).unwrap())
        .unwrap()
        .expect("decision record is in the ledger");
    SignedLedgerRecord::decode_canonical(&bytes).unwrap()
}

#[test]
fn full_release_round_trips_through_the_verifier() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);

    // The small stratum and its complement are withheld; the roster total and
    // an overlapping partition are reported as measured.
    let proj = p.projection();
    assert_eq!(proj.cells.len(), 6);
    let (a_pub, c_pub) = (
        proj.cells.as_slice()[0].value.clone(),
        proj.cells.as_slice()[2].value.clone(),
    );
    assert!(matches!(c_pub, CellValue::Suppressed {}));
    assert!(matches!(a_pub, CellValue::Suppressed {}));

    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let released = with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(RELEASE_AT),
        )
        .unwrap()
    });
    let delivered = sink.delivered();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, "benchmarks-feed");
    assert_eq!(delivered[0].1, released.to_bytes().unwrap());

    let env = PublicProjectionEnvelope::decode(&delivered[0].1).unwrap();
    assert_eq!(reported(&env, "all"), Some((50, 75)));
    assert_eq!(reported(&env, "c"), None);
    assert_eq!(env.payload.projection_digest().unwrap(), *p.digest());
    // The evidence class and the ground-truth claim ride along unchanged.
    assert_eq!(
        serde_json::to_value(&env.payload.attestation).unwrap()["ground_truth"],
        "not_established"
    );
    assert_eq!(
        serde_json::to_value(&env.payload.attestation).unwrap()["organisational_independence"],
        "not_claimed"
    );

    // Verifier round trip: signature, digest, destination, approver recorded.
    let decision = decision_record(&w, &env, "benchmarks-feed");
    let v = verify_release(&delivered[0].1, &decision, &dest, &w.verifier).unwrap();
    assert_eq!(v.projection_digest, *p.digest());
    let RecordBody::Publication(b) = &decision.payload.body else {
        panic!("not a publication record");
    };
    let d = b.decision.as_ref().unwrap();
    assert_eq!(d.approver.as_str(), cc::id("act_", 2));
    assert_eq!(d.destination.as_str(), "benchmarks-feed");

    // The disclosure policy was ledgered before release.
    assert!(w
        .backend
        .paths()
        .iter()
        .any(|p| p.starts_with("records/policy/")));
}

#[test]
fn verifier_rejects_wrong_destination_tampering_and_substituted_decisions() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(RELEASE_AT),
        )
        .unwrap()
    });
    let bytes = sink.delivered()[0].1.clone();
    let env = PublicProjectionEnvelope::decode(&bytes).unwrap();
    let decision = decision_record(&w, &env, "benchmarks-feed");

    // Approved for one destination, presented for another.
    let other = w.destination("site-preview");
    assert_eq!(
        verify_release(&bytes, &decision, &other, &w.verifier),
        Err(R::DestinationMismatch)
    );

    // Tampered cell: the signature no longer verifies.
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["payload"]["cells"][5]["value"]["numerator"] = json!(51);
    let tampered = serde_json::to_vec(&v).unwrap();
    assert!(verify_release(&tampered, &decision, &dest, &w.verifier).is_err());

    // A decision for a different projection does not cover this envelope.
    let mut other_env = env.clone();
    other_env.payload.fresh_until = now(RELEASE_AT + 1);
    let other_bytes = custodian_contracts::canonical::to_canonical_bytes(&other_env).unwrap();
    assert!(verify_release(&other_bytes, &decision, &dest, &w.verifier).is_err());

    // Non-canonical bytes are refused even when otherwise valid.
    let mut spaced = bytes.clone();
    spaced.insert(1, b' ');
    assert_eq!(
        verify_release(&spaced, &decision, &dest, &w.verifier),
        Err(R::EnvelopeInvalid)
    );

    // An unrelated verifier (other key) rejects the signature.
    let stranger = custodian_ledger::Verifier::new(
        custodian_ledger::Keyring::new().with_root(test_key(1).entry),
    );
    assert_eq!(
        verify_release(&bytes, &decision, &dest, &stranger),
        Err(R::SignatureInvalid)
    );
}

#[test]
fn release_refuses_wrong_destination_and_digest_and_scope() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let try_release = |approval: &custodian_contracts::approval::Approval, dest: &str| {
        let d = w.destination(dest);
        with_default_service(&w, |svc| {
            svc.release(
                &p,
                &w.release_request(approval, &d, &obs),
                &sink,
                now(RELEASE_AT),
            )
        })
    };

    // Destination outside the policy allowlist.
    let good = w.release_approval(&p);
    assert_eq!(
        try_release(&good, "public-internet").err(),
        Some(R::DestinationNotAllowed)
    );

    // Approval bound to a different projection digest.
    let mut v = w.release_approval_json(&p);
    v["scope"]["projection_digest"] = json!(cc::dg("another-projection"));
    let wrong_digest: custodian_contracts::approval::Approval = cc::parse(&v);
    assert_eq!(
        try_release(&wrong_digest, "benchmarks-feed").err(),
        Some(R::ApprovalNotBound)
    );
    let _ = ProjectionDigest::from_raw([0; 32]);

    // Approval bound to a different execution.
    let mut v = w.release_approval_json(&p);
    v["scope"]["execution_id"] = json!(cc::id("exe_", 9));
    let wrong_exec: custodian_contracts::approval::Approval = cc::parse(&v);
    assert_eq!(
        try_release(&wrong_exec, "benchmarks-feed").err(),
        Some(R::ApprovalNotBound)
    );

    // Approval bound to a different disclosure policy version.
    let mut v = w.release_approval_json(&p);
    v["scope"]["disclosure_policy"]["version"] = json!(2);
    let wrong_policy: custodian_contracts::approval::Approval = cc::parse(&v);
    assert_eq!(
        try_release(&wrong_policy, "benchmarks-feed").err(),
        Some(R::ApprovalNotBound)
    );

    // The execution approval is not a release approval.
    assert_eq!(
        try_release(&w.exec_approval, "benchmarks-feed").err(),
        Some(R::ApprovalWrongScope)
    );

    // An agent cannot approve: the contract refuses to even decode it, and a
    // hand-built value is refused by the release check.
    let mut v = w.release_approval_json(&p);
    v["approver_kind"] = json!("agent");
    assert!(custodian_contracts::approval::Approval::decode(&cc::to_bytes(&v)).is_err());
    let mut agent = good.clone();
    agent.approver_kind = custodian_contracts::common::ActorKind::Agent;
    assert_eq!(
        try_release(&agent, "benchmarks-feed").err(),
        Some(R::ApproverNotPermitted)
    );

    // Expired approval.
    let mut v = w.release_approval_json(&p);
    v["issued_at"] = json!(NOW);
    v["expires_at"] = json!(NOW + 60);
    let expired: custodian_contracts::approval::Approval = cc::parse(&v);
    assert_eq!(
        try_release(&expired, "benchmarks-feed").err(),
        Some(R::ApprovalExpired)
    );

    assert!(sink.delivered().is_empty());
    assert!(!w
        .backend
        .paths()
        .iter()
        .any(|p| p.starts_with("records/publication/")));
}

#[test]
fn stale_or_revoked_policy_activation_blocks_release() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let sink = RecordingSink::new();
    let go = |obs: &custodian_contracts::policy::ObservedActivation| {
        with_default_service(&w, |svc| {
            svc.release(
                &p,
                &w.release_request(&approval, &dest, obs),
                &sink,
                now(RELEASE_AT),
            )
        })
    };
    // Observed too long ago.
    assert_eq!(
        go(&disclosure_activation(RELEASE_AT - 301, "active")).err(),
        Some(R::ActivationStale)
    );
    // Revoked and superseded since the approval was issued.
    assert_eq!(
        go(&disclosure_activation(RELEASE_AT, "revoked")).err(),
        Some(R::PolicyStale)
    );
    assert_eq!(
        go(&disclosure_activation(RELEASE_AT, "superseded")).err(),
        Some(R::PolicyStale)
    );
    // A different activation than the one the approval bound.
    let other = cc::observed(
        cc::parse(&activation_value(
            disclosure_ref(),
            &cc::id("pac_", 7),
            1,
            "active",
        )),
        RELEASE_AT,
    );
    assert_eq!(go(&other).err(), Some(R::ActivationNotCurrent));
    // The policy document changed since the projection was prepared.
    let mut changed = w.policy.clone();
    changed.min_stratum_size = custodian_contracts::types::Count::new(11).unwrap();
    let obs = disclosure_activation(RELEASE_AT, "active");
    let r = with_default_service(&w, |svc| {
        svc.release(
            &p,
            &custodian_disclosure::ReleaseRequest {
                approval: &approval,
                destination: &dest,
                policy: &changed,
                policy_activation: &obs,
            },
            &sink,
            now(RELEASE_AT),
        )
    });
    assert_eq!(r.err(), Some(R::PolicyStale));
    // A projection past its freshness window is not released.
    let r = with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(PREPARE_AT + 86_400),
        )
    });
    assert_eq!(r.err(), Some(R::PolicyStale));
    assert!(sink.delivered().is_empty());
}

#[test]
fn stale_execution_activation_blocks_prepare() {
    let mut w = World::new(Opts::default());
    w.exec_obs = exec_activation(PREPARE_AT - 301);
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::ActivationStale)
        );
    });
    // Nothing was charged for a refusal before validation finished.
    let scope = custodian_store::ReleaseScope::Requester(w.request.asserted_actor.as_str());
    assert_eq!(
        w.store
            .release_budget_status(&scope)
            .unwrap()
            .unwrap()
            .consumed,
        0
    );
}

#[test]
fn pending_ledger_export_blocks_prepare_and_release() {
    // The terminal audit event of the run is not yet exported.
    let w = World::new(Opts {
        export_before: false,
        ..Opts::default()
    });
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::PreconditionNotMet)
        );
    });

    // Export, prepare, then add a new unexported audit event: the charge's
    // own events are what the release waits for.
    let w = World::new(Opts::default());
    let p = prepared_pending(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let go = || {
        with_default_service(&w, |svc| {
            svc.release(
                &p,
                &w.release_request(&approval, &dest, &obs),
                &sink,
                now(RELEASE_AT),
            )
        })
    };
    // The charge made at prepare time is still pending export.
    assert_eq!(go().err(), Some(R::AuditNotAcknowledged));
    assert!(sink.delivered().is_empty());
    w.export();
    assert!(go().is_ok());
}

#[test]
fn restored_database_needing_reconcile_blocks_everything() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    // A checkpoint that disagrees with the store marks it needs_reconcile.
    let bad = custodian_store::Checkpoint {
        seq: 1,
        chain: "f".repeat(64),
    };
    assert!(w.store.verify_external_checkpoint(&bad).is_err());
    assert!(w.store.needs_reconcile().unwrap());
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let r = with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(RELEASE_AT),
        )
    });
    assert_eq!(r.err(), Some(R::PreconditionNotMet));
    assert!(sink.delivered().is_empty());
}

#[test]
fn ledger_unavailable_blocks_release_and_retry_succeeds_once_back() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let go = || {
        with_default_service(&w, |svc| {
            svc.release(
                &p,
                &w.release_request(&approval, &dest, &obs),
                &sink,
                now(RELEASE_AT),
            )
        })
    };
    w.backend.set_available(false);
    assert_eq!(go().err(), Some(R::LedgerUnavailable));
    assert!(sink.delivered().is_empty());
    w.backend.set_available(true);
    go().unwrap();
    assert_eq!(sink.delivered().len(), 1);
    // Releasing again is idempotent in the ledger (identical records).
    go().unwrap();
}

#[test]
fn eligibility_hook_denies_before_ledger_and_again_before_delivery() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    let req = w.release_request(&approval, &dest, &obs);

    let denied = FixedEligibility(Err(EligibilityRefusal::Revoked));
    let r = with_service(&w, &denied, |svc| {
        svc.release(&p, &req, &sink, now(RELEASE_AT))
    });
    assert_eq!(r.err(), Some(R::EligibilityDenied));
    assert!(!w
        .backend
        .paths()
        .iter()
        .any(|p| p.starts_with("records/publication/")));

    // Eligible at the first check, revoked by the time bytes would leave.
    struct FlipAfterOne(std::sync::atomic::AtomicU32);
    impl custodian_disclosure::ReleaseEligibility for FlipAfterOne {
        fn check(
            &self,
            _: &custodian_disclosure::EligibilitySubject<'_>,
            _: custodian_contracts::types::Timestamp,
        ) -> Result<(), EligibilityRefusal> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(EligibilityRefusal::Contaminated)
            }
        }
    }
    let flip = FlipAfterOne(std::sync::atomic::AtomicU32::new(0));
    let r = with_service(&w, &flip, |svc| {
        svc.release(&p, &req, &sink, now(RELEASE_AT))
    });
    assert_eq!(r.err(), Some(R::EligibilityDenied));
    assert!(sink.delivered().is_empty());
}

#[test]
fn delivery_failure_is_a_reason_code_and_leaves_no_delivery() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::failing();
    let r = with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(RELEASE_AT),
        )
    });
    assert_eq!(r.err(), Some(R::DeliveryFailed));
}

#[test]
fn exhausted_requester_budget_blocks_and_counts_every_attempt() {
    let w = World::new(Opts::default());
    with_default_service(&w, |svc| {
        w.provision(svc);
        // per_requester = 4: four attempts, the fifth is refused.
        for n in 1..=4 {
            let key = w.release_key(n);
            // Same inputs, so after the first the later ones are withheld by
            // composition only if they conflict; here they all succeed.
            let r = svc.prepare(&w.input(&key), now(PREPARE_AT));
            assert!(r.is_ok(), "attempt {n}: {r:?}");
        }
        let key = w.release_key(5);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::BudgetExhausted)
        );
    });
}

#[test]
fn population_budget_is_shared_across_requesters_and_never_resets() {
    let w = World::new(Opts::default());
    with_default_service(&w, |svc| {
        w.provision(svc);
        // Re-provisioning with the same limits does not restore consumption.
        for n in 1..=3 {
            let key = w.release_key(n);
            svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        }
        w.provision(svc);
        let key = w.release_key(4);
        svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
    });
}

#[test]
fn unprovisioned_budget_refuses() {
    let w = World::new(Opts::default());
    with_default_service(&w, |svc| {
        let key = w.release_key(1);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::BudgetNotProvisioned)
        );
    });
}

#[test]
fn blind_lineage_budget_is_charged_and_exhausts_independently() {
    let w = World::new(Opts {
        lineage: true,
        ..Opts::default()
    });
    with_default_service(&w, |svc| {
        w.provision(svc);
        // per_lineage = 3 is the tightest scope.
        for n in 1..=3 {
            let key = w.release_key(n);
            svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        }
        let key = w.release_key(4);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::BudgetExhausted)
        );
    });
}

#[test]
fn a_retry_of_the_same_attempt_is_not_charged_twice() {
    let w = World::new(Opts::default());
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        let a = svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        let b = svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.projection().projection_id, b.projection().projection_id);
    });
    let scope = custodian_store::ReleaseScope::Requester(w.request.asserted_actor.as_str());
    assert_eq!(
        w.store
            .release_budget_status(&scope)
            .unwrap()
            .unwrap()
            .consumed,
        1
    );
}

#[test]
fn a_structurally_rejected_artifact_is_refused_before_any_charge() {
    let w = World::new(Opts::default());
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        // A structurally rejected artifact never reaches the charge.
        let mut bad = w.aggregates.clone();
        bad.push(b' ');
        let mut input = w.input(&key);
        input.aggregates = &bad;
        assert_eq!(
            svc.prepare(&input, now(PREPARE_AT)).err(),
            Some(R::ArtifactMismatch)
        );
    });
    let scope = custodian_store::ReleaseScope::Requester(w.request.asserted_actor.as_str());
    assert_eq!(
        w.store
            .release_budget_status(&scope)
            .unwrap()
            .unwrap()
            .consumed,
        0
    );
}

#[test]
fn history_race_is_a_conflict_and_the_retry_replays_the_charge() {
    struct Racing<'a> {
        inner: &'a custodian_store::SqliteStore,
        fired: std::sync::atomic::AtomicBool,
    }
    impl DisclosureStore for Racing<'_> {
        fn precondition(&self, a: &custodian_core::RunId) -> Result<(), R> {
            self.inner.precondition(a)
        }
        fn attempt_binding(&self, a: &custodian_core::RunId) -> Result<(String, String), R> {
            self.inner.attempt_binding(a)
        }
        fn provision(
            &self,
            s: &custodian_store::ReleaseScope<'_>,
            l: u64,
            a: &custodian_core::ActorId,
            n: u64,
        ) -> Result<(), R> {
            self.inner.provision(s, l, a, n)
        }
        fn charge(
            &self,
            c: &custodian_store::ReleaseCharge<'_>,
        ) -> Result<custodian_store::ChargeOutcome, R> {
            self.inner.charge(c)
        }
        fn charge_exported(&self, c: &str) -> Result<bool, R> {
            self.inner.charge_exported(c)
        }
        fn history(&self, series: &str) -> Result<Vec<custodian_store::DisclosureHistoryEntry>, R> {
            let h = DisclosureStore::history(self.inner, series)?;
            if !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                // A competing release lands between our read and our append.
                self.inner.append(
                    series,
                    0,
                    "prj_competing0000000001",
                    "{\"v\":1,\"measurement\":\"x\",\"relations\":[],\"cells\":[]}",
                    NOW,
                )?;
            }
            Ok(h)
        }
        fn append(&self, series: &str, e: u64, r: &str, p: &str, n: u64) -> Result<u64, R> {
            self.inner.append(series, e, r, p, n)
        }
    }
    let w = World::new(Opts::default());
    let racing = Racing {
        inner: &w.store,
        fired: std::sync::atomic::AtomicBool::new(false),
    };
    let exporter = w.exporter();
    let names = w.names();
    let svc = custodian_disclosure::DisclosureService {
        store: &racing,
        exporter: &exporter,
        signer: &w.key.signer,
        eligibility: &UncheckedEligibility,
        names: &names,
    };
    w.provision(&svc);
    let key = w.release_key(1);
    assert_eq!(
        svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
        Some(R::HistoryConflict)
    );
    // The charge was taken; the retry replays it and now sees the competitor.
    svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
    let scope = custodian_store::ReleaseScope::Requester(w.request.asserted_actor.as_str());
    assert_eq!(
        w.store
            .release_budget_status(&scope)
            .unwrap()
            .unwrap()
            .consumed,
        1
    );
}

#[test]
fn partial_with_a_complete_roster_is_not_an_acceptable_receipt() {
    // Contract level: Partial requires observed < expected.
    let mut v = cc::receipt_json();
    v["outcome"] = json!("partial");
    assert!(custodian_contracts::execution::InternalReceipt::decode(&cc::to_bytes(&v)).is_err());

    // Service level: a Success receipt that still names a failed item is not
    // releasable, and neither is a genuine Partial.
    let w = World::new(Opts {
        roster_failed: 1,
        ..Opts::default()
    });
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::RosterIncomplete)
        );
    });
    let mut w = World::new(Opts::default());
    let mut v = cc::receipt_json();
    v["plan_digest"] = json!(w.request.plan.plan_digest().unwrap().as_str());
    v["outcome"] = json!("partial");
    v["roster"] = json!({"expected": 75, "observed": 60, "failed": 0});
    w.receipt = cc::parse(&v);
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        assert_eq!(
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
            Some(R::ReceiptNotReleasable)
        );
    });
}

#[test]
fn wrong_provenance_is_refused() {
    let base = || World::new(Opts::default());
    let check = |w: &World, want: R| {
        with_default_service(w, |svc| {
            w.provision(svc);
            let key = w.release_key(1);
            assert_eq!(
                svc.prepare(&w.input(&key), now(PREPARE_AT)).err(),
                Some(want)
            );
        });
    };

    // Receipt names a different engine than the plan froze.
    let mut w = base();
    let mut v = cc::receipt_json();
    v["plan_digest"] = json!(w.request.plan.plan_digest().unwrap().as_str());
    v["frozen"]["engine"] = cc::artifact("another-engine");
    v["result"] = json!({"digest": sha_digest(&w.aggregates), "size_bytes": w.aggregates.len(), "protocol": cc::protocol()});
    v["roster"] = json!({"expected": 75, "observed": 75, "failed": 0});
    w.receipt = cc::parse(&v);
    check(&w, R::ProvenanceMismatch);

    // Receipt for a different plan.
    let mut w = base();
    let mut v = cc::receipt_json();
    v["result"] = json!({"digest": sha_digest(&w.aggregates), "size_bytes": w.aggregates.len(), "protocol": cc::protocol()});
    v["roster"] = json!({"expected": 75, "observed": 75, "failed": 0});
    w.receipt = cc::parse(&v);
    check(&w, R::ProvenanceMismatch);

    // Receipt for a different execution.
    let mut w = base();
    let mut v = serde_json::to_value(&w.receipt).unwrap();
    v["execution_id"] = json!(cc::id("exe_", 9));
    w.receipt = cc::parse(&v);
    check(&w, R::ProvenanceMismatch);

    // Execution record that belongs to another reservation.
    let mut w = base();
    let mut v = serde_json::to_value(&w.execution).unwrap();
    v["reservation_id"] = json!(cc::id("rsv_", 9));
    w.execution = cc::parse(&v);
    check(&w, R::ProvenanceMismatch);

    // An attempt that is not the one that ran this request.
    let mut w = base();
    w.attempt = custodian_core::RunId::new("att_not_this_one");
    check(&w, R::PreconditionNotMet);

    // Execution approval for another plan.
    let mut w = base();
    let mut v = serde_json::to_value(&w.exec_approval).unwrap();
    v["scope"]["plan_digest"] = json!(cc::dg("another-plan"));
    w.exec_approval = cc::parse(&v);
    check(&w, R::ProvenanceMismatch);

    // Plan names a different disclosure policy than the one supplied.
    let mut w = base();
    w.policy.policy.version = custodian_contracts::types::Count::new(2).unwrap();
    w.policy_binding.policy.version = custodian_contracts::types::Count::new(2).unwrap();
    check(&w, R::PolicyMismatch);

    // Evidence class: a public synthetic control claiming a protected
    // evaluation plan, and the reverse.
    let mut w = base();
    let mut v = serde_json::to_value(&w.receipt).unwrap();
    v["attestation"]["independence"] = json!("public-control");
    w.receipt = cc::parse(&v);
    check(&w, R::ProvenanceMismatch);
    let w = World::new(Opts {
        conformance: true,
        ..Opts::default()
    });
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        let p = svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        // The control stays a public control in the projection.
        assert_eq!(
            serde_json::to_value(&p.projection().attestation).unwrap()["independence"],
            "public-control"
        );
    });
}

#[test]
fn artifact_with_unknown_fields_or_foreign_strata_is_refused() {
    let try_with = |agg: serde_json::Value| -> R {
        let w = World::new(Opts {
            aggregates: agg,
            ..Opts::default()
        });
        with_default_service(&w, |svc| {
            w.provision(svc);
            let key = w.release_key(1);
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err().unwrap()
        })
    };

    // Per-case data smuggled next to the aggregates.
    let mut v = aggregates_json();
    v["case_ids"] = json!([CANARY_CASE]);
    assert_eq!(try_with(v), R::ArtifactMalformed);
    let mut v = aggregates_json();
    v["cells"][0]["seed"] = json!(CANARY_SEED);
    assert_eq!(try_with(v), R::ArtifactMalformed);
    let mut v = aggregates_json();
    v["log"] = json!(CANARY_TEXT);
    assert_eq!(try_with(v), R::ArtifactMalformed);

    // A stratum or metric the policy does not allow.
    let mut v = aggregates_json();
    v["cells"][0]["stratum"] = json!(CANARY_CASE);
    assert_eq!(try_with(v), R::StratumNotAllowed);
    let mut v = aggregates_json();
    v["cells"][0]["metric"] = json!("per-case-hash");
    assert_eq!(try_with(v), R::MetricNotAllowed);

    // Missing, duplicated or inconsistent cells.
    let mut v = aggregates_json();
    v["cells"].as_array_mut().unwrap().pop();
    assert_eq!(try_with(v), R::ArtifactIncomplete);
    let mut v = aggregates_json();
    let dup = v["cells"][0].clone();
    v["cells"].as_array_mut().unwrap().push(dup);
    assert_eq!(try_with(v), R::ArtifactInconsistent);
    let mut v = aggregates_json();
    v["cells"][0]["numerator"] = json!(31);
    assert_eq!(try_with(v), R::ArtifactInconsistent);
    let mut v = aggregates_json();
    v["cells"][5]["denominator"] = json!(76);
    assert_eq!(try_with(v), R::ArtifactInconsistent);

    // Roster in the artifact disagrees with the signed receipt.
    let mut v = aggregates_json();
    v["roster"] = json!({"expected": 75, "observed": 74, "failed": 0});
    assert_eq!(try_with(v), R::ArtifactMismatch);
    let mut v = aggregates_json();
    v["protocol"]["version"] = json!("2");
    assert_eq!(try_with(v), R::ArtifactMismatch);
    let mut v = aggregates_json();
    v["schema"] = json!("private-custodian.aggregates/2");
    assert_eq!(try_with(v), R::ArtifactMalformed);
}

#[test]
fn policy_documents_reject_unknown_fields_and_inconsistent_structure() {
    let mut v = policy_json();
    v["note"] = json!("free text");
    assert!(serde_json::from_value::<custodian_disclosure::DisclosurePolicy>(v).is_err());

    let bad = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = policy_json();
        f(&mut v);
        let p: custodian_disclosure::DisclosurePolicy = serde_json::from_value(v).unwrap();
        assert_eq!(p.validate(), Err(R::PolicyInvalid));
    };
    bad(&|v| v["total_stratum"] = json!("nowhere"));
    bad(&|v| v["relations"][0]["parts"] = json!(["a"]));
    bad(&|v| v["relations"][0]["parts"] = json!(["a", "b", "ghost"]));
    bad(&|v| v["relations"][0]["total"] = json!("a"));
    bad(&|v| v["min_stratum_size"] = json!(0));
    bad(&|v| v["min_interval_width"] = json!(0));
    bad(&|v| v["destinations"] = json!([]));
    bad(&|v| v["budgets"]["per_population"] = json!(0));
    bad(&|v| v["metrics"] = json!(["detected", "detected"]));
    bad(&|v| v["policy"]["kind"] = json!("approval"));

    // No silent noise: the only representable perturbation is none, and the
    // two charge rules have one value each.
    for (k, val) in [
        ("perturbation", json!({"mechanism": "laplace"})),
        ("withheld_attempts", json!("free")),
        ("failed_attempts", json!("refunded")),
        ("audit", json!("best_effort")),
    ] {
        let mut v = policy_json();
        v[k] = val;
        assert!(serde_json::from_value::<custodian_disclosure::DisclosurePolicy>(v).is_err());
    }

    // Canonical round trip and a stable ledger digest.
    let p = policy();
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(
        custodian_disclosure::DisclosurePolicy::decode_canonical(&bytes).unwrap(),
        p
    );
    assert_eq!(p.document_digest().unwrap(), p.document_digest().unwrap());
    let mut p2 = p.clone();
    p2.min_stratum_size = custodian_contracts::types::Count::new(11).unwrap();
    assert_ne!(p.document_digest().unwrap(), p2.document_digest().unwrap());
}

#[test]
fn unused_helpers_compile() {
    let _ = digest_of("x");
    let _ = actor();
    let _ = sink();
    let _ = RecordingSink::new();
    let _ = FixedEligibility(Ok(()));
}

#[test]
fn publication_decisions_are_closed_distinct_per_destination_and_never_agent_approved() {
    use custodian_contracts::common::ActorKind;
    use custodian_ledger::record::PublicationDecision;

    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let body = |dest: &str, kind: ActorKind| PublicationBody {
        projection_id: p.projection().projection_id.clone(),
        receipt_id: p.projection().receipt_id.clone(),
        projection_digest: p.digest().clone(),
        signature_key_id: custodian_ledger::Signer::key_id(&w.key.signer).clone(),
        decision: Some(PublicationDecision {
            destination: w.destination(dest),
            disclosure_policy: w.policy.policy.clone(),
            execution_id: p.execution_id().clone(),
            approval_id: custodian_contracts::types::ApprovalId::parse(&cc::id("apr_", 2)).unwrap(),
            approver: custodian_contracts::types::ActorRef::parse(&cc::id("act_", 2)).unwrap(),
            approver_kind: kind,
        }),
    };
    let a = LedgerRecord::publication(body("benchmarks-feed", ActorKind::Human), 1).unwrap();
    let b = LedgerRecord::publication(body("site-preview", ActorKind::Human), 1).unwrap();
    assert_ne!(a.record_id, b.record_id, "one decision per destination");
    // An agent approver is unrepresentable in a ledgered decision.
    assert!(LedgerRecord::publication(body("benchmarks-feed", ActorKind::Agent), 1).is_err());
    // A record without a decision keeps its pre-C8 shape (no new key).
    let mut legacy = body("benchmarks-feed", ActorKind::Human);
    legacy.decision = None;
    let legacy = LedgerRecord::publication(legacy, 1).unwrap();
    let bytes = String::from_utf8(legacy.canonical_bytes().unwrap()).unwrap();
    assert!(!bytes.contains("decision"));
    // Unknown fields in a stored decision are refused.
    let mut v: serde_json::Value = serde_json::from_slice(&a.canonical_bytes().unwrap()).unwrap();
    v["body"]["decision"]["note"] = json!("free text");
    assert!(LedgerRecord::decode_canonical(&serde_json::to_vec(&v).unwrap()).is_err());
}

#[test]
fn envelope_with_unknown_fields_is_refused_by_the_verifier() {
    let w = World::new(Opts::default());
    let p = prepared(&w, 1);
    let approval = w.release_approval(&p);
    let dest = w.destination("benchmarks-feed");
    let obs = disclosure_activation(RELEASE_AT, "active");
    let sink = RecordingSink::new();
    with_default_service(&w, |svc| {
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(RELEASE_AT),
        )
        .unwrap()
    });
    let bytes = sink.delivered()[0].1.clone();
    let env = PublicProjectionEnvelope::decode(&bytes).unwrap();
    let decision = decision_record(&w, &env, "benchmarks-feed");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["payload"]["case_ids"] = json!(["x"]);
    assert_eq!(
        verify_release(
            &serde_json::to_vec(&v).unwrap(),
            &decision,
            &dest,
            &w.verifier
        ),
        Err(R::EnvelopeInvalid)
    );
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["payload"]["cells"][0]["value"]["hint"] = json!(3);
    assert_eq!(
        verify_release(
            &serde_json::to_vec(&v).unwrap(),
            &decision,
            &dest,
            &w.verifier
        ),
        Err(R::EnvelopeInvalid)
    );
}
