//! Deterministic crash matrix for attempt fencing, uncertain-outcome recovery and
//! the independent janitor (ADR 0144). Synthetic provider double and in-memory
//! store only: not live-host, remote crash or restart evidence.
use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::types::{ArtifactDigest, ProtocolName, VersionLabel};
use custodian_worker::result::job_document;
use custodian_worker_ec2::*;
use custodian_worker_microvm::{sha256, AttemptBinding, ResultEnvelope, RESULT_ENVELOPE_SCHEMA};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const MAX_LIFETIME: u64 = 900;

fn protocol() -> ProtocolRef {
    ProtocolRef {
        domain: EvaluationDomain::Credential,
        name: ProtocolName::parse("synthetic-protocol").unwrap(),
        version: VersionLabel::parse("1").unwrap(),
    }
}
fn job() -> Vec<u8> {
    job_document(
        EvaluationDomain::Credential,
        &protocol(),
        &["public-synthetic".into()],
    )
    .unwrap()
}
fn binding_with(attempt: u64, fence: u64) -> AttemptBinding {
    let d = sha256(b"public-synthetic-artifact");
    serde_json::from_value(json!({
        "request": "req_0000000000000001", "approval": "apr_0000000000000001",
        "reservation": "rsv_0000000000000001", "execution": "exe_0000000000000001",
        "attempt": attempt, "fence": fence, "plan_digest": d, "candidate_digest": d,
        "image_digest": d, "image_version": "1.0", "engine_digest": d, "adapter_digest": d,
        "config_digest": d, "scanner_digests": [d], "job_digest": sha256(&job())
    }))
    .unwrap()
}
fn binding() -> AttemptBinding {
    binding_with(1, 1)
}
fn pins() -> HostPins {
    HostPins {
        ami_id: "ami-0123456789abcdef0".into(),
        ami_manifest_digest: ArtifactDigest::parse(&sha256(b"synthetic-ami-manifest")).unwrap(),
    }
}
fn envelope(b: &AttemptBinding) -> Vec<u8> {
    let stdout = serde_json::to_vec(&json!({
        "schema": "private-custodian.worker-result/1", "domain": "credential",
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "status": "complete", "roster": {"expected": 1, "observed": 1, "failed": 0},
        "aggregates": {"schema": "private-custodian.aggregates/1", "public_synthetic": true}
    }))
    .unwrap();
    serde_json::to_vec(&ResultEnvelope {
        schema: RESULT_ENVELOPE_SCHEMA.into(),
        binding: b.clone(),
        stdout,
    })
    .unwrap()
}

struct Gate(AtomicBool);
impl Gates for Gate {
    fn exposure_acknowledged(&self, _: &AttemptBinding) -> bool {
        true
    }
    fn export_acknowledged(&self, _: &AttemptBinding) -> bool {
        true
    }
    fn lease_current(&self, _: &AttemptBinding) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
fn gates() -> Arc<Gate> {
    Arc::new(Gate(AtomicBool::new(true)))
}

type A = Adapter<SyntheticProvider, MemoryStore, Arc<Gate>>;
fn adapter() -> A {
    Adapter::new(
        SyntheticProvider::default(),
        MemoryStore::default(),
        gates(),
    )
}
/// Coordinator loss: drop the adapter, keep the provider and the durable store.
fn restart(a: &A) -> A {
    Adapter::new(
        a.provider.clone(),
        MemoryStore::restore(a.store.snapshot()),
        gates(),
    )
}
fn collect(a: &A, k: &AttemptKey) -> Result<(), AdapterError> {
    a.collect(k, EvaluationDomain::Credential, &protocol(), 1)
        .map(|_| ())
}
fn sweep(a: &A, now: u64) -> SweepReport {
    a.provider.set_clock(now);
    Janitor::new(
        &a.provider,
        &a.store,
        JanitorPolicy {
            max_lifetime_secs: MAX_LIFETIME,
        },
    )
    .sweep(now)
    .unwrap()
}

/// Test ledger: one charge per attempt key, no refund API at all.
#[derive(Default)]
struct Charges(Mutex<BTreeSet<AttemptKey>>);
impl Charges {
    fn settle(&self, k: &AttemptKey, o: &Outcome) {
        if matches!(o, Outcome::ResultAccepted(_) | Outcome::ExposedConsumed) {
            self.0.lock().unwrap().insert(k.clone());
        }
    }
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

/// Invariants every recovered scenario must satisfy after janitor convergence.
fn assert_closed_and_bounded(a: &A, k: &AttemptKey) {
    let r = sweep(a, MAX_LIFETIME + 1);
    assert!(r.unverified.is_empty());
    assert!(
        a.provider.running().is_empty(),
        "no owned instance may outlive the bound"
    );
    for id in a.provider.owned_ids() {
        assert!(a.provider.billable_secs(&id) <= MAX_LIFETIME + 1);
    }
    let rec = a.store.load(k).unwrap().unwrap();
    assert!(rec.terminated, "attempt closed or reconciled");
    assert!(a.provider.total_deliveries() <= 1, "never two deliveries");
    let again = sweep(a, MAX_LIFETIME + 2);
    assert_eq!(again, SweepReport::default(), "sweep is idempotent");
}

/// Crash points, in lifecycle order. Each returns the durable state at the crash.
#[derive(Debug, Clone, Copy)]
enum Crash {
    BeforeIntent,
    AfterIntentBeforeCreate,
    AfterCreateBeforeRecord,
    LostCreateResponse,
    AfterLaunchedBeforeDelivery,
    DeliveryDroppedBeforeSend,
    DeliveryLostResponse,
    AfterDeliveredBeforeResult,
    ResultPresentBeforeSettlement,
    AfterSettledBeforeTerminate,
    TerminateFailed,
    TerminateLied,
}

/// Expected deterministic outcome per crash point.
fn expected(c: Crash) -> Outcome {
    use Crash::*;
    match c {
        BeforeIntent
        | AfterIntentBeforeCreate
        | AfterCreateBeforeRecord
        | LostCreateResponse
        | AfterLaunchedBeforeDelivery => Outcome::NotExposed,
        DeliveryDroppedBeforeSend
        | DeliveryLostResponse
        | AfterDeliveredBeforeResult
        | TerminateFailed
        | TerminateLied => Outcome::ExposedConsumed,
        ResultPresentBeforeSettlement | AfterSettledBeforeTerminate => {
            Outcome::ResultAccepted(sha256(&envelope(&binding())))
        }
    }
}

/// Drive to the crash point; returns the key if a record exists.
fn run_to(c: Crash, a: &A) -> Option<AttemptKey> {
    use Crash::*;
    if matches!(c, BeforeIntent) {
        return None;
    }
    let k = a.begin(&binding(), &pins()).unwrap();
    let token = a.store.load(&k).unwrap().unwrap().token;
    match c {
        BeforeIntent | AfterIntentBeforeCreate => {}
        AfterCreateBeforeRecord => {
            a.provider.launch(&token, &pins()).unwrap();
        }
        LostCreateResponse => {
            a.provider.lose_next_launch_response();
            assert!(a.launch(&k).is_err());
        }
        _ => {
            let id = a.launch(&k).unwrap();
            match c {
                AfterLaunchedBeforeDelivery => {}
                DeliveryDroppedBeforeSend => {
                    a.provider.drop_next_delivery();
                    assert!(a.deliver(&k, &job()).is_err());
                }
                DeliveryLostResponse => {
                    a.provider.lose_next_delivery_response();
                    assert!(a.deliver(&k, &job()).is_err());
                }
                _ => {
                    a.deliver(&k, &job()).unwrap();
                    if matches!(
                        c,
                        ResultPresentBeforeSettlement | AfterSettledBeforeTerminate
                    ) {
                        a.provider.set_result(&id, envelope(&binding()));
                    }
                    if matches!(c, AfterSettledBeforeTerminate) {
                        collect(a, &k).unwrap();
                    }
                    if matches!(c, TerminateFailed) {
                        a.provider.fail_next_terminates(1);
                        assert!(a.terminate(&k).is_err());
                    }
                    if matches!(c, TerminateLied) {
                        a.provider.lie_next_terminates(1);
                        assert_eq!(a.terminate(&k), Err(AdapterError::TerminateUnverified));
                    }
                }
            }
        }
    }
    Some(k)
}

#[test]
fn crash_matrix_has_deterministic_outcomes_no_double_charge_no_hidden_refund() {
    use Crash::*;
    let all = [
        BeforeIntent,
        AfterIntentBeforeCreate,
        AfterCreateBeforeRecord,
        LostCreateResponse,
        AfterLaunchedBeforeDelivery,
        DeliveryDroppedBeforeSend,
        DeliveryLostResponse,
        AfterDeliveredBeforeResult,
        ResultPresentBeforeSettlement,
        AfterSettledBeforeTerminate,
        TerminateFailed,
        TerminateLied,
    ];
    for c in all {
        let before = adapter();
        let Some(k) = run_to(c, &before) else {
            // Nothing durable existed: restart sees nothing, nothing was created.
            let a = restart(&before);
            assert!(a.store.list().unwrap().is_empty());
            assert_eq!(a.provider.launches(), 0, "{c:?}");
            continue;
        };
        let pre_exposed = before.store.load(&k).unwrap().unwrap().is_exposed();
        let a = restart(&before);
        let charges = Charges::default();

        // Recovery: reconcile, then finish only what is legitimately finishable.
        let _ = a.reconcile(&k);
        if matches!(c, ResultPresentBeforeSettlement) {
            collect(&a, &k).unwrap();
            collect(&a, &k).unwrap(); // idempotent replay, one acceptance
        }
        let _ = a.terminate(&k); // may fail for TerminateFailed's second call: it must not
        let _ = a.terminate(&k);
        assert_closed_and_bounded(&a, &k);

        let rec = a.store.load(&k).unwrap().unwrap();
        // Exposure is monotonic across recovery: never hidden.
        assert!(!pre_exposed || rec.is_exposed(), "{c:?} hid exposure");
        let outcome = rec.outcome();
        assert_eq!(outcome, expected(c), "{c:?}");
        // Settling any number of times (replays, janitor, restarts) charges once.
        for _ in 0..3 {
            charges.settle(&k, &outcome);
        }
        let want = usize::from(!matches!(outcome, Outcome::NotExposed));
        assert_eq!(charges.len(), want, "{c:?}");
        // A late result for a closed attempt is never accepted.
        if let Some(id) = rec.instance {
            a.provider.set_result(&id, envelope(&binding()));
            if !matches!(rec.phase, Phase::Terminated) {
                assert!(collect(&a, &k).is_err(), "{c:?} accepted stale result");
            }
        }
    }
}

#[test]
fn coordinator_loss_never_delivers_to_two_instances_for_one_attempt() {
    let a = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    a.provider.lose_next_launch_response();
    assert!(a.launch(&k).is_err());
    // Retry storm from several restarted coordinators.
    for _ in 0..3 {
        let b = restart(&a);
        assert_eq!(b.launch(&k), Err(AdapterError::WrongPhase));
        assert_eq!(b.deliver(&k, &job()), Err(AdapterError::WrongPhase));
        let _ = b.reconcile(&k);
    }
    assert_eq!(a.provider.launches(), 1);
    assert_eq!(a.provider.total_deliveries(), 0);
}

#[test]
fn conflicting_retries_and_single_live_fence_owner() {
    let a = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    // Same attempt, different binding or pins: conflict, not adoption.
    let mut other = binding();
    other.job_digest = ArtifactDigest::parse(&sha256(b"other-job")).unwrap();
    assert_eq!(a.begin(&other, &pins()).err(), Some(AdapterError::Conflict));
    // Next attempt while the first is open: the live fence is held.
    assert_eq!(
        a.begin(&binding_with(2, 2), &pins()).err(),
        Some(AdapterError::FenceHeld)
    );
    // A non-increasing fence is stale even for a new attempt number.
    assert_eq!(
        a.begin(&binding_with(2, 1), &pins()).err(),
        Some(AdapterError::StaleFence)
    );
    a.launch(&k).unwrap();
    a.terminate(&k).unwrap();
    // Closed with verified termination: now the next fence may start.
    let k2 = a.begin(&binding_with(2, 2), &pins()).unwrap();
    // The superseded lower fence can no longer begin again.
    assert_eq!(
        a.begin(&binding_with(3, 2), &pins()).err(),
        Some(AdapterError::StaleFence)
    );
    let id2 = a.launch(&k2).unwrap();
    // Delayed writer of attempt 1 cannot cross attempts: its envelope is bound
    // to attempt 1 and is refused by attempt 2, and attempt 1 is closed.
    a.deliver(&k2, &job()).unwrap();
    a.provider.set_result(&id2, envelope(&binding()));
    assert!(matches!(
        a.collect(&k2, EvaluationDomain::Credential, &protocol(), 1),
        Err(AdapterError::Result(_))
    ));
    assert!(collect(&a, &k).is_err());
}

#[test]
fn concurrent_coordinators_deliver_at_most_once() {
    for _ in 0..20 {
        let a = adapter();
        let k = a.begin(&binding(), &pins()).unwrap();
        a.launch(&k).unwrap();
        let wins: usize = std::thread::scope(|s| {
            let hs: Vec<_> = (0..4)
                .map(|_| s.spawn(|| a.deliver(&k, &job()).is_ok()))
                .collect();
            hs.into_iter().map(|h| usize::from(h.join().unwrap())).sum()
        });
        assert_eq!(wins, 1);
        assert_eq!(a.provider.total_deliveries(), 1);
    }
}

#[test]
fn duplicate_instance_for_one_token_is_never_adopted_or_delivered_to() {
    let a = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    let token = a.store.load(&k).unwrap().unwrap().token;
    a.provider.launch(&token, &pins()).unwrap();
    a.provider.plant_duplicate(&token, &pins());
    // Ambiguous inventory: reconcile refuses to pick one.
    assert_eq!(
        a.reconcile(&k),
        Err(AdapterError::Provider(ProviderError::Ambiguous))
    );
    assert_eq!(a.deliver(&k, &job()), Err(AdapterError::WrongPhase));
    // The janitor terminates every instance answering to that token, and closes.
    let r = sweep(&a, 10);
    assert_eq!(r.terminated.len(), 2);
    assert!(a.provider.running().is_empty());
    assert_eq!(a.provider.total_deliveries(), 0);
    assert_eq!(a.outcome(&k).unwrap(), Outcome::NotExposed);
}

#[test]
fn cancellation_refunds_only_unexposed_and_never_an_exposed_run() {
    // Before launch: nothing exposed.
    let a = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    assert_eq!(a.cancel(&k).unwrap(), Outcome::NotExposed);
    // Launched, not delivered: still unexposed, instance terminated.
    let a = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    let id = a.launch(&k).unwrap();
    assert_eq!(a.cancel(&k).unwrap(), Outcome::NotExposed);
    assert!(a.provider.is_terminated(&id));
    // After delivery starts (even with a lost send response): consumed.
    for lose in [false, true] {
        let a = adapter();
        let k = a.begin(&binding(), &pins()).unwrap();
        let id = a.launch(&k).unwrap();
        if lose {
            a.provider.lose_next_delivery_response();
            assert!(a.deliver(&k, &job()).is_err());
        } else {
            a.deliver(&k, &job()).unwrap();
        }
        assert_eq!(a.cancel(&k).unwrap(), Outcome::ExposedConsumed);
        assert_eq!(a.cancel(&k).unwrap(), Outcome::ExposedConsumed);
        a.provider.set_result(&id, envelope(&binding()));
        assert!(collect(&a, &k).is_err(), "late result after cancel");
        assert!(a.store.load(&k).unwrap().unwrap().is_exposed());
    }
}

#[test]
fn orphan_reconciliation_and_bounded_lifetime_by_janitor_alone() {
    let a = adapter();
    // Owned instance with no durable record (write-ahead violated or store lost).
    a.provider.launch("pc-no-record", &pins()).unwrap();
    // A foreign instance outside the owned tag is never touched.
    let foreign = a.provider.plant_foreign(&pins());
    // An open attempt within lifetime is left to its coordinator...
    let k = a.begin(&binding(), &pins()).unwrap();
    let id = a.launch(&k).unwrap();
    let r = sweep(&a, 100);
    assert_eq!(r.orphans.len(), 1);
    assert_eq!(r.left_running, vec![id.clone()]);
    assert!(!a.provider.is_terminated(&foreign));
    // ...but never beyond max lifetime, with a hung terminate retried.
    a.provider.fail_next_terminates(1);
    let r = sweep(&a, MAX_LIFETIME + 1);
    assert_eq!(r.unverified, vec![id.clone()]);
    a.provider.lie_next_terminates(1);
    let r = sweep(&a, MAX_LIFETIME + 2);
    assert_eq!(r.unverified, vec![id.clone()], "a lie is not verification");
    let r = sweep(&a, MAX_LIFETIME + 3);
    assert_eq!(r.terminated, vec![id.clone()]);
    assert_eq!(r.expired, vec![id.clone()]);
    assert_eq!(r.closed_attempts, vec![k.clone()]);
    assert!(a.provider.billable_secs(&id) <= MAX_LIFETIME + 3);
    assert_eq!(a.outcome(&k).unwrap(), Outcome::NotExposed);
}

#[test]
fn janitor_close_after_exposure_stays_consumed_and_restart_is_idempotent() {
    let a = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    a.launch(&k).unwrap();
    a.provider.lose_next_delivery_response();
    assert!(a.deliver(&k, &job()).is_err());
    // Coordinator never returns; only the janitor acts, then the store restarts.
    let r = sweep(&a, MAX_LIFETIME + 1);
    assert_eq!(r.terminated.len(), 1);
    let b = restart(&a);
    assert_eq!(b.outcome(&k).unwrap(), Outcome::ExposedConsumed);
    assert_eq!(b.reconcile(&k).unwrap(), Phase::Failed);
    assert_eq!(b.launch(&k), Err(AdapterError::WrongPhase));
    assert_eq!(b.provider.total_deliveries(), 1);
}
