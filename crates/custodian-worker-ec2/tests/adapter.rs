//! Public synthetic controls for the EC2 adapter port. Not live-host evidence.
use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::types::{ArtifactDigest, ProtocolName, VersionLabel};
use custodian_worker::result::job_document;
use custodian_worker_ec2::*;
use custodian_worker_microvm::{
    sha256, AttemptBinding, Refusal, ResultEnvelope, RESULT_ENVELOPE_SCHEMA,
};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
fn result_bytes() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "private-custodian.worker-result/1", "domain": "credential",
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "status": "complete", "roster": {"expected": 1, "observed": 1, "failed": 0},
        "aggregates": {"schema": "private-custodian.aggregates/1", "public_synthetic": true}
    }))
    .unwrap()
}
fn envelope(b: &AttemptBinding) -> Vec<u8> {
    serde_json::to_vec(&ResultEnvelope {
        schema: RESULT_ENVELOPE_SCHEMA.into(),
        binding: b.clone(),
        stdout: result_bytes(),
    })
    .unwrap()
}

struct TestGates {
    exposure: AtomicBool,
    export: AtomicBool,
    lease: AtomicBool,
}
impl TestGates {
    fn open() -> Arc<Self> {
        Arc::new(Self {
            exposure: AtomicBool::new(true),
            export: AtomicBool::new(true),
            lease: AtomicBool::new(true),
        })
    }
}
impl Gates for TestGates {
    fn exposure_acknowledged(&self, _: &AttemptBinding) -> bool {
        self.exposure.load(Ordering::SeqCst)
    }
    fn export_acknowledged(&self, _: &AttemptBinding) -> bool {
        self.export.load(Ordering::SeqCst)
    }
    fn lease_current(&self, _: &AttemptBinding) -> bool {
        self.lease.load(Ordering::SeqCst)
    }
}

type A = Adapter<SyntheticProvider, MemoryStore, Arc<TestGates>>;
fn adapter() -> (A, Arc<TestGates>) {
    let g = TestGates::open();
    (
        Adapter::new(
            SyntheticProvider::default(),
            MemoryStore::default(),
            g.clone(),
        ),
        g,
    )
}
fn collect(a: &A, k: &AttemptKey) -> Result<(), AdapterError> {
    a.collect(k, EvaluationDomain::Credential, &protocol(), 1)
        .map(|_| ())
}
fn ready(a: &A) -> (AttemptKey, InstanceId) {
    let k = a.begin(&binding(), &pins()).unwrap();
    let id = a.launch(&k).unwrap();
    (k, id)
}

#[test]
fn synthetic_round_trip_verifies_input_and_result_identity() {
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    a.deliver(&k, &job()).unwrap();
    assert_eq!(a.provider.delivered(&id), vec![job()]);
    a.provider.set_result(&id, envelope(&binding()));
    let r = a
        .collect(&k, EvaluationDomain::Credential, &protocol(), 1)
        .ok()
        .unwrap();
    assert_eq!(r.private_bytes(), result_bytes());
    a.terminate(&k).unwrap();
    a.terminate(&k).unwrap();
    assert!(a.provider.is_terminated(&id));
    assert_eq!(a.reconcile(&k).unwrap(), Phase::Terminated);
}

#[test]
fn result_collect_is_idempotent_and_conflicting_bytes_refuse() {
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    a.deliver(&k, &job()).unwrap();
    a.provider.set_result(&id, envelope(&binding()));
    collect(&a, &k).unwrap();
    collect(&a, &k).unwrap();
    let mut other = envelope(&binding());
    other.push(b' ');
    a.provider.set_result(&id, other);
    assert_eq!(collect(&a, &k), Err(AdapterError::Conflict));
}

#[test]
fn malformed_oversize_and_wrong_binding_results_refuse() {
    for (bytes, want) in [
        (
            b"not json".to_vec(),
            AdapterError::Result(Refusal::Malformed),
        ),
        (
            vec![b'x'; custodian_worker_microvm::MAX_ENVELOPE_BYTES + 1],
            AdapterError::Result(Refusal::Oversized),
        ),
        (
            envelope(&binding_with(1, 2)),
            AdapterError::Result(Refusal::BindingMismatch),
        ),
        (
            envelope(&binding_with(2, 1)),
            AdapterError::Result(Refusal::BindingMismatch),
        ),
    ] {
        let (a, _) = adapter();
        let (k, id) = ready(&a);
        a.deliver(&k, &job()).unwrap();
        a.provider.set_result(&id, bytes);
        assert_eq!(collect(&a, &k), Err(want));
    }
}

#[test]
fn oversize_or_altered_job_is_never_delivered() {
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    assert_eq!(
        a.deliver(&k, &vec![b'x'; MAX_JOB_BYTES + 1]),
        Err(AdapterError::Oversized)
    );
    let mut changed = job();
    changed.push(b' ');
    assert_eq!(
        a.deliver(&k, &changed),
        Err(AdapterError::Result(Refusal::BindingMismatch))
    );
    assert_eq!(a.provider.deliveries(&id), 0);
}

#[test]
fn closed_gates_and_stale_fence_block_delivery_and_collection() {
    for which in 0..3 {
        let (a, g) = adapter();
        let (k, id) = ready(&a);
        match which {
            0 => g.exposure.store(false, Ordering::SeqCst),
            1 => g.export.store(false, Ordering::SeqCst),
            _ => g.lease.store(false, Ordering::SeqCst),
        }
        let want = if which == 2 {
            AdapterError::StaleFence
        } else {
            AdapterError::GateClosed
        };
        assert_eq!(a.deliver(&k, &job()), Err(want));
        assert_eq!(a.provider.deliveries(&id), 0);
    }
    let (a, g) = adapter();
    let (k, id) = ready(&a);
    a.deliver(&k, &job()).unwrap();
    a.provider.set_result(&id, envelope(&binding()));
    g.lease.store(false, Ordering::SeqCst);
    assert_eq!(collect(&a, &k), Err(AdapterError::StaleFence));
}

#[test]
fn wrong_instance_or_image_never_receives_input() {
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    let other = HostPins {
        ami_id: "ami-0fedcba987654321f".into(),
        ..pins()
    };
    a.provider.swap_pins(&id, other);
    assert_eq!(a.deliver(&k, &job()), Err(AdapterError::InstanceMismatch));
    assert_eq!(a.provider.deliveries(&id), 0);

    let (a, _) = adapter();
    let (k, id) = ready(&a);
    a.provider.set_state(&id, InstanceState::Terminated);
    assert_eq!(a.deliver(&k, &job()), Err(AdapterError::InstanceMismatch));

    // A foreign instance cannot be substituted: the record names the instance.
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    let foreign = a.provider.plant_foreign(&pins());
    a.deliver(&k, &job()).unwrap();
    assert_eq!(a.provider.deliveries(&foreign), 0);
    assert_eq!(a.provider.deliveries(&id), 1);
}

#[test]
fn begin_is_idempotent_conflicts_and_rejects_stale_fence_or_bad_pins() {
    let (a, _) = adapter();
    let k = a.begin(&binding_with(1, 5), &pins()).unwrap();
    assert_eq!(a.begin(&binding_with(1, 5), &pins()).unwrap(), k);
    assert_eq!(
        a.begin(&binding_with(1, 4), &pins()).err(),
        Some(AdapterError::StaleFence)
    );
    assert_eq!(
        a.begin(&binding_with(1, 6), &pins()).err(),
        Some(AdapterError::Conflict)
    );
    let other = HostPins {
        ami_id: "ami-0fedcba987654321f".into(),
        ..pins()
    };
    assert_eq!(
        a.begin(&binding_with(1, 5), &other).err(),
        Some(AdapterError::Conflict)
    );
    let bad = HostPins {
        ami_id: "ami-latest".into(),
        ..pins()
    };
    assert_eq!(
        a.begin(&binding_with(2, 1), &bad).err(),
        Some(AdapterError::Invalid)
    );
    assert!(InstanceId::parse("i-ZZZ").is_err());
}

#[test]
fn launch_is_idempotent_and_one_instance_per_attempt() {
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    assert_eq!(a.launch(&k).unwrap(), id);
    assert_eq!(a.provider.launches(), 1);
    // A new attempt is a new instance, never reuse.
    let k2 = a.begin(&binding_with(2, 2), &pins()).unwrap();
    assert_ne!(a.launch(&k2).unwrap(), id);
    assert_eq!(a.provider.launches(), 2);
}

#[test]
fn lost_launch_response_is_ambiguous_then_fails_closed_without_delivery() {
    let (a, _) = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    a.provider.lose_next_launch_response();
    assert!(a.launch(&k).is_err());
    assert_eq!(a.deliver(&k, &job()), Err(AdapterError::WrongPhase));
    assert_eq!(a.launch(&k), Err(AdapterError::WrongPhase));
    assert_eq!(a.reconcile(&k).unwrap(), Phase::Failed);
    let id = a.store.load(&k).unwrap().unwrap().instance.unwrap();
    assert!(a.provider.is_terminated(&id));
    assert_eq!(a.provider.deliveries(&id), 0);
}

#[test]
fn restart_after_intent_adopts_or_relaunches_without_duplicates() {
    let (a, _) = adapter();
    let k = a.begin(&binding(), &pins()).unwrap();
    // Restart before any provider call: relaunch is safe.
    let restarted = Adapter::new(
        a.provider.clone(),
        MemoryStore::restore(a.store.snapshot()),
        TestGates::open(),
    );
    assert_eq!(restarted.reconcile(&k).unwrap(), Phase::LaunchIntent);
    let id = restarted.launch(&k).unwrap();
    // Crash after provider created but before the record was updated.
    let (b, _) = adapter();
    let kb = b.begin(&binding(), &pins()).unwrap();
    let token = b.store.load(&kb).unwrap().unwrap().token;
    let orphan = b.provider.launch(&token, &pins()).unwrap();
    assert_eq!(b.reconcile(&kb).unwrap(), Phase::Launched);
    assert_eq!(b.launch(&kb).unwrap(), orphan);
    assert_eq!(b.provider.launches(), 1);
    let _ = id;
}

#[test]
fn crash_after_delivery_start_is_possible_exposure_and_never_redelivered() {
    let (a, _) = adapter();
    let (k, id) = ready(&a);
    let mut rec = a.store.load(&k).unwrap().unwrap();
    rec.phase = Phase::Delivering;
    let v = rec.version;
    a.store.update(&k, v, rec).unwrap();
    assert_eq!(a.deliver(&k, &job()), Err(AdapterError::WrongPhase));
    assert_eq!(a.reconcile(&k).unwrap(), Phase::Failed);
    assert!(a.provider.is_terminated(&id));
    assert_eq!(a.provider.deliveries(&id), 0);
}

#[test]
fn concurrent_begin_and_launch_converge_on_one_record_and_instance() {
    let provider = SyntheticProvider::default();
    let store = MemoryStore::default();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (p, s) = (provider.clone(), store.clone());
            std::thread::spawn(move || {
                struct Open;
                impl Gates for Open {
                    fn exposure_acknowledged(&self, _: &AttemptBinding) -> bool {
                        true
                    }
                    fn export_acknowledged(&self, _: &AttemptBinding) -> bool {
                        true
                    }
                    fn lease_current(&self, _: &AttemptBinding) -> bool {
                        true
                    }
                }
                let a = Adapter::new(p, s, Open);
                let k = match a.begin(&binding(), &pins()) {
                    Ok(k) => k,
                    Err(_) => AttemptKey::of(&binding()),
                };
                a.launch(&k).ok()
            })
        })
        .collect();
    let ids: Vec<_> = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();
    assert!(!ids.is_empty());
    assert!(ids.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(provider.launches(), 1);
}
