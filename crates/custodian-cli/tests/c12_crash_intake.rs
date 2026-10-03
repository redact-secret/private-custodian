//! C12 crash windows for lease renewal, the intake queue, installation removal
//! and submission cancel: the store fault points that had no injected-crash
//! test before this suite. Real SQLite files, synthetic data.
//!
//! The intake queue is at-least-once by design: a consumer that crashes
//! before completing gets the item again. What must hold is that nothing is
//! lost, no two consumers hold a live lease, and redelivery cannot cause a
//! second charge (the submission path is idempotent; see edge.rs).

mod c12;

use std::sync::{Arc, Mutex};

use c12::*;
use custodian_cli::Command;
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{
    Claim, DeliveryStore, InstallationRegistry, IntakeQueue, QueuedRequest,
};
use custodian_store::{
    FaultInjector, FaultOp, FaultPhase, FaultPoint, SqliteStore, StartCommand, StoreConfig,
};

#[derive(Default)]
struct Arm(Mutex<Option<FaultPoint>>);

impl Arm {
    fn arm(&self, op: FaultOp, phase: FaultPhase) {
        *self.0.lock().unwrap() = Some(FaultPoint { op, phase });
    }
    fn fired(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }
}

impl FaultInjector for Arm {
    fn crash_at(&self, point: FaultPoint) -> bool {
        let mut g = self.0.lock().unwrap();
        if *g == Some(point) {
            *g = None;
            true
        } else {
            false
        }
    }
}

fn open_with(p: &mut Pipe, arm: Option<&Arc<Arm>>) {
    let path = p.w.rw.db.path();
    let cfg = match arm {
        Some(a) => StoreConfig::default().with_fault(a.clone()),
        None => StoreConfig::default(),
    };
    p.w.rw.store = SqliteStore::open_with_config(path, cfg).unwrap();
}

fn delivery(n: u64) -> DeliveryId {
    DeliveryId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap()
}

fn queued_request(n: u64) -> QueuedRequest {
    QueuedRequest {
        delivery: delivery(n),
        installation: InstallationId::new(900_001).unwrap(),
        repository: RepositoryId::new(800_001).unwrap(),
        pull_request: PullRequestNumber::new(7).unwrap(),
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        actor: custodian_contracts::types::ActorRef::parse(&cc::id("act_", 1)).unwrap(),
        github_user: GithubUserId::new(700_001).unwrap(),
        received_at: ts(NOW),
    }
}

const PHASES: [FaultPhase; 2] = [FaultPhase::BeforeCommit, FaultPhase::AfterCommit];

#[test]
fn a_lost_lease_renewal_acknowledgement_does_not_stop_the_holder_or_double_charge() {
    for phase in PHASES {
        let mut p = Pipe::new(3, 4);
        let (attempt, _) = p.reserve(1);
        let arm = Arc::new(Arm::default());
        open_with(&mut p, Some(&arm));
        let lease = p
            .w
            .rw
            .store
            .start_attempt(&StartCommand {
                attempt: &attempt,
                owner: "worker-renew",
                actor: &sc::actor(),
                now: NOW + 1,
                lease_secs: 300,
                observed: Some(&cc::observed(cc::activation(), NOW + 1)),
                max_state_age_secs: 300,
            })
            .unwrap();
        arm.arm(FaultOp::RenewLease, phase);
        assert!(p.w.rw.store.renew_lease(&lease, NOW + 10, 300).is_err());
        assert!(arm.fired());
        open_with(&mut p, None);
        // The holder repeats the renewal it never saw acknowledged, then finishes.
        let lease = p.w.rw.store.renew_lease(&lease, NOW + 20, 300).unwrap();
        let s = &p.w.rw.store;
        s.record_exposure(&lease, &sc::actor(), NOW + 21).unwrap();
        s.begin_validation(&lease, &sc::actor(), NOW + 22).unwrap();
        s.finish(
            &lease,
            custodian_contracts::execution::ExecutionOutcome::Success,
            custodian_core::ReasonCode::Completed,
            &sc::actor(),
            NOW + 23,
        )
        .unwrap();
        let b = p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0), "{phase:?}");
        p.w.rw.store.verify_invariants().unwrap();
    }
}

#[test]
fn queue_lease_and_completion_crashes_redeliver_and_never_lose_or_duplicate() {
    for phase in PHASES {
        for op in [FaultOp::IntakeLease, FaultOp::IntakeComplete] {
            let mut q = Pipe::new(3, 4);
            assert_eq!(q.w.rw.store.claim(&delivery(1)).unwrap(), Claim::New);
            q.w.rw.store.enqueue(queued_request(1)).unwrap();
            let arm = Arc::new(Arm::default());
            open_with(&mut q, Some(&arm));
            let mut t = NOW;
            if op == FaultOp::IntakeLease {
                arm.arm(op, phase);
                assert!(q.w.rw.store.queue_lease("c1", t, 60).is_err());
            } else {
                let leased = q.w.rw.store.queue_lease("c1", t, 60).unwrap().unwrap();
                arm.arm(op, phase);
                assert!(q
                    .w
                    .rw
                    .store
                    .queue_complete(leased.seq, leased.lease_token, t + 1)
                    .is_err());
            }
            assert!(arm.fired(), "{op:?}/{phase:?}");
            open_with(&mut q, None);
            t += 1_000; // any earlier lease has lapsed
            assert!(q.w.rw.store.queue_depth().unwrap() <= 1);
            // The consumer returns: it gets the item at most once at a time
            // and finishes it, or finds it already finished.
            match q.w.rw.store.queue_lease("c2", t, 60).unwrap() {
                Some(l) => {
                    assert!(
                        q.w.rw.store.queue_lease("c3", t, 60).unwrap().is_none(),
                        "two live leases"
                    );
                    q.w.rw.store
                        .queue_complete(l.seq, l.lease_token, t + 1)
                        .unwrap();
                }
                None => assert_eq!(
                    q.w.rw.store.queue_depth().unwrap(),
                    0,
                    "{op:?}/{phase:?}: lost"
                ),
            }
            assert_eq!(q.w.rw.store.queue_depth().unwrap(), 0, "{op:?}/{phase:?}");
            assert_eq!(q.w.rw.store.claim(&delivery(1)).unwrap(), Claim::Seen);
            q.w.rw.store.integrity_check().unwrap();
        }
    }
}

#[test]
fn installation_removal_and_submission_cancel_crashes_converge_on_repeat() {
    for phase in PHASES {
        // An installation removal only ever restricts further; a crash either
        // records it or not, and a repeat records it.
        let mut r = Pipe::new(3, 4);
        let arm = Arc::new(Arm::default());
        open_with(&mut r, Some(&arm));
        arm.arm(FaultOp::IntakeRemoval, phase);
        let inst = InstallationId::new(900_001).unwrap();
        assert!(r.w.rw.store.mark_installation_removed(inst).is_err());
        assert!(arm.fired());
        open_with(&mut r, None);
        r.w.rw.store.mark_installation_removed(inst).unwrap();
        assert!(r.w.rw.store.installation_removed(inst).unwrap());

        // Cancelling a pending submission charges and refunds nothing, and a
        // repeat after a crash finishes the job.
        let mut s = Pipe::new(3, 4);
        assert!(s.submit(1).is_ok());
        let arm = Arc::new(Arm::default());
        open_with(&mut s, Some(&arm));
        arm.arm(FaultOp::CancelSubmission, phase);
        let (req, _) = s.request(1);
        let cancel = Command::RequestCancel {
            request_id: req.request_id.clone(),
        };
        let _ = s.w.run(Who::Requester, &cancel);
        assert!(arm.fired(), "{phase:?}");
        open_with(&mut s, None);
        let again = s.w.run(Who::Requester, &cancel);
        assert!(
            again.is_ok() || again.code() == "already_decided",
            "{phase:?}: {}",
            again.code()
        );
        let b = s.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 0), "{phase:?}");
        assert_eq!(
            s.approve(1).code(),
            "already_decided",
            "{phase:?}: a cancelled request cannot be approved"
        );
        s.w.rw.store.verify_invariants().unwrap();
    }
}
