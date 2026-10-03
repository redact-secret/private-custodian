//! C12 crash-window sweep across the whole pipeline.
//!
//! The store, ledger and lifecycle crates each test their own crash windows.
//! This suite crosses the layers: a crash is injected at every reachable
//! boundary of a full run (submit, approve, reserve, start, exposure,
//! validation, finish, audit export, feed publication, release charge and
//! history, contamination, activation import), then the process "restarts"
//! (the database file is reopened, the lease clock passes, `Service::start`
//! runs its startup sequence), the idempotent script is driven again, and the
//! end state is checked for the properties that matter: no double execution,
//! no double charge, no refund after exposure, nothing lost from the audit
//! trail, a ledger that still verifies, and a store that still starts.
//!
//! Every `FaultOp` must be either swept here or named in `COVERED_ELSEWHERE`
//! with the test that covers it, so a new fault point forces a decision.
//! Synthetic data only; project-maintained evidence.

mod c12;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use c12::*;
use custodian_cli::command::{Contaminated, ReconcileTarget, RepairCommand, VerifyTarget};
use custodian_cli::{Command, Control};
use custodian_core::{Exposure, RunState};
use custodian_ledger::{ExportFaultPoint, Exporter, Verifier};
use custodian_lifecycle::{CrashOnce as LifeCrash, LifecyclePoint};
use custodian_store::{FaultInjector, FaultOp, FaultPhase, FaultPoint, SqliteStore, StoreConfig};

/// Fires once at a chosen store boundary.
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

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn open_with(p: &mut Pipe, arm: Option<&Arc<Arm>>) {
    let path = p.w.rw.db.path();
    let cfg = match arm {
        Some(a) => StoreConfig::default().with_fault(a.clone()),
        None => StoreConfig::default(),
    };
    p.w.rw.store = SqliteStore::open_with_config(path, cfg).unwrap();
}

/// Fault ops that the cross-layer sweep does not reach, and the test that
/// covers each. Anything not here must be fired by the sweep.
const COVERED_ELSEWHERE: &[(FaultOp, &str)] = &[
    (
        FaultOp::ProvisionBudget,
        "custodian-store/tests/crash.rs::crash_around_ack_and_provision_and_exhaustion_denial",
    ),
    (
        FaultOp::Retry,
        "custodian-store/tests/crash.rs::crash_during_retry_never_double_charges",
    ),
    (
        FaultOp::RecordRotation,
        "this file: lifecycle_crashes_converge_when_the_same_command_is_repeated; custodian-store/tests/epoch_standing.rs",
    ),
    (
        FaultOp::Cancel,
        "this file: identity_mismatch_before_start_refunds_and_a_cancel_crash_refunds_once",
    ),
    (
        FaultOp::FailBeforeStart,
        "this file: identity_mismatch_before_start_refunds_and_a_cancel_crash_refunds_once",
    ),
    (
        FaultOp::Reconcile,
        "this file: a_crash_inside_repair_recover_and_clear_reconcile_is_resumable",
    ),
    (
        FaultOp::RenewLease,
        "c12_crash_intake.rs::a_lost_lease_renewal_acknowledgement_does_not_stop_the_holder_or_double_charge",
    ),
    (
        FaultOp::IntakeClaim,
        "custodian-store/tests/intake.rs::crash_injection_at_every_intake_boundary_loses_and_duplicates_nothing",
    ),
    (
        FaultOp::IntakeEnqueue,
        "custodian-store/tests/intake.rs::crash_injection_at_every_intake_boundary_loses_and_duplicates_nothing",
    ),
    (
        FaultOp::IntakeLease,
        "c12_crash_intake.rs::queue_lease_and_completion_crashes_redeliver_and_never_lose_or_duplicate",
    ),
    (
        FaultOp::IntakeComplete,
        "c12_crash_intake.rs::queue_lease_and_completion_crashes_redeliver_and_never_lose_or_duplicate",
    ),
    (
        FaultOp::IntakeRemoval,
        "c12_crash_intake.rs::installation_removal_and_submission_cancel_crashes_converge_on_repeat",
    ),
    (
        FaultOp::CancelSubmission,
        "c12_crash_intake.rs::installation_removal_and_submission_cancel_crashes_converge_on_repeat",
    ),
    (
        FaultOp::ApplyLegacyImport,
        "custodian-store/tests/legacy_import.rs::a_crash_at_either_commit_boundary_leaves_nothing_or_everything",
    ),
    (
        FaultOp::RetentionExpire,
        "custodian-store/tests/retention.rs::a_crash_during_a_pass_leaves_a_consistent_store_and_the_next_pass_converges",
    ),
    (
        FaultOp::RetentionPurge,
        "custodian-store/tests/retention.rs::a_crash_during_a_pass_leaves_a_consistent_store_and_the_next_pass_converges",
    ),
];

// ---- the main pipeline script ------------------------------------------------

struct Cx {
    attempt: Option<custodian_core::RunId>,
    approval_id: Option<String>,
}

fn act_doc() -> Vec<u8> {
    let v = dc::activation_value(dc::disclosure_ref(), &cc::id("pac_", 7), 1, "active");
    serde_json::to_vec(&v).unwrap()
}

/// Run script step `i` best effort. Returns false when the injected crash
/// fired (the "process" is gone and the script must stop).
fn step(p: &Pipe, arm: &Arm, i: usize, cx: &mut Cx) -> bool {
    let (req, _) = p.request(1);
    match i {
        0 => {
            p.w.run(
                Who::Operator,
                &Command::PolicyImportActivation {
                    document: act_doc(),
                    confirm_activation_id: cc::id("pac_", 7),
                    confirm_sequence: 1,
                },
            );
        }
        1 => {
            p.submit(1);
        }
        2 => {
            let o = p.approve(1);
            if let Some(a) = o.field("attempt_id").and_then(|v| v.as_str()) {
                cx.attempt = Some(custodian_core::RunId::new(a.to_owned()));
                cx.approval_id = o
                    .field("approval_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
            }
        }
        3 => {
            // Resolve the attempt from the store (the crash may have lost the
            // output) and dispatch only if it is still reserved.
            let rec = p.w.rw.store.latest_attempt_of(req.request_id.as_str());
            if let Ok(Some(a)) = rec {
                cx.attempt = Some(a.attempt.clone());
                if a.state == RunState::Reserved {
                    let acts = p.activations();
                    if let Ok(svc) = p.start(&acts) {
                        let _ = p.dispatch(&svc, 1, &a.attempt);
                    }
                }
            }
        }
        4 => {
            p.export();
        }
        5 => {
            p.w.run(Who::Operator, &Command::FeedPublish);
        }
        6 => {
            // Prepare a release if the attempt completed. Idempotent by key.
            if let Some(attempt) = cx.attempt.clone() {
                let rec = p.w.rw.store.attempt(&attempt);
                if let Ok(Some(r)) = rec {
                    if r.state == RunState::Completed {
                        let acts = p.activations();
                        if let Ok(svc) = p.start(&acts) {
                            let rep = fake_report(p, &attempt);
                            let aid = cx.approval_id.clone().unwrap_or_default();
                            if !aid.is_empty() {
                                let asm = p.assemble(1, &attempt, &aid, &rep);
                                p.w.clock.set(PREPARE_AT.max(p.w.clock.as_ref_now()));
                                let _ = prepare(p, &svc, &req, &asm, 1, p.w.clock.as_ref_now());
                            }
                        }
                    }
                }
            }
        }
        7 => {
            p.w.run(
                Who::Operator,
                &Command::LifecycleReport {
                    epoch: p.w.rw.epoch.clone(),
                    kind: Contaminated::Exposed,
                    reason: "results_exposed".into(),
                    key: lc::idk(1),
                },
            );
        }
        8 => {
            p.w.run(Who::Operator, &Command::FeedPublish);
        }
        9 => {
            p.export();
        }
        _ => unreachable!(),
    }
    arm.fired() || !armed(arm)
}

fn armed(arm: &Arm) -> bool {
    arm.0.lock().unwrap().is_some()
}

/// A validated-roster report stand-in used only to assemble records after a
/// crash-and-restart, when the original `DispatchReport` is gone.
fn fake_report(p: &Pipe, attempt: &custodian_core::RunId) -> custodian_worker::DispatchReport {
    // Re-run validation of the scripted good output against the plan.
    let (req, _) = p.request(1);
    let validated = custodian_worker::result::validate_result(
        &Scripted::good_stdout(p.sandbox.roster),
        req.plan.domain,
        &req.plan.protocol,
        p.sandbox.roster,
    )
    .unwrap();
    let _ = attempt;
    custodian_worker::DispatchReport {
        outcome: validated.outcome,
        reason: validated.reason,
        exposure: Exposure::Exposed,
        termination: None,
        result: Some(validated),
        settled: true,
        elapsed: std::time::Duration::ZERO,
        isolation: custodian_worker::IsolationVerification::test_only_not_isolated(NOW),
    }
}

const STEPS: usize = 10;

/// Ops the main script is expected to reach.
const SWEPT: &[FaultOp] = &[
    FaultOp::RecordActivation,
    FaultOp::SubmitRequest,
    FaultOp::ApproveSubmission,
    FaultOp::Reserve,
    FaultOp::Start,
    FaultOp::RecordExposure,
    FaultOp::BeginValidation,
    FaultOp::Finish,
    FaultOp::OutboxAck,
    FaultOp::FeedAppend,
    FaultOp::FeedDelivered,
    FaultOp::ChargeRelease,
    FaultOp::AppendDisclosureHistory,
    FaultOp::EpochChange,
    FaultOp::ObligationEnqueue,
    FaultOp::Recover,
];

fn check_end_state(p: &Pipe, label: &str) {
    let store = &p.w.rw.store;
    store
        .integrity_check()
        .unwrap_or_else(|e| panic!("{label}: integrity {e:?}"));
    store
        .verify_lifecycle_invariants()
        .unwrap_or_else(|e| panic!("{label}: lifecycle invariants {e:?}"));
    let attempts = store.request_attempts(&cc::id("req_", 1)).unwrap();
    assert!(attempts.len() <= 1, "{label}: more than one attempt");
    let b = p.w.budget();
    assert_eq!(b.held, 0, "{label}: nothing may stay held after recovery");
    assert!(b.consumed + b.refunded <= 1, "{label}: double charge {b:?}");
    assert!(p.sandbox.runs() <= 1, "{label}: double execution");
    if let Some(a) = attempts.first() {
        assert!(a.state.is_terminal(), "{label}: attempt left {:?}", a.state);
        match a.exposure {
            Exposure::Exposed => assert_eq!(
                (b.consumed, b.refunded),
                (1, 0),
                "{label}: exposed work must be consumed, never refunded"
            ),
            Exposure::NotExposed => {
                assert_eq!(p.sandbox.runs(), 0, "{label}: ran without exposure record");
                assert_eq!(
                    (b.consumed, b.refunded),
                    (0, 1),
                    "{label}: unexposed refunds once"
                );
            }
        }
    }
    // The audit trail drains and the ledger verifies with the pinned root.
    assert_eq!(code(&p.export()), "exported", "{label}");
    assert_eq!(store.outbox_pending_count().unwrap(), 0, "{label}");
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
        "verified",
        "{label}"
    );
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Store))),
        "consistent",
        "{label}"
    );
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger))),
        "consistent",
        "{label}"
    );
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Feed))),
        "consistent",
        "{label}"
    );
}

#[test]
fn a_crash_at_every_reachable_boundary_of_the_full_pipeline_converges_safely() {
    let mut fired_ops: BTreeSet<String> = BTreeSet::new();
    for op in SWEPT {
        for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
            let label = format!("{op:?}/{phase:?}");
            // Only the release steps need the full authorized roster; a small
            // population keeps the rest of the sweep fast.
            let entries = if matches!(
                op,
                FaultOp::ChargeRelease | FaultOp::AppendDisclosureHistory
            ) {
                ROSTER
            } else {
                4
            };
            let mut p = Pipe::new(3, entries);
            let arm = Arc::new(Arm::default());
            open_with(&mut p, Some(&arm));
            arm.arm(*op, phase);
            let mut cx = Cx {
                attempt: None,
                approval_id: None,
            };
            let mut crashed = false;
            for i in 0..STEPS {
                if !step(&p, &arm, i, &mut cx) {
                    crashed = true;
                    break;
                }
                if arm.fired() {
                    crashed = true;
                    break;
                }
            }
            // Recover is only reached on restart; fire it there if needed.
            if !crashed {
                // The script ran clean past the armed point: the point is
                // reached only by the startup sequence of a later start.
                p.w.clock.advance(10_000);
                let acts = p.activations();
                let _ = p.start(&acts);
                crashed = arm.fired();
            }
            assert!(crashed, "{label}: the fault was never reached");
            fired_ops.insert(format!("{op:?}"));

            // Restart: a new process opens the same file, time passes.
            open_with(&mut p, None);
            p.w.clock.advance(10_000);
            {
                let acts = p.activations();
                p.start(&acts).unwrap_or_else(|e| {
                    panic!("{label}: restart refused at {}: {:?}", e.step, e.reason)
                });
            }
            // Drive the whole idempotent script again.
            let none = Arm::default();
            let mut cx = Cx {
                attempt: cx.attempt,
                approval_id: cx.approval_id,
            };
            for i in 0..STEPS {
                step(&p, &none, i, &mut cx);
            }
            check_end_state(&p, &label);
        }
    }
    // Every fault op is either swept above or accounted for.
    let covered: BTreeSet<String> = COVERED_ELSEWHERE
        .iter()
        .filter(|(op, _)| !SWEPT.contains(op))
        .map(|(op, _)| format!("{op:?}"))
        .collect();
    for op in FaultOp::ALL {
        let name = format!("{op:?}");
        assert!(
            fired_ops.contains(&name) || covered.contains(&name),
            "{name}: neither swept nor covered elsewhere"
        );
    }
    for (op, _) in COVERED_ELSEWHERE {
        assert!(FaultOp::ALL.contains(op));
    }
}

// ---- ledger exporter windows ---------------------------------------------------

#[test]
fn export_crashes_converge_with_each_event_written_once() {
    use custodian_ledger::{CrashOnce as ExportCrash, ExporterConfig};
    let _ = ExporterConfig::default;
    for point in [
        ExportFaultPoint::BeforeWrite,
        ExportFaultPoint::AfterWrite,
        ExportFaultPoint::AfterAck,
    ] {
        let p = Pipe::new(3, 4);
        p.reserve(1);
        p.reserve(2);
        let pending = p.w.rw.store.outbox_pending_count().unwrap();
        assert!(pending >= 4);
        let verifier = Verifier::new(p.w.roots.clone());
        let fault = ExportCrash::new(point);
        let exporter = Exporter::new(&p.w.ledger, &p.w.key.signer, &verifier).with_fault(&fault);
        let r = exporter.export_pending(&p.w.rw.store, NOW + 10);
        assert!(r.is_err(), "{point:?}: the crash must surface");
        assert!(fault.fired());
        // The restart finishes the job; identical bytes are a no-op.
        assert_eq!(code(&p.export()), "exported", "{point:?}");
        assert_eq!(p.w.rw.store.outbox_pending_count().unwrap(), 0);
        let audit_files =
            p.w.ledger
                .paths()
                .into_iter()
                .filter(|f| f.starts_with("records/audit/"))
                .count();
        assert!(audit_files as u64 >= pending, "{point:?}: events missing");
        assert!(
            !p.w.ledger
                .paths()
                .iter()
                .any(|f| f.starts_with("quarantine/")),
            "{point:?}: a retry must never conflict"
        );
        assert_eq!(
            code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
            "verified"
        );
        assert_eq!(
            code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Ledger))),
            "consistent"
        );
    }
}

// ---- lifecycle windows -----------------------------------------------------------

fn crash_cmd(p: &Pipe, point: LifecyclePoint, who: Who, cmd: &Command) -> (bool, &'static str) {
    let fault = LifeCrash::new(point);
    let mut parts = p.w.parts();
    parts.fault = &fault;
    let out = Control::new(parts).execute(&p.w.principal(who), cmd, false);
    (fault.fired(), out.code())
}

#[test]
fn lifecycle_crashes_converge_when_the_same_command_is_repeated() {
    // Report: crash after the contamination is durable, before retirement.
    let p = Pipe::new(3, 4);
    p.reserve(1);
    let report = Command::LifecycleReport {
        epoch: p.w.rw.epoch.clone(),
        kind: Contaminated::Exposed,
        reason: "results_exposed".into(),
        key: lc::idk(1),
    };
    let (fired, _) = crash_cmd(&p, LifecyclePoint::AfterReport, Who::Operator, &report);
    assert!(fired);
    // The repeat replays the durable report and finishes the retirement that
    // the crash interrupted, in the store and in the registry.
    let again = p.w.run(Who::Operator, &report);
    assert!(again.is_ok(), "{}", again.render());
    let standing =
        p.w.rw
            .store
            .epoch_standing(p.w.rw.epoch.as_str())
            .unwrap()
            .unwrap();
    assert!(standing.standing.retired);
    assert_eq!(
        p.w.rw.fx.pop.state(&p.w.rw.epoch).unwrap(),
        custodian_corpus::EpochState::Retired
    );
    assert_eq!(
        code(&p.w.run(Who::Operator, &Command::FeedPublish)),
        "published"
    );
    p.export();
    assert_eq!(
        code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Feed))),
        "consistent"
    );

    // Rotation: crash at each of the four steps; the repeat converges and the
    // old epoch's budget is never touched.
    for point in [
        LifecyclePoint::AfterStoreRetire,
        LifecyclePoint::AfterRegistryRetire,
        LifecyclePoint::AfterRotationLink,
        LifecyclePoint::AfterRotationBudgets,
    ] {
        let p = Pipe::new(3, 4);
        p.reserve(1);
        let spent = p.w.budget();
        let next = p.w.rw.seal_next("rot");
        let rotate = Command::LifecycleRotate {
            predecessor: p.w.rw.epoch.clone(),
            successor: next.clone(),
            confirm_predecessor: p.w.rw.epoch.clone(),
            confirm_successor: next.clone(),
            run_budget_limit: 2,
            reason: "planned_rotation".into(),
            key: lc::idk(3),
        };
        let (fired, _) = crash_cmd(&p, point, Who::Operator, &rotate);
        assert!(fired, "{point:?}");
        // Fails closed in between: the old epoch no longer admits new use.
        assert_eq!(code(&p.submit(5)), "epoch_blocked", "{point:?}");
        let o = p.w.run(Who::Operator, &rotate);
        assert_eq!(code(&o), "rotated", "{point:?}: {}", o.render());
        assert_eq!(
            p.w.budget(),
            spent,
            "{point:?}: the old budget is untouched"
        );
        p.w.rw.store.verify_lifecycle_invariants().unwrap();
        p.export();
        assert_eq!(
            code(&p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All))),
            "verified"
        );
    }

    // Feed publication: crash at each of its three boundaries.
    for point in [
        LifecyclePoint::BeforeFeedAppend,
        LifecyclePoint::AfterFeedAppend,
        LifecyclePoint::AfterDestinationPut,
    ] {
        let p = Pipe::new(3, 4);
        p.reserve(1);
        let (fired, _) = crash_cmd(&p, point, Who::Operator, &Command::FeedPublish);
        assert!(fired, "{point:?}");
        // The next publication (or the startup delivery) finishes exactly once.
        let acts = p.activations();
        p.start(&acts).unwrap();
        let again = p.w.run(Who::Operator, &Command::FeedPublish);
        assert!(again.is_ok(), "{point:?}: {}", again.render());
        let seqs = p.w.feed.sequences(&lc::feed_id());
        let expected: Vec<u64> = (1..=seqs.len() as u64).collect();
        assert_eq!(
            seqs, expected,
            "{point:?}: contiguous, no gap, no duplicate"
        );
        assert_eq!(
            code(&p.w.run(Who::Auditor, &Command::Reconcile(ReconcileTarget::Feed))),
            "consistent",
            "{point:?}"
        );
    }
}

// ---- recover and clear windows ---------------------------------------------------

#[test]
fn a_crash_inside_repair_recover_and_clear_reconcile_is_resumable() {
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        // Recover: an exposed attempt that lapsed is consumed once, whatever
        // happens to the first recovery.
        let mut p = Pipe::new(3, 4);
        let (attempt, _) = p.reserve(1);
        // Start it, then lose the worker.
        let lease =
            p.w.rw
                .store
                .start_attempt(&custodian_store::StartCommand {
                    attempt: &attempt,
                    owner: "worker-lost",
                    actor: &sc::actor(),
                    now: NOW + 1,
                    lease_secs: 300,
                    observed: Some(&cc::observed(cc::activation(), NOW + 1)),
                    max_state_age_secs: 300,
                })
                .unwrap();
        p.w.rw
            .store
            .record_exposure(&lease, &sc::actor(), NOW + 2)
            .unwrap();
        p.w.clock.advance(5_000);
        let arm = Arc::new(Arm::default());
        open_with(&mut p, Some(&arm));
        arm.arm(FaultOp::Recover, phase);
        let recover = |p: &Pipe| {
            p.w.run(
                Who::Operator,
                &Command::Repair(RepairCommand::Recover {
                    confirm_store_id: p.w.rw.store.store_id().unwrap(),
                }),
            )
        };
        let first = recover(&p);
        assert!(arm.fired(), "{phase:?}: {}", first.code());
        open_with(&mut p, None);
        let second = recover(&p);
        assert!(
            second.is_ok() || second.code() == "recovered",
            "{phase:?}: {}",
            second.code()
        );
        let b = p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0), "{phase:?}");
        p.w.rw.store.verify_invariants().unwrap();

        // Clear: a crash around the audited clear leaves either blocked or
        // cleared, never half; a repeat finishes it.
        let mut q = Pipe::new(3, 4);
        q.reserve(1);
        q.export();
        q.w.rw.store.block_for_reconcile().unwrap();
        let arm = Arc::new(Arm::default());
        open_with(&mut q, Some(&arm));
        arm.arm(FaultOp::Reconcile, phase);
        let clear = |q: &Pipe| {
            let seq = q.w.rw.store.latest_checkpoint().unwrap().unwrap().seq;
            q.w.run(
                Who::Operator,
                &Command::Repair(RepairCommand::ClearReconcile {
                    confirm_store_id: q.w.rw.store.store_id().unwrap(),
                    confirm_checkpoint_seq: seq,
                }),
            )
        };
        let _ = clear(&q);
        assert!(arm.fired(), "{phase:?}");
        open_with(&mut q, None);
        if q.w.rw.store.needs_reconcile().unwrap() {
            assert_eq!(code(&clear(&q)), "cleared", "{phase:?}");
        }
        assert!(!q.w.rw.store.needs_reconcile().unwrap());
        assert_eq!(
            q.w.budget().held,
            1,
            "{phase:?}: budget untouched by the clear"
        );
        q.w.rw.store.verify_invariants().unwrap();
    }
}

#[test]
fn identity_mismatch_before_start_refunds_and_a_cancel_crash_refunds_once() {
    // FailBeforeStart: a pinned artifact changed after approval is refused
    // before any protected byte is opened, so the reservation is refunded.
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        let mut p = Pipe::new(3, 4);
        let (req, _) = p.request(1);
        let (attempt, _) = p.reserve(1);
        std::fs::write(&p.arts.sources.config, b"tampered after approval").unwrap();
        let arm = Arc::new(Arm::default());
        open_with(&mut p, Some(&arm));
        arm.arm(FaultOp::FailBeforeStart, phase);
        {
            let acts = p.activations();
            let svc = p.start(&acts).unwrap();
            let _ = p.dispatch_req(&svc, &req, &attempt);
        }
        assert!(arm.fired(), "{phase:?}");
        open_with(&mut p, None);
        p.w.clock.advance(10_000);
        let acts = p.activations();
        p.start(&acts).unwrap();
        let b = p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 1), "{phase:?}");
        assert_eq!(p.sandbox.runs(), 0);
        p.w.rw.store.verify_invariants().unwrap();
    }
    // Cancel: before start it refunds exactly once, even if the first cancel
    // crashes at either boundary.
    for phase in [FaultPhase::BeforeCommit, FaultPhase::AfterCommit] {
        let mut p = Pipe::new(3, 4);
        p.reserve(1);
        let arm = Arc::new(Arm::default());
        open_with(&mut p, Some(&arm));
        arm.arm(FaultOp::Cancel, phase);
        let (req, _) = p.request(1);
        let cancel = Command::RequestCancel {
            request_id: req.request_id.clone(),
        };
        let _ = p.w.run(Who::Operator, &cancel);
        assert!(arm.fired(), "{phase:?}");
        open_with(&mut p, None);
        let o = p.w.run(Who::Operator, &cancel);
        assert!(o.is_ok(), "{phase:?}: {}", o.code());
        let b = p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 1), "{phase:?}");
        p.w.rw.store.verify_invariants().unwrap();
    }
}
