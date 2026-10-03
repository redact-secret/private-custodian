//! HG-3 through the operator CLI: `legacy apply` (ADR 0115, ADR 0118).
//!
//! The command re-imports the reviewed extract deterministically, requires the
//! operator to name the exact handoff and report digests, requires every gate
//! of the handoff to be cited, and then writes the legacy consumption through
//! the store in one audited transaction. Synthetic data only; nothing here
//! reads a protected corpus or a real legacy directory.

mod common;

use common::*;
use custodian_bridge::legacy::handoff::{CheckEvidence, HandoffEntry, HandoffRecord};
use custodian_bridge::legacy::model::Label;
use custodian_bridge::legacy::{dry_run, DryRun};
use custodian_cli::command::{build_command, parse_args};
use custodian_cli::{CliReason, Command};
use custodian_contracts::common::{BudgetKind, EvaluationDomain};
use custodian_contracts::types::{DocumentDigest, Timestamp};
use serde_json::{json, Value};

const T0: u64 = 1_800_000_000;

fn sha(n: u64) -> String {
    format!("sha256:{n:064x}")
}

fn src(kind: &str, locator: &str, n: u64) -> Value {
    json!({"kind": kind, "locator": locator, "sha256": sha(n), "observed_at": T0})
}

fn extract_bytes(scope: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "private-custodian.legacy-extract/1",
        "extracted_at": T0,
        "review": {"reviewer_role": "maintainer", "review_ref": "review-synthetic-1", "reviewed_at": T0 + 10},
        "scopes": [scope]
    }))
    .unwrap()
}

/// One complete attempt against a declared limit of three: one unit consumed.
fn spent_once() -> Value {
    json!({
        "lifecycle": "holdout", "domain": "credential",
        "scope": {"kind": "population_epoch", "population": "synthetic-pop-a", "epoch": "epoch-1"},
        "declared_limit": 3,
        "attempts": [{"run": "run-0001", "state": "complete", "source": 1}],
        "reported_consumed": 1, "reported_receipts": 1,
        "independence": {"claim": "custodian-declared"},
        "contamination": {"state": "none_recorded", "source": 2},
        "sources": [
            src("manifest", "holdout/synthetic-manifest.json", 1),
            src("aggregate", "evidence/synthetic/aggregate.json", 2),
            {"kind": "custodian-statement", "locator": "reviewed-no-contamination-mark", "observed_at": T0}
        ]
    })
}

/// The same legacy scope, now attested unspent: fewer consumed units.
fn attested_unspent() -> Value {
    json!({
        "lifecycle": "holdout", "domain": "credential",
        "scope": {"kind": "population_epoch", "population": "synthetic-pop-a", "epoch": "epoch-1"},
        "declared_limit": 3, "attempts": [],
        "independence": {"claim": "custodian-declared"},
        "contamination": {"state": "none_recorded", "source": 1},
        "sources": [
            src("unspent-attestation", "evidence/synthetic/unspent.json", 3),
            {"kind": "custodian-statement", "locator": "reviewed-no-contamination-mark", "observed_at": T0}
        ]
    })
}

fn evidence(n: u64) -> Option<CheckEvidence> {
    Some(CheckEvidence {
        reference: Label::parse(&format!("review-{n}")).unwrap(),
        at: Timestamp::new(T0 + n).unwrap(),
    })
}

struct Prepared {
    extract: Vec<u8>,
    handoff: Vec<u8>,
    handoff_digest: DocumentDigest,
    report_digest: DocumentDigest,
    run: DryRun,
}

fn prepare(w: &World, extract: Vec<u8>, complete: bool) -> Prepared {
    let run = dry_run(&extract).unwrap();
    assert!(run.report.gate.ready_for_review, "{:?}", run.report.refused);
    let mut h = HandoffRecord::propose(
        EvaluationDomain::Credential,
        Timestamp::new(T0 + 100).unwrap(),
        &run.report,
        vec![HandoffEntry {
            import_id: run.records[0].import_id.clone(),
            custodian_scope: lc::run_scope(&w.rw.binding),
        }],
    );
    if complete {
        h.checks.inventory_reviewed = evidence(1);
        h.checks.dry_run_zero_unexplained = evidence(2);
        h.checks.envelope_verification_proven = evidence(3);
        h.checks.rollback_rehearsed = evidence(4);
        h.checks.legacy_runner_disabled_same_change = evidence(5);
        h.checks.credential_readiness = evidence(6);
    }
    Prepared {
        handoff: h.canonical_bytes().unwrap(),
        handoff_digest: h.digest().unwrap(),
        report_digest: run.report.digest(),
        extract,
        run,
    }
}

fn apply_cmd(p: &Prepared) -> Command {
    Command::LegacyApply {
        extract: p.extract.clone(),
        handoff: p.handoff.clone(),
        confirm_handoff_digest: p.handoff_digest.clone(),
        confirm_report_digest: p.report_digest.clone(),
    }
}

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

fn consumed(w: &World) -> (u64, u64, u64) {
    let st =
        w.rw.store
            .budget_status(BudgetKind::Run, &lc::run_scope(&w.rw.binding))
            .unwrap()
            .unwrap();
    (st.limit, st.consumed, st.held)
}

#[test]
fn only_a_human_operator_may_apply() {
    let w = World::new(5);
    let p = prepare(&w, extract_bytes(spent_once()), true);
    let cmd = apply_cmd(&p);
    for (who, want) in [
        (Who::Requester, CliReason::Forbidden),
        (Who::Approver, CliReason::Forbidden),
        (Who::Auditor, CliReason::Forbidden),
        (Who::Agent, CliReason::AgentNotPermitted),
        (Who::Service, CliReason::AutomationNotPermitted),
    ] {
        let o = w.run(who, &cmd);
        assert_eq!(code(&o), want.code(), "{who:?}");
    }
    assert_eq!(consumed(&w), (5, 0, 0));
    let o = w.run(Who::Operator, &cmd);
    assert!(o.is_ok(), "{}", o.code());
}

#[test]
fn the_exact_digests_and_every_gate_are_required_and_a_dry_run_writes_nothing() {
    let w = World::new(5);
    let p = prepare(&w, extract_bytes(spent_once()), true);

    // A different digest for either confirmation is a mismatch.
    let mut wrong = apply_cmd(&p);
    if let Command::LegacyApply {
        confirm_handoff_digest,
        ..
    } = &mut wrong
    {
        *confirm_handoff_digest = DocumentDigest::from_raw([9u8; 32]);
    }
    assert_eq!(
        code(&w.run(Who::Operator, &wrong)),
        CliReason::ConfirmationMismatch.code()
    );
    let mut wrong = apply_cmd(&p);
    if let Command::LegacyApply {
        confirm_report_digest,
        ..
    } = &mut wrong
    {
        *confirm_report_digest = DocumentDigest::from_raw([9u8; 32]);
    }
    assert_eq!(
        code(&w.run(Who::Operator, &wrong)),
        CliReason::ConfirmationMismatch.code()
    );

    // A handoff with a missing gate is not applied, whatever is confirmed.
    let open = prepare(&w, extract_bytes(spent_once()), false);
    assert_eq!(
        code(&w.run(Who::Operator, &apply_cmd(&open))),
        CliReason::HandoffNotReady.code()
    );

    // A malformed extract or handoff is an invalid document.
    let mut junk = apply_cmd(&p);
    if let Command::LegacyApply { extract, .. } = &mut junk {
        *extract = b"{}".to_vec();
    }
    assert_eq!(
        code(&w.run(Who::Operator, &junk)),
        CliReason::InvalidDocument.code()
    );

    // Dry run: reports, writes nothing, and the outbox is unchanged.
    let before = w.rw.store.latest_checkpoint().unwrap();
    let d = w.dry(Who::Operator, &apply_cmd(&p));
    assert_eq!(code(&d), "would_apply");
    assert!(d.is_ok());
    assert_eq!(consumed(&w), (5, 0, 0));
    assert_eq!(w.rw.store.latest_checkpoint().unwrap(), before);
}

#[test]
fn apply_writes_the_consumed_units_once_audits_them_and_replays_idempotently() {
    let w = World::new(5);
    let p = prepare(&w, extract_bytes(spent_once()), true);
    assert_eq!(p.run.records[0].body.budget.consumed, 1);

    let o = w.run(Who::Operator, &apply_cmd(&p));
    assert!(o.is_ok(), "{}", o.code());
    assert_eq!(o.field("applied_units").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(o.field("created").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(consumed(&w), (5, 1, 0), "limit untouched, one unit spent");

    // Audited under the operator's identity, with the digests that were
    // confirmed, and pending export like any state change.
    let ev =
        w.rw.store
            .outbox_pending(1000)
            .unwrap()
            .into_iter()
            .find(|e| e.kind == "budget.imported")
            .expect("audited");
    assert!(ev.payload.contains(&Who::Operator.actor()));
    assert!(ev.payload.contains(p.handoff_digest.as_str()));
    assert!(ev.payload.contains(p.report_digest.as_str()));
    // The dispatch gate counts the import as unexported spend.
    assert!(w.rw.store.unexported_budget_events().unwrap() >= 1);

    // Replaying changes nothing and says so.
    let again = w.run(Who::Operator, &apply_cmd(&p));
    assert!(again.is_ok());
    assert_eq!(
        again.field("applied_units").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        again.field("already_applied").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(consumed(&w), (5, 1, 0));
    w.rw.store.verify_invariants().unwrap();
}

#[test]
fn a_later_record_that_lowers_consumption_is_refused_and_recorded() {
    let w = World::new(5);
    let first = prepare(&w, extract_bytes(spent_once()), true);
    assert!(w.run(Who::Operator, &apply_cmd(&first)).is_ok());

    // The same legacy scope, now with fewer consumed units, fully reviewed.
    let lower = prepare(&w, extract_bytes(attested_unspent()), true);
    assert_eq!(lower.run.records[0].body.budget.consumed, 0);
    assert_ne!(
        lower.run.records[0].import_id,
        first.run.records[0].import_id
    );
    let o = w.run(Who::Operator, &apply_cmd(&lower));
    assert_eq!(code(&o), CliReason::ImportRefused.code());
    assert_eq!(CliReason::ImportRefused.exit_code(), 5);
    assert_eq!(
        o.field("refusal").and_then(|v| v.as_str()),
        Some("would_reduce_consumption")
    );
    assert_eq!(consumed(&w), (5, 1, 0), "spent stays spent");
    assert!(w
        .rw
        .store
        .outbox_pending(1000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "budget.import_refused"));
    w.rw.store.verify_invariants().unwrap();
}

#[test]
fn the_grammar_needs_every_confirmation_and_rejects_unknown_flags() {
    let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
    let read = |_: &str| Ok(b"{}".to_vec());
    let d = sha(7);
    for (line, want) in [
        (
            "legacy apply --extract e --handoff h".to_owned(),
            CliReason::ConfirmationMissing,
        ),
        (
            format!("legacy apply --extract e --handoff h --confirm-handoff-digest {d}"),
            CliReason::ConfirmationMissing,
        ),
        (
            format!(
                "legacy apply --extract e --handoff h --confirm-handoff-digest {d} \
                 --confirm-report-digest nonsense"
            ),
            CliReason::UsageError,
        ),
        (
            format!(
                "legacy apply --extract e --handoff h --confirm-handoff-digest {d} \
                 --confirm-report-digest {d} --surprise 1"
            ),
            CliReason::UsageError,
        ),
        ("legacy apply --handoff h".to_owned(), CliReason::UsageError),
    ] {
        let p = parse_args(&args(&line)).unwrap();
        assert_eq!(build_command(&p, &read).err(), Some(want), "{line}");
    }
    let ok = parse_args(&args(&format!(
        "legacy apply --extract e --handoff h --confirm-handoff-digest {d} \
         --confirm-report-digest {d}"
    )))
    .unwrap();
    assert_eq!(build_command(&ok, &read).unwrap().name(), "legacy.apply");
}
