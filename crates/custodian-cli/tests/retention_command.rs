//! HG-4 through the operator CLI: `repair retention` (ADR 0117).
//!
//! Every age is an explicit operator decision; the store refuses ages below
//! its hard floors; only a human operator may run it, with the exact store
//! identity confirmed. Synthetic data only.

mod common;

use common::*;
use custodian_cli::command::{build_command, parse_args, RepairCommand};
use custodian_cli::{CliReason, Command};
use custodian_contracts::types::{ActorRef, Timestamp};
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{DeliveryStore, IntakeQueue, QueuedRequest};

const DAY: u64 = 86_400;

fn queued(n: u64) -> QueuedRequest {
    QueuedRequest {
        delivery: DeliveryId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap(),
        installation: InstallationId::new(900_001).unwrap(),
        repository: RepositoryId::new(800_001).unwrap(),
        pull_request: PullRequestNumber::new(7).unwrap(),
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        actor: ActorRef::parse(&cc::id("act_", 1)).unwrap(),
        github_user: GithubUserId::new(700_001).unwrap(),
        received_at: Timestamp::new(NOW).unwrap(),
    }
}

fn cmd(w: &World, queue: u64, claim: u64) -> Command {
    Command::Repair(RepairCommand::Retention {
        confirm_store_id: w.rw.store.store_id().unwrap(),
        queue_done_min_age_secs: queue,
        claim_min_age_secs: claim,
        decided_submission_min_age_secs: 20 * DAY,
        pending_submission_max_age_secs: 5 * DAY,
        batch_limit: 100,
    })
}

#[test]
fn retention_is_a_human_operator_decision_with_hard_floors_and_exact_confirmation() {
    let w = World::new(5);
    let store = &w.rw.store;
    for n in 1..=2 {
        let d = queued(n).delivery.clone();
        store.claim(&d).unwrap();
        store.enqueue(queued(n)).unwrap();
        let l = store.queue_lease("worker", NOW, 60).unwrap().unwrap();
        store.queue_complete(l.seq, l.lease_token, NOW).unwrap();
    }
    let good = cmd(&w, 2 * DAY, 10 * DAY);

    for (who, want) in [
        (Who::Requester, CliReason::Forbidden),
        (Who::Auditor, CliReason::Forbidden),
        (Who::Agent, CliReason::AgentNotPermitted),
        (Who::Service, CliReason::AutomationNotPermitted),
    ] {
        assert_eq!(w.run(who, &good).code(), want.code(), "{who:?}");
    }
    // The wrong store identity names a different store.
    let wrong = Command::Repair(RepairCommand::Retention {
        confirm_store_id: "0".repeat(32),
        queue_done_min_age_secs: 2 * DAY,
        claim_min_age_secs: 10 * DAY,
        decided_submission_min_age_secs: 20 * DAY,
        pending_submission_max_age_secs: 5 * DAY,
        batch_limit: 100,
    });
    assert_eq!(
        w.run(Who::Operator, &wrong).code(),
        CliReason::ConfirmationMismatch.code()
    );
    // An age below the floor is refused whatever the operator typed.
    assert_eq!(
        w.run(Who::Operator, &cmd(&w, 60, 10 * DAY)).code(),
        CliReason::InvalidDocument.code()
    );
    assert_eq!(
        w.run(Who::Operator, &cmd(&w, 2 * DAY, 3600)).code(),
        CliReason::InvalidDocument.code()
    );

    // Nothing is old enough yet (the clock is at NOW): a pass removes nothing.
    let o = w.run(Who::Operator, &good);
    assert!(o.is_ok(), "{}", o.code());
    assert_eq!(o.field("purged_queue").and_then(|v| v.as_u64()), Some(0));

    // A dry run reports and removes nothing even when everything is old.
    w.clock.set(NOW + 11 * DAY);
    assert_eq!(w.dry(Who::Operator, &good).code(), "would_purge");

    let o = w.run(Who::Operator, &good);
    assert_eq!(o.code(), "purged");
    assert_eq!(o.field("purged_queue").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(o.field("purged_claims").and_then(|v| v.as_u64()), Some(2));
    // Nothing is left to remove: the dry run really removed nothing before.
    assert_eq!(
        w.run(Who::Operator, &good)
            .field("purged_queue")
            .and_then(|v| v.as_u64()),
        Some(0)
    );
    // The purge is audited and pending export; budgets are untouched.
    assert!(store
        .outbox_pending(1000)
        .unwrap()
        .iter()
        .any(|e| e.kind == "retention.purged"));
    store.verify_invariants().unwrap();
}

#[test]
fn the_grammar_has_no_default_ages() {
    let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
    let read = |_: &str| Ok(b"{}".to_vec());
    let id = "0".repeat(32);
    // The store identity is a confirmation; every age is a required number.
    let p = parse_args(&args("repair retention")).unwrap();
    assert_eq!(
        build_command(&p, &read).err(),
        Some(CliReason::ConfirmationMissing)
    );
    let p = parse_args(&args(&format!(
        "repair retention --confirm-store-id {id} --queue-done-min-age-secs 1"
    )))
    .unwrap();
    assert_eq!(build_command(&p, &read).err(), Some(CliReason::UsageError));
    let full = format!(
        "repair retention --confirm-store-id {id} --queue-done-min-age-secs 172800 \
         --claim-min-age-secs 864000 --decided-submission-min-age-secs 1728000 \
         --pending-submission-max-age-secs 432000"
    );
    let p = parse_args(&args(&full)).unwrap();
    assert_eq!(build_command(&p, &read).unwrap().name(), "repair.retention");
}
