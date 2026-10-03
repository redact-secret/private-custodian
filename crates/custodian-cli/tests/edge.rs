//! The GitHub request edge and the operator CLI share one idempotency and
//! budget control plane (C10). The edge here is the real `Intake` and
//! `ExecutionGate` over the durable store ports, in a second connection to the
//! same database file (as a separate process would be). Synthetic only.

mod common;
#[path = "../../custodian-intake/tests/common/mod.rs"]
mod ic;

use std::sync::Arc;

use common::*;
use custodian_cli::Command;
use custodian_contracts::approval::Approval;
use custodian_contracts::request::EvaluationRequest;
use custodian_intake::config::WebhookSecret;
use custodian_intake::gate::{ExecutionGate, StagedCandidate};
use custodian_intake::ids::HeadSha;
use custodian_intake::memory::FixedPullRequestSource;
use custodian_intake::signature::sign_body;
use custodian_intake::testing::random_bytes;
use custodian_intake::webhook::{Delivery, Intake, Outcome};
use custodian_intake::IntakeReason;
use custodian_store::{ReserveCommand, SqliteStore};

fn code(o: &custodian_cli::Output) -> &'static str {
    o.code()
}

struct Edge {
    store: Arc<SqliteStore>,
    secret: Vec<u8>,
}

impl Edge {
    fn open(w: &World, secret: Option<Vec<u8>>) -> Self {
        Self {
            store: Arc::new(SqliteStore::open(w.rw.db.path()).unwrap()),
            secret: secret.unwrap_or_else(|| random_bytes(32)),
        }
    }

    fn intake(&self) -> Intake {
        Intake::new(
            ic::config(),
            WebhookSecret::new(self.secret.clone()).unwrap(),
            self.store.clone(),
            self.store.clone(),
            self.store.clone(),
        )
    }

    fn deliver(&self, n: u64, sender: u64) -> Result<Outcome, IntakeReason> {
        let body = serde_json::to_vec(&ic::pr_payload("opened", sender, "User")).unwrap();
        let sig = sign_body(&WebhookSecret::new(self.secret.clone()).unwrap(), &body);
        let delivery_id = ic::uuid(n);
        self.intake().handle(
            &Delivery {
                signature: Some(&sig),
                event: Some("pull_request"),
                delivery_id: Some(&delivery_id),
                content_type: Some("application/json"),
                body: &body,
            },
            ic::ts(NOW),
        )
    }

    fn gate(&self) -> ExecutionGate {
        ExecutionGate::new(
            ic::config(),
            self.store.clone(),
            Arc::new(FixedPullRequestSource::new(ic::head('a'))),
        )
    }
}

/// What the control plane does with a leased queue item: gate it, then reserve
/// through the contract path. The consumer is idempotent because the
/// reservation is keyed by the request's idempotency key.
fn app_reserve(
    edge: &Edge,
    leased: &custodian_store::LeasedRequest,
    req: &EvaluationRequest,
    apr: &Approval,
) -> custodian_store::ReserveOutcome {
    let staged = StagedCandidate {
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        candidate: req.plan.candidate.clone(),
        config_digest: req.plan.config_digest.clone(),
    };
    let observed = cc::observed(cc::activation(), NOW);
    use custodian_contracts::Contract;
    edge.gate()
        .authorize(
            &leased.request,
            &req.canonical_bytes().unwrap(),
            &staged,
            Some(apr),
            &observed,
            ic::ts(NOW),
        )
        .expect("gate");
    edge.store
        .reserve_request(&ReserveCommand {
            request: req,
            approval: apr,
            observed: &observed,
            now: ic::ts(NOW),
            max_state_age_secs: 300,
            reservation_window_secs: 600,
        })
        .unwrap()
}

#[test]
fn the_same_request_charges_once_whether_the_app_or_the_cli_reserves_first() {
    // App first, CLI second.
    let w = World::new(5);
    let edge = Edge::open(&w, None);
    assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
    let (req, apr) = lc::request_for(&w.rw.binding, 1);
    let leased = edge.store.queue_lease("control", NOW, 60).unwrap().unwrap();
    assert_eq!(leased.request.actor, req.asserted_actor);
    let out = app_reserve(&edge, &leased, &req, &apr);
    assert!(!out.replay);
    edge.store
        .queue_complete(leased.seq, leased.lease_token, NOW)
        .unwrap();
    assert_eq!(w.budget().held, 1);

    let s = w.submit(Who::Requester, 1);
    assert_eq!(code(&s), "submitted");
    assert_eq!(s.field("status").unwrap(), "reserved_elsewhere");
    assert_eq!(s.field("replay").unwrap(), true);
    assert_eq!(
        s.field("attempt_id").unwrap(),
        &serde_json::json!(out.attempt.as_str())
    );
    let a = w.approve(Who::Approver, 1);
    assert_eq!(code(&a), "already_decided");
    assert_eq!(w.budget().held, 1, "charged once");
    w.rw.store.integrity_check().unwrap();

    // CLI first, App second.
    let w = World::new(5);
    let edge = Edge::open(&w, None);
    w.submit(Who::Requester, 1);
    let cli = w.approve(Who::Approver, 1);
    assert_eq!(code(&cli), "approved");
    assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
    let (req, apr) = lc::request_for(&w.rw.binding, 1);
    let leased = edge.store.queue_lease("control", NOW, 60).unwrap().unwrap();
    let out = app_reserve(&edge, &leased, &req, &apr);
    assert!(out.replay, "the App path finds the CLI's reservation");
    assert_eq!(
        out.attempt.as_str(),
        cli.field("attempt_id").unwrap().as_str().unwrap()
    );
    assert_eq!(w.budget().held, 1, "charged once");
}

#[test]
fn both_paths_draw_on_the_same_budget() {
    let w = World::new(1);
    let edge = Edge::open(&w, None);
    assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
    let (req, apr) = lc::request_for(&w.rw.binding, 1);
    let leased = edge.store.queue_lease("control", NOW, 60).unwrap().unwrap();
    app_reserve(&edge, &leased, &req, &apr);
    // The CLI's different request meets the same exhausted budget.
    w.submit(Who::Requester, 2);
    let o = w.approve(Who::Approver, 2);
    assert_eq!(code(&o), "budget_exhausted");
    let b = w.budget();
    assert_eq!((b.limit, b.held), (1, 1));
}

#[test]
fn replay_protection_and_the_queue_survive_a_restart() {
    let w = World::new(3);
    {
        let edge = Edge::open(&w, Some(vec![7u8; 32]));
        assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
        assert_eq!(
            edge.deliver(1, ic::REQUESTER),
            Err(IntakeReason::DeliveryReplay)
        );
        assert_eq!(edge.deliver(2, ic::REQUESTER), Ok(Outcome::Queued));
    }
    // New process, same database.
    let edge = Edge::open(&w, Some(vec![7u8; 32]));
    assert_eq!(
        edge.deliver(1, ic::REQUESTER),
        Err(IntakeReason::DeliveryReplay)
    );
    assert_eq!(edge.store.queue_depth().unwrap(), 2);
    let first = edge.store.queue_lease("control", NOW, 60).unwrap().unwrap();
    assert_eq!(first.request.delivery.as_str(), ic::uuid(1));
    // A hostile sender is refused before the queue.
    assert_eq!(
        edge.deliver(3, ic::STRANGER),
        Err(IntakeReason::ActorNotAuthorized)
    );
    assert_eq!(edge.store.queue_depth().unwrap(), 2);
}

#[test]
fn the_consumer_is_idempotent_across_redelivery_of_a_lapsed_lease() {
    let w = World::new(3);
    let edge = Edge::open(&w, None);
    assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
    let (req, apr) = lc::request_for(&w.rw.binding, 1);
    // First consumer reserves, then crashes before completing the item.
    let first = edge
        .store
        .queue_lease("control-a", NOW, 60)
        .unwrap()
        .unwrap();
    let r1 = app_reserve(&edge, &first, &req, &apr);
    // The lease lapses; a second consumer gets the same item again.
    let second = edge
        .store
        .queue_lease("control-b", NOW + 61, 60)
        .unwrap()
        .unwrap();
    assert_eq!(second.attempts, 2);
    let r2 = app_reserve(&edge, &second, &req, &apr);
    assert!(r2.replay);
    assert_eq!(r1.attempt, r2.attempt);
    edge.store
        .queue_complete(second.seq, second.lease_token, NOW + 62)
        .unwrap();
    assert_eq!(
        w.budget().held,
        1,
        "at-least-once delivery, exactly-once charge"
    );
    assert!(edge
        .store
        .queue_lease("control-c", NOW + 500, 60)
        .unwrap()
        .is_none());
}

#[test]
fn an_installation_removal_is_durable_and_stops_both_intake_and_the_gate() {
    let w = World::new(3);
    let secret = vec![9u8; 32];
    {
        let edge = Edge::open(&w, Some(secret.clone()));
        assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
        // GitHub tells us the installation was removed.
        use custodian_intake::ports::InstallationRegistry;
        edge.store.mark_installation_removed(ic::inst()).unwrap();
    }
    let edge = Edge::open(&w, Some(secret));
    assert_eq!(
        edge.deliver(2, ic::REQUESTER),
        Err(IntakeReason::InstallationRemoved)
    );
    // The request already queued is stopped at the gate, not run.
    let (req, apr) = lc::request_for(&w.rw.binding, 1);
    let leased = edge.store.queue_lease("control", NOW, 60).unwrap().unwrap();
    let staged = StagedCandidate {
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        candidate: req.plan.candidate.clone(),
        config_digest: req.plan.config_digest.clone(),
    };
    use custodian_contracts::Contract;
    let denied = edge.gate().authorize(
        &leased.request,
        &req.canonical_bytes().unwrap(),
        &staged,
        Some(&apr),
        &cc::observed(cc::activation(), NOW),
        ic::ts(NOW),
    );
    assert_eq!(denied.err(), Some(IntakeReason::InstallationRemoved));
    assert_eq!(w.budget().held, 0);
}

#[test]
fn queueing_and_requesting_are_not_approving() {
    // An allowlisted requester's webhook gets a request queued; nothing the
    // webhook carries (title, body, labels, comments) approves it. Only a
    // separate approval, here through the CLI, turns it into a reservation.
    let w = World::new(3);
    let edge = Edge::open(&w, None);
    assert_eq!(edge.deliver(1, ic::REQUESTER), Ok(Outcome::Queued));
    assert_eq!(w.budget().held, 0);
    let (req, _) = lc::request_for(&w.rw.binding, 1);
    let leased = edge.store.queue_lease("control", NOW, 60).unwrap().unwrap();
    let staged = StagedCandidate {
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        candidate: req.plan.candidate.clone(),
        config_digest: req.plan.config_digest.clone(),
    };
    use custodian_contracts::Contract;
    let no_approval = edge.gate().authorize(
        &leased.request,
        &req.canonical_bytes().unwrap(),
        &staged,
        None,
        &cc::observed(cc::activation(), NOW),
        ic::ts(NOW),
    );
    assert_eq!(no_approval.err(), Some(IntakeReason::ApprovalRequired));
    assert_eq!(w.budget().held, 0);
    // The CLI path needs the explicit approval step too.
    assert_eq!(code(&w.submit(Who::Requester, 1)), "submitted");
    assert_eq!(w.budget().held, 0);
    assert_eq!(code(&w.approve(Who::Approver, 1)), "approved");
    assert_eq!(w.budget().held, 1);
    let _ = Command::FeedPublish;
}
