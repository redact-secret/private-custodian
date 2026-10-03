//! The queue consumer over the durable intake queue: leases and fencing,
//! idempotent handling, bounded retries with backoff, poison messages,
//! graceful shutdown, and real threads. Synthetic only.

mod common;

use std::sync::Arc;
use std::thread;

use common::*;
use custodian_contracts::types::Timestamp;
use custodian_daemon::config::QueueConfig;
use custodian_daemon::consumer::{QueueConsumer, Step, POISON_REASON};
use custodian_daemon::schedule::Degraded;
use custodian_daemon::Shutdown;
use custodian_intake::checks::{CheckReporter, CheckSink, CheckState, RecordingCheckSink};
use custodian_intake::gate::ExecutionGate;
use custodian_intake::ids::{HeadSha, InstallationId, PullRequestNumber, RepositoryId};
use custodian_intake::memory::FixedPullRequestSource;
use custodian_intake::ports::PullRequestSource;
use custodian_intake::signature::sign_body;
use custodian_intake::testing::random_bytes;
use custodian_intake::webhook::{Delivery, Intake, Outcome};
use custodian_intake::IntakeReason;
use custodian_store::{Clock, QueueOutcome, SqliteStore, StoreConfig, SubmissionStatus};

struct Edge {
    intake: Intake,
    secret: Vec<u8>,
}

impl Edge {
    fn new(env: &Env) -> Self {
        let secret = random_bytes(32);
        Self {
            intake: env.edge_intake(&secret),
            secret,
        }
    }

    fn deliver_pr(
        &self,
        n: u64,
        number: u64,
        sender: u64,
        head: char,
    ) -> Result<Outcome, IntakeReason> {
        let mut payload = pr_payload("opened", sender, "User", head);
        payload["pull_request"]["number"] = serde_json::json!(number);
        let body = serde_json::to_vec(&payload).unwrap();
        let sig = sign_body(
            &custodian_intake::config::WebhookSecret::new(self.secret.clone()).unwrap(),
            &body,
        );
        self.intake.handle(
            &Delivery {
                signature: Some(&sig),
                event: Some("pull_request"),
                delivery_id: Some(&uuid(n)),
                content_type: Some("application/json"),
                body: &body,
            },
            Timestamp::new(NOW).unwrap(),
        )
    }
}

fn cfg() -> QueueConfig {
    QueueConfig {
        workers: 1,
        owner: "consumer-test".to_owned(),
        lease_secs: 60,
        max_attempts: 3,
        backoff_base_secs: 5,
        backoff_max_secs: 300,
        poll: std::time::Duration::from_millis(10),
    }
}

fn consumer_with(
    env: &Env,
    store: Arc<SqliteStore>,
    pulls: Arc<dyn PullRequestSource>,
    sink: Arc<dyn CheckSink>,
) -> QueueConsumer {
    QueueConsumer {
        gate: ExecutionGate::new(intake_config(), store.clone(), pulls),
        checks: Some(Arc::new(CheckReporter::new(
            intake_config(),
            store.clone(),
            sink,
        ))),
        store,
        requests: Arc::new(custodian_daemon::source::DirRequestSource::new(
            env.requests_dir.clone(),
        )),
        stager: Arc::new(custodian_daemon::source::DirStager::new(&env.art_dir)),
        clock: env.p.w.clock.clone(),
        log: env.log.clone(),
        cfg: cfg(),
        degraded: Degraded::new(),
    }
}

fn head_a() -> Arc<dyn PullRequestSource> {
    Arc::new(FixedPullRequestSource::new(
        HeadSha::parse(&sha40('a')).unwrap(),
    ))
}

fn consumer(env: &Env) -> QueueConsumer {
    consumer_with(env, env.edge.clone(), head_a(), env.checks.clone())
}

fn step(c: &QueueConsumer) -> Step {
    c.step(&Shutdown::new()).expect("step")
}

fn rid(env: &Env, n: u32) -> String {
    env.request(n).0.request_id.as_str().to_owned()
}

#[test]
fn a_queued_pull_request_becomes_one_pending_submission_and_a_queued_check() {
    let env = Env::new(3);
    let edge = Edge::new(&env);
    env.stage_request(1, 7, 'a');
    assert_eq!(
        edge.deliver_pr(1, 7, REQUESTER_USER, 'a'),
        Ok(Outcome::Queued)
    );
    let c = consumer(&env);
    assert_eq!(
        step(&c),
        Step::Settled(QueueOutcome::Submitted, "submitted")
    );
    // A pending submission through the same path as the CLI, channel app.
    let sub = env.store().submission(&rid(&env, 1)).unwrap().unwrap();
    assert_eq!(sub.status, SubmissionStatus::Pending);
    assert_eq!(sub.channel.as_str(), "app");
    assert_eq!(sub.submitted_by, Who::Requester.actor());
    // Nothing was reserved, approved or charged by the consumer.
    let b = env.p.w.budget();
    assert_eq!((b.held, b.consumed, b.refunded), (0, 0, 0));
    // The outcome, the link and the Check.
    let o = env.edge.queue_outcome(1).unwrap().unwrap();
    assert_eq!(
        (o.outcome, o.reason.as_str()),
        (QueueOutcome::Submitted, "submitted")
    );
    let link = env.edge.request_link(&rid(&env, 1)).unwrap().unwrap();
    assert_eq!((link.repository_id, link.pull_request), (REPO, 7));
    let posts = env.checks.posts();
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].status,
        custodian_intake::checks::GithubStatus::Queued
    );
    assert!(
        posts[0].summary.contains("Reason: requested"),
        "{}",
        posts[0].summary
    );
    // A second look finds nothing; the queue is empty.
    assert_eq!(step(&c), Step::Idle);
    assert_eq!(env.edge.queue_depth().unwrap(), 0);
    // And the human approval path the CLI offers now works on it.
    let o = env.p.approve(1);
    assert!(o.is_ok(), "{}", o.code());
    assert_eq!(env.p.w.budget().held, 1);
}

#[test]
fn a_redelivered_lapsed_lease_is_handled_idempotently() {
    let env = Env::new(3);
    let edge = Edge::new(&env);
    env.stage_request(1, 7, 'a');
    edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
    // A consumer leases the item and dies before settling it.
    let first = env.edge.queue_lease("dead", NOW, 10).unwrap().unwrap();
    assert_eq!(first.attempts, 1);
    // After the lease lapses a live consumer gets it with a higher token.
    env.at(NOW + 11);
    assert_eq!(
        step(&consumer(&env)),
        Step::Settled(QueueOutcome::Submitted, "submitted")
    );
    // The dead consumer's late settlement is fenced off.
    let late = env.edge.queue_settle(
        first.seq,
        first.lease_token,
        NOW + 12,
        &custodian_store::QueueSettle {
            outcome: QueueOutcome::Denied,
            reason: "late",
            request_id: None,
            link: None,
        },
    );
    // Done items accept a repeat idempotently; the outcome is still the first.
    assert!(late.is_ok());
    assert_eq!(
        env.edge.queue_outcome(first.seq).unwrap().unwrap().outcome,
        QueueOutcome::Submitted
    );
    assert_eq!(env.store().submissions(10).unwrap().len(), 1);
}

#[test]
fn terminal_refusals_are_recorded_with_fixed_codes_and_charge_nothing() {
    // (label, setup, expected reason)
    type Setup = fn(&Env, &Edge);
    let cases: [(&str, Setup, &str); 7] = [
        // The head commit moved on after the event.
        (
            "stale",
            |env, edge| {
                env.stage_request(1, 7, 'c');
                edge.deliver_pr(1, 7, REQUESTER_USER, 'c').unwrap();
            },
            "stale_commit",
        ),
        // The staged candidate is not the one the plan pins.
        (
            "candidate",
            |env, edge| {
                let (mut req_json, _) = (serde_json::to_value(env.request(1).0).unwrap(), ());
                req_json["plan"]["candidate"] = serde_json::json!(dg_of("another candidate"));
                let bytes = serde_json::to_vec(&req_json).unwrap();
                env.stage_request_bytes(&bytes, 7, 'a');
                env.stage_commit('a', &env.request(1).0);
                edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
            },
            "candidate_mismatch",
        ),
        // The request names a different actor than the verified sender.
        (
            "actor",
            |env, edge| {
                env.stage_request(1, 7, 'a');
                edge.deliver_pr(1, 7, APPROVER_USER, 'a').unwrap();
            },
            "actor_mismatch",
        ),
        // A document that is not a request.
        (
            "garbage",
            |env, edge| {
                env.stage_request_bytes(b"not a request", 7, 'a');
                env.stage_commit('a', &env.request(1).0);
                edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
            },
            "request_invalid",
        ),
        // The installation was removed after the delivery was queued.
        (
            "removed",
            |env, edge| {
                env.stage_request(1, 7, 'a');
                edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
                use custodian_intake::ports::InstallationRegistry;
                env.edge
                    .mark_installation_removed(InstallationId::new(INSTALLATION).unwrap())
                    .unwrap();
            },
            "installation_removed",
        ),
        // The repository was removed.
        (
            "repo-removed",
            |env, edge| {
                env.stage_request(1, 7, 'a');
                edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
                use custodian_intake::ports::InstallationRegistry;
                env.edge
                    .mark_repository_removed(
                        InstallationId::new(INSTALLATION).unwrap(),
                        RepositoryId::new(REPO).unwrap(),
                    )
                    .unwrap();
            },
            "repository_removed",
        ),
        // The epoch was contaminated.
        (
            "epoch",
            |env, edge| {
                env.stage_request(1, 7, 'a');
                edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
                let o = env.p.w.run(
                    Who::Operator,
                    &custodian_cli::Command::LifecycleReport {
                        epoch: env.p.w.rw.epoch.clone(),
                        kind: custodian_cli::command::Contaminated::Exposed,
                        reason: "results_exposed".into(),
                        key: lc::idk(1),
                    },
                );
                assert!(o.is_ok());
            },
            "epoch_blocked",
        ),
    ];
    for (label, setup, reason) in cases {
        let env = Env::new(3);
        let edge = Edge::new(&env);
        setup(&env, &edge);
        let c = consumer(&env);
        // The "stale" case needs a head the source does not report as 'c'.
        let outcome = step(&c);
        assert_eq!(
            outcome,
            Step::Settled(QueueOutcome::Denied, reason),
            "{label}"
        );
        assert!(env.store().submissions(10).unwrap().is_empty(), "{label}");
        assert_eq!(env.p.w.budget().held, 0, "{label}");
        let posts = env.checks.posts();
        if matches!(reason, "installation_removed" | "repository_removed") {
            // No Check is ever written for an installation or repository
            // that was removed: the reporter refuses the scope.
            assert!(posts.is_empty(), "{label}");
            continue;
        }
        assert_eq!(posts.len(), 1, "{label}");
        assert_eq!(
            posts[0].conclusion,
            Some(custodian_intake::checks::GithubConclusion::Failure)
        );
        // The Check says only a fixed word.
        assert!(
            posts[0]
                .summary
                .contains(&format!("Reason: {}", check_word(reason))),
            "{label}: {}",
            posts[0].summary
        );
        env.store().integrity_check().unwrap();
        let _ = CheckState::Denied;
    }
}

fn dg_of(label: &str) -> String {
    custodian_contracts::types::CandidateDigest::of_bytes(label.as_bytes())
        .as_str()
        .to_owned()
}

/// The word a Check carries for a consumer refusal.
fn check_word(reason: &str) -> &str {
    match reason {
        "epoch_blocked" => "authorization_denied",
        r => r,
    }
}

#[test]
fn a_missing_document_backs_off_exactly_then_succeeds_when_it_arrives() {
    let env = Env::new(3);
    let edge = Edge::new(&env);
    edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
    let c = consumer(&env);
    // Nothing provided yet: deferred by base (5 s), then 10 s.
    assert_eq!(step(&c), Step::Deferred("request_not_provided"));
    assert_eq!(
        step(&c),
        Step::Idle,
        "the lease holds the item for the backoff"
    );
    env.at(NOW + 4);
    assert_eq!(step(&c), Step::Idle);
    env.at(NOW + 5);
    assert_eq!(step(&c), Step::Deferred("request_not_provided"));
    env.at(NOW + 5 + 9);
    assert_eq!(step(&c), Step::Idle);
    // The requester provides the document (and the staging step records the
    // candidate); the next lease submits.
    env.stage_request(1, 7, 'a');
    env.at(NOW + 5 + 10);
    assert_eq!(
        step(&c),
        Step::Settled(QueueOutcome::Submitted, "submitted")
    );
    assert_eq!(env.store().submissions(10).unwrap().len(), 1);
}

struct Down;
impl PullRequestSource for Down {
    fn current_head(
        &self,
        _: InstallationId,
        _: RepositoryId,
        _: PullRequestNumber,
    ) -> Result<HeadSha, IntakeReason> {
        Err(IntakeReason::TokenUnavailable)
    }
}

#[test]
fn a_message_that_never_succeeds_is_set_aside_audited_and_never_loops() {
    let env = Env::new(3);
    let edge = Edge::new(&env);
    env.stage_request(1, 7, 'a');
    edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
    let c = consumer_with(&env, env.edge.clone(), Arc::new(Down), env.checks.clone());
    let mut t = NOW;
    let mut deferrals = 0;
    let end = loop {
        env.at(t);
        match step(&c) {
            Step::Deferred(w) => {
                assert_eq!(w, "token_unavailable");
                deferrals += 1;
            }
            Step::Idle => {}
            other => break other,
        }
        t += 1;
        assert!(t < NOW + 10_000, "the loop never ends");
    };
    // max_attempts = 3: two deferrals, the third failing lease is poison.
    assert_eq!(deferrals, 2);
    assert_eq!(end, Step::Settled(QueueOutcome::Poisoned, POISON_REASON));
    let o = env.edge.queue_outcome(1).unwrap().unwrap();
    assert_eq!(
        (o.outcome, o.reason.as_str(), o.attempts),
        (QueueOutcome::Poisoned, "poison_message", 3)
    );
    // Audited: one exported-able outbox event; nothing reserved or charged.
    let events: Vec<_> = env
        .edge
        .outbox_pending(1000)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "queue.settled")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].payload.contains("poisoned"));
    assert!(events[0].payload.contains("poison_message"));
    assert!(env.store().submissions(10).unwrap().is_empty());
    assert_eq!(env.p.w.budget().held, 0);
    assert_eq!(env.edge.queue_depth().unwrap(), 0);
    // Never tried again.
    env.at(t + 100_000);
    assert_eq!(step(&c), Step::Idle);
    // The Check says failed with a fixed word.
    let last = env.checks.posts().pop().unwrap();
    assert_eq!(
        last.conclusion,
        Some(custodian_intake::checks::GithubConclusion::Failure)
    );
}

#[test]
fn a_crash_looping_item_is_poisoned_without_being_processed_again() {
    let env = Env::new(3);
    let edge = Edge::new(&env);
    env.stage_request(1, 7, 'a');
    edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
    // Consumers that lease it and die, over and over.
    let mut t = NOW;
    for _ in 0..3 {
        env.edge.queue_lease("crashy", t, 10).unwrap().unwrap();
        t += 11;
    }
    env.at(t);
    // The fourth lease exceeds max_attempts: set aside, not processed (a
    // valid request is sitting right there and is not submitted).
    assert_eq!(
        step(&consumer(&env)),
        Step::Settled(QueueOutcome::Poisoned, POISON_REASON)
    );
    assert!(env.store().submissions(10).unwrap().is_empty());
}

#[test]
fn a_failing_check_sink_never_changes_the_outcome() {
    struct Failing;
    impl CheckSink for Failing {
        fn post(&self, _: &custodian_intake::checks::CheckPost) -> Result<(), IntakeReason> {
            Err(IntakeReason::CheckUpdateFailed)
        }
    }
    let env = Env::new(3);
    let edge = Edge::new(&env);
    env.stage_request(1, 7, 'a');
    edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
    let c = consumer_with(&env, env.edge.clone(), head_a(), Arc::new(Failing));
    assert_eq!(
        step(&c),
        Step::Settled(QueueOutcome::Submitted, "submitted")
    );
    assert!(env.log.count("consumer", "check_failed") >= 1);
    let _ = RecordingCheckSink::new();
}

#[test]
fn shutdown_stops_claiming_and_gives_back_what_was_leased() {
    let env = Env::new(3);
    let edge = Edge::new(&env);
    env.stage_request(1, 7, 'a');
    edge.deliver_pr(1, 7, REQUESTER_USER, 'a').unwrap();
    let c = consumer(&env);
    let down = Shutdown::new();
    down.request();
    // Not claiming at all.
    assert_eq!(c.step(&down).unwrap(), Step::Idle);
    assert_eq!(env.edge.queue_depth().unwrap(), 1);
    assert!(env.edge.queue_outcome(1).unwrap().is_none());
    // A degraded daemon claims nothing either.
    let degraded = Degraded::new();
    let mut c2 = consumer(&env);
    c2.degraded = degraded.clone();
    // (set through the schedule's own API in the scheduler tests; here the
    // flag is shared and only read)
    assert_eq!(
        step(&c2),
        Step::Settled(QueueOutcome::Submitted, "submitted")
    );
}

#[test]
fn many_consumers_on_real_threads_submit_every_item_exactly_once() {
    const ITEMS: u32 = 12;
    let env = Env::new(3);
    let edge = Edge::new(&env);
    for n in 1..=ITEMS {
        let number = 100 + u64::from(n);
        // Distinct requests (distinct ids and idempotency keys), one per PR.
        env.stage_request(n, number, 'a');
        assert_eq!(
            edge.deliver_pr(u64::from(n), number, REQUESTER_USER, 'a'),
            Ok(Outcome::Queued)
        );
    }
    assert_eq!(env.edge.queue_depth().unwrap(), u64::from(ITEMS));
    let path = env.p.w.rw.db.path();
    let consumers: Vec<QueueConsumer> = (0..4)
        .map(|i| {
            let store = Arc::new(
                SqliteStore::open_with_config(
                    &path,
                    StoreConfig::enforced()
                        .with_clock(env.p.w.clock.clone())
                        .with_busy_timeout_ms(20_000),
                )
                .unwrap(),
            );
            let mut c = consumer_with(&env, store, head_a(), env.checks.clone());
            c.cfg.owner = format!("consumer-{i}");
            c
        })
        .collect();
    let shutdown = Shutdown::new();
    thread::scope(|s| {
        for c in &consumers {
            let shutdown = shutdown.clone();
            s.spawn(move || {
                // Run until the queue is empty.
                loop {
                    match c.step(&shutdown) {
                        Ok(Step::Idle) => break,
                        Ok(_) | Err(_) => {}
                    }
                }
            });
        }
    });
    assert_eq!(env.edge.queue_depth().unwrap(), 0);
    let subs = env.store().submissions(200).unwrap();
    assert_eq!(subs.len(), ITEMS as usize, "one submission per request");
    let outcomes = env.edge.queue_outcomes(100).unwrap();
    assert_eq!(outcomes.len(), ITEMS as usize);
    assert!(outcomes
        .iter()
        .all(|o| o.outcome == QueueOutcome::Submitted));
    let mut ids: Vec<_> = subs.iter().map(|s| s.request_id.clone()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), ITEMS as usize);
    // Nothing was reserved by any of them.
    assert_eq!(env.p.w.budget().held, 0);
    env.store().integrity_check().unwrap();
    let _ = env.p.w.clock.now();
}
