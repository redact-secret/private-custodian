//! Synthetic, offline crash-matrix tests for issue #44 (PoC P4): attempt
//! fencing, uncertain outcomes, and MicroVM cleanup accounting. No AWS
//! client, no network, no protected corpus or real operational identifier;
//! every id and digest below is an obviously synthetic placeholder.
//!
//! `custodian-worker-microvm::decode_result` is a pure, stateless envelope
//! parser (see `src/lib.rs`): it holds no run state across calls and cannot
//! by itself remember a prior delivery. The fencing, idempotent settlement
//! and conservative-refund behavior ADR 0133 (steps 2, 4, 6, 8) designs for
//! the remote worker actually live in `custodian-store`, which this crate
//! depends on transitively through `custodian-worker`. These tests drive
//! the real `custodian_store::SqliteStore` side by side with this crate's
//! envelope types, so each scenario shows, honestly, which half is real
//! enforced behavior and which half is a caller obligation or still just
//! ADR prose.
//!
//! One finding is negative and is called out instead of hidden: ADR 0133
//! step 4 asks for "durably bind[ing] exactly one VM to the live fence" so
//! an unknown/duplicate VM gets no inputs. No VM identity type exists
//! anywhere in this codebase today -- `AttemptBinding` has no such field,
//! and nothing in `custodian-worker-microvm` or `custodian-store` tracks a
//! provider VM id. `envelope_wire_contract_has_no_vm_identity_field` below
//! proves the wire contract actively refuses one if a caller tried to add
//! it. The duplicate-delivery protection that does exist is attempt/lease
//! identity at the store layer (attempt id + lease token + owner), not any
//! VM correlation. Do not read these tests as evidence that VM-ID fencing
//! is implemented; it is not.

mod fixture;

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::ExecutionOutcome as Outcome;
use custodian_contracts::reservation::ReservationState;
use custodian_contracts::types::{ProtocolName, VersionLabel};
use custodian_core::{ActorId, Exposure, ReasonCode, RunState};
use custodian_store::{StartCommand, StoreError};
use custodian_worker::result::job_document;
use custodian_worker_microvm::{decode_result, sha256, AttemptBinding, Refusal, ResultEnvelope};
use fixture::*;
use serde_json::{json, Value};

fn actor() -> ActorId {
    ActorId::new("act_synthetic_operator")
}

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

fn result_bytes() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "private-custodian.worker-result/1", "domain": "credential",
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "status": "complete", "roster": {"expected": 1, "observed": 1, "failed": 0},
        "aggregates": {"schema": "private-custodian.aggregates/1", "public_synthetic": true}
    }))
    .unwrap()
}

/// Build the binding the remote worker would echo back, for one attempt at
/// one fence. `fence` stands in for the store's lease token: the only
/// authoritative "is this still the live attempt" signal the envelope has.
fn binding_for(
    request: &str,
    approval: &str,
    reservation: &str,
    execution: &str,
    fence: u64,
) -> AttemptBinding {
    let digest = sha256(b"public-synthetic-artifact");
    serde_json::from_value(json!({
        "request": request, "approval": approval,
        "reservation": reservation, "execution": execution,
        "attempt": 1, "fence": fence, "plan_digest": digest,
        "candidate_digest": digest, "image_digest": digest, "image_version": "1.0",
        "engine_digest": digest, "adapter_digest": digest, "config_digest": digest,
        "scanner_digests": [digest], "job_digest": sha256(&job())
    }))
    .unwrap()
}

fn envelope_json(binding: &AttemptBinding) -> Value {
    serde_json::to_value(ResultEnvelope {
        schema: custodian_worker_microvm::RESULT_ENVELOPE_SCHEMA.into(),
        binding: binding.clone(),
        stdout: result_bytes(),
    })
    .unwrap()
}

fn decode(
    bytes: &[u8],
    expected: &AttemptBinding,
) -> Result<custodian_worker::result::ValidatedResult, Refusal> {
    decode_result(
        bytes,
        expected,
        EvaluationDomain::Credential,
        &protocol(),
        1,
    )
}

// ---------------------------------------------------------------------------
// Scenario 1: orchestrator killed/disconnected after the run was created but
// before the result was retrieved.
// ---------------------------------------------------------------------------

/// After a crash, `SqliteStore::recover` force-terminates a still-`running`
/// attempt it finds past its lease window and -- critically -- fences the
/// lease (bumps the token) when it does. A stale orchestrator that comes
/// back later holding the pre-crash lease is refused with a fixed reason
/// (`LeaseLost`), not silently allowed to settle a result nobody can any
/// longer trust came from the live attempt. The same fence number is also
/// the one piece of the envelope binding a correctly-written caller can use
/// to refuse a replayed delivery before it ever reaches `decode_result`.
#[test]
fn orchestrator_crash_fences_the_lease_so_a_stale_finish_is_refused_not_silently_accepted() {
    let db = TempDb::new("crash-fence");
    let store = open(&db);
    let fx = fixture(1);
    provision(&store, &fx, 3);
    let out = reserve(&store, &fx).unwrap();
    let pre_crash_lease = store
        .start_attempt(&StartCommand {
            attempt: &out.attempt,
            owner: "worker-synthetic-1",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    store
        .record_exposure(&pre_crash_lease, &actor(), NOW + 1)
        .unwrap();

    let stale_binding = binding_for(
        &fx.request_id(),
        fx.apr.approval_id.as_str(),
        out.reservation_id.as_deref().unwrap(),
        out.attempt.as_str(),
        pre_crash_lease.token,
    );
    let stale_envelope = serde_json::to_vec(&envelope_json(&stale_binding)).unwrap();

    // Nothing has lapsed yet: recovery is a no-op, the stale delivery would
    // still be legitimate right now.
    assert_eq!(
        store.recover(&actor(), NOW + 2).unwrap(),
        Default::default()
    );
    assert!(decode(&stale_envelope, &stale_binding).is_ok());

    // The orchestrator vanishes. The lease window lapses and an independent
    // recovery sweep (the "janitor") runs, long after the orchestrator went
    // silent.
    let report = store.recover(&actor(), NOW + 1 + LEASE + 10_000).unwrap();
    assert_eq!(report.failed_consumed, vec![out.attempt.clone()]);
    let rec = store.attempt(&out.attempt).unwrap().unwrap();
    assert_eq!(
        (rec.state, rec.exposure),
        (RunState::Failed, Exposure::Exposed)
    );
    assert_eq!(
        rec.lease_token,
        pre_crash_lease.token + 1,
        "recovery fences the lease"
    );

    // The orchestrator reappears, holding only the pre-crash lease, and
    // tries to deliver the result it has been sitting on. The store refuses
    // with a fixed reason; it never silently re-accepts or re-settles.
    assert_eq!(
        store
            .finish(
                &pre_crash_lease,
                Outcome::Success,
                ReasonCode::Completed,
                &actor(),
                NOW + 1 + LEASE + 10_001
            )
            .unwrap_err(),
        StoreError::LeaseLost
    );
    // Consumed exactly once, by recovery; the late delivery changed nothing.
    assert_eq!(status(&store, &fx), (0, 1, 0));

    // The same staleness is visible at the envelope layer too, *if* the
    // caller re-fetches the live fence before deciding whether to accept:
    // the post-recovery fence no longer equals the one baked into the
    // envelope the (now-dead) orchestrator was carrying.
    let fresh_expected = binding_for(
        &fx.request_id(),
        fx.apr.approval_id.as_str(),
        out.reservation_id.as_deref().unwrap(),
        out.attempt.as_str(),
        rec.lease_token,
    );
    assert_eq!(
        decode(&stale_envelope, &fresh_expected).err(),
        Some(Refusal::BindingMismatch)
    );
    store.verify_invariants().unwrap();
}

/// The converse of the test above, stated explicitly so the gap is not
/// mistaken for coverage: `decode_result` has no memory and performs no
/// autonomous freshness check. If the caller reuses the same (now stale)
/// `expected` binding instead of re-fetching the live fence, decoding the
/// identical stale envelope succeeds again. ADR 0133 says this plainly
/// ("the parser does not establish freshness: callers must check the
/// current authoritative lease before acceptance") -- this test is the
/// proof that nothing in this crate enforces that caller obligation.
#[test]
fn decode_result_alone_enforces_no_freshness_a_misused_stale_expected_still_accepts() {
    let binding = binding_for(
        "req_synthetic000000000001",
        "apr_synthetic000000000001",
        "rsv_synthetic000000000001",
        "exe_synthetic000000000001",
        1,
    );
    let envelope = serde_json::to_vec(&envelope_json(&binding)).unwrap();
    assert!(decode(&envelope, &binding).is_ok());
    // Nothing changed inside `decode_result`; calling it again with the
    // exact same stale `expected` still accepts the exact same bytes.
    assert!(decode(&envelope, &binding).is_ok());
}

// ---------------------------------------------------------------------------
// Scenario 2: a lost run-response followed by retry.
// ---------------------------------------------------------------------------

/// A delivery succeeds in the store, but the acknowledgement is lost before
/// the orchestrator sees it, so it retries. The retry must not double-settle
/// the budget. `custodian-store`'s `finish` is idempotent on the terminal
/// state it already recorded: it returns the existing settlement rather
/// than re-running the transition. A retry that instead disagrees with the
/// already-settled outcome is refused with a fixed reason, never silently
/// overwritten. Both are enforced purely by attempt identity (attempt id +
/// lease token + owner) -- there is no VM identity anywhere in this path.
#[test]
fn lost_response_then_retry_settles_once_by_attempt_identity_not_vm_identity() {
    let db = TempDb::new("lost-response");
    let store = open(&db);
    let fx = fixture(2);
    provision(&store, &fx, 3);
    let out = reserve(&store, &fx).unwrap();
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &out.attempt,
            owner: "worker-synthetic-1",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    store.record_exposure(&lease, &actor(), NOW + 1).unwrap();
    store.begin_validation(&lease, &actor(), NOW + 2).unwrap();

    let first = store
        .finish(
            &lease,
            Outcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 2,
        )
        .unwrap();
    assert_eq!(first.result, ReservationState::Consumed);
    assert_eq!(status(&store, &fx), (0, 1, 0));

    // The orchestrator never saw the ack (network drop) and retries the
    // exact same delivery with the lease it already holds.
    let retried = store
        .finish(
            &lease,
            Outcome::Success,
            ReasonCode::Completed,
            &actor(),
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        retried, first,
        "retry returns the existing settlement, not a new one"
    );
    assert_eq!(
        status(&store, &fx),
        (0, 1, 0),
        "a lost-ack retry must not consume the budget a second time"
    );

    // A confused/conflicting retry -- same lease, different claimed outcome
    // -- is refused outright rather than silently flipping the result.
    assert_eq!(
        store
            .finish(
                &lease,
                Outcome::Cancelled,
                ReasonCode::Cancelled,
                &actor(),
                NOW + 4
            )
            .unwrap_err(),
        StoreError::InvalidTransition
    );
    assert_eq!(status(&store, &fx), (0, 1, 0));
    store.verify_invariants().unwrap();
}

/// The wire contract that would have to carry a VM identity for ADR 0133
/// step 4's "bind exactly one VM to the live fence" has no field for one.
/// Strict deny-unknown-fields decoding refuses an envelope that tries to
/// smuggle one in, the same fixed way it refuses any other unknown field.
/// This is the concrete evidence that VM-ID correlation is not part of the
/// implemented contract, only of ADR 0133's prose.
#[test]
fn envelope_wire_contract_has_no_vm_identity_field() {
    let binding = binding_for(
        "req_synthetic000000000002",
        "apr_synthetic000000000002",
        "rsv_synthetic000000000002",
        "exe_synthetic000000000002",
        1,
    );
    let mut v = envelope_json(&binding);
    v["binding"]["vm_id"] = json!("synthetic-microvm-0001");
    let bytes = serde_json::to_vec(&v).unwrap();
    assert_eq!(decode(&bytes, &binding).err(), Some(Refusal::Malformed));
}

// ---------------------------------------------------------------------------
// Scenario 3: cancellation of an exposed-but-uncertain run.
// ---------------------------------------------------------------------------

/// Once exposure is committed (ADR 0133 step 6: before any corpus bytes are
/// opened), a cancellation of that run must never refund the budget, even
/// though the custodian genuinely does not know whether the remote engine
/// ever read anything. `custodian-store::cancel` on a `running` attempt
/// presumes exposure and consumes, unconditionally. The contrast with a
/// cancellation before exposure (refunded) shows this is specifically about
/// exposure, not about cancellation itself.
#[test]
fn cancellation_after_exposure_never_refunds_the_uncertain_run() {
    let db = TempDb::new("cancel-exposed");
    let store = open(&db);
    let fx = fixture(3);
    provision(&store, &fx, 3);
    let out = reserve(&store, &fx).unwrap();
    let lease = store
        .start_attempt(&StartCommand {
            attempt: &out.attempt,
            owner: "worker-synthetic-1",
            actor: &actor(),
            now: NOW + 1,
            lease_secs: LEASE,
            observed: Some(&fx.obs),
            max_state_age_secs: MAX_AGE,
        })
        .unwrap();
    // Exposure is committed before the (hypothetical) remote corpus bytes
    // would have been sent; cancellation now happens in a genuinely
    // uncertain window where the engine may or may not have read anything.
    store.record_exposure(&lease, &actor(), NOW + 1).unwrap();

    let settlement = store
        .cancel(&out.attempt, &actor(), ReasonCode::Cancelled, NOW + 2)
        .unwrap();
    assert_eq!(
        settlement.result,
        ReservationState::Consumed,
        "no silent refund of exposed work"
    );
    assert_eq!(settlement.exposure, Exposure::Exposed);
    assert_eq!(settlement.state, RunState::Cancelled);
    assert_eq!(status(&store, &fx), (0, 1, 0));

    // Idempotent: cancelling again changes nothing and still does not refund.
    let again = store
        .cancel(&out.attempt, &actor(), ReasonCode::Cancelled, NOW + 3)
        .unwrap();
    assert_eq!(again, settlement);
    assert_eq!(status(&store, &fx), (0, 1, 0));

    // Contrast: cancelling an attempt that never started (never exposed) is
    // refunded. The conservative rule is about exposure, not cancellation.
    let fx2 = fixture(4);
    provision(&store, &fx2, 3);
    let out2 = reserve(&store, &fx2).unwrap();
    let settlement2 = store
        .cancel(&out2.attempt, &actor(), ReasonCode::Cancelled, NOW + 2)
        .unwrap();
    assert_eq!(settlement2.result, ReservationState::Refunded);
    assert_eq!(status(&store, &fx2), (0, 0, 1));

    store.verify_invariants().unwrap();
}
