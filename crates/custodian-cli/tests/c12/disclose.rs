//! Disclosure helpers for the C12 pipeline: prepare and release through the
//! shared eligibility of a started `Service`.
#![allow(dead_code)]

use super::*;
use custodian_contracts::types::{DestinationId, IdempotencyKey, Timestamp};
use custodian_disclosure::testing::{RecordingSink, StaticNames};
use custodian_disclosure::{
    DisclosureService, PrepareInput, PreparedRelease, ReleaseRequest, ReleasedEnvelope,
};
use custodian_ledger::{Exporter, Verifier};

pub fn ts(secs: u64) -> Timestamp {
    Timestamp::new(secs).unwrap()
}

/// A disclosure service wired to `svc`'s shared eligibility, the pinned-root
/// verifier and the world's ledger.
pub fn with_disclosure<R>(
    p: &Pipe,
    svc: &Service<'_, FsEpochStore>,
    f: impl FnOnce(&DisclosureService<'_>) -> R,
) -> R {
    // As the control plane's own export does: the verifier is the pinned roots
    // extended by the verified key events of the ledger (a rotated key).
    let walk = custodian_ledger::walk_ledger(&p.w.ledger, &p.w.roots).unwrap();
    let verifier = Verifier::new(walk.keyring);
    let exporter = Exporter::new(&p.w.ledger, &p.w.key.signer, &verifier);
    let names = StaticNames(lc::opaque(1));
    let d = svc.disclosure_service(&p.w.rw.store, &exporter, &names);
    f(&d)
}

/// Provision the release budgets and prepare the release on `d`. Errors are
/// fixed reason words.
pub fn prepare_on(
    d: &DisclosureService<'_>,
    feed: custodian_contracts::public::FeedRef,
    req: &EvaluationRequest,
    asm: &Assembled,
    release_n: u32,
    at: u64,
) -> Result<PreparedRelease, &'static str> {
    let policy = dc::policy();
    let key = IdempotencyKey::parse(&cc::id("idk_", 100 + release_n)).unwrap();
    let exec_obs = cc::observed(cc::activation(), at);
    let policy_obs = dc::disclosure_activation(at, "active");
    let binding = policy_binding();
    d.provision_budgets(&policy, &req.plan, &req.asserted_actor, &sc::actor(), NOW)
        .map_err(|e| e.as_str())?;
    d.prepare(
        &PrepareInput {
            policy: &policy,
            request: req,
            execution_approval: &asm.approval,
            reservation: &asm.reservation,
            execution: &asm.execution,
            receipt: &asm.receipt,
            aggregates: &asm.aggregates,
            attempt: &asm.attempt,
            execution_activation: &exec_obs,
            policy_binding: &binding,
            policy_activation: &policy_obs,
            release_key: &key,
            feed,
        },
        ts(at),
    )
    .map_err(|e| e.as_str())
}

/// Release a prepared projection to `dest` at `at` on `d`.
pub fn release_on(
    d: &DisclosureService<'_>,
    prepared: &PreparedRelease,
    approval: &Approval,
    dest: &str,
    sink: &RecordingSink,
    at: u64,
) -> Result<ReleasedEnvelope, &'static str> {
    let policy = dc::policy();
    let obs = dc::disclosure_activation(at, "active");
    let dest = DestinationId::parse(dest).unwrap();
    d.release(
        prepared,
        &ReleaseRequest {
            approval,
            destination: &dest,
            policy: &policy,
            policy_activation: &obs,
        },
        sink,
        ts(at),
    )
    .map_err(|e| e.as_str())
}

/// Provision the release budgets and prepare the release.
pub fn prepare(
    p: &Pipe,
    svc: &Service<'_, FsEpochStore>,
    req: &EvaluationRequest,
    asm: &Assembled,
    release_n: u32,
    at: u64,
) -> Result<PreparedRelease, &'static str> {
    let feed = svc.feed_ref().map_err(|r| r.code())?;
    with_disclosure(p, svc, |d| prepare_on(d, feed, req, asm, release_n, at))
}

/// Release a prepared projection to `dest` at `at`.
pub fn release(
    p: &Pipe,
    svc: &Service<'_, FsEpochStore>,
    prepared: &PreparedRelease,
    approval: &Approval,
    dest: &str,
    sink: &RecordingSink,
    at: u64,
) -> Result<ReleasedEnvelope, &'static str> {
    with_disclosure(p, svc, |d| release_on(d, prepared, approval, dest, sink, at))
}
