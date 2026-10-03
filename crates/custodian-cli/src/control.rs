//! The operator control plane: every command, through the same service state
//! machine as the request edge (C10, ADR 0080 to 0083).
//!
//! What "the same" means here, concretely:
//!
//! * a request becomes a reservation only through `SqliteStore::approve_submission`,
//!   which runs the `reserve_tx` the contract path (`reserve_request`) runs,
//!   keyed by the request's idempotency key, gated by the epoch standing and
//!   checked against the policy activation read inside the same transaction.
//!   There is no other way to charge a budget from this crate;
//! * contamination, retirement, rotation and revocation go through
//!   `custodian-lifecycle`, whose own authorization runs again under the
//!   deployment's [`PolicyAuthority`];
//! * the CLI never opens the database with its own SQL, never edits a budget,
//!   a history table or the ledger, and has no command that raises, lowers or
//!   resets consumption. The repair group can only run the idempotent
//!   operations the service itself runs at startup, plus the audited
//!   `clear_reconcile`, which is refused unless the store is demonstrably not
//!   behind the ledger.

use std::sync::Arc;

use custodian_bridge::legacy::{
    dry_run as legacy_dry_run, ContaminationStanding, HandoffRecord, HandoffStatus, ImportId,
    LegacyImportRecord,
};
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::{ActivationRef, ActorKind, BudgetScope};
use custodian_contracts::policy::{check_current, PolicyActivation};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::ReservationState;
use custodian_contracts::revocation::{PublicRevocationReason, RevocationAction, RevocationTarget};
use custodian_contracts::types::{
    ApprovalId, DocumentDigest, EpochId, FeedId, RequestId, Timestamp,
};
use custodian_core::{ActorId, Contamination, EpochStanding, ReasonCode, RunId, RunState};
use custodian_corpus::{EpochBlobStore, ProtectedPopulations};
use custodian_ledger::{
    walk_ledger, ExportStatus, Exporter, FindingCode, Keyring, LedgerBackend, Signer, Verifier,
};
use custodian_lifecycle::{
    parse_policy_key, ChangeRequest, EpochManager, EpochOutcome, EpochReason, FeedConfig,
    FeedDestination, FeedPublisher, LifecycleFault, OperatorAction, PublicPopulations,
    RevocationSpec, RotationBudget, RotationRequest,
};
use custodian_store::{
    ApproveCommand, Clock, ImportOutcome, LegacyImportCommand, LegacyImportItem, RetentionPolicy,
    SqliteStore, SubmissionChannel, SubmissionStatus, SubmitCommand, Submitted,
};
use serde_json::json;

use crate::authority::{Permission, PolicyAuthority, Principal};
use crate::command::{
    Command, Contaminated, ReconcileTarget, RepairCommand, RevocationKind, RevocationVerb,
    VerifyTarget,
};
use crate::output::Output;
use crate::reason::CliReason;

type Res<T> = Result<T, CliReason>;

/// Everything the control plane is wired to. All references: the deployment
/// owns the objects. `signer` is whatever signer the deployment provides (an
/// isolated signer transport in production); this crate holds no key.
pub struct Parts<'a, S: EpochBlobStore> {
    pub store: &'a SqliteStore,
    pub clock: Arc<dyn Clock>,
    pub authority: &'a PolicyAuthority,
    pub populations: &'a ProtectedPopulations<S>,
    pub ledger: &'a dyn LedgerBackend,
    /// Pinned trust anchors, obtained out of band.
    pub roots: &'a Keyring,
    pub signer: &'a dyn Signer,
    pub feed_destination: &'a dyn FeedDestination,
    pub feed_populations: &'a dyn PublicPopulations,
    pub feed_config: FeedConfig,
    pub fault: &'a dyn LifecycleFault,
}

impl<S: EpochBlobStore> Clone for Parts<'_, S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store,
            clock: self.clock.clone(),
            authority: self.authority,
            populations: self.populations,
            ledger: self.ledger,
            roots: self.roots,
            signer: self.signer,
            feed_destination: self.feed_destination,
            feed_populations: self.feed_populations,
            feed_config: self.feed_config.clone(),
            fault: self.fault,
        }
    }
}

pub struct Control<'a, S: EpochBlobStore> {
    p: Parts<'a, S>,
}

pub(crate) fn state_word(s: RunState) -> &'static str {
    match s {
        RunState::Proposed => "proposed",
        RunState::Authorized => "authorized",
        RunState::Reserved => "reserved",
        RunState::Running => "running",
        RunState::Validating => "validating",
        RunState::Completed => "completed",
        RunState::Denied => "denied",
        RunState::Failed => "failed",
        RunState::Cancelled => "cancelled",
        RunState::Expired => "expired",
    }
}

fn reason_word(r: ReasonCode) -> &'static str {
    match r {
        ReasonCode::Requested => "requested",
        ReasonCode::Authorized => "authorized",
        ReasonCode::AuthorizationDenied => "authorization_denied",
        ReasonCode::PlanMismatch => "plan_mismatch",
        ReasonCode::AuthorizationExpired => "authorization_expired",
        ReasonCode::BudgetReserved => "budget_reserved",
        ReasonCode::BudgetExhausted => "budget_exhausted",
        ReasonCode::DuplicateRequest => "duplicate_request",
        ReasonCode::CorpusUnavailable => "corpus_unavailable",
        ReasonCode::ExecutionFailed => "execution_failed",
        ReasonCode::InvalidArtifact => "invalid_artifact",
        ReasonCode::Cancelled => "cancelled",
        ReasonCode::Completed => "completed",
        ReasonCode::ProtectedBytesAcquired => "protected_bytes_acquired",
        ReasonCode::InvalidTransition => "invalid_transition",
        ReasonCode::StoreUnavailable => "store_unavailable",
        ReasonCode::DisclosureNotPermitted => "disclosure_not_permitted",
    }
}

fn finding_word(c: FindingCode) -> &'static str {
    match c {
        FindingCode::Malformed => "malformed",
        FindingCode::PathMismatch => "path_mismatch",
        FindingCode::BadSignature(_) => "bad_signature",
        FindingCode::KeyEventRejected(_) => "key_event_rejected",
        FindingCode::SeqGap => "seq_gap",
        FindingCode::ChainMismatch => "chain_mismatch",
        FindingCode::CheckpointFork => "checkpoint_fork",
        FindingCode::SupersedesMissing => "supersedes_missing",
        FindingCode::SupersessionFork => "supersession_fork",
        FindingCode::SupersessionChangedChain => "supersession_changed_chain",
        FindingCode::QuarantinePresent => "quarantine_present",
    }
}

fn standing_fields(o: Output, prefix: [&'static str; 2], s: EpochStanding) -> Output {
    o.word(prefix[0], s.contamination.as_str())
        .flag(prefix[1], s.retired)
}

fn epoch_reason(word: &str) -> Res<EpochReason> {
    [
        EpochReason::ResultsExposed,
        EpochReason::TunedOnResults,
        EpochReason::IntegrityAlarm,
        EpochReason::UnreviewedPopulationChange,
        EpochReason::ReviewedNoImpact,
        EpochReason::ContaminationResponse,
        EpochReason::PlannedRotation,
        EpochReason::OperatorDecision,
    ]
    .into_iter()
    .find(|r| r.code() == word)
    .ok_or(CliReason::UsageError)
}

fn store_id_matches(store: &SqliteStore, confirm: &str) -> Res<()> {
    let id = store.store_id().map_err(CliReason::from)?;
    if id == confirm {
        Ok(())
    } else {
        Err(CliReason::ConfirmationMismatch)
    }
}

impl<'a, S: EpochBlobStore> Control<'a, S> {
    pub fn new(parts: Parts<'a, S>) -> Self {
        Self { p: parts }
    }

    pub fn parts(&self) -> &Parts<'a, S> {
        &self.p
    }

    fn now(&self) -> Res<Timestamp> {
        Timestamp::new(self.p.clock.now()).map_err(|_| CliReason::Internal)
    }

    fn limits(&self) -> crate::authority::Limits {
        self.p.authority.policy().limits()
    }

    fn manager(&self) -> EpochManager<'_, S> {
        EpochManager {
            store: self.p.store,
            populations: self.p.populations,
            authority: self.p.authority,
            fault: self.p.fault,
        }
    }

    fn publisher(&self) -> FeedPublisher<'_> {
        FeedPublisher {
            store: self.p.store,
            populations: self.p.feed_populations,
            signer: self.p.signer,
            destination: self.p.feed_destination,
            authority: self.p.authority,
            config: self.p.feed_config.clone(),
            fault: self.p.fault,
        }
    }

    /// The startup check, run before any state-changing command. There is no
    /// flag that skips it. A rollback, an untrusted ledger or a registry
    /// rollback persists the store's write block (cleared only by the audited
    /// `repair clear-reconcile`); an unreachable ledger refuses this command
    /// and changes nothing.
    pub fn gate(&self) -> Res<()> {
        crate::startup::check(&self.p)
            .map(|_| ())
            .map_err(|(r, _)| r)
    }

    fn exporter_verifier(&self) -> Res<Verifier> {
        let walk =
            walk_ledger(self.p.ledger, self.p.roots).map_err(|_| CliReason::LedgerUnavailable)?;
        Ok(Verifier::new(walk.keyring))
    }

    fn check_activation_current(&self, binding: &ActivationRef, now: Timestamp) -> Res<()> {
        let observed = self
            .p
            .store
            .observe_activation(binding, now)
            .map_err(CliReason::from)?
            .ok_or(CliReason::StalePolicy)?;
        check_current(binding, &observed, now, self.limits().max_state_age_secs)
            .map_err(CliReason::from)
    }

    /// Run a command as an authenticated principal.
    pub fn execute(&self, who: &Principal, cmd: &Command, dry_run: bool) -> Output {
        match self.run(who, cmd, dry_run) {
            Ok(o) => o.dry(dry_run),
            Err(r) => Output::refused(cmd.name(), r).dry(dry_run),
        }
    }

    fn run(&self, who: &Principal, cmd: &Command, dry: bool) -> Res<Output> {
        let name = cmd.name();
        match cmd {
            Command::RequestSubmit { document } => self.submit(who, name, document, dry),
            Command::RequestStatus { request_id } => self.status(who, name, request_id),
            Command::RequestList { limit } => self.list(who, name, *limit),
            Command::RequestApprove {
                request_id,
                confirm_plan_digest,
                ttl_secs,
            } => self.approve(
                who,
                name,
                request_id,
                confirm_plan_digest.as_str(),
                *ttl_secs,
                dry,
            ),
            Command::RequestCancel { request_id } => self.cancel(who, name, request_id, dry),
            Command::Verify(t) => self.verify(who, name, *t),
            Command::Reconcile(t) => self.reconcile(who, name, *t),
            Command::LifecycleReport {
                epoch,
                kind,
                reason,
                key,
            } => self.lifecycle_report(who, name, epoch, *kind, reason, key, dry),
            Command::LifecycleClear {
                epoch,
                confirm_epoch,
                key,
            } => self.lifecycle_clear(who, name, epoch, confirm_epoch, key, dry),
            Command::LifecycleRetire {
                epoch,
                confirm_epoch,
                reason,
                key,
            } => self.lifecycle_retire(who, name, epoch, confirm_epoch, reason, key, dry),
            Command::LifecycleRotate {
                predecessor,
                successor,
                confirm_predecessor,
                confirm_successor,
                run_budget_limit,
                reason,
                key,
            } => self.lifecycle_rotate(
                who,
                name,
                (predecessor, successor),
                (confirm_predecessor, confirm_successor),
                *run_budget_limit,
                reason,
                key,
                dry,
            ),
            Command::FeedRecordRevocation {
                id,
                what,
                verb,
                reason,
            } => self.feed_record(who, name, id, what, verb, reason, dry),
            Command::FeedPublish => self.feed_publish(who, name, dry),
            Command::PolicyValidate { document } => self.policy_validate(who, name, document),
            Command::PolicyImportActivation {
                document,
                confirm_activation_id,
                confirm_sequence,
            } => self.policy_import(
                who,
                name,
                document,
                confirm_activation_id,
                *confirm_sequence,
                dry,
            ),
            Command::LegacyApply {
                extract,
                handoff,
                confirm_handoff_digest,
                confirm_report_digest,
            } => self.legacy_apply(
                who,
                name,
                (extract, handoff),
                (confirm_handoff_digest, confirm_report_digest),
                dry,
            ),
            Command::Repair(r) => self.repair(who, name, r, dry),
        }
    }

    // ---- request.submit ---------------------------------------------------------

    fn decode_request(document: &[u8]) -> Res<EvaluationRequest> {
        EvaluationRequest::decode(document).map_err(|_| CliReason::InvalidDocument)
    }

    fn submit(&self, who: &Principal, name: &'static str, doc: &[u8], dry: bool) -> Res<Output> {
        who.check(Permission::RequestSubmit)?;
        let request = Self::decode_request(doc)?;
        // The authenticated identity is the requester. A document that names
        // someone else is refused, never trusted.
        if request.asserted_actor != *who.actor() {
            return Err(CliReason::ActorMismatch);
        }
        let now = self.now()?;
        self.check_activation_current(&request.plan.policy_activation, now)?;
        self.p
            .store
            .check_epoch_usable(request.plan.population.epoch_id.as_str())
            .map_err(CliReason::from)?;
        self.gate()?;
        let rid = request.request_id.as_str();
        let plan_digest = request
            .plan
            .plan_digest()
            .map_err(|_| CliReason::InvalidDocument)?;
        if dry {
            let known = self
                .p
                .store
                .submission(rid)
                .map_err(CliReason::from)?
                .is_some()
                || self
                    .p
                    .store
                    .latest_attempt_of(rid)
                    .map_err(CliReason::from)?
                    .is_some();
            return Ok(Output::ok(
                name,
                if known {
                    "would_replay"
                } else {
                    "would_submit"
                },
            )
            .id("request_id", rid)
            .id("plan_digest", plan_digest.as_str()));
        }
        let out = self
            .p
            .store
            .submit_request(&SubmitCommand {
                request: &request,
                channel: SubmissionChannel::Cli,
                submitted_by: who.actor(),
                now,
            })
            .map_err(|e| match e {
                custodian_store::StoreError::Constraint => CliReason::SubmissionLimit,
                other => other.into(),
            })?;
        let base = Output::ok(name, "submitted")
            .id("request_id", rid)
            .id("plan_digest", plan_digest.as_str());
        Ok(match out {
            Submitted::New => base.word("status", "pending").flag("replay", false),
            Submitted::Replay(s) => base.word("status", s.as_str_word()).flag("replay", true),
            Submitted::ReservedElsewhere { attempt, state } => base
                .word("status", "reserved_elsewhere")
                .id("attempt_id", attempt.as_str())
                .word("run_state", state_word(state))
                .flag("replay", true),
        })
    }

    // ---- request.status / list --------------------------------------------------

    /// Whether the principal may see requests other than its own.
    fn sees_any(who: &Principal) -> bool {
        who.check(Permission::RequestViewAny).is_ok()
    }

    fn status(&self, who: &Principal, name: &'static str, id: &RequestId) -> Res<Output> {
        let any = Self::sees_any(who);
        if !any {
            who.check(Permission::RequestViewOwn)?;
        }
        let rid = id.as_str();
        let store = self.p.store;
        let sub = store.submission(rid).map_err(CliReason::from)?;
        let reserved = store.reserved_request(rid).map_err(CliReason::from)?;
        let attempt = store.latest_attempt_of(rid).map_err(CliReason::from)?;
        let requester = match (&sub, &reserved) {
            (Some(s), _) => s.requester.clone(),
            (None, Some(r)) => r.asserted_actor.as_str().to_owned(),
            (None, None) => return Err(CliReason::NotFound),
        };
        // A requester learns nothing about requests that are not theirs.
        if !any && requester != who.actor().as_str() {
            return Err(CliReason::NotFound);
        }
        let mut o = Output::ok(name, "status").id("request_id", rid);
        o = o.word(
            "submission",
            sub.as_ref().map_or("none", |s| s.status.as_str_word()),
        );
        if let Some(s) = &sub {
            o = o.word("channel", s.channel.as_str_word());
            o = o.opt_id("decided_by", s.decided_by.as_deref());
            o = o.opt_id("approval_id", s.approval_id.as_deref());
        }
        let doc = match (&sub, &reserved) {
            (Some(_), _) => store
                .submission_request(rid)
                .map_err(CliReason::from)?
                .map(|(r, _)| r),
            (None, r) => r.clone(),
        };
        if let Some(a) = &attempt {
            o = o
                .id("attempt_id", a.attempt.as_str())
                .word("run_state", state_word(a.state))
                .word(
                    "exposure",
                    match a.exposure {
                        custodian_core::Exposure::Exposed => "exposed",
                        custodian_core::Exposure::NotExposed => "not_exposed",
                    },
                )
                .num("attempt_no", u64::from(a.attempt_no));
            if let Ok(h) = store.history(&a.attempt) {
                if let Some(last) = h.last() {
                    o = o.word("last_reason", reason_word(last.reason));
                }
            }
        }
        if let Some(r) = doc {
            let b = store
                .budget_status(r.plan.accounting.kind, &r.plan.accounting.budget)
                .map_err(CliReason::from)?;
            if let Some(b) = b {
                o = o
                    .num("budget_limit", b.limit)
                    .num("budget_held", b.held)
                    .num("budget_consumed", b.consumed)
                    .num("budget_refunded", b.refunded)
                    .num("budget_available", b.available());
            } else {
                o = o.word("budget", "not_provisioned");
            }
        }
        Ok(o)
    }

    fn list(&self, who: &Principal, name: &'static str, limit: u32) -> Res<Output> {
        if !Self::sees_any(who) {
            return Err(CliReason::Forbidden);
        }
        let subs = self.p.store.submissions(limit).map_err(CliReason::from)?;
        let pending: Vec<String> = subs
            .iter()
            .filter(|s| s.status == SubmissionStatus::Pending)
            .map(|s| s.request_id.clone())
            .collect();
        Ok(Output::ok(name, "listed")
            .num("count", subs.len() as u64)
            .num("pending", pending.len() as u64)
            .ids("pending_request_ids", &pending))
    }

    // ---- request.approve --------------------------------------------------------

    fn approve(
        &self,
        who: &Principal,
        name: &'static str,
        id: &RequestId,
        confirm_plan: &str,
        ttl: Option<u64>,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::RequestApprove)?;
        // Belt and braces: the permission check already refuses non-humans.
        if who.kind() != ActorKind::Human {
            return Err(CliReason::AutomationNotPermitted);
        }
        self.gate()?;
        let rid = id.as_str();
        let (request, rec) = match self
            .p
            .store
            .submission_request(rid)
            .map_err(CliReason::from)?
        {
            Some(v) => v,
            None => {
                return Err(
                    if self
                        .p
                        .store
                        .reserved_request(rid)
                        .map_err(CliReason::from)?
                        .is_some()
                    {
                        CliReason::AlreadyDecided
                    } else {
                        CliReason::NotFound
                    },
                )
            }
        };
        if rec.status != SubmissionStatus::Pending {
            return Err(CliReason::AlreadyDecided);
        }
        let plan_digest = request
            .plan
            .plan_digest()
            .map_err(|_| CliReason::InvalidDocument)?;
        if plan_digest.as_str() != confirm_plan {
            return Err(CliReason::ConfirmationMismatch);
        }
        if who.actor() == &request.asserted_actor || who.actor().as_str() == rec.submitted_by {
            return Err(CliReason::SelfApproval);
        }
        let now = self.now()?;
        let limits = self.limits();
        let ttl = ttl
            .unwrap_or(limits.approval_ttl_secs)
            .min(limits.approval_ttl_secs);
        if ttl == 0 {
            return Err(CliReason::UsageError);
        }
        let approval = self.compose_approval(who, &request, &plan_digest, now, ttl)?;
        if dry {
            let observed = self
                .p
                .store
                .observe_activation(&approval.activation, now)
                .map_err(CliReason::from)?
                .ok_or(CliReason::StalePolicy)?;
            approval
                .check_for_execution(&request, &observed, now, limits.max_state_age_secs)
                .map_err(CliReason::from)?;
            self.p
                .store
                .check_epoch_usable(request.plan.population.epoch_id.as_str())
                .map_err(CliReason::from)?;
            let b = self
                .p
                .store
                .budget_status(
                    request.plan.accounting.kind,
                    &request.plan.accounting.budget,
                )
                .map_err(CliReason::from)?;
            let units = request.plan.accounting.units.get();
            if b.is_none_or(|b| b.available() < units) {
                return Err(CliReason::BudgetExhausted);
            }
            return Ok(Output::ok(name, "would_approve")
                .id("request_id", rid)
                .id("plan_digest", plan_digest.as_str()));
        }
        let outcome = self
            .p
            .store
            .approve_submission(&ApproveCommand {
                request_id: rid,
                approval: &approval,
                now,
                max_state_age_secs: limits.max_state_age_secs,
                reservation_window_secs: limits.reservation_window_secs,
            })
            .map_err(CliReason::from)?;
        let r = outcome.reserve;
        let base = |o: Output| {
            o.id("request_id", rid)
                .id("approval_id", approval.approval_id.as_str())
                .id("attempt_id", r.attempt.as_str())
                .word("run_state", state_word(r.state))
        };
        if r.state == RunState::Denied {
            // The denial is recorded exactly as on the request edge. The
            // approval was spent on a request the budget could not cover.
            return Ok(
                base(Output::refused(name, CliReason::BudgetExhausted)).flag("recorded", true)
            );
        }
        Ok(base(Output::ok(name, "approved")).flag("recorded", true))
    }

    fn compose_approval(
        &self,
        who: &Principal,
        request: &EvaluationRequest,
        plan_digest: &custodian_contracts::types::PlanDigest,
        now: Timestamp,
        ttl: u64,
    ) -> Res<Approval> {
        use sha2::{Digest, Sha256};
        // Deterministic id: a retry after a crash composes the same approval.
        let mut h = Sha256::new();
        h.update(b"private-custodian/cli/approval/v1\0");
        h.update(request.request_id.as_str().as_bytes());
        h.update([0]);
        h.update(who.actor().as_str().as_bytes());
        let d = h.finalize();
        let mut aid = String::from("apr_");
        for b in d.iter().take(16) {
            aid.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            aid.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
        }
        let plan = &request.plan;
        let v = json!({
            "schema": "private-custodian.approval/1",
            "approval_id": ApprovalId::parse(&aid).map_err(|_| CliReason::Internal)?,
            "scope": {
                "operation": "execute",
                "request_id": request.request_id,
                "plan_digest": plan_digest,
                "candidate": plan.candidate,
                "population": plan.population,
                "budget": plan.accounting.budget,
            },
            "activation": plan.policy_activation,
            "proposer": request.asserted_actor,
            "approver": who.actor(),
            "approver_kind": "human",
            "role_separation": "distinct_principals_procedural",
            "issued_at": now.secs(),
            "expires_at": now.secs().saturating_add(ttl),
        });
        let bytes = serde_json::to_vec(&v).map_err(|_| CliReason::Internal)?;
        Approval::decode(&bytes).map_err(|_| CliReason::ApprovalNotBound)
    }

    // ---- request.cancel ---------------------------------------------------------

    fn cancel(
        &self,
        who: &Principal,
        name: &'static str,
        id: &RequestId,
        dry: bool,
    ) -> Res<Output> {
        let rid = id.as_str();
        let store = self.p.store;
        let sub = store.submission(rid).map_err(CliReason::from)?;
        let reserved = store.reserved_request(rid).map_err(CliReason::from)?;
        let requester = match (&sub, &reserved) {
            (Some(s), _) => s.requester.clone(),
            (None, Some(r)) => r.asserted_actor.as_str().to_owned(),
            (None, None) => return Err(CliReason::NotFound),
        };
        if requester == who.actor().as_str() {
            who.check(Permission::RequestCancelOwn)?;
        } else {
            // Not theirs: only an operator may, and nobody else learns it exists.
            if who.check(Permission::RequestCancelAny).is_err() {
                return Err(if Self::sees_any(who) {
                    CliReason::Forbidden
                } else {
                    CliReason::NotFound
                });
            }
        }
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_cancel").id("request_id", rid));
        }
        let now = self.now()?;
        if let Some(s) = &sub {
            if s.status == SubmissionStatus::Pending || s.status == SubmissionStatus::Cancelled {
                store
                    .cancel_submission(rid, who.actor(), who.kind(), now)
                    .map_err(CliReason::from)?;
                return Ok(Output::ok(name, "cancelled")
                    .id("request_id", rid)
                    .word("run_state", "none"));
            }
        }
        let attempt = store
            .latest_attempt_of(rid)
            .map_err(CliReason::from)?
            .ok_or(CliReason::NotFound)?;
        let settlement = store
            .cancel(
                &RunId::new(attempt.attempt.as_str().to_owned()),
                &ActorId::new(who.actor().as_str()),
                ReasonCode::Cancelled,
                now.secs(),
            )
            .map_err(CliReason::from)?;
        Ok(Output::ok(name, "cancelled")
            .id("request_id", rid)
            .id("attempt_id", attempt.attempt.as_str())
            .word("run_state", state_word(settlement.state))
            .word(
                "settlement",
                match settlement.result {
                    ReservationState::Refunded => "refunded",
                    ReservationState::Consumed => "consumed",
                    ReservationState::Held => "held",
                },
            ))
    }

    // ---- verify -----------------------------------------------------------------

    fn verify(&self, who: &Principal, name: &'static str, t: VerifyTarget) -> Res<Output> {
        who.check(Permission::Verify)?;
        let mut o = Output::ok(name, "verified");
        let mut failed: Option<CliReason> = None;
        let fail = |r: CliReason, failed: &mut Option<CliReason>| {
            if failed.is_none() {
                *failed = Some(r);
            }
        };
        let all = t == VerifyTarget::All;
        let walk = if matches!(
            t,
            VerifyTarget::Ledger
                | VerifyTarget::Checkpoint
                | VerifyTarget::Registry
                | VerifyTarget::All
        ) {
            Some(
                walk_ledger(self.p.ledger, self.p.roots)
                    .map_err(|_| CliReason::LedgerUnavailable)?,
            )
        } else {
            None
        };
        if matches!(t, VerifyTarget::Ledger | VerifyTarget::All) {
            if let Some(w) = &walk {
                let mut words: Vec<String> = w
                    .findings
                    .iter()
                    .map(|f| finding_word(f.code).to_owned())
                    .collect();
                words.sort();
                words.dedup();
                o = o
                    .num("ledger_records", w.records as u64)
                    .num("ledger_findings", w.findings.len() as u64)
                    .num("ledger_quarantined", w.quarantined.len() as u64)
                    .ids("ledger_finding_codes", &words)
                    .flag("ledger_trustworthy", w.is_trustworthy());
                if !w.is_trustworthy() {
                    fail(CliReason::LedgerUntrusted, &mut failed);
                }
            }
        }
        if matches!(t, VerifyTarget::Store | VerifyTarget::All) {
            let r = self
                .p
                .store
                .integrity_check()
                .and_then(|()| self.p.store.verify_lifecycle_invariants());
            match r {
                Ok(()) => o = o.flag("store_intact", true),
                Err(e) => {
                    o = o.flag("store_intact", false);
                    if let custodian_store::StoreError::Invariant(n) = e {
                        o = o.id("store_failed_check", n);
                    }
                    fail(CliReason::VerificationFailed, &mut failed);
                }
            }
            o = o.flag(
                "store_needs_reconcile",
                self.p.store.needs_reconcile().unwrap_or(true),
            );
        }
        if matches!(t, VerifyTarget::Registry | VerifyTarget::All) {
            let view = self
                .p
                .populations
                .registry()
                .view()
                .map_err(|_| CliReason::StoreUnavailable)?;
            o = o
                .num("registry_events", view.event_count())
                .id("registry_head", view.head().as_str());
            let ok = match walk.as_ref().and_then(|w| w.registry_checkpoint.as_ref()) {
                None => {
                    o = o.word("registry_checkpoint", "absent");
                    true
                }
                Some(point) => {
                    let ok = view.event_count() >= point.event_count
                        && view.head_after(point.event_count).as_ref() == Some(&point.head);
                    o = o.word(
                        "registry_checkpoint",
                        if ok { "matches" } else { "diverged" },
                    );
                    ok
                }
            };
            if !ok {
                fail(CliReason::RegistryRolledBack, &mut failed);
            }
        }
        if matches!(t, VerifyTarget::Checkpoint | VerifyTarget::All) {
            let ok = match walk.as_ref().and_then(|w| w.store_checkpoint.as_ref()) {
                None => {
                    o = o.word("store_checkpoint", "absent");
                    true
                }
                Some(cp) => {
                    let ok = self
                        .p
                        .store
                        .contains_checkpoint(cp)
                        .map_err(CliReason::from)?;
                    o = o
                        .word(
                            "store_checkpoint",
                            if ok { "contained" } else { "behind_ledger" },
                        )
                        .num("ledger_checkpoint_seq", cp.seq);
                    ok
                }
            };
            if !ok {
                fail(CliReason::StoreRolledBack, &mut failed);
            }
        }
        let _ = all;
        Ok(match failed {
            None => o,
            Some(r) => rebuild_failed(o, name, r),
        })
    }

    // ---- reconcile (read-only diagnosis) ------------------------------------------

    fn reconcile(&self, who: &Principal, name: &'static str, t: ReconcileTarget) -> Res<Output> {
        who.check(Permission::Diagnose)?;
        let now = self.now()?;
        let store = self.p.store;
        match t {
            ReconcileTarget::Store => {
                let blocked = store.needs_reconcile().map_err(CliReason::from)?;
                let o = Output::ok(name, "consistent")
                    .word("target", "store")
                    .flag("needs_reconcile", blocked)
                    .num(
                        "pending_submissions",
                        store.pending_submission_count().map_err(CliReason::from)?,
                    )
                    .num(
                        "recoverable_attempts",
                        store
                            .recoverable_attempt_count(now.secs())
                            .map_err(CliReason::from)?,
                    )
                    .num(
                        "outbox_unacknowledged",
                        store.outbox_pending_count().map_err(CliReason::from)?,
                    )
                    .num(
                        "store_checkpoint_seq",
                        store
                            .latest_checkpoint()
                            .map_err(CliReason::from)?
                            .map_or(0, |c| c.seq),
                    )
                    .id("store_id", &store.store_id().map_err(CliReason::from)?);
                Ok(if blocked {
                    rebuild_failed(o, name, CliReason::StoreNeedsReconcile)
                } else {
                    o
                })
            }
            ReconcileTarget::Ledger => {
                let verifier = self.exporter_verifier()?;
                let exporter = Exporter::new(self.p.ledger, self.p.signer, &verifier);
                let rep = exporter
                    .reconcile(store, now.secs(), false, false)
                    .map_err(export_reason)?;
                let o = Output::ok(name, "consistent")
                    .word("target", "ledger")
                    .num("store_events", rep.store_events)
                    .num("missing_in_ledger", rep.missing_in_ledger.len() as u64)
                    .num(
                        "unacknowledged_in_ledger",
                        rep.unacked_in_ledger.len() as u64,
                    )
                    .num("conflicting", rep.conflicting.len() as u64);
                let clean = rep.missing_in_ledger.is_empty()
                    && rep.unacked_in_ledger.is_empty()
                    && rep.conflicting.is_empty();
                Ok(if clean {
                    o
                } else {
                    rebuild_failed(o, name, CliReason::VerificationFailed)
                })
            }
            ReconcileTarget::Feed => {
                let feed = self.p.feed_config.feed_id.as_str();
                let head = store.feed_head(feed).map_err(CliReason::from)?;
                let envs = store.feed_envelopes(feed, 1).map_err(CliReason::from)?;
                let undelivered = envs.iter().filter(|e| !e.delivered).count() as u64;
                let pending = store.pending_obligation_count().map_err(CliReason::from)?;
                let o = Output::ok(name, "consistent")
                    .word("target", "feed")
                    .num("head_sequence", head.as_ref().map_or(0, |h| h.sequence))
                    .num("fresh_until", head.as_ref().map_or(0, |h| h.fresh_until))
                    .num("undelivered_envelopes", undelivered)
                    .num("pending_obligations", pending);
                Ok(if undelivered == 0 && pending == 0 {
                    o
                } else {
                    rebuild_failed(o, name, CliReason::PendingObligations)
                })
            }
        }
    }

    // ---- lifecycle ----------------------------------------------------------------

    fn change<'b>(
        &self,
        epoch: &'b EpochId,
        who: &'b custodian_lifecycle::OperatorAuthorization,
        key: &'b custodian_contracts::types::IdempotencyKey,
        reason: EpochReason,
        now: Timestamp,
    ) -> ChangeRequest<'b> {
        ChangeRequest {
            epoch,
            who,
            key,
            reason,
            now,
        }
    }

    fn outcome_fields(o: Output, e: &EpochOutcome) -> Output {
        let mut o = standing_fields(
            o,
            ["prior_contamination", "prior_retired"],
            e.transition.prior,
        );
        o = standing_fields(o, ["new_contamination", "new_retired"], e.transition.new);
        o = o.flag("changed", e.changed).flag("replay", e.replay);
        if let Some(ob) = &e.obligation {
            o = o.id("obligation_id", ob);
        }
        if let Some(r) = &e.retirement {
            o = o
                .flag("also_retired", true)
                .flag("retirement_changed", r.changed);
        }
        o
    }

    #[allow(clippy::too_many_arguments)]
    fn lifecycle_report(
        &self,
        who: &Principal,
        name: &'static str,
        epoch: &EpochId,
        kind: Contaminated,
        reason: &str,
        key: &custodian_contracts::types::IdempotencyKey,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Lifecycle(OperatorAction::ReportContamination))?;
        let reason = epoch_reason(reason)?;
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_report").id("epoch_id", epoch.as_str()));
        }
        let auth =
            who.operator_authorization(OperatorAction::ReportContamination.code(), key.as_str())?;
        let req = self.change(epoch, &auth, key, reason, self.now()?);
        let c = match kind {
            Contaminated::UnreviewedChange => Contamination::UnreviewedChange,
            Contaminated::Exposed => Contamination::Exposed,
            Contaminated::UsedForTuning => Contamination::UsedForTuning,
        };
        let out = self.manager().report(&req, c).map_err(CliReason::from)?;
        Ok(Self::outcome_fields(
            Output::ok(name, "reported").id("epoch_id", epoch.as_str()),
            &out,
        ))
    }

    fn lifecycle_clear(
        &self,
        who: &Principal,
        name: &'static str,
        epoch: &EpochId,
        confirm: &EpochId,
        key: &custodian_contracts::types::IdempotencyKey,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Lifecycle(OperatorAction::ClearUnreviewedChange))?;
        if epoch != confirm {
            return Err(CliReason::ConfirmationMismatch);
        }
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_clear").id("epoch_id", epoch.as_str()));
        }
        let auth =
            who.operator_authorization(OperatorAction::ClearUnreviewedChange.code(), key.as_str())?;
        let req = self.change(
            epoch,
            &auth,
            key,
            EpochReason::ReviewedNoImpact,
            self.now()?,
        );
        let out = self.manager().clear(&req).map_err(CliReason::from)?;
        Ok(Self::outcome_fields(
            Output::ok(name, "cleared").id("epoch_id", epoch.as_str()),
            &out,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn lifecycle_retire(
        &self,
        who: &Principal,
        name: &'static str,
        epoch: &EpochId,
        confirm: &EpochId,
        reason: &str,
        key: &custodian_contracts::types::IdempotencyKey,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Lifecycle(OperatorAction::RetireEpoch))?;
        if epoch != confirm {
            return Err(CliReason::ConfirmationMismatch);
        }
        let reason = epoch_reason(reason)?;
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_retire").id("epoch_id", epoch.as_str()));
        }
        let auth = who.operator_authorization(OperatorAction::RetireEpoch.code(), key.as_str())?;
        let req = self.change(epoch, &auth, key, reason, self.now()?);
        let out = self.manager().retire(&req).map_err(CliReason::from)?;
        Ok(Self::outcome_fields(
            Output::ok(name, "retired").id("epoch_id", epoch.as_str()),
            &out,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn lifecycle_rotate(
        &self,
        who: &Principal,
        name: &'static str,
        (pred, succ): (&EpochId, &EpochId),
        (cpred, csucc): (&EpochId, &EpochId),
        limit: u64,
        reason: &str,
        key: &custodian_contracts::types::IdempotencyKey,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Lifecycle(OperatorAction::RotateEpoch))?;
        if pred != cpred || succ != csucc {
            return Err(CliReason::ConfirmationMismatch);
        }
        if limit == 0 {
            return Err(CliReason::UsageError);
        }
        let reason = epoch_reason(reason)?;
        self.gate()?;
        // The successor's budget names the successor epoch, from the registry.
        let scope = {
            let view = self
                .p
                .populations
                .registry()
                .view()
                .map_err(|_| CliReason::StoreUnavailable)?;
            let (row, _) = view.get(succ).ok_or(CliReason::NotFound)?;
            BudgetScope::PopulationEpoch {
                corpus_id: row.corpus_id.clone(),
                epoch_id: row.epoch_id.clone(),
                family_id: row.family_id.clone(),
            }
        };
        if dry {
            return Ok(Output::ok(name, "would_rotate")
                .id("predecessor", pred.as_str())
                .id("successor", succ.as_str()));
        }
        let auth = who.operator_authorization(OperatorAction::RotateEpoch.code(), key.as_str())?;
        let budgets = [RotationBudget {
            kind: custodian_contracts::common::BudgetKind::Run,
            scope,
            limit,
        }];
        let out = self
            .manager()
            .rotate(&RotationRequest {
                predecessor: pred,
                successor: succ,
                who: &auth,
                key,
                reason,
                budgets: &budgets,
                now: self.now()?,
            })
            .map_err(CliReason::from)?;
        Ok(Output::ok(name, "rotated")
            .id("predecessor", pred.as_str())
            .id("successor", succ.as_str())
            .flag("linked", out.linked)
            .num("budgets_provisioned", out.budgets_provisioned as u64)
            .flag("activated", out.activated)
            .flag("predecessor_changed", out.retirement.changed))
    }

    // ---- feed -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn feed_record(
        &self,
        who: &Principal,
        name: &'static str,
        id: &str,
        what: &RevocationKind,
        verb: &RevocationVerb,
        reason: &str,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Lifecycle(OperatorAction::RecordRevocation))?;
        let target: RevocationTarget = serde_json::from_value(match what {
            RevocationKind::Candidate(c) => json!({"target": "candidate", "candidate": c}),
            RevocationKind::Projection(p) => json!({"target": "projection", "projection_id": p}),
            RevocationKind::Receipt(r) => json!({"target": "receipt", "receipt_id": r}),
            RevocationKind::Policy(p) => {
                let policy = parse_policy_key(p).ok_or(CliReason::UsageError)?;
                json!({"target": "policy", "policy": policy})
            }
        })
        .map_err(|_| CliReason::UsageError)?;
        let action: RevocationAction = serde_json::from_value(match verb {
            RevocationVerb::Revoked => json!({"action": "revoked"}),
            RevocationVerb::Contaminated => json!({"action": "contaminated"}),
            RevocationVerb::Superseded(by) => json!({"action": "superseded", "superseded_by": by}),
        })
        .map_err(|_| CliReason::UsageError)?;
        let reason: PublicRevocationReason =
            serde_json::from_value(json!(reason)).map_err(|_| CliReason::UsageError)?;
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_record").id("revocation_id", id));
        }
        let auth = who.operator_authorization(OperatorAction::RecordRevocation.code(), id)?;
        let fresh = self
            .publisher()
            .record_revocation(
                &auth,
                id,
                &RevocationSpec {
                    target,
                    action,
                    reason,
                },
                self.now()?,
            )
            .map_err(CliReason::from)?;
        Ok(Output::ok(name, "recorded")
            .id("revocation_id", id)
            .flag("replay", !fresh))
    }

    fn feed_publish(&self, who: &Principal, name: &'static str, dry: bool) -> Res<Output> {
        who.check(Permission::Lifecycle(OperatorAction::PublishFeed))?;
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_publish"));
        }
        let auth = who.operator_authorization(OperatorAction::PublishFeed.code(), "publish")?;
        let rep = self
            .publisher()
            .publish(&auth, self.now()?)
            .map_err(CliReason::from)?;
        Ok(Output::ok(
            name,
            if rep.appended.is_some() {
                "published"
            } else {
                "unchanged"
            },
        )
        .num("sequence", rep.appended.unwrap_or(0))
        .num("entries", rep.entries as u64)
        .num("delivered", rep.delivered as u64))
    }

    // ---- policy ---------------------------------------------------------------------

    /// Read-only policy validation of a request document: the same checks
    /// `submit` and `approve` run, with nothing written.
    fn policy_validate(&self, who: &Principal, name: &'static str, doc: &[u8]) -> Res<Output> {
        who.check(Permission::PolicyValidate)?;
        let request = Self::decode_request(doc)?;
        let now = self.now()?;
        self.check_activation_current(&request.plan.policy_activation, now)?;
        self.p
            .store
            .check_epoch_usable(request.plan.population.epoch_id.as_str())
            .map_err(CliReason::from)?;
        let b = self
            .p
            .store
            .budget_status(
                request.plan.accounting.kind,
                &request.plan.accounting.budget,
            )
            .map_err(CliReason::from)?;
        let units = request.plan.accounting.units.get();
        if b.is_none_or(|b| b.available() < units) {
            return Err(CliReason::BudgetExhausted);
        }
        let plan_digest = request
            .plan
            .plan_digest()
            .map_err(|_| CliReason::InvalidDocument)?;
        Ok(Output::ok(name, "valid")
            .id("request_id", request.request_id.as_str())
            .id("plan_digest", plan_digest.as_str())
            .flag("activation_current", true)
            .flag("epoch_usable", true)
            .flag("budget_available", true))
    }

    fn policy_import(
        &self,
        who: &Principal,
        name: &'static str,
        doc: &[u8],
        confirm_id: &str,
        confirm_seq: u64,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::PolicyImport)?;
        let act = PolicyActivation::decode(doc).map_err(|_| CliReason::InvalidDocument)?;
        if act.activation_id.as_str() != confirm_id || act.sequence.get() != confirm_seq {
            return Err(CliReason::ConfirmationMismatch);
        }
        self.gate()?;
        if dry {
            return Ok(Output::ok(name, "would_import").id("activation_id", confirm_id));
        }
        let fresh = self
            .p
            .store
            .record_activation(
                &act,
                &ActorId::new(who.actor().as_str()),
                self.now()?.secs(),
            )
            .map_err(CliReason::from)?;
        Ok(
            Output::ok(name, if fresh { "imported" } else { "unchanged" })
                .id("activation_id", confirm_id)
                .num("sequence", confirm_seq)
                .flag("replay", !fresh),
        )
    }

    // ---- legacy.apply ----------------------------------------------------------------

    /// HG-3 (ADR 0115, ADR 0118): write reviewed legacy consumption into the
    /// runtime budget store. Human operator only. The extract is re-imported
    /// deterministically here (the importer is a pure function of its bytes),
    /// the operator names the exact handoff and report digests, and every gate
    /// of the handoff record must already be cited. The store applies all
    /// records or none, only ever adds, and audits each application and each
    /// refusal in the outbox.
    fn legacy_apply(
        &self,
        who: &Principal,
        name: &'static str,
        (extract, handoff): (&[u8], &[u8]),
        (confirm_handoff, confirm_report): (&DocumentDigest, &DocumentDigest),
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::LegacyImport)?;
        let run = legacy_dry_run(extract).map_err(|_| CliReason::InvalidDocument)?;
        let record = HandoffRecord::decode(handoff).ok_or(CliReason::InvalidDocument)?;
        let handoff_digest = record.digest().ok_or(CliReason::InvalidDocument)?;
        let report_digest = run.report.digest();
        if &handoff_digest != confirm_handoff || &report_digest != confirm_report {
            return Err(CliReason::ConfirmationMismatch);
        }
        if !matches!(
            record.assess(&run.report, &run.records),
            HandoffStatus::ReadyForSignoff
        ) {
            return Err(CliReason::HandoffNotReady);
        }
        let by_id: std::collections::BTreeMap<&ImportId, &LegacyImportRecord> =
            run.records.iter().map(|r| (&r.import_id, r)).collect();
        let mut items = Vec::with_capacity(record.entries.len());
        let (mut contaminated, mut unknown) = (0u64, 0u64);
        for e in &record.entries {
            let r = by_id.get(&e.import_id).ok_or(CliReason::Internal)?;
            match r.body.contamination {
                ContaminationStanding::Contaminated { .. } => contaminated += 1,
                ContaminationStanding::Unknown {} => unknown += 1,
                ContaminationStanding::NoneRecorded {} => {}
            }
            let canonical = r.canonical_bytes().map_err(|_| CliReason::Internal)?;
            items.push(LegacyImportItem {
                import_id: e.import_id.as_str().to_owned(),
                record_digest: sha256_token(&canonical),
                source_scope_key: r.body.scope_key.as_str().to_owned(),
                scope: e.custodian_scope.clone(),
                consumed: u64::from(r.body.budget.consumed),
                declared_limit: r.body.budget.limit.map(u64::from),
                exhausted: r.body.budget.exhausted,
            });
        }
        let base = |o: Output| {
            o.num("records", items.len() as u64)
                .num("contaminated", contaminated)
                .num("contamination_unknown", unknown)
        };
        if dry {
            return Ok(base(Output::ok(name, "would_apply")));
        }
        self.gate()?;
        let now = self.now()?;
        let outcome = self
            .p
            .store
            .apply_legacy_imports(&LegacyImportCommand {
                items: &items,
                handoff_digest: handoff_digest.as_str(),
                report_digest: report_digest.as_str(),
                actor: &ActorId::new(who.actor().as_str()),
                now: now.secs(),
            })
            .map_err(CliReason::from)?;
        Ok(match outcome {
            ImportOutcome::Applied(rep) => base(Output::ok(name, "applied"))
                .num("created", rep.created as u64)
                .num("superseded", rep.superseded as u64)
                .num("already_applied", rep.already_applied as u64)
                .num("applied_units", rep.applied_units),
            ImportOutcome::Refused { reason, .. } => base(Output::ok(name, "refused"))
                .word("refusal", reason.code())
                .with_failure(name, CliReason::ImportRefused),
        })
    }

    // ---- repair ----------------------------------------------------------------------

    fn repair(
        &self,
        who: &Principal,
        name: &'static str,
        r: &RepairCommand,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Repair)?;
        let store = self.p.store;
        let now = self.now()?;
        let op_actor = ActorId::new(who.actor().as_str());
        match r {
            RepairCommand::Recover { confirm_store_id } => {
                store_id_matches(store, confirm_store_id)?;
                if dry {
                    return Ok(Output::ok(name, "would_recover"));
                }
                let rep = store
                    .recover(&op_actor, now.secs())
                    .map_err(CliReason::from)?;
                Ok(Output::ok(name, "recovered")
                    .num("expired_unstarted", rep.expired_unstarted.len() as u64)
                    .num("failed_consumed", rep.failed_consumed.len() as u64))
            }
            RepairCommand::RegistrySweep { confirm_store_id } => {
                store_id_matches(store, confirm_store_id)?;
                if dry {
                    return Ok(Output::ok(name, "would_sweep"));
                }
                let n = self
                    .manager()
                    .reconcile_registry(now)
                    .map_err(CliReason::from)?;
                Ok(Output::ok(name, "swept").num("registry_retired", n as u64))
            }
            RepairCommand::Export { confirm_store_id } => {
                store_id_matches(store, confirm_store_id)?;
                if dry {
                    return Ok(Output::ok(name, "would_export"));
                }
                crate::startup::export_all(&self.p, now).map(|(rep, wrote)| {
                    Output::ok(name, "exported")
                        .num("exported", rep.exported.len() as u64)
                        .num("already_present", rep.already_present.len() as u64)
                        .num("quarantined", rep.quarantined.len() as u64)
                        .word("status", export_status_word(rep.status))
                        .flag("checkpoint_recorded", wrote)
                })
            }
            RepairCommand::LedgerReconcile { confirm_store_id } => {
                store_id_matches(store, confirm_store_id)?;
                if dry {
                    return Ok(Output::ok(name, "would_reconcile"));
                }
                let verifier = self.exporter_verifier()?;
                let exporter = Exporter::new(self.p.ledger, self.p.signer, &verifier);
                let rep = exporter
                    .reconcile(store, now.secs(), true, true)
                    .map_err(export_reason)?;
                let o = Output::ok(name, "reconciled")
                    .num("store_events", rep.store_events)
                    .num("repaired", rep.repaired.len() as u64)
                    .num("conflicting", rep.conflicting.len() as u64);
                Ok(if rep.conflicting.is_empty() {
                    o
                } else {
                    // A conflicting record is never repaired automatically.
                    rebuild_failed(o, name, CliReason::VerificationFailed)
                })
            }
            RepairCommand::FeedDeliver { confirm_feed_id } => {
                let feed: &FeedId = &self.p.feed_config.feed_id;
                if feed.as_str() != confirm_feed_id {
                    return Err(CliReason::ConfirmationMismatch);
                }
                if dry {
                    return Ok(Output::ok(name, "would_deliver"));
                }
                let n = self
                    .publisher()
                    .deliver_pending(now)
                    .map_err(CliReason::from)?;
                Ok(Output::ok(name, "delivered").num("delivered", n as u64))
            }
            RepairCommand::Retention {
                confirm_store_id,
                queue_done_min_age_secs,
                claim_min_age_secs,
                decided_submission_min_age_secs,
                pending_submission_max_age_secs,
                batch_limit,
            } => {
                store_id_matches(store, confirm_store_id)?;
                let policy = RetentionPolicy {
                    queue_done_min_age_secs: *queue_done_min_age_secs,
                    claim_min_age_secs: *claim_min_age_secs,
                    decided_submission_min_age_secs: *decided_submission_min_age_secs,
                    pending_submission_max_age_secs: *pending_submission_max_age_secs,
                    batch_limit: *batch_limit,
                };
                policy.validate().map_err(CliReason::from)?;
                if dry {
                    return Ok(Output::ok(name, "would_purge"));
                }
                self.gate()?;
                let r = store
                    .run_retention(&policy, &op_actor, now.secs())
                    .map_err(CliReason::from)?;
                Ok(Output::ok(name, "purged")
                    .num("expired_pending", r.expired_pending)
                    .num("purged_queue", r.purged_queue)
                    .num("purged_claims", r.purged_claims)
                    .num("purged_submissions", r.purged_submissions)
                    .num("kept_unacknowledged", r.kept_unacknowledged))
            }
            RepairCommand::ClearReconcile {
                confirm_store_id,
                confirm_checkpoint_seq,
            } => self.clear_reconcile(who, name, confirm_store_id, *confirm_checkpoint_seq, dry),
        }
    }

    /// The only way out of the restore block. It is refused unless the ledger
    /// is trustworthy, the store contains the ledger's newest checkpoint (so
    /// consumed budget cannot be understated), the registry is not behind its
    /// checkpoint, and the operator named the exact store and checkpoint
    /// sequence. If the store is behind the ledger no flag helps: the
    /// runbook's answer is a newer backup, or retiring the affected epochs,
    /// never lowering a count.
    fn clear_reconcile(
        &self,
        who: &Principal,
        name: &'static str,
        confirm_store_id: &str,
        confirm_seq: u64,
        dry: bool,
    ) -> Res<Output> {
        let store = self.p.store;
        store_id_matches(store, confirm_store_id)?;
        let walk =
            walk_ledger(self.p.ledger, self.p.roots).map_err(|_| CliReason::LedgerUnavailable)?;
        if !walk.is_trustworthy() {
            return Err(CliReason::LedgerUntrusted);
        }
        let local = store.latest_checkpoint().map_err(CliReason::from)?;
        if local.as_ref().map_or(0, |c| c.seq) != confirm_seq {
            return Err(CliReason::ConfirmationMismatch);
        }
        if let Some(cp) = &walk.store_checkpoint {
            if !store.contains_checkpoint(cp).map_err(CliReason::from)? {
                return Err(CliReason::StoreBehindLedger);
            }
        }
        if let Some(point) = &walk.registry_checkpoint {
            let view = self
                .p
                .populations
                .registry()
                .view()
                .map_err(|_| CliReason::StoreUnavailable)?;
            if view.event_count() < point.event_count
                || view.head_after(point.event_count).as_ref() != Some(&point.head)
            {
                return Err(CliReason::RegistryRolledBack);
            }
        }
        if dry {
            return Ok(Output::ok(name, "would_clear").flag(
                "was_blocked",
                store.needs_reconcile().map_err(CliReason::from)?,
            ));
        }
        let was = store.needs_reconcile().map_err(CliReason::from)?;
        store
            .clear_reconcile(&ActorId::new(who.actor().as_str()), self.now()?.secs())
            .map_err(CliReason::from)?;
        Ok(Output::ok(name, "cleared").flag("was_blocked", was))
    }
}

/// `sha256:` plus the lowercase hex SHA-256 of `bytes`.
fn sha256_token(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut out = String::from("sha256:");
    for b in Sha256::digest(bytes) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

trait Word {
    fn as_str_word(&self) -> &'static str;
}
impl Word for SubmissionStatus {
    fn as_str_word(&self) -> &'static str {
        self.as_str()
    }
}
impl Word for SubmissionChannel {
    fn as_str_word(&self) -> &'static str {
        self.as_str()
    }
}

/// Keep the fields gathered so far, turn the result into a failure.
fn rebuild_failed(o: Output, name: &'static str, r: CliReason) -> Output {
    o.with_failure(name, r)
}

/// The fixed CLI reason an export failure is reported under. Public so the
/// daemon's scheduler reports exactly the codes the operator CLI does.
pub fn export_reason(e: custodian_ledger::ExportError) -> CliReason {
    use custodian_ledger::ExportError as E;
    match e {
        E::Source(s) => s.into(),
        E::Sign(custodian_ledger::SignRefusal::SignerUnavailable) => CliReason::SignerUnavailable,
        E::Sign(_) | E::SelfCheck(_) => CliReason::SignerUnavailable,
        E::Backend(_) => CliReason::LedgerUnavailable,
        E::Record(_) | E::AckConflict => CliReason::VerificationFailed,
        E::InjectedCrash(_) => CliReason::Internal,
    }
}

pub(crate) fn export_status_word(s: ExportStatus) -> &'static str {
    match s {
        ExportStatus::Drained => "drained",
        ExportStatus::Deferred { .. } => "deferred",
        ExportStatus::Blocked => "blocked",
    }
}
