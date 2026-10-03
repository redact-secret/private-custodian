//! The disclosure service: validate the complete internal record, charge the
//! budgets, decide the cells, build a separate public projection from an
//! explicit allowlist, and (after a distinct release approval and a durable
//! audit acknowledgement) sign, ledger and deliver it (ADR 0060 to 0063).
//!
//! Two steps, because the release approval binds the projection digest:
//!
//! 1. [`DisclosureService::prepare_bound`] validates, charges and builds a
//!    public projection v2 whose signed payload carries the intended
//!    destination (ADR 0119, 0120). Nothing leaves the private boundary.
//!    [`DisclosureService::prepare`] is the legacy v1 path with no
//!    destination in the payload; it stays for stored-document compatibility
//!    and its releases are labelled "no destination binding" by consumers.
//! 2. [`DisclosureService::release`] needs a release `Approval` (a scope
//!    separate from execution approval), a current disclosure-policy
//!    activation, a destination the policy allows, a cleared precondition and
//!    an acknowledged charge audit. It writes the `policy` and `publication`
//!    ledger records durably, signs through `ApprovedPayload::projection_v2`
//!    (or `projection` for the legacy path), and
//!    only then hands a [`ReleasedEnvelope`] to the sink.
//!
//! A public projection is never produced by deleting fields from an internal
//! record: the builder below names every public field and copies in only
//! values that are public by contract.

use custodian_contracts::approval::{Approval, ApprovalScope};
use custodian_contracts::canonical::{to_canonical_bytes, Contract};
use custodian_contracts::common::{
    ActivationRef, BudgetScope, IndependenceClaim, Purpose, SignatureAlgorithm,
};
use custodian_contracts::error::BindingError;
use custodian_contracts::execution::{ExecutionOutcome, ExecutionRecord, InternalReceipt};
use custodian_contracts::policy::{check_current, ObservedActivation};
use custodian_contracts::public::{
    AggregateCell, CellValue, FeedRef, PublicProjection, PublicProjectionEnvelope,
    PublicProjectionSchema, ScopeKind,
};
use custodian_contracts::public_v2::{
    AnyProjectionEnvelope, PublicProjectionEnvelopeV2, PublicProjectionV2,
};
use custodian_contracts::request::{EvaluationPlan, EvaluationRequest};
use custodian_contracts::reservation::Reservation;
use custodian_contracts::types::{
    ActorRef, ApprovalId, BoundedVec, Count, DestinationId, DocumentDigest, ExecutionId,
    IdempotencyKey, ProjectionDigest, ProjectionId, ReceiptId, Timestamp,
};
use custodian_core::{ActorId, RunId};
use custodian_ledger::record::{PublicationBody, PublicationDecision};
use custodian_ledger::{
    ApprovedPayload, ExportError, Exporter, LedgerRecord, SignRefusal, Signer, WriteOutcome,
};
use custodian_store::{ChargeOutcome, ReleaseCharge, ReleaseScope};
use sha2::{Digest, Sha256};

use crate::aggregate::PrivateAggregates;
use crate::compose::{check_artifact, decide, history_payload, Prior};
use crate::policy::DisclosurePolicy;
use crate::ports::{
    DisclosureStore, EligibilitySubject, PublicPopulationNames, ReleaseEligibility, Sink,
};
use crate::reason::DisclosureReason as R;
use crate::released::ReleasedEnvelope;

type Res<T> = Result<T, R>;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

fn derived(domain: &str, input: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/v1/disclosure/");
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(input.as_bytes());
    hex(&h.finalize())
}

/// Binding errors against the execution policy activation (receipt reuse).
fn map_activation(e: BindingError) -> R {
    match e {
        BindingError::StateStale => R::ActivationStale,
        _ => R::ActivationNotCurrent,
    }
}

/// Binding errors against the disclosure policy activation.
fn map_policy_activation(e: BindingError) -> R {
    match e {
        BindingError::StateStale => R::ActivationStale,
        BindingError::ActivationRevoked
        | BindingError::ActivationSuperseded
        | BindingError::ActivationExpired => R::PolicyStale,
        _ => R::ActivationNotCurrent,
    }
}

/// What a caller supplies to prepare a release. Every field is internal and
/// stays internal: the builder copies public values out of them one by one.
pub struct PrepareInput<'a> {
    pub policy: &'a DisclosurePolicy,
    pub request: &'a EvaluationRequest,
    pub execution_approval: &'a Approval,
    pub reservation: &'a Reservation,
    pub execution: &'a ExecutionRecord,
    pub receipt: &'a InternalReceipt,
    /// The private aggregate artifact the receipt's `result` names.
    pub aggregates: &'a [u8],
    /// The store attempt whose terminal audit event gates disclosure.
    pub attempt: &'a RunId,
    /// Current state of the execution-policy activation the plan bound.
    pub execution_activation: &'a ObservedActivation,
    /// The disclosure-policy activation a release approval must bind.
    pub policy_binding: &'a ActivationRef,
    pub policy_activation: &'a ObservedActivation,
    /// Idempotency identity of this release attempt. A retry reuses it and is
    /// never charged twice.
    pub release_key: &'a IdempotencyKey,
    /// Where consumers find revocation state (C9 supplies the feed).
    pub feed: FeedRef,
}

/// A built, unsigned projection awaiting a release approval. The digest is
/// what the approval must bind.
pub struct PreparedRelease {
    /// The version-neutral fields in the v1 shape. For a bound (v2) release
    /// this is a review view only; the signed document is `v2`.
    projection: PublicProjection,
    /// Present when prepared with [`DisclosureService::prepare_bound`].
    v2: Option<PublicProjectionV2>,
    /// The destination bound at prepare time (v2 only).
    destination: Option<DestinationId>,
    digest: ProjectionDigest,
    policy_digest: DocumentDigest,
    execution_id: ExecutionId,
    execution_approval_id: ApprovalId,
    attempt: RunId,
    charge_id: String,
    candidate: custodian_contracts::types::CandidateDigest,
    population: custodian_contracts::common::PopulationBinding,
}

impl core::fmt::Debug for PreparedRelease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedRelease")
            .field("digest", &self.digest.as_str())
            .finish()
    }
}

impl PreparedRelease {
    /// The version-neutral projection fields the approver reviews. Public by
    /// construction. For a bound (v2) release this is the v1-shaped view of
    /// the common fields: it is not what is signed and its digest is not
    /// [`Self::digest`]; see [`Self::projection_v2`].
    pub fn projection(&self) -> &PublicProjection {
        &self.projection
    }

    /// The v2 projection that will be signed, when prepared with a destination.
    pub fn projection_v2(&self) -> Option<&PublicProjectionV2> {
        self.v2.as_ref()
    }

    /// The destination bound into the signed payload; `None` on the legacy
    /// v1 path.
    pub fn destination(&self) -> Option<&DestinationId> {
        self.destination.as_ref()
    }

    /// The digest a release `Approval` must bind.
    pub fn digest(&self) -> &ProjectionDigest {
        &self.digest
    }

    pub fn execution_id(&self) -> &ExecutionId {
        &self.execution_id
    }
}

/// A release decision.
pub struct ReleaseRequest<'a> {
    pub approval: &'a Approval,
    pub destination: &'a DestinationId,
    pub policy: &'a DisclosurePolicy,
    pub policy_activation: &'a ObservedActivation,
}

pub struct DisclosureService<'a> {
    pub store: &'a dyn DisclosureStore,
    pub exporter: &'a Exporter<'a>,
    pub signer: &'a dyn Signer,
    pub eligibility: &'a dyn ReleaseEligibility,
    pub names: &'a dyn PublicPopulationNames,
}

/// Population and lineage scopes a plan draws on, plus the requester.
fn release_scopes(plan: &EvaluationPlan) -> (BudgetScope, Option<BudgetScope>) {
    let p = &plan.population;
    let pop = BudgetScope::PopulationEpoch {
        corpus_id: p.corpus_id.clone(),
        epoch_id: p.epoch_id.clone(),
        family_id: p.family_id.clone(),
    };
    let lineage = match &plan.accounting.budget {
        b @ BudgetScope::CandidateLineageEpoch { .. } => Some(b.clone()),
        BudgetScope::PopulationEpoch { .. } => None,
    };
    (pop, lineage)
}

fn series_key(pop: &BudgetScope) -> Res<String> {
    ReleaseScope::Budget(pop)
        .key()
        .map_err(|_| R::StoreUnavailable)
}

impl DisclosureService<'_> {
    /// Provision (or raise) the release and query budgets the policy states
    /// for a plan's population, candidate lineage and requester. A limit only
    /// rises; consumption never resets.
    pub fn provision_budgets(
        &self,
        policy: &DisclosurePolicy,
        plan: &EvaluationPlan,
        requester: &ActorRef,
        actor: &ActorId,
        now: u64,
    ) -> Res<()> {
        policy.validate()?;
        let (pop, lineage) = release_scopes(plan);
        let b = &policy.budgets;
        self.store.provision(
            &ReleaseScope::Budget(&pop),
            b.per_population.get(),
            actor,
            now,
        )?;
        if let Some(l) = &lineage {
            self.store
                .provision(&ReleaseScope::Budget(l), b.per_lineage.get(), actor, now)?;
        }
        self.store.provision(
            &ReleaseScope::Requester(requester.as_str()),
            b.per_requester.get(),
            actor,
            now,
        )
    }

    /// Validate the complete internal record, charge the budgets, decide the
    /// cells and build the public projection.
    ///
    /// Everything before the charge is free of side effects. From the charge
    /// on, the attempt is counted whatever happens next (released, withheld,
    /// failed): the policy has no refund. A retry with the same release key
    /// replays the charge and recomputes the same projection.
    ///
    /// This is the legacy v1 path: the projection has no destination, so a
    /// consumer cannot verify one from the envelope. New releases should use
    /// [`Self::prepare_bound`].
    pub fn prepare(&self, input: &PrepareInput<'_>, now: Timestamp) -> Res<PreparedRelease> {
        self.prepare_inner(input, None, now)
    }

    /// Like [`Self::prepare`], but builds a public projection v2 whose signed
    /// payload carries `destination`, so the release approval (which binds
    /// the v2 digest) covers it and a consumer verifies the binding from the
    /// envelope alone. The destination must be on the policy's allowlist; a
    /// refusal happens before anything is charged. `release` refuses a
    /// different destination.
    pub fn prepare_bound(
        &self,
        input: &PrepareInput<'_>,
        destination: &DestinationId,
        now: Timestamp,
    ) -> Res<PreparedRelease> {
        self.prepare_inner(input, Some(destination), now)
    }

    fn prepare_inner(
        &self,
        input: &PrepareInput<'_>,
        destination: Option<&DestinationId>,
        now: Timestamp,
    ) -> Res<PreparedRelease> {
        let policy = input.policy;
        policy.validate()?;
        if let Some(d) = destination {
            if !policy.allows_destination(d) {
                return Err(R::DestinationNotAllowed);
            }
        }
        let plan = &input.request.plan;
        let max_age = policy.state_max_age_secs.get();

        // 1. Gate: completed, settled, terminal audit durably exported.
        self.store.precondition(input.attempt)?;

        // 2. Validate every internal record before anything is built.
        self.validate_internal(input, now, max_age)?;
        let aggregates = PrivateAggregates::decode(
            input.aggregates,
            &input.receipt.result,
            plan.domain,
            &input.receipt.frozen.protocol,
            &input.receipt.roster,
        )?;
        check_artifact(policy, &aggregates)?;

        // Eligibility (C9) before anything is charged: a contaminated,
        // retired or revoked population or candidate must not cost budget or
        // leave a history entry. The projection does not exist yet, so the
        // subject carries an all-zero digest; `release` checks again with the
        // real one, twice.
        self.eligibility
            .check(
                &EligibilitySubject {
                    candidate: &plan.candidate,
                    population: &plan.population,
                    execution: &input.execution.execution_id,
                    projection: &ProjectionDigest::from_raw([0u8; 32]),
                },
                now,
            )
            .map_err(|_| R::EligibilityDenied)?;

        // 3. Charge. From here the attempt is counted.
        let (pop, lineage) = release_scopes(plan);
        let requester = input.request.asserted_actor.as_str();
        let mut scopes = vec![ReleaseScope::Budget(&pop)];
        if let Some(l) = &lineage {
            scopes.push(ReleaseScope::Budget(l));
        }
        scopes.push(ReleaseScope::Requester(requester));
        let charge_id = input.release_key.as_str();
        let actor = ActorId::new(requester);
        let outcome = self.store.charge(&ReleaseCharge {
            charge_id,
            scopes: &scopes,
            units: policy.budgets.units_per_attempt.get(),
            actor: &actor,
            now: now.secs(),
        })?;
        match outcome {
            ChargeOutcome::Charged | ChargeOutcome::Replayed => {}
            ChargeOutcome::Exhausted => return Err(R::BudgetExhausted),
            ChargeOutcome::NotProvisioned => return Err(R::BudgetNotProvisioned),
        }

        // 4. Composition: what has this population's series already revealed?
        let series = series_key(&pop)?;
        let measurement = derived(
            "measurement",
            &hex(&to_canonical_bytes(&input.receipt.frozen).map_err(|_| R::ReceiptInvalid)?),
        );
        let (projection_id, receipt_id) = public_ids(charge_id)?;
        let history = self.store.history(&series)?;
        let own = projection_id.as_str();
        let before: Vec<_> = history
            .iter()
            .take_while(|e| e.release_id != own)
            .cloned()
            .collect();
        let expected_seq = u64::try_from(before.len()).map_err(|_| R::HistoryConflict)?;
        if history.len() > before.len() + 1 {
            // Our own entry exists but later releases followed: a retry must
            // not reorder what was revealed.
            return Err(R::HistoryConflict);
        }
        let prior = Prior::from_history(&before, &measurement)?;
        let decisions = decide(policy, &aggregates, &prior)?;

        // 5. Build the separate public projection from the allowlist.
        let public_population = self
            .names
            .public_ref(&plan.population)
            .ok_or(R::BindingMismatch)?;
        let cells: Vec<AggregateCell> = decisions
            .iter()
            .map(|d| AggregateCell {
                stratum: d.stratum.clone(),
                metric: d.metric.clone(),
                value: match d.value {
                    Some((n, den)) => match (Count::new(n), Count::new(den)) {
                        (Ok(numerator), Ok(denominator)) => CellValue::Reported {
                            numerator,
                            denominator,
                        },
                        _ => CellValue::Suppressed {},
                    },
                    None => CellValue::Suppressed {},
                },
            })
            .collect();
        let issued_at = now;
        let fresh_until = Timestamp::new(
            now.secs()
                .checked_add(policy.freshness_secs.get())
                .ok_or(R::PolicyInvalid)?,
        )
        .map_err(|_| R::PolicyInvalid)?;
        let projection = PublicProjection {
            schema: PublicProjectionSchema,
            projection_id: projection_id.clone(),
            receipt_id,
            domain: plan.domain,
            population: public_population,
            candidate: plan.candidate.clone(),
            engine: plan.engine.clone(),
            protocol: plan.protocol.clone(),
            scope_kind: match plan.accounting.budget {
                BudgetScope::PopulationEpoch { .. } => ScopeKind::PopulationEpoch,
                BudgetScope::CandidateLineageEpoch { .. } => ScopeKind::CandidateLineageEpoch,
            },
            disclosure_policy: policy.policy.clone(),
            attestation: input.receipt.attestation.clone(),
            cells: BoundedVec::new(cells).map_err(|_| R::PolicyInvalid)?,
            issued_at,
            fresh_until,
            revocation_feed: input.feed.clone(),
        };
        projection.validate().map_err(|_| R::PolicyInvalid)?;
        let v2 = destination.map(|d| PublicProjectionV2::bind(&projection, d.clone()));
        let digest = match &v2 {
            Some(p) => {
                p.validate().map_err(|_| R::PolicyInvalid)?;
                p.projection_digest()
            }
            None => projection.projection_digest(),
        }
        .map_err(|_| R::PolicyInvalid)?;

        // 6. Record what this release reveals, conditional on the history we
        // checked against. A concurrent release makes this a conflict.
        let payload = history_payload(policy, &measurement, &decisions)?;
        self.store
            .append(&series, expected_seq, own, &payload, now.secs())?;

        Ok(PreparedRelease {
            projection,
            v2,
            destination: destination.cloned(),
            digest,
            policy_digest: policy.document_digest()?,
            execution_id: input.execution.execution_id.clone(),
            execution_approval_id: input.execution_approval.approval_id.clone(),
            attempt: input.attempt.clone(),
            charge_id: charge_id.to_owned(),
            candidate: plan.candidate.clone(),
            population: plan.population.clone(),
        })
    }

    /// Validate the whole internal record: schema (already strict at decode),
    /// bindings to plan, candidate, engine, population and activation,
    /// provenance, roster coverage and evidence class.
    fn validate_internal(&self, input: &PrepareInput<'_>, now: Timestamp, max_age: u64) -> Res<()> {
        let policy = input.policy;
        let request = input.request;
        let plan = &request.plan;
        let receipt = input.receipt;
        let execution = input.execution;

        plan.validate().map_err(|_| R::BindingMismatch)?;
        if plan.disclosure_policy != policy.policy {
            return Err(R::PolicyMismatch);
        }
        receipt.validate().map_err(|_| R::ReceiptInvalid)?;
        execution.validate().map_err(|_| R::ReceiptInvalid)?;
        if receipt.outcome != ExecutionOutcome::Success
            || execution.outcome != ExecutionOutcome::Success
            || !execution.is_releasable()
        {
            return Err(R::ReceiptNotReleasable);
        }
        // A complete roster with no failed item, exactly as authorized.
        let r = &receipt.roster;
        if r.observed != r.expected || r.failed.get() != 0 || r.expected.get() == 0 {
            return Err(R::RosterIncomplete);
        }
        // The execution record belongs to the store attempt whose audit trail
        // gates this release.
        let (attempt_request, attempt_reservation) = self.store.attempt_binding(input.attempt)?;
        if attempt_request != execution.request_id.as_str()
            || attempt_reservation != execution.reservation_id.as_str()
        {
            return Err(R::ProvenanceMismatch);
        }
        // Execution record against request and reservation.
        execution
            .check_binding(request, input.reservation)
            .map_err(|_| R::BindingMismatch)?;
        let plan_digest = plan.plan_digest().map_err(|_| R::BindingMismatch)?;
        if receipt.execution_id != execution.execution_id
            || receipt.plan_digest != plan_digest
            || receipt.activation != plan.policy_activation
            || receipt.frozen != plan.frozen_identities()
        {
            return Err(R::ProvenanceMismatch);
        }
        // The execution approval is the one that authorized this run.
        let ApprovalScope::Execute {
            plan_digest: approved_plan,
            candidate,
            population,
            ..
        } = &input.execution_approval.scope
        else {
            return Err(R::ProvenanceMismatch);
        };
        if input.execution_approval.approval_id != execution.approval_id
            || *approved_plan != plan_digest
            || *candidate != plan.candidate
            || *population != plan.population
        {
            return Err(R::ProvenanceMismatch);
        }
        // Evidence class stays separate from public/synthetic qualification:
        // a conformance control is `public-control` and nothing else is.
        let public_control = receipt.attestation.independence == IndependenceClaim::PublicControl;
        if (plan.purpose == Purpose::ConformanceControl) != public_control {
            return Err(R::ProvenanceMismatch);
        }
        // A prior success is evidence, never permission.
        receipt
            .check_still_valid(input.execution_activation, now, max_age)
            .map_err(map_activation)?;
        // The disclosure policy itself must be the one named and current.
        if input.policy_binding.policy != policy.policy {
            return Err(R::PolicyMismatch);
        }
        check_current(input.policy_binding, input.policy_activation, now, max_age)
            .map_err(map_policy_activation)?;
        Ok(())
    }

    /// Release a prepared projection to one destination.
    ///
    /// Order: destination and policy checks; precondition and audit
    /// acknowledgement; the release approval and current activation; the
    /// eligibility hook; signing through the approved-payload gate; the
    /// `policy` and `publication` ledger records, durably; the eligibility
    /// hook again; and last, delivery. Any failure before delivery leaves
    /// nothing delivered. The release approval is single-purpose: it binds
    /// this execution, this digest and this policy, and it must not be the
    /// execution approval.
    pub fn release(
        &self,
        prepared: &PreparedRelease,
        request: &ReleaseRequest<'_>,
        sink: &dyn Sink,
        now: Timestamp,
    ) -> Res<ReleasedEnvelope> {
        let policy = request.policy;
        policy.validate()?;
        let projection = &prepared.projection;
        if projection.disclosure_policy != policy.policy {
            return Err(R::PolicyMismatch);
        }
        if policy.document_digest()? != prepared.policy_digest {
            return Err(R::PolicyStale);
        }
        if !policy.allows_destination(request.destination) {
            return Err(R::DestinationNotAllowed);
        }
        // A bound projection was prepared, digested and approved for one
        // destination; releasing it anywhere else is refused.
        if let Some(bound) = &prepared.destination {
            if bound != request.destination {
                return Err(R::DestinationMismatch);
            }
        }
        if now >= projection.fresh_until {
            return Err(R::PolicyStale);
        }
        let max_age = policy.state_max_age_secs.get();

        // Durable audit before anything is signed or delivered.
        self.store.precondition(&prepared.attempt)?;
        if !self.store.charge_exported(&prepared.charge_id)? {
            return Err(R::AuditNotAcknowledged);
        }

        // The release approval: a distinct scope, bound to this projection.
        let approval = request.approval;
        if approval.approval_id == prepared.execution_approval_id {
            return Err(R::ApprovalWrongScope);
        }
        if approval.activation.policy != policy.policy
            || request.policy_activation.activation.policy != policy.policy
        {
            return Err(R::PolicyMismatch);
        }
        approval
            .check_for_release(
                &prepared.execution_id,
                &prepared.digest,
                &projection.disclosure_policy,
                request.policy_activation,
                now,
                max_age,
            )
            .map_err(|e| match e {
                BindingError::OperationMismatch => R::ApprovalWrongScope,
                BindingError::ApproverNotPermitted => R::ApproverNotPermitted,
                BindingError::ExecutionMismatch
                | BindingError::ProjectionMismatch
                | BindingError::PolicyMismatch => R::ApprovalNotBound,
                BindingError::ApprovalExpired | BindingError::ApprovalNotYetValid => {
                    R::ApprovalExpired
                }
                other => map_policy_activation(other),
            })?;

        self.eligible(prepared, now)?;

        // Sign only through the approved-payload gate; the signer re-validates.
        let approved = match &prepared.v2 {
            Some(v2) => ApprovedPayload::projection_v2(
                v2,
                approval,
                &prepared.execution_id,
                request.policy_activation,
                now,
                max_age,
            ),
            None => ApprovedPayload::projection(
                projection,
                approval,
                &prepared.execution_id,
                request.policy_activation,
                now,
                max_age,
            ),
        }
        .map_err(|_| R::SigningRefused)?;
        let signature = self.signer.sign(&approved).map_err(|e| match e {
            SignRefusal::SignerUnavailable => R::SignerUnavailable,
            _ => R::SigningRefused,
        })?;
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(R::SigningRefused);
        }

        // Ledger the policy and the publication decision durably, before any
        // signed byte leaves.
        let policy_record = policy.ledger_record(
            approval.activation.clone(),
            request.policy_activation.activation.changed_at.secs(),
        )?;
        self.write(&policy_record)?;
        let decision = LedgerRecord::publication(
            PublicationBody {
                projection_id: projection.projection_id.clone(),
                receipt_id: projection.receipt_id.clone(),
                projection_digest: prepared.digest.clone(),
                signature_key_id: signature.key_id.clone(),
                decision: Some(PublicationDecision {
                    destination: request.destination.clone(),
                    disclosure_policy: policy.policy.clone(),
                    execution_id: prepared.execution_id.clone(),
                    approval_id: approval.approval_id.clone(),
                    approver: approval.approver.clone(),
                    approver_kind: approval.approver_kind,
                }),
            },
            projection.issued_at.secs(),
        )
        .map_err(|_| R::LedgerConflict)?;
        self.write(&decision)?;

        // The last gate before bytes leave.
        self.eligible(prepared, now)?;
        let envelope = match &prepared.v2 {
            Some(v2) => AnyProjectionEnvelope::V2(PublicProjectionEnvelopeV2 {
                payload: v2.clone(),
                signature,
            }),
            None => AnyProjectionEnvelope::V1(PublicProjectionEnvelope {
                payload: projection.clone(),
                signature,
            }),
        };
        let released = ReleasedEnvelope::new(envelope, request.destination.clone());
        sink.deliver(&released).map_err(|_| R::DeliveryFailed)?;
        Ok(released)
    }

    fn eligible(&self, prepared: &PreparedRelease, now: Timestamp) -> Res<()> {
        self.eligibility
            .check(
                &EligibilitySubject {
                    candidate: &prepared.candidate,
                    population: &prepared.population,
                    execution: &prepared.execution_id,
                    projection: &prepared.digest,
                },
                now,
            )
            .map_err(|_| R::EligibilityDenied)
    }

    fn write(&self, record: &LedgerRecord) -> Res<()> {
        match self.exporter.write_record(record) {
            Ok(WriteOutcome::Created | WriteOutcome::Identical) => Ok(()),
            Ok(WriteOutcome::Quarantined { .. }) => Err(R::LedgerConflict),
            Ok(WriteOutcome::Deferred { .. }) => Err(R::LedgerUnavailable),
            Err(ExportError::Sign(SignRefusal::SignerUnavailable)) => Err(R::SignerUnavailable),
            Err(ExportError::Sign(_) | ExportError::SelfCheck(_) | ExportError::Record(_)) => {
                Err(R::SigningRefused)
            }
            Err(_) => Err(R::LedgerUnavailable),
        }
    }
}

/// Public identities, derived from the release key so a retry is identical
/// and neither value equals or reveals an internal id.
fn public_ids(release_key: &str) -> Res<(ProjectionId, ReceiptId)> {
    let p = derived("projection-id", release_key);
    let r = derived("receipt-id", release_key);
    Ok((
        ProjectionId::parse(&format!("prj_{}", &p[..32])).map_err(|_| R::PolicyInvalid)?,
        ReceiptId::parse(&format!("rcp_{}", &r[..32])).map_err(|_| R::PolicyInvalid)?,
    ))
}
