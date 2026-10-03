//! Shared building blocks: evaluation domains, frozen identities, population
//! and budget bindings, policy references, attestations and signatures.

use custodian_core::{Exposure, ReasonCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::*;

/// Evaluation domain. Plan, protocol, population and policies must all agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationDomain {
    Credential,
    Pii,
}

/// Why the run is requested. A conformance control is a public synthetic
/// lifecycle test, never protected-holdout evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    ProtectedEvaluation,
    ConformanceControl,
}

/// A named, versioned, content-addressed component (engine, adapter, scanner).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub name: ComponentName,
    pub version: VersionLabel,
    pub digest: ArtifactDigest,
}

/// Measurement protocol, versioned separately from schemas and policies. The
/// legacy TypeScript semantics are a named protocol here, never an implicit one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRef {
    pub domain: EvaluationDomain,
    pub name: ProtocolName,
    pub version: VersionLabel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    /// Execution approval and authorization rules.
    Approval,
    /// Projection allowlist, strata and composition rules.
    Disclosure,
    Budget,
    Retention,
    Signer,
}

/// A named, versioned policy. Changing a policy is a reviewed revision, i.e. a
/// new version, never an in-place edit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub kind: PolicyKind,
    pub domain: EvaluationDomain,
    pub name: PolicyName,
    pub version: Version,
}

/// Binding to one activation record of a policy. `sequence` is the
/// activation's state sequence seen when the binding was made; any later
/// state (revocation, supersession) has a higher sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationRef {
    pub policy: PolicyRef,
    pub activation_id: ActivationId,
    pub sequence: Seq,
}

/// Internal population binding. Never public: it names custody identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PopulationBinding {
    pub domain: EvaluationDomain,
    pub corpus_id: CorpusId,
    pub epoch_id: EpochId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::types::some_only"
    )]
    pub family_id: Option<FamilyId>,
    pub population_digest: PopulationDigest,
    pub custody_version: Version,
}

/// What kind of budget a reservation draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    /// One protected execution attempt.
    Run,
    /// One public release or query of an aggregate.
    ReleaseQuery,
}

/// Budget scope. Two legacy semantics stay distinct (ADR 0003): holdout
/// attempts are per population (and family) epoch; blind attempts are per
/// candidate lineage per epoch. They are different variants, never one counter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum BudgetScope {
    PopulationEpoch {
        corpus_id: CorpusId,
        epoch_id: EpochId,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::types::some_only"
        )]
        family_id: Option<FamilyId>,
    },
    CandidateLineageEpoch {
        corpus_id: CorpusId,
        epoch_id: EpochId,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::types::some_only"
        )]
        family_id: Option<FamilyId>,
        lineage_id: LineageId,
    },
}

impl BudgetScope {
    /// Whether this scope is drawn on the given population.
    pub fn covers(&self, pop: &PopulationBinding) -> bool {
        let (c, e, f) = match self {
            Self::PopulationEpoch {
                corpus_id,
                epoch_id,
                family_id,
            }
            | Self::CandidateLineageEpoch {
                corpus_id,
                epoch_id,
                family_id,
                ..
            } => (corpus_id, epoch_id, family_id),
        };
        *c == pop.corpus_id && *e == pop.epoch_id && *f == pop.family_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountingSettings {
    pub kind: BudgetKind,
    pub budget: BudgetScope,
    /// Budget units requested (at least one).
    pub units: Count<16>,
    /// Retries permitted after a failure. Each retry passes the same checks
    /// and is a new auditable attempt; none is free after exposure.
    pub max_retries: Count<8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu_seconds: Count<86_400>,
    pub wall_seconds: Count<86_400>,
    pub memory_mib: Count<1_048_576>,
    pub storage_mib: Count<1_048_576>,
    pub max_processes: Count<4_096>,
    pub max_output_bytes: Count<1_073_741_824>,
}

/// Seed handling. Seeds are custodian-held and never appear in a contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeedPolicy {
    CustodianHeldFixed,
    CustodianHeldPerAttempt,
}

/// The identities frozen at approval and re-verified before and after
/// execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenIdentities {
    pub domain: EvaluationDomain,
    pub candidate: CandidateDigest,
    pub engine: ArtifactIdentity,
    pub adapter: ArtifactIdentity,
    pub scanners: BoundedVec<ArtifactIdentity, 8>,
    pub config_digest: ConfigDigest,
    pub protocol: ProtocolRef,
    pub population_digest: PopulationDigest,
}

/// Whether protected bytes were acquired. Wire form of `custodian_core::Exposure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExposureState {
    NotExposed,
    Exposed,
}

impl From<Exposure> for ExposureState {
    fn from(e: Exposure) -> Self {
        match e {
            Exposure::NotExposed => Self::NotExposed,
            Exposure::Exposed => Self::Exposed,
        }
    }
}

impl From<ExposureState> for Exposure {
    fn from(e: ExposureState) -> Self {
        match e {
            ExposureState::NotExposed => Self::NotExposed,
            ExposureState::Exposed => Self::Exposed,
        }
    }
}

/// Wire form of `custodian_core::ReasonCode` (fixed vocabulary, no free text).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Requested,
    Authorized,
    AuthorizationDenied,
    PlanMismatch,
    AuthorizationExpired,
    BudgetReserved,
    BudgetExhausted,
    DuplicateRequest,
    CorpusUnavailable,
    ExecutionFailed,
    InvalidArtifact,
    Cancelled,
    Completed,
    ProtectedBytesAcquired,
    InvalidTransition,
    StoreUnavailable,
    DisclosureNotPermitted,
}

impl From<ReasonCode> for Reason {
    fn from(r: ReasonCode) -> Self {
        match r {
            ReasonCode::Requested => Self::Requested,
            ReasonCode::Authorized => Self::Authorized,
            ReasonCode::AuthorizationDenied => Self::AuthorizationDenied,
            ReasonCode::PlanMismatch => Self::PlanMismatch,
            ReasonCode::AuthorizationExpired => Self::AuthorizationExpired,
            ReasonCode::BudgetReserved => Self::BudgetReserved,
            ReasonCode::BudgetExhausted => Self::BudgetExhausted,
            ReasonCode::DuplicateRequest => Self::DuplicateRequest,
            ReasonCode::CorpusUnavailable => Self::CorpusUnavailable,
            ReasonCode::ExecutionFailed => Self::ExecutionFailed,
            ReasonCode::InvalidArtifact => Self::InvalidArtifact,
            ReasonCode::Cancelled => Self::Cancelled,
            ReasonCode::Completed => Self::Completed,
            ReasonCode::ProtectedBytesAcquired => Self::ProtectedBytesAcquired,
            ReasonCode::InvalidTransition => Self::InvalidTransition,
            ReasonCode::StoreUnavailable => Self::StoreUnavailable,
            ReasonCode::DisclosureNotPermitted => Self::DisclosureNotPermitted,
        }
    }
}

/// What kind of principal acted. An agent can propose; it can never approve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Human,
    Service,
    Agent,
}

/// How proposal, execution approval and disclosure approval are separated.
/// Both variants are procedural. There is deliberately no organizational
/// variant: it is not offered until a reviewed schema revision adds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoleSeparation {
    /// One person holds the roles; separation is a procedure, not a control.
    SingleOperatorProcedural,
    /// Distinct principals, still within one organization.
    DistinctPrincipalsProcedural,
}

/// Legacy independence vocabulary, preserved verbatim (ADR 0003). None of
/// these means "independent".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum IndependenceClaim {
    #[serde(rename = "public-control")]
    PublicControl,
    #[serde(rename = "custodian-declared")]
    CustodianDeclared,
    #[serde(rename = "procedural-separation")]
    ProceduralSeparation,
}

/// Organizational independence. The only representable value is `not_claimed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrganisationalIndependence {
    NotClaimed,
}

/// Who authored expectations. `external_*` values are declarations by the
/// custodian operator and are not verified by this system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Authorship {
    ProjectAuthored,
    ExternalAuthoredUnverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    NotReviewed,
    ProjectReviewed,
    ExternalReviewedUnverified,
}

/// Custody and signatures attest origin and binding, never truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GroundTruthClaim {
    NotEstablished,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub independence: IndependenceClaim,
    pub role_separation: RoleSeparation,
    pub organisational_independence: OrganisationalIndependence,
    pub authorship: Authorship,
    pub review: ReviewStatus,
    pub ground_truth: GroundTruthClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

/// Signature over `Contract::signing_input` of the enclosed payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub key_id: KeyId,
    pub algorithm: SignatureAlgorithm,
    pub value: SignatureValue,
}
