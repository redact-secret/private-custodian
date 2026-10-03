//! Fixed reason codes. Nothing in this crate carries free-form text out of a
//! worker: not stderr, not stdout beyond the strictly validated result
//! document, not paths, not engine messages (CONVENTIONS.md, "Execution and
//! logging").

use custodian_core::ReasonCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkerReason {
    /// Completed normally (used only in reports, never as an error).
    Completed,
    // Isolation
    UnsupportedPlatform,
    IsolationUnavailable,
    IsolationCheckFailed,
    IsolationNotVerified,
    VerificationStale,
    // Identity and staging
    PlanInconsistent,
    ArtifactNotAllowlisted,
    ArtifactInvalid,
    IdentityMismatch,
    IdentityChangedAfterStaging,
    IdentityChangedAfterExecution,
    StagingFailed,
    PathRejected,
    // Execution
    SpawnFailed,
    Timeout,
    OutputLimit,
    Signaled,
    NonZeroExit,
    SandboxFailure,
    // Result
    ResultMalformed,
    ResultOversized,
    ResultMismatch,
    RosterMismatch,
    EnginePartial,
    // Control plane
    CorpusUnavailable,
    PopulationMismatch,
    LedgerUnavailable,
    LeaseLost,
    Cancelled,
}

impl WorkerReason {
    /// Stable machine code for logs and audit.
    pub fn code(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::IsolationUnavailable => "isolation_unavailable",
            Self::IsolationCheckFailed => "isolation_check_failed",
            Self::IsolationNotVerified => "isolation_not_verified",
            Self::VerificationStale => "verification_stale",
            Self::PlanInconsistent => "plan_inconsistent",
            Self::ArtifactNotAllowlisted => "artifact_not_allowlisted",
            Self::ArtifactInvalid => "artifact_invalid",
            Self::IdentityMismatch => "identity_mismatch",
            Self::IdentityChangedAfterStaging => "identity_changed_after_staging",
            Self::IdentityChangedAfterExecution => "identity_changed_after_execution",
            Self::StagingFailed => "staging_failed",
            Self::PathRejected => "path_rejected",
            Self::SpawnFailed => "spawn_failed",
            Self::Timeout => "timeout",
            Self::OutputLimit => "output_limit",
            Self::Signaled => "signaled",
            Self::NonZeroExit => "non_zero_exit",
            Self::SandboxFailure => "sandbox_failure",
            Self::ResultMalformed => "result_malformed",
            Self::ResultOversized => "result_oversized",
            Self::ResultMismatch => "result_mismatch",
            Self::RosterMismatch => "roster_mismatch",
            Self::EnginePartial => "engine_partial",
            Self::CorpusUnavailable => "corpus_unavailable",
            Self::PopulationMismatch => "population_mismatch",
            Self::LedgerUnavailable => "ledger_unavailable",
            Self::LeaseLost => "lease_lost",
            Self::Cancelled => "cancelled",
        }
    }

    /// The coarse core reason recorded in the state store.
    pub fn core_reason(self) -> ReasonCode {
        match self {
            Self::Completed => ReasonCode::Completed,
            Self::Cancelled | Self::LeaseLost => ReasonCode::Cancelled,
            Self::IdentityMismatch
            | Self::IdentityChangedAfterStaging
            | Self::IdentityChangedAfterExecution
            | Self::PlanInconsistent
            | Self::PopulationMismatch => ReasonCode::PlanMismatch,
            Self::ResultMalformed
            | Self::ResultOversized
            | Self::ResultMismatch
            | Self::RosterMismatch => ReasonCode::InvalidArtifact,
            Self::CorpusUnavailable => ReasonCode::CorpusUnavailable,
            Self::LedgerUnavailable => ReasonCode::StoreUnavailable,
            _ => ReasonCode::ExecutionFailed,
        }
    }
}

impl core::fmt::Display for WorkerReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for WorkerReason {}

pub type Result<T> = core::result::Result<T, WorkerReason>;
