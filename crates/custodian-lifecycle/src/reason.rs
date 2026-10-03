//! Fixed reason codes. No variant carries a path, a name, a digest or free
//! text, so a refusal can be logged, returned or rendered in a Check without
//! leaking a population, a candidate or a case.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecycleReason {
    /// The authority did not permit this actor to perform this action.
    Unauthorized,
    /// An agent attempted an operator-only action.
    AgentNotPermitted,
    /// The epoch is not in the registry.
    UnknownEpoch,
    /// The epoch's corpus, family or domain does not match the request.
    EpochMismatch,
    /// Clearing something that is not clearable (permanent contamination,
    /// not contaminated, or retired).
    NotClearable,
    /// The reported kind is not a contamination, or the reason does not fit
    /// the kind or the change.
    InvalidChange,
    /// A rotation precondition failed (successor not sealed or not distinct,
    /// budget scope for another epoch, ...).
    RotationInvalid,
    /// Input outside the allowed shape.
    InvalidInput,
    /// An idempotency key was reused for a different change.
    IdempotencyConflict,
    /// The store is unreachable, busy or refused.
    StoreUnavailable,
    /// The registry is unreachable or invalid.
    RegistryUnavailable,
    /// Another publisher won the sequence; nothing was written.
    FeedConflict,
    /// The feed has no envelope yet.
    FeedNotInitialized,
    /// Revocation obligations are recorded but not yet in a published
    /// envelope, so a feed reference would not cover them.
    PendingObligations,
    /// An obligation cannot be translated to a public target.
    Unpublishable,
    /// The clock went backwards relative to the feed head.
    ClockSkew,
    SigningRefused,
    SignerUnavailable,
    /// The public destination refused or failed the write.
    DestinationUnavailable,
    /// The destination already holds different bytes for that sequence.
    DestinationConflict,
    /// A deliberately injected crash (tests only).
    InjectedCrash,
}

impl LifecycleReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::AgentNotPermitted => "agent_not_permitted",
            Self::UnknownEpoch => "unknown_epoch",
            Self::EpochMismatch => "epoch_mismatch",
            Self::NotClearable => "not_clearable",
            Self::InvalidChange => "invalid_change",
            Self::RotationInvalid => "rotation_invalid",
            Self::InvalidInput => "invalid_input",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::StoreUnavailable => "store_unavailable",
            Self::RegistryUnavailable => "registry_unavailable",
            Self::FeedConflict => "feed_conflict",
            Self::FeedNotInitialized => "feed_not_initialized",
            Self::PendingObligations => "pending_obligations",
            Self::Unpublishable => "unpublishable",
            Self::ClockSkew => "clock_skew",
            Self::SigningRefused => "signing_refused",
            Self::SignerUnavailable => "signer_unavailable",
            Self::DestinationUnavailable => "destination_unavailable",
            Self::DestinationConflict => "destination_conflict",
            Self::InjectedCrash => "injected_crash",
        }
    }
}

impl core::fmt::Display for LifecycleReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for LifecycleReason {}

pub type Result<T> = core::result::Result<T, LifecycleReason>;

pub(crate) fn from_store(e: custodian_store::StoreError) -> LifecycleReason {
    use custodian_store::StoreError as S;
    match e {
        S::IdempotencyConflict | S::IdentityConflict => LifecycleReason::IdempotencyConflict,
        S::InvalidTransition => LifecycleReason::NotClearable,
        S::InvalidInput => LifecycleReason::InvalidInput,
        S::Conflict => LifecycleReason::FeedConflict,
        S::InjectedCrash(_) => LifecycleReason::InjectedCrash,
        _ => LifecycleReason::StoreUnavailable,
    }
}
