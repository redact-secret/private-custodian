//! Fixed intake reason codes.
//!
//! Every refusal at the request edge is one of these fieldless variants. None
//! carries input text, so a hostile payload, header, token or path cannot
//! travel through an error, a log line, an HTTP body or a Check update.
//! `to_core` maps each onto the closed `custodian_core::ReasonCode` vocabulary
//! used by the control service; the finer intake distinction stays here so the
//! shared core enum is not widened by the edge adapter.

use core::fmt;

use custodian_core::ReasonCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IntakeReason {
    // Authenticity and shape.
    BodyTooLarge,
    SignatureInvalid,
    ContentTypeInvalid,
    DeliveryIdInvalid,
    PayloadMalformed,
    // Replay and state.
    DeliveryReplay,
    StoreUnavailable,
    QueueUnavailable,
    // Event policy.
    EventNotAllowed,
    ActionNotAllowed,
    CommentTriggerDenied,
    WorkflowTriggerDenied,
    // Scope.
    InstallationNotAllowed,
    InstallationRemoved,
    RepositoryNotAllowed,
    RepositoryRemoved,
    ForkDenied,
    CrossRepositoryDenied,
    // Actor.
    ActorNotAuthorized,
    ActorKindDenied,
    ActorMismatch,
    ApproverNotAuthorized,
    // Binding.
    RequestInvalid,
    StaleCommit,
    CandidateMismatch,
    ConfigMismatch,
    ApprovalRequired,
    ApprovalNotBound,
    ApprovalExpired,
    ActivationNotCurrent,
    // App authentication and Checks.
    AppAuthFailed,
    TokenUnavailable,
    PermissionsExceeded,
    CheckUpdateFailed,
    // Deployment.
    CredentialBoundaryViolation,
}

impl IntakeReason {
    /// Stable machine-readable code. Lowercase ASCII and underscores only.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body_too_large",
            Self::SignatureInvalid => "signature_invalid",
            Self::ContentTypeInvalid => "content_type_invalid",
            Self::DeliveryIdInvalid => "delivery_id_invalid",
            Self::PayloadMalformed => "payload_malformed",
            Self::DeliveryReplay => "delivery_replay",
            Self::StoreUnavailable => "store_unavailable",
            Self::QueueUnavailable => "queue_unavailable",
            Self::EventNotAllowed => "event_not_allowed",
            Self::ActionNotAllowed => "action_not_allowed",
            Self::CommentTriggerDenied => "comment_trigger_denied",
            Self::WorkflowTriggerDenied => "workflow_trigger_denied",
            Self::InstallationNotAllowed => "installation_not_allowed",
            Self::InstallationRemoved => "installation_removed",
            Self::RepositoryNotAllowed => "repository_not_allowed",
            Self::RepositoryRemoved => "repository_removed",
            Self::ForkDenied => "fork_denied",
            Self::CrossRepositoryDenied => "cross_repository_denied",
            Self::ActorNotAuthorized => "actor_not_authorized",
            Self::ActorKindDenied => "actor_kind_denied",
            Self::ActorMismatch => "actor_mismatch",
            Self::ApproverNotAuthorized => "approver_not_authorized",
            Self::RequestInvalid => "request_invalid",
            Self::StaleCommit => "stale_commit",
            Self::CandidateMismatch => "candidate_mismatch",
            Self::ConfigMismatch => "config_mismatch",
            Self::ApprovalRequired => "approval_required",
            Self::ApprovalNotBound => "approval_not_bound",
            Self::ApprovalExpired => "approval_expired",
            Self::ActivationNotCurrent => "activation_not_current",
            Self::AppAuthFailed => "app_auth_failed",
            Self::TokenUnavailable => "token_unavailable",
            Self::PermissionsExceeded => "permissions_exceeded",
            Self::CheckUpdateFailed => "check_update_failed",
            Self::CredentialBoundaryViolation => "credential_boundary_violation",
        }
    }

    /// Every variant, for exhaustive tests of the fixed vocabulary.
    pub const ALL: [IntakeReason; 35] = [
        Self::BodyTooLarge,
        Self::SignatureInvalid,
        Self::ContentTypeInvalid,
        Self::DeliveryIdInvalid,
        Self::PayloadMalformed,
        Self::DeliveryReplay,
        Self::StoreUnavailable,
        Self::QueueUnavailable,
        Self::EventNotAllowed,
        Self::ActionNotAllowed,
        Self::CommentTriggerDenied,
        Self::WorkflowTriggerDenied,
        Self::InstallationNotAllowed,
        Self::InstallationRemoved,
        Self::RepositoryNotAllowed,
        Self::RepositoryRemoved,
        Self::ForkDenied,
        Self::CrossRepositoryDenied,
        Self::ActorNotAuthorized,
        Self::ActorKindDenied,
        Self::ActorMismatch,
        Self::ApproverNotAuthorized,
        Self::RequestInvalid,
        Self::StaleCommit,
        Self::CandidateMismatch,
        Self::ConfigMismatch,
        Self::ApprovalRequired,
        Self::ApprovalNotBound,
        Self::ApprovalExpired,
        Self::ActivationNotCurrent,
        Self::AppAuthFailed,
        Self::TokenUnavailable,
        Self::PermissionsExceeded,
        Self::CheckUpdateFailed,
        Self::CredentialBoundaryViolation,
    ];

    /// The control-plane reason code this refusal is recorded under.
    pub fn to_core(self) -> ReasonCode {
        match self {
            Self::DeliveryReplay => ReasonCode::DuplicateRequest,
            Self::StoreUnavailable | Self::QueueUnavailable => ReasonCode::StoreUnavailable,
            Self::StaleCommit
            | Self::CandidateMismatch
            | Self::ConfigMismatch
            | Self::ApprovalNotBound
            | Self::RequestInvalid => ReasonCode::PlanMismatch,
            Self::ApprovalExpired | Self::ActivationNotCurrent => ReasonCode::AuthorizationExpired,
            _ => ReasonCode::AuthorizationDenied,
        }
    }

    /// HTTP status for the webhook response. The body is only `as_str`.
    pub fn http_status(self) -> u16 {
        match self {
            Self::BodyTooLarge => 413,
            Self::ContentTypeInvalid => 415,
            Self::SignatureInvalid => 401,
            Self::DeliveryIdInvalid | Self::PayloadMalformed | Self::RequestInvalid => 400,
            Self::DeliveryReplay => 409,
            Self::StoreUnavailable | Self::QueueUnavailable | Self::TokenUnavailable => 503,
            Self::AppAuthFailed | Self::CheckUpdateFailed => 502,
            _ => 403,
        }
    }
}

impl fmt::Display for IntakeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for IntakeReason {}

/// A deployment configuration was rejected. Fixed vocabulary, no values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigError {
    Malformed,
    NoInstallations,
    NoRepositories,
    NoActors,
    NoEvents,
    Duplicate,
    UnsupportedEvent,
    ActorRoleMissing,
    BodyLimitOutOfRange,
    SecretTooShort,
    IdentifierRejected,
}

impl ConfigError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "config_malformed",
            Self::NoInstallations => "config_no_installations",
            Self::NoRepositories => "config_no_repositories",
            Self::NoActors => "config_no_actors",
            Self::NoEvents => "config_no_events",
            Self::Duplicate => "config_duplicate",
            Self::UnsupportedEvent => "config_unsupported_event",
            Self::ActorRoleMissing => "config_actor_role_missing",
            Self::BodyLimitOutOfRange => "config_body_limit_out_of_range",
            Self::SecretTooShort => "config_secret_too_short",
            Self::IdentifierRejected => "config_identifier_rejected",
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ConfigError {}
