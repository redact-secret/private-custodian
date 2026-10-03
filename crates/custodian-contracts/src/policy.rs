//! Policy activation, expiry, revocation and current-state freshness.
//!
//! An approval, a reservation, an execution and a receipt all bind to an
//! `ActivationRef`. Using any of them is allowed only if the policy's
//! *current* activation state, read recently enough, still matches that
//! binding and is active. A prior success never stands in for that check.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::canonical::{Contract, DomainTag};
use crate::common::{ActivationRef, PolicyRef};
use crate::error::{BindingError, ContractError};
use crate::types::{schema_tag, ActivationId, Seq, Timestamp};

schema_tag!(
    /// Schema tag for `PolicyActivation` v1.
    PolicyActivationSchema,
    "private-custodian.policy-activation/1"
);

/// Hard ceiling for how old the observed activation state may be when it is
/// used to authorize something. Callers may require less, never more.
pub const MAX_STATE_AGE_SECS: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    Active,
    Revoked,
    Superseded,
}

/// One state of one activation. State changes append a new record with a
/// higher `sequence`; a record is never edited in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivation {
    pub schema: PolicyActivationSchema,
    pub policy: PolicyRef,
    pub activation_id: ActivationId,
    pub sequence: Seq,
    pub status: ActivationStatus,
    pub activates_at: Timestamp,
    pub expires_at: Timestamp,
    /// When this state (sequence) was recorded.
    pub changed_at: Timestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActivationPhase {
    NotYetActive,
    Active,
    Expired,
    Revoked,
    Superseded,
}

impl Contract for PolicyActivation {
    const DOMAIN: DomainTag = DomainTag::PolicyActivation;

    fn validate(&self) -> Result<(), ContractError> {
        if self.expires_at <= self.activates_at {
            return Err(ContractError::Inconsistent);
        }
        Ok(())
    }
}

impl PolicyActivation {
    /// Phase at `now`. Revocation and supersession win over every time-based
    /// phase, so a revoked activation is never "still within its window".
    pub fn phase_at(&self, now: Timestamp) -> ActivationPhase {
        match self.status {
            ActivationStatus::Revoked => ActivationPhase::Revoked,
            ActivationStatus::Superseded => ActivationPhase::Superseded,
            ActivationStatus::Active if now < self.activates_at => ActivationPhase::NotYetActive,
            ActivationStatus::Active if now >= self.expires_at => ActivationPhase::Expired,
            ActivationStatus::Active => ActivationPhase::Active,
        }
    }
}

/// An activation state together with when the control service read it from
/// the authoritative store. Not a wire type: freshness is judged by the reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedActivation {
    pub activation: PolicyActivation,
    pub observed_at: Timestamp,
}

/// Check a binding against current activation state. Fails closed: an
/// unknown, old, future-dated, mismatched, inactive or since-changed state is
/// a rejection. Use for every approval, reservation, execution start, release
/// and any reuse of a prior receipt.
pub fn check_current(
    binding: &ActivationRef,
    observed: &ObservedActivation,
    now: Timestamp,
    max_state_age_secs: u64,
) -> Result<(), BindingError> {
    let max_age = max_state_age_secs.min(MAX_STATE_AGE_SECS);
    if observed.observed_at > now || now.secs() - observed.observed_at.secs() > max_age {
        return Err(BindingError::StateStale);
    }
    let a = &observed.activation;
    if a.policy != binding.policy || a.activation_id != binding.activation_id {
        return Err(BindingError::ActivationMismatch);
    }
    match a.phase_at(now) {
        ActivationPhase::Revoked => return Err(BindingError::ActivationRevoked),
        ActivationPhase::Superseded => return Err(BindingError::ActivationSuperseded),
        ActivationPhase::NotYetActive => return Err(BindingError::ActivationNotYetActive),
        ActivationPhase::Expired => return Err(BindingError::ActivationExpired),
        ActivationPhase::Active => {}
    }
    if a.sequence > binding.sequence {
        // The state changed after the binding was made even though it is
        // active again or still: the binding is stale.
        return Err(BindingError::ActivationSuperseded);
    }
    if a.sequence < binding.sequence {
        return Err(BindingError::ActivationMismatch);
    }
    Ok(())
}
