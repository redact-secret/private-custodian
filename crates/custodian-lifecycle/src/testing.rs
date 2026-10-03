//! Synthetic doubles for the lifecycle ports. Used by this crate's tests and
//! available to downstream tests (C10, C11). None of them is a control.

use std::collections::BTreeSet;

use custodian_contracts::common::ActivationRef;
use custodian_contracts::policy::ObservedActivation;

use crate::authority::{OperatorAction, OperatorAuthority, OperatorAuthorization};
use crate::eligibility::ActivationSource;

/// Permits exactly the listed `(actor, action)` pairs. The kind rules in
/// `authorize` still apply on top, as they do for every authority.
#[derive(Default)]
pub struct StaticAuthority {
    allowed: BTreeSet<(String, &'static str)>,
}

impl StaticAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(mut self, actor: &str, action: OperatorAction) -> Self {
        self.allowed.insert((actor.to_owned(), action.code()));
        self
    }

    /// Permit the actor for every action (a lenient authority, to show the
    /// kind rules hold regardless).
    pub fn allow_all(mut self, actor: &str) -> Self {
        for a in OperatorAction::ALL {
            self.allowed.insert((actor.to_owned(), a.code()));
        }
        self
    }
}

impl OperatorAuthority for StaticAuthority {
    fn permits(&self, who: &OperatorAuthorization, action: OperatorAction) -> bool {
        self.allowed
            .contains(&(who.actor.as_str().to_owned(), action.code()))
    }
}

/// Always observes the same state (or nothing).
pub struct FixedActivations(pub Option<ObservedActivation>);

impl ActivationSource for FixedActivations {
    fn observe(&self, _: &ActivationRef) -> Option<ObservedActivation> {
        self.0.clone()
    }
}
