//! Run and disclosure lifecycles, exposure tracking and refund policy.

/// Run lifecycle. Mirrors ARCHITECTURE.md "Lifecycle".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunState {
    Proposed,
    Authorized,
    Reserved,
    Running,
    Validating,
    Completed,
    Denied,
    Failed,
    Cancelled,
    Expired,
}

impl RunState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Denied | Self::Failed | Self::Cancelled | Self::Expired
        )
    }

    /// Whether `self -> next` is an allowed transition. Everything else is
    /// rejected (fail closed).
    pub fn can_transition(self, next: Self) -> bool {
        use RunState::*;
        matches!(
            (self, next),
            (Proposed, Authorized)
                | (Proposed, Denied)
                | (Authorized, Reserved)
                | (Authorized, Denied)
                | (Authorized, Expired)
                | (Reserved, Running)
                | (Reserved, Cancelled)
                | (Reserved, Expired)
                | (Reserved, Failed)
                | (Running, Validating)
                | (Running, Failed)
                | (Running, Cancelled)
                | (Validating, Completed)
                | (Validating, Failed)
        )
    }
}

/// Disclosure lifecycle, separate from the run lifecycle. Completing a run
/// does not authorize release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DisclosureState {
    Prepared,
    Approved,
    Released,
    Withheld,
    Rejected,
}

impl DisclosureState {
    pub fn can_transition(self, next: Self) -> bool {
        use DisclosureState::*;
        matches!(
            (self, next),
            (Prepared, Approved)
                | (Prepared, Withheld)
                | (Prepared, Rejected)
                | (Approved, Released)
                | (Approved, Withheld)
        )
    }
}

/// Whether protected bytes were acquired by the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exposure {
    NotExposed,
    Exposed,
}

/// Fixed reason codes. Logs and errors carry these instead of free-form text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReasonCode {
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

/// Refund policy for a reserved budget unit: only a run that never acquired
/// protected bytes may be refunded. Once exposed, a crash, failure or
/// cancellation consumes the unit; idempotency does not make a new exposure
/// free. Store adapters must apply this function, not their own rule.
pub fn budget_refundable(exposure: Exposure, terminal: RunState) -> bool {
    exposure == Exposure::NotExposed
        && matches!(
            terminal,
            RunState::Failed | RunState::Cancelled | RunState::Expired
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [RunState; 10] = [
        RunState::Proposed,
        RunState::Authorized,
        RunState::Reserved,
        RunState::Running,
        RunState::Validating,
        RunState::Completed,
        RunState::Denied,
        RunState::Failed,
        RunState::Cancelled,
        RunState::Expired,
    ];

    #[test]
    fn terminal_states_have_no_outgoing_transitions() {
        for from in ALL.iter().copied().filter(|s| s.is_terminal()) {
            for to in ALL {
                assert!(!from.can_transition(to), "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn cannot_skip_reservation_before_running() {
        assert!(!RunState::Authorized.can_transition(RunState::Running));
        assert!(!RunState::Proposed.can_transition(RunState::Reserved));
    }

    #[test]
    fn completion_requires_validation() {
        assert!(!RunState::Running.can_transition(RunState::Completed));
        assert!(RunState::Validating.can_transition(RunState::Completed));
    }

    #[test]
    fn release_requires_approval() {
        assert!(!DisclosureState::Prepared.can_transition(DisclosureState::Released));
        assert!(DisclosureState::Approved.can_transition(DisclosureState::Released));
    }

    #[test]
    fn exposure_blocks_refund() {
        for t in [RunState::Failed, RunState::Cancelled, RunState::Expired] {
            assert!(budget_refundable(Exposure::NotExposed, t));
            assert!(!budget_refundable(Exposure::Exposed, t));
        }
        assert!(!budget_refundable(
            Exposure::NotExposed,
            RunState::Completed
        ));
    }
}
