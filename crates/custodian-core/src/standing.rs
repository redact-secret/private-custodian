//! Epoch standing: the contamination state machine and retirement (C9).
//!
//! A population epoch is sealed and immutable (C5). What can still happen to
//! it is that its use becomes untrustworthy. This module holds the pure rules
//! for that; the store makes them durable and atomic, and
//! `custodian-lifecycle` orchestrates them. No I/O, no dependencies.
//!
//! # States
//!
//! * `Unaffected`: no known problem.
//! * `UnreviewedChange`: the population or its binding may have changed
//!   without a reviewed re-seal (for example an integrity alarm). Blocks use.
//!   The only state a reviewed action may clear.
//! * `Exposed`: protected contents, or per-case detail derived from them, may
//!   have reached a party that must not see them. Permanent.
//! * `UsedForTuning`: a candidate or detector was adjusted using this
//!   population's results. Permanent.
//!
//! Severity is `Unaffected < UnreviewedChange < Exposed < UsedForTuning`. A
//! report can only raise severity or leave it unchanged: it is never a
//! silent downgrade, and a weaker later report cannot hide a stronger earlier
//! one. Retirement is an independent one-way flag. Nothing lowers consumed
//! budget; this module has no notion of budget at all.
//!
//! # What may be cleared
//!
//! Only `UnreviewedChange`, and only by the explicit `Clear` change, which
//! callers must authorize outside this module (reviewed action by a
//! non-agent actor). `Exposed` and `UsedForTuning` are never cleared: the
//! epoch must be retired and replaced by a new reviewed epoch and seal. A
//! retired epoch cannot be cleared either.

/// Contamination state of an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Contamination {
    Unaffected,
    UnreviewedChange,
    Exposed,
    UsedForTuning,
}

impl Contamination {
    pub const ALL: [Contamination; 4] = [
        Self::Unaffected,
        Self::UnreviewedChange,
        Self::Exposed,
        Self::UsedForTuning,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unaffected => "unaffected",
            Self::UnreviewedChange => "unreviewed_change",
            Self::Exposed => "exposed",
            Self::UsedForTuning => "used_for_tuning",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// Evidence from an epoch in this state is invalid for independent
    /// qualification for good: it is never cleared.
    pub fn is_permanent(self) -> bool {
        matches!(self, Self::Exposed | Self::UsedForTuning)
    }

    /// Any state other than `Unaffected` blocks new use of the epoch.
    pub fn blocks_use(self) -> bool {
        self != Self::Unaffected
    }

    /// Only a possibly-benign change can be cleared by a reviewed action.
    pub fn is_clearable(self) -> bool {
        self == Self::UnreviewedChange
    }
}

/// Current standing of one epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EpochStanding {
    pub contamination: Contamination,
    pub retired: bool,
}

impl EpochStanding {
    /// The standing of an epoch nothing has been recorded about.
    pub const CLEAN: Self = Self {
        contamination: Contamination::Unaffected,
        retired: false,
    };

    /// New use (reserve, retry, start, exposure, release) is allowed only
    /// when nothing blocks it.
    pub fn usable(self) -> bool {
        !self.retired && !self.contamination.blocks_use()
    }
}

/// A requested change of standing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EpochChange {
    /// Report a (possibly stronger) contamination. Raises or keeps.
    Report(Contamination),
    /// Reviewed clearance of `UnreviewedChange`.
    Clear,
    /// End the epoch's use for good.
    Retire,
}

impl EpochChange {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Report(_) => "report",
            Self::Clear => "clear",
            Self::Retire => "retire",
        }
    }
}

/// Why a change was refused. Fieldless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StandingRefusal {
    /// `Report(Unaffected)` is not a report.
    NothingToReport,
    /// Clearing something that is not clearable (permanent contamination,
    /// not contaminated at all, or retired).
    NotClearable,
}

/// The result of applying a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    pub prior: EpochStanding,
    pub new: EpochStanding,
}

impl Transition {
    pub fn changed(&self) -> bool {
        self.prior != self.new
    }
}

/// Apply `change` to `current`. The only function that decides a standing
/// transition; the store calls it inside the transaction that persists the
/// result.
pub fn apply(current: EpochStanding, change: EpochChange) -> Result<Transition, StandingRefusal> {
    let new = match change {
        EpochChange::Report(Contamination::Unaffected) => {
            return Err(StandingRefusal::NothingToReport)
        }
        EpochChange::Report(c) => EpochStanding {
            contamination: current.contamination.max(c),
            retired: current.retired,
        },
        EpochChange::Clear => {
            if current.retired || !current.contamination.is_clearable() {
                return Err(StandingRefusal::NotClearable);
            }
            EpochStanding {
                contamination: Contamination::Unaffected,
                retired: false,
            }
        }
        EpochChange::Retire => EpochStanding {
            contamination: current.contamination,
            retired: true,
        },
    };
    Ok(Transition {
        prior: current,
        new,
    })
}

/// What a transition means for evidence already released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceEffect {
    /// Every projection of this epoch's population is contaminated.
    Contaminated,
    /// The epoch ended for a reason other than contamination: its evidence is
    /// revoked (no longer to be relied on for new claims).
    EpochEnded,
}

/// The public consequence of a transition, if any. Contamination wins over
/// retirement; an unreviewed change alone is private (it blocks use but
/// says nothing about results measured on the sealed population); a repeat
/// or a clearance has no new consequence.
pub fn evidence_effect(t: &Transition) -> Option<EvidenceEffect> {
    let newly_permanent = t.new.contamination.is_permanent() && !t.prior.contamination.is_permanent();
    if newly_permanent {
        return Some(EvidenceEffect::Contaminated);
    }
    if t.new.retired && !t.prior.retired && !t.new.contamination.is_permanent() {
        return Some(EvidenceEffect::EpochEnded);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use Contamination::*;

    fn st(c: Contamination, retired: bool) -> EpochStanding {
        EpochStanding {
            contamination: c,
            retired,
        }
    }

    #[test]
    fn reports_only_raise_and_never_downgrade() {
        for from in Contamination::ALL {
            for to in [UnreviewedChange, Exposed, UsedForTuning] {
                let t = apply(st(from, false), EpochChange::Report(to)).unwrap();
                assert_eq!(t.new.contamination, from.max(to));
                assert!(t.new.contamination >= from);
            }
        }
        assert_eq!(
            apply(st(Exposed, false), EpochChange::Report(UnreviewedChange))
                .unwrap()
                .new
                .contamination,
            Exposed
        );
        assert_eq!(
            apply(st(UsedForTuning, false), EpochChange::Report(Exposed))
                .unwrap()
                .new
                .contamination,
            UsedForTuning
        );
        assert_eq!(
            apply(st(Unaffected, false), EpochChange::Report(Unaffected)),
            Err(StandingRefusal::NothingToReport)
        );
    }

    #[test]
    fn only_an_unretired_unreviewed_change_clears() {
        assert_eq!(
            apply(st(UnreviewedChange, false), EpochChange::Clear)
                .unwrap()
                .new,
            EpochStanding::CLEAN
        );
        for (c, r) in [
            (Unaffected, false),
            (Exposed, false),
            (UsedForTuning, false),
            (UnreviewedChange, true),
            (Exposed, true),
        ] {
            assert_eq!(
                apply(st(c, r), EpochChange::Clear),
                Err(StandingRefusal::NotClearable),
                "{c:?} retired={r}"
            );
        }
    }

    #[test]
    fn retirement_is_one_way_and_keeps_contamination() {
        let t = apply(st(Exposed, false), EpochChange::Retire).unwrap();
        assert_eq!(t.new, st(Exposed, true));
        let again = apply(t.new, EpochChange::Retire).unwrap();
        assert!(!again.changed());
        // No change can un-retire.
        for c in [
            EpochChange::Report(Exposed),
            EpochChange::Retire,
            EpochChange::Report(UnreviewedChange),
        ] {
            assert!(apply(t.new, c).unwrap().new.retired);
        }
    }

    #[test]
    fn usable_requires_clean_and_not_retired() {
        assert!(EpochStanding::CLEAN.usable());
        assert!(!st(UnreviewedChange, false).usable());
        assert!(!st(Unaffected, true).usable());
    }

    #[test]
    fn evidence_effects_follow_the_transition() {
        let eff = |from, change| evidence_effect(&apply(from, change).unwrap());
        assert_eq!(
            eff(EpochStanding::CLEAN, EpochChange::Report(Exposed)),
            Some(EvidenceEffect::Contaminated)
        );
        assert_eq!(
            eff(st(Exposed, false), EpochChange::Report(UsedForTuning)),
            None
        );
        assert_eq!(
            eff(EpochStanding::CLEAN, EpochChange::Report(UnreviewedChange)),
            None
        );
        assert_eq!(
            eff(st(UnreviewedChange, false), EpochChange::Report(Exposed)),
            Some(EvidenceEffect::Contaminated)
        );
        assert_eq!(
            eff(EpochStanding::CLEAN, EpochChange::Retire),
            Some(EvidenceEffect::EpochEnded)
        );
        assert_eq!(eff(st(Exposed, false), EpochChange::Retire), None);
        assert_eq!(eff(st(UnreviewedChange, false), EpochChange::Clear), None);
    }
}
