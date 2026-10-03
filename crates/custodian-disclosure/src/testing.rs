//! Synthetic doubles for the disclosure ports. Used by this crate's tests and
//! available to downstream tests (C9, C11). None of them is a control.

use std::sync::Mutex;

use custodian_contracts::common::PopulationBinding;
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::types::Timestamp;

use crate::ports::{
    EligibilityRefusal, EligibilitySubject, PublicPopulationNames, ReleaseEligibility, Sink,
};
use crate::reason::DisclosureReason;
use crate::released::ReleasedEnvelope;

/// Checks nothing. For tests that are not about eligibility. A deployment
/// passing this would release evidence that was revoked or contaminated; C9
/// supplies the real implementation.
pub struct UncheckedEligibility;

impl ReleaseEligibility for UncheckedEligibility {
    fn check(&self, _: &EligibilitySubject<'_>, _: Timestamp) -> Result<(), EligibilityRefusal> {
        Ok(())
    }
}

/// Always answers the same way.
pub struct FixedEligibility(pub Result<(), EligibilityRefusal>);

impl ReleaseEligibility for FixedEligibility {
    fn check(&self, _: &EligibilitySubject<'_>, _: Timestamp) -> Result<(), EligibilityRefusal> {
        self.0
    }
}

/// One public reference for every population.
pub struct StaticNames(pub PublicPopulationRef);

impl PublicPopulationNames for StaticNames {
    fn public_ref(&self, _: &PopulationBinding) -> Option<PublicPopulationRef> {
        Some(self.0.clone())
    }
}

/// Records the canonical bytes of every delivered envelope.
#[derive(Default)]
pub struct RecordingSink {
    delivered: Mutex<Vec<(String, Vec<u8>)>>,
    fail: bool,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn failing() -> Self {
        Self {
            delivered: Mutex::new(Vec::new()),
            fail: true,
        }
    }

    /// `(destination label, canonical envelope bytes)` per delivery.
    pub fn delivered(&self) -> Vec<(String, Vec<u8>)> {
        self.delivered.lock().map(|d| d.clone()).unwrap_or_default()
    }
}

impl Sink for RecordingSink {
    fn deliver(&self, released: &ReleasedEnvelope) -> Result<(), DisclosureReason> {
        if self.fail {
            return Err(DisclosureReason::DeliveryFailed);
        }
        let bytes = released.to_bytes()?;
        self.delivered
            .lock()
            .map_err(|_| DisclosureReason::DeliveryFailed)?
            .push((released.destination().as_str().to_owned(), bytes));
        Ok(())
    }
}
