//! Run the reference consumer over a parsed bundle.
//!
//! The request the response must answer is rebuilt here from the caller's own
//! expectations and pins, never read from the bundle, so a bundle cannot
//! choose what it is judged against.

use custodian_bridge::{BridgeConsumer, ConsumerPins};
use custodian_contracts::types::Timestamp;
use custodian_ledger::Verifier;

use crate::input::{Bundle, Expectations, InputError, Pins};
use crate::report::{ProjectionRejection, Report};

/// Verify `bundle` against `pins` and `expect` at `now` (Unix seconds).
pub fn verify(pins: &Pins, expect: &Expectations, bundle: &Bundle, now: u64) -> Report {
    let Ok(at) = Timestamp::new(now) else {
        return Report::input_error(InputError::Usage, Some(now));
    };
    let mut consumer = BridgeConsumer::new(ConsumerPins {
        domain: expect.domain,
        feed_id: pins.feed_id.clone(),
        destination: expect.destination.clone(),
        verifier: Verifier::new(pins.keyring.clone()),
        accepted_populations: expect.populations.clone(),
        accepted_policies: expect.policies.clone(),
    });
    let Ok(request) = consumer.request(
        expect.candidate.clone(),
        expect.config.clone(),
        expect.populations.clone(),
    ) else {
        return Report::input_error(InputError::ExpectationsInvalid, Some(now));
    };
    match consumer.accept_response(&request, &bundle.response, at) {
        Err(rejection) => Report::response_rejected(rejection.code(), now),
        Ok(outcome) => Report::judged(
            outcome.accepted.len(),
            outcome
                .rejected
                .iter()
                .map(|(index, r)| ProjectionRejection {
                    index: *index,
                    reason: r.code(),
                })
                .collect(),
            outcome.feed_applied,
            outcome.feed_error.map(|e| e.code()),
            consumer.known_sequence(),
            now,
        ),
    }
}
