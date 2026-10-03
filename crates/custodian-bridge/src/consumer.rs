//! The reference consumer: what benchmarks (or any downstream) does with a
//! bridge response, using public inputs only.
//!
//! # What this module can see
//!
//! * pinned public verification keys (a [`Verifier`], which holds no secret),
//! * the pinned feed identity, destination label and evaluation domain,
//! * the product's own pins: which public populations and which disclosure
//!   policy versions it is willing to rely on,
//! * the bytes of a response, and the clock.
//!
//! It has no import of a store, a ledger backend, a ledger record, a signer, a
//! protected population or a corpus, and `tests/no_private_access.rs` checks
//! both the imports and the function types.
//!
//! # Destination binding (ADR 0119, 0121)
//!
//! A public projection v2 carries its destination inside the signed payload,
//! so this consumer verifies the binding from the envelope alone: a v2
//! projection whose signed destination differs from the pinned one is
//! rejected as `destination_mismatch`. A v1 projection has no destination.
//! It still verifies (v1 stays decodable and verifiable) but is reported as
//! [`VerificationOutcome::DestinationUnbound`] and never as bound, and a
//! consumer that calls [`BridgeConsumer::require_destination_binding`]
//! rejects it as `destination_unbound`. The manifest destination label stays
//! an unsigned routing hint; it proves nothing for either major.
//!
//! # What it does not decide
//!
//! Whether a verified, still valid projection is good enough for a support
//! claim, a release or a page is product policy and stays with the consumer.
//! The public review ledger is product adjudication; it is not the private
//! audit export and nothing here reads or writes it.

use std::collections::BTreeSet;

use custodian_contracts::common::{Attestation, EvaluationDomain, PolicyRef};
use custodian_contracts::public::{PublicPopulationRef, PublicProjection};
use custodian_contracts::public_v2::{AnyProjectionEnvelope, DestinationBinding};
use custodian_contracts::revocation::Standing;
use custodian_contracts::types::{
    BoundedVec, CandidateDigest, ConfigDigest, DestinationId, FeedId, ProjectionDigest, Seq,
    Timestamp,
};
use custodian_ledger::{Verifier, VerifyError};
use custodian_lifecycle::{FeedConsumer, StandingChange, SyncError};

use crate::reason::Rejection;
use crate::wire::{
    BridgeManifest, BridgeRequest, BridgeRequestSchema, BridgeResponse, MAX_DOCUMENT_BYTES,
};

/// Everything the consumer is configured with, out of band. Nothing here is
/// taken from a response.
#[derive(Clone, Debug)]
pub struct ConsumerPins {
    pub domain: EvaluationDomain,
    pub feed_id: FeedId,
    /// The channel label benchmarks expects its answers to be prepared for.
    pub destination: DestinationId,
    /// Public keys and their authorized domains. No secret.
    pub verifier: Verifier,
    /// Public populations the product relies on. Empty accepts nothing.
    pub accepted_populations: Vec<PublicPopulationRef>,
    /// Disclosure policy versions the product accepts. Empty accepts nothing.
    pub accepted_policies: Vec<PolicyRef>,
}

/// What a successful verification established about the destination. A
/// distinct outcome, so a v1 projection is never mistaken for a bound one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerificationOutcome {
    /// v2: the signed destination equals the pinned destination.
    DestinationBound,
    /// v1: authentic and unchanged, but it carries no destination, so the
    /// destination cannot be verified from it (code `destination_unbound`).
    DestinationUnbound,
}

impl VerificationOutcome {
    pub fn code(self) -> &'static str {
        match self {
            Self::DestinationBound => "destination_bound",
            Self::DestinationUnbound => DestinationBinding::UNBOUND_CODE,
        }
    }
}

/// A projection that passed every check at the time given. It cannot be
/// constructed outside this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProjection {
    projection: PublicProjection,
    digest: ProjectionDigest,
    verified_at: Timestamp,
    major: u32,
    destination: Option<DestinationId>,
}

impl VerifiedProjection {
    /// The version-neutral projection fields in the v1 shape (cells,
    /// population, candidate, policy, attestation, freshness, feed). For a v2
    /// projection this is a derived view: its schema tag is the v1 tag and
    /// its digest is not the signed one. Use [`Self::digest`],
    /// [`Self::major`] and [`Self::destination`] for what was signed.
    pub fn projection(&self) -> &PublicProjection {
        &self.projection
    }
    /// The projection major that was verified (1 or 2).
    pub fn major(&self) -> u32 {
        self.major
    }
    /// The signed destination; `None` for v1, which has none.
    pub fn destination(&self) -> Option<&DestinationId> {
        self.destination.as_ref()
    }
    pub fn binding(&self) -> DestinationBinding {
        if self.destination.is_some() {
            DestinationBinding::Bound
        } else {
            DestinationBinding::Unbound
        }
    }
    /// `DestinationBound` only for v2; v1 is `DestinationUnbound`.
    pub fn outcome(&self) -> VerificationOutcome {
        match self.binding() {
            DestinationBinding::Bound => VerificationOutcome::DestinationBound,
            DestinationBinding::Unbound => VerificationOutcome::DestinationUnbound,
        }
    }
    pub fn digest(&self) -> &ProjectionDigest {
        &self.digest
    }
    pub fn verified_at(&self) -> Timestamp {
        self.verified_at
    }
    /// The attestation exactly as released: legacy independence vocabulary
    /// intact, organizational independence not claimed, ground truth not
    /// established.
    pub fn attestation(&self) -> &Attestation {
        &self.projection.attestation
    }
}

/// The result of one response. Rejections are per projection; the feed part
/// has its own outcome. Nothing here is a support decision.
#[derive(Debug, PartialEq, Eq)]
pub struct ResponseOutcome {
    pub accepted: Vec<VerifiedProjection>,
    /// Index into the response's projections, and why.
    pub rejected: Vec<(usize, Rejection)>,
    /// How many new feed envelopes were applied, and the first feed error (the
    /// feed part stops at it).
    pub feed_applied: usize,
    pub feed_error: Option<SyncError>,
}

/// The consumer. Its methods take bytes, requests, pins and a timestamp, and
/// nothing from the private side; a private-ledger record is not accepted
/// where bytes are expected:
///
/// ```compile_fail
/// use custodian_bridge::{BridgeConsumer, BridgeRequest};
/// use custodian_contracts::types::Timestamp;
/// use custodian_ledger::SignedLedgerRecord;
///
/// fn feed_it_a_ledger_record(
///     c: &BridgeConsumer,
///     r: &BridgeRequest,
///     record: &SignedLedgerRecord,
///     now: Timestamp,
/// ) {
///     let _ = c.verify_projection(r, record, now);
/// }
/// ```
pub struct BridgeConsumer {
    pins: ConsumerPins,
    feed: FeedConsumer,
    require_binding: bool,
}

impl BridgeConsumer {
    pub fn new(pins: ConsumerPins) -> Self {
        let feed = FeedConsumer::new(pins.feed_id.clone(), pins.verifier.clone());
        Self {
            pins,
            feed,
            require_binding: false,
        }
    }

    /// Reject v1 projections (no destination in the signed payload) as
    /// `destination_unbound` instead of accepting them with the
    /// [`VerificationOutcome::DestinationUnbound`] label. Recommended once
    /// the custodian issues v2.
    pub fn require_destination_binding(mut self) -> Self {
        self.require_binding = true;
        self
    }

    pub fn pins(&self) -> &ConsumerPins {
        &self.pins
    }

    /// The last feed sequence verified so far.
    pub fn known_sequence(&self) -> u64 {
        self.feed.sequence()
    }

    /// Build the request for a frozen candidate and configuration, from the
    /// pins and the feed state held.
    pub fn request(
        &self,
        candidate: CandidateDigest,
        config: ConfigDigest,
        populations: Vec<PublicPopulationRef>,
    ) -> Result<BridgeRequest, Rejection> {
        let req = BridgeRequest {
            schema: BridgeRequestSchema,
            domain: self.pins.domain,
            candidate,
            config,
            feed_id: self.pins.feed_id.clone(),
            known_sequence: Seq::new(self.feed.sequence()).map_err(|_| Rejection::Malformed)?,
            populations: BoundedVec::new(populations).map_err(|_| Rejection::Malformed)?,
        };
        req.validate().map_err(|_| Rejection::Malformed)?;
        Ok(req)
    }

    /// Verify one projection envelope (canonical bytes) against `request` and
    /// the pins, at `now`, using the feed state held. Each step fails closed:
    ///
    /// 1. size bound, strict closed schema of exactly major 1 or 2 (chosen by
    ///    the payload's schema tag, never merged), canonical form (an unsigned
    ///    envelope has no signature field and is malformed);
    /// 2. signature under a pinned key authorized for that major's
    ///    projection domain (a v1 signature never verifies a v2 body or the
    ///    reverse), then the destination: v2 must carry the pinned
    ///    destination (`destination_mismatch`); v1 carries none and is
    ///    accepted as `DestinationUnbound`, or rejected as
    ///    `destination_unbound` when binding is required;
    /// 3. evaluation domain equals the pinned and requested domain;
    /// 4. candidate equals the requested candidate;
    /// 5. population is in the request filter (if any) and in the product pins;
    /// 6. disclosure policy is one the product accepts;
    /// 7. the projection points at the pinned feed;
    /// 8. standing at `now` is `Valid` (revocation, contamination,
    ///    supersession, feed freshness and minimum sequence, own freshness).
    pub fn verify_projection(
        &self,
        request: &BridgeRequest,
        bytes: &[u8],
        now: Timestamp,
    ) -> Result<VerifiedProjection, Rejection> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(Rejection::Malformed);
        }
        let env = AnyProjectionEnvelope::decode(bytes).map_err(|_| Rejection::Malformed)?;
        if env.canonical_bytes().map_err(|_| Rejection::Malformed)? != bytes {
            return Err(Rejection::Malformed);
        }
        self.pins
            .verifier
            .verify_any_projection(&env)
            .map_err(|e| match e {
                VerifyError::BadSignature | VerifyError::MalformedSignature => {
                    Rejection::BadSignature
                }
                VerifyError::PayloadInvalid => Rejection::Malformed,
                VerifyError::UnsupportedAlgorithm
                | VerifyError::UnknownKey
                | VerifyError::KeyRevoked
                | VerifyError::KeyNotValidAtTime
                | VerifyError::WrongDomain => Rejection::KeyNotAcceptable,
            })?;
        match env.destination() {
            Some(signed) if *signed != self.pins.destination => {
                return Err(Rejection::DestinationMismatch);
            }
            None if self.require_binding => return Err(Rejection::DestinationUnbound),
            _ => {}
        }
        let p = env.common_fields();
        if p.domain != self.pins.domain || p.domain != request.domain {
            return Err(Rejection::WrongDomain);
        }
        if p.candidate != request.candidate {
            return Err(Rejection::WrongCandidate);
        }
        if !(request.populations.is_empty()
            || request.populations.as_slice().contains(&p.population))
            || !self.pins.accepted_populations.contains(&p.population)
        {
            return Err(Rejection::WrongPopulation);
        }
        if !self.pins.accepted_policies.contains(&p.disclosure_policy) {
            return Err(Rejection::PolicyNotAccepted);
        }
        if p.revocation_feed.feed_id != self.pins.feed_id {
            return Err(Rejection::WrongFeed);
        }
        match self.feed.standing(&p, now) {
            Standing::Valid => {}
            Standing::Expired => return Err(Rejection::Expired),
            Standing::Stale => return Err(Rejection::Stale),
            Standing::Superseded => return Err(Rejection::Superseded),
            Standing::Revoked => return Err(Rejection::Revoked),
        }
        let digest = env.projection_digest().map_err(|_| Rejection::Malformed)?;
        Ok(VerifiedProjection {
            projection: p,
            digest,
            verified_at: now,
            major: env.major(),
            destination: env.destination().cloned(),
        })
    }

    /// Process a whole response: route it to the request, apply the feed
    /// updates in order (stopping at the first failure), then verify each
    /// projection against the feed state now held. Accepted projections are
    /// tracked for [`Self::reevaluate`].
    pub fn accept_response(
        &mut self,
        request: &BridgeRequest,
        response: &BridgeResponse,
        now: Timestamp,
    ) -> Result<ResponseOutcome, Rejection> {
        response.check_bounds().map_err(|_| Rejection::Malformed)?;
        let manifest: &BridgeManifest = &response.manifest;
        let digest = request.digest().map_err(|_| Rejection::Malformed)?;
        if manifest.request_digest != digest || request.feed_id != self.pins.feed_id {
            return Err(Rejection::WrongRequest);
        }
        if manifest.feed_id != self.pins.feed_id {
            return Err(Rejection::WrongFeed);
        }
        if manifest.destination != self.pins.destination {
            return Err(Rejection::WrongDestination);
        }

        // Revocation updates first: a response can revoke, never validate on
        // its own, and projections are judged on the state after it.
        let mut feed_applied = 0;
        let mut feed_error = None;
        for bytes in &response.revocations {
            match self.feed.observe(bytes) {
                Ok(custodian_lifecycle::Observed::Applied) => feed_applied += 1,
                Ok(custodian_lifecycle::Observed::AlreadyApplied) => {}
                Err(e) => {
                    feed_error = Some(e);
                    break;
                }
            }
        }

        let listed: BTreeSet<&str> = manifest
            .projections
            .as_slice()
            .iter()
            .map(|d| d.as_str())
            .collect();
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for (i, bytes) in response.projections.iter().enumerate() {
            match self.verify_projection(request, bytes, now) {
                Ok(v) => {
                    if !listed.contains(v.digest().as_str()) {
                        rejected.push((i, Rejection::ManifestMismatch));
                        continue;
                    }
                    self.feed.track(v.projection.clone(), now);
                    accepted.push(v);
                }
                Err(r) => rejected.push((i, r)),
            }
        }
        Ok(ResponseOutcome {
            accepted,
            rejected,
            feed_applied,
            feed_error,
        })
    }

    /// Current standing of a projection accepted earlier.
    pub fn standing(&self, v: &VerifiedProjection, now: Timestamp) -> Standing {
        self.feed.standing(&v.projection, now)
    }

    /// The accepted projections that stopped being valid since the last call.
    /// The product re-evaluates whatever support it derived from each; this
    /// crate does not.
    pub fn reevaluate(&mut self, now: Timestamp) -> Vec<StandingChange> {
        self.feed.reevaluate(now)
    }
}
