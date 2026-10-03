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
//! both the imports and the function types. It cannot verify the destination
//! binding of a release (that lives in the private publication record); it
//! checks the channel label the response was prepared for and says so.
//!
//! # What it does not decide
//!
//! Whether a verified, still valid projection is good enough for a support
//! claim, a release or a page is product policy and stays with the consumer.
//! The public review ledger is product adjudication; it is not the private
//! audit export and nothing here reads or writes it.

use std::collections::BTreeSet;

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{Attestation, EvaluationDomain, PolicyRef};
use custodian_contracts::public::{
    PublicPopulationRef, PublicProjection, PublicProjectionEnvelope,
};
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

/// A projection that passed every check at the time given. It cannot be
/// constructed outside this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProjection {
    projection: PublicProjection,
    digest: ProjectionDigest,
    verified_at: Timestamp,
}

impl VerifiedProjection {
    pub fn projection(&self) -> &PublicProjection {
        &self.projection
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
}

impl BridgeConsumer {
    pub fn new(pins: ConsumerPins) -> Self {
        let feed = FeedConsumer::new(pins.feed_id.clone(), pins.verifier.clone());
        Self { pins, feed }
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
    /// 1. size bound, strict closed schema, canonical form (an unsigned
    ///    envelope has no signature field and is malformed);
    /// 2. signature under a pinned key authorized for the projection domain;
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
        let env = PublicProjectionEnvelope::decode(bytes).map_err(|_| Rejection::Malformed)?;
        if to_canonical_bytes(&env).map_err(|_| Rejection::Malformed)? != bytes {
            return Err(Rejection::Malformed);
        }
        self.pins
            .verifier
            .verify_projection(&env)
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
        let p = env.payload;
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
        let digest = p.projection_digest().map_err(|_| Rejection::Malformed)?;
        Ok(VerifiedProjection {
            projection: p,
            digest,
            verified_at: now,
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
