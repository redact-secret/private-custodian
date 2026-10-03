//! The custodian side of the bridge: answer a request with approved
//! projections and revocation updates, and nothing else.
//!
//! What can leave is limited by types, not by filtering. The only projection
//! type the service accepts from its catalog is
//! [`custodian_disclosure::ReleasedEnvelope`], which only a completed,
//! approved release can produce; an internal receipt, an aggregate artifact,
//! a ledger record or an unreleased projection has no conversion into it. The
//! revocation updates are the bytes of the public feed, copied unchanged.
//!
//! The service holds no signing key (it never signs: projections were signed
//! at release and feed envelopes at publication), opens no store and reads no
//! protected population. The catalog is the one port that touches custodian
//! state; a deployment implements it over the release records.

use custodian_contracts::common::EvaluationDomain;
use custodian_contracts::types::{
    BoundedVec, CandidateDigest, ConfigDigest, DestinationId, FeedId, ProjectionDigest, Seq,
};
use custodian_disclosure::ReleasedEnvelope;
use custodian_lifecycle::FeedSource;

use crate::reason::BridgeReason;
use crate::wire::{
    BridgeManifest, BridgeManifestSchema, BridgeRequest, BridgeResponse, MAX_PROJECTIONS,
    MAX_REVOCATIONS,
};

/// What the catalog is asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseQuery {
    pub domain: EvaluationDomain,
    pub candidate: CandidateDigest,
    pub config: ConfigDigest,
}

/// The catalog failed; it carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogUnavailable;

/// The approved releases the custodian holds for a frozen candidate and
/// configuration. Port: the implementation joins release records; this crate
/// never sees how.
pub trait ApprovedCatalog: Send + Sync {
    fn released(&self, query: &ReleaseQuery) -> Result<Vec<ReleasedEnvelope>, CatalogUnavailable>;
}

pub struct BridgeService<'a> {
    pub catalog: &'a dyn ApprovedCatalog,
    pub feed: &'a dyn FeedSource,
    pub feed_id: FeedId,
    /// The one destination this channel serves. A release approved for
    /// another destination is not included.
    pub destination: DestinationId,
}

impl BridgeService<'_> {
    /// Answer a request given as untrusted bytes. Fails closed with a fixed
    /// reason; the response only ever contains released envelopes for this
    /// destination and public feed documents.
    pub fn answer(&self, request_bytes: &[u8]) -> Result<BridgeResponse, BridgeReason> {
        let request =
            BridgeRequest::decode(request_bytes).map_err(|_| BridgeReason::RequestInvalid)?;
        if request.feed_id != self.feed_id {
            return Err(BridgeReason::WrongFeed);
        }
        let request_digest = request.digest().map_err(|_| BridgeReason::RequestInvalid)?;

        // Projections.
        let released = self
            .catalog
            .released(&ReleaseQuery {
                domain: request.domain,
                candidate: request.candidate.clone(),
                config: request.config.clone(),
            })
            .map_err(|_| BridgeReason::CatalogUnavailable)?;
        let mut chosen: Vec<(ProjectionDigest, Vec<u8>)> = Vec::new();
        for r in &released {
            let p = r.envelope().common_fields();
            // The catalog is a port: re-check what it returned. A v2 envelope
            // also names its destination in the signed payload; it must be
            // the one this service answers for.
            if r.destination() != &self.destination
                || r.envelope()
                    .destination()
                    .is_some_and(|signed| signed != &self.destination)
                || p.domain != request.domain
                || p.candidate != request.candidate
                || !(request.populations.is_empty()
                    || request.populations.as_slice().contains(&p.population))
            {
                continue;
            }
            let digest = r
                .envelope()
                .projection_digest()
                .map_err(|_| BridgeReason::DocumentInvalid)?;
            if chosen.iter().any(|(d, _)| *d == digest) {
                continue;
            }
            let bytes = r.to_bytes().map_err(|_| BridgeReason::DocumentInvalid)?;
            chosen.push((digest, bytes));
        }
        // Deterministic order and bound.
        chosen.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        chosen.truncate(MAX_PROJECTIONS);

        // Revocation updates: known + 1 onwards, as found.
        let known = request.known_sequence.get();
        if known > 0
            && self
                .feed
                .get(&self.feed_id, known)
                .map_err(|_| BridgeReason::FeedUnavailable)?
                .is_none()
        {
            return Err(BridgeReason::SequenceAheadOfFeed);
        }
        let mut revocations = Vec::new();
        let mut next = known + 1;
        while revocations.len() < MAX_REVOCATIONS {
            match self
                .feed
                .get(&self.feed_id, next)
                .map_err(|_| BridgeReason::FeedUnavailable)?
            {
                Some(bytes) => {
                    if bytes.len() > crate::wire::MAX_DOCUMENT_BYTES {
                        return Err(BridgeReason::DocumentInvalid);
                    }
                    revocations.push(bytes);
                    next += 1;
                }
                None => {
                    if self
                        .feed
                        .get(&self.feed_id, next + 1)
                        .map_err(|_| BridgeReason::FeedUnavailable)?
                        .is_some()
                    {
                        return Err(BridgeReason::FeedGap);
                    }
                    break;
                }
            }
        }
        let (first, last) = if revocations.is_empty() {
            (0, 0)
        } else {
            (known + 1, known + revocations.len() as u64)
        };

        let manifest = BridgeManifest {
            schema: BridgeManifestSchema,
            request_digest,
            feed_id: self.feed_id.clone(),
            destination: self.destination.clone(),
            projections: BoundedVec::new(chosen.iter().map(|(d, _)| d.clone()).collect())
                .map_err(|_| BridgeReason::DocumentInvalid)?,
            first_sequence: Seq::new(first).map_err(|_| BridgeReason::DocumentInvalid)?,
            last_sequence: Seq::new(last).map_err(|_| BridgeReason::DocumentInvalid)?,
        };
        manifest
            .validate()
            .map_err(|_| BridgeReason::DocumentInvalid)?;
        Ok(BridgeResponse {
            manifest,
            projections: chosen.into_iter().map(|(_, b)| b).collect(),
            revocations,
        })
    }
}
