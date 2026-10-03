//! Fixed reason codes for both sides of the bridge. No variant carries input
//! text, a digest, a path or an identity, so a refusal can be logged or
//! returned without echoing anything a hostile peer supplied.

/// Why the custodian side refused to answer a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BridgeReason {
    /// The request is not a strict, bounded, canonical request.
    RequestInvalid,
    /// The request names a feed other than the one this channel serves.
    WrongFeed,
    /// The request is ahead of the feed head (a sequence the custodian has not
    /// published).
    SequenceAheadOfFeed,
    /// The approved-release catalog is unavailable.
    CatalogUnavailable,
    /// The feed source is unavailable.
    FeedUnavailable,
    /// A document the custodian was about to send is not in canonical form or
    /// is over its bound. Nothing is sent.
    DocumentInvalid,
    /// The feed has a gap: `n + 1` is absent while a later sequence exists.
    FeedGap,
}

impl BridgeReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::RequestInvalid => "bridge_request_invalid",
            Self::WrongFeed => "bridge_wrong_feed",
            Self::SequenceAheadOfFeed => "bridge_sequence_ahead_of_feed",
            Self::CatalogUnavailable => "bridge_catalog_unavailable",
            Self::FeedUnavailable => "bridge_feed_unavailable",
            Self::DocumentInvalid => "bridge_document_invalid",
            Self::FeedGap => "bridge_feed_gap",
        }
    }
}

impl core::fmt::Display for BridgeReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for BridgeReason {}

/// Why the consumer did not accept a projection or a response. Every variant
/// is a rejection; there is no warning level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// Over its size bound, not valid, not strictly typed, or not in
    /// canonical form (this includes a missing signature).
    Malformed,
    /// The signature does not verify under the pinned keys.
    BadSignature,
    /// A key that is unknown, revoked, not valid at the issue time or not
    /// authorized for the projection domain.
    KeyNotAcceptable,
    /// The projection is for another evaluation domain than the one pinned
    /// and requested.
    WrongDomain,
    /// The projection is for another candidate than the one requested.
    WrongCandidate,
    /// The projection's population is not one the request and the product
    /// pins allow.
    WrongPopulation,
    /// The disclosure policy is not one the product has pinned as accepted.
    PolicyNotAccepted,
    /// The projection points at another revocation feed than the pinned one.
    WrongFeed,
    /// The response is for another request, or for another channel.
    WrongRequest,
    /// The response was prepared for another destination label than the one
    /// pinned.
    WrongDestination,
    /// The held feed state is missing, old, behind the projection's minimum
    /// sequence, or the projection is not yet valid. Unknown is not valid.
    Stale,
    /// Past the projection's own `fresh_until`.
    Expired,
    /// A revocation, contamination or key compromise entry covers it.
    Revoked,
    /// A supersession entry covers it.
    Superseded,
    /// The feed part of the response failed verification (see the feed
    /// outcome for which step).
    FeedRejected,
    /// The manifest's digest list does not match the projections carried.
    ManifestMismatch,
}

impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::KeyNotAcceptable => "key_not_acceptable",
            Self::WrongDomain => "wrong_domain",
            Self::WrongCandidate => "wrong_candidate",
            Self::WrongPopulation => "wrong_population",
            Self::PolicyNotAccepted => "policy_not_accepted",
            Self::WrongFeed => "wrong_feed",
            Self::WrongRequest => "wrong_request",
            Self::WrongDestination => "wrong_destination",
            Self::Stale => "stale",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::FeedRejected => "feed_rejected",
            Self::ManifestMismatch => "manifest_mismatch",
        }
    }
}

impl core::fmt::Display for Rejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Rejection {}
