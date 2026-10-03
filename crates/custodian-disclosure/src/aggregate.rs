//! The private aggregate artifact: the only measured data a projection is
//! built from (ADR 0062).
//!
//! It is strict and closed. There is no field for a case identity, a path, a
//! seed, a range, a per-case hash, a log line or an error message; a document
//! that carries one fails to parse (`deny_unknown_fields`) rather than being
//! trimmed. Parsing never echoes input, and `Debug` prints no value, so the
//! artifact cannot reach a log through formatting.
//!
//! Binding: the bytes must hash to the digest the signed internal receipt
//! recorded, name the frozen domain and protocol, and carry the same roster
//! counters as the receipt.

use std::collections::BTreeMap;

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::{PrivateArtifactRef, RosterCounts};
use custodian_contracts::types::{MetricId, ResultDigest, StratumId};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::reason::DisclosureReason;

pub const AGGREGATE_SCHEMA: &str = "private-custodian.aggregates/1";
/// Hard cap, whatever the artifact reference says.
pub const MAX_AGGREGATE_BYTES: usize = 64 * 1024;
pub const MAX_CELLS: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProtocol {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoster {
    expected: u64,
    observed: u64,
    failed: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCell {
    stratum: StratumId,
    metric: MetricId,
    numerator: u64,
    denominator: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAggregates {
    schema: String,
    domain: EvaluationDomain,
    protocol: WireProtocol,
    roster: WireRoster,
    cells: Vec<WireCell>,
}

/// Counts per (stratum, metric), checked against the receipt. Private to the
/// crate: nothing outside this crate can read a value from it except through
/// the projection builder.
pub struct PrivateAggregates {
    pub(crate) cells: BTreeMap<(StratumId, MetricId), (u64, u64)>,
}

impl core::fmt::Debug for PrivateAggregates {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateAggregates")
            .field("cells", &self.cells.len())
            .finish()
    }
}

impl PrivateAggregates {
    /// Parse and bind the private artifact. Every failure is a fixed reason.
    pub fn decode(
        bytes: &[u8],
        reference: &PrivateArtifactRef,
        domain: EvaluationDomain,
        protocol: &ProtocolRef,
        roster: &RosterCounts,
    ) -> Result<Self, DisclosureReason> {
        if bytes.len() > MAX_AGGREGATE_BYTES {
            return Err(DisclosureReason::ArtifactMalformed);
        }
        // Binding to the receipt comes first: nothing is parsed unless these
        // exact bytes are the ones the receipt recorded.
        if ResultDigest::from_raw(Sha256::digest(bytes).into()) != reference.digest
            || u64::try_from(bytes.len()).ok() != Some(reference.size_bytes.get())
        {
            return Err(DisclosureReason::ArtifactMismatch);
        }
        let w: WireAggregates =
            serde_json::from_slice(bytes).map_err(|_| DisclosureReason::ArtifactMalformed)?;
        if w.schema != AGGREGATE_SCHEMA || w.cells.len() > MAX_CELLS || w.cells.is_empty() {
            return Err(DisclosureReason::ArtifactMalformed);
        }
        if w.domain != domain
            || w.protocol.name != protocol.name.as_str()
            || w.protocol.version != protocol.version.as_str()
            || reference.protocol != *protocol
        {
            return Err(DisclosureReason::ArtifactMismatch);
        }
        let r = (w.roster.expected, w.roster.observed, w.roster.failed);
        if r != (
            roster.expected.get(),
            roster.observed.get(),
            roster.failed.get(),
        ) {
            return Err(DisclosureReason::ArtifactMismatch);
        }
        let mut cells = BTreeMap::new();
        for c in w.cells {
            if c.numerator > c.denominator || c.denominator > r.1 {
                return Err(DisclosureReason::ArtifactInconsistent);
            }
            if cells
                .insert((c.stratum, c.metric), (c.numerator, c.denominator))
                .is_some()
            {
                return Err(DisclosureReason::ArtifactInconsistent);
            }
        }
        Ok(Self { cells })
    }
}
