//! Synthetic doubles for the bridge ports. None of them is a control.

use std::sync::Mutex;

use custodian_contracts::types::ConfigDigest;
use custodian_disclosure::ReleasedEnvelope;

use crate::service::{ApprovedCatalog, CatalogUnavailable, ReleaseQuery};

/// An in-memory catalog: releases keyed by the configuration they were
/// approved for. Matching on domain and candidate is done by the service.
#[derive(Default)]
pub struct MemoryCatalog {
    rows: Mutex<Vec<(ConfigDigest, ReleasedEnvelope)>>,
    down: Mutex<bool>,
}

impl MemoryCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, config: ConfigDigest, released: ReleasedEnvelope) {
        if let Ok(mut g) = self.rows.lock() {
            g.push((config, released));
        }
    }

    pub fn set_unavailable(&self, down: bool) {
        if let Ok(mut g) = self.down.lock() {
            *g = down;
        }
    }
}

impl ApprovedCatalog for MemoryCatalog {
    fn released(&self, q: &ReleaseQuery) -> Result<Vec<ReleasedEnvelope>, CatalogUnavailable> {
        if self.down.lock().map(|g| *g).unwrap_or(true) {
            return Err(CatalogUnavailable);
        }
        let g = self.rows.lock().map_err(|_| CatalogUnavailable)?;
        Ok(g.iter()
            .filter(|(c, _)| *c == q.config)
            .map(|(_, r)| r.clone())
            .collect())
    }
}
