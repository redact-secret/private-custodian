//! Deterministic migration of legacy protected-lifecycle metadata (ADR 0091,
//! ADR 0092).
//!
//! * [`model`]: the reviewed metadata extract and the legacy vocabulary.
//! * [`import`]: `dry_run`, a pure function from extract bytes to import
//!   records and a report.
//! * [`report`]: the dry-run report and the handoff gate figures.
//! * [`store`]: idempotent, monotone application to an import store.
//! * [`handoff`]: the reviewed handoff record. It proposes; it never executes.
//!
//! Nothing here reads a file, a corpus, a seed, a ledger or a private root,
//! opens the runtime store, or runs an evaluation. Parity is judged on
//! metadata only. Rules that bind every part: a spent attempt stays spent, an
//! ambiguous attempt counts as consumed, a contaminated epoch stays
//! contaminated, and the legacy independence vocabulary is kept verbatim with
//! no value meaning "independent".

pub mod handoff;
pub mod import;
pub mod model;
pub mod report;
pub mod store;

pub use handoff::{
    contested_scopes, Blocker, CheckEvidence, HandoffChecks, HandoffEntry, HandoffRecord,
    HandoffStatus,
};
pub use import::{
    dry_run, Ambiguity, ConsumptionBasis, ContaminationStanding, DryRun, ExtractRefusal, ImportId,
    LegacyImportRecord, ScopeKey,
};
pub use model::{LegacyExtract, Lifecycle, ScopeSpec};
pub use report::{DryRunReport, RefusalCode};
pub use store::{apply, ApplyRefusal, ApplyReport, ImportStore, MemoryImportStore};
