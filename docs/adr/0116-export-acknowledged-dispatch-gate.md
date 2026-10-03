# 0116. Export-acknowledged dispatch gate

- Status: accepted; implemented in custodian-store, custodian-worker and custodian-cli
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0101 accepted an unrecoverable window: spend after the last ledger export is invisible to the ledger, and a
restore from an older backup can let the same request run again. It deferred a code gate.

## Decision

1. `start_attempt` and `record_exposure` fail with `StoreError::ExportPending` (`store_export_pending`) while more
   than `max_unexported` budget-affecting outbox events are unacknowledged. Production uses 0.
2. Counted events: `reservation.created`, `approval.granted`, `attempt.started`, `exposure.recorded`,
   `attempt.terminal`, `disclosure.charged`, `budget.imported`.
3. The worker dispatcher calls `RunLedger::confirm_exposure_exported` before protected bytes open;
   `StoreRunLedger::with_export_barrier` runs an export pass before `start` and before the exposure record. The
   exposure record must be acknowledged before the corpus opens.
4. `StoreConfig::default()` keeps the gate off so older suites remain valid; `StoreConfig::enforced()` is what the
   CLI deployment path always uses (`deploy.rs`).
5. A ledger outage keeps dispatch closed and changes no budget. The operator restores the ledger, exports, then
   dispatches.

## Consequences

R-2 narrows from an accepted window to a gated one for dispatch. Spend that happened before the gate existed, and
loss of the ledger itself, are unchanged. Tests: `crates/custodian-store/tests/export_gate.rs`,
`crates/custodian-cli/tests/c12_export_gate.rs`, and the extended crash-window sweep.
