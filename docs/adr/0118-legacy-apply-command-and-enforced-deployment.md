# 0118. legacy apply, repair retention and gate enforcement in deployments

- Status: accepted; implemented in custodian-cli
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Decision

1. `custodian legacy apply --extract F --handoff F --confirm-handoff-digest D --confirm-report-digest D` needs the
   new `Permission::LegacyImport`, a reviewed handoff in a ready state, and both digests typed by the operator.
   Refusals use `import_refused` or `handoff_not_ready` (exit 5).
2. `custodian repair retention` takes the four ages explicitly (ADR 0117).
3. `deploy.rs` always opens the store with `StoreConfig::enforced()`, so the CLI cannot run without the dispatch
   gate. `custodian-bridge` becomes a normal CLI dependency.
4. Contamination marks from the legacy extract are reported as counts only; they are recorded with
   `lifecycle report`.

## Consequences

Tests: `legacy_apply.rs`, `retention_command.rs`, `c12_export_gate.rs`, and a gate-enforced check in `binary.rs`.
