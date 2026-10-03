# 0115. Legacy consumption import: migration 0005 and the additive budget import

- Status: accepted; implemented in custodian-store (migration 0005)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0102 recorded the design for writing legacy consumed units into the runtime store and forbade handoff
until it existed. This ADR implements it.

## Decision

1. Migration 0005 adds `budget_imports`, an append-only table keyed by (import id, record digest). Imported units
   are summed into the existing budget invariants; the `budgets` rows are never edited in place.
2. `SqliteStore::apply_legacy_imports` runs in one transaction and only adds. It is idempotent by (import id,
   record digest). The same import id with different bytes is refused and recorded as a `budget.import_refused`
   outbox event. Lowering, un-exhausting, changing a limit, or exceeding the runtime limit are refused.
3. A record that declares its budget exhausted (unknown, or consumed at the limit) consumes all remaining
   headroom. Silence and ambiguity count as consumed (ADR 0091).
4. Each applied import writes a `budget.imported` outbox event so the private ledger sees it. The ledger payload
   allowlist gains the import keys; nothing else about the legacy record is exported.
5. `legacy apply` carries budget units only. Legacy contamination marks are not written to the store; the
   operator records them with `lifecycle report`.

## Consequences

A migrated scope starts with its legacy consumption already spent. Tests:
`crates/custodian-store/tests/legacy_import.rs`, `crates/custodian-cli/tests/legacy_apply.rs`. Not deployed; no
real legacy extract has been applied.
