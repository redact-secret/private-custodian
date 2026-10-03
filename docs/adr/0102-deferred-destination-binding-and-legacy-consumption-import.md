# 0102. Deferred changes: destination binding in the public projection and legacy consumption import

- Status: accepted as designs; not implemented; each is a recorded blocker in docs/release-readiness.md
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

Two gaps were handed to C12 with the instruction to implement only if small and safe, otherwise to record the
exact design. Neither is small: the first changes a signed public schema, the second adds a store migration and
touches the invariants that protect budgets.

1. **Destination binding (C8, C11, ADR 0090).** `PublicProjection` has no destination field. The destination is
   checked by the disclosure policy, recorded in the signed publication decision in the private ledger, and
   enforced by the bridge service when it chooses what to answer. A consumer holding only public inputs cannot
   verify that a projection was approved for the destination it came from.
2. **Legacy consumption (C11, ADR 0091 section 11).** The importer produces immutable records saying how many
   units each legacy scope consumed, but nothing writes those units into the runtime budget store, so a
   migrated scope would start with its whole budget available. Until it exists, no legacy population may be
   handed off (ADR 0092 gates).

## Options

| Topic | Alternatives considered |
| --- | --- |
| Destination | leave bridge-enforced; add `destination` to the projection under a new schema major; carry it in an envelope field outside the signed payload |
| Consumption | write directly into `budgets`; a new append-only import table summed into the existing invariants; defer and forbid handoff |

## Decision

### Destination binding: schema major 2

1. Add `destination: DestinationId` to the public projection under `private-custodian.public-projection/2`,
   with a new domain tag `private-custodian/v2/public-projection` so a v1 and a v2 document can never share a
   digest or a signing input. The destination is inside the signed payload and inside the projection digest, so
   the release approval (which binds the digest) covers it.
2. The disclosure service sets it from `ReleaseRequest::destination` after the policy check; `release` refuses
   when the approval's bound digest was prepared for another destination (a prepare step takes the intended
   destination).
3. The consumer pins its destination (it already does, `ConsumerPins::destination`) and rejects a projection
   whose signed destination differs, with no catalog access.
4. Migration is additive: v1 releases stay verifiable with the v1 rules; the bridge answers with v2 once the
   consumer announces support; v1 is never reinterpreted. Golden vectors for v2 are added and the second
   implementation (`crates/custodian-contracts/testdata/verify_golden.py`) is extended in the same change.

### Legacy consumption: store migration 0005

1. New append-only table `budget_imports` (`import_id` = the importer's facts-only `lgi_` identity, `scope_key`,
   `units`, `record_digest`, `supersedes`, `applied_by`, `applied_at`), with triggers that forbid update and
   delete, in the style of `epoch_events`.
2. `verify_invariants` is extended so that for every budget, `consumed` equals the sum of settled consumption
   plus the sum of imported units; the budget `CHECK (held + consumed <= limit)` still holds. The limit is
   raised to the declared legacy limit by the existing audited `provision_budget` before the import; an unknown
   limit imports as an exhausted budget (limit equal to consumed), as ADR 0091 requires.
3. `apply_legacy_import(&Handoff, &Report)` runs in one `BEGIN IMMEDIATE` transaction: all records or none; the
   same `import_id` is a no-op; a new record for a known scope applies only the non-negative difference and
   never lowers anything; an outbox event `budget.imported` carries the import id, units and scope kind (new
   allowlisted payload keys), so the ledger records it like any other state change.
4. The CLI exposes it only as `legacy apply`, human operator, with exact confirmations of the handoff id and
   report digest, after `Handoff::check` reports every gate cited. It is never an agent or service action.
5. Tests required before it is relied on: crash at both boundaries, idempotent replay, concurrent apply and
   reserve, restore behind the ledger after an import, invariant detection of a hand-edited import row.

## Security properties claimed

Designs only; nothing is claimed as implemented. The existing evidence that bounds the gap: the bridge refuses
to answer for another destination (`crates/custodian-bridge/tests/roundtrip.rs`), and a consumer cannot verify
destination without that service. For consumption: ADR 0091 rules 2 to 4 hold in the importer and the dry-run
report states `executed: nothing`.

## Adapter contract

The store gains one port method and one table; contracts gain one schema major. No new dependency.

## Failure and recovery

Both changes fail closed: an unknown schema major is rejected by the strict decoder; an import that cannot be
applied atomically is not applied.

## Performance evidence plan

Import cost is one transaction per handoff; destination binding adds one field to a bounded document.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Destination field and v2 schema | yes | no | no |
| Migration 0005 and `legacy apply` | yes | no | no |

## Consequences, migration, exit

Until the first exists, treat the destination binding as bridge-enforced and say so wherever projections are
described; until the second exists, do not hand off a legacy population. Owner role for both: engineering,
with the maintainer approving the schema and migration.
