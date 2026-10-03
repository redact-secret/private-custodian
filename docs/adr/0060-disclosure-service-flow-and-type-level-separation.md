# 0060. Disclosure service flow, crate boundary and type-level separation

- Status: accepted (design); implemented in `crates/custodian-disclosure` (C8); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ARCHITECTURE.md ("Disclosure and receipts") requires a disclosure service that validates the private result,
builds a public projection from an allowlist, applies policy, and signs only approved projections. C2 made the
public contracts closed allowlists, C4 left `ReleaseQuery` budgets as schema, C6 produces a validated roster
and an artifact reference, and C7 signs only through `ApprovedPayload::projection`. The threats are an
untrusted engine or agent, accidental publication of an internal record, hostile text in any input, a crash
between audit and release, and adaptive extraction. The `custodian_core::Disclosure` port from the scaffold
takes opaque identities and cannot carry a digest-bound approval.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Where the code lives | extend `custodian-contracts` or `custodian-ledger`; a new crate; inside `custodian-service` |
| How a projection is made | strip fields from the internal receipt; build from an allowlist |
| Separation | convention and review; types that make the wrong call not compile |
| Flow | one `release` call; prepare then release |
| Core port | implement `custodian_core::Disclosure`; replace it with a typed service |
| Dependencies | add a linear-algebra or fraction crate; use none |

## Decision

1. A new crate `custodian-disclosure` depends on `custodian-core`, `custodian-contracts`, `custodian-store`,
   `custodian-ledger` and `custodian-intake` (Check rendering only) and adds no third-party crate: serde,
   serde_json and sha2 are the versions already pinned (exact `=`) by those crates. Exact rational
   elimination is about 100 lines with `i128` and checked arithmetic; overflow fails closed.
2. The projection is **built**, never trimmed. The builder names every `PublicProjection` field and copies
   public values from validated internal records one by one. All internal records are validated first
   (schema at decode, receipt and execution consistency, bindings to plan, candidate, engine, adapter,
   scanners, configuration, protocol, population and activation, store attempt identity, roster coverage,
   evidence class, aggregate artifact digest and shape).
3. `Sink::deliver` accepts only `ReleasedEnvelope`: private fields, crate-private constructor, produced only by
   a completed `release`. Internal types have no conversion. Two `compile_fail` doctests pin this.
4. Two steps. `prepare` validates, charges and builds (no public effect). `release` needs a distinct release
   `Approval` bound to the projection digest, so the approver reviews the exact public bytes.
5. `custodian_core::Disclosure` is not implemented. The typed service replaces it; C10 retires or adapts the
   port when wiring the control service.
6. No logging or printing path exists in the crate; errors are fieldless `DisclosureReason`s; Checks use the
   intake crate's renderer, which has no free-text field.
7. Evidence class: a plan with purpose `conformance_control` must carry `public-control` independence and a
   protected evaluation must not, so public synthetic qualification and protected evidence cannot be
   confused. Attestation is copied from the signed internal receipt; `ground_truth` and organizational
   independence are single-valued in the types.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| No internal identity, digest or canary reaches a public release | `tests/leakage.rs::no_internal_identity_or_canary_reaches_a_public_release` |
| Unknown fields rejected in artifact, policy, projection, decision | `release.rs::artifact_with_unknown_fields_or_foreign_strata_is_refused`, `policy_documents_reject_unknown_fields...`, `envelope_with_unknown_fields_is_refused_by_the_verifier` |
| Errors, Debug and Checks echo no input | `leakage.rs::errors_debug_output_and_checks_never_echo_injected_details`, `debug_output_of_internal_values_prints_no_values` |
| Internal types cannot be delivered | doctests in `src/released.rs` |
| Wrong provenance refused | `release.rs::wrong_provenance_is_refused` |
| Partial with a complete roster rejected | `release.rs::partial_with_a_complete_roster_is_not_an_acceptable_receipt` |
| No logging path | `leakage.rs::the_crate_has_no_logging_or_printing_path` |

## Adapter contract

`DisclosureStore` (precondition, attempt binding, provisioning, charge, charge audit, history),
`PublicPopulationNames` (opaque reference or keyed commitment), `ReleaseEligibility` (C9), `Sink`. `SqliteStore`
implements `DisclosureStore`. Signing uses the existing `Signer`; ledger writes use `Exporter::write_record`.

## Failure and recovery

Every refusal before the charge has no side effect. After the charge nothing is refunded (ADR 0062). A crash
between steps leaves at most a charge, a history entry, and ledger records; a retry with the same release key
replays them and recomputes the same projection. Ledger, store or signer unavailable fails closed with a fixed
code and delivers nothing.

## Performance evidence plan

Not claimed. Measure separately later: validation, suppression (bounded by 256 cells and 64 relations),
charge transaction, ledger write, signing.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Service, builder, type split, verifier | yes | yes | no |
| Engine emission of the aggregate artifact | yes | no | no |
| Wiring into the control service | yes (C10) | no | no |

## Consequences, migration, exit

A new member of the workspace and one new public ledger-record shape (ADR 0063). Policy impact: the
disclosure policy is a reviewed document (ADR 0061); changing it is a new version and activation.

## Open risks and revisit triggers

A destination field in `PublicProjection` (new schema major) would let consumers verify the destination
without the ledger. Revisit if C11 needs it, or if an engine needs a richer aggregate contract.
