# 0063. Publication decision, release approval, destination binding and failure codes

- Status: accepted (design); implemented in `crates/custodian-disclosure` and `crates/custodian-ledger` (C8);
  not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The issue requires a signed or ledgered publication decision binding destination, projection digest, policy
version and approver; an explicit release approval distinct from execution approval; a durable audit
acknowledgement before release; and sanitized failure messages, including GitHub Check text. C2's `Approval`
already has a `Release` scope bound to the projection digest and disclosure policy, but `PublicProjection`
has no destination field and `PublicationBody` (C7) had no decision fields.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Destination binding | new field in `PublicProjection` (new schema major); new field in the release `Approval` (new major); bind in the ledger record |
| Ledger shape | a new record kind; optional fields on `publication` |
| Order | deliver then record; record then deliver |
| Audit gate | precondition only; precondition plus acknowledged charge events |
| Failure text | descriptive messages; fixed codes; fixed codes mapped to the core vocabulary for Checks |

## Decision

1. Add an optional `decision: PublicationDecision` to `PublicationBody` (destination, disclosure policy,
   execution, approval id, approver, approver kind). Additive: a record without it serializes and hashes as
   before; the record id includes destination and approval id when present, so one decision exists per
   destination and approval; an agent approver or a non-disclosure policy kind is inconsistent. A
   `DestinationId` label type is added to `custodian-contracts` (no schema changes). The destination is bound
   in the signed ledger record, not in the public projection.
2. Release requires: destination in the policy allowlist; the release `Approval` with scope `Release` bound to
   this execution, this projection digest and this disclosure policy; not the execution approval; a
   non-agent approver; time window; and a current, fresh activation of the disclosure policy (revoked or
   superseded is `policy_stale`). Signing goes only through `ApprovedPayload::projection`, which re-validates.
3. Order: precondition and charge acknowledgement; approval; eligibility hook; sign; ledger `policy` then
   `publication` decision (durable); eligibility again; deliver. Nothing leaves before the decision is durable.
   A decision for an undelivered release is a decision, not a delivery; a repeat writes identical records.
4. `verify_release` checks the envelope (strict, canonical), both signatures, the digest, identities, key,
   policy and destination. A consumer without the ledger verifies signature and digest only; this limit is
   documented, and a destination field remains a possible schema major.
5. Failures are fieldless `DisclosureReason`s. Checks use `custodian_intake::checks` and the core
   `ReasonCode` vocabulary only (`budget_exhausted`, `store_unavailable`, `disclosure_not_permitted`); success
   is the neutral "finished" Check.
6. Single-operator reality: separation of proposal, execution approval and release approval is procedural
   (`single_operator_procedural` or `distinct_principals_procedural`). Nothing here claims organizational
   independence or ground truth.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Wrong destination, digest, execution, policy, scope, agent, expired approval refused | `release.rs::release_refuses_wrong_destination_and_digest_and_scope` |
| Stale, revoked, superseded or other activation refused; changed policy refused; stale projection refused | `release.rs::stale_or_revoked_policy_activation_blocks_release` |
| Pending export, reconcile, ledger down block release | `release.rs::pending_ledger_export_blocks_prepare_and_release`, `restored_database_needing_reconcile_blocks_everything`, `ledger_unavailable_blocks_release_and_retry_succeeds_once_back` |
| Eligibility denied before and at delivery | `release.rs::eligibility_hook_denies_before_ledger_and_again_before_delivery` |
| Verifier round trip and rejection of tampering, other destination, other decision | `release.rs::full_release_round_trips_through_the_verifier`, `verifier_rejects_wrong_destination_tampering_and_substituted_decisions` |
| Decision record shape | `release.rs::publication_decisions_are_closed_distinct_per_destination_and_never_agent_approved` |
| Checks carry only coarse fixed codes | `leakage.rs::errors_debug_output_and_checks_never_echo_injected_details` |

## Adapter contract

`Sink`, `ReleaseEligibility`, `PublicPopulationNames`, `Signer`, `Exporter::write_record` (existing).

## Failure and recovery

Ledger unavailable: `ledger_unavailable`, nothing delivered, retry is idempotent. Quarantined
ledger bytes: `ledger_conflict`, human review. Signer unavailable: `signer_unavailable`. Delivery failure:
`delivery_failed`; the decision stands and a retry is safe. All fail closed.

## Performance evidence plan

Two ledger writes and one signature per release; measure separately from suppression.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Decision record, approval checks, verifier | yes | yes | no |
| Destination in the public contract | open | no | no |
| Real sink, signer process, private-ledger repository | yes (C10 to C12) | no | no |

## Consequences, migration, exit

`PublicationBody` gained an optional field (ledger schema unchanged). Existing records are unaffected.

## Open risks and revisit triggers

Destination binding is verifiable only with ledger access. Revisit if benchmarks must verify it, which needs a
reviewed new major of the projection or approval contract.
