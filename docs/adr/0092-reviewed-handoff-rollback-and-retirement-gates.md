# 0092. Reviewed handoff, rollback and retirement gates

- Status: accepted (design); handoff record and checks implemented in `custodian-bridge::legacy` (C11); no
  handoff or cutover has been performed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0003 item 5 states the handoff gate in one sentence. Benchmarks issue 666 asks for a recorded oracle-exit
period and a rehearsed rollback, and says a credential authority setting is not sufficient for PII. The
credential domain has its own readiness path (credential-eval keeps holdout, blind and policy qualification
out of scope for now). C11 must record gates that preserve prior evidence, require explicit authorization for
any new protected execution, never force the credential cutover, and never rerun protected data for parity,
without itself performing a cutover.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Handoff unit | one population at a time, entire; per scope; per domain at once |
| Representation | prose in a pull request; a typed record whose states cannot express an executed cutover or a rerun |
| Gate evaluation | the record states it passed; the gates are recomputed from the dry run and the import records |
| Credential timing | cut over with PII; wait for credential readiness evidence |
| Rollback | delete imported state; restore legacy authority and keep imported records |

## Decision

1. **A population moves whole, to one authority.** A handoff names every scope of a population (population
   label for holdout and PII, epoch for blind). A handoff that includes some scopes of a population is blocked
   (`partial_population`), and two handoffs that claim one scope are reported (`contested_scopes`). Partial
   dual authority is refused.
2. **The record proposes; it cannot execute.** `HandoffRecord` has one cutover state (`not_executed`), one
   parity method (`metadata_only`), one prior-evidence term (`preserved`) and one new-execution term
   (`requires_approval`). A document that says otherwise does not parse. `assess` returns `Proposed(blockers)`
   or `ReadyForSignoff`; there is no executed state, and no code in this repository acts on a handoff.
3. **Gates are recomputed.** `assess` checks, from the dry-run report and import records, not from the
   record's word: the digest of the dry run matches; the dry run is ready for review (zero unexplained
   differences, zero refused scopes, zero unknown contamination); every entry names an imported record in the
   same domain; each custodian scope has the variant that matches the legacy budget semantics; the population
   is complete. It then requires cited evidence (a reference and a date) for the maintainer's inventory
   review, the zero-difference dry run, benchmarks' verification of signed envelopes with freshness and
   revocation, a rehearsed rollback and the legacy runner disabled for that population in the same change.
4. **Credential is not forced.** A credential-domain handoff additionally requires the credential domain's own
   readiness evidence (`credential_not_ready` otherwise). PII readiness is not credential readiness and neither
   is implied by the other.
5. **No protected rerun for parity.** Parity is the metadata comparison in the dry-run report. Any new
   protected execution after a handoff is an ordinary custodian run and requires an explicit execution
   `Approval` bound to the exact request, plan, candidate, population, budget scope and policy activation, like
   every other run. A migration, a handoff or a successful verification is never an authorization.
6. **Rollback preserves evidence.** Rolling back a handoff re-establishes the legacy runner's authority for
   the population; it never deletes an import record, a receipt, a seal or a contamination mark, and never
   resets a budget. Budget consumed under custodian authority after a handoff is carried back into the legacy
   state by a recorded reconciliation before the legacy runner is re-enabled, because a spent attempt stays
   spent in both directions. Rollback is rehearsed before the handoff and the rehearsal is cited.
7. **Retirement of the legacy runner is a separate, later, authorized act.** It follows a recorded
   oracle-exit period (benchmarks issue 666 owns its length and the shipped-surface decision), requires the
   maintainer's explicit written authorization, and archives rather than deletes legacy receipts and manifests.
   Dual verification of old and new receipt formats runs for a bounded period; benchmarks owns that period.
8. **Contamination travels.** A population contaminated in the legacy lifecycle remains contaminated after the
   handoff: the import record keeps the mark (ADR 0091), applying a record that drops it is refused, and no
   operation in this repository clears a legacy mark. Unknown contamination blocks the dry-run gate until a
   reviewer records a decision.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| The record cannot express an executed cutover, a protected rerun, or execution without approval | `tests/legacy.rs` `a_handoff_only_proposes_until_every_gate_has_evidence` |
| Missing gate evidence blocks; a different dry run invalidates | same |
| Credential requires its own readiness; the two budget semantics are never collapsed; partial and dual authority are blocked | `credential_is_not_forced_and_unready_or_partial_handoffs_are_blocked` |
| The dry run executes nothing | `the_synthetic_fixture_extract_is_ready_for_review_and_executes_nothing` |

## Adapter contract

None. The handoff is data plus pure checks. A cutover tool, if one is ever written, consumes a
`ReadyForSignoff` record that a human signed off and goes through the operator CLI and the same authorization
and budget control plane (C10).

## Failure and recovery

A blocker fails the gate closed. A rollback follows decision 6. No step is automatic.

## Performance evidence plan

Not applicable.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Handoff record, gate checks, contested-scope check | yes | yes (synthetic) | no |
| Cutover, rollback rehearsal, runner disablement | yes (maintainer, benchmarks) | no | no |
| Legacy retirement | yes (benchmarks 666) | no | no |

## Consequences, migration, exit

Adding a gate is an additive blocker. Relaxing one is a reviewed policy revision recorded as a new ADR.

## Open risks and revisit triggers

The same-change disablement of the legacy runner happens in benchmarks, which this repository cannot observe;
the record only cites the evidence. The reconciliation in decision 6 has no implementation until a cutover tool
exists. Revisit when C10 provides the operator command surface and when C12 provisions the real stores.
