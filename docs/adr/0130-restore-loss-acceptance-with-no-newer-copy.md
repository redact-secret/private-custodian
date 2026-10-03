# 0130. Restore loss acceptance when no copy reaches the ledger checkpoint (R-1)

- Status: accepted; implemented in `custodian-store` (migration 0008), `custodian-ledger` and `custodian-cli`;
  not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The C12 restore drill left one case with no executable answer, register entry R-1
([release-readiness.md](../release-readiness.md), [ADR 0101](0101-restore-recovery-window-and-signing-key-operating-constraints.md)
decision 2): a database restored from a backup older than the private ledger's newest checkpoint, with **no
newer copy anywhere**. Every state-changing command is refused (`store_needs_reconcile`), `repair
clear-reconcile` is refused (`store_behind_ledger`), and even `lifecycle retire` is refused, so the runbook's
"retire the affected epochs" was not executable. ADR 0101 deferred a "new store and new ledger lineage"
(`repair begin-lineage`) and said it needed its own ADR.

What the ledger does hold is the acknowledged audit tail: for every event the store exported, its sequence,
chain value, payload digest and an allowlisted payload (ADR 0051). That is enough to extend the restored
store's own hash chain byte for byte, and enough to bound what each budget scope had consumed
([ADR 0054](0054-external-checkpoints-startup-check-and-independent-verification.md) decision 3 already said
the block is cleared after "a reviewed procedure that raises consumed budget to at least the figures in the
ledger's audit records"; no such procedure existed).

## Options

| Option | Judged against: never lowers budget; never silently trusts a rolled-back store; audited; no ledger fork; testable |
| --- | --- |
| A. Defer (the ADR 0101 state): stop, treat as an incident, no continuation | Safe, but leaves the deployment unrecoverable without a manual rebuild; R-1 stays a blocker |
| B. New store and new ledger lineage (`begin-lineage`): a fresh store id, a new ledger repository or branch, carry nothing over but a document | No fork, but needs a transplant of budgets and standing into a store whose history is new, a new pinned checkpoint and consumer re-pinning; budgets must be re-provisioned from outside, which is the "recreate a budget" step the rules forbid |
| C. Reconcile in place: adopt the ledger's acknowledged tail into the restored store, raise budgets to the ledger's figures, tighten standing, record an explicit loss acceptance, clear the block in the same transaction | One lineage, no fork, budgets only rise, fully audited; the lost window is bounded and stated |
| D. Edit the database | Forbidden (SECURITY.md, ARCHITECTURE.md) |

## Decision

Option C, as one closed operator path in the `repair` group, human operator only.

1. **Plan, then accept.** `repair loss-plan` is read-only and prints what the ledger holds that the store
   lacks (events to adopt, scopes and units to raise, epochs to retire, lost attempts, lost feed events) and a
   `plan_digest`. `repair accept-loss` needs the exact store id, the store's newest sequence, the ledger's
   newest checkpoint sequence and chain value (read from the **independent checkpoint copy**, not from the
   ledger being judged), the plan digest and the literal word `accept-unexported-loss`. Any mismatch refuses and
   writes nothing. `--dry-run` validates everything and writes nothing. The same plan accepted twice is a
   no-op.
2. **Refuse what is not a rollback.** The ledger must walk clean from the pinned roots; the store must
   not already contain the ledger's checkpoint (then `clear-reconcile` is the path); the registry must not be
   behind its checkpoint; the store's newest chain value must equal the ledger's chain value at that sequence
   (otherwise `lineage_diverged`: two histories, an incident); the ledger must hold a contiguous audit tail up
   to its checkpoint (`ledger_tail_incomplete`), and every tail event must reproduce its recorded payload
   digest.
3. **Adopt the tail byte for byte.** The store inserts the missing events as acknowledged outbox rows
   (`export_ref` is the ledger record). Every payload must hash to its digest and every chain value must be the
   one the store's own chain construction yields from its last row. A tail that does not extend the chain is
   refused whole (`loss_chain_mismatch`).
4. **Budgets only rise.** Consumption per scope is derived from the whole ledger: a reservation counts as
   consumed unless a terminal record says it was refunded (ambiguity is consumption, ADR 0091); disclosure
   charges and imported units count as stated. A scope's consumed units are raised by the deficit, capped at
   the headroom (the budget then **saturates**: no further use, flagged `saturated`; it never exceeds its
   limit). A scope unknown to the restored store is recorded in `budget_recoveries`, and a budget provisioned
   for it later starts with those units consumed. `verify_invariants` requires consumed units to equal settled
   consumption plus charges plus legacy imports plus recoveries.
5. **Standing only tightens.** Every epoch with spend-affecting activity in the lost window is retired, and an
   epoch whose last ledger standing is contaminated is raised to it (`Report` takes the maximum), through the
   same transaction and audit path as `lifecycle report` and `lifecycle retire` (reason `restore_loss`). The
   operator then rotates to successor epochs the normal way.
6. **Audited, atomic.** The acceptance writes `loss_acceptances`, `budget_recoveries`, one
   `budget.recovered` event per scope and one `store.loss_accepted` event, all in the transaction that clears
   the write block. The events are exported by the next `repair export`; the acceptance is therefore also in
   the ledger.

## What it cannot recover (stated limits)

- **Spend that was never exported.** The ledger cannot know it. With the export-acknowledged dispatch gate
  (ADR 0116, enforced in every deployment) no protected bytes are opened for spend the ledger has not
  acknowledged, so the unacknowledged window holds reservations that did not yet expose anything. Without the
  gate the window can hide an exposure. That is why the operator acknowledges the loss in words.
- **The requests and attempts of the lost window.** No rows are invented. Their cost is carried by the budgets;
  a lost request that is submitted again is charged again (never run for free), and its epoch is retired.
- **Feed obligations.** Their targets are not in the ledger (ADR 0072), so the store cannot recreate them. The
  plan lists how many were lost; the operator re-records the revocations (`feed record-revocation`) and
  publishes the feed.
- **A held reservation whose terminal event is in the lost window** is counted by the ledger figure and may
  also settle in the restored store: the result can overcount (never undercount) by at most the held units.
- **A diverged store, a lost or rewritten ledger tail, a registry that rolled back.** These are incidents; the
  command refuses. A new lineage (option B) stays a documented fallback and is not implemented.
- **Limit raises** made in the lost window are not carried; the budget saturates earlier and a reviewed
  provisioning raises it again.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| The previously blocking restore (no newer copy) is recovered; budgets equal the lost newer copy's; the epoch is exposed and retired; nothing runs again; startup passes after export | `crates/custodian-cli/tests/s6_recovery.rs::the_previously_blocking_restore_is_recovered_by_an_explicit_audited_acceptance` |
| Every confirmation is exact; roles and agents are refused; dry run writes nothing; a repeat is a no-op | same test |
| A store from another history is `lineage_diverged`; a healthy store has nothing to accept; a tampered ledger is never adopted | `s6_recovery.rs::{a_store_that_is_not_a_prefix_of_the_ledger_is_an_incident_not_a_repair, a_healthy_store_has_nothing_to_accept, a_tampered_ledger_tail_is_never_adopted}` |
| The tail is adopted byte for byte, budgets only rise, the block clears atomically, invariants hold | `crates/custodian-store/tests/loss.rs::the_ledger_tail_is_adopted_byte_for_byte_and_budgets_only_rise` |
| A tail that does not extend the chain is refused and nothing is written | `loss.rs::a_tail_that_does_not_extend_the_stores_own_chain_is_refused_and_nothing_is_written` |
| Saturation instead of overshoot; unknown scopes start consumed | `loss.rs::{consumption_beyond_the_limit_saturates_the_budget_instead_of_exceeding_it, a_scope_the_store_never_heard_of_starts_consumed_when_it_is_provisioned}` |
| Derivation rules (refunded vs consumed, tail scopes, floors) | `crates/custodian-ledger/src/recovery.rs` unit tests |

Data and keys in all of these are synthetic and generated in the tests. This is functional verification on
public synthetic data, not an independent protected evaluation.

## Adapter contract

`SqliteStore::accept_ledger_loss(&LossAcceptCommand) -> LossOutcome`. The store never reads the ledger; the CLI
passes events the walker already verified. The ledger crate's `recovery` module holds the pure derivations.

## Failure and recovery

Refusals write nothing. A crash during the transaction rolls it back whole (one transaction, `FaultOp::Reconcile`).
After a crash the same command is safe to repeat. If the operator cannot supply the independent checkpoint
values, the right action is to stop and treat it as an incident.

## Performance evidence plan

One transaction proportional to the lost window; the ledger walk it relies on is the same linear walk as every
state-changing command (R-7).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Loss plan and acceptance, migration 0008, invariants | yes | yes (synthetic) | no |
| Rehearsal on a real deployment | yes | no | no |
| New-lineage fallback for a diverged store | maybe | no | no |

## Consequences, migration, exit

Migration 0008 is additive. The decision supersedes the deferred design of ADR 0101 decision 2 ("a new store
and a new ledger lineage") for the rollback case; ADR 0101's operating rules stand. Revisit if a diverged store
becomes a real case, or if the ledger gains per-record epoch identity (which would remove the registry lookup).

## Open risks and revisit triggers

The operator is trusted to read the independent checkpoint honestly; the repository cannot enforce that. A
ledger rewritten consistently with the independent copy would be adopted. Revisit with a second independent
copy.
