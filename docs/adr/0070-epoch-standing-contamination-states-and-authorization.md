# 0070. Epoch standing: contamination states, retirement and authorization

- Status: accepted (design); implemented in `custodian-core`, `custodian-store` and `custodian-lifecycle` (C9);
  not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

C5 made a sealed epoch immutable and left contamination handling to C9 (`LifecycleObserver`). The responsibility
map and ADR 0003 require that contaminated or rotated epochs stay contaminated, that migration cannot clear a
mark, and that no exhausted budget is reset. The issue asks for exposed, used-for-tuning and unreviewed-change
transitions, conservative retirement, and a reviewed, audited, non-agent clearance. Agents are untrusted
(ADR 0001): the model is not the authority.

## Options

| Choice | Alternatives considered |
| --- | --- |
| State shape | one enum of everything; separate flags; severity-ordered contamination plus an independent retirement flag |
| Downgrade | allow any reviewed downgrade; allow none; allow exactly the possibly-benign state |
| Where the rule lives | in the store; in the orchestration crate; as a pure function in `custodian-core` applied inside the store transaction |
| Reporting by agents | forbidden (misses real exposure); allowed for everything (public DoS by an agent); allowed only for the reversible state |
| Clearing authority | any authorized actor; human only; two-person |
| Defer | leave contamination to the benchmark side |

## Decision

1. **Standing = contamination (`unaffected < unreviewed_change < exposed < used_for_tuning`) plus a one-way
   `retired` flag.** `Exposed` and `UsedForTuning` are permanent. Retirement is independent so a contaminated
   epoch stays contaminated when retired.
2. **A report only raises or keeps severity** (`max`). A weaker report on a stronger state is recorded and
   changes nothing, so it can neither downgrade nor hide the stronger earlier one.
3. **Only `unreviewed_change` is clearable**, by the explicit `Clear` change, on an un-retired epoch, with reason
   `reviewed_no_impact`, by a **human** actor under an authority permit. Permanent contamination is never
   cleared: the epoch is retired and replaced (rotation, ADR 0073).
4. **The rule is one pure function** (`custodian_core::standing::apply`), applied by the store inside the
   transaction that persists the change. The database repeats the invariants as a trigger (no downgrade except
   the clearance, no un-retire, no delete).
5. **A permanent report retires the epoch** in the same call. The store retires first (new use stops), then the
   registry follows; a crash between the two is converged by a retry with the same key or by a startup sweep.
6. **Authorization.** `OperatorAuthority` (deployment-supplied, no default) answers `permits(actor, action)`.
   Fixed kind rules apply on top and cannot be configured away: an agent may only report
   `unreviewed_change`; clearing needs a human; retire, rotate, record revocation and publish refuse agents.
   Every change records actor, actor kind, reason code, prior state and the authorization reference
   (an `ApprovalId`) in an append-only event row, with an audit outbox event.
7. **Public consequences.** A newly permanent contamination publishes a `Contaminated` entry; retirement of an
   epoch that is not permanently contaminated publishes `Revoked` with reason `epoch_rotation`; an unreviewed
   change publishes nothing (it blocks use but says nothing about results measured on the sealed population).
8. **Crate boundary.** `custodian-lifecycle` orchestrates; it adds no third-party dependency (serde_json and
   sha2 at the workspace pins). The state machine is core policy, as `RunState` and `DisclosureState` are.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Reports never downgrade; weaker reports are recorded | `standing.rs` unit tests; `epoch_standing.rs::reports_never_downgrade...` |
| Only an unreviewed change clears; a refused clear writes nothing | `epoch_standing.rs::only_an_unreviewed_change_clears...`; `epochs.rs::a_permanent_contamination_is_never_cleared...` |
| The database refuses a downgrade, un-retire, edit or delete | `epoch_standing.rs::the_database_itself_refuses...`, `the_reviewed_clearance_is_the_only_downgrade...` |
| Agents report only `unreviewed_change`; clearing needs a human; a lenient authority changes nothing | `epochs.rs::an_agent_can_only_report...`, `clearing_needs_a_human...` |
| Every change is audited with actor, reason, prior state, authorization | `epochs.rs::clearing_needs_a_human...`; `feed.rs::every_new_audit_event_kind_exports...` |
| Idempotent retries replay; conflicting reuse is refused | `epoch_standing.rs::idempotent_retries...`; `epochs.rs::reports_are_validated_and_idempotent` |

## Adapter contract

`OperatorAuthority` (permit decision), `EpochBlobStore` and `ProtectedPopulations` (registry mirror),
`SqliteStore` (durable standing). No vendor type enters core.

## Failure and recovery

Crash inside a change: all or nothing, the retry replays. Crash between a permanent report and its retirement,
or between store retirement and registry retirement: blocked in the store already; `report` again with the same
key or `reconcile_registry` converges (`epochs.rs::crash_between_a_report_and_its_retirement...`).

## Performance evidence plan

One write transaction per change; the gate adds one primary-key read to reserve, retry, start and exposure.
Measure the gate's cost against those transactions without relaxing it.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| State machine, store enforcement, audit | yes | yes | no |
| Authority implementation over real identities | yes (C10) | no (test double only) | no |
| Independent review of who may clear | open | no | no |

## Consequences, migration, exit

A reviewed policy revision (a new reason code, a new clearable state) is a new ADR and a forward migration;
existing event rows are never reinterpreted. Contamination invalidates the use of earlier evidence; it rewrites
no prior record and changes no independence vocabulary.

## Open risks and revisit triggers

An authorized reporter can block an epoch. A single operator holds report, review and publish roles
(procedural separation). Revisit when a second principal exists, or if agent reports of `unreviewed_change`
prove noisy.
