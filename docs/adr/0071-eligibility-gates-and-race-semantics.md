# 0071. Eligibility gates and race semantics

- Status: accepted (design); implemented in `custodian-store`, `custodian-lifecycle`, `custodian-worker` and
  `custodian-disclosure` (C9); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The issue requires contamination racing with dispatch or publication to fail closed by documented semantics,
current eligibility to be rechecked before dispatch and disclosure, and historical receipts to stay auditable
without authorizing future use. C8 left a `ReleaseEligibility` hook, called twice per release, with no
default. C4's reserve, start and exposure are single write transactions; C6 commits the write-ahead exposure
before opening protected bytes.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Dispatch gate | a check in the control plane only; a check inside the store transaction only; both |
| Where in the dispatch | reserve only; reserve and start; reserve, start and the exposure record |
| Already-exposed attempts | kill them; block their settlement; let them settle and refuse their release |
| Release gates | at release only; at prepare and release |
| Revocation source | only the published feed; the custodian's own obligations (published or not) |
| Unknown state | allow; refuse |

## Decision

1. **Two layers.** The store reads the epoch standing inside the transaction of `reserve_request`,
   `retry_attempt`, `start_attempt` and (when not yet exposed) `record_exposure`. Writers are serialized, so a
   contamination commit is totally ordered against each gate: before it, the operation is refused with
   `EpochBlocked` and writes nothing; after it, the operation already took effect. The control plane adds
   `GuardedRunLedger` before `start` and before `record_exposure`, for what the store does not know
   (recorded revocations by candidate or policy, policy activation freshness).
2. **The exposure record is the last gate before protected bytes.** A refusal there is settled as a rejected,
   unexposed attempt and refunded: nothing was opened.
3. **An attempt already exposed is not killed.** `begin_validation` and `finish` are not gated, so it settles
   truthfully, consumed, never refunded (idempotency does not make a new exposure free). Its result is refused
   at every later gate. It is re-evaluated at the next gate it reaches.
4. **Release gates.** `DisclosureService::prepare` checks eligibility before charging anything (the subject
   carries an all-zero projection digest, since none exists yet); `release` checks before any ledger write and
   again immediately before delivery (C8). A prior success is never consulted.
5. **Publication race.** The last check is the linearization point. A contamination committed before it
   refuses the release; one committed after it loses: the projection leaves and is revoked by the population
   entry the contamination recorded atomically, as soon as the feed carries it. The window between delivery and
   the next envelope is real and bounded by practice (publish after recording, short `ttl_secs`,
   `feed_ref` requires every known obligation published), not eliminated; bytes cannot be un-sent.
6. **Eligibility reads the authoritative store**, including obligations not yet in the feed (a revocation counts
   when recorded). **Unknown is a refusal**: store errors, a stale or unobservable activation, and a store
   awaiting reconciliation after a restore (which could be missing a contamination).
7. **Precedence** of the refusal reason: contaminated, retired, revoked, unknown (store trouble first).

## Security properties claimed

| Property | Failure test |
| --- | --- |
| No start or reservation that began after a contamination returned succeeds, whatever the interleaving | `epoch_standing.rs::contamination_racing_with_start...`, `..._with_reservation...` (real threads) |
| Refused before exposure: nothing opened, budget refunded; the store gate alone suffices | `dispatch.rs::contamination_after_reservation...`, `the_store_gate_alone...`, `contamination_between_start_and_exposure...` |
| Revoked candidate stops dispatch though the epoch is clean | `dispatch.rs::a_recorded_revocation_of_the_candidate...` |
| Exposed attempt settles consumed and cannot be released | `dispatch.rs::an_attempt_already_exposed...` |
| No release that started after the contamination returned is delivered; contamination before either release check refuses | `release.rs::real_threads_racing_release...`, `contamination_just_before_the_last_gate...` |
| Contamination after the last gate is published and revokes what left | `release.rs::contamination_after_the_last_gate...` |
| Prepare refuses before charging | `release.rs::a_contaminated_population_is_refused_at_prepare...` |
| Historical receipts verify but cannot authorize | `release.rs::historical_receipts_stay_auditable...` |
| An older restore cannot vouch for eligibility | `release.rs::an_older_restore_cannot_vouch...` |
| Activation revoked, superseded, stale or unobservable refuses | `release.rs::the_policy_activation_and_unknown_state_gates_fail_closed` |

## Adapter contract

`ReleaseEligibility` (C8 port) implemented by `LifecycleEligibility`; `DispatchGuard` and `RunLedger`
(`GuardedRunLedger` wraps any ledger); `ActivationSource` (the control service's activation store). The
worker gains one fixed reason, `eligibility_denied` (core reason `authorization_denied`), and the dispatcher
settles it before start (refunded) or at the exposure gate (rejected, unexposed).

## Failure and recovery

Store unavailable: refusal, nothing changes, retry-safe. A refused start leaves a `reserved` attempt that the
dispatcher fails before start; if the process dies first the reservation window lapses and recovery refunds
it. Contamination while the signer or ledger is down does not weaken any gate: the gates read the store.

## Performance evidence plan

The gate is one indexed read inside an existing write transaction; eligibility is a few reads. Measure them
against reserve, start and release latency separately.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Store gates, guard, release wiring | yes | yes | no |
| Activation source over the real activation store | yes (C10) | no (test double) | no |
| Closing the publish-to-feed window | open | no (bounded, documented) | no |

## Consequences, migration, exit

`DisclosureService::prepare` now calls the hook once more than C8 documented (before the charge); a hook that
refuses at prepare means no budget is spent. Tests of C8 are unchanged. Exit: the guard is a wrapper; the
store gate is three lines per operation.

## Open risks and revisit triggers

The delivery-to-feed window. Revisit if consumers must verify a destination or a "released but not yet
covered" interval must be zero: that needs a destination-side check (a publisher gate in front of the
destination) or a pull-with-proof consumer protocol, both outside C9.
