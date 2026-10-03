# Contamination, epoch rotation and public evidence revocation (C9)

Status: **implemented** in `crates/custodian-lifecycle` (orchestration, eligibility, feed, reference consumer),
`crates/custodian-core/src/standing.rs` (the state machine) and `crates/custodian-store` (migration 0003,
the use gates, the feed tables), with small edits to `custodian-worker`, `custodian-ledger` and
`custodian-disclosure`. Tested with synthetic data and test-generated keys only; **not deployed**. No feed
destination exists, no signer process runs, and the private ledger is not provisioned.
Decisions: [ADR 0070](adr/0070-epoch-standing-contamination-states-and-authorization.md) (states and
authorization), [ADR 0071](adr/0071-eligibility-gates-and-race-semantics.md) (gates and races),
[ADR 0072](adr/0072-public-revocation-feed-shape-publication-and-consumer-verification.md) (feed),
[ADR 0073](adr/0073-store-migration-0003-audit-events-and-rotation-protocol.md) (store, audit, rotation).

This repository is maintained by the Redact Secret project. Invalidating evidence is a custody statement. It
says "do not rely on this", never "this was wrong" or "this was right": signatures and custody attest origin,
binding and history, not ground truth or independent review (`ground_truth` stays `not_established`,
organizational independence `not_claimed`). The legacy independence vocabulary is unchanged and none of it
means independent.

## 1. Epoch standing

An epoch is sealed and immutable (C5). What changes is whether its *use* can still be trusted. The standing of
an epoch is a contamination state plus an independent one-way retirement flag. The rules are one pure
function, `custodian_core::standing::apply`; the store calls it inside the transaction that persists the
result.

| State | Meaning | Severity | Blocks new use | Clearable | Public consequence when entered |
| --- | --- | --- | --- | --- | --- |
| `unaffected` | nothing recorded (also: no row exists) | 0 | no | n/a | none |
| `unreviewed_change` | the population or its binding may have changed without a reviewed re-seal (for example an integrity alarm) | 1 | yes | **yes, by a reviewed action only** | none (private: it blocks use, it says nothing about results measured on the sealed population) |
| `exposed` | protected contents or per-case detail derived from them may have reached a party outside custody | 2 | yes | never | `Contaminated` entry for the population |
| `used_for_tuning` | a candidate or detector was adjusted using this population's results | 3 | yes | never | `Contaminated` entry for the population |

`retired` is a flag, not a state: new use is refused, the registry retires the epoch, and nothing un-retires
it. Retirement of an epoch that is not permanently contaminated publishes a `Revoked` entry with reason
`epoch_rotation` (its evidence no longer describes a current population). Retirement of a permanently
contaminated epoch adds nothing new: contamination already says it.

### Transitions

| Change | Allowed from | Result | Notes |
| --- | --- | --- | --- |
| `report(k)` | any | `max(current, k)` | Never lowers. A weaker report on a stronger state changes nothing and is **still recorded** (event row with `changed = 0`), so a weaker later report cannot hide a stronger earlier one. `report(unaffected)` is refused |
| `clear` | `unreviewed_change`, not retired | `unaffected` | Reason must be `reviewed_no_impact`. Refused for every other state: `exposed`, `used_for_tuning`, retired, or not flagged. A refused change writes nothing |
| `retire` | any | `retired = true`, contamination kept | Idempotent. Applied in the store first (new use stops), then mirrored into the registry |
| permanent report | any | also `retire` in the same call | `report(exposed or used_for_tuning)` retires the epoch (`contamination_response`). A crash between the two is converged by a retry with the same key or by `reconcile_registry` |

The database enforces the same rule independently (trigger `epoch_standing_guard`): severity never drops except
`unreviewed_change -> unaffected` on an un-retired epoch, `retired` never returns to 0, rows are never
deleted, and the version rises by exactly one per change.

### Who may do what

| Action | Human | Service | Agent | Also needs |
| --- | --- | --- | --- | --- |
| Report `unreviewed_change` | yes | yes | **yes** (it blocks use at once and is reversible by review) | `OperatorAuthority` permit |
| Report `exposed` or `used_for_tuning` | yes | yes | no | permit |
| Clear `unreviewed_change` | **yes** | no | no | permit, reason `reviewed_no_impact` |
| Retire, rotate | yes | yes | no | permit |
| Record an operator revocation entry | yes | yes | no | permit |
| Publish the feed (including freshness renewal) | yes | yes | no | permit |

The kind rules hold whatever the authority answers (`custodian_lifecycle::authorize`): a lenient authority
that permits an agent everything still cannot make it clear, retire, rotate or publish. The authority is
supplied by the deployment; C10 implements it over a reviewed operator policy file (`custodian_cli::PolicyAuthority`, ADR 0081) and is stricter than this table for automation: a `service` identity holds no operator role in the CLI. The library itself still has no default. Residual risk: an authorized reporter can
block an epoch (an availability cost, deliberately on the safe side). An agent can only cause a reversible
block, never a public contamination.

### What is recorded

Every change request that reaches the store is one append-only row in `epoch_events`: epoch, change, reported
kind, prior state and retired flag, new state and retired flag, whether anything changed, version after,
**actor, actor kind, reason code, authorization reference** and time. The standing row and the event commit
together with the audit outbox event (`epoch.standing`, exported to the private ledger like every other state
change) and any feed obligation. History is never edited: a cleared flag stays visible as `report, clear`.
Reason codes are the fixed `EpochReason` vocabulary; no free text is representable.

## 2. Epoch rotation

A new reviewed population is a **new epoch and a new seal** (C5: `begin_epoch`, `add_entry`, `seal`). Rotation
(`EpochManager::rotate`) retires the old epoch and activates the new one without touching either's state:

1. validate: the successor is a different epoch of the same corpus, family and domain, is sealed or active and
   not blocked, has a different population digest and a different seal, and every budget to provision names
   the **successor** epoch (a scope for any other epoch is refused before anything changes);
2. the store retires the predecessor (new use is refused from here);
3. the registry retires the predecessor;
4. the store links predecessor to successor (`epoch_rotations`: one successor per epoch, one predecessor per
   epoch);
5. the successor's budgets are provisioned under **its own scope keys** (the budget key digests the epoch, so
   a new epoch is a new key by construction);
6. the registry activates the successor. This is the only step that makes it usable, so it is last.

Old state is preserved exactly: the predecessor's budgets (exhausted ones stay exhausted, held and consumed
units stay), history, seal and registry events are never edited, and the store has no operation that lowers a
limit or consumption. Every step is idempotent and each intermediate state fails closed (table below).
Retention of the retired epoch's sealed bytes follows [protected-storage.md](protected-storage.md).

| Crash after | Durable state | Fails closed because | Recovery |
| --- | --- | --- | --- |
| store retire | predecessor blocked in the store; registry still active | the store gate refuses reserve, retry, start and exposure | rerun `rotate` (same key), or `reconcile_registry` |
| registry retire | predecessor retired everywhere; no link | nothing is active for the corpus | rerun |
| link | link recorded; successor has no budget | a reservation on a scope without a budget is denied | rerun |
| budgets | budgets provisioned; successor still sealed | the registry refuses to open a sealed epoch (`not_active`) | rerun |

## 3. Race semantics

All lifecycle writes and all use gates are `BEGIN IMMEDIATE` transactions on one SQLite database, so they are
totally ordered. The rule for every race is the same: **whichever commits first wins, and a contamination that
loses a race is still published and still blocks everything after it**.

### Where the standing is read

| Gate | Where | On refusal |
| --- | --- | --- |
| New request (`reserve_request`) | inside the reservation transaction, for new requests (replays are exempt: they charge nothing) | `StoreError::EpochBlocked`; nothing written |
| Retry (`retry_attempt`) | inside the retry transaction | same |
| Start (`start_attempt`) | inside the transaction that takes the lease | same; the dispatcher settles the attempt as a refunded pre-exposure failure |
| Exposure (`record_exposure`) | inside the write-ahead exposure transaction, only when the attempt is not yet exposed | same; nothing was opened, so the attempt settles as a refund |
| Dispatch guard | `GuardedRunLedger::start` and `::record_exposure`, before the store call | `WorkerReason::EligibilityDenied`; adds the checks the store does not know (recorded revocations, policy activation freshness) |
| Prepare | `DisclosureService::prepare`, before any budget is charged | `eligibility_denied`; no charge, no history entry |
| Release | `DisclosureService::release`, before any ledger write and again immediately before delivery | `eligibility_denied`; nothing delivered |

### Contamination versus dispatch

* Commit **before** a gate: the operation is refused. A refused reserve creates no request and no attempt; a
  refused start leaves the attempt `reserved` and the dispatcher fails it before start (refunded); a refused
  exposure marks the attempt failed with no exposure (refunded). No protected byte was opened.
* Commit **after** the exposure gate: the attempt is already exposed and **cannot be un-exposed**. It is not
  killed: `begin_validation` and `finish` are not gated, so it settles truthfully, **consumed, never refunded**.
  Its result is held; every later gate (prepare, release) refuses it. It is re-evaluated at the next gate it
  reaches, which is the disclosure gate.
* A running attempt that has not yet recorded exposure when the commit lands is stopped at the exposure gate.
* Tested with real threads on separate connections: no start that began after the contamination call
  returned succeeds, whatever the interleaving (`crates/custodian-store/tests/epoch_standing.rs`).

### Contamination versus publication

* Commit before the first release check, or between the two: the release is refused and nothing is delivered
  (a ledgered decision record may exist for the second case; a decision is not a delivery).
* Commit **after the last check**: publication won. The projection leaves, and the contamination, already
  recorded with its population-wide feed obligation, revokes it for consumers as soon as the next envelope is
  published. Between the delivery and that envelope a consumer holding the older feed still sees the
  projection as usable. This window cannot be closed by any local check (bytes cannot be un-sent). It is
  bounded by operating practice: publish the feed right after recording a contamination (the obligation is
  durable, so a crash does not lose it), keep `ttl_secs` short, and have projections require
  `min_sequence` of a feed that included every revocation known at preparation (`FeedPublisher::feed_ref`
  refuses while an obligation is unpublished).
* Tested: `release.rs` (contamination just before the last gate, after it, and with real threads: no release
  that started after the contamination returned is delivered; whichever ordering occurred, the feed revokes
  what left).

### Other fail-closed edges

* A store restored from an older backup may be missing a contamination. Eligibility refuses (`unknown`) while
  the store is awaiting reconciliation (`needs_reconcile`), and every write already refuses (C4).
* Anything unknown is a refusal: a store error, an activation that cannot be observed, an unresolvable public
  target.

## 4. Eligibility

`LifecycleEligibility` is the one evaluation behind both gates. It reads the authoritative store, never a
prior receipt, and checks in order: the store is not awaiting reconciliation; the epoch's standing; every
recorded revocation obligation (published or not) naming the epoch's population, the candidate or a guarded
disclosure policy; and the current, fresh state of each required policy activation
(`contracts::policy::check_current`). Refusal mapping onto the C8 `EligibilityRefusal`: a store that is
awaiting reconciliation or fails gives `unknown` straight away; otherwise contamination (any contamination
state, or a `Contaminated` entry) gives `contaminated`, a retired epoch `epoch_retired`, a `Revoked` or
`Superseded` entry or a revoked or superseded activation `revoked`, and a stale or unobservable activation
`unknown`. Contamination outranks the rest.

**Historical receipts remain auditable but cannot authorize future use.** A delivered projection keeps
verifying (`Verifier::verify_projection`, `verify_release` against its ledgered decision) and its ledger
records stay. None of it is consulted when deciding whether to run, prepare or release again. Contamination
may invalidate the *use* of earlier evidence for independent qualification; it never rewrites or removes a
prior record (the tests re-verify a delivered projection after revocation and re-release it unsuccessfully).

## 5. The public revocation feed

### Shape

The feed is a sequence of `SignedRevocationEnvelope` documents (schema
`private-custodian.revocation-envelope/1`, signing domain `private-custodian/v1/revocation-envelope`, Ed25519),
one per file:

```
<feed_id>/0000000001.json    canonical JSON of the signed envelope, nothing else
<feed_id>/0000000002.json
```

* Sequences are 1-based, contiguous, zero-padded to ten digits. A file is written once and never changed or
  removed. There is no index and no mutable "latest" pointer.
* Each envelope carries `feed_id`, `sequence`, `previous` (document digest of the previous envelope, absent
  exactly for 1), `issued_at`, `fresh_until` and at most 128 **new** entries. A consumer's log is the union of
  all entries; an entry is never removed by a later envelope.
* An entry is `{target, action, reason, effective_at}`. Targets: `projection`, `receipt`, `candidate`,
  `population` (the public reference, an opaque id or a keyed commitment, never a plain hash), `policy`.
  Actions: `revoked`, `contaminated` (never cleared by a later entry), `superseded` (names the replacing
  projection). Reasons: `contamination`, `epoch_rotation`, `key_compromise`, `policy_revoked`,
  `error_correction`, `newer_evidence`.
* **Nothing else is representable**: no epoch, corpus, family or lineage identity, case identity, seed, path,
  budget, actor, authorization or free text. `tests/feed.rs` checks the bytes against a forbidden list and the
  top-level key set.
* An empty envelope renews freshness. `fresh_until = issued_at + ttl_secs`.

### Publisher

`FeedPublisher::publish` (operator-only): deliver any committed-but-undelivered envelopes in order; read the
head and up to 128 pending obligations; if there is nothing to say and the head is fresh beyond
`renew_margin_secs`, stop; otherwise build the next envelope, sign it through
`ApprovedPayload::revocation` and the `Signer` (the signer re-validates shape and domain; a key not
authorized for that domain refuses), append it with `append_feed_envelope` (contiguity and the `previous` link
enforced in code and by trigger; the obligations are stamped published in the same transaction, once), then
write it to the destination and record the delivery. Two publishers racing for a sequence cannot both commit:
the loser re-reads. A crash leaves one of: nothing; a committed envelope not yet at the destination; bytes at
the destination not yet marked delivered. The next `publish` finishes it exactly once.

Obligations come from two places, both durable before anything is public: standing changes record theirs in
the transaction that changes the standing, and `record_revocation` records operator entries (candidate,
projection, receipt, policy; supersession; a population entry is refused because populations are revoked by
standing changes). Eligibility counts an obligation from the moment it is recorded, before the feed carries it.

### Destination contract

`FeedDestination::put(feed, sequence, bytes)`: create-if-absent; identical bytes again succeed; different
bytes for an existing sequence are refused (`destination_conflict`, never overwritten, never marked
delivered). Readable by consumers with no private-ledger or runtime-store access. Holds only these documents.
Writes are in order. `MemoryFeed` and `DirFeed` (temporary file then hard link, so a reader never sees a
partial file and an existing sequence is never replaced) implement it; a real destination (static hosting, an
object store) is C12/deployment and must meet this contract.

### Consumer verification steps

What a downstream system without private-ledger access does (`custodian_lifecycle::FeedConsumer` is a working
reference; C11 implements the equivalent in its own repository):

1. **Pin the feed identity and the signing keys** out of band (the public verification keys and their
   authorization for the `revocation-envelope` domain). Never take keys from the feed.
2. **Fetch** `known + 1`, then `known + 2`, until a sequence is absent. If `n + 1` is absent but `n + 2`
   exists, there is a **gap**: stop, accept nothing past it, alert.
3. For each envelope: strict canonical decode (size cap, unknown fields rejected, bytes equal to their
   canonical form); `feed_id` equals the pinned feed; verify the Ed25519 signature over
   `domain || 0x00 || canonical(payload)` under a pinned key valid at `issued_at` for that domain.
4. **Replay**: a sequence already accepted with identical bytes is harmless. **Fork**: a correctly signed,
   different document for an accepted sequence is an alarm and is never resolved silently. An unsigned
   imitation is just a bad signature.
5. **Chain**: `sequence = head + 1` and `previous` equals the head's document digest; otherwise reject.
6. **Standing of a projection** (`RevocationLog::standing`), at time `now`: a matching entry makes it
   `Revoked` (also `contaminated`) or `Superseded`, decided from whatever state is held, so a stale feed can
   revoke but never validate; otherwise it is `Stale` unless the log is for the projection's feed, at or
   beyond its `min_sequence`, and `now <= fresh_until` of the head, and `now` is before the projection's own
   `fresh_until` (then `Expired`). Only `Valid` may be relied on.
7. **Re-evaluation trigger**: on each sync and clock tick, re-evaluate tracked projections and re-evaluate
   whatever support was derived from each that stopped being `Valid` (`FeedConsumer::reevaluate` reports only
   losses; regaining validity is not a trigger). Product support decisions stay the consumer's.

## 6. Operator-only actions (implemented by C10: the `custodian lifecycle` and `custodian feed` commands, see docs/operator-runbook.md)

All run through the same authorization as everything else; none is an agent tool. Each takes an
`OperatorAuthorization { actor, kind, authorization }` and an idempotency key; a repeat with the same key and
content replays, the same key with different content is `idempotency_conflict`.

| Action | API | `OperatorAction` | Agent | Output |
| --- | --- | --- | --- | --- |
| Report contamination | `EpochManager::report` | `report_contamination` | `unreviewed_change` only | outcome; permanent kinds retire the epoch |
| Clear an unreviewed change | `EpochManager::clear` | `clear_unreviewed_change` | no; human only | outcome |
| Retire an epoch | `EpochManager::retire` | `retire_epoch` | no | outcome, feed obligation |
| Rotate to a new epoch | `EpochManager::rotate` | `rotate_epoch` | no | link, budgets, activation |
| Reconcile registry with store | `EpochManager::reconcile_registry` | (startup sweep) | n/a | count retired |
| Record a revocation or supersession | `FeedPublisher::record_revocation` | `record_revocation` | no | obligation |
| Publish or renew the feed | `FeedPublisher::publish`, `deliver_pending` | `publish_feed` | no | sequence, entries, deliveries |
| Reference for a projection | `FeedPublisher::feed_ref` | none (read) | n/a | `FeedRef` or `pending_obligations` |

Startup sequence addition: after the store opens and `recover` runs, call `reconcile_registry`, then
`deliver_pending`, then export. Gate wiring: build one `LifecycleEligibility` per deployment, pass it as the
`DisclosureService` eligibility, and wrap every `RunLedger` in `GuardedRunLedger`.

## 7. Failure and recovery

| Situation | Behavior |
| --- | --- |
| Store unreachable or busy | refusal (`store_unavailable`); eligibility `unknown`; nothing changes; every operation is retry-safe |
| Crash in a standing change | all or nothing (one transaction); a retry replays |
| Crash in rotation, report or publish | see section 2 and the publisher paragraph; rerun converges |
| Destination down | the envelope is durable; the consumer sees nothing new and its feed goes stale (fail closed); `publish` delivers when it is back |
| Destination holds other bytes | `destination_conflict`; never overwritten; human review |
| Signer unavailable or refuses | nothing appended; obligations stay pending |
| An obligation cannot be translated (unknown public naming) | `unpublishable`; nothing published; eligibility still refuses; fix the naming and publish |
| Clock earlier than the head | `clock_skew`; nothing published |
| Restored older database | eligibility `unknown` and all writes refuse until reconciled |
| Key compromise | revoke the key (C7), publish `key_compromise` entries for affected projections, supersede records under a new key |

## 8. Evidence

| Claim | Evidence |
| --- | --- |
| State machine: never downgrade, only unreviewed change clears, retirement one-way, evidence effects | `custodian-core/src/standing.rs` tests |
| Database refuses downgrade, un-retire, edits, deletion, feed gap and fork | `custodian-store/tests/epoch_standing.rs` (`the_database_itself_refuses...`, `the_feed_is_contiguous...`) |
| Gates in reserve, retry, start and exposure; exposed attempt settles consumed; unexposed refunded | `epoch_standing.rs` (`contamination_blocks...`, `a_running_unexposed_attempt...`) |
| Contamination vs dispatch and vs reservation, real threads | `epoch_standing.rs` (`contamination_racing_with_start...`, `..._reservation...`) |
| Crash at every new transaction boundary | `epoch_standing.rs` (`crash_at_the_standing_change...`, `crash_at_the_obligation_feed_delivery_and_rotation...`) |
| Idempotent retries and conflicting reuse | `epoch_standing.rs`, `epochs.rs` |
| Clearing authorization, agents report only, permanent never clears | `custodian-lifecycle/tests/epochs.rs` |
| Rotation: new epoch, new budgets, old state untouched, crash at each step | `epochs.rs` (`rotation_gives...`, `crash_at_every_rotation_boundary...`) |
| Dispatch: refund before exposure, store gate alone, revoked candidate, exposed attempt, retired epoch | `custodian-lifecycle/tests/dispatch.rs` |
| Release: prepare refusal, before and after each gate, real-thread race, restore, activation, revoked policy | `custodian-lifecycle/tests/release.rs` |
| Historical receipts auditable, no re-release | `release.rs::historical_receipts_stay_auditable...` |
| Feed: replay, fork, gap, misorder, forgery, wrong feed, domain separation | `custodian-lifecycle/tests/feed.rs` |
| Feed: concurrent publishers, crash points, outage, conflicting destination, no private detail | `feed.rs` |
| Synthetic consumer: freshness, revocation, contamination, re-evaluation | `custodian-lifecycle/tests/consumer_demo.rs` |

## 9. Limitations

* Whoever can write the database file as the service owner can add or alter rows; the triggers and the
  external checkpoints make this detectable, not impossible (C4, C7).
* A contamination that loses a race with a publication is published after the fact; see section 3 for the
  window and its bounds.
* Retiring the registry entry stops `ProtectedPopulations::open_verified`; an `unreviewed_change` is blocked
  by the store gate and the guard but the registry entry stays `active` until retired, so a caller that opens
  the population directly without the control plane is not stopped by the standing. The control plane is the
  only caller by design.
* The public naming of a population (`PublicPopulationNames`) must be the same object the disclosure service
  uses; a different mapping would publish entries that match no projection.
* An authorized reporter can block an epoch; an authorized human can publish a revocation. These are the
  accountable operator actions, recorded with actor and authorization reference, not agent actions.
* Single-operator reality: separation of reporter, reviewer and publisher is procedural.

## 10. Planned, implemented, deployed

| Item | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| State machine, store migration 0003, gates, audit events | yes | yes | no |
| Epoch manager, rotation, registry mirror and sweep | yes | yes | no |
| Eligibility, dispatch guard, prepare and release wiring | yes | yes | no |
| Feed publisher, destination contract, `MemoryFeed`, `DirFeed`, reference consumer | yes | yes | no |
| Operator CLI over these APIs (`custodian-cli`, ADR 0080 to 0082) | yes (C10) | yes (synthetic tests) | no |
| Authority over a reviewed operator policy file (ADR 0081), activation source over the store (ADR 0083) | yes (C10) | yes (synthetic tests) | no |
| Real feed destination, signer process, key provider | yes (C12) | no | no |
| Benchmarks-side consumer and legacy contamination import | yes (C11) | no | no |
