# Aggregate disclosure, suppression and publication approval (C8)

Status: **implemented** in `crates/custodian-disclosure` (with budget and history storage in
`crates/custodian-store`, migration 0002, and a publication decision in `crates/custodian-ledger`) and
tested with synthetic data only; **not deployed**. No policy is activated, no budget is provisioned, no
destination exists and no key exists.
Decisions: [ADR 0060](adr/0060-disclosure-service-flow-and-type-level-separation.md) (flow and
separation), [ADR 0061](adr/0061-disclosure-policy-and-suppression-algorithm.md) (policy and suppression),
[ADR 0062](adr/0062-release-query-budgets-and-composition-accounting.md) (budgets and composition),
[ADR 0063](adr/0063-publication-decision-approval-and-failure-codes.md) (publication decision, approval,
failure codes).

This repository is maintained by the Redact Secret project. A released projection is project-maintained
evidence of origin, binding and history. It is not independent validation, and it does not establish ground
truth (`ground_truth` is always `not_established`, organizational independence `not_claimed`).

**Aggregate-only disclosure does not by itself guarantee privacy.** Suppression, budgets and approvals make
leakage harder and accountable. They do not make it impossible. See [Residual leakage](#residual-leakage).

## 1. Flow

```
 internal record (never leaves)                               public side
 ------------------------------                               -----------
 request/plan  approval(execute)  reservation  execution       DisclosurePolicy (versioned, ledgered)
 InternalReceipt  private aggregate artifact                         |
        |                                                            v
        v   1 prepare                                       PublicProjection (explicit allowlist)
 validate everything ----charge budgets----> decide cells ----build----> PreparedRelease (digest)
        |                                                            |
        |   2 release   (distinct Release approval, current activation, allowed destination)
        v                                                            v
 precondition clear + charge audit acknowledged -> sign (ApprovedPayload::projection)
        -> ledger `policy` + `publication` decision (durable) -> eligibility recheck -> Sink::deliver
```

`DisclosureService::prepare` (validate, charge, build) has no public effect. `DisclosureService::release`
requires a release `Approval` that binds the execution, the projection digest and the disclosure policy. The
approval is a different scope from the execution approval; completing a run authorizes nothing. An agent
cannot approve (the contract refuses to decode an agent approver, and the release check refuses a constructed
one).

### What `prepare` validates, in order

1. The disclosure policy is well formed (`policy_invalid`).
2. `check_disclosure_precondition(attempt)`: the attempt completed, settled, its terminal audit event is
   durably exported and the store is not awaiting reconciliation (`precondition_not_met`).
3. The complete internal record, before anything is built:
   - the plan names this disclosure policy (`policy_mismatch`);
   - the receipt and execution record are valid, `Success`, releasable, with a complete roster and no failed
     item (`receipt_invalid`, `receipt_not_releasable`, `roster_incomplete`; a Partial receipt with a complete
     roster cannot even be constructed, `InternalReceipt::validate`);
   - the execution record belongs to the store attempt, request and reservation (`provenance_mismatch`,
     `binding_mismatch`), and the receipt's plan digest, activation and frozen identities (candidate, engine,
     adapter, scanners, configuration, protocol, population) equal the plan's;
   - the execution approval is the one that authorized this plan, candidate and population;
   - evidence class: a conformance control is `public-control` and nothing else is. Public synthetic
     qualification is never presented as protected evaluation evidence, or the reverse;
   - the execution activation and the disclosure-policy activation are current and fresh
     (`activation_stale`, `activation_not_current`, `policy_stale`);
   - the private aggregate artifact hashes to the receipt's result digest, is strict (unknown fields rejected),
     names the frozen domain and protocol, repeats the receipt's roster, and every cell is inside the policy
     allowlist, complete, and consistent with the declared relations (`artifact_*`, `stratum_not_allowed`,
     `metric_not_allowed`).
4. Charge the budgets (see below). Everything above is free; from here the attempt counts.
5. Read the series history, decide the cells, build the projection, and append what it reveals to the
   history, conditional on the history that was checked.

### What `release` does, in order

Destination in the policy allowlist (`destination_not_allowed`); policy document unchanged since prepare
(`policy_stale`); projection inside its freshness window; `check_disclosure_precondition` again and the
charge's audit events acknowledged by the ledger (`audit_not_acknowledged`); the release approval checked
(`approval_wrong_scope`, `approval_not_bound`, `approval_expired`, `approver_not_permitted`, activation
reasons); the eligibility hook (C9); signing only through `ApprovedPayload::projection`, which re-validates
the projection and the approval; the `policy` ledger record and then the `publication` decision record, both
durable (`ledger_unavailable`, `ledger_conflict`); the eligibility hook once more; and last, delivery
(`delivery_failed`). Nothing is delivered if any step fails. A decision record may exist for a release that
was then not delivered; it is a decision, not a delivery. Repeating the release writes identical records.

## 2. The public projection

A projection is built field by field. The builder names every public field of `PublicProjection` and copies
in only values that are public by contract: the candidate digest, the engine identity, the protocol, the
policy reference, the attestation (as recorded by the signed receipt), the cells, and the feed reference. It
never starts from an internal record and removes fields.

Excluded by construction: protected text, seeds, case identities, ranges, per-case hashes, logs, free-form
errors, plan/corpus/epoch/family/lineage identities, adapter and scanner identities, configuration and
population digests, request, approval, reservation and execution identities, and budgets. The public receipt
and projection identities are derived from the release key by a domain-separated hash, so they equal no
internal id. Population identity is an opaque reference or a keyed commitment (`PublicPopulationNames`),
never a plain hash.

Type-level separation: `Sink::deliver` takes a `ReleasedEnvelope`, which has private fields and a
crate-private constructor. No internal type converts into one, so an internal record cannot be handed to a
destination (two `compile_fail` doctests in `released.rs`). `PrivateAggregates` and `PreparedRelease` print
no values in `Debug`. The crate contains no logging or printing path (`tests/leakage.rs` checks the source).

## 3. Disclosure policy

A `DisclosurePolicy` (`private-custodian.disclosure-policy/1`) is a closed document. A change is a new policy
version and a new activation, never an edit.

| Field | Meaning |
| --- | --- |
| `policy` | `PolicyRef` of kind `disclosure`, domain, name, version |
| `strata` | Publishable strata with a dimension label. **Order is the suppression preference**: earlier strata are withheld first |
| `metrics` | Publishable metrics (integer counts only) |
| `total_stratum` | The stratum covering the roster |
| `relations` | `total = sum(parts)` for numerators and denominators, per metric. Overlapping dimensions are several relations over the same total |
| `min_stratum_size` | A cell whose denominator is below this is never published |
| `min_interval_width` | A withheld cell must remain uncertain over at least this many integer values |
| `perturbation` | `{"mechanism":"none"}`. Nothing is rounded, noised or bucketed. Any other mechanism is a new schema major with stated measurement consequences |
| `budgets` | `per_population`, `per_lineage`, `per_requester`, `units_per_attempt` |
| `withheld_attempts`, `failed_attempts` | `"charged"` (one value each): an attempt that got past validation costs budget whether or not it released |
| `audit` | `"acknowledged"`: release needs the durable ledger acknowledgement |
| `destinations` | Allowed destination labels |
| `freshness_secs` | Reliance window of a released projection |
| `state_max_age_secs` | Oldest activation state a release may use (at most 300) |

The canonical document digest (domain `private-custodian/v1/ledger/policy`) is what the `policy` ledger
record carries (`DisclosurePolicy::ledger_record`). A reviewer compares the digest of the document they read
with the ledger. `DisclosureService::provision_budgets` applies the stated limits (limits only rise).

## 4. Suppression algorithm and its limits

Per metric, strata are variables with a numerator and a denominator, related by the policy's linear
relations. A published cell makes its variable known. An observer solves the relations for the rest.

1. **Primary.** Withhold every cell whose denominator is below `min_stratum_size`.
2. **Gather knowledge.** This release's reported cells, plus every cell an earlier release in the same
   population series already published (numerators of the same measurement; denominators of the
   population), plus the relations of every earlier release's policy.
3. **Find exposed cells**, separately for numerators and denominators: unknown variables that are
   *determined* by the relations (exact rational row reduction over the unknown columns) or whose interval,
   by non-negativity and bound propagation over the relations, is narrower than `min_interval_width`.
4. **Complementary (secondary) suppression.** For the first exposed variable, withhold the first cell, in
   policy order, that shares a relation with it and whose withholding removes the exposure (else the first
   candidate), skipping cells already public. Repeat from step 3.
5. If nothing can be withheld to make the release safe, **refuse** (`composition_unresolvable`).

The choice in step 4 uses only structure, the policy order and published values, never a withheld numerator,
so the pattern of withheld cells does not depend on the secrets it protects beyond the (public) fact that
primary cells are small.

Across successive releases the same algorithm runs over the union of what was revealed, so a later request
cannot difference a cell hidden earlier against a cell published earlier. A release whose values contradict
an earlier one for the same measurement or population (non-determinism, a changed population) is refused
(`measurement_conflict`): repeated runs are not allowed to be averaged against each other.

Evidence: `tests/composition.rs` shows an adversary recovering a small cell from a naive publication and from
two sequential releases, then failing against the real decisions; it enumerates every integer assignment of
the unpublished cells that satisfies the relations (a complete oracle for these structures) and runs a
randomized check of hundreds of tables and three-release sequences. Unit tests cover a three-way cycle that
single-unknown solving misses.

### Residual leakage

- **Declared structure only.** The algorithm protects against relations the policy declares. A relation that
  exists in the data but not in the policy is invisible to it.
- **Interval test is not linear programming.** Bound propagation can overstate the uncertainty on cyclic
  overlapping structures. The exact test is complete for linear relations, but combined with integer or
  coupling constraints (for example numerator not above denominator across unpublished cells) an observer may
  narrow a cell further than the algorithm assumes. `min_interval_width` is a stated tolerance, not a proof.
- **Reported cells.** A published cell with a numerator of 0 or equal to its denominator reveals every member
  of that stratum's outcome. `min_stratum_size` bounds how few members that can be; it does not hide uniform
  outcomes.
- **Suppression is itself a signal.** That a cell is withheld tells an observer it was small or complementary.
  Primary suppression discloses "denominator below the minimum".
- **Per-requester and adaptive tuning.** Budgets bound how often a requester may ask, not what a patient
  requester learns across many candidates. Colluding requesters have separate requester budgets (the
  population and lineage budgets still apply). Adaptive tuning against a held-out population is reduced, not
  prevented; protected failures are never exposed to developers or agents, only approved summaries.
- **Timing and error channels.** Failures are fixed reason codes; Checks show one of three coarse core codes.
  Latency of a release, of a refusal and of a charge is not equalized.
- **External knowledge.** Anything an observer knows from outside (the corpus authors, a public dataset,
  another system) is outside the model.
- **Small populations.** With few strata and tight budgets the algorithm may refuse or publish only the roster
  total. That is the intended fail-closed behavior.
- **No noise.** Published numbers are exact. This keeps measurement semantics simple and makes the leakage
  above exact too.

## 5. Budgets and composition accounting

Cumulative release and query budgets live in the store (`budgets`, kind `release_query`), keyed by:

- the population epoch (and family) scope: all requesters and candidates;
- the candidate-lineage scope, when the plan's budget scope is a lineage (blind evaluation);
- the requester: `ReleaseScope::Requester(actor)`.

A charge draws `units_per_attempt` from every applicable scope in one transaction, all or none
(`ChargeOutcome::Charged`, `Exhausted`, `NotProvisioned`), is final (no refund path), is idempotent per
release key (`Replayed`), and writes an outbox event per scope that the exporter sends to the private ledger.
Release needs those events acknowledged. Limits only rise; consumption never resets; a restored older
database is blocked by the existing `needs_reconcile` rule (every write refuses, including charges).

Policy: a request that fails before validation completes reveals nothing about protected data and is not
charged (rate limiting of malformed requests is the intake edge's concern). From the charge on, a released,
withheld, failed or conflicting attempt is charged. Exhaustion itself is audited (`disclosure.denied`).

History (`disclosure_history`, append-only) holds, per population series, what each release made public:
relations in force and reported cells with a measurement identity. Withheld values are never stored. An
append is conditional on the sequence the caller read (`history_conflict`); the retry replays the charge and
recomputes. A prepared-but-not-released projection stays in the history: it is treated as revealed, which can
only make later decisions more conservative.

## 6. Publication decision and verification

The `publication` ledger record carries the projection digest and identities, the signing key, and a
`PublicationDecision`: destination, disclosure policy, execution, release approval id, approver and approver
kind. It is written (durably, idempotently) before any signed byte leaves, one per destination.

`verify_release(envelope_bytes, decision, expected_destination, verifier)` checks, using public keys only:
strict canonical parse of the envelope, its signature, the decision's signature, that the decision is a
publication decision, the projection digest, the projection and receipt identities, the signing key, the
disclosure policy, and that the decision approved exactly the destination presented.

Limit: `PublicProjection` has no destination field (a new schema major would add one). A consumer without
access to the private ledger can verify signature and digest, not the destination binding. Operators,
auditors and the publisher gate in front of a destination can verify all of it. The destination is public
configuration, not a secret.

## 7. Reason codes

Every refusal is a fieldless `DisclosureReason` (`as_str()` is the stable code). A GitHub Check is rendered by
`custodian_intake::checks::CheckPost::render` from fixed strings and one core code; `to_core()` maps to only
`budget_exhausted`, `store_unavailable` or `disclosure_not_permitted`, and `check_update` has no string
parameter, so a Check cannot carry a finer code, a value or an identity.

| Group | Codes |
| --- | --- |
| Gate and audit | `precondition_not_met`, `audit_not_acknowledged`, `store_unavailable`, `ledger_unavailable`, `ledger_conflict` |
| Internal record | `receipt_invalid`, `receipt_not_releasable`, `roster_incomplete`, `binding_mismatch`, `provenance_mismatch` |
| Artifact | `artifact_malformed`, `artifact_mismatch`, `artifact_incomplete`, `artifact_inconsistent`, `stratum_not_allowed`, `metric_not_allowed` |
| Policy and activation | `policy_invalid`, `policy_mismatch`, `policy_stale`, `activation_stale`, `activation_not_current` |
| Approval and destination | `approval_not_bound`, `approval_wrong_scope`, `approval_expired`, `approver_not_permitted`, `destination_not_allowed`, `destination_mismatch`, `digest_mismatch` |
| Budgets and composition | `budget_exhausted`, `budget_not_provisioned`, `composition_unresolvable`, `measurement_conflict`, `history_conflict` |
| Release | `eligibility_denied`, `signing_refused`, `signer_unavailable`, `delivery_failed` |
| Verification | `envelope_invalid`, `signature_invalid` |

## 8. Hooks for later issues

- **C9 (revocation, contamination, epoch rotation).** Implement `ReleaseEligibility` over revocation and
  epoch records and pass it to `DisclosureService`. It is called twice per release (before any ledger write and
  again immediately before delivery) with the candidate, population binding, execution and projection digest.
  The revocation feed reference is supplied by the caller in `PrepareInput::feed`. `PublicProjection` carries
  the feed reference and `fresh_until`; revocation of an already-released projection is a signed revocation
  envelope (C7 `ApprovedPayload::revocation`), not a disclosure operation. There is no default eligibility:
  `testing::UncheckedEligibility` exists for tests and says so.
- **C10 (operations).** The core `Disclosure` port (opaque string identities) is not implemented: it cannot
  carry a digest-bound `Approval`. The typed `DisclosureService` replaces it; retire or adapt the port when the
  control service is wired.
- **C11 (benchmarks).** Consume `PublicProjectionEnvelope` plus `RevocationLog`. Destination binding needs the
  `publication` record or a schema major that adds a destination field.
- **Engines.** The private aggregate artifact (`private-custodian.aggregates/1`) is the input contract. The
  current worker protocol (`worker-result/1`) returns only roster counters, so no engine emits strata yet.

## 9. Evidence

| Claim | Evidence |
| --- | --- |
| Leakage: canaries in every input, error, Debug and Check path | `crates/custodian-disclosure/tests/leakage.rs` |
| Unknown fields, wrong provenance, destination, digest, stale activation, budgets, pending export, ledger down, eligibility | `crates/custodian-disclosure/tests/release.rs` |
| Differencing across overlapping strata and successive releases fails | `crates/custodian-disclosure/tests/composition.rs` |
| Budgets atomic, final, idempotent, concurrent | `crates/custodian-store/tests/disclosure.rs` |
| Verifier round trip | `release.rs::full_release_round_trips_through_the_verifier` |
| Type split | `released.rs` doctests |

## 10. Planned, implemented, deployed

| Item | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Policy, suppression, composition, budgets, projection builder, release flow, verifier | yes | yes | no |
| Policy activation, budget provisioning, destinations, signer, private ledger | yes (C10 to C12) | no | no |
| Engine emission of the aggregate artifact | yes | no | no |
| Revocation and contamination recheck | yes (C9) | hook only | no |
| Destination field in the public contract | open | no | no |
