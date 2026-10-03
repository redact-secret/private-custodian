# 0005. Contract set, internal versus public split, freshness and versioning

- Status: accepted (design baseline)
- Date: 2026-10-02
- Deciders (by role): repository maintainer (single human operator)
- Maintenance: this repository is maintained by the Redact Secret project; decisions here are
  project-maintained, not independent validation.

## Context

C3 to C9 and the sibling engines and benchmarks need frozen shapes for request, approval, reservation,
execution, receipt and disclosure (issue C2). The epic requires that benchmarks never read the private
ledger yet receive freshness and revocation updates, that a stale approval or a prior successful receipt
never bypasses revocation, and that legacy budget scopes and independence vocabulary stay representable
(ADR 0003). Custody and signatures do not prove independent ground truth (ADR 0001, T3).

## Options

1. One receipt type with a public view derived by omission. Rejected: omission is a filter, and a new field
   leaks by default.
2. Separate internal and public contracts, public as an explicit allowlist. Chosen.
3. Public consumers poll the private ledger for revocation. Rejected: benchmarks cannot read it.
4. A public, signed, chained revocation feed with explicit freshness. Chosen.

## Decision

### Contract set (`custodian-contracts`, schemas in `crates/custodian-contracts/schemas/v1/`)

| Contract | Side | Schema tag | Purpose |
| --- | --- | --- | --- |
| `EvaluationRequest` (+ `EvaluationPlan`) | internal | `private-custodian.request/1` | Exact frozen plan; plan digest is its identity |
| `Approval` | internal | `private-custodian.approval/1` | `execute` or `release` scope, bound to exact identities |
| `Reservation` | internal | `private-custodian.reservation/1` | Budget unit, scope, lease, exposure, settlement |
| `ExecutionRecord` | internal | `private-custodian.execution/1` | Frozen identities, attempt, outcome, exposure |
| `InternalReceipt` | internal | `private-custodian.internal-receipt/1` | Measured run; private artifact reference |
| `PolicyActivation` | internal | `private-custodian.policy-activation/1` | Activation, expiry, revocation state |
| `PublicProjectionEnvelope` | public | `private-custodian.public-projection/1` | Allowlisted aggregate plus signature |
| `SignedRevocationEnvelope` | public | `private-custodian.revocation-envelope/1` | Chained revocation and supersession feed |

Distinct Rust types exist for request, approval, reservation, execution and receipt identities; corpus,
epoch, family and lineage identities; candidate, config, artifact, population, result, plan and
projection digests (ADR 0004).

### Execution outcomes

`success`, `partial`, `failed`, `cancelled`, `expired`, `rejected` (artifact failed validation). Only
`success` is releasable. A measured result (`success`, `partial`) implies protected exposure. The refund
rule is the core rule (`budget_refundable`): refund only when no protected bytes were acquired and the
attempt failed, was cancelled or expired. `Reservation::settled_state` is the single implementation.

### Budget scopes

`BudgetScope::PopulationEpoch { corpus, epoch, family? }` models holdout (per population or family epoch).
`BudgetScope::CandidateLineageEpoch { corpus, epoch, family?, lineage }` models blind (per candidate
identity per epoch); the lineage identity, not the candidate digest, keys the budget, so a tuned copy with a
new digest does not get a fresh budget (ADR 0001, T2). Scopes are different variants and never one counter.
`BudgetKind` separates run budgets from release or query budgets. Resource budgets stay in
`ResourceLimits`.

### Freshness and revocation

- **Policy activation** records are append-only states with a rising `sequence`, a validity window and a
  status (`active`, `revoked`, `superseded`). Every approval, plan, execution and internal receipt carries
  an `ActivationRef` (policy, activation id, sequence seen).
- **Current-state check** (`policy::check_current`) runs at every use: reservation, execution start,
  release, and any reuse of a prior receipt. It fails closed when the observed state is older than
  `min(caller allowance, 300 s)` or dated in the future, names another activation, is revoked, superseded,
  expired or not yet active, or has a different sequence than the binding. Revocation and supersession
  beat every time window.
- **Approvals** also expire (`expires_at`, at most seven days) and are bound to the plan digest, candidate,
  population, budget scope, activation and request. A stale approval fails on any mismatch. Execution and
  release approvals are separate scopes; completing a run never authorizes release. An agent actor kind
  cannot approve; the stated role separation must equal the real principals and is always procedural.
- **A prior successful receipt is evidence, not permission.** `InternalReceipt::check_still_valid` runs the
  same current-state check; success in the past does not bypass later revocation.
- **Public side.** Each projection names a `revocation_feed` (feed id, minimum sequence) and its own
  `fresh_until` (at most 30 days). The feed is a chain of signed envelopes: strictly increasing sequence,
  `previous` digest link, cumulative entries, and a `fresh_until` renewed by publishing a new (possibly
  empty) envelope. `RevocationLog::standing` returns `Valid`, `Expired`, `Stale`, `Superseded` or
  `Revoked`. Revocation and contamination are decided first and from whatever feed state is held, so a
  stale feed can still revoke but can never validate. Missing, wrong-feed, too-old or expired feed state is
  `Stale`. Entries are never removed: a contaminated epoch stays contaminated (ADR 0003).
- Revocation entries use fixed reasons only (`contamination`, `epoch_rotation`, `key_compromise`,
  `policy_revoked`, `error_correction`, `newer_evidence`).

### Public projection allowlist

Fields: ids (projection, receipt, feed), domain, an opaque or keyed-commitment population reference,
candidate digest, engine identity, protocol, scope kind, disclosure policy reference, attestation, aggregate
cells (stratum label, metric label, integer numerator and denominator, or `suppressed` with no value),
issue and freshness times, feed reference, signature. Nothing else is representable. Labels come from a
lowercase alphabet; there is no prose field. Absent by construction: seeds, case or file identities, paths,
text, ranges, value-level hashes, errors, internal plan, corpus, epoch, family, lineage and population
digests, budgets, limits, actors, scanner and adapter configuration. Disclosure policy parameters (minimum
strata, composition rules, query budgets) are C8; the contract carries `suppressed` cells but does not
decide them.

### Independence and attestation

`IndependenceClaim` keeps the legacy vocabulary: `public-control`, `custodian-declared`,
`procedural-separation`. None means independent. `OrganisationalIndependence` has the single value
`not_claimed`; `GroundTruthClaim` has the single value `not_established`. `RoleSeparation` is
`single_operator_procedural` or `distinct_principals_procedural`. Expectation attestations are
`authorship` (`project_authored`, `external_authored_unverified`) and `review` (`not_reviewed`,
`project_reviewed`, `external_reviewed_unverified`): they record what the custodian operator declares and do
not verify an external party. Adding an organizational claim needs a reviewed schema revision.

### Versioning

See `docs/contracts.md`, "Versioning and compatibility". Summary: a schema tag ends in a major number;
v1 readers reject every other tag and every unknown field; additive change means a new major whose readers
accept the previous major; no document is reinterpreted in place; domain tags, schemas, policies,
protocols and store migrations version separately.

## Security properties claimed

Each is a contract-layer check with a named test, not a deployed control: stale or expired approval,
wrong request, plan, candidate, domain, population, budget scope and activation rejected
(`tests/bindings.rs`); revoked, superseded, expired, not-yet-active, stale-observed activation rejected;
prior receipt cannot bypass revocation; public standing fails closed; no exposed refund; legacy scopes and
vocabulary representable (`tests/bindings.rs`, `tests/negative.rs`); public schemas contain no forbidden
fields, internal types, internal id patterns or value-hash shapes (`tests/schemas.rs`).

## Adapter contract

Stores (C4) persist these documents and enforce atomicity; the signer (C7) signs `signing_input`;
disclosure (C8) builds `PublicProjection` and decides cells; benchmarks (C11) apply `RevocationLog`
semantics. None of them reinterpret a contract.

## Failure and recovery

Unavailable activation state, an expired feed or a missing feed means no execution, no release and no
reliance: reject or `Stale`. Replay of a feed envelope, a gap or a broken link is rejected and the held
state is kept. Recovery re-reads authoritative activation state; it never reuses a cached "valid".

## Performance evidence plan

Checks are in-memory comparisons plus one canonicalization and one hash; C4 measures them inside
reservation latency.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Contract types, checks and schemas | yes | yes (contract layer) | no |
| Activation store and clock source | yes (C4) | no | no |
| Feed publication, signing and verification | yes (C7, C9) | no | no |
| Consumer standing check in benchmarks | yes (C11) | no | no |
| Disclosure parameters and suppression rules | yes (C8) | no | no |

## Consequences, migration, exit

Changing an allowlist, a bound, an enum or an activation rule is a policy and schema revision (a new
major), reviewed explicitly. Legacy imports (C11) map into these shapes and record consumption; they do not
recompute it.

## Open risks and revisit triggers

Counts only: metrics that are not integer counts (for example means) need a schema revision with a leakage
review. Keyed commitments need a key lifecycle (C5, C7). One feed per deployment is assumed. The attestation
fields describe the first single-operator deployment honestly and must be revised if a second party or
organization takes part. The 300 s state ceiling and 7 day approval ceiling are starting values to revisit
with C4 measurements.
