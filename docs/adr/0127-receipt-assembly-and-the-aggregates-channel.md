# 0127. Receipt assembly from a dispatch report and the aggregates channel

- Status: accepted and implemented against a synthetic engine fixture; real engines do not emit this yet
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The disclosure path needs an `ExecutionRecord`, an `InternalReceipt` and a `private-custodian.aggregates/1`
artifact. The worker result carried only a roster. The question (also raised in the pii-eval hand-over) is how
the aggregates leave the engine.

## Options

1. A file in `/scratch`. Rejected: scratch is a namespace-private tmpfs; exposing it would need a writable host
   bind, which widens the isolation boundary.
2. A second stdout document. Two parse paths.
3. An optional `aggregates` object embedded in `worker-result/1` (additive).

## Decision

Option 3. `ValidatedResult::aggregates_bytes()` returns the canonical bytes; the existing size, shape and
unknown-field rules apply, and the disclosure crate's `PrivateAggregates::decode` validates it against the
receipt it will be bound to. A result without aggregates is valid for the worker and is closed by the pipeline
(`no_aggregates`).

Assembly rules (`src/pipeline/assemble.rs`):

- ids derive from the attempt id; times come from the attempt's transition history;
- outcome from the settled attempt state: `Success` only for a completed, fully observed run, `Partial` only
  when observed < expected, otherwise no receipt;
- attestation: `independence` follows the plan purpose, `role_separation` follows the approval, authorship and
  review come from a declaration in the daemon config, organizational independence is `not_claimed`, ground
  truth is `not_established`;
- population and roster must match the registry `entry_count`; any drift refuses.

The fixture `custodian-synthetic-engine` prints such results for both domains; **real engines do not emit
`worker-result/1` with aggregates yet**, a cross-repository job. This ADR and the fixture are the contract
those engines must meet.

## Security properties claimed

`tests/engine.rs` (the fixture's output passes the worker and disclosure validators; its failure modes are
rejected with fixed reasons), `tests/pipeline.rs`, `custodian-worker` tests `staging_result.rs` and
`dispatch_fake.rs`. Not claimed: that any real engine is correct.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Assembly in production code | yes | yes | no |
| Real engine emits aggregates | yes | no | no |

## Consequences, migration, exit

Additive to `worker-result/1`; old results remain valid. Functional verification on public synthetic data, not
independent protected evaluation.

## Open risks and revisit triggers

Attestation fields come from declarations, not evidence; they are labelled as such in the receipt. Revisit
when an engine repository ships the emitter.
