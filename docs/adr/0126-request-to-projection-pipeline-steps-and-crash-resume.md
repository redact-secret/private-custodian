# 0126. Request-to-projection pipeline: steps, idempotence and crash resume

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

R-3: no production code carried an approved request through dispatch, receipt assembly, disclosure
preparation and release. Each step has external effects (a spent budget unit, a signature, a delivered
envelope), so a crash anywhere must neither duplicate an effect nor produce a clean-looking receipt.

## Decision

`crates/custodian-daemon/src/pipeline` runs one pass per control-loop tick over durable state in
`pipeline_runs` (migration 0007). The step is monotone:

`enrolled` -> `dispatched` -> `assembled` -> `prepared` -> `released` (or `closed` with a fixed reason, from any
earlier step).

1. **Enroll** an approved, unenrolled attempt (or cancel and refund it when its installation or repository was
   removed: the scope guard). Idempotent by attempt id.
2. **Dispatch** only after `startup_check` and the export-drain preflight pass. The worker persists the
   validated result through the `ResultSink` hook **before** the attempt is settled; a sink failure ends the
   attempt `Failed` with `ledger_unavailable`. A crash after exposure leaves a lapsed lease that recovery
   settles as consumed.
3. **Assemble** only from a settled attempt. The settled attempt state decides the outcome, never the stored
   result. `Partial` only when observed items < expected; a crash, an unreadable result or any drift yields
   `closed`, never a clean receipt (ADR 0127).
4. **Prepare** (`prepare_bound`) with a persisted `prepared_at`. A replay after a crash pins the clock to that
   value (`PinnableClock`, pinned only around `prepare_bound` so that eligibility's live-clock activation
   observation still matches) and the write-once prepared mark makes the replay idempotent.
5. **Release** only with a distinct human approval read from `approvals_dir/<request_id>.json` (checked mode,
   strict decode, bound to the v2 projection digest). The daemon never creates or signs an approval. Delivery
   goes through an idempotent `DirSink`.

Feed publication stays a human operator action (ADR 0081); the daemon only delivers pending envelopes.

## Security properties claimed

`tests/pipeline.rs` (17), `tests/crash.rs` (4, injected failures at every new fault point and resume to the
same final state), `tests/e2e.rs` (real listener to verified release), `custodian-store/tests/pipeline.rs`
(14: monotonicity, write-once artifacts). Released output is accepted by `custodian-verify` in
`tests/common/verify.rs`.

## Failure and recovery

Every step reads durable state first and does only what is missing. Refusal paths close with a fixed reason
and apply the existing budget rules (exposed means consumed).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Pipeline and resume | yes | yes | no |
| Real engine output | yes | no (ADR 0127) | no |

## Consequences, migration, exit

Functional verification on public synthetic data, not independent protected evaluation.

## Open risks and revisit triggers

Only one pipeline pass runs at a time per root (single writer, HG-6).
