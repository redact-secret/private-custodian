# 0143. EC2 remote worker adapter boundary and bounded job/result delivery

- Status: proposed; offline port, synthetic provider double and tests implemented in
  `crates/custodian-worker-ec2`; no live host, no AWS client, worker and control-plane NO-GO unchanged
- Date: 2026-10-06
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions
  are project-maintained, not independent validation.
- Tracking: issue #42 under epic #40; builds on ADR 0127, 0133, 0140, 0141, 0142; coordinates #44 and #72

## Context

`Sandbox::run` consumes local staged paths and a synchronous heartbeat (ADR 0133). An EC2 worker
(ADR 0141) with a fresh instance per attempt (ADR 0142) is a remote boundary, not a drop-in
`Sandbox`. The prior MicroVM prototype (`custodian-worker-microvm`, ADR 0133/0140 evidence) is kept
unchanged and reused for its `AttemptBinding` and result envelope.

## Decision

### Adapter boundary

The adapter lives outside the domain core and is not selectable in the daemon. It owns only: the
durable attempt record, calls through a vendor-neutral `Provider` port, and verification. It does not
authorize, reserve budget, settle, sign, canonicalize, validate aggregates or release. Exposure,
export and lease answers come from a `Gates` port backed by the store/ledger, never from the worker
or from a result. The worker host holds no DB, Git, signer or ledger credentials, and the provider
credentials used by the adapter are separate from the worker role (ADR 0142 inventory).

### Wire, version and size rules (no new schema field)

- Input is exact `worker-job/1` bytes, at most `MAX_JOB_BYTES` (= `MAX_RESULT_BYTES`, 64 KiB), whose
  SHA-256 equals `AttemptBinding.job_digest`; the exact staged bytes are checked, not a reserialization.
- Output is the existing `private-custodian.remote-result/1` envelope (`schema`, `binding`, `stdout`,
  unknown fields denied) of at most `MAX_ENVELOPE_BYTES`; `stdout` is one `worker-result/1` of at most
  64 KiB, validated by the existing `validate_result` with embedded aggregates (ADR 0127). No scratch
  file collection, no second canonicalizer, no new field in worker-job/1, worker-result/1 or the envelope.
- Instance identity is not a wire field. It is established by the authenticated provider port plus the
  durable record below. Result parsing alone never establishes a live fence or trusted execution.

### Pinned identities and per-attempt binding

Binding pins (existing): request, approval, reservation, execution, attempt (1-16), nonzero fence,
plan, candidate, config, runner image digest and version, engine, adapter, scanner digests, job digest.
`HostPins` adds the immutable AMI id (`ami-` plus 8-17 lowercase hex, never an alias) and the digest of the
reviewed AMI manifest. The launch idempotency token is a SHA-256 derivation over execution, attempt,
fence, plan, candidate, config, job digest, AMI id and manifest digest, so a different identity can never
share a token. A `begin` with the same execution and attempt but a different binding or pins is a
`Conflict`; a lower fence is `StaleFence`.

### Durable state and phases (custodian-owned)

Record per (execution, attempt): binding, pins, token, phase, instance id, result digest, version,
written by compare-and-swap (`AttemptStore`). Phases: `LaunchIntent` -> `Launched` -> `Delivering` ->
`Delivered` -> `Settled` -> `Terminated`, plus `Ambiguous` and `Failed`.

1. `begin` records intent BEFORE any provider call.
2. `launch` is idempotent on the token. A provider error (for example a lost response) moves to
   `Ambiguous`; no input is delivered and `launch` is refused until `reconcile`.
3. `deliver` requires phase `Launched`, a job within bounds matching the digest, a current lease
   fence, exposure and export acknowledgements, and a provider `describe` of the exact recorded
   instance whose token, AMI id, manifest digest and `Running` state match. `Delivering` is written
   before the send. Inputs are never sent to an ambiguous, stale, terminated, foreign or re-imaged
   instance.
4. `collect` requires `Delivered`, a current fence, the same instance check, a result envelope whose
   binding equals the durable binding, and a result digest equal to any earlier one (different bytes
   are a `Conflict`; identical bytes are idempotent).
5. `terminate` is idempotent, never reuses an instance, and ends settled attempts as `Terminated` and
   every other attempt as `Failed`.
6. `reconcile` after restart uses custodian state only: `LaunchIntent`/`Ambiguous` adopt an instance
   found by token (an ambiguous one is terminated and fails closed); `Delivering` is possible exposure,
   terminated, never redelivered. A retry is a new attempt, a new fence and a new instance.

### Concurrency and idempotency

All transitions are version compare-and-swap; a concurrent loser gets `Store(Conflict)` and retries from
the record. Provider launch is idempotent on the token, so racing launches converge on one instance
(tested). `begin`, `launch`, `collect` and `terminate` are idempotent; `deliver` is at-most-once by
construction (`Delivering` precedes the send).

## Security properties claimed (synthetic, project-owned)

Tests in `crates/custodian-worker-ec2/tests/adapter.rs` cover: round trip with input and result identity;
malformed, oversize, conflicting and wrongly bound results; altered or oversize jobs; each closed
gate; stale fence; wrong or re-imaged or terminated instance; idempotent begin/launch; lost launch
response; restart before and after provider create; crash after delivery start; concurrent launch.

## Not claimed

A verified EC2 host, real transport authentication (the port requires it; the double has none), live
isolation, key provisioning (#72), crash reconciliation against the real store and janitor (#44),
dispatcher or startup integration, measured cost, or independent validation. The in-memory store is not
durable; the production store mapping (SQLite table and migration) is not built. No protected data, key
or AWS identifier is involved.

## Open work for #42

Real provider implementation and authenticated transport (separately authorized, #40), SQLite attempt
table with migration, `Gates` backed by the real `RunLedger`/store, dispatcher integration, runner image
inventory evidence, and the live synthetic rehearsal.
