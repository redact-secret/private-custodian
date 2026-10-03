# 0042. Dispatch order, identity verification, staging and result protocol

- Status: accepted (design); implemented in `crates/custodian-worker` (C6); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0021 requires write-ahead exposure (`record_exposure` committed before protected bytes are opened),
treats uncertain attempts as consumed, and makes a retry a new, charged attempt. ADR 0004 and the C2
contracts freeze engine, adapter, scanner, candidate, configuration and population identities in the plan and
require crashes never to be clean scans and results to cover the authorized roster. ARCHITECTURE.md requires
immutable staging, hash checks before and after execution, and validated, bounded results. Engines are
pinned binaries, never source imports.

## Options

| Option | Judged against: TOCTOU, exposure ordering, bounded untrusted output, engine independence |
| --- | --- |
| Copy once while hashing, mount read-only, re-hash at three points, validate a strict versioned stdout document | No gap between the checked and the used bytes; bounded; no free-form text path |
| Hash the source path, then run from it | TOCTOU between hash and exec. Rejected |
| Let the engine write a result file anywhere | Larger surface, needs a writable result mount, harder to bound. Rejected |
| Parse a lenient JSON result | A silently growing allowlist is a leak path (docs/contracts.md section 8). Rejected |
| Defer | Rejected |

## Decision

1. **Order** (`Dispatcher::run_attempt`): isolation verification fresh and matching; quotas from the plan
   capped by operator caps; every artifact resolved through the allowlist and its SHA-256 verified against the
   plan (`fail_before_start`, refunded, on any failure or a cancelled token); `start` (lease); stage and
   hash-while-copying, then re-hash staged copies; cancel check; **`record_exposure`**; corpus `open` (verifies
   the whole epoch); population binding must equal the plan's; entry names and materialize each input as a new
   read-only regular file; write the job document; a last re-hash of staged copies; run with a heartbeat;
   re-hash staged copies, source files and the input shape; `begin_validation` (clean exit only); validate;
   `finish`. A failure after `start` and before exposure is a holder `finish` (refunded by the store); after
   exposure it is consumed.
2. **Artifacts.** Paths must be absolute, resolve under an allowlisted owner-only root, be regular files
   with one link, no symlink in the final component or any ancestor, no group or other write bit on the file
   or its directories. The digest comparison covers engine, adapter, every scanner, candidate (plain SHA-256)
   and configuration. Staged copies are 0500 or 0400 in a 0700 directory and mounted read-only.
3. **Result protocol v1** (`private-custodian.worker-job/1`, `private-custodian.worker-result/1`): the engine
   prints one strict JSON document on stdout, at most 64 KiB. Unknown fields, duplicate keys, trailing data,
   other schema versions, another domain or protocol, a roster other than the authorized one, inconsistent
   counters or status are rejected. The only strings that travel are the enumerated labels the contracts
   already validate. stderr is counted and discarded. A worker that did not exit cleanly is never parsed.
4. **Outcome mapping** to `custodian_contracts::execution::ExecutionOutcome`: see docs/worker-isolation.md
   section 7. `Success` requires a clean exit, `complete`, observed = expected and failed = 0. Anything else
   that parsed is `Partial`; invalid output or drift is `Rejected`; crash, signal, timeout, non-zero exit or
   output over its bound is `Failed`; cancellation is `Cancelled`. The mapping to the store reason uses
   `ReasonCode` only.
5. **Ports.** The dispatcher drives `RunLedger` and `CorpusPort`. `StoreRunLedger` adapts
   `custodian-store` (lease, heartbeat, exposure, validation, finish) and `PopulationsCorpus` adapts
   `custodian-corpus`. A lost lease (`LeaseLost`, from cancel or recovery) stops the worker, returns a
   `Cancelled` report with `settled = false`, and never calls `finish`.
6. Engine measurement logic stays in credential-eval and pii-eval. This crate does not parse a score.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Exposure is committed before the corpus is opened | `both_domains_succeed_in_control_plane_order`, `success_completes_and_consumes_with_exposure_committed_before_open` (real store) |
| Changed engine, adapter, scanner, candidate or config is rejected before exposure | `identity_tampering_before_dispatch_fails_closed_before_exposure`, `identity_mismatch_before_start_is_refunded_and_unexposed` |
| Staged copy changed after staging is rejected before the engine runs | `identity_tampering_after_staging_fails_closed_and_never_runs` |
| A source changed during execution is rejected even after a clean run | `source_changed_during_execution_is_rejected_even_if_the_run_was_clean` |
| Symlinks, hard links, writable files and paths outside the allowlist are refused | `artifacts_outside_the_allowlist_or_linked_are_refused` |
| Unsafe input names, overwrite and links in staging are refused | `materialization_refuses_unsafe_names_overwrite_and_links` |
| Malformed, oversized, wrong-roster and unknown-field results are rejected | `validator_rejects_malformed_inconsistent_and_oversized_results`, `malformed_oversized_and_mismatched_results_are_rejected` |
| Crash, signal, timeout and floods are never clean | `crash_signal_exit_timeout_and_floods_are_failed` and the Linux dispatch test |
| Secret-shaped stderr is not propagated | `stderr_with_secret_shaped_text_is_not_propagated` |
| Fenced lease stops the worker and does not settle | `a_fenced_lease_stops_the_worker_and_does_not_finish`, `cancel_in_the_store_fences_the_holder_and_stops_the_worker` |
| A tampered protected entry fails closed after exposure | `tampered_protected_entry_fails_closed_after_exposure` |
| Duplicate dispatch of a started attempt is refused | `duplicate_dispatch_of_a_started_attempt_is_refused` |

## Adapter contract

`RunLedger` and `CorpusPort` (`custodian_worker::ports`) are the seams; the store and corpus adapters are
the first implementations, recording fakes are the test doubles. A different store or corpus implements
the same traits and must preserve the order in the decision.

## Failure and recovery

Control service crash after `start`: the lease lapses; `recover` settles the attempt (ADR 0021): failed and
consumed once exposure may have occurred. A ledger error while settling returns `Err(LedgerUnavailable)`
and relies on that recovery. A retry is a new attempt that re-passes every check and is charged again.
Staging is removed on every path; a crash can leave a staging directory, which the operator removes (a
cleanup procedure for C12).

## Performance evidence plan

Measure separately: allowlist resolution and hashing, staging copy, input materialization, sandbox start,
engine execution, post-run hashing, result validation, and store calls. Not measured yet.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Dispatch order, identity checks, staging, result protocol v1, outcome mapping | yes | yes | no |
| Store and corpus adapters | yes | yes | no |
| Engine implementations of protocol v1 in credential-eval and pii-eval | yes | no (cross-repository, C11) | no |
| Private result artifact storage and receipt issuance | yes | no (C7) | no |

## Consequences, migration, exit

Protocol v1 is exact: a new field or schema is a new version (`.../2`), never an in-place change. Engines
need a small adapter to speak it. `Partial` outcomes are private failure records and never releasable; C7
must not issue a receipt for an engine-reported partial result whose observed count equals expected.

## Open risks and revisit triggers

- Large artifacts are copied per run; cache by digest in a read-only store if startup cost matters.
- Inputs are staged on the host filesystem (owner-only, removed afterwards). A tmpfs staging base or
  encrypted staging may be required before real protected data; revisit with the protected-run decision.
