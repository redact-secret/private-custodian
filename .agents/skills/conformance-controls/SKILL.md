---
name: conformance-controls
description: Plan, write, or audit the public synthetic conformance tests that prove custody lifecycle behavior (concurrency, duplicate dispatch, budget exhaustion, crash after exposure, cancellation, malicious output, isolation denial, cross-run reuse, invalid bindings, suppression, signing refusal, recovery). Use when adding tests or judging acceptance readiness.
---

# Conformance controls

Reference: [_shared/identities-and-lifecycle.md](../_shared/identities-and-lifecycle.md),
[_shared/data-handling.md](../_shared/data-handling.md).

Source of truth: `ARCHITECTURE.md` Acceptance and `CONVENTIONS.md` Testing. Ordinary CI uses public synthetic
data only. These controls prove mechanism, never protected-corpus independence or holdout quality; say so in
test names, docs, and reports.

## Required coverage matrix

Build or audit a matrix, one row per scenario, with status `tested` / `missing` / `not assessable`:

| Scenario | Must demonstrate |
| --- | --- |
| Authorization denial, stale plan, changed plan | Rejected before any reservation |
| Wrong candidate / engine / scanner / config identity | Rejected pre- and post-execution |
| Duplicate dispatch, duplicate request | One run, one charge |
| Concurrent reservation of the last unit | Exactly one wins |
| Budget exhaustion (run, release/query, CPU/time/storage) | Denied; recorded |
| Lease loss, crash before exposure | Safe retry; refund per policy |
| Crash / cancellation after exposure | No silent refund; recorded as post-exposure |
| Cancellation | Child process tree cleaned up |
| Malicious output (oversize, malformed, partial roster, forged counters) | Rejected; bounded; no free-form leakage |
| Filesystem and network denial | Worker cannot reach host creds, egress, or other runs |
| Cross-run reuse of results or authorization | Rejected |
| Invalid bindings / receipts | Verifier rejects |
| Suppressed strata and composition | Overlapping totals do not reveal a suppressed cell |
| Signing refusal | Signer rejects unapproved or unvalidated projection |
| Restart and recovery | State, budget, audit consistent; no double publication |
| Redaction | Safe synthetic error fixtures never appear in logs or public output |

## Rules for the tests

- Exercise concurrency and failure, not only sequential success. Prefer deterministic fault injection and
  recorded schedules over sleeps.
- Fixtures are unmistakably synthetic; the corpus used is a public control, never a protected one.
- Performance measurements (coordinator latency, worker startup, validation, resource use, engine time) are
  taken separately. Never relax isolation, skip audit writes, or reset budgets to speed a benchmark.
- Identify the test command from the repository; if no test framework exists, report that fact instead of
  inventing one.

Output: the matrix, gaps ranked by risk, and for each gap the smallest test that would close it.
