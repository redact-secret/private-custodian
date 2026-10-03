---
name: sast-sweep
description: Run static analysis over private-custodian's coordinator, worker launcher, artifact validator, disclosure service, signer, and agent tools for unsafe execution, path handling, races, and sensitive-data leakage. Report-only unless fixes are requested.
---

# SAST sweep

Shared rules: [_shared/README.md](../_shared/README.md). Report shape: [_shared/finding-format.md](../_shared/finding-format.md).

Select analyzers from the languages and manifests that actually exist; record tool versions, rule sets, and
scope. If there is no source yet, report that and stop.

## Prioritized patterns

- Command construction: shell strings, string-concatenated argv, non-allowlisted engine or scanner paths.
- Path traversal, symlink and hardlink escape, archive extraction (zip-slip, bombs) before materialization.
- Unsafe deserialization of engine/scanner output; schema validation after the data is already consumed.
- Check-then-act on budget, lease, or state: non-atomic read-modify-write, missing compare-and-swap, missing
  idempotency key, time-of-check/time-of-use on candidate bytes between verification and execution.
- Budget refund or reset reachable from crash/cancel/error paths after protected exposure.
- Secrets, seeds, case IDs/paths, value hashes, raw stderr, or tokens in logs, exceptions, metrics, traces, or
  test output; string-interpolated errors.
- Disclosure projection built by denylist instead of allowlist; free-form error text in public output.
- Signing reachable from agent or scanner-adjacent code; hard-coded keys or key paths.
- Non-constant-time comparison of tokens or digests; weak or non-canonical digest inputs.
- Unbounded stdout/stderr capture, missing timeouts, orphaned child processes.
- Nondeterministic iteration in canonical serialization.

Triage every hit against surrounding code. Report severity, `path:line`, data flow, existing guard, impact on
custody, budget, or disclosure, and a regression test. Do not report design-level gaps as SAST findings; route
them to `owasp-review` or `run-lifecycle-review`.
