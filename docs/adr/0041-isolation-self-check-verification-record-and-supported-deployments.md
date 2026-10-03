# 0041. Isolation self-check, verification record and supported deployments

- Status: accepted (design); implemented in `crates/custodian-worker` (C6); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

CONVENTIONS.md: "record verification of enforcement rather than a descriptive network flag alone".
ARCHITECTURE.md: "the deployment must prove its sandbox configuration and failure behavior; containers alone
are not an assurance statement". A manifest, a config boolean or the presence of Docker proves nothing about
what the kernel enforces on this host today.

## Options

| Option | Judged against: evidence of enforcement on this host, forgery resistance, fail-closed, maintainability |
| --- | --- |
| Run a probe inside the real sandbox at startup; refuse to build a dispatcher unless every check passes | Tests the actual mechanism including host-side canaries; the record is produced only by that code |
| Trust a configuration flag or "isolation: enabled" manifest | Descriptive only. Rejected |
| Check for `bwrap` or Docker presence | Presence is not behavior. Rejected |
| Verify only in CI | CI proves the mechanism on the CI image, not the production host. Necessary, not sufficient |
| Defer | Rejected |

## Decision

1. `run_self_check` runs `custodian-worker-probe` inside the sandbox that will run engines, with quotas,
   a host canary file, canary launcher environment variables named like ledger, App, DB-admin, GitHub and AWS
   credentials, and a host loopback listener. The probe prints one `PASS`/`FAIL` line per required check
   (`egress_denied, host_files_absent, env_scrubbed, write_outside_scratch_denied, scratch_writable,
   pid_namespace, no_capabilities, rlimits_applied`). The host requires exactly those lines in order, a clean
   exit, and that the host listener saw no connection. `scratch_writable` is a positive control.
2. The result is an `IsolationVerification` (`#[non_exhaustive]`: only this module constructs a `Verified`
   one) holding the sandbox kind, grade, per-check results, probe digest, launcher version, platform and
   time. `Dispatcher::new` accepts only a `Verified`, all-passed record for the same sandbox kind, and refuses
   one older than `verification_max_age_secs`. Each `DispatchReport` carries the record it ran under so the
   audit retains evidence, not a flag.
3. `RefusingSandbox` cannot pass; the test fake cannot pass (`run_self_check` refuses it) and is accepted
   only by `Dispatcher::new_for_tests` with a record marked `TestOnlyNotIsolated`, which exists only with the
   `test-fakes` feature.
4. A failed self-check returns `SelfCheckError { reason, failed_checks, probe_ended }`: fixed vocabulary
   only, so an operator can see which check failed without any probe output.
5. **Skip policy for tests.** Isolation tests that need Linux with bubblewrap log
   `ISOLATION-TEST-SKIPPED <name>: <reason>` and return when the host cannot run them, and fail instead when
   `CUSTODIAN_REQUIRE_ISOLATION=1`. The Ubuntu CI job `worker-isolation` sets it and also greps the log for a
   skip and for `ISOLATION-VERIFIED`. A skipped test is never evidence. Docker on a developer machine is a
   convenience for debugging, not evidence.
6. **Supported deployment** (docs/worker-isolation.md section 8): Linux 5.14 or later, unprivileged user
   namespaces, bubblewrap 0.8 or later, `prlimit`, a dedicated non-root worker account distinct from the
   control-service, DB, storage, signer and ledger identities, a root-owned non-writable artifact allowlist
   root, an owner-only local staging base. The deployment must prove the self-check on the production host and
   image at start and after changes, that any container adds no capability, mount or credential, and record an
   explicit risk decision for any shared-host or privileged arrangement. Other platforms are unsupported.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| A dispatcher cannot exist without a passing self-check on its own sandbox kind | `product_constructor_refuses_the_fake_and_the_refusing_backend` |
| The probe output must be exactly the required checks | `isolation::tests::probe_output_must_be_exactly_the_required_checks` |
| The self-check detects real enforcement on a real sandbox | `linux_self_check_records_real_verification` (CI) |
| A skip cannot pass CI | CI step `Isolation tests (must run, must not skip)` |

## Adapter contract

`run_self_check` takes `&dyn Sandbox`; every backend is checked by the same probe.

## Failure and recovery

Check fails or the probe cannot run: no dispatcher, no run, `SelfCheckError` for the operator. A stale
record: the dispatch is refused (`VerificationStale`) before reservation work is consumed (`fail_before_start`,
refunded). Re-run the self-check and rebuild the dispatcher.

## Performance evidence plan

Measure the self-check duration at startup and per periodic re-check. Not measured yet.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Self-check, verification record, fail-closed construction | yes | yes | no |
| Periodic re-check scheduling in a service | yes | no (caller re-runs; C10/C12) | no |
| Production host proof | yes | no | no |

## Consequences, migration, exit

C8, C11 and C12 consume `IsolationVerification` from the report. Adding a check is additive: add it to
`REQUIRED_CHECKS` and the probe together.

## Open risks and revisit triggers

- The probe runs in the same sandbox but cannot prove the absence of every escape; it proves the
  checks it makes. Add checks when a new threat is identified (for example a cgroup or seccomp layer).
- A sandbox that behaves differently for the probe than for an engine (an adversary aware of the probe) is
  out of scope for a self-check; the periodic re-check and host controls address drift, not adversarial probes.
