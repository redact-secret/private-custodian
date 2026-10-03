# 0100. Operational readiness validation and the code-only release posture

- Status: accepted (design); validation implemented and run on synthetic data (C12); nothing deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

C1 to C11 built the custody, isolation, ledger, disclosure, lifecycle, operator and bridge layers, each tested
on its own. The parent epic asks whether the whole is operationally sound and whether the code could be made
public later (SECURITY.md "Public release gate"). Nothing is deployed and nothing external is provisioned: no
host, signer, private ledger, feed destination, operator policy or live GitHub App exists. The honest question
for C12 is therefore what can be shown with synthetic data and test-generated keys, what remains for humans,
and what the gap register looks like.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Validation | extend each crate's tests only; one cross-layer suite over the real components; defer to deployment |
| Sandbox in cross-layer tests | require Linux and bubblewrap everywhere; an in-process scripted `Sandbox` for control-plane behavior plus the existing `worker-isolation` CI job for real isolation |
| Crash testing | add more per-crate tests; a sweep that injects a crash at every reachable boundary of a full run and checks end-state properties, with a coverage rule over the fault points |
| Readiness result | declare ready when tests pass; a per-item report with pass, fail, not assessable, a gap register with dispositions and an explicit go or no-go |
| Provisioning | create the ledger repository, keys and policy now; document exactly what a human must provision and approve |
| License | pick one; list the options and leave the decision explicit |

## Decision

1. **One cross-layer suite** in `crates/custodian-cli/tests/c12_*.rs` drives the real operator CLI, SQLite store,
   sealed protected-population root, dispatcher, ledger exporter, disclosure service, feed publisher and the
   benchmarks-side consumer, on synthetic data, with keys generated inside each test. It adds no production
   dependency (`custodian-bridge` is a dev-dependency of `custodian-cli`).
2. **The sandbox in this suite is a test double** (`Scripted`, kind `TestOnlyUnsandboxedFake`), accepted only by
   `Dispatcher::new_for_tests`. It proves ordering, settlement, exposure and result handling; it proves nothing
   about isolation. Real isolation evidence stays the `worker-isolation` CI job (`CUSTODIAN_REQUIRE_ISOLATION=1`).
3. **Every `FaultOp` is accounted for.** `c12_crash_windows.rs` fails when a fault point is neither fired by the
   sweep nor named with the test that covers it, so a new fault point forces a decision.
4. **Leakage is tested by canaries on every output path**, with a negative control proving the scan can fail
   (`c12_leakage.rs`), plus a guard that library code has no ad-hoc logging.
5. **Measurements are separate and non-gating** (`examples/c12_measure.rs`, `docs/measurements.md`). They never
   relax isolation, skip audit writes or reset budgets, and they do not include scanner or kernel time.
6. **`docs/release-readiness.md` is the readiness record.** Every gate item is pass, fail or not assessable with
   an evidence path; every known gap has a disposition (fixed here, accepted with rationale, or blocker with an
   owner role); the go or no-go is explicit. The expected and recorded result is NO-GO for publication and for
   deployment until the human items are done.
7. **No external provisioning.** Documents (`docs/deployment-runbook.md`, `docs/incident-response.md`,
   `docs/backup-recovery.md`) say what a human provisions and approves. Nothing in the repository creates a
   repository, key, host, policy or App, and no license is chosen: license selection stays a human decision with
   options listed in the readiness record.
8. **Claims.** A signature attests origin and binding of project-maintained records, not independent truth.
   Publishing the source does not by itself disclose or grant access to the runtime database, ledger, corpora,
   keys or credentials, provided the exclusions in the release gate hold; security does not rely on the source
   being private.

## Security properties claimed

| Property | Evidence |
| --- | --- |
| Pipeline crosses every layer and each negative variant stops at the right one | `c12_e2e.rs` |
| No double execution, no double charge, no refund after exposure, ledger still verifies, store still starts after a crash at any reachable boundary | `c12_crash_windows.rs`, `c12_crash_intake.rs` |
| Concurrent budgets, duplicate dispatch, contamination racing reservations | `c12_concurrency.rs` |
| Restored older database cannot double spend or republish; the residual window is exact | `c12_restore_drill.rs` |
| Ledger rollback, holes and forged records are found; outages keep events pending | `c12_keys_and_ledger.rs` |
| Revocation races, with the one known gap pinned | `c12_revocation.rs` |
| Canaries absent from every output, storage and publication path | `c12_leakage.rs` |

## Failure and recovery

The suite itself fails closed: an unreached fault point, a missing coverage entry, a leaked canary or a changed
refusal code fails the build. A test that cannot run (no network for the advisory database, no Linux) is
reported as not assessable, never as passed.

## Performance evidence plan

`docs/measurements.md`: request latency, queue limits, database contention and ledger export growth, each
described as one machine on one day.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Cross-layer synthetic suite, crash sweep, restore drill, leakage canaries | yes | yes | no |
| Measurements | yes | yes (one machine) | no |
| Incident response, deployment runbook, backup and recovery documents | yes | yes (documents) | no |
| Readiness record and gap register | yes | yes | no |
| Any deployment, key, ledger, host or App | yes (humans) | no | no |

## Consequences, migration, exit

The suite is additive. Gaps it found are registered (docs/release-readiness.md); designs for the larger ones are
in ADR 0101 and ADR 0102. Revisit when a service exists: the restore drill and crash sweep must then run
against the real process boundary, and the measurements must be repeated on the production host class.
