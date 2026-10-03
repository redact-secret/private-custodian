# 0132. The full synthetic flow job, deployment examples and the server-prerequisite checklist

- Status: accepted; implemented; nothing is deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The follow-up epic (#27, ADR 0110) targets an implementation that is complete and verifiable **without a
server**. Its last issue (#33) closes the loop: one place that runs the whole synthetic flow, configuration
examples a human can adapt later without any real value in the repository, and a single list of what a human
must do once a server exists.

## Decision

1. **A dedicated workflow, `full-synthetic-flow.yml`**, one job, Linux, `contents: read`, no secret, no
   protected data, no production key, no ledger token, no server or cloud resource. Its name and summary state
   that it is functional verification on public synthetic conformance data and not an independent protected
   evaluation. It installs bubblewrap exactly as `worker-isolation` does (that job is unchanged) and runs
   `crates/custodian-daemon/tests/full_flow.rs` with `CUSTODIAN_REQUIRE_ISOLATION=1`: a signed webhook,
   approval, reservation, the engine in the real sandbox, the isolated signer over a Unix socket, a local Git
   ledger, the destination-bound v2 projection, `custodian-verify` and the bridge consumer, then
   contamination, revocation, rejection and the consumer's re-evaluation trigger. It fails if the isolated
   variant is skipped. The same job runs the restore-drill, loss-acceptance, key-revocation and re-issue
   variants and the hostile negatives. All test keys are generated inside the job.
2. **Deployment examples under `deploy/examples/`**, every value a placeholder, with a test
   (`crates/custodian-daemon/tests/deploy_examples.rs`) that scans the directory for real-looking values
   (addresses outside the documentation ranges, real domains, key material, tokens, email addresses, absolute
   home paths), has negative controls so the scanner cannot silently go blind, parses each JSON example with the
   real parser of its component, and keeps the systemd hardening directives, the layout modes and the proxy
   example consistent with the daemon example. The two example files that lived in `docs/` moved here; their
   tests follow them.
3. **`docs/server-prerequisites-checklist.md`**: one checklist, in dependency order, each item with what, who,
   evidence to record and the repository document or command that verifies it. It covers everything from host
   requirements to the benchmarks authority cutover gates; the GitHub App webhook is last, after every other item.
4. **`docs/release-readiness.md` is refreshed** into four separated parts (implemented and verified and where it
   ran; not verifiable without a server; manual settings and decisions; remaining issues and next-work order),
   with a short completion report at the top. Publication and protected runs stay NO-GO.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| The full flow works end to end; the consumer rejects after contamination and reports the downstream trigger | `full_flow.rs` (both variants); CI marker `FULL-FLOW-VERIFIED full_flow_real_bubblewrap` |
| The workflow declares no secret, pins every action, states what it is | `crates/custodian-verify/tests/workflow_matrix.rs` |
| The examples contain no real-looking value; the scanner finds each category | `deploy_examples.rs::{every_example_is_free_of_real_looking_values, the_scanner_has_teeth}` |
| The examples are accepted by the real parsers; units keep hardening | `deploy_examples.rs` |

## Failure and recovery

If the isolated variant is skipped on Linux the job fails (marker grep and `CUSTODIAN_REQUIRE_ISOLATION`). On
macOS the isolated variant logs `ISOLATION-TEST-SKIPPED` and proves nothing; only the CI run is evidence.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Full-flow job and test | yes | yes (CI evidence is the run on the pull request) | no |
| Examples and scanner | yes | yes | no |
| Checklist and readiness refresh | yes | yes (documents) | no |

## Consequences, migration, exit

Adding an example file requires passing the scanner. Adding a real value anywhere under `deploy/` fails CI.

## Open risks and revisit triggers

The scanner is a net for accidents (a short TLD list, pattern-based key detection); it is not a secret scanner
and does not replace the history scan. Revisit if an example needs a value the scanner cannot tell from a real
one.
