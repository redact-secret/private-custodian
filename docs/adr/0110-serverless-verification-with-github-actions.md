# 0110. Server-less verification with GitHub Actions: a verifier CLI, a reusable workflow, a locked build and a synthetic conformance set

- Status: accepted
- Date: 2026-10-03
- Deciders (by role): project maintainer (sole maintainer)
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The follow-up to the benchmarks bridge (issue #1, C11) needs an implementation that can be built and verified
without any server: GitHub Actions builds and runs the synthetic tests, and other repositories verify signed
public results through a reusable workflow. The reference consumer (ADR 0090) already verifies with public keys
and pins only. Hosted runners are shared, ephemeral and reachable by anyone who can change a workflow, so
nothing that protects holdout integrity may enter them. Threats: a bundle crafted to exhaust or confuse the
verifier, an injected workflow input, a swapped binary, a pull request that exfiltrates a secret, a result read
as stronger than it is.

## Options

1. **Defer** until a transport and a server exist. Judged: leaves the consumer path unproven end to end.
2. **A hosted verification service.** Judged: a server, a credential and a cost; out of scope, and a bigger
   target.
3. **A thin CLI over the C11 consumer plus a reusable workflow, with synthetic fixtures** (chosen).
4. A composite action instead of a reusable workflow. Judged: runs inside the caller's job and permissions,
   cannot constrain its own permissions to `contents: read`.

## Decision

- Add `crates/custodian-verify`: a std-only CLI over `BridgeConsumer`, public inputs only, strict bounded
  parsing of an untrusted bundle, one sanitized JSON result, fixed reason codes and stable exit codes
  (0, 10, 11, 12, 20, 21; `docs/ci-and-reusable-workflows.md`).
- Add `verify-signed-results.yml` (`workflow_call`, `contents: read`, no secrets, pinned actions). It builds the
  verifier from an exact commit SHA or accepts a binary pinned by SHA-256, and passes only when the observed
  exit code equals the expected one.
- Add `build.yml`: locked release build, SHA-256 digests, one-day artifact, and a provenance attestation only on
  tag push or manual dispatch, in the one job that holds `id-token: write` and `attestations: write`.
- Add `synthetic-conformance.yml` and label the existing `rust` and `worker-isolation` jobs as the "synthetic
  conformance" set. `worker-isolation` is unchanged, including `CUSTODIAN_REQUIRE_ISOLATION=1`.
- Check in synthetic fixtures generated deterministically with a public throwaway key, plus the generator, and
  test that the files equal the generator output.
- **Forbidden in Actions:** protected corpus, production signing key, private-ledger token, webhook secrets,
  deployment or cloud credentials. No workflow declares or passes a secret; a test enforces it.
- Every result states that it is functional verification on public data and not an independent protected
  evaluation.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| The verifier takes public inputs only | `custodian-verify/tests/no_private_access.rs` (entry-point type, exhaustive pins, source scan, exact dependency list) |
| An untrusted bundle cannot exhaust or confuse it | `tests/hostile_input.rs` (size bounds before read, counts, strays, links, strict keys and expectations) |
| A bundle cannot choose what it is judged against | request rebuilt from the caller's expectations; `hostile_input.rs::a_rewritten_bundle_cannot_choose_its_own_judge` |
| Each rejection class gives its documented exit code and reason | `tests/fixtures.rs` through the real binary; the CI caller matrix |
| A negative case passes only if rejected exactly as expected | the reusable workflow's exact-match assertion; the caller's output assertion |
| No secret, no `pull_request_target`, pinned actions, attestation scopes only in `attest` | `tests/workflow_matrix.rs` |
| Output never echoes input | `fixtures.rs::rejected_output_never_echoes_input_text` |

These are properties of tested code and workflow text, tamper-evident where a digest or attestation is
involved, not tamper-proof.

## Adapter contract

None added. The verifier consumes `BridgeConsumer`, `Verifier` and `Keyring` as they are; no port changes.

## Failure and recovery

Every failure is a fixed exit code and reason; nothing is retried or defaulted. An unreadable, oversized or
malformed input is exit 21, never a pass. A missing or old feed state is `stale`. A caller whose job fails can
re-run it; no state is kept.

## Performance evidence plan

None. Build mode compiles the verifier per call; the synthetic caller builds once and shares the binary by
digest.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| `custodian-verify` CLI and fixtures | yes | yes (synthetic) | no |
| Reusable verification workflow | yes | yes (called from this repository in CI) | no |
| Build workflow and provenance attestation | yes | build yes; attestation not yet run | no |
| Cross-repository reuse | yes | not exercised from a second repository | no |
| A bridge transport producing real bundles | no | no | no |

## Consequences, migration, exit

A schema major change of the public documents (for example the destination schema work) changes the fixtures;
regenerate them and the test shows the diff. The result and key/expectation file schemas are versioned
(`/1`); changes are additive. Private reuse needs a maintainer-only repository setting that this work does not
change. Exit: delete the three workflows and the crate; nothing else depends on them.

## Open risks and revisit triggers

- Build mode cannot read a private source repository with a caller's default token; artifact mode needs the
  caller to bring a pinned binary. Revisit at publication.
- Attestation for a private repository depends on the GitHub plan.
- `custodian-ledger` links the store crate transitively, so the verifier binary is larger than it needs to be.
  Splitting the public-key verifier out of the ledger crate is a larger change owned elsewhere.
- Solo maintainer: a workflow change is reviewed only by its author (ADR 0103).
