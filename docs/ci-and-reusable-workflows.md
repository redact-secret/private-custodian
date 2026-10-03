# CI, the build workflow and the reusable verification workflow (S1)

Design decision: [ADR 0110](adr/0110-serverless-verification-with-github-actions.md). Follow-up to C11 (the bridge
and its reference consumer, [benchmarks-integration.md](benchmarks-integration.md)); tracked in issue #28
(epic #27).

> **What these workflows are.** Functional verification on public synthetic data, with test-generated keys.
> They show that the code builds, that the synthetic suite passes, and that another repository can check a
> signed public result bundle against pinned public keys without any server. They are **not** an independent
> protected evaluation, they do not establish ground truth, and this repository is maintained by the Redact
> Secret project, so nothing here is independent validation.

## 1. What runs where

| Workflow | Trigger | What it does | Permissions |
| --- | --- | --- | --- |
| `ci.yml` | pull request, push to `main` | `rust` (fmt, clippy, the whole test suite including the C12 suite), `dependency-audit`, `worker-isolation` (Linux bubblewrap probes, `CUSTODIAN_REQUIRE_ISOLATION=1`, must not skip) | `contents: read` |
| `synthetic-conformance.yml` | pull request, push to `main`, manual | Calls the reusable workflow on the checked-in synthetic bundles, positive and negative; runs the C12 end-to-end, revocation and leakage tests; one aggregate status | `contents: read` |
| `verify-signed-results.yml` | `workflow_call` only | Verifies a bundle with `custodian-verify` and public pins; asserts the expected outcome | `contents: read`; no secrets |
| `build.yml` | PR touching code or workflows, push to `main`, `v*` tags, manual | Locked release build of `custodian-verify` and `custodian`, SHA-256 digests in the job summary, one-day artifact; provenance attestation only on tag push and manual dispatch | `contents: read`; the `attest` job alone adds `id-token: write` and `attestations: write` |

The **synthetic conformance** job set is: the `rust` job and the `worker-isolation` job in `ci.yml` (their
display names start with "synthetic conformance:") plus every job of `synthetic-conformance.yml`, which ends in
one aggregate job, "synthetic conformance (functional verification, not independent evaluation)". The
`worker-isolation` job is unchanged: it installs bubblewrap, enables user namespaces on the ephemeral runner,
runs the isolation tests with `CUSTODIAN_REQUIRE_ISOLATION=1` and fails if any test logs a skip.

### Forbidden in Actions

Nothing in this repository's workflows may receive, create, cache or print any of the following, in any
workflow, now or later:

- a protected corpus, a seed, or any protected population material;
- a production signing key, or any key that signs something a consumer would rely on;
- a private-ledger token or any credential to the private-ledger repository;
- webhook secrets, GitHub App credentials, deployment credentials, or cloud credentials.

No workflow declares `secrets:` or passes a secret, none uses `pull_request_target`, and no job calls a server
or a cloud resource. `crates/custodian-verify/tests/workflow_matrix.rs` fails if a workflow gains a `secrets`
reference, a `pull_request_target` trigger, an unpinned action, or an `id-token` / `attestations` scope outside
the `attest` job. Test keys are throwaway: their seed is a public constant in the fixture generator.

### Pinned actions

Every action is pinned to the full commit its release tag points at (a test checks the 40-hex form):
`actions/checkout` v4.2.2, `actions/upload-artifact` v7.0.1, `actions/download-artifact` v8.0.1,
`actions/attest-build-provenance` v4.2.2. The SHAs were resolved with `gh api repos/<owner>/<repo>/commits/<tag>`.
Update them deliberately, together with the comment naming the tag.

## 2. The verifier: `custodian-verify`

A small CLI (`crates/custodian-verify`) over the C11 reference consumer. It takes public inputs only and has no
ledger, store, corpus, or signer. `tests/no_private_access.rs` keeps the C11 proofs: an entry-point type test, an
exhaustive pins struct, a source scan, and an exact dependency list. (Note: `custodian-ledger`, which provides
the public-key verifier, itself links the store crate; the verifier never calls it, and the source scan keeps it
from naming it.)

```
custodian-verify --bundle DIR --keys FILE --feed-id ID --expect FILE --now UNIX_SECONDS
```

- `--bundle` is a directory with exactly `manifest.json`, `projections/NNNN.json` and `revocations/NNNN.json`
  (1 to 8 digits; revocations in ascending sequence). The manifest is the bridge manifest; the documents are the
  canonical bytes of released projection envelopes and revocation envelopes.
- `--keys` is the pinned public keys file `private-custodian.verify-keys/1`: key id, 64-hex public key,
  purposes (`projection`, `revocation`; no ledger purpose is accepted), `valid_from`, optional `retired_at` and
  `revoked_at`. Public material only.
- `--feed-id` is the pinned revocation feed id.
- `--expect` is the expectations file `private-custodian.verify-expectations/1`: `domain`, `candidate`, `config`,
  `destination`, at least one accepted public `populations` entry and one accepted disclosure `policies` entry.
  The request the response must answer is rebuilt from this file, never read from the bundle, so a bundle cannot
  pick what it is judged against.
- `--now` is the time to judge at, in Unix seconds. The tool reads no clock; the workflow supplies it.

The bundle is untrusted. Every file is bounded before it is read (document cap of the contracts, manifest cap of
the bridge, 64 KiB for pins and expectations, at most 16 projections and 32 revocations); links, devices and
stray entries are refused; parsing is strict (closed schemas, canonical form checked by the consumer). The tool
prints no path, file name or file content, and never writes to standard error.

### Output and exit codes

Exactly one JSON line `private-custodian.verify-result/1` with `verdict` (`accepted`, `rejected`, `error`),
`exit_code`, `reason`, `projections_accepted`, `projections_rejected` (index and reason), `feed_applied`,
`feed_error`, `feed_sequence`, `now`, and a fixed `scope` sentence stating that the result is functional
verification, not an independent protected evaluation.

| Exit | Meaning | `reason` values |
| --- | --- | --- |
| 0 | accepted: every projection verified, the feed applied cleanly | `ok` |
| 10 | a projection was rejected, or none was present | `malformed`, `bad_signature`, `key_not_acceptable`, `wrong_domain`, `wrong_candidate`, `wrong_population`, `policy_not_accepted`, `wrong_feed`, `stale`, `expired`, `revoked`, `superseded`, `manifest_mismatch`, `no_projection` |
| 11 | the revocation feed failed verification | `feed_malformed`, `feed_bad_signature`, `feed_wrong_feed`, `feed_gap`, `feed_fork`, `feed_broken_chain` |
| 12 | the bundle answers another request, feed or destination | `wrong_request`, `wrong_destination`, `wrong_feed`, `malformed` |
| 20 | usage error | `usage` |
| 21 | an input file is unreadable, over a bound or not strictly valid | `input_unreadable`, `input_too_large`, `bundle_unexpected_entry`, `bundle_malformed`, `keys_invalid`, `expectations_invalid`, `feed_id_invalid` |

When several apply the order is 12, then 11, then 10. Unknown is not valid: a missing, old or behind-the-pin feed
state yields `stale`.

### Synthetic fixtures

`crates/custodian-verify/fixtures/synthetic/` holds one shared `keys.json` and seven bundles: `positive` (exit 0);
`stale-feed`, `wrong-domain`, `wrong-candidate`, `revoked`, `tampered` (exit 10, one reason each); `feed-gap`
(exit 11). They are derived artifacts of `tests/support/mod.rs` (the generation rule), not canonical evidence.
A test fails if a file differs from the generator; regenerate with
`UPDATE_FIXTURES=1 cargo test -p custodian-verify --test fixtures`. Every identity and digest is a visible
placeholder and the signing seed is a public constant.

## 3. The reusable workflow `verify-signed-results.yml`

Inputs (all strings; there are no secrets):

| Input | Required | Meaning |
| --- | --- | --- |
| `bundle-path` | yes | Bundle directory, relative to the caller checkout (or to the downloaded bundle artifact) |
| `bundle-artifact-name` | no | Take the bundle from an artifact of the same run instead of the checkout |
| `keys-file` | yes | Pinned public keys file in the caller checkout |
| `feed-id` | yes | Pinned feed id |
| `expectations-file` | yes | Expectations file in the caller checkout |
| `now` | no | Unix seconds; empty uses the runner clock |
| `verifier-source` | no | `build` (default) or `artifact` |
| `verifier-source-repository` | no | Build mode: repository to build from, default `redact-secret/private-custodian` |
| `verifier-source-ref` | build mode | Full 40-hex commit SHA; branch and tag names are refused |
| `verifier-artifact-name`, `verifier-sha256` | artifact mode | A binary from an artifact of the same run, accepted only if its SHA-256 equals the pin |
| `expected-exit-code` | no | Default `0` (must be accepted). A negative test sets the rejection code it expects |
| `expected-reason` | no | Optional fixed reason the result must carry |

Outputs: `exit-code`, `verdict`, `reason`, `result-json`. The job fails unless the verifier's exit code equals
`expected-exit-code` (and the reason matches `expected-reason`, if given). The outputs are also set when the job
fails. Inputs reach the shell only through environment variables, and paths with `..`, absolute paths, or
whitespace are refused.

**Build mode** checks out `verifier-source-repository` at the given commit with the caller's automatic
`GITHUB_TOKEN` and builds `custodian-verify` with `cargo build --release --locked`. That token can read only the
caller's own repository or public repositories. **Artifact mode** takes a binary your own earlier job produced
and fetched, and refuses it unless it matches the SHA-256 you pin. Obtaining that binary across repositories
(for example by downloading a release artifact and checking its attestation) is your job's responsibility and
may need a read credential of your own; this workflow never asks for one.

### Calling it from another repository

```yaml
jobs:
  verify:
    uses: redact-secret/private-custodian/.github/workflows/verify-signed-results.yml@<full-commit-sha>
    permissions:
      contents: read
    with:
      bundle-path: results/bundle
      keys-file: pins/verify-keys.json
      feed-id: fed_...
      expectations-file: pins/verify-expectations.json
      verifier-source-ref: <the same full commit sha>
```

Pin `@<full-commit-sha>` (a branch or tag can move). Keep the keys and expectations files in the caller
repository under review, not in the bundle. A caller that branches on rejection passes `expected-exit-code` for
the rejection it expects and reads `outputs.reason` in a later job; this repository's
`synthetic-conformance.yml` does exactly that for the `revoked` case.

### Maintainer-only setting for private reuse (not changed by this work)

While `redact-secret/private-custodian` is private, another repository can call the workflow only if the
maintainer allows it: **Settings > Actions > General > Access > "Accessible from repositories in the
`redact-secret` organization"** (the exact wording and plan availability are GitHub's; check the page). This
setting is repository-level and was not touched by S1. It lets the caller `uses:` the workflow; it does not let
the caller's `GITHUB_TOKEN` read this repository's contents, which is why build mode works only for a caller in
this repository or after publication, and why artifact mode exists. Leave it off until a caller needs it.

## 4. The build workflow `build.yml`

- Locked release build: `cargo build --release --locked -p custodian-verify -p custodian-cli`.
- A smoke test runs the freshly built verifier on the positive synthetic bundle.
- `sha256sum` of both binaries goes to the job summary and to job outputs.
- The binaries are uploaded as one artifact with `retention-days: 1`.
- `attest` (only on `v*` tag pushes and manual dispatch) downloads the artifact, checks it against the build
  job's digests, and runs `actions/attest-build-provenance`. It is the only job with `id-token: write` and
  `attestations: write`. Artifact attestations on a private repository need a GitHub plan that supports them; on
  a plan without that, the job fails visibly and nothing else is affected. This was not exercised from a PR
  because the job does not run on pull requests.
- It creates no release, publishes nothing, and calls nothing outside this repository.

### Trust model of the artifacts

A workflow artifact and a digest in a job summary tell a reader what this repository's CI produced from a given
commit. They do not make the binary trustworthy by themselves: whoever can edit the workflows or push to the
repository can change what is built. The provenance attestation binds the binary to the workflow, the commit and
the runner identity (verify it with `gh attestation verify`), which is useful evidence of where a binary came
from and not evidence that its verdicts are correct. A consumer that needs more should build from a reviewed
commit itself. The repository has one maintainer, so none of this is independent validation.

## 5. Not verified / limits

- The cross-repository call from a second real repository was not exercised; only calls from this repository
  (`./.github/workflows/...`) are tested in CI.
- The attestation job has not run (tag or manual dispatch only).
- Bundles are produced elsewhere (by a bridge transport that does not exist yet). The fixtures here come from a
  generator with a throwaway key; no production key, real ledger or real protected run exists or is used.
- No branch protection exists on this plan, so no workflow is a required check.
