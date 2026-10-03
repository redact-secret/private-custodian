# Exact pii-eval adoption handoff (#37)

Custodian decisions: [ADR 0133](adr/0133-pii-worker-contract-and-synthetic-adoption.md).
Read against pii-eval PR #29 merge `6157cbc5918b3888c8e84b1884719ea8f3278b36` and issue #30.
This handoff is independent of GitHub App creation and webhook activation; both remain deferred.
Only public synthetic conformance data is authorized for this integration work.

## Contract to adopt

| pii-eval slot | Required production adapter |
| --- | --- |
| `stage-layout` (Q9) | Fixed `/stage`, `/input`, `/scratch`; engine is the real CLI; adapter is shim bundle; candidate is package bundle; scanner-0 is pinned Node; config is `pii-eval-worker-config/1` |
| `bundle-format` (Q4) | Engine-owned `pii-eval-bundle/1` bounded regular-file archive; verify file digest before safe scratch extraction and distinct tree digest after extraction |
| `entry-format` (Q1) | Engine-owned `pii-eval-worker-entry/1`, one authored case per opaque flat entry; `roster = entries.len()`; no new authoring logic in custodian |
| `aggregates-channel` (Q2) | Embedded JSON object in ONE `private-custodian.worker-result/1` stdout document; total <=65536 bytes; no scratch/stderr collection |
| `aggregate-labels` (Q3) | Closed nine-label profile, stratum `overall`, below; `measurable-share` omitted from these cells only, retained in engine-private measurement |

Exactly these labels:

```text
type-miss-rate
wrong-family-rate
wrong-jurisdiction-rate
sensitive-miss-rate
non-sensitive-flag-rate
context-discrimination-rate
benign-suppression-rate
jurisdiction-collision-rate
range-collateral-rate
```

No new labels or dimensions are inferred from engine output. Operational release still requires a reviewed,
versioned, activated disclosure policy with minimum sizes, composition and cumulative budgets. HG-9 remains
open. Do not copy the synthetic test policy into an operational activation.

The invocation remains `/stage/engine --job /job/job.json`, `pii-v1` version `2`, `sha256:` file pins,
strict worker-job/result v1, and the existing environment and resource limits. The config's bare semantic
population digest is checked by the engine; it is never compared to the custodian's keyed custody commitment.
Both are bound by the pinned config and plan. No freshness/expiry field is added.

Coverage is unchanged: after all entries are read, scanner failures produce `complete`, `observed == expected`,
`failed > 0`, exit 0 and no aggregates. Custodian records a consumed `Partial` execution without a releasable
receipt. `partial` requires genuinely incomplete coverage. Never falsify `observed` or clamp denominators.

## Files and exact implementation work for pii-eval #30

[tools/engines/pii-adoption.patch](../tools/engines/pii-adoption.patch) is an applyable reference patch against
the merge SHA. It changes only worker adapters/result transport and their default-wiring tests:

1. Install five `Decided` adapters in `Adapters::production()`; preserve production rejection of Proposed
   and TestOnly adapters and absence of an operator/environment selector.
2. Keep existing bounded bundle/entry codecs and staged digest verification. Do not reinterpret roles in
   custodian core or substitute the tree digest for the candidate file digest.
3. Render the aggregate object into `WorkerOutput.result`; bound the entire serialized result after embedding.
   Remove file/stderr channel behavior from production. The reference embedded adapter has no I/O; the
   renderer is the only delivery. A renderer failure prints no result.
4. Preserve the kernel/pipeline and numerator/denominator accounting. Whitelist the nine emitted labels.
5. Update worker default tests to expect job parsing after adapter resolution, retaining no test marker,
   malformed/missing job refusal and exact alias checks. Parse the bounded job before resolving stage
   directories; malformed input must not access staged artifacts. Add embedded-object and whole-document size tests.
6. Update feature integration/replica tests and `worker_test_engine` to use embedded delivery, eliminating the
   old scratch/stderr assumptions. The reference patch intentionally does not port all TestOnly example
   transport tests; that example is used here **only to author synthetic fixtures**, never as the engine.
7. Update `docs/worker-job.md`, ADR 0015, `custodian-contract-status.md`, `custodian-boundary.md`, README and
   issue #30 statuses. Mark the five slots decided; retain production-host/ARM64/real-scanner sizing as open.
8. Publish a default-feature CLI artifact with source/build provenance and exact binary SHA-256. Record Node
   provenance and the separate bundle and tree identities. Provide artifact-side sizing evidence for the
   pinned runtime/engine/scanner, architecture, launcher and plan limits (P-C); distinguish a tested profile
   from a minimum. P-B is deferred; do not add an unnegotiated probe command or automatically raise memory.

A reference-patched binary has a new digest and is **not** the unchanged PR #29 artifact. No pii-eval
repository was mutated remotely. Its maintainer must review/adopt the handoff and run that repository's full
checks, including its updated feature tests, before claiming upstream adoption.

## Custodian CLI and synthetic validation

Offline structural binding check, with no deployment, credential, App or webhook:

```sh
cargo run --locked -p custodian-cli --bin custodian -- artifact validate \
  --request public-synthetic-request.json \
  --receipt public-synthetic-receipt.json \
  --result public-synthetic-worker-result.json
```

Output is one sanitized JSON result (`artifact_bound` on success). This checks frozen plan/receipt/roster
and canonical embedded aggregate bytes. It does **not** authenticate a signature, prove an execution,
check current activation/revocation, apply a disclosure policy, grant approval or release anything.
The existing pipeline and public verifier perform those separate checks. Missing aggregates, partials,
changed content or bindings refuse. Result input is bounded to 64 KiB; no raw content/path is echoed.

Linux x86_64 reproducible public synthetic integration:

```sh
tools/engines/build-pii-synthetic.sh /tmp/new-pii-synthetic-assets
CUSTODIAN_PII_ASSETS=/tmp/new-pii-synthetic-assets CUSTODIAN_REQUIRE_ISOLATION=1 \
  cargo test --locked -p custodian-daemon --test pii_engine -- --nocapture --test-threads=1
```

The build pins the merge commit and Node 22.23.3 binary digest
`fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`, verifies the patch applies,
builds an unchanged and an adopted real CLI, excludes test adapters from the adopted CLI and records
source, patch and binary identities in `provenance.json`. The fixture builder authors 75 tiny public
synthetic cases and an inert fake package; it is not the staged engine. The custodian test uses a software test signer and an in-memory ledger; the existing full-flow suite
separately exercises the isolated signer and local Git ledger. The custodian seals the fixtures locally,
submits/approves through the existing CLI control plane and uses the actual dispatcher, startup self-check,
receipt assembly, disclosure and durable pipeline. No engine source is imported into a custodian crate.

`.github/workflows/pii-engine-synthetic.yml` is a reusable same-repository gate. A caller in
`private-custodian` first uploads a **public synthetic** bundle as an Actions artifact in that run, then
calls this workflow pinned to a full commit SHA, passing the same `custodian-commit`, `artifact-name`,
`adopted-sha256` and `upstream-sha256` (bare 64 hex). Upload only `provenance.json`, the two CLI binaries,
and the seven scenario directories (`stage`, `input`, `job`, `pins.json`); exclude source/build directories.
The gate verifies the explicit pins and fixed layout before executing; source/patch labels in provenance
are not a source attestation. It needs no cross-repository token or live App. No caller artifact-delivery
workflow has been activated by this change, and no hosted Actions run is claimed.

For a credential-free local Linux build, provide a byte-pinned archive from the known checkout:

```sh
git -C /path/to/pii-eval archive 6157cbc5918b3888c8e84b1884719ea8f3278b36 \
  --output=/tmp/pii-source.tar
CUSTODIAN_PII_SOURCE_ARCHIVE=/tmp/pii-source.tar \
  tools/engines/build-pii-synthetic.sh /tmp/new-pii-synthetic-assets
```

The archive must hash to
`e86756f8a556af326c712f1abdaca3624fdae2f59dd924a497791892c2b0b6e1`; an unpinned archive refuses.
Otherwise the build script uses the invoking operator's existing read access to the private source repo;
it does not provision or print a credential. CI fails if required artifacts/isolation are absent; ordinary workspace tests explicitly skip this external
integration when artifacts were not built and claim no evidence from that skip. Profiles are explicitly
1024 and 1536 MiB with a 512 MiB negative; each profile explicitly requests CPU 30 seconds, wall
20 seconds, scratch 64 MiB, 32 processes and stdout 65536 bytes. No operator cap or sandbox rule is relaxed.
Pipeline replay must preserve one consumption and one delivered projection. Refusals after exposure consume
and cannot release. Existing pipeline tests separately reject missing/malformed aggregates and exercise
crash/restart/concurrency.

## Executed evidence

Local Darwin x86_64, Rust 1.99.0: formatting and workspace Clippy with warnings denied pass;
the three offline artifact CLI tests, four artifact-loader controls and eleven second-implementation
golden vectors pass. The unfiltered workspace suite encounters an existing platform setup failure:
`custodian-corpus::swapped_epoch_directories_are_a_wrong_epoch` receives `PermissionDenied` while
renaming a sealed directory at `protected_storage.rs:482`, before its custody assertions. A focused
retry reproduces it. The rest of the workspace suite passes with that single test explicitly skipped
(`cargo test --workspace --locked -- --skip swapped_epoch_directories_are_a_wrong_epoch`).
No storage permissions or unrelated test were changed to hide this limitation.

Local Linux x86_64 (Docker Desktop kernel `6.10.14-linuxkit`, Bubblewrap 0.8.0),
with custodian Rust 1.90.0 and pii-eval's pinned Rust 1.98.1: the unchanged source CLI and reference
adoption build completed; reference CLI formatting, Clippy with warnings denied, 36 library tests and
seven default-worker tests pass. Explicit delivery pins and all seven scenario layouts pass the artifact
verifier. The disposable container has namespace capability solely to exercise the real Bubblewrap
launcher; startup self-checks are required. No operational host or protected asset is mounted.

The two adopted profiles (1024 and 1536 MiB) pass execution, receipt assembly, the nine-cell projection,
synthetic human-approved release, public bridge verification and durable store restart/replay.
All ten pipeline scenarios pass, with required isolation and no skips: unchanged upstream refusal,
both adopted successes, 512 MiB full-roster partial, scanner crash, and population/run-class/tree/bundle/runtime
mismatches. Every exposed refusal consumes one unit without refund or public output; successes retain one
consumption and one projection through restart. The complete test took 2188.22 seconds on this loaded local
runner, including fixture/store/ledger setup and verification; this is not worker latency or production sizing.
Software test signer and in-memory ledger limitations remain as specified above. This is local project-owned synthetic evidence; no hosted Actions run is claimed.

Exact build identities (rebuilds must verify their own binary identities):

| Artifact | SHA-256 |
| --- | --- |
| Unchanged upstream CLI | `sha256:6350124b42445c6fd71d35d5756adca8a01d3700e06d37d5fae371fcae3271e7` |
| Reference-adopted CLI | `sha256:e1f5e79884a78a45186270d87cb296a7660c56c99577fbb92fa4bd25c72e6daa` |
| Reference adoption patch | `sha256:fc18b7bdf1b95f7af87adc50373abd827070f198ec33430d2d784a87ecf18d62` |
| Node 22.23.3 x86_64 executable | `sha256:fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48` |

Production host, protected population, real scanner package sizing, operational PII policy, live App,
webhook, keys and ledger provisioning remain deferred. Nothing is deployed; evidence is project-owned
functional verification on public synthetic data, not independent protected evaluation.
