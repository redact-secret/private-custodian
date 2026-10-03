# Lambda MicroVM feasibility record (Epic #40)

Date: 2026-10-03. Custodian baseline: `00e1bb0` (S6 merged).
Evidence is project-maintained public synthetic functional verification, not
independent measurement validation. **Worker: NO-GO for protected execution
(unverified runtime). Ordinary Lambda control plane: NO-GO for migration
(missing distributed adapters).** These are separate conclusions. No production
custody, policy activation, webhook, real ledger or protected run was performed.

## What exists and what does not

Implemented here: offline remote result binding parser and negative controls,
read-only AWS preflight with sanitized output, a pinned ARM64 tools-only
health-image build definition and synthetic health probe, an image CloudFormation
preparation template, remote-adapter ADR and control-plane migration inventory.
The health probe refuses every evaluation job and reports `verified: false`.
It is not a trusted production runner or a MicroVM worker implementation.

The final source image was built locally for Linux ARM64 using Docker emulation.
Its loopback smoke check passed: `/health` returned the fixed synthetic/unverified
response, `/job` and a query-bearing health path returned empty 403 responses,
the container user was `65534:65534`, and runtime logs were empty. The disposable
local container was removed and absence confirmed. This tests packaging and the
health handler only; it provides no AWS isolation, lifecycle or engine evidence.

Not implemented: authenticated remote dispatcher, durable VM/attempt mapping,
write-ahead remote input delivery, remote live-lease checking, independent orphan
janitor, internal sandbox on the AWS image, real engine worker integration,
DynamoDB/S3 adapters or network signer. Nothing in this prototype can be selected
as the daemon worker or set its isolation verification record.

No paid AWS resource has been created by this work. The user requested use of
`AWS_PROFILE=redact-secret`; authentication and read-only support APIs succeeded.
A cost-ceiling/cleanup authorization was requested under #40's explicit experiment
gate and remains pending. A live run must record the account/region authorization
and resource inventory outside the repository; account IDs, VM IDs, endpoints,
roles, tokens and raw service errors must never enter commits or CI output.

## P1: compatibility/tooling evidence

| Surface | Documented/local evidence | Actual AWS runtime evidence |
| --- | --- | --- |
| Availability | Official AWS MicroVM docs; selected region `us-east-1` | Authenticated `ListManagedMicrovmImages`, `ListManagedMicrovmImageVersions` and `ListMicrovms` succeeded; this does not prove create/run permission or quotas |
| AWS CLI | Installed `aws-cli/2.37.9`; `lambda-microvms` create/run input skeletons inspected | Read-only API requests succeeded; no provisioning call |
| ARM64 | Managed container manifest is Linux ARM64; local pinned base ran `uname -m` = `aarch64` through Docker emulation | No actual AWS image build/run, no engine sizing proof |
| Rust integration | Remote binding crate reuses exact-pinned existing dependencies; no AWS SDK added | No Rust AWS transport or SDK runtime integration |
| IaC | CloudFormation `AWS::Lambda::MicrovmImage` and SAM `AWS::Serverless::MicrovmImage` are officially documented; sample template prepared | Read-only CloudFormation ValidateTemplate succeeded (5 parameters); it cannot prove provisioning or sandbox enforcement |
| Packaging | Source-only health image, explicit compiler and container manifest pins; default nonroot uid; no input/credential COPY | Snapshot build/credential scrub and lifecycle restore remain unverified |
| Quotas | Explicit service maximum duration and resource baseline/burst documented | Account create/run/concurrency/connector quotas not measured |

Reproduce the read-only support check:

```sh
AWS_PROFILE=redact-secret python3 infra/aws/poc/preflight.py
python3 -m unittest discover -s tests/microvm-conformance
cargo test -p custodian-worker-microvm --locked
```

`preflight.py` captures raw responses only in memory, prints fixed keys/booleans,
and never provisions resources. Error/empty-image controls fail closed. Its
NO-GO result intentionally cannot be promoted by API discovery alone.

Immutable preparation pins:

- AWS ARM64 container manifest:
  `sha256:73a51c3b6eb9f116f75ea89395c9dac70760c172e653121052863ff1f71072af`.
- Rust ARM64 Alpine compiler manifest:
  `sha256:63086e1fb45a56fe0ab75d77e23323a96ec07f1bb74cb0793516280271c852bd`.
- credential-eval source: `c331809c15d5e82730852df91577d64b07dfaaf6`.
- pii-eval source: `6157cbc5918b3888c8e84b1884719ea8f3278b36`.

Source pins are not executable artifact hashes. No engine binary is claimed to
have been built or accepted. An authorized image build must additionally pin the
managed base version, archive SHA-256, runner/binary digests and resulting image
version, then collect package inventory and provenance without credentials.

## P2: adapter and job/result boundary

[ADR 0133](../adr/0133-remote-worker-experiment-boundary.md) reviews the actual
Sandbox/Dispatcher/RunLedger seams and defines the proposed ordered remote
lifecycle. The implemented envelope tests check every distinct identity, lease
fence and artifact/job pin; malformed/oversized/unknown/conflicting bytes refuse.
They reuse `validate_result` and the embedded aggregate channel, so they do not
prove aggregate validity, authorization, isolation or receipt release.

The health image contains no engine, candidate or corpus. It cannot process a
job. That deliberate refusal prevents a packaging experiment becoming an
unsupported protected worker. Build-role snapshot residue, VM endpoint tokens
and internal runner isolation require actual canaries before adding engines.

## P3: exact-image hostile controls still required

Every row needs a working positive control and denial on the exact immutable
AWS image. **All live rows below are not assessable; none is counted as passed.**

| Claim | Positive control | Adversarial control / failure condition |
| --- | --- | --- |
| IPv4/IPv6 public egress denied | Benign controlled listener reachable from a separately allowed probe | Engine/scanner cannot reach either address family under denied policy |
| DNS denied | Resolve a public synthetic name on permitted control | Direct UDP/TCP DNS and AmazonProvidedDNS denied inside engine boundary; SG alone cannot filter Amazon DNS |
| Link-local/internal endpoints denied | Disposable internal canary reachable by authorized control | No metadata, credentials, signer, DB, VM-service or peer-attempt endpoint accessible to engine |
| Credential absence | Inject a disposable synthetic credential canary into trusted control only | Engine env/files/proc/SDK discovery cannot obtain build/operator/runtime credentials; no execution role |
| Filesystem custody | Authorized fixture reads exact input bytes | Host/control/peer files inaccessible; input/candidate readonly; traversal/symlink/hardlink/duplicate archive members refuse before extraction |
| Process separation | Runner control state accessible to trusted control | Engine cannot read/modify runner proc memory/files, signal it, inherit descriptors or mint attestation; capabilities dropped before execution |
| Result/log channels bounded | Valid synthetic result and diagnostic control | stdout/stderr floods, raw canary/error text and unsolicited fields cannot escape; CloudWatch runtime logs disabled; HTTP endpoints bounded |
| VM ingress scoped | Authenticated health request to runner port | Missing/expired/wrong-VM/wrong-port token refused; shell connector absent; no all-ports token; engine cannot call lifecycle hooks |
| No reuse/snapshots | Separate fresh VM per synthetic attempt | Peer state absent; no protected-state suspend/resume; build snapshot has no job/corpus/keys |

Default MicroVM internet egress is incompatible with custody. A customer VPC
connector with restrictive security groups is not sufficient DNS evidence.
Internal namespaces or equivalent enforcement must isolate malicious engines
from the trusted runner even when the outer VM is tenant-isolated. AWS offers
only `ALL` for additional OS capabilities; do not enable it to make a probe pass
without a reviewed risk decision and proof of capability drop before execution.

## P4: fault, fencing and cleanup matrix still required

Existing SQLite/control-plane crash suites run separately; they do not prove
remote cleanup. The remote adapter must inject failure before/after each stage:

| Fault window | Required deterministic outcome | Missing AWS proof |
| --- | --- | --- |
| Creation intent before API / lost create response | Same client token, reconcile inventory, bind at most one VM; never send inputs to unknown VM | Provider idempotency retention and restart inventory |
| VM exists before exposure/export | External cleanup; refund only through existing proven pre-exposure rules | No input delivery and termination |
| Exposure committed / export pending | Inputs withheld until durable export ack; conservative recovery retains consumption | Disconnected orchestrator and durable gate |
| Input upload partial/lost response | No second VM delivery for same attempt; uncertain exposure consumed | Deduplication under network faults |
| Result retrieval / expired lease | Old fence rejected; no stale success or receipt | Concurrent orchestrators and stale-result replay |
| Timeout/OOM/CPU/process/disk/output flood | Bounded process tree, rejected/failed result, consumed if exposed | Limits at exact approved plan and peak VM resources |
| Cancel / lease loss / local kill | Durable settlement once; external terminate independent of worker | Local-process death versus AWS lifetime |
| Terminate failure / janitor crash | Retry/reconcile from durable mapping; maximum lifetime caps orphan duration | Actual provider state, independent janitor and deletion inventory |

No silent refund, double charge, budget reset, runtime limit widening or protected
state reuse is allowed. Unknown outcomes are not successful measurements.

## P5: pinned engines and ARM64 blockers

At the source pins above, credential-eval's CLI dispatch in
`crates/credential-eval-cli/src/main.rs` supports `run`, `compat`, `perf` and
`default-config`; it has no custodian `/stage/engine --job` entrypoint. pii-eval's
`worker/contract.rs` has five unconfigured production adapter slots and refuses
`contract-not-final`; `worker/mod.rs` confirms the test-only feature boundary.
Do not use test adapters or copy metric logic to claim real production integration.

Contract proposals for engine owners under #37/#45:

- Keep exact archive-file candidate/scanner SHA-256 distinct from the engine's
  extracted package-tree digest; opaque package/entry formats remain engine-owned.
- Existing generic staged slots can carry engine binary, shim adapter bundle,
  candidate bundle, worker config and pinned Node as `scanner-0`; no semantic
  reinterpretation of their file identities or core changes are needed.
- Adopt ADR 0127 embedded aggregates, never scratch collection. One authored case
  per entry is a viable engine proposal only when every published denominator
  stays <= observed. Never clamp; exclude `measurable-share` from a *proposed*
  case-roster projection or refine the roster through a reviewed contract.
- `overall` and metric labels require an explicitly reviewed disclosure policy;
  this change does not create or activate a PII policy or choose its allowlist.
- Require digest-specific runtime minimum declarations and a future pre-exposure
  synthetic startup probe under exact plan limits. Do not automatically raise
  limits or replace Node behavior with `--jitless`.

The historical x86 Linux Node 768–800 MiB RLIMIT_AS transition in #37 is not
ARM64 evidence. Record Node/Rust startup, resident memory, virtual address-space
headroom, corpus growth and timeouts separately on the eventual image. Neither
engine has a passing authorized ARM64 MicroVM experiment here.

## P6 and P7: separate decisions, cost and teardown

The [control-plane inventory](lambda-control-plane.md) covers current concrete
store, filesystem, signer, export, scheduler and S6 recovery dependencies and a
minimum migration backlog. Existing concurrency, export, signer and crash tests
are baseline synthetic evidence only. No /tmp SQLite authority, network signer,
DynamoDB or S3 proof is claimed.

Actual AWS compute/burst, image size/read/write units, build/start/transfer/run/
validation/termination times and billed charges are **unmeasured**. Do not offer a
4–8 daily-run price as a measured conclusion. The official MicroVM pricing model
includes baseline plus active burst CPU/memory seconds, snapshot read/write and
storage (image storage has a one-week minimum retention), plus transfers. Add
S3, connectors/endpoints, logs, signer, state, orchestration, retries and orphan
windows; ordinary Lambda function free tier does not establish MicroVM pricing.

For future measured runs: daily total = measured per-run compute/burst + image
reads + transfers, multiplied by 4 and 8 separately, plus retained image/storage,
control services and cleanup windows. Record omissions, region/rate date, build
amortization and uncertainty. Deleted image storage may still incur its minimum
billing period; deletion is not a zero-cost claim.

Resources created by this work: **0 AWS resources**. There is no AWS deletion
claim based on terminating a local Docker process. A future authorized run must
inventory its bucket/objects, build role/policies, image/versions, every VM
(including lost-response orphans), connectors/ENIs/security groups/VPC/DNS
controls, logs and any scheduled cleanup. Terminate VMs, confirm terminal state,
delete image/versions, remove connector dependencies, remove build object/bucket
and role, then query each owned resource class until absence is verified. Restrict
cleanup to this experiment's recorded identifiers; never bulk-delete account
resources. Keep private inventory outside Git; export only counts/status codes.

## Verification commands and scope

The added Rust contract/health tests and Python preflight controls pass locally.
`cargo fmt --all --check` and workspace Clippy with `-D warnings` pass.
The second implementation reproduces all 11 golden vectors. Complete workspace
tests and Linux CI results are recorded with the PR; platform-skipped Linux
isolation checks on macOS are not credited as MicroVM runtime evidence.
No AWS credential is supplied to CI.

## Acceptance disposition

| Child | Completed preparation/evidence | Remaining acceptance |
| --- | --- | --- |
| #41 | Official/tooling matrix, real read-only APIs, ARM64 base execution, immutable source/manifest pins | AWS synthetic build/run/terminate, quotas and experiment authorization |
| #42 | Seam ADR, bounded strict envelope round-trip/negative controls, tools-only image preparation | Authenticated ingress, snapshot inventory and actual remote runner |
| #43 | Exact-image positive/negative probe matrix and fail-closed decision | Every live isolation control |
| #44 | Crash/reconciliation protocol and baseline store tests | Remote fault injection, quotas, janitor and orphan cleanup |
| #45 | Immutable engine source audit and explicit refusal/contract/sizing blockers | Engine-owned adoption and both real ARM64 worker experiments |
| #46 | Complete authority/dependency group inventory, minimum backlog, baseline critical-path tests | Distributed adapter prototypes and parallel Lambda proof |
| #47 | Separate NO-GO conclusions, honest unmeasured cost/cleanup record | Runtime measurements, billed units and authorized teardown proof |

Children with outstanding acceptance remain open. This record does not check off
missing experiments or close the epic by relabeling preparation as runtime proof.
Fallback remains the existing Linux backend; its actual production host still
requires the repository's normal readiness review.

## Primary references (checked 2026-10-03)

- [MicroVM overview](https://docs.aws.amazon.com/lambda/latest/dg/lambda-microvms-guide.html)
- [Images, ARM64 and OS capabilities](https://docs.aws.amazon.com/lambda/latest/dg/microvms-images.html)
- [Run, maximum duration and lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/microvms-launching.html)
- [Optional runtime role and port tokens](https://docs.aws.amazon.com/lambda/latest/dg/microvms-security.html)
- [Default egress and VPC connectors](https://docs.aws.amazon.com/lambda/latest/dg/microvms-networking.html)
- [Security group DNS exception](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [CloudFormation image resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-microvmimage.html)
- [SAM image resource](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-microvmimage.html)
- [MicroVM billing](https://aws.amazon.com/lambda/pricing/)
- [DynamoDB transaction semantics](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis.html)
- [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
