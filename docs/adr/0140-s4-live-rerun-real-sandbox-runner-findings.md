# 0140. S4 live rerun: real sandboxed runner on actual AWS Lambda MicroVM hardware

- Status: proposed assessment; worker NO-GO unchanged, control-plane NO-GO unchanged
- Date: 2026-10-05
- Decision owner: custody maintainer
- Tracking: epic #40, issue #57 (S4); references ADR 0136 (original experiment), ADR
  0137/0138/0139 (ARM64 CI sandbox evidence)

## Context

The repository owner explicitly authorized a second live AWS experiment: a **total US$50
ceiling**, the designated AWS profile, region `us-east-1`, synthetic inputs only, and
deletion of all experiment resources on completion or failure — identical terms to the
first experiment (ADR 0136). This ADR records what that second experiment found.

Unlike the first experiment, this one could build and launch the **real sandboxed runner**
(`deploy/aws/microvm/Dockerfile.runner`, `crates/custodian-worker/src/bin/runner.rs`, merged
in PR #68 after ADR 0136 was written), which performs the actual `BubblewrapSandbox`/
`run_self_check` mechanism ADR 0137's addendum already proved passes on GitHub-hosted
ARM64 CI (`worker-isolation-arm64`, real bare VM, not emulated). The purpose of this rerun
was to find out whether that same mechanism also passes on the actual target infrastructure:
a real AWS Lambda MicroVM, not a GitHub Actions runner and not local emulated Docker.

All resource identifiers (account, ARNs, VM IDs, endpoints, tokens) were recorded only in an
owner-only directory outside Git and are not reproduced here, matching ADR 0136's convention.

## What was rebuilt and tested

Fresh infrastructure, built from nothing (the first experiment's resources were already torn
down): an isolated VPC/subnet with a custom security group with all default egress removed,
one `lambda-core` network connector attached to that closed group (the "denied" runtime
path), a separate build-time path with real internet egress (needed because, unlike the
first experiment's two dependency-free `rustc` builds, `Dockerfile.runner` runs a real `cargo
build --release` reaching crates.io — see "New finding: image build egress" below), an
encrypted public-blocked S3 bucket, and the IAM roles AWS's own `CreateNetworkConnector` and
`CreateMicrovmImage` operations require.

Three images were built with the explicit, fully-specified configuration ADR 0136's B1-vs-B2
lesson requires (ARM64, 512 MiB, no added capabilities, empty environment, Ready/Validate
hooks on port 8080, disabled runtime hooks and logging), each polled to `SUCCESSFUL`/`ACTIVE`
and read back to confirm no field was silently replaced with a service default:

1. The health image (`Dockerfile`/`health.rs`) — reproduces the first experiment's P1/P2
   evidence on fresh infrastructure.
2. The unsandboxed diagnostic (`Dockerfile.probe`/`probe.rs`) — reproduces the first
   experiment's P3 findings on fresh infrastructure.
3. **The real sandboxed runner (`Dockerfile.runner`) — not attempted in the first
   experiment, because it did not exist yet.** This is the actual point of this rerun.

## Findings: the original P3 failures reproduce exactly, on fresh infrastructure

The health harness (`infra/aws/poc/live_health.py`) ran against the health image: explicit
configuration confirmed, creation-replay idempotency confirmed, fresh-VM-per-attempt
confirmed, missing/invalid/wrong-port/wrong-VM/shell-connector/job-dispatch all correctly
refused, maximum-lifetime termination confirmed. **The one-minute token still worked past its
stated expiry** (`expiredTokenDenied: false`) — the exact failure ADR 0136 recorded ("worked
at 65 and 90 seconds"). Token TTL still cannot serve as the custodian's authoritative
cancellation or lease fence; nothing about this rerun changes that.

The unsandboxed diagnostic was launched twice with the identical immutable image version —
once with open/public egress (the positive control) and once with the closed "denied"
connector (the actual test) — and hit `/probe` on each:

| Control | Positive control (open egress) | Denied connector (the test) | Matches ADR 0136? |
| --- | --- | --- | --- |
| Same-uid runner-state file read | readable | **still readable** | Yes — exact reproduction |
| DNS resolution (`example.com`) | resolved | **still resolved** | Yes — exact reproduction |
| IPv4 public egress | connected | **blocked** | Yes — the VPC connector's lack of a route did block this, same as before |
| Link-local TCP (`169.254.169.254:80`) | connected | **still connected** | Yes — exact reproduction |
| IPv6 positive control | failed to connect | not assessable | Yes — still no working positive control; IPv6 remains `untested`, never `blocked` |
| `unshare` tool presence | absent | absent | Yes — exact reproduction |

Every single P3 finding from ADR 0136 reproduces, unchanged, on completely fresh
infrastructure built independently by this rerun. This is strong evidence those were not a
one-off fluke of the first account/image/VPC state.

## The new finding: the real sandboxed runner does not pass on actual AWS MicroVM hardware

The runner image was launched with the same closed/denied connector (the configuration a
real deployment would use) and its `/health` endpoint queried. It reported:

```json
{"synthetic":true,"verified":false,"reason":"self_check_failed: isolation_check_failed failed_checks=[] probe_ended=Exited(1)"}
```

`failed_checks=[]` with `probe_ended=Exited(1)` means the self-check probe process did not
survive long enough to report **any** of the `REQUIRED_CHECKS` — a setup-level failure, not a
specific check failing. This is the identical signature PR #68 found testing the same image
locally on non-privileged Docker Desktop (`bwrap: Can't mount proc on /newroot/proc:
Operation not permitted`), which that PR correctly refused to work around with `--privileged`
or a weakened security profile, reporting `verified: false` as the honest result rather than
forcing a pass.

This rerun did not have a way to get a shell or raw log inside the MicroVM to confirm the
exact underlying syscall failure (no shell connector exists, by design, and image logging is
disabled, by design) — getting that level of detail would require instrumenting the runner
or probe binary to report more diagnostic detail on `run_self_check` failure and rebuilding,
which is a code change, not something this live rerun should improvise under a cost ceiling.
What can be stated with confidence: **the exact mechanism that passes on GitHub-hosted ARM64
CI (`worker-isolation-arm64`, a bare virtual machine with no further sandboxing) does not
currently pass on the actual AWS Lambda MicroVM target**, and the failure mode matches local
Docker Desktop's lack of privilege for nested unprivileged namespaces more closely than it
matches the CI success case. The most likely explanation is that AWS Lambda MicroVMs apply
their own restriction on nested unprivileged user-namespace/mount operations from inside the
VM (whatever AWS's own hypervisor/guest-kernel boundary permits a tenant process to do),
distinct from both a bare CI VM and a container host. This is stated as the most likely
explanation, not a confirmed root cause — confirming it would need AWS support engagement or
a kernel-level probe inside the MicroVM, neither attempted here.

## New finding: image build egress

Unrelated to the sandbox question but a genuine operational finding: `CreateMicrovmImage`'s
`egressNetworkConnectors` field, despite its name suggesting it controls build-time network
access, actually behaves as a *restriction* — supplying the closed/denied connector caused
every build to fail (`CREATE_FAILED`, `stateReason: "An unknown error occurred"`, no further
detail available from the service). Supplying an **empty list** let the build use the
platform's default (open) egress and succeeded immediately for all three images, including
the `cargo build --release` reaching crates.io for the runner image. This matches
`docs/poc/lambda-microvm.md`'s existing note, "Default MicroVM internet egress is
incompatible with custody" — default egress already includes internet access; a connector is
how that default is *replaced* with a restricted VPC path, not how egress is *granted*. The
runtime `run-microvm` calls still use the closed connector normally, as that is the actual
security boundary under test; this finding only concerns the separate build-time API.

A second, minor, now-fixed finding: `infra/aws/poc/image.template.json`'s CloudFormation
template had `"Logging": {"Disabled": {}}` where the `AWS::Lambda::MicrovmImage` resource
type's own published schema requires a boolean (`{"Disabled": true}`) — CloudFormation's
early property validation rejects the template as a result. The *raw* `lambda-microvms`
service API, confirmed by `live_health.py`'s own exact-configuration check (`image.get
("logging") != {"disabled": {}}`), wants the opposite shape (an empty object), so the
template's original shape was actually correct for the real API and only wrong for
CloudFormation's resource-provider schema — a mismatch between AWS's own CFN provider and its
underlying service, not a bug in this repository's template as written. This ADR's rerun used
the raw API directly rather than fix the CloudFormation path further, since it unblocks this
rerun without betting more budget on a third-party schema inconsistency.

## Conclusion — conservative, per epic #40's explicit rule

**Worker NO-GO stands. Control-plane NO-GO stands (unchanged; this rerun did not touch
Lambda/DynamoDB control-plane primitives, see "Scope not re-covered" below).** None of ADR
0136's original failures were resolved by this rerun — they were independently reproduced on
fresh infrastructure, which strengthens confidence they are real and systematic rather than
an artifact of the first account state, but does not narrow the NO-GO. The one new question
this rerun set out to answer — whether the real sandbox mechanism (proven on ARM64 CI) also
works on the actual AWS MicroVM target — has a new, specific, negative answer: **it does not
currently pass**, with a failure signature suggesting AWS's own MicroVM virtualization layer
restricts the same unprivileged-namespace operations CI's bare VM permits. This is a narrower,
more specific NO-GO reason than before (previously: "no sandbox was ever attempted"; now: "a
real sandbox was attempted and did not pass on this exact infrastructure"), which is real
progress in the sense of eliminating ambiguity, but it is still NO-GO.

## Scope not re-covered in this rerun

To conserve the cost ceiling once the two priority questions (original-finding reproduction,
real-sandbox-on-AWS result) were answered, this rerun did **not** re-run: the Lambda/DynamoDB
transaction primitive (#46) — ADR 0136's result there stands unchanged and unre-verified by
this rerun; the ADR 0138/0139 new adversarial probe matrix (DNS-by-name, link-local-by-name,
IPv6, symlink/hardlink escape, supplementary-group escape, forged attestation) against a real
sandboxed child on AWS — moot in any case, since the sandbox itself did not pass its own
self-check, so there is no sandboxed child to probe yet; or any instrumentation to find the
exact kernel/syscall cause of the runner's `Exited(1)`. All of these remain open follow-up
work, not silently dropped.

## Teardown and evidence gate

Every resource created by this rerun was deleted and independently verified absent by the
same session that created it, using both the Resource Groups Tagging API (14 resources
tracked by a dedicated tag) and direct per-service list/get calls (since the tagging index is
known to lag real deletions by a short window): the VPC, subnet, two security groups, route
table, internet gateway, two network connectors (confirmed via `list-network-connectors`
returning zero, independent of the tagging index), the S3 bucket (confirmed via `HeadBucket`
404), two IAM roles, and all 5 MicroVM images across all versions (including two that failed
mid-rerun before the build-egress finding above was understood). All 5 MicroVMs launched
during the rerun were confirmed `TERMINATED`. Actual cost was well under the $50 ceiling —
a handful of minutes of 512 MiB ARM64 MicroVM compute across 5 short-lived VMs plus three
image builds, the same order of magnitude as ADR 0136's experiment.

## Consequences, migration, exit

No approval, retention, budget, disclosure, or signer policy changes. No schema migration.
This ADR does not authorize further live AWS work and does not change any custody
authorization rule. The next step this finding points to is diagnosing *why* `bwrap` cannot
set up its sandbox inside an AWS Lambda MicroVM specifically — likely requiring either AWS
support engagement to learn what the MicroVM guest kernel/hypervisor boundary actually
permits, or a diagnostic image that reports more detail than a boolean on self-check failure
— neither of which this rerun attempted, both of which are explicit follow-up, not implied
success.
