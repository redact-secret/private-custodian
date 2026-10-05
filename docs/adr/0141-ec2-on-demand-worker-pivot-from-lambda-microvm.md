# 0141. Pivot the remote worker target from Lambda MicroVM to on-demand EC2

- Status: proposed (design decision only); no infrastructure provisioned, no code
  written, no custody authority changed
- Date: 2026-10-05
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions
  are project-maintained, not independent validation.
- Tracking: epic #40; supersedes the Lambda MicroVM worker target for future work, does
  not supersede or close #40 or any of its children

## Context

ADR 0140 recorded that the real sandboxed runner (`Dockerfile.runner`, proven on real
GitHub-hosted ARM64 CI per ADR 0137's addendum) reports `verified: false` with the same
`Exited(1)` signature as non-privileged local Docker Desktop when launched on an actual
AWS Lambda MicroVM. The most likely explanation is that Lambda MicroVM's own tenant
isolation boundary restricts the unprivileged user-namespace/mount operations `bwrap`
needs, and that boundary is not something a customer can configure around — it is a
property of the managed service, not of this repository's image or runner code.

Given that, the custody maintainer decided in direct conversation to stop pursuing Lambda
MicroVM as the remote worker target and instead plan around a regular EC2 instance, where
the operator controls the full kernel (including `kernel.unprivileged_userns_clone`, the
exact sysctl `.github/workflows/ci.yml`'s `worker-isolation` jobs already set) and the
already-proven `BubblewrapSandbox`/`run_self_check` mechanism should work unchanged, the
same way it already does on GitHub's own ARM64 CI runners (themselves ordinary VMs, not a
managed micro-VM service with Lambda's specific restrictions).

This ADR records that decision and the cost analysis behind choosing an on-demand
(start/stop) EC2 lifecycle over an always-on one. **It is a decision record only.** No EC2
instance, security group, IAM role, or other resource has been created. No code changes
to `custodian-worker`/`custodian-daemon` have been made. Wiring an EC2-backed worker into
the actual control plane (dispatch, lifecycle, fencing — the remaining scope already
tracked under #42/#44/#46) is explicit future work, not implied by this ADR.

## Options considered for the worker's run lifecycle

| Option | Boot/dispatch latency | Relative monthly cost (worker only, see tables below) | Operational complexity |
| --- | --- | --- | --- |
| **Chosen: on-demand start/stop**, this repository's own control plane starts the instance per dispatch and stops it after settlement | One EC2 stop→start cycle per attempt (not a fresh launch) | Lowest | Low — the daemon already owns run lifecycle; adding an EC2 start/stop call is a bounded addition, not a new subsystem |
| Always-on instance | None | ~5-10x the on-demand estimate | Lowest (nothing to orchestrate) |
| Fresh launch-from-AMI per attempt (not stop/start) | Full cold boot (30-60s typically) | Similar to on-demand stop/start, slightly higher due to no EBS/kernel warm state | Higher — needs a launch-and-terminate cycle instead of reusing one instance |
| EC2 hibernate (RAM-to-EBS) per attempt | Lowest of the non-always-on options (RAM restore, no OS boot) | Similar to stop/start plus hibernation-sized EBS | Higher — needs a hibernation-enabled AMI and an encrypted root volume sized for RAM |

Stop/start was chosen over fresh-launch-per-attempt or hibernate because this repository's
existing control plane (the daemon's run-state machine) is already the natural place to
own "start before dispatch, stop after settlement," and stop/start needs no additional
AMI/encryption prerequisites that hibernate would. Fresh-launch-per-attempt was rejected
because it discards the kernel/sysctl warm state between attempts for no benefit over
stop/start on the same instance. Always-on was rejected on cost alone, given the low
expected attempt volume (the "daily 4-8 runs" sizing already noted under issue #47); the
latency difference the comparison table below shows is not large enough at this volume to
justify 5-10x the cost.

## Cost comparison (estimates; `us-east-1`, ARM64 Graviton `t4g` on-demand pricing at
## decision time; not a committed budget, not yet measured against real engine sizing)

Two separate concerns are priced: the custody worker itself, and a self-hosted CI runner
considered in the same conversation as a way to amortize always-on cost by sharing a host
with another purpose. **The CI runner must not share a host with the custody worker** —
see "Rejected: co-locating a self-hosted CI runner" below — so it is priced as a separate
instance throughout, not folded into the worker's number.

### Always-on

| Component | Instance | Compute | EBS (~20-30 GiB gp3) | Public IPv4 (if attached) | Monthly total |
| --- | --- | --- | --- | --- | --- |
| Custody worker | `t4g.medium` (4 GiB) | ~$24.55 | ~$1.60 | $0 (private subnet, no public IP needed -- see below) | **~$26** |
| Custody worker (smaller, if #45 sizing allows) | `t4g.small` (2 GiB) | ~$12.28 | ~$1.60 | $0 | **~$14** |
| Self-hosted CI runner | `t4g.small` (2 GiB) | ~$12.28 | ~$1.60-4 | ~$3.60 | **~$17.5-20** |
| **Combined (worker `t4g.medium` + CI runner)** | | | | | **~$43-46/month** |

### On-demand (start/stop; "accepting the boot/resume delay")

Assuming the issue #47-style volume (4-8 custody attempts/day, ~10 min active per attempt;
CI runner active ~10-15 min per build trigger, assumed similarly infrequent for this
project's current activity level):

| Component | Instance | Active hours/month (est.) | Compute | EBS (always billed, instance state or not) | Public IPv4 (only while running, auto-assigned, not Elastic IP) | Monthly total |
| --- | --- | --- | --- | --- | --- | --- |
| Custody worker | `t4g.medium` | ~30 | ~$1.00 | ~$1.60 | $0 (private subnet) | **~$2.6** |
| Self-hosted CI runner | `t4g.small` | ~50 | ~$0.84 | ~$2.40 | ~$0.25 | **~$3.5** |
| **Combined** | | | | | | **~$6-7/month** |

The custody worker's private-subnet design (no public IP, no NAT Gateway) relies on an S3
Gateway VPC endpoint (free) for any artifact staging that needs S3, matching this
repository's existing "no internet gateway/NAT/endpoints" denial-by-default posture from
`docs/poc/lambda-microvm-live-runbook.md` -- this is a property worth preserving in the EC2
design, not a new idea introduced here. The CI runner genuinely needs outbound internet
(to reach `github.com`/`crates.io`) and is cheaper with a plain public-subnet auto-assigned
IP (billed only while the instance runs) than with a NAT Gateway (a flat ~$32+/month
regardless of usage, which would cost more than the entire on-demand combined total above).

### Decision

**On-demand (start/stop) for this implementation**, for both the worker and (if a
self-hosted CI runner is built at all — not decided by this ADR) the CI runner. The
~6-7x cost difference is large relative to the low attempt volume this project expects,
and the stop/start latency (one resume cycle per dispatched attempt, not a fresh boot) is
judged acceptable for a system that is not serving interactive, latency-sensitive
requests. This can be revisited if attempt volume grows enough that the cost gap narrows
relative to the latency cost, or if hibernate turns out to meaningfully beat stop/start
once measured against the real engine's actual boot/warm-up behavior (not yet measured).

## Rejected: co-locating a self-hosted CI runner with the custody worker

Raised and rejected in the same conversation: running a self-hosted GitHub Actions runner
on the *same* host as the custody worker, to amortize an always-on cost across two
purposes. Rejected because a self-hosted runner executes code triggered by this
repository's own CI events (pushes, PRs), which is a materially different trust boundary
than the sandboxed, isolated candidate execution the custody worker exists to contain; a
compromised runner on the same host as the worker would have a lateral path toward
whatever credentials, signing material, or corpus access that host holds, undermining
exactly the isolation property this epic's work (ADR 0136 through 0140) spent significant
effort proving and disproving. If a self-hosted runner is built at all, it must be a
separate instance (or stronger isolation than a separate instance, if ever justified),
never the same host as the worker. This repository's own trust-boundary model (ADR 0001)
and the `agent-surface-review`/`boundary-review` skills are the right place to re-litigate
this if a future change proposes otherwise -- this ADR does not reopen it, it records why
it was rejected once.

## What this ADR does not decide

- The exact instance size (`t4g.small` vs `t4g.medium`) is not fixed; it depends on the
  real engine memory sizing issue #45 still owes, re-measured on ARM64 under the actual
  resource limits the worker will enforce (the same `prlimit`/`RLIMIT_AS` bounds
  `crates/custodian-worker` already implements and proves in CI, not a new mechanism).
- Whether a self-hosted CI runner is built at all is not decided here — only that *if* one
  is built, it must not share a host with the worker.
- How the daemon's existing run-state machine issues the actual `StartInstances`/
  `StopInstances` calls, what IAM permissions that needs, and how a stop/start failure
  is fenced (the same crash/restart discipline ADR 0133/0136 already require of a remote
  worker) are not designed here — that is explicit follow-up work under #42/#44/#46,
  which this ADR's pivot now targets EC2 instead of Lambda MicroVM, without having
  redesigned any of their already-open scope.
- This ADR does not change ADR 0136/0140's recorded findings about Lambda MicroVM, which
  stand as historical evidence of what was tried and why it did not pass, not something
  this pivot erases.

## Consequences, migration, exit

No approval, retention, budget, disclosure, or signer policy changes. No schema migration.
No AWS resource is created by this ADR. The worker and control-plane NO-GO from ADR 0136/
0140 are unchanged -- this ADR changes the *target* future work aims at, not the current
feasibility conclusion, which remains NO-GO until the EC2-based path is actually built and
proven, not merely planned.

## Open risks and revisit triggers

- **Cost estimates are current on-demand `t4g` pricing at decision time, not a committed
  figure** -- AWS pricing changes, and the per-public-IPv4 charge referenced here (in
  effect since February 2024) is itself an example of a pricing-model change that could
  recur.
- **Real engine memory sizing is unmeasured on ARM64** (issue #45); the instance-size
  numbers above could be wrong in either direction once that measurement exists.
- **Stop/start latency was not measured against this repository's actual engine
  boot/warm-up time** -- the "~10 min active per attempt" estimate is a placeholder
  carried over from the Lambda MicroVM experiments' VM lifetimes, not a measurement of
  the real credential/PII engines running on EC2.
- **A self-hosted CI runner's cost/latency figures assume GitHub-triggered start/stop is
  built via a webhook-driven Lambda** (the common `workflow_job: queued` pattern); no such
  automation exists yet, and building it is separate, undecided future work.
