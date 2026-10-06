# 0142. EC2 worker lifecycle: fresh instance per attempt, stop/start reuse not selected, host validation plan

- Status: proposed; amends the lifecycle choice in ADR 0141; worker and control-plane NO-GO unchanged
- Date: 2026-10-06
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions
  are project-maintained, not independent validation.
- Tracking: issue #71 under epic #40 (follows #54-#56, ADR 0140/0141)

## Context

ADR 0141 pivoted the remote worker to EC2 and chose one stop/start instance for cost. Epic #40
requires a fresh VM per attempt. Stop/start keeps the root volume, so any writable
input/output/scratch/log/cache channel, delayed writer, crashed cleanup or retained candidate state
could cross attempts. ADR 0141 did not prove otherwise and its cost totals are placeholders, not
measurements. A cost choice must not silently relax an isolation requirement.

## Options

| Option | Cross-attempt state | Cost | Verdict |
| --- | --- | --- | --- |
| A. Fresh launch from pinned AMI, terminate after settlement | None by construction (root and data volumes `DeleteOnTermination`, no reuse) | Compute only while running; cold boot per attempt, unmeasured | **Chosen** |
| B. Stop/start one instance | Disk persists; needs a proven cleanup of every channel, peer-attempt denial, delayed-writer and crashed-cleanup handling | Lowest, unmeasured | Not selected; admissible only with the evidence below |
| C. Hibernate | RAM and protected state written to disk | Higher | Prohibited: no protected-state hibernation |
| D. Always-on | Same as B plus longest exposure | Highest | Rejected on cost and exposure |
| E. Defer | n/a | n/a | Not needed; A is implementable offline |

## Decision

1. The worker lifecycle is **fresh launch from a pinned immutable ARM64 AMI per attempt, terminated
   after settlement**. ADR 0141's stop/start choice is superseded for lifecycle; its pivot to EC2,
   its rejection of co-locating a CI runner, and its Lambda MicroVM history stand.
2. Stop/start reuse (B) may be proposed in a later ADR only if it shows, with positive controls:
   cleanup of every writable/persistent input, output, scratch, log, cache and child-process
   channel; denial of a peer attempt reading a predecessor; behavior for delayed writers, crashed
   cleanup and retained candidate state; and measured cost benefit over A. Insufficient evidence
   means A. Any failed or missing cleanup attestation fails closed (instance terminated, attempt
   not evaluated).
3. No evaluation runs after a failed `run_self_check`; a self-check that was skipped is a failure,
   not a success.
4. A self-hosted CI runner stays on a different host, outside custody credentials and data paths.

## Host image and trust (required before acceptance)

- Pinned ARM64 AMI id, kernel, `bwrap`, runtime and tool versions recorded as immutable image
  evidence (digest/manifest); the AMI is built by a reviewed recipe, not selected by a mutable alias.
- Trusted boot/setup runs once at image build; at launch the worker identity is a non-root user,
  setup privileges are dropped, `kernel.unprivileged_userns_clone` is set in the image (as
  `.github/workflows/ci.yml` does), IMDSv2 required with hop limit 1, no SSH ingress.
- Acceptance requires, on that exact image: the real `Sandbox`/`run_self_check` passes, and the
  #55/#56 adversarial probes pass with positive controls and no skipped success.

## Network and permission inventory (separate from child egress denial)

Child egress denial stays enforced inside the sandbox. The host separately needs private
transport; an S3 endpoint alone does not provide it:

| Need | Mechanism | Permission |
| --- | --- | --- |
| Inbound candidate/input artifact | S3 gateway endpoint | `s3:GetObject` on `inbound/*` only |
| Outbound private artifact | S3 gateway endpoint | `s3:PutObject` on `outbound/*` only |
| Dispatcher/control channel (#42, #44) | Interface endpoint, worker group to endpoint group on 443 | Defined by #42; not yet designed |
| Signer connectivity | Not on the worker; the worker never signs | None |
| Instance launch/terminate | Control plane principal, not the worker role | Out of the worker role; policy defined with #44 |

The worker role has no `ec2:*`, `iam:*`, `kms:*` or wildcard. No internet gateway, NAT or public IP.
`infra/aws/ec2/worker.template.json` encodes this as IaC; `tests/ec2-conformance` checks it offline.
The template is a design artifact: never deployed by this repository, and the interface-endpoint
service for #42 is not provisioned by it.

## Security properties claimed

- Per-attempt state isolation by construction (fresh volumes): template test
  `test_fresh_instance_terminates_and_storage_dies_with_it`.
- No reuse or hibernation knob: `test_no_hibernation_or_reuse_knob`.
- IMDSv2-only, no public IP, no ingress, no open CIDR, scoped IAM: the matching template tests.
- Not claimed: a verified sandbox on EC2, live isolation, independent validation, or measured cost.

## Failure and recovery

Launch failure, boot failure, failed self-check, crash mid-run or lost janitor: the instance is
terminated and the attempt is not evaluated or silently retried on the same instance; a retry is a
new instance and a new attempt identity. Orphaned instances are found by the `custody-lifecycle` tag
and reaped by the janitor (#44). Terminate is idempotent; the launch is idempotent via a
client token derived from the attempt identity (to be implemented under #42/#44, not yet built).

## Performance and cost evidence plan (unmeasured)

Measure separately, without relaxing isolation: boot, self-check, runtime, staging, cleanup, real
engine memory headroom when #45 supplies artifacts, and full retained cost (compute, EBS, endpoint
hours and data, snapshots/AMI storage, logs). ADR 0141 totals remain placeholders and must not be
quoted as measured. Warm kernel state across stop/start is not assumed.

## Live rehearsal

Not authorized here. A paid rehearsal needs a verified authorization record covering account,
region, budget ceiling (`AuthorizationCeilingUsd`), and teardown, and uses public synthetic data
only. Until then the EC2 path stays NO-GO and the acceptance items in #71 that need a live host
remain open.

## Consequences

No policy, schema, budget or signer change. Control-plane work gains a launch/terminate
requirement in #42/#44 instead of start/stop.
