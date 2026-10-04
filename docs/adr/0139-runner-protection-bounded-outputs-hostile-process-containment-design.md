# 0139. Runner protection, bounded outputs and hostile process containment design (S3, issue 56)

- Status: proposed (design only); no probe code, CI job, or `crates/custodian-worker` change is added
  by this ADR — but see "Addendum (2026-10-04): the existing mount/PID/capability/resource checks
  now have real ARM64 evidence" for what the existing suite (not this ADR's new matrix) proved
- Date: 2026-10-03
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Tracking: epic #40, issue #56 (S3); explicitly depends on #54 (S1); coordinates with #55 (S2) and #44;
  feeds #43 and S4 (#57)

## Context

[ADR 0136](0136-authorized-microvm-experiment-findings.md) recorded that in the one authorized live AWS
MicroVM experiment, the same-uid child **read** the runner's owner-only (0600) synthetic control file
(the P3 table's "Child reads runner-owned 0600 canary: reads / reads — Inner filesystem/process trust
boundary fails without a sandbox"). That finding is explicit evidence that VM-level process placement
with no inner sandbox does not protect runner-owned state from a same-uid child. The same report lists,
as unverified rather than failed, every control issue #56 is about: "Filesystem/archive confinement,
runner memory/signals, arbitrary internal endpoints, complete credential absence, stdout/stderr floods
and hostile process resource limits remain unverified. Do not interpret unavailable controls as passed."
That diagnostic (`deploy/aws/microvm/probe.rs`) is, by design, unsandboxed
(`deploy/aws/microvm/README.md`) — it has no inner sandbox at all, so the reachable-canary finding is
exactly what motivates building one, not a finding about the real `Sandbox`/`BubblewrapSandbox`
implementation this repository already has.

[ADR 0137](0137-arm64-inner-sandbox-image-and-ci-capability-probe.md) (S1, issue #54) proved kernel and
tooling *capability* on ARM64 (the capability-probe workflow ran on the confirmed-schedulable
`ubuntu-24.04-arm` runner), but explicitly did not run the real `Sandbox`/`run_self_check` on ARM64, and
states that full dispatch proof plus runner-protection hardening is deferred to S2/S3 (#55, #56). Issue
#56's own text says "Depends on S1" and "Offline implementation and tests may proceed now" but reserves
paid AWS execution for later, separately authorized work. This ADR is therefore the design-only scoping
issue #56 asks for: which attack categories must be tested, what bounded-output and resource-limit
mechanisms already exist to test against, and how the "no releasable evidence on hostile leakage" rule
already works — without running any adversarial probe against a real ARM64-sandboxed child.

The existing mechanisms, already implemented and unchanged by this ADR:

- **Filesystem isolation and runner-state invisibility.** `BubblewrapSandbox::build_argv`
  (`crates/custodian-worker/src/bwrap.rs` lines 116-185) binds only the system roots, `/proc`, a minimal
  `/dev`, the explicit `RoMount`s, and a size-capped `/scratch`, then issues `--remount-ro /` after every
  mount is in place (bwrap.rs lines 149-165; restated in ADR 0137's "Design" section). The runner's
  control file, sockets, staging-base parent directory, and sibling-attempt scratch are never bind-mounted
  in; they are **not present** in the child's mount namespace, not merely permission-denied — the exact
  property the unsandboxed AWS diagnostic lacked. The self-check's `host_files_absent` and
  `write_outside_scratch_denied` checks (`docs/worker-isolation.md` section 4) already attempt to open a
  host-written canary file and to stat `/root`, `/home`, `/etc/shadow` and secret-mount paths, and
  already attempt writes to `/`, `/usr`, `/input`, `/stage`, requiring all of them to fail.
- **Process/PID namespace.** `--unshare-pid` plus `--proc /proc` (bwrap.rs lines 123-150) gives the
  child a fresh procfs for its own PID namespace; the self-check's `pid_namespace` check requires at most
  8 visible processes (`docs/worker-isolation.md` section 4), so a child cannot see runner or
  sibling-attempt processes, signals, or memory/debug interfaces outside its own namespace.
- **Capability drop.** `--cap-drop ALL` (bwrap.rs line 129-130), checked by the self-check's
  `no_capabilities` check reading `CapEff` and requiring zero (`docs/worker-isolation.md` section 4).
- **Resource/flood bounds, already implemented, cited exactly:**
  - CPU, address-space, process-count, file-size: `prlimit --cpu=... --as=... --nproc=... --fsize=...
    --core=0 --nofile=256`, applied inside the already-restricted namespaces, immediately before `exec`
    (bwrap.rs lines 172-180; `docs/worker-isolation.md` section 5's limits table). `--nproc` is enforced
    per user namespace on kernel 5.14+ and is the fork-bomb bound.
  - Wall clock: `supervise`'s deadline loop (`crates/custodian-worker/src/sandbox.rs` lines 234-324)
    kills the whole process tree once `start.elapsed() >= quotas.wall`.
  - stdout (the result channel): read in a dedicated thread, capped at `cap_out = quotas.stdout_bytes`
    (plan limit, `min`-bounded to 64 KiB per `docs/worker-isolation.md` section 5); the reader thread
    detects `(buf.len() + n) as u64 > cap_out`, sets an `AtomicBool` flag, clears the buffer, and keeps
    draining without blocking the child while the supervisor observes the flag and kills the tree
    (`sandbox.rs` lines 245-271, 310-311) — this is the exact "one byte over kill" `Termination::OutputLimit`
    behavior.
  - stderr: counted but **never retained** — the reader thread only accumulates a byte count, never the
    bytes themselves, and the same `cap_err`/flood-detection logic applies (`sandbox.rs` lines 273-291).
  - Tree cleanup: `kill_group` (`sandbox.rs` lines 206-223) sends `SIGKILL` to the child's whole process
    group (the child leads its own group via `process_group(0)` in `prepare_command`, `sandbox.rs` lines
    198-204) on **every** exit path, including a normal exit — explicitly to catch a daemonized
    grandchild that would otherwise outlive the run. `--die-with-parent` (bwrap.rs line 121) is a second,
    kernel-level backstop inside the sandbox.
  - Descriptor inheritance: Rust's close-on-exec default plus the three explicitly redirected standard
    streams (`sandbox.rs` lines 198-204) means no extra descriptor reaches the payload.
- **Forged or hostile result cannot become releasable evidence.** The worker protocol parser
  (`crates/custodian-worker/src/result.rs`, `docs/worker-isolation.md` section 7) rejects unknown fields,
  duplicate keys, trailing data, wrong schema/domain/protocol, an `expected` outside the authorized
  roster, `observed > expected`, `failed > observed`, and a status that disagrees with the counters. A
  worker that did not exit cleanly never has its stdout parsed at all. Independently of that parser, the
  disclosure-facing gate is `ExecutionRecord::is_releasable()`
  (`crates/custodian-contracts/src/execution.rs` lines 93-97): **`true` only when `outcome ==
  ExecutionOutcome::Success`** — every other outcome (`Partial`, `Failed`, `Rejected`, `Cancelled`), which
  is what a hostile-process attack, a resource-exhaustion kill, an output-flood kill, or a forged/garbled
  result all map to per the outcome table in `docs/worker-isolation.md` section 7, is categorically
  excluded from feeding a projection. `crates/custodian-disclosure/src/service.rs` line 478 checks exactly
  this flag before accepting an execution into the release path. A `Partial` outcome is additionally never
  releasable even though it is a form of "the engine ran," per the same section 7 note.
- **Hostile stderr/raw output never reaches a public surface.** Stderr content is never retained
  (counted and discarded, above); the only released artifact of a run is `ValidatedResult::private_bytes()`
  stored privately (`docs/worker-isolation.md` section 11), which the dispatcher "never signs, discloses
  or exports" itself — disclosure is a separate, later, independently gated step.

None of the above is new in this ADR. What is missing, and is this ADR's actual content, is the
specification of the adversarial attack categories issue #56 asks for, matched against these existing
mechanisms, so a future adversarial-probe implementation (after S1's real self-check runs on ARM64) has
an unambiguous target and nothing is reinvented.

## Options

| Option | Reuses the existing contract | Addresses ADR 0136's specific gap (same-uid file read) | Matches issue #56 scope |
| --- | --- | --- | --- |
| **Chosen: specify the attack-category matrix against the existing mount/PID/capability namespaces, `prlimit`/`supervise` bounds, and `is_releasable()` gate; design only, no new mechanism** | Yes — no new custody code | Yes, by naming exactly how the mount-namespace change (ADR 0137's design section) removes the AWS diagnostic's reachable-canary condition | Yes — issue #56 explicitly allows offline design/implementation planning now, reserves paid AWS execution for later |
| Add a new sandboxed "runner-protection" layer distinct from `BubblewrapSandbox` | No — duplicates mount/PID/capability isolation the existing backend already provides | N/A | No — issue #56 says to coordinate lifecycle/resource ownership with #44, not reimplement budgets/settlement or sandbox mechanics |
| Treat the existing `worker-isolation` x86_64 CI pass (`linux_isolation.rs`'s fork-bomb/memory/disk/CPU/stdout-flood/timeout/cleanup tests) as sufficient evidence for ARM64 | N/A | No — exactly the substitution ADR 0136 and ADR 0137 both warn against | No |
| Implement the adversarial probes now | Eventually, yes | Only once actually run | No — "Depends on S1," and S1 only proved capability, not a real self-check run on ARM64; writing adversarial probe code against an unconfirmed runner path and an un-run self-check is premature |
| Defer all design work until S4 (#57)'s AWS rerun | N/A | No | No — #57 needs a specified matrix to rerun |

## Decision

1. **No new custody logic.** The mount namespace, `--unshare-pid`/`--proc`, `--cap-drop ALL`, `prlimit`
   limits, `supervise`'s wall-clock/output/tree-kill logic, and `ExecutionRecord::is_releasable()` are
   unchanged and remain the only mechanisms this repository will point at runner protection, bounded
   output, and hostile-process containment. This ADR adds no code to `crates/custodian-worker` or
   `crates/custodian-contracts`.
2. **Attack-category matrix, specified for future implementation**, organized exactly along issue #56's
   own categories:
   - **Filesystem.** Read/write attempts against runner files, environment, `/proc` entries outside the
     child's own PID namespace, memory/debug interfaces (`/proc/self/mem`, `ptrace` of any visible
     process), control sockets, and other-attempt scratch directories — all of which the mount and PID
     namespaces already make absent rather than merely denied (see Context). Symlink/hardlink/archive
     traversal and writable-mount-escape attempts against the staged read-only mounts and the single
     writable `/scratch` — `docs/worker-isolation.md` section 6 already states archive formats are not
     accepted (every staged input is a flat file) and `validate_member_path` exists precisely so a
     future archive reader validates names first; a future probe must attempt symlink/hardlink
     construction inside `/scratch` and confirm it cannot reach outside it, and must attempt to write
     through a `RoMount` and confirm `--remount-ro /` (applied after every mount, bwrap.rs lines
     162-163) denies it.
   - **Process.** Fork-bomb up to and beyond `--nproc`; descendant and daemonized process survival
     across a normal exit, a timeout, and a `kill_group` sweep; signal delivery to and from processes
     outside the PID namespace (should be impossible, namespace-absent); executable replacement of a
     staged binary after staging (already covered by re-hashing before launch and after execution per
     `docs/worker-isolation.md` section 6, restated here as a case the matrix must exercise against a
     real sandbox, not re-specified as a new mechanism).
   - **Privilege.** Attempted capability regain, attempted `setuid`/`setgid` paths, attempted escape via
     any inherited supplementary group — the last is the specific **open risk** ADR 0137 already flagged
     ("Supplementary groups: an explicit open risk, not yet a positive control," ADR 0137 privilege-drop
     step 7); this ADR does not resolve that risk, it restates that a future S3 probe matrix should
     attempt to exploit it and must record the result as `untested`, not passed, if `getgroups()` cannot
     yet be asserted by the self-check.
   - **Descriptor.** Count of inherited file descriptors (shared design point with S2's inherited-socket
     case, ADR 0138 decision 2); attempted use of a descriptor beyond the three standard streams;
     attempted `/proc/self/fd` enumeration to find anything beyond those three.
   - **Resource exhaustion and flood.** CPU, address-space (`RLIMIT_AS`, virtual not resident — the
     explicit, already-stated limit in `docs/worker-isolation.md` section 5), process count, disk
     (`/scratch` size cap plus `RLIMIT_FSIZE`), and open-file-descriptor (`--nofile=256`) exhaustion, each
     tested at and just beyond its configured limit; stdout and stderr floods at and just beyond
     `cap_out`/`cap_err`, confirming `Termination::OutputLimit` fires and the tree is killed
     (`sandbox.rs` lines 245-271, 310-311) without the flood blocking the supervisor itself (the existing
     "keep draining so the child is not blocked" design, `sandbox.rs` lines 260-261).
   - **Forged completion or isolation attestation.** A hostile engine that prints a well-formed
     `worker-result/1` document claiming `complete`/full roster while actually dropping, corrupting, or
     substituting data; the existing parser's exact-schema/no-unknown-fields/counter-consistency checks
     (`docs/worker-isolation.md` section 7) are the only defense and are unchanged. A hostile engine
     cannot forge an `IsolationVerification` — that type is `#[non_exhaustive]` and constructible only by
     `run_self_check` inside the trusted control-plane process (`crates/custodian-worker/src/isolation.rs`
     lines 62-74), never by payload code, which already rules out the "forge trusted completion or
     isolation attestation" case issue #56 names, by construction rather than by a new probe.
3. **Bounded-output and flood-control requirements are already implemented**, cited above; this ADR
   states that the future probe matrix's job is to *exercise* `cap_out`/`cap_err`/`RLIMIT_*` at their
   exact configured boundary on a real ARM64-sandboxed child, not to invent a new limiting mechanism.
4. **"No releasable evidence on hostile leakage" is already implemented** as
   `ExecutionRecord::is_releasable()` returning `false` for every outcome except `Success`
   (`crates/custodian-contracts/src/execution.rs` lines 93-97), checked before disclosure
   (`crates/custodian-disclosure/src/service.rs` line 478). This ADR states explicitly: a future S3
   adversarial test that successfully triggers a hostile outcome (a canary leaking, a forged result
   slipping past the parser, a resource-exhaustion crash) must be checked against this existing gate —
   if the gate already gives `false` for that outcome, the test is confirming existing behavior, not
   motivating a new mechanism; if a test ever found a hostile `Success` outcome carrying leaked data,
   that would be a parser or staging defect to fix under the existing contract, not a reason to add a new
   disclosure rule.
5. **Coordination, not reimplementation.** Lifecycle, timeout, and resource ownership for a remote worker
   deployment belong to issue #44 and ADR 0133's proposed (not implemented) remote execution adapter; this
   ADR does not reassign or duplicate that ownership. Cancellation and uncertain-exposure accounting stay
   on the existing conservative rule (`docs/worker-isolation.md` section 7's outcome table: a cancel during
   run is "consumed (running: presumed exposed)").
6. **No adversarial probes have been run.** This ADR states what the matrix must contain. It does not run
   any filesystem, process, privilege, descriptor, resource-exhaustion, flood, or forged-result attack
   against a real ARM64-sandboxed child. Doing so requires S1's real `Sandbox`/`run_self_check` wired onto
   the confirmed `ubuntu-24.04-arm` runner from ADR 0137 — explicit future work, out of scope here, and
   not invented by this ADR.

## Status of the claim: design-only versus CI-checked versus AWS-verified

| Aspect | Design only (not probed) | CI-checked (pending a future run) | AWS-verified |
| --- | --- | --- | --- |
| Mount namespace (runner state absent, not merely denied), PID namespace, capability drop | Unchanged; already implemented (`bwrap.rs`) | Yes on x86_64 (`worker-isolation` CI job, `linux_isolation.rs`); not yet on ARM64 | **No** — the only AWS trial ran the deliberately unsandboxed `probe.rs`; it is not evidence about the real mount/PID namespace |
| `prlimit` resource bounds, `supervise` wall-clock/output/tree-kill | Unchanged; already implemented | Yes on x86_64 (fork bomb, memory, disk, CPU, stdout flood, timeout, tree cleanup per `docs/worker-isolation.md` section 10); not yet on ARM64 | No |
| `ExecutionRecord::is_releasable()` / disclosure gate on non-`Success` outcomes | Unchanged; already implemented | Covered by `crates/custodian-contracts/tests/bindings.rs`'s `only_full_success_is_releasable` and the daemon pipeline test; architecture-independent, not an isolation-specific test | No |
| Filesystem/archive-traversal, writable-mount-escape probe cases (new) | Yes — specified here; no code added | Not run anywhere yet | Not attempted (the unsandboxed diagnostic has no mount boundary to test) |
| Same-uid runner-file-read probe, specifically repeating ADR 0136's finding against a real sandbox | Yes — specified here; no code added | Not run anywhere yet | **AWS-verified as a failure in the unsandboxed case**: the child read the runner's 0600 canary (ADR 0136). Whether the real mount-namespace-absent design prevents this on ARM64 is unverified |
| Fork-bomb/resource-exhaustion/flood probes beyond the configured limit, on ARM64 specifically | Yes — specified here (restates existing x86_64 cases) | Not run on ARM64 yet | Not attempted (`docs/worker-isolation.md` section 10's rows are x86_64-only) |
| Supplementary-group escape probe | Yes — specified here; explicitly an open risk per ADR 0137, not resolved by this ADR | Not run anywhere yet | Not attempted |
| Forged-completion/attestation probe | Yes — specified here; ruled out by construction for the attestation half (`#[non_exhaustive]`, no payload-side constructor) | Covered indirectly by `tests/dispatch_fake.rs` and `tests/staging_result.rs` on the result-forgery half | Not attempted |
| Real `Sandbox`/`run_self_check` execution of any of the above on ARM64 | — | **Not attempted.** Requires S1's self-check wired to the confirmed `ubuntu-24.04-arm` runner (ADR 0137); explicit future work | Not attempted |

No claim in this ADR should be read as "a runner-protection or hostile-containment probe passed" or
"ran" on ARM64 or on real AWS infrastructure with a real sandbox. ADR 0136's worker NO-GO is unchanged
by this ADR.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| No new custody, isolation, or disclosure logic is introduced; S3's design reuses the existing mount/PID/capability namespaces, `prlimit`/`supervise` bounds, and `ExecutionRecord::is_releasable()` exactly as implemented | Code review: this ADR's diff touches no file under `crates/custodian-worker/src` or `crates/custodian-contracts/src` |
| The attack-category matrix specified here enumerates every category issue #56's "Work" and "Acceptance" sections name (filesystem, process, privilege, descriptor, resource/flood, forged attestation) | Review against issue #56, line by line |
| Hostile or adversarial outcomes cannot become releasable evidence | `ExecutionRecord::is_releasable()` already returns `false` for every `ExecutionOutcome` except `Success` (`execution.rs` lines 93-97), independent of whether the underlying attack "succeeded" against the sandbox |
| A hostile engine cannot construct a passing `IsolationVerification` from inside the payload | `IsolationVerification` is `#[non_exhaustive]` and constructed only by `run_self_check`, which runs in the trusted control-plane process, never by payload code |
| This ADR makes no claim that any probe in the matrix has run on ARM64 or against real AWS infrastructure | This document's own "Status of the claim" table above |

## Adapter contract

Unchanged. The runner-protection mechanisms sit entirely inside the existing `Sandbox` trait boundary and
`supervise`'s shared supervision loop (`crates/custodian-worker/src/sandbox.rs`); the disclosure gate sits
in `crates/custodian-contracts/src/execution.rs` and `crates/custodian-disclosure/src/service.rs`. This
ADR adds no new port and reassigns no existing one; lifecycle/resource ownership for a remote deployment
stays with issue #44 and ADR 0133 as already decided.

## Failure and recovery

Unchanged from `docs/worker-isolation.md`. A future adversarial probe that fails, or that cannot run at
all (missing tool, missing runner label, an attack that cannot even be attempted), leaves
`run_self_check` returning a `SelfCheckError` and `build_worker` returning `(None,
"isolation_check_failed")`; the daemon answers `worker_unavailable`. A hostile outcome during an ordinary
dispatch (not the self-check) maps through the existing outcome table
(`docs/worker-isolation.md` section 7) to `Failed`/`Rejected`, which is "failed, consumed" settlement and
never releasable, per the existing `is_releasable()` gate. This ADR introduces no new failure or recovery
path because it introduces no code.

## Performance evidence plan

Not in scope. Measuring the wall-clock or resource cost of an expanded adversarial probe matrix is
deferred to the same future work that wires the real self-check onto a confirmed ARM64 runner (tracked
under #56 itself, feeding S4 #57).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Runner-protection/hostile-containment attack-category matrix specification (this ADR) | yes | yes (a specification; no code consumes it) | no |
| "No releasable evidence on hostile leakage" rule | yes | yes — already implemented as `ExecutionRecord::is_releasable()`, predating this ADR | no (nothing deployed) |
| Expanded adversarial probe code in `crates/custodian-worker` | yes (this ADR states the design) | no — explicit future work, not this change | no |
| Real adversarial probes run against an ARM64-sandboxed child | yes (eventually, once S1 is fully wired) | no | no |
| Worker NO-GO from ADR 0136 | — | unchanged | unchanged |

## Consequences, migration, exit

No approval, retention, budget, disclosure, or signer policy changes. No schema migration. This ADR does
not change the worker NO-GO from ADR 0136; it does not authorize any new AWS provisioning; it does not
claim any runner-protection or hostile-containment case has been probed on ARM64 or in a real sandboxed
AWS run. Once S1's real `Sandbox`/`run_self_check` is confirmed running on the ARM64 runner from ADR
0137, the next step is implementing the attack-category matrix specified in the "Decision" section above
against that confirmed runner — not inventing a new mechanism — coordinated with S2's probe additions
(ADR 0138) and with #44's lifecycle/resource ownership, followed by S4 (#57)'s exact-image AWS isolation
matrix rerun.

## Open risks and revisit triggers

- **Supplementary-group dropping remains an open risk, not a positive control**, carried over
  unresolved from ADR 0137; a future self-check addition asserting `getgroups()` is empty is the
  concrete fix, not yet built.
- **Virtual-address (`RLIMIT_AS`) and resident-memory are different quantities** (`docs/worker-isolation.md`
  section 5); a future adversarial memory-exhaustion probe must say which one it is attacking and not
  conflate a virtual-address-space spike with resident-memory pressure, since no cgroup memory controller
  is in use.
- **The matrix is a specification, not code.** If a future implementer narrows it (for example, skipping
  the archive-traversal or forged-attestation cases) without revising this ADR, that narrowing should be
  treated as a design change requiring review.
- **x86_64 evidence must never be substituted for ARM64 evidence**, including in a future PR's
  description — the same caution ADR 0137 states and ADR 0136's original mistake illustrates.
- **A nested-virtualization base image may mask `/proc` or further restrict user namespaces**, which
  could make some of these probes fail closed for reasons unrelated to a real attack succeeding
  (ADR 0137's own open risk, restated here because it applies equally to S3's probes); a fail-closed
  result from such masking must be read as "unknown," not as a passing or failing finding.
- **cgroup v2 controllers, seccomp filters, and per-run disk I/O shaping remain unimplemented**
  (`docs/worker-isolation.md` section 9); this ADR does not change that scope, and any adversarial probe
  that relies on one of those being present will correctly find it absent.

## Addendum (2026-10-04): the existing mount/PID/capability/resource checks now have real ARM64 evidence

ADR 0137's addendum records that `worker-isolation-arm64` ran the full, **unmodified**
`linux_isolation.rs` and `linux_pipeline.rs` suites on `ubuntu-24.04-arm`, 15 and 2 tests
respectively, all passed, zero skipped. Concretely, these rows in the "Status of the claim" table
above move from "not yet on ARM64" / "unverified" to **done, and passed, on real ARM64 hardware**:

- Mount namespace (runner state absent), PID namespace, capability drop — `linux_host_files_are_not_reachable`,
  `linux_launcher_credentials_and_env_never_reach_the_worker`, `linux_staged_artifacts_are_read_only_to_the_worker`,
  and the self-check's `pid_namespace`/`no_capabilities` checks inside `linux_self_check_records_real_verification`.
- `prlimit` resource bounds and `supervise`'s wall-clock/output/tree-kill logic —
  `linux_fork_bomb_is_bounded_and_cleaned`, `linux_memory_exhaustion_is_bounded`,
  `linux_disk_exhaustion_is_bounded_to_the_scratch_quota`, `linux_cpu_spin_is_stopped_by_the_cpu_limit`,
  `linux_stdout_flood_is_bounded`, `linux_timeout_kills_the_whole_tree`.
- Cancellation cleanup and identity tampering — `linux_cancellation_cleans_up_the_worker_tree`,
  `linux_identity_tampering_fails_closed_under_the_real_sandbox`.
- The hostile-engine-cannot-leak-bytes property, specifically, at the pipeline level —
  `a_hostile_engine_inside_real_bubblewrap_still_cannot_carry_protected_bytes_out`
  (`linux_pipeline.rs`), which is the closest existing test to this ADR's "forged completion or
  isolation attestation" and "no releasable evidence on hostile leakage" categories, now run end
  to end through the daemon pipeline on ARM64, not just unit-level on `is_releasable()`.

This is the direct answer, on real ARM64 hardware, to ADR 0136's original same-uid-runner-file-read
finding: `linux_host_files_are_not_reachable` passing means the mount-namespace-absent design (the
runner's control file, credentials, and host paths are not present in the child's view, not merely
permission-denied) **does prevent that exact failure mode on ARM64** — the first real evidence
either way.

**What did NOT change — this ADR's new matrix items remain unimplemented and unrun:**
symlink/hardlink/archive-traversal probes against `/scratch`, writable-mount-escape attempts
through a `RoMount`, the supplementary-group escape probe (still an open risk per ADR 0137, not
resolved), descendant/daemonized-process-survival probes beyond what `linux_fork_bomb_is_bounded_and_cleaned`
already covers, and a dedicated forged-`worker-result/1` adversarial probe (distinct from the
existing parser unit tests). None of these are covered by the suite that ran. Issue #56 should not
be read as closed by this addendum.

**What did NOT change — ADR 0136's AWS finding itself:** this ran on a GitHub-hosted CI runner, not
inside an actual AWS Lambda MicroVM with the real sandbox wired into the deployed image. ADR
0136's worker NO-GO stands unchanged; S4 (#57)'s live-AWS rerun, with the sandbox actually in the
image this time, is the step that would make this finding count as resolved on the real target
infrastructure, and it has not been attempted.

## Addendum (2026-10-04): the new attack-category probes ran for real, on both architectures, and found a nonzero supplementary-group count

Issue #56's symlink/hardlink-escape, descriptor-count, supplementary-group, and forged-attestation
probes (all listed as "unimplemented and unrun" in the addendum above) were implemented in
`crates/custodian-worker/tests/linux_isolation.rs` and `crates/custodian-worker/src/bin/fixture.rs`
and **actually executed** inside a real `BubblewrapSandbox` on both `worker-isolation` (x86_64) and
`worker-isolation-arm64`, with `CUSTODIAN_REQUIRE_ISOLATION=1`. All 23 tests in the suite passed on
both runs (up from 15), with no skip. Concretely, each case in this ADR's Decision section 2 moves
from "specified, no code added" to the following observed result, on **both** architectures:

- **Filesystem.** `linux_symlink_inside_scratch_cannot_escape_to_a_host_path` and
  `linux_hardlink_cannot_cross_from_scratch_to_a_staged_mount` both passed: a symlink created inside
  `/scratch` pointing at a host path outside the sandbox could not be read through (the target is
  absent from the mount namespace, matching the existing `host_files_absent` property, not a new
  mechanism), and a hardlink from the writable `/scratch` tmpfs to a file on the read-only staged
  `RoMount` failed (confirmed by `crates/custodian-worker/tests/argv.rs`'s existing
  `mounts_are_read_only_and_system_roots_are_explicit` that `/scratch` and the staged mounts really
  are distinct mount points in `build_argv`'s argv, not merely different paths).
- **Descriptor.** `linux_no_extra_file_descriptor_is_inherited_by_the_payload` passed with exactly
  3 descriptors counted on both architectures — confirming, for the first time with a real probe
  rather than an inference from `prepare_command`'s source, that no bwrap-internal sync pipe or
  socketpair leaks into the final exec'd payload.
- **Privilege (supplementary groups) — the genuine finding.** `linux_supplementary_groups_are_recorded_not_assumed`
  passed (it only asserts that a count was parseable, not that the count is zero), and logged
  `PROBE-RESULT groups: supplementary_group_count=5` on **both** the x86_64 and the ARM64
  GitHub-hosted runners. **This is new, real evidence that the open risk ADR 0137 flagged
  ("Supplementary groups: an explicit open risk, not yet a positive control") is not hypothetical:
  the sandboxed child genuinely retains a nonzero set of supplementary group IDs** — `--unshare-user`
  and `--cap-drop ALL` do not, by themselves, clear `getgroups()`. The identical count on both
  architectures is consistent with both runners' `bwrap`-launching user having the same small set of
  default groups, carried into the child's credentials unchanged. This finding does **not** by
  itself demonstrate an exploitable escape (no probe here attempted to use a supplementary group to
  reach anything — that attempt is still future work, as this ADR's Decision section 2 "Privilege"
  item already said), and it does **not** change ADR 0136's worker NO-GO or authorize any new AWS
  work. It does mean the open risk should be treated as confirmed-present, not merely theoretical,
  until a future self-check adds an explicit `getgroups()`-empty assertion (this ADR's own "Open
  risks" section already named this as the concrete fix, not yet built; it remains not built).
- **Forged attestation.** The new assertion inside
  `linux_dispatch_maps_both_domains_and_failures_without_clean_crashes` (the `forged-attestation`
  fixture mode, a `worker-result/1` document carrying an extra `verification` object shaped like a
  passing `IsolationVerification`) passed on both architectures: `validate_result`'s
  `#[serde(deny_unknown_fields)]` parser rejects it with `ResultMalformed`, the same way it already
  rejects `unknown-field`. No change to the parser was needed; this is confirmation, not a fix.

**What did NOT change:** DNS-by-name-resolution (as opposed to the raw-socket case, which S2's
addendum below covers), archive-traversal probes (no archive reader exists to probe), and
descendant/daemonized-process-survival probes beyond `linux_fork_bomb_is_bounded_and_cleaned`
remain unimplemented. ADR 0136's worker NO-GO is unchanged. No AWS work was authorized or
performed by this addendum.
