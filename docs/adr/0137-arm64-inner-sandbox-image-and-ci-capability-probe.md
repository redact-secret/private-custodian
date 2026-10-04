# 0137. ARM64 inner-sandbox image design and CI capability probe (S1, issue 54)

- Status: proposed (design); the capability-probe CI job is added but its result on GitHub's
  infrastructure is **unverified from this environment** (see "Status of the claim")
- Date: 2026-10-03
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Tracking: epic #40, issue #54 (S1); follow-on #55 (S2), #56 (S3), #57 (S4)

## Context

[ADR 0136](0136-authorized-microvm-experiment-findings.md) recorded that in the one authorized live
AWS MicroVM experiment, a same-uid child could read the trusted runner's owner-only (0600) synthetic
control file, because `deploy/aws/microvm/probe.rs` is a deliberately unsandboxed diagnostic (see
`deploy/aws/microvm/README.md`): it has **no inner process, mount or network boundary at all**, by
design, so that its failures expose the gap rather than a sandbox's blind spot. The absence of the
`unshare` tool in that diagnostic also left namespace support on that image neither confirmed nor
denied.

This repository already has an inner sandbox: `crates/custodian-worker` implements the `Sandbox`
trait, the Linux `BubblewrapSandbox` backend, and the startup self-check
(`crates/custodian-worker/src/sandbox.rs`, `bwrap.rs`, `isolation.rs`; [ADR 0040](0040-worker-sandbox-interface-linux-backend-and-dependencies.md)
through [ADR 0042](0042-dispatch-order-identity-verification-staging-and-result-protocol.md);
[docs/worker-isolation.md](../worker-isolation.md)). The `worker-isolation` CI job
(`.github/workflows/ci.yml`) already runs the real bubblewrap backend and fails the build if any
isolation test is skipped — but that job runs on `ubuntu-latest`, a **x86_64** GitHub-hosted runner.
GitHub's ARM64 Linux hosted runners use the distinct label `ubuntu-24.04-arm`; nothing in this
repository has ever run the self-check, `build_argv`, or the fork-bomb/egress/host-file isolation
tests on that architecture. The live MicroVM experiment that found the uid/mount-visibility gap ran
on ARM64 Lambda MicroVMs, so x86_64 CI evidence does not stand in for it: kernel build, default
`kernel.unprivileged_userns_clone`/AppArmor restriction, and available `bwrap`/`prlimit` packages can
all differ by image and architecture, not only by distribution version (worker-isolation.md section 8
already states this must be proven per host and image, not assumed).

Issue #54 (epic #40, S1) asks this repository to package and prove an enforceable inner sandbox on
ARM64, explicitly by reusing the existing `Sandbox`/`Dispatcher` contract rather than inventing new
custody logic, and explicitly as a **capability probe**, not the full dispatcher wiring (that is S2
`#55` network denial and S3 `#56` runner protection). The user authorized only offline/design/CI-level
work: no live AWS provisioning in this change.

## Options

| Option | Reuses the existing contract | Proves ARM64, not just x86_64 | Matches issue #54 scope |
| --- | --- | --- | --- |
| **Chosen: reuse `Sandbox`/`BubblewrapSandbox` unchanged; add an ARM64 image manifest and a capability-probe-only CI job** | Yes, no new custody code | Yes, once the job actually runs on GitHub's infrastructure | Yes |
| Treat the existing x86_64 `worker-isolation` CI result as sufficient evidence for ARM64 | N/A | No — this is exactly the mistake ADR 0136 warns against (architecture- and image-specific kernel behavior) | No |
| Build a second, ARM64-specific sandbox implementation | No — duplicates custody logic the issue says to reuse | Yes | No |
| Wire the full dispatcher onto a real ARM64 self-check run in this change | Yes | Only if the runner exists | No — issue #54 scopes this to packaging and a capability probe; full dispatch proof on ARM64 plus network/runner-protection hardening is S2/S3 (#55, #56) |
| Defer until the next live AWS experiment (S4, #57) | N/A | No | No — #54 is the explicit prerequisite the epic sequences before S2/S3/S4 |

## Decision

1. **No new custody logic.** The `Sandbox` trait, `BubblewrapSandbox::build_argv`, and
   `run_self_check` (`crates/custodian-worker/src/sandbox.rs`, `bwrap.rs`, `isolation.rs`) are
   unchanged by this ADR and are the only mechanism this repository will ever point at an ARM64
   host. There is no ARM64-specific sandbox code path.
2. **Image manifest.** `deploy/examples/arm64-sandbox-image.example.json` (new, placeholder-only,
   same convention as every other file in `deploy/examples/`) states the packages, kernel settings,
   and per-dispatch privilege/mount/capability contract an ARM64 image or CI tools image must provide
   before `BubblewrapSandbox::detect()` and `run_self_check` are even attempted. It restates, for
   ARM64, exactly the deployment requirements `docs/worker-isolation.md` section 8 already states for
   "Linux (x86_64 or aarch64)" — it does not invent new ones.
3. **CI capability probe (this change).** A new, separate workflow,
   `.github/workflows/arm64-sandbox-probe.yml`, runs on `runs-on: ubuntu-24.04-arm` and probes kernel
   and tooling support only: `unshare --user --pid --mount --net echo ok`,
   `/proc/sys/kernel/unprivileged_userns_clone`, `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`
   (when present), `/proc/sys/kernel/seccomp/actions_avail` (kernel seccomp support, not a filter
   installed by this repository, which installs none — see worker-isolation.md section 9), `bwrap
   --version`, and `prlimit --version`/presence. Each probe is independent and records exactly one of
   `supported`, `blocked`, or `untested` (tool absent or the specific file missing is `untested`, not a
   passing or failing denial — matching the "missing tools ... are not passing isolation evidence"
   rule in issue #54's scope note). This is a capability probe, **not** the `worker-isolation` self-check:
   it does not build a `BubblewrapSandbox`, does not run `run_self_check`, and launches no evaluation
   engine. It is intentionally separate from the `ci` workflow so a currently-unavailable ARM64 runner
   label cannot block ordinary pull requests.
4. **Refusal, not fallback, is unchanged and explicit.** `Dispatcher::new` already refuses to
   construct without a `Verified` `IsolationVerification` produced by `run_self_check` on the same
   `SandboxKind`, and `custodian-daemon::runtime::build_worker` already returns `(None,
   "isolation_unavailable")` or `(None, "isolation_check_failed")` on any setup or self-check failure
   instead of running anything (`crates/custodian-daemon/src/runtime.rs`). This ADR changes none of
   that logic; it only adds an image manifest and a probe that must never be wired to accept a
   degraded result as "verified." A failed or missing ARM64 probe keeps the ARM64 worker NO-GO from
   ADR 0136 in force; it is not evidence either way until it actually runs.

## Design: identity separation, mounts, `/proc`, descriptors, result channel

All of the following is **already implemented and already applies on any architecture**, including
ARM64, because it lives in the architecture-independent `Sandbox` trait and `BubblewrapSandbox`
backend; nothing here is new code. It is restated so the ARM64 image manifest can be checked against
it line by line.

- **Runner and child identity.** The dispatcher, store, and corpus adapters run in the trusted
  control-plane process and never execute engine code (`docs/worker-isolation.md` section 2). The
  worker account is a dedicated, non-root identity distinct from the control-service, runtime-DB,
  signer, and ledger-writer identities (`docs/worker-isolation.md` section 8). The uid the launcher
  runs as is **not** the boundary the live experiment was missing — unprivileged user namespaces keep
  the host uid as far as `DAC` is concerned. The boundary that experiment lacked entirely was the
  **mount namespace**: `--unshare-user` plus a fresh, remounted-read-only tmpfs root means the child's
  filesystem view contains only `/usr`, `/lib*`, `/bin`, `/sbin` (read-only), the explicit
  `ro_mounts`, `/proc`, a minimal `/dev`, and a size-capped `/scratch` — the runner's control file,
  sockets, and working directories are never bind-mounted in, so they are not merely permission-denied,
  they are **not present** in the child's view at all. This is exactly the property the unsandboxed
  AWS diagnostic (by explicit design, see `deploy/aws/microvm/README.md`) did not have.
- **Read-only runtime/input mounts.** `build_argv` binds the system roots and every `RoMount` from
  `SandboxSpec.ro_mounts` with `--ro-bind`, then issues one final `--remount-ro /` after all mounts are
  in place, so even the fresh tmpfs root itself ends read-only before the target program runs.
- **Private scratch.** `--tmpfs /scratch` sized exactly to the plan's `storage_bytes` quota is the only
  writable path, and it is namespace-private: it is never bind-mounted from a host directory, so there
  is no host-writable path a nested VM/container layer could expose it through (`docs/worker-isolation.md`
  section 7, "Aggregates channel" note).
- **`/proc` visibility.** `--proc /proc` is a fresh procfs for the new PID namespace; the self-check's
  `pid_namespace` control requires at most 8 visible processes, so the child cannot see runner or
  sibling-attempt processes.
- **Inherited-descriptor handling.** `prepare_command` (`sandbox.rs`) sets `stdin(Stdio::null())`,
  redirects `stdout`/`stderr` through pipes the supervisor reads, and calls `process_group(0)` so the
  child leads its own process group. Rust's standard library marks file descriptors it opens
  close-on-exec by default, so the launcher process passes the child no file descriptor beyond the
  three explicitly redirected standard streams; the result channel is `stdout` only, bounded at
  `min(plan limit, 64 KiB)` with a one-byte-over kill (`Termination::OutputLimit`), and `stderr` is
  counted and discarded, never retained (`docs/worker-isolation.md` section 5).
- **Result channel.** The worker protocol (`docs/worker-isolation.md` section 7) is the single
  `private-custodian.worker-result/1` JSON document on `stdout`; there is no side channel through
  `/scratch`, the filesystem, or an inherited socket, because none of those are reachable from the
  child's mount/PID/network namespaces.
- **Runner state and endpoints stay outside the child's view** as a direct consequence of the mount
  and network namespace unshares above: the control-plane's SQLite connection, staging-base parent
  directory, signer socket, and ledger clone are never mounted, bound, or reachable from inside the
  sandbox, because `--unshare-net` leaves no interface up (no route to the host's loopback either,
  verified by the self-check's `egress_denied` and `host_listener_untouched` checks) and the mount
  namespace never includes them.

## Design: privilege-drop sequence

The sequence below is the existing, unchanged order in `BubblewrapSandbox::build_argv`
(`crates/custodian-worker/src/bwrap.rs`), restated as the ordering guarantee the ARM64 image manifest
must preserve:

1. **Setup stays in trusted code.** Locating `bwrap` and `prlimit`, resolving pinned artifact digests,
   staging files, and building the argument vector all happen in the control-plane process, before any
   elevated or namespaced context exists. None of this requires `setuid`, `CAP_SYS_ADMIN`, or any
   capability beyond what an unprivileged user namespace grants; the image manifest requires
   `kernel.unprivileged_userns_clone=1` (or the distribution's equivalent) precisely so that no setup
   step needs root.
2. **Namespaces first.** `--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts
   --unshare-cgroup-try` are requested before anything else in the argument vector.
3. **Capabilities and session dropped before any mount or exec.** `--cap-drop ALL` and `--new-session`
   appear immediately after the namespace flags and before any `--ro-bind`, `--proc`, `--dev`, or
   `--tmpfs`. `--die-with-parent` is set in the same group, so an orphaned child cannot outlive a
   killed launcher. `--clearenv` follows immediately, before the allowlisted `--setenv` pairs are
   added later — the payload never sees the launcher's environment, only the names in `ENV_ALLOWLIST`,
   and names that look like credentials are refused even if someone adds them to that list
   (`env_name_allowed`, `DENY_FRAGMENTS`).
4. **Mounts, then the final read-only remount, then `chdir`.** System roots, `/proc`, `/dev`, the
   scratch tmpfs, and every `RoMount` are bound first; `--remount-ro /` is issued only after every
   mount is in place, so nothing can be made writable again after that point; `--chdir /scratch` puts
   the process in its only writable directory.
5. **`prlimit` runs inside the already-restricted namespaces, still before the target program**, and
   applies `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_FSIZE`, disables core dumps, and caps
   open files — all before `exec`-ing the pinned engine binary.
6. **Refusal, not fallback, on any setup or verification failure.** `SandboxSpec::validate()` rejects a
   malformed spec before any process is spawned; `BubblewrapSandbox::detect()` returns
   `IsolationUnavailable`/`UnsupportedPlatform` rather than degrading to an unsandboxed run if `bwrap`
   or `prlimit` is missing; `run_self_check` requires every one of the eight required checks
   (`REQUIRED_CHECKS`) to pass, in order, with no extra or missing lines, or it returns a
   `SelfCheckError` and `Dispatcher::new` is never called; `build_worker`
   (`crates/custodian-daemon/src/runtime.rs`) returns `(None, "isolation_unavailable")` or `(None,
   "isolation_check_failed")` on any of those failures, and the daemon then answers every approved run
   with `worker_unavailable` rather than executing anything outside the boundary. **There is no code
   path in a product build that runs a candidate, adapter, scanner, or engine without a sandbox that
   passed this sequence.**
7. **Supplementary groups: an explicit open risk, not yet a positive control.** `build_argv` does not
   itself call `setgroups`/drop supplementary groups; it relies on the unprivileged user namespace's
   own uid/gid remapping and on the dedicated worker account (item above) having minimal supplementary
   group membership by construction, the same way `deploy/examples/systemd/custodiand.service.example`
   pins `User=custodian-svc` with no additional groups. The ARM64 image manifest states this
   requirement explicitly (`worker_account.supplementary_groups: []`) so a reviewer can check it
   against the actual account the image creates; it is not independently probed by the self-check
   today and is listed as an open risk below.

## Status of the claim: design-only versus CI-checked in this change

| Aspect | Design only (not probed) | Checked by this change's CI job, pending an actual run |
| --- | --- | --- |
| `Sandbox` trait, `BubblewrapSandbox`, `run_self_check`, dispatch order, refusal-not-fallback | Unchanged; already covered on x86_64 by the existing `worker-isolation` job (`linux_isolation.rs`, `linux_dispatch_...`) | Not re-covered here; ARM64 coverage of the real self-check/dispatcher is explicit follow-up, not this change |
| ARM64 image manifest contents (packages, kernel settings, mount/capability contract) | Yes — a specification, not a provisioned host or image | N/A (no code consumes this manifest yet; nothing parses or enforces it) |
| Identity separation, read-only mounts, `/proc` visibility, descriptor handling, result channel (the section above) | No — these already run and are proven on x86_64 in CI; whether the *same* argv produces the *same* kernel behavior on an actual ARM64 host is unverified | Indirectly, if and only if the probe job below runs and every probe reports `supported` |
| Whether `ubuntu-24.04-arm` (or any ARM64 label) is actually schedulable on this repository's current GitHub plan/tier | **Unconfirmed from this sandboxed environment.** `gh api` shows this repository is public (`"visibility":"public"`) under the `redact-secret` organization on GitHub's Free plan, with zero self-hosted runners registered. Public repositories generally receive standard GitHub-hosted runner minutes at no charge, but there is no API queried here that confirms which hosted-runner *labels* (including `ubuntu-24.04-arm`) are enabled for this specific repository without actually dispatching a workflow, which this environment cannot do. | The workflow added by this change is the only way to find out; its result is not available yet |
| `unshare`/`/proc/sys/kernel/unprivileged_userns_clone`/seccomp availability/`bwrap` presence on the actual GitHub ARM64 image | **Unverified.** No claim of `supported`, `blocked`, or anything else is made in this ADR | This is exactly what `arm64-sandbox-probe.yml` is for; its output is the first real evidence, once a human observes a run |

No claim in this ADR or its accompanying files should be read as "ARM64 probes passed." None have run
from this environment, and this environment cannot execute GitHub Actions. ADR 0136's worker NO-GO is
unchanged by this ADR.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| No new custody logic is introduced; the ARM64 path reuses the exact `Sandbox`/`Dispatcher` contract already covered by `crates/custodian-worker`'s existing test suite | Code review: this ADR's diff touches no file under `crates/custodian-worker/src` or `crates/custodian-daemon/src` |
| A missing or failed ARM64 capability probe is recorded as `untested`/`blocked`, never silently treated as a pass | `arm64-sandbox-probe.yml` records one of three fixed outcomes per probe and never asserts `supported` on a probe it could not run |
| The capability-probe job cannot gate or silently pass `ci.yml`'s required checks | It is a separate workflow file, not a job added to `ci.yml`; it does not share `ci.yml`'s `concurrency` group |
| Refusal-not-fallback: sandbox-creation failure never launches an evaluation child | Unchanged, already covered by `tests/dispatch_fake.rs::product_constructor_refuses_the_fake_and_the_refusing_backend` and by `build_worker`'s `(None, reason)` returns on every failure branch |

## Adapter contract

Unchanged. The ARM64 image manifest sits above the existing `trait Sandbox` seam
(`crates/custodian-worker/src/sandbox.rs`); it is deployment configuration, not a new port. The core
`Sandbox`/`Dispatcher` contracts remain vendor- and architecture-neutral, as ARCHITECTURE.md requires.

## Failure and recovery

Unchanged from `docs/worker-isolation.md`: a failed self-check, missing `bwrap`/`prlimit`, or an
unsupported platform all leave `build_worker` returning `None`, so the daemon answers
`worker_unavailable` rather than ever executing a candidate outside the boundary. This ADR adds no new
failure or recovery path; the CI probe job has no runtime interaction with the custody store, budget,
or ledger at all.

## Performance evidence plan

Not in scope for this change. Issue #54 is packaging and a capability probe; measuring the dispatcher's
real wall-clock/CPU/memory behavior on an actual ARM64 host is deferred to the follow-up that wires the
real self-check onto a confirmed ARM64 runner (tracked under #55/#56/#57), which requires the runner
label's availability to be confirmed first.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| ARM64 image manifest (`deploy/examples/arm64-sandbox-image.example.json`) | yes | yes (a placeholder specification; nothing parses or enforces it) | no |
| ARM64 capability-probe CI job (`arm64-sandbox-probe.yml`) | yes | yes (added; whether it runs/passes on GitHub's infrastructure is unconfirmed from this environment) | no |
| Real `Sandbox`/`run_self_check` proof on ARM64 | yes (this ADR states the design is already architecture-neutral) | no (not attempted in this change; scoped to #55/#56/#57) | no |
| Worker NO-GO from ADR 0136 | — | unchanged | unchanged |

## Consequences, migration, exit

No approval, retention, budget, disclosure, or signer policy changes. No schema migration. This ADR
does not change the worker NO-GO from ADR 0136; it does not authorize any new AWS provisioning; it
does not claim ARM64 isolation is proven. Once a human observes the probe workflow actually run on
GitHub's infrastructure and records which of `unshare`, `unprivileged_userns_clone`,
`seccomp/actions_avail`, and `bwrap`/`prlimit` presence are `supported` versus `blocked` versus
`untested`, the next step is wiring the real self-check (`run_self_check` against a real
`BubblewrapSandbox`) onto that confirmed ARM64 runner — not inventing a new mechanism — which is
explicit follow-up, not this change.

## Open risks and revisit triggers

- **Runner-label availability is unconfirmed.** If `ubuntu-24.04-arm` is not schedulable on this
  repository's current plan/tier, the workflow will show as failed or stuck at the queue stage; that
  outcome must be read as "unknown," not as a kernel/tooling finding.
- **Supplementary-group dropping is not an automated positive control.** See privilege-drop step 7
  above; a future self-check addition could assert `getgroups()` is empty inside the sandbox, the same
  way `no_capabilities` already asserts `CapEff` is zero.
- **x86_64 evidence must never be substituted for ARM64 evidence**, including in a future PR's
  description; this was explicitly the mistake ADR 0136 warns against.
- **A nested-virtualization base image (e.g., a future AWS MicroVM base) may mask `/proc` or restrict
  user namespaces further than a bare GitHub-hosted runner does**; a pass on `ubuntu-24.04-arm` is
  evidence for that runner, not for every ARM64 execution environment this project might later target
  (worker-isolation.md section 8, item 2).
- **cgroup v2 controllers, seccomp filters, and per-run disk I/O shaping remain unimplemented** on any
  architecture; this ADR does not change that scope (worker-isolation.md section 9).
