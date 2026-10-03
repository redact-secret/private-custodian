# Worker isolation (C6)

Status: **implemented** in `crates/custodian-worker` and tested with synthetic data; **not deployed**.
Decisions: [ADR 0040](adr/0040-worker-sandbox-interface-linux-backend-and-dependencies.md) (interface,
Linux backend, dependencies), [ADR 0041](adr/0041-isolation-self-check-verification-record-and-supported-deployments.md)
(self-check, supported deployments, skip policy),
[ADR 0042](adr/0042-dispatch-order-identity-verification-staging-and-result-protocol.md) (dispatch order,
identity checks, staging, result protocol). This repository is maintained by the Redact Secret project;
nothing here is independent validation. Rust, `chmod`, a container or a manifest flag alone is not
evidence of isolation; the self-check below is.

## 1. Threat model recap

From [ADR 0001](adr/0001-trust-boundaries-and-threat-model.md): the engine, adapter, scanners and candidate
are untrusted code that is handed protected synthetic bytes. They may try to read host files or
credentials, reach the network, exhaust CPU, memory, processes or disk, flood stdout or stderr, outlive the
run, alter their own inputs, swap a binary between check and use, or return a forged, partial or
secret-bearing result. The control plane (this crate, the store, the corpus) is trusted. Engine
measurement logic stays in credential-eval and pii-eval; nothing in this crate computes a score.

## 2. What runs where

| Piece | Side | Notes |
| --- | --- | --- |
| `Dispatcher`, `Staging`, `validate_result`, store and corpus adapters | trusted control plane | Same process as the control service; never runs engine code |
| `Sandbox` backends | boundary | `BubblewrapSandbox` (Linux), `RefusingSandbox` (everything else), `TestOnlyUnsandboxedFake` (`test-fakes` feature, tests only) |
| Engine, adapter, scanners, candidate | untrusted | Pinned binaries run inside the sandbox; never imported as source |
| `custodian-worker-probe` | trusted, runs inside | Self-check probe; holds no secret |
| `custodian-worker-fixture` | test only | Synthetic hostile engine; never in a production allowlist |

## 3. Sandbox backends

**Linux (`BubblewrapSandbox`)**: the launcher is `bwrap` from a fixed location (never `PATH`), started
with a structured argv (no shell, no string interpolation; a hostile argument stays one `argv` element) and
a cleared environment. It requests: new user, IPC, PID, network and UTS namespaces (cgroup namespace when
available); all capabilities dropped; a new session; `--die-with-parent`; a fresh tmpfs root remounted
read-only containing only `/usr`, `/lib*`, `/bin`, `/sbin` (read-only), `/proc`, a minimal `/dev`, the
read-only staged mounts, and a size-capped tmpfs `/scratch`; `--clearenv` plus a validated allowlist. Inside
the namespaces, `prlimit` applies `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_FSIZE`, no core dumps
and a file-descriptor cap, then executes the engine. `build_argv` is a pure function with unit tests that run
on every platform (`tests/argv.rs`).

**Unsupported platforms (`RefusingSandbox`)**: `run` always returns `UnsupportedPlatform`. A `Dispatcher`
cannot be built on it, because the self-check cannot pass. macOS is such a platform. There is no code
path that runs a candidate without the boundary in a product build.

**Test fake (`TestOnlyUnsandboxedFake`)**: compiled only with the `test-fakes` feature (enabled by the
crate's own dev-dependency, never by a product build). It runs the program as an ordinary child with a
scrubbed environment and **no isolation**. It reports its own kind, `Dispatcher::new` refuses it,
`run_self_check` refuses it, and only `Dispatcher::new_for_tests` accepts it together with a verification
marked `TestOnlyNotIsolated`. Tests that use it prove dispatcher logic, not isolation.

## 4. The startup self-check

`run_self_check(sandbox, launcher_version, probe, allowlist, work_base, now)` runs the probe **inside the
sandbox that will run engines** and returns an `IsolationVerification`. `Dispatcher::new` accepts only a
`Verified` record with every check passed, produced for the same sandbox kind. The record is
`#[non_exhaustive]`, so code outside the crate cannot forge one. The dispatcher also refuses a record older
than `verification_max_age_secs` (default 3600), so a long-running service must re-run the check.

| Check id | What is attempted inside the sandbox | Pass means |
| --- | --- | --- |
| `egress_denied` | TCP to the host's loopback listener, a public address, TEST-NET and RFC 1918 addresses; a UDP send | Every attempt fails; the host-side listener also saw no connection (`host_listener_untouched`) |
| `host_files_absent` | Open a canary file the self-check wrote on the host; stat `/root`, `/home`, `/etc/shadow`, secret-mount paths | None reachable |
| `env_scrubbed` | Launcher is given canary variables named like ledger, App, DB-admin, GitHub and AWS credentials; probe lists its own environment | No canary present; every name is on the allowlist |
| `write_outside_scratch_denied` | Create files in `/`, `/usr`, `/input`, `/stage` | All fail |
| `scratch_writable` | Positive control: write 4 KiB in `/scratch` | Succeeds (a probe that can do nothing cannot pass) |
| `pid_namespace` | Count visible processes in `/proc` | At most 8 |
| `no_capabilities` | Read `CapEff` | Zero |
| `rlimits_applied` | Read `/proc/self/limits` | CPU, address space, processes match the requested values; core is 0 |

A failure returns a `SelfCheckError` carrying the fixed reason, the fixed ids of the failed checks and how
the probe ended. It never carries probe output. The verification stores the sandbox kind, grade, per-check
results, probe digest, launcher version string, platform and time. It is evidence for that host at that
time, not a standing property.

## 5. Quotas, limits and what each one bounds

Quotas come from the approved plan's `ResourceLimits`, capped by `OperatorCaps` (a plan can ask for less,
never more). Zero is refused as an inconsistent plan.

| Quota | Mechanism | Honest limits |
| --- | --- | --- |
| Wall clock | Supervisor deadline; kills the whole tree | Includes everything; the primary aggregate bound |
| CPU | `RLIMIT_CPU` per process | Per process, not summed across children; wall clock and the process cap bound the total |
| Memory | `RLIMIT_AS` per process | Virtual address space, not resident memory; no cgroup memory controller is used (not claimed). Scratch tmpfs pages are not covered by it |
| Processes | `RLIMIT_NPROC` inside the new user namespace | Counted per user namespace on current kernels (5.14 or later); verified by the fork-bomb test on the CI runner |
| Storage | Size-capped tmpfs `/scratch` plus `RLIMIT_FSIZE` | Bounds scratch only; staged inputs are read-only and sized by the corpus |
| stdout | Read bound `min(plan limit, 64 KiB)`; one byte more trips `OutputLimit` and a kill | stdout is the result channel only |
| stderr | Counted and discarded, bound `min(plan limit, 1 MiB)`; excess trips `OutputLimit` | Content is never retained or logged |

Process-tree cleanup has two layers: the sandbox's PID namespace dies with its init (and
`--die-with-parent`), and the supervisor kills the child's process group and reaps it on every exit path,
including a normal exit with a daemonized child. Group kill uses the system `kill` utility because the crate
forbids `unsafe`; its failure is not fatal because the PID namespace is the primary mechanism.

## 6. Dispatch order, identity and staging

The order is fixed (ADR 0042): reserve (store, by the caller) -> verify identities -> `start` -> stage and
re-verify -> **`record_exposure`** -> open corpus -> run -> re-verify -> `begin_validation` -> validate ->
`finish`.

- Engine, adapter, scanners, candidate and configuration are files whose SHA-256 is frozen in the approved
  plan (`ArtifactIdentity`, `CandidateDigest`, `ConfigDigest`). Each path must resolve under an allowlisted,
  owner-only root as a regular, unaliased file (no symlink in the final component or any ancestor, no hard-link
  alias, no group or other write bit). Digests are checked **before** any protected input is touched; a
  mismatch is `fail_before_start` (refunded, nothing exposed).
- Each artifact is copied once into a private 0700 staging directory while hashing the exact bytes copied,
  then mounted read-only. Staged copies are re-hashed after staging, again immediately before launch, and
  again after execution together with the source files and the shape of the input directory. A change in any
  of them is `Rejected`, whatever the worker returned.
- Protected inputs are written as new read-only regular files (`create_new`, flat names matching
  `[a-z0-9][a-z0-9._-]{0,63}`, no links, no overwrite). The corpus handle is released as soon as inputs are
  staged. The staging directory is removed at the end of every run (cleanup, not secure erasure).
- The population binding returned by the corpus must equal the plan's (domain, corpus, epoch, population
  digest) or the run is `Rejected` (`PopulationMismatch`); the exposure is already recorded and consumed.
- `archive` formats are not accepted: every input is a flat file. `validate_member_path` exists so any
  future archive reader must validate names before materializing.

## 7. Worker protocol v1 and outcome mapping

The engine is started as `/stage/engine --job /job/job.json`. Staged files are `/stage/{engine, adapter,
candidate, config, scanner-N}`, inputs are `/input/<entry>`, scratch is `/scratch`. The job document
(`private-custodian.worker-job/1`) carries domain, protocol, roster size and opaque entry names.

The engine prints one document on stdout (`private-custodian.worker-result/1`): domain, protocol
`{name, version}`, `status` (`complete` or `partial`) and `roster {expected, observed, failed}`. The parser
rejects unknown fields, duplicate keys, trailing data, another schema version, another domain or protocol, an
`expected` that is not the authorized roster, `observed > expected`, `failed > observed`, and a status that
disagrees with the counters. Free-form worker text has no field to travel in, and stderr is never kept.
The raw private document is returned only as `ValidatedResult::private_bytes()` for private storage, with a
`PrivateArtifactRef` (digest, size, protocol).

| Worker behavior | `ExecutionOutcome` | Reason code (private) | Store settlement |
| --- | --- | --- | --- |
| Clean exit, `complete`, observed = expected, failed = 0 | `Success` | `completed` | completed, consumed |
| Clean exit, `partial`, or any failed item | `Partial` | `engine_partial` | failed, consumed |
| Crash, signal, SIGKILL by OOM, CPU limit | `Failed` | `signaled` | failed, consumed |
| Non-zero exit | `Failed` | `non_zero_exit` | failed, consumed |
| Wall-clock timeout | `Failed` | `timeout` | failed, consumed |
| stdout or stderr over its bound | `Failed` | `output_limit` | failed, consumed |
| Malformed, oversized, wrong domain or protocol, wrong roster | `Rejected` | `result_*`, `roster_mismatch` | failed, consumed |
| Any identity or population drift | `Rejected` | `identity_*`, `population_mismatch` | failed (refunded if before exposure) |
| Operator cancel before start | `Cancelled` | `cancelled` | cancelled, refunded |
| Cancel token during run | `Cancelled` | `cancelled` | cancelled, consumed (running: presumed exposed) |
| Store fenced the lease (cancel, recovery) | `Cancelled` | `lease_lost` | already settled by the store; the dispatcher does not settle |

A worker that did not exit cleanly never has its stdout parsed. Both domains (`credential`, `pii`) use the
same checked path; the domain only selects which frozen protocol the result must claim. A `Partial` outcome
is never releasable (`ExecutionRecord::is_releasable`), and `InternalReceipt` accepts partial only with
observed < expected, so C7 must not issue a receipt from an engine-reported `Partial` with
observed = expected (failed items); treat `Partial` as a private failure record.

## 8. Supported deployment isolation, and what the deployment must prove

Supported (planned for the first deployment): **Linux** (x86_64 or aarch64), kernel 5.14 or later, with
unprivileged user namespaces permitted, `bubblewrap` 0.8 or later and `util-linux` `prlimit` installed in
standard locations. The control service runs the dispatcher; workers run as a dedicated non-root account that
is not the control-service, runtime-DB, protected-storage, signer or ledger-writer identity. Engine
artifacts live under a root-owned, non-writable directory that is the allowlist root. The staging base is a
local owner-only directory. macOS, Windows and Linux hosts that fail the self-check are unsupported and run
nothing.

The deployment must itself prove, and record, each of these. None is established by this repository:

1. The self-check passes on the production host and image, at startup and after any change to the launcher,
   kernel, container runtime or allowlist; the verification record is retained with the run audit.
2. If workers run inside a container or VM, the self-check still passes inside it, and the container does
   not grant extra capabilities, a host PID namespace, host mounts, the Docker socket, or host credentials.
   A container's presence is not evidence; the self-check inside it is, and nesting restrictions (for
   example a masked `/proc`) may make it fail, which is the correct fail-closed result.
3. The host has no route that the worker's network namespace could reach another way, and host-level egress
   filtering is applied as defense in depth. (The namespace denial is verified; host firewalling is not
   implemented here.)
4. Ledger, App, signing and DB-admin credentials are not readable by the worker account, are not in the
   control-service environment inherited by it, and are held only by their own identities (ADR 0002).
5. The allowlist directory, staging base, protected storage and database directories have the owner-only modes
   the store and corpus already require; backups and snapshots of staging are controlled by retention policy.
6. Privileged or shared-host execution (anything weaker than the above, including a single host where an
   operator is also root) has an explicit risk decision recorded in an ADR, as ARCHITECTURE.md requires.

## 9. What is NOT claimed

- No claim of protection against a Linux kernel or `bwrap` vulnerability, a user-namespace escape, or a
  malicious host operator. Namespaces and rlimits reduce exposure; they are not a hardware boundary.
- No seccomp syscall filter, no cgroup v2 controllers (no memory, pids or CPU accounting), no per-run disk
  quota on the host filesystem, no I/O or network-bandwidth shaping. Residual denial-of-service on a shared
  host is possible within the wall-clock bound.
- No claim that scratch or staged protected inputs are securely erased; removal is ordinary deletion.
- No claim about side channels, timing, or the engine's own correctness. Custody and isolation do not
  establish ground truth or independence; evidence here is project-maintained.
- Isolation tests that did not run did not verify anything. On macOS they log
  `ISOLATION-TEST-SKIPPED <name>: <reason>` and return. The Linux isolation tests were exercised during
  development in a Docker container (not accepted as evidence); the evidence is the Ubuntu CI job
  `worker-isolation`, which sets `CUSTODIAN_REQUIRE_ISOLATION=1` so a skip fails the job.
- The lease-renewal heartbeat is checked about every 200 ms by the supervisor and acted on at the
  configured interval; a lease shorter than the heartbeat plus store latency can be lost spuriously, which
  fails safe (the store fences and consumes).
- Disclosure, suppression, signing and the App are out of scope (C7, C8, C3).

## 10. Evidence

| Control | Test | Where it runs |
| --- | --- | --- |
| Argv is structured and complete | `tests/argv.rs` | Everywhere |
| Refusing backend; fake refused by product constructors; self-check refuses fake | `tests/dispatch_fake.rs` | Everywhere |
| Ordering (exposure before corpus), outcome mapping, both domains | `tests/dispatch_fake.rs`, `tests/staging_result.rs` | Everywhere (fake sandbox) |
| Identity tampering before dispatch, after staging, after execution; allowlist, symlink, hard link | `tests/dispatch_fake.rs` | Everywhere (fake sandbox) |
| Malformed, oversized, partial-roster, secret-shaped stderr | `tests/dispatch_fake.rs`, `tests/staging_result.rs` | Everywhere (fake sandbox) |
| Real store and corpus integration, cancel fencing, refund and consume | `tests/integration_store_corpus.rs` | Everywhere (fake sandbox) |
| Self-check on a real sandbox | `linux_self_check_records_real_verification` | Linux with bubblewrap (CI `worker-isolation`) |
| Egress denied (incl. host loopback), host files, env and token absence, read-only stage | `tests/linux_isolation.rs` | Linux with bubblewrap (CI) |
| Fork bomb, memory, disk, CPU, stdout flood, timeout, tree cleanup, cancellation | `tests/linux_isolation.rs` | Linux with bubblewrap (CI) |
| Dispatch of both domains and failure modes under the real sandbox | `linux_dispatch_maps_both_domains_and_failures_without_clean_crashes` | Linux with bubblewrap (CI) |

## 11. Control-plane API (for C8, C11, C12)

```text
run_self_check(&dyn Sandbox, launcher_version, probe, &ArtifactAllowlist, work_base, now)
    -> Result<IsolationVerification, SelfCheckError>
Dispatcher::new(Arc<dyn Sandbox>, IsolationVerification, DispatcherConfig) -> Result<Dispatcher>
Dispatcher::run_attempt(&DispatchJob{plan, sources}, &dyn RunLedger, &dyn CorpusPort, &CancelToken)
    -> Result<DispatchReport>      // Err only when nothing could be settled
DispatchReport { outcome, reason, exposure, termination, result: Option<ValidatedResult>,
                 settled, elapsed, isolation }
StoreRunLedger::new(&SqliteStore, attempt, owner, actor, lease_secs, max_age, clock, observed)
PopulationsCorpus::new(&ProtectedPopulations<S>, Authorization)
```

The caller reserves first (`reserve_request`), passes the attempt id to `StoreRunLedger`, and stores
`ValidatedResult::private_bytes()` privately if the report carries one. The dispatcher never signs,
discloses or exports.

## Aggregates channel and the daemon pipeline (S5)

`worker-result/1` may embed an optional `aggregates` object (the `private-custodian.aggregates/1` artifact). It
travels on stdout, not through `/scratch`: scratch is namespace-private tmpfs, and a writable host bind would
widen the boundary. The dispatcher hands the validated result to a `ResultSink` before the attempt is settled.
Real engines do not emit it yet; `custodian-synthetic-engine` does. The `worker-isolation` CI job also runs the
daemon pipeline with the engine inside the real sandbox (`custodian-daemon/tests/linux_pipeline.rs`). ADR 0127;
[daemon.md](daemon.md).
