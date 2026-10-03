# 0040. Worker sandbox interface, Linux backend and dependencies

- Status: accepted (design); implemented in `crates/custodian-worker` (C6); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ARCHITECTURE.md requires a worker boundary with no external egress by default, no host credentials,
restricted writable scratch, bounded stdout and stderr, CPU, memory, process and storage limits, and
timeout and process-tree cleanup. ADR 0001 (T1, T2) assumes engines and candidates are hostile. CONVENTIONS.md
requires structured executable arguments and says Rust, `chmod` or a container is not evidence. The
isolation platform was left open for C6. The crate forbids `unsafe`, the dev machine is macOS (no supported
isolation), and CI is Ubuntu.

## Options

| Option | Judged against: real egress and filesystem denial, no `unsafe`, structured argv, auditable, pinned, works on CI |
| --- | --- |
| `bwrap` (bubblewrap) launched with structured argv, plus `prlimit` for rlimits | Unprivileged user, IPC, PID, network and UTS namespaces, read-only root, tmpfs scratch, `--die-with-parent`, `--cap-drop ALL`, `--clearenv`. No daemon, no root. Small, widely reviewed (Flatpak). Needs unprivileged user namespaces and an installed binary. No new Rust dependency |
| `nsjail` | Adds seccomp and cgroup options in one binary, config files, less commonly packaged, larger attack surface. Deferred as a future backend behind the same trait |
| Docker or another container runtime | Needs a daemon with root, a socket that is itself a credential, and defaults that are not an assurance statement. Not accepted as isolation evidence |
| In-process `libc`/`nix` namespaces and seccomp | Needs `unsafe` (forbidden workspace-wide) or a new dependency with `unsafe` inside; larger review burden |
| A VM (Firecracker, gVisor) | Strongest boundary; needs infrastructure the first deployment does not have. Revisit trigger below |
| Defer | Blocks C8, C11, C12. Rejected |

## Decision

1. `trait Sandbox { kind(); run(spec, cancel, keepalive) -> RawRun }` is the only way to run engine code.
   Backends: `BubblewrapSandbox` (Linux), `RefusingSandbox` (every other platform: `run` always fails with
   `UnsupportedPlatform`), and `TestOnlyUnsandboxedFake` (feature `test-fakes`, tests only, applies no
   isolation and is named accordingly). There is no unsandboxed path in a product build.
2. The Linux backend is `bwrap` (found at fixed locations, never `PATH`) with `prlimit` running inside the
   namespaces. The argv is built as a vector of arguments; no shell is involved, and a hostile argument is
   one `argv` element. The launcher environment is cleared; the payload receives only the validated
   allowlist (`PATH, HOME, PWD, TMPDIR, LANG` and the staging roots), and names that look like credentials
   are refused even if added to the list.
3. Resource quotas: wall clock by the supervisor; `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_FSIZE` by
   `prlimit`; scratch size by `bwrap --size`; stdout bounded at read time; stderr counted and discarded.
4. Tree cleanup: PID namespace (dies with its init), `--die-with-parent`, and a supervisor that kills the
   child's process group and reaps on every exit path. `bwrap` reports a signaled payload as exit
   `128 + signal`; the backend maps that range to `Signaled`. Any non-zero or signaled end is a failure.
5. **No new third-party dependency.** `serde = "=1.0.229"`, `serde_json = "=1.0.151"` and `sha2 = "=0.10.9"`
   are the pins already justified by ADR 0004; `custodian-core`, `-contracts`, `-corpus` and `-store` are
   path dependencies. `Cargo.lock` is committed and CI runs `--locked`. `bwrap` and `prlimit` are host
   executables, not linked code; their versions are recorded in the verification record.
6. No seccomp filter and no cgroup controllers in this version. This is a stated limit, not an omission to
   hide (docs/worker-isolation.md section 9). A seccomp or cgroup layer is additive behind the same trait.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| No network egress, including to the host's loopback | `linux_network_egress_is_denied_including_host_loopback`, self-check `egress_denied` |
| Host files and credentials unreachable | `linux_host_files_are_not_reachable`, `host_files_absent` |
| Launcher credentials never reach the worker | `linux_launcher_credentials_and_env_never_reach_the_worker`, `env_scrubbed` |
| Writes only to scratch; staged inputs read-only | `linux_staged_artifacts_are_read_only_to_the_worker`, `write_outside_scratch_denied` |
| Process, memory, disk, CPU, stdout bounds | `linux_fork_bomb_*`, `linux_memory_*`, `linux_disk_*`, `linux_cpu_*`, `linux_stdout_flood_*` |
| Timeout and cancellation kill the tree | `linux_timeout_kills_the_whole_tree`, `linux_cancellation_cleans_up_the_worker_tree` |
| Argv is structured and complete | `tests/argv.rs` |
| Unsupported platform runs nothing | `refusing_backend_runs_nothing_*`, `off_linux_the_backend_refuses_to_run` |

These Linux tests run in the Ubuntu CI job `worker-isolation` and log a skip elsewhere. They claim
mechanism on that host, not resistance to a kernel or launcher vulnerability.

## Adapter contract

`custodian-worker::sandbox::Sandbox` is the port. The dispatcher depends only on the trait, the spec
(`SandboxSpec`, `Quotas`, `RoMount`) and `RawRun`. A future backend (nsjail, gVisor, Firecracker) must pass
the same self-check and the Linux isolation tests, adapted, before it is accepted.

## Failure and recovery

`bwrap` missing, user namespaces denied, `prlimit` missing or `/proc` not mountable: spawn fails or the
probe fails, the self-check fails, no dispatcher exists, no run starts. A mid-run launcher failure is a
non-zero exit: `Failed`, consumed if exposed. Supervisor errors never produce a clean result. A crash of the
control service leaves a running attempt whose lease lapses; the store recovers it as failed and consumed
(ADR 0021), and `--die-with-parent` ends the orphaned sandbox.

## Performance evidence plan

Measure separately, without relaxing a control: sandbox start (namespace and mount setup), staging copy and
hashing of the pinned artifacts, input materialization, engine execution, and result validation. Not
measured yet.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| `Sandbox` trait, bubblewrap backend, refusing backend, test fake | yes | yes | no |
| Namespace, rlimit, scratch and cleanup controls and their tests | yes | yes (tests run in CI on Ubuntu) | no |
| seccomp filter, cgroup v2 controllers, host egress filtering | yes (revisit) | no | no |
| VM-grade boundary | no | no | no |

## Consequences, migration, exit

The first deployment needs Linux with unprivileged user namespaces, `bwrap` and `prlimit`. Another backend
replaces `BubblewrapSandbox` without changing the dispatcher. Changing what the allowlist, quotas or caps
permit is a reviewed policy change, not a runtime edit.

## Open risks and revisit triggers

- Kernel or `bwrap` vulnerabilities: patch policy belongs to the deployment (C12). Revisit with a VM-grade
  backend before any non-synthetic protected run on a shared host.
- `RLIMIT_AS` is virtual memory and `RLIMIT_CPU` is per process; add cgroup v2 limits when the deployment
  can delegate a cgroup.
- Distribution policies (for example AppArmor restricting unprivileged user namespaces) can block the
  launcher; the self-check reports this as a failure, which is the intended behavior.
