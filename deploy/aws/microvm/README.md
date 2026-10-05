# Synthetic MicroVM image preparation

This directory is **not** a protected worker. The health binary accepts only a
fixed health route and AWS build-ready/validate hooks; all evaluation jobs refuse.
No engine is embedded and no isolation attestation is issued.

Build locally with the explicit ARM64 compiler and base manifests in Dockerfile:

```sh
docker build --platform linux/arm64 -t custodian-microvm-synthetic:local deploy/aws/microvm
```

The context allowlist contains only the two Dockerfiles and their public Rust
sources. Each AWS zip contains exactly its Dockerfile and corresponding source.
The build has no package
manager/network dependency install; the compiler container is separate from the
final AWS container. Final image adds one static Rust binary and runs as uid/gid
65534. The base includes AWS-managed components whose inventory and build-role
residue still require verification on the actual restored AWS snapshot.

An authorized AWS image build consumes a zip containing these two files at the
archive root, not the full repository. Record SHA-256 of archive, source and
compiled runner, compiler version, base manifest, managed base version and AWS
image version. Do not use latest-active version at dispatch. Never add corpus,
job, keys, environment credentials or worker input to COPY or image environment.
`image_inventory.py` enumerates this directory's own `.dockerignore`-filtered
build context and checks it against a reviewed allowlist and an explicit
corpus/seed/ledger/key/token/identifier denylist; see
`tests/microvm-conformance/test_image_inventory.py`. That check is offline and
synthetic only: it proves the in-repo build context, not the restored AWS
snapshot or build-role residue.

`infra/aws/poc/image.template.json` prepares the CloudFormation image/build role
with a single build-object read permission, ARM64, no added capabilities, no
runtime environment values and disabled logs. It requires an explicitly chosen
customer VPC egress connector; the template does not create or prove that
connector's DNS/network isolation. CloudFormation validation does not establish
resource-handler deployment support or runtime security. SAM also documents a
MicrovmImage resource; the experiment does not assume only one provisioning tool.

Read-only preflight:

```sh
AWS_PROFILE=redact-secret python3 infra/aws/poc/preflight.py
```

Provisioning remains an operator experiment, not a custody dispatcher. Under Epic #40, record explicit
account/region, cost ceiling and cleanup authorization before any billable call.
A live synthetic health experiment uses one fresh VM, exact image version,
no execution role, disabled runtime logging, no shell connector, a token for
port 8080 only, disabled auto-resume and a service maximum lifetime. A trusted
external orchestrator must explicitly terminate and verify absence even if
health fails. Keep endpoint/auth token/private inventory outside source control.
Health success is packaging/lifecycle evidence only; it never authorizes an engine
or protected input. See the [evidence record](../../../docs/poc/lambda-microvm.md)
and the exact-image adversarial/cleanup requirements before any further work.

`Dockerfile.probe` builds the separate public synthetic diagnostic binary. Its
fixed child deliberately has no inner sandbox: it checks whether it can read a
runner-owned 0600 canary, resolve `example.com`, connect TCP over IPv4/IPv6, and
reach link-local TCP. It sends no canary over the network and returns only
booleans, never addresses, file contents, credentials or process stderr. The
bounded child also checks availability of `true` and `unshare`. A missing tool or
failed positive control makes the associated denial not assessable.

This diagnostic exposes an expected missing-boundary failure; it must never be
used as an isolated engine runner. Both binaries refuse evaluation jobs and
always report `verified: false`. The [authorized live record](../../../docs/poc/lambda-microvm-live.md)
separates observed controls, failed denials and missing implementation.

## Trusted runner image (issues #42, #54)

`Dockerfile.runner` packages `custodian-worker-runner`, which runs the real
`BubblewrapSandbox`/`run_self_check` mechanism CI already proves
(`worker-isolation`, `worker-isolation-arm64`) using the pinned
`custodian-worker-probe` built alongside it, then serves `/health` reporting
`verified: true` only if every required check actually passed, with no
fallback mode. It does not implement remote job delivery (issues #42/#46
remain separate, unimplemented work).

Unlike `Dockerfile`/`Dockerfile.probe`, this build is a real Cargo workspace
build, not a dependency-free `rustc` compile of one source file, so it
**does reach crates.io during `docker build`** (pinned only by the checked-in
`Cargo.lock`) to resolve `custodian-worker`'s dependency graph, including
`rusqlite`'s bundled-SQLite C sources transitively through `custodian-store`.
It also pins a different compiler base than the other two Dockerfiles: a
multi-platform, glibc `rust:1-bookworm` manifest-list digest (with a C
toolchain, for `rusqlite`'s `cc` build step) rather than the single-architecture
Alpine manifest those Dockerfiles use. The final stage reuses the same
AWS-managed MicroVM base digest already pinned in `Dockerfile`/`Dockerfile.probe`.

Because this build needs the full workspace manifest graph (`Cargo.toml`,
`Cargo.lock`, `crates/`), it is built from the **repository root**, not this
directory, with an explicit `-f`:

```sh
docker build --platform linux/amd64 -f deploy/aws/microvm/Dockerfile.runner \
  -t custodian-runner-test:amd64 .
```

Record SHA-256 of the two compiled binaries, the `rust:1-bookworm` compiler
manifest-list digest, the AWS-managed base digest and the resulting local
image ID alongside the existing archive/source/compiled-runner/compiler/base/
AWS-image-version record for the other two images, following the same
convention; this artifact has not been built for an AWS zip and carries no
AWS image version of its own yet. The two compiled binaries from the amd64
build below hashed `b8744d1e7445a52c7bc8113b94f92293410e74ff4c007c063b71221d3055344a`
(`custodian-worker-runner`) and `513b800ca5c7ee4a2cd706022d99c02af33d1ab25625f034371fa74bba42c25c`
(`custodian-worker-probe`).

### Actual local build/run result (recorded here, not asserted from memory)

**`--platform linux/amd64`**: the `build` stage (the real `cargo build
--release` against the full workspace) succeeds cleanly and reproducibly --
cargo reports `Finished release profile [optimized] target(s) in 5m 10s`, no
errors, both binaries produced, hashes above. The final stage's `dnf install
bubblewrap util-linux` against the AWS base, however, reliably hung
indefinitely at `Downloading metadata...` with no further progress across
every attempt (killed only by an external 10-minute-no-log-growth
watchdog) -- because that AWS base publishes **only** `linux/arm64`
manifests (confirmed directly against the public ECR registry API: every
tag, dated or `latest`, resolves to a single-architecture arm64 manifest,
no amd64 counterpart), so BuildKit accepts the mismatched platform with an
`InvalidBaseImagePlatform` warning and silently runs that whole final stage
under arm64 emulation regardless of the `--platform linux/amd64` requested
for the build overall. The hang is specific to `dnf` under that emulation,
not to anything in this Dockerfile's own instructions.

To still get a genuine, running answer for the runner/self-check logic
itself (not blocked on that unrelated package-manager-under-emulation
hang), the two compiled binaries were copied into a disposable, non-AWS,
`apt`-based amd64 image (same `bubblewrap`/`util-linux` packages, installed
in under 20 seconds with no emulation involved) and run directly --
`docker run --rm -p 8080:8080 <that image>` then `curl localhost:8080/health`
returned exactly:

```json
{"synthetic":true,"verified":false,"reason":"self_check_failed: isolation_check_failed failed_checks=[] probe_ended=Exited(1)"}
```

with `docker logs` showing `RUNNER-SELF-CHECK-FAILED self_check_failed:
isolation_check_failed failed_checks=[] probe_ended=Exited(1)`. Isolating
the exact cause with a direct `bwrap` invocation in the same image gave:
`bwrap: Can't mount proc on /newroot/proc: Operation not permitted` --
Docker Desktop's default (non-`--privileged`) container runtime does not
let `bwrap` mount a fresh `/proc` inside the new PID namespace it creates
for the self-check. `--cap-add SYS_ADMIN` alone does not fix this (verified
directly); only `--privileged` does, and `--privileged` (like `--security-opt
seccomp=unconfined`) is explicitly **not** used here or recommended, because
it would weaken exactly the isolation boundary the self-check exists to
prove, making a local "pass" meaningless. `verified: false` for this exact,
explained reason is therefore the correct and expected local result, not a
bug: section 8 of [docs/worker-isolation.md](../../../docs/worker-isolation.md)
already states the HOST running the container must permit unprivileged user
namespaces and that the self-check must pass inside the container without
extra capabilities, a host PID namespace, host mounts or the Docker socket
-- a Docker Desktop VM on macOS is not that host. The authoritative
self-check evidence that the identical `BubblewrapSandbox`/`run_self_check`
code reports `verified: true` remains CI's `worker-isolation`/
`worker-isolation-arm64` jobs on real GitHub-hosted x86_64 and ARM64 Linux
runners (PR #64/#65), not this local build.

**`--platform linux/arm64`**: attempted four times (with BuildKit cache
mounts added to `Dockerfile.runner` specifically to make repeated attempts
cheaper -- see the comment in the Dockerfile). Every attempt, run under this
macOS Docker Desktop host's QEMU user-mode emulation for `linux/arm64`,
reproducibly stalled for ten or more minutes at a time with no log output at
one of two exact points -- the `rusqlite`/`libsqlite3-sys` bundled-SQLite C
compile, and separately the final stage's `dnf install` -- confirmed to
still be consuming real host CPU during the stalls (not a deadlock), just
pathologically slow. One attempt did eventually clear the C-compile step
after roughly 40 minutes of real time on a second try with a warm cache;
every other attempt, including one bounded by an explicit 10-minute
no-log-growth watchdog, did not. This is a known class of issue with QEMU
user-mode/`binfmt_misc` emulation of `linux/arm64` under heavy host
contention (this machine had other, unrelated heavy builds running
concurrently for part of this), not a defect in this Dockerfile, in
`custodian-worker-runner`, or in ARM64 hardware itself -- the real ARM64
evidence for the identical self-check mechanism already exists from CI's
`worker-isolation-arm64` job running on an actual `ubuntu-24.04-arm` GitHub
runner (PR #64/#65), not emulated. This local arm64 build attempt is
recorded as inconclusive on this host, not as a failure of the mechanism.
