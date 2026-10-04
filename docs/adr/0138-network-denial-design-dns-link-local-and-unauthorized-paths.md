# 0138. Network-denial design: DNS, link-local and unauthorized paths (S2, issue 55)

- Status: proposed (design only); no probe code, CI job, or `crates/custodian-worker` change is added
  by this ADR
- Date: 2026-10-03
- Deciders (by role): custody maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.
- Tracking: epic #40, issue #55 (S2); explicitly depends on #54 (S1); feeds #43 and S4 (#57)

## Context

[ADR 0136](0136-authorized-microvm-experiment-findings.md) recorded concrete network-denial failures
from the one authorized live AWS MicroVM experiment: on the exact image under test, DNS resolution of
`example.com` succeeded in **both** the allowed-egress and the denied-VPC trials, and TCP to the
link-local address `169.254.169.254:80` **connected** in both trials. A no-NAT VPC/security group alone
was shown insufficient evidence of child network isolation. IPv6 TCP had no successful positive control
(the allowed trial also refused), so it is recorded as "not assessable," not a verified denial; the
`unshare` tool was absent on that image, so kernel user-namespace support was neither confirmed nor
denied. Critically, that diagnostic (`deploy/aws/microvm/probe.rs`) is, by explicit design
(`deploy/aws/microvm/README.md`), **unsandboxed**: it has no inner process, mount or network namespace
boundary at all, so none of those observations say anything about how a real `Sandbox` backend behaves.
They establish only that VM-level network placement (VPC, security group, no-NAT) is not itself a
network-denial mechanism.

[ADR 0137](0137-arm64-inner-sandbox-image-and-ci-capability-probe.md) (S1, issue #54) proved kernel and
tooling *capability* on ARM64 — the capability-probe workflow actually ran on `ubuntu-24.04-arm` (a
GitHub-hosted ARM64 runner, confirmed schedulable on this repository by that merged workflow run) and
reported `unshare`, `unprivileged_userns_clone`, `seccomp/actions_avail`, and `bwrap`/`prlimit`
presence. It explicitly did **not** build a real `BubblewrapSandbox` or run `run_self_check` on ARM64;
ARM64 coverage of the actual self-check and dispatcher is stated there as explicit follow-up, not done.

Issue #55 is the detailed follow-up to P3 (#43) and says in its own text: "Depends on S1 supported
sandbox mechanism." Because S1 proved capability only, not a real ARM64 self-check run, none of issue
#55's required work items — exercising DNS UDP/TCP, link-local, loopback, private/internal, public
IPv4/IPv6 and VM control/lifecycle paths; confirming inherited sockets and proxy/resolver environment
variables cannot bypass isolation; confirming the trusted runner's transport still works while the
child cannot reach it — can be *run* against a real ARM64-sandboxed child yet. This ADR is therefore
scoped to design only: what the mechanism already is, what issue #55's probe matrix must enumerate, and
what "a working positive control for each protocol/address-family" (issue #55's acceptance criterion)
means precisely, so that the eventual probe implementation (after S1's real self-check is wired to a
confirmed ARM64 runner) has an unambiguous specification to build against.

The existing mechanism, already implemented and unchanged by this ADR:

- `BubblewrapSandbox::build_argv` (`crates/custodian-worker/src/bwrap.rs` lines 120-134) requests
  `--unshare-net` together with `--unshare-user --unshare-ipc --unshare-pid --unshare-uts
  --unshare-cgroup-try`, before `--cap-drop ALL`, `--clearenv`, any mount, or `exec` (bwrap.rs's own
  module doc, lines 1-18; restated in ADR 0137's "Design: privilege-drop sequence" item 2). A network
  namespace with no interface brought up inside it has no route anywhere, including to the host's own
  loopback (`docs/worker-isolation.md` section 3).
- The startup self-check's `egress_denied` check (`docs/worker-isolation.md` section 4;
  `crates/custodian-worker/src/isolation.rs` lines 187-196, 255-258, 294-296) already attempts, from
  **inside** the sandbox: TCP to the host's own loopback listener (bound fresh per run on
  `127.0.0.1:0`), a public address, a TEST-NET address, an RFC 1918 address, and a UDP send. Passing
  requires every attempt to fail **and** the host-side listener to observe no connection
  (`host_listener_untouched`, `IsolationVerification::all_passed`, isolation.rs lines 76-81). This is
  exactly the "confirm trusted runner transport still works while the child cannot reach it" shape
  issue #55 asks for, already implemented for one address — it is not yet enumerated for DNS, link-local
  or IPv6 by name.
- Inherited-descriptor and environment handling already exist: `prepare_command`
  (`crates/custodian-worker/src/sandbox.rs` lines 198-204) sets `stdin(Stdio::null())`, pipes
  `stdout`/`stderr`, and calls `process_group(0)`; Rust's standard library marks descriptors it opens
  close-on-exec by default, so no descriptor beyond the three explicit standard streams reaches the
  child. `--clearenv` (bwrap.rs line 131) plus the validated `ENV_ALLOWLIST`/`DENY_FRAGMENTS`
  (`sandbox.rs` lines 20-45, `env_name_allowed`) strip everything the launcher had and allow only a
  fixed, credential-shaped-name-refusing list through.

None of the above is new in this ADR. What is missing, and is this ADR's actual content, is a precise
specification of the probe matrix and positive-control rule issue #55 asks for, so a future
implementation (after S1's real self-check runs on ARM64) has one unambiguous target.

## Options

| Option | Reuses the existing contract | Fixes ADR 0136's specific gaps (DNS, link-local, IPv6 control) | Matches issue #55 scope |
| --- | --- | --- | --- |
| **Chosen: extend the existing `egress_denied` self-check's enumerated targets and host-side positive-control pattern to name DNS, link-local, IPv6 and inherited-descriptor/environment cases explicitly; specify but do not implement the additions** | Yes — `--unshare-net`, `host_listener_untouched`, `prepare_command`, `--clearenv`/allowlist are unchanged | Yes, by naming the exact missing cases | Yes — issue #55 is explicit that offline design/implementation planning may proceed now, actual AWS execution may not |
| Trust the VM-level network layer (VPC routing, security groups, no NAT) as the denial mechanism | N/A | No — this is exactly what ADR 0136 showed fails (DNS and link-local both succeeded despite no-NAT) | No |
| Add a seccomp syscall filter or iptables/nftables rules inside the sandbox as a second mechanism | No — invents a new enforcement path `docs/worker-isolation.md` section 9 explicitly says is not installed ("no seccomp syscall filter ... is used") | Possibly, but duplicates `--unshare-net`'s guarantee and adds unreviewed custody-adjacent logic | No — issue #55 says "prefer no-network child namespaces where supported," which is already `--unshare-net`; a filter is only "other enforceable mechanisms when unavailable," not the default |
| Implement the actual probe code and CI wiring now | Yes, eventually | Only once it actually runs | No — issue #55 says "Depends on S1 supported sandbox mechanism," and S1 (ADR 0137) only proved capability, not a real self-check run on ARM64; writing probe code against an unconfirmed runner path is the premature-implementation issue #55's own dependency note is guarding against |
| Defer all design work until S4 (#57)'s AWS rerun | N/A | No | No — #57 is the exact-image AWS isolation matrix rerun; it needs a specified matrix to rerun, which is this ADR's job to produce |

## Decision

1. **No new custody logic.** `BubblewrapSandbox::build_argv`'s `--unshare-net` flag, the self-check's
   `host_listener_untouched` host-side observation pattern, `prepare_command`'s descriptor handling, and
   `--clearenv`/`ENV_ALLOWLIST` are unchanged and remain the only mechanisms this repository will point
   at network denial. This ADR adds no code to `crates/custodian-worker`.
2. **Probe matrix, specified for future implementation.** The `egress_denied` check's enumerated
   targets (`docs/worker-isolation.md` section 4) must grow, in a future change that is **not** this
   ADR, to include at minimum:
   - DNS over UDP and TCP, to both a public resolver address and the loopback address, by name
     resolution attempt and by raw socket connect (a child that cannot resolve names should also be
     unable to open a raw UDP/TCP socket to a well-known DNS port, since `--unshare-net` denies
     transport, not just name resolution — ADR 0136's gap was observed against an *unsandboxed* child,
     where of course both succeeded).
   - Link-local, explicitly including `169.254.169.254` (the exact address ADR 0136 found reachable) and
     the link-local range generally (RFC 3927 IPv4, `fe80::/10` IPv6).
   - Loopback (already present), a public IPv4 address (already present), a TEST-NET/RFC 1918 address
     (already present), and IPv6 equivalents of each of the above, not present today.
   - "VM control/lifecycle service paths" (issue #55's wording) — any address or port a deployment's
     orchestration layer might expose to a host (for example a provider metadata or control endpoint);
     this is deployment-specific and must be named per deployment in the image manifest
     (`deploy/examples/arm64-sandbox-image.example.json`, ADR 0137 decision 2), not hard-coded in the
     sandbox-neutral probe.
   - Inherited sockets: a probe case that counts open file descriptors visible to the child (for
     example via `/proc/self/fd`) and asserts the count matches exactly the three standard streams,
     extending the existing close-on-exec guarantee from "relied upon" to "actively checked."
   - Proxy/resolver environment bypass: explicit canary names for proxy and resolver configuration
     (for example `HTTP_PROXY`, `http_proxy`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `RES_OPTIONS`,
     `HOSTALIASES`) added to a check that mirrors the existing `env_scrubbed` check
     (`docs/worker-isolation.md` section 4), which already proves ledger/App/DB-admin/GitHub/AWS-shaped
     canaries do not reach the payload (`CANARY_ENV`, `crates/custodian-worker/src/isolation.rs` lines
     35-41) — the same mechanism, a longer canary list.
3. **Positive-control rule, restated precisely.** For every denial case in the probe matrix, there must
   be an independently demonstrated reachability baseline for that exact protocol and address family,
   run either outside the sandbox or in a control configuration that does not apply `--unshare-net`, so
   that a failed attempt means "denied" and not "this protocol never worked here regardless of the
   sandbox." This is the same shape as the self-check's existing `scratch_writable` positive control
   (`docs/worker-isolation.md` section 4: "a probe that can do nothing cannot pass") generalized from
   filesystem write to every network case. Concretely: **if the IPv6 positive control cannot connect
   (as happened in the live AWS trial per ADR 0136), the IPv6 denial result must be recorded as
   `untested`/unverified, never as `supported`/denied** — this directly encodes issue #55's acceptance
   line "If an allowed IPv6 control cannot connect, mark IPv6 unverified rather than denied," and reuses
   the three-outcome vocabulary (`supported`/`blocked`/`untested`) ADR 0137 already established for the
   capability probe.
4. **Trusted-runner-transport confirmation, restated as the pattern to extend.** `host_listener_untouched`
   already proves the host side observes no connection from the sandboxed child while the host's own
   loopback listener remains bindable and functional outside the sandbox. The probe matrix above must
   apply the same two-sided pattern (host-side observation plus independent reachability) to every new
   case, not just loopback TCP — for example, a host-side DNS-query-received counter for the DNS case,
   and a host-side connection-accepted counter for the link-local case, mirroring `host_listener_untouched`.
5. **Refusal, not fallback, is unchanged.** A missing, failed, or `untested` probe result does not
   become a pass by omission; `Dispatcher::new`'s requirement that every one of `REQUIRED_CHECKS` pass,
   and `build_worker`'s `(None, "isolation_check_failed")` refusal path
   (`crates/custodian-daemon/src/runtime.rs`), are unchanged and are exactly what a future failed S2
   probe must continue to trigger.
6. **No probes have been run.** This ADR states what the matrix must contain. It does not run any DNS
   resolution attempt, link-local connection attempt, IPv6 control, or inherited-socket/environment
   bypass probe against a real ARM64-sandboxed child. Doing so requires S1's real `Sandbox`/
   `run_self_check` wired onto the confirmed `ubuntu-24.04-arm` runner from ADR 0137 — explicit future
   work, out of scope here, and not invented by this ADR.

## Status of the claim: design-only versus CI-checked versus AWS-verified

| Aspect | Design only (not probed) | CI-checked (pending a future run) | AWS-verified |
| --- | --- | --- | --- |
| `--unshare-net` namespace flag, requested before mounts/exec | Unchanged; already implemented (`bwrap.rs`) | Yes on x86_64 (`worker-isolation` CI job, `linux_isolation.rs`); not yet on ARM64 | **No** — the only AWS trial (ADR 0136) ran the deliberately unsandboxed `probe.rs`, which has no network namespace at all; it is not evidence about `--unshare-net`'s behavior |
| `egress_denied` check: loopback, public, TEST-NET, RFC 1918, UDP (existing targets) | Unchanged; already implemented | Yes on x86_64; ARM64 run is explicit follow-up to S1, not done | No |
| DNS-specific denial probe (new target, this ADR specifies it) | Yes — specified here; no code added | Not run anywhere yet | DNS resolution was **observed to succeed** on the unsandboxed AWS diagnostic (ADR 0136) — a known failure mode in the absence of any sandbox, not evidence about the sandboxed case |
| Link-local denial probe, including `169.254.169.254` by name (new target) | Yes — specified here; no code added | Not run anywhere yet | TCP to `169.254.169.254:80` was **observed to connect** on the unsandboxed AWS diagnostic (ADR 0136) — same caveat as above |
| IPv6 positive control and denial probe (new target) | Yes — specified here; no code added | Not run anywhere yet | The AWS trial's IPv6 positive control itself failed to connect, so even that unsandboxed trial could not assess IPv6; recorded `untested`, matching this ADR's rule |
| Inherited-socket descriptor-count probe (new target) | Yes — specified here; no code added | Not run anywhere yet | Not attempted in the AWS trial |
| Proxy/resolver environment canary list (extension of `env_scrubbed`) | Yes — specified here; no code added | Not run anywhere yet | Not attempted in the AWS trial |
| Real `Sandbox`/`run_self_check` execution of any of the above on ARM64 | — | **Not attempted.** Requires S1's self-check wired to the confirmed `ubuntu-24.04-arm` runner (ADR 0137); explicit future work | Not attempted |

No claim in this ADR should be read as "a network-denial probe passed" or "ran" on ARM64 or on real
AWS infrastructure with a real sandbox. ADR 0136's worker NO-GO is unchanged by this ADR.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| No new custody or network-enforcement logic is introduced; S2's design reuses `--unshare-net`, `host_listener_untouched`, `prepare_command`, and `ENV_ALLOWLIST` exactly as implemented | Code review: this ADR's diff touches no file under `crates/custodian-worker/src` |
| The probe matrix specified here enumerates every case issue #55's acceptance criteria name (DNS UDP/TCP, link-local, loopback, private/internal, public IPv4/IPv6, VM control paths, inherited sockets, proxy/resolver environment) | Review against issue #55's "Work" and "Acceptance" sections, line by line |
| A positive control that cannot connect yields `untested`, never `supported`/denied, for that case | Matches issue #55's explicit IPv6 acceptance rule and ADR 0137's three-outcome vocabulary; to be enforced by the future probe's parser, the same way `parse_probe_output` already rejects anything but the fixed `PASS`/`FAIL` vocabulary (`isolation.rs` lines 104-120) |
| This ADR makes no claim that any probe in the matrix has run on ARM64 or against real AWS infrastructure | This document's own "Status of the claim" table above |

## Adapter contract

Unchanged. The network-denial mechanism sits entirely inside the existing `Sandbox` trait boundary
(`crates/custodian-worker/src/sandbox.rs`) and the self-check's probe/parser seam
(`crates/custodian-worker/src/isolation.rs`); this ADR adds no new port. Deployment-specific targets
(the "VM control/lifecycle service paths" case) belong in the image manifest
(`deploy/examples/arm64-sandbox-image.example.json`), not in the vendor-neutral probe logic, consistent
with ADR 0137's placement of deployment facts outside the `Sandbox`/`Dispatcher` contract.

## Failure and recovery

Unchanged from `docs/worker-isolation.md`. A future probe that fails, or that cannot run at all (missing
tool, missing runner label, missing positive control), leaves `run_self_check` returning a
`SelfCheckError` and `build_worker` returning `(None, "isolation_check_failed")`; the daemon answers
`worker_unavailable`. This ADR introduces no new failure or recovery path because it introduces no code.

## Performance evidence plan

Not in scope. Measuring the wall-clock or resource cost of an expanded probe matrix is deferred to the
same future work that wires the real self-check onto a confirmed ARM64 runner (tracked under #55 itself,
feeding S4 #57).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Network-denial probe matrix specification (this ADR) | yes | yes (a specification; no code consumes it) | no |
| Positive-control rule (`untested` over false denial) | yes | yes (stated here; not yet enforced by any parser) | no |
| Expanded `egress_denied`/`env_scrubbed` probe code in `crates/custodian-worker` | yes (this ADR states the design) | no — explicit future work, not this change | no |
| Real network-denial probes run against an ARM64-sandboxed child | yes (eventually, once S1 is fully wired) | no | no |
| Worker NO-GO from ADR 0136 | — | unchanged | unchanged |

## Consequences, migration, exit

No approval, retention, budget, disclosure, or signer policy changes. No schema migration. This ADR does
not change the worker NO-GO from ADR 0136; it does not authorize any new AWS provisioning; it does not
claim any network-denial case has been probed on ARM64 or in a real sandboxed AWS run. Once S1's real
`Sandbox`/`run_self_check` is confirmed running on the ARM64 runner from ADR 0137, the next step is
implementing the probe-matrix additions specified in the "Decision" section above against that confirmed
runner — not inventing a new mechanism — followed by S4 (#57)'s exact-image AWS isolation matrix rerun.

## Open risks and revisit triggers

- **The probe matrix is a specification, not code.** If a future implementer narrows it (for example,
  omitting the link-local or inherited-descriptor cases) without revising this ADR, that narrowing
  should be treated as a design change requiring review, not a routine implementation detail.
- **VM control/lifecycle service paths are deployment-specific** and cannot be fully enumerated in a
  vendor-neutral ADR; each future deployment's image manifest must name its own provider endpoints
  (metadata services, control-plane addresses) for the probe to target.
- **A positive control that itself depends on the same denied mechanism is not independent.** For
  example, a DNS positive control that resolves through a resolver reachable only via the same route
  being denied is not a valid control; future implementation must run positive controls from a context
  that does not share the denial path under test.
- **x86_64 evidence must never be substituted for ARM64 evidence**, including in a future PR's
  description — the same caution ADR 0137 states and ADR 0136's original mistake illustrates.
- **A successful denial on a GitHub-hosted ARM64 runner is evidence for that runner's network
  configuration, not for every ARM64 execution environment** (including a future AWS MicroVM base
  image, which may have a materially different network setup than a bare CI runner).
