# ADR 0133: remote worker experiment boundary

- Status: proposed; offline contract prototype implemented, no remote dispatcher deployed
- Date: 2026-10-03
- Decision owner: custody maintainer; deployment and policy review remain separate
- Tracking: #40, #42, #44

## Context and alternatives

The existing `Sandbox::run` consumes local staged paths and a synchronous
heartbeat callback (`crates/custodian-worker/src/sandbox.rs:182`). The dispatcher
owns exposure and settlement (`dispatcher.rs:366`); `RunLedger` owns the durable
export barrier (`ports.rs:20`). A network worker cannot inherit local mounts or
use worker claims to establish enforcement. Engines, adapters, scanners and
candidates remain potentially malicious inside a VM.

| Option | Exact identities and recovery | Isolation evidence | Migration |
| --- | --- | --- | --- |
| Pretend an HTTPS endpoint is a local Sandbox | Local staging and remote lifetime differ; reject | VM alone does not isolate runner from engine | Misleading replacement |
| Remote execution adapter outside the domain core | Explicit durable attempt/provider mapping and fences | Requires exact-image adversarial controls | Additional orchestration and transport work |
| Defer; retain Linux worker | Existing single-host lifecycle and export gates | Existing Linux CI evidence, host rehearsal still required | No migration |

## Recommendation and implemented seam

Prototype the remote execution adapter without changing the core or making it
selectable in the daemon. Retain the Linux worker for actual implementation
fallback. `custodian-worker-microvm` currently implements only the bounded
`private-custodian.remote-result/1` envelope parser; it cannot launch a VM,
authorize a run, establish isolation, settle a budget, sign or release evidence.

The envelope has exactly `schema`, `binding`, `stdout`. Binding contains distinct
request, approval, reservation and execution contract IDs, 1-based attempt
(1–16), a nonzero lease fence, plan/candidate/config digests, trusted image
artifact digest and explicit image version, engine/adapter/scanner digests and
SHA-256 of exact job bytes. Scanner pins are nonempty and at most 8. Existing
contract types enforce IDs, labels and digests. Image digest names the reviewed
build artifact, not an invented AWS snapshot digest. A future adapter also
records the provider's image ARN/version outside source control.

Job bytes remain `worker-job/1`; stdout remains one `worker-result/1`, with the
optional embedded aggregates channel from ADR 0127. Output is at most 64 KiB;
job bytes are at most 64 KiB in this prototype. The envelope is at most
`5 * 65536 + 4096` bytes to allow JSON byte-array expansion. Unknown and duplicate
fields, wrong schema, wrong bindings and invalid worker results refuse. No
scratch collector, measurement formulas or alternative aggregate canonicalizer
is introduced. Accepted transport bytes still require the existing disclosure
validator and independent release approval. The parser does not establish
freshness: callers must check the current authoritative lease before acceptance.

## Proposed ingress, execution and recovery contract

These steps are requirements, **not implemented remote enforcement**:

1. Revalidate reviewed plan, current authorization/standing and immutable pins.
   Reserve/start through the authoritative store and drain required exports.
2. Persist creation intent keyed by execution ID, fence and provider client token
   in the same authoritative transaction domain as the attempt. Pin image
   version, maximum lifetime, operator identity and allowed connector set.
3. Run one fresh VM without execution role, runtime logging, shell ingress or
   all-ports token. Authenticate ingress with a short-lived service JWE restricted
   to the runner port. Give the engine neither that token nor lifecycle access.
4. Reconcile uncertain creation using the same client token and provider inventory.
   Never issue a different creation token for the same attempt. Before delivery,
   durably bind exactly one VM to the live fence; unknown/duplicate VMs receive no
   inputs and must be terminated by the external cleanup identity.
5. Probe the exact staged runtime under approved limits with public synthetic
   inputs. Verify internal engine isolation and reviewed egress configuration.
6. Commit exposure and acknowledge its ledger export **before** reading or sending
   corpus bytes. A delivery timeout after this point is conservatively consumed;
   replaying delivery to a second VM is forbidden. A retry is a new reserved attempt.
7. Validate result against the control-plane expected binding, live lease and
   pinned bytes. Persist private result, use existing begin-validation/finish,
   then existing receipt/disclosure paths. An echoed binding is not attestation.
8. External orchestrator terminates the VM on success, denial, cancellation,
   lease loss and timeout. An independently scheduled janitor reconciles creation
   intents and orphans after restart. Termination failure is a cleanup incident,
   never a reason to refund exposed work or accept a stale result.

No protected-state suspension/resume or cross-attempt reuse. Use a service-enforced
maximum lifetime as an independent backstop; local subprocess termination does
not terminate AWS compute. Durable janitor ownership must survive orchestrator
failure. Temporary deletion is cleanup, not secure erasure.

## Claims and failure tests

Implemented contract controls: every identity/fence substitution, exact job-byte
mutation, wrong domain/protocol/roster, unknown/duplicate fields, malformed IDs,
empty/oversized pin lists, oversized ingress/stdout and fixed-code canary errors
are covered by `tests/contract.rs`. Positive transport round-trip preserves private
stdout and embedded aggregates, including intentionally invalid aggregate content
that remains the disclosure layer's responsibility.

No claim is made for live network, credentials, namespaces, process isolation,
CPU/memory/disk limits, fencing persistence, orphan cleanup or distributed
transactions. The evidence matrix in `docs/poc/lambda-microvm.md` lists required
positive and negative runtime controls. Unsupported or unavailable probes are
NO-GO, not skipped success.

## Image and performance requirements

Build a trusted tools-only snapshot: pinned ARM64 base, toolchain, runner and
engine-owned binaries; inventory hashes and package versions. No input corpus,
job, production credential, signing material or operational environment variables
enter the snapshot. Keep build permissions and operator/lifecycle permissions
separate from the credential-free runtime. Build readiness only proves snapshot
readiness; it never marks protected isolation as verified.

Measure build, launch, runtime preflight, transfer, execution, result validation,
termination and orphan windows separately. Record virtual-address limits separately
from VM resident-memory baseline/burst. No x86 Node result establishes ARM64
headroom. No implicit `--jitless` substitution or automatic limit widening.

## Policy, consequences and exit

No approval, retention, budget, disclosure or signer policy changes. No schema
migration or existing lifecycle changes. The envelope is an experimental remote
adapter protocol, not a core contract replacement. Switch to a deployed adapter
only after durable mapping, authenticated ingress, internal sandbox enforcement,
exact-image hostile probes, engine contract adoption and cleanup evidence have
been reviewed. Until then remote protected custody remains NO-GO.
