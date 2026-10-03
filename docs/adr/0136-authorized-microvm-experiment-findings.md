# ADR 0136: authorized synthetic MicroVM experiment findings

- Status: proposed assessment; worker and control-plane migration NO-GO
- Date: 2026-10-03
- Decision owner: custody maintainer
- Tracking: #40 through #47; engine prerequisite #37

## Context

The operator authorized a $50 synthetic experiment using the designated AWS
profile. Five disposable MicroVMs and an ordinary Lambda/DynamoDB primitive
probe ran. All owned resources were subsequently deleted and checked absent;
all VMs were checked terminal. The [report](../poc/lambda-microvm-live.md) and
[allowlisted evidence](../poc/lambda-microvm-live-evidence.json) preserve both
successful and failed observations. This is project-owned verification.

## Assessment

Keep the worker NO-GO. A VPC connector without routes blocked the tested public
IPv4 connection, but DNS resolution and link-local TCP still succeeded. The
same-uid child read the runner's owner-only synthetic control file. IPv6 had no
successful positive control and the user-namespace tool was absent; neither is
a verified denial. A requested one-minute endpoint token worked at 65 and 90
seconds. Token TTL therefore cannot serve as the custodian's authoritative
cancellation or lease fence.

Require complete explicit image configuration on every update and verify the
returned version before launch: an omitted-field update replaced the requested
512 MiB configuration with a 2048 MiB default and changed hooks/logging. Reject
that version rather than accepting service defaults. Resolve ambiguous creation
against the exact persisted intent and owned inventory; cleanup must never
create another VM. Finite lifetime bounds exposure, but does not prove cleanup
or authoritative fencing after coordinator failure.

Keep the control-plane NO-GO separately. Sixteen concurrent Lambda invocations
produced one atomic counter/intent/outbox transaction, and stored bindings
supported replay and conflict refusal. These primitives do not implement the
domain store, distributed leases, export barrier, custody storage, network
signer, crash/restart recovery or authorization.

## Options and consequences

Retaining current custody while developing a remote worker is smaller than
migrating all authority, but still requires a separately enforced inner sandbox,
live fencing, immutable artifact verification and real engine adapters. Moving
the existing daemon/SQLite into ephemeral Lambda storage remains rejected.
Defer production selection until those implementations and failure tests exist.
No engine formulas, policy, budget semantics, signer policy or protected state
change here. Cost approval authorizes disposable synthetic infrastructure only.

Measured VM compute is a small partial component; actual burst units, snapshot
sizes and the attributed invoice remain unknown. Snapshot minimum billing may
outlive resource deletion. The resource/time bounds and teardown are not an
account-wide billing cap. Real-engine four/eight-run daily sizing remains absent.

## Required follow-up evidence

An independent inner isolation boundary must deny child access to runner state,
DNS and link-local traffic while retaining positive controls. Implement stale
lease/cancellation refusal outside the engine; exercise lost responses, duplicate
dispatch, crash after exposure and restart without refunding or resetting prior
consumption. PR #52 supplies the PII contract/reference adoption handoff; complete upstream
engine adoption and ARM64 real-engine sizing. Port the
full custody transaction/conformance suite before any distributed authority
choice. Rehearse a persistent independent janitor and ambiguous-create recovery;
record verified absence rather than a successful delete request alone. Any new
policy or production deployment needs its own reviewed decision.
