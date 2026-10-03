# 0084. Retire the core `Disclosure` port

- Status: accepted (design); implemented in `custodian-core` and `custodian-service` (C10)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The C1 scaffold put a `Disclosure` trait (`prepare`, `approve`, `release`, `state`), a `ProjectionId` newtype
and an `InMemoryDisclosure` double in `custodian-core`, and `ControlService::prepare_disclosure` drove it.
C8 implemented disclosure as the typed `custodian_disclosure::DisclosureService` (validated internal record,
separate public projection, budgets, signed receipt, ledgered publication decision, distinct release
approval). The core port was left in place unimplemented. A second, weaker seam that looks like the disclosure
lifecycle but enforces none of it (it had no budget, no suppression, no signature, no eligibility) is a
misleading seam: someone could wire it and believe disclosure was gated.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Keep it | leave as is; mark `#[deprecated]` |
| Adapt it | make `DisclosureService` implement the port |
| Retire it | remove the trait, `ProjectionId`, the double and `prepare_disclosure`, and document the removal |

## Decision

Retire it. `custodian_core::ports` no longer has `Disclosure` or `ProjectionId`; `custodian_core::testing` no
longer has `InMemoryDisclosure`; `ControlService` loses its fifth type parameter and `prepare_disclosure`; the
tests that exercised the in-memory double (`requester_cannot_approve_own_disclosure`,
`disclosure_requires_a_completed_run`, the tail of the happy-path test) are removed because the behavior they
described is covered by the real service (`custodian-disclosure/tests/release.rs`, which tests
distinct release approval, the audit precondition and eligibility). Adapting was rejected: the port's shape
(a bare `prepare(run, outcome, requester)`) cannot carry the policy, activation, reservation, receipt and feed
inputs the real flow needs, and widening it would turn core into a mirror of the disclosure crate.

`DisclosureState` stays in `custodian-core` as the documented lifecycle vocabulary (`Prepared`, `Approved`,
`Released`, `Withheld`, `Rejected`) with its transition table and unit test; the enforcement is in
`custodian-disclosure`. A comment at the old location records the removal.

## Security properties claimed

Removing a seam cannot weaken a control that did not exist. The disclosure controls are tested where they are
implemented (ADR 0060 to 0063). The workspace builds and passes with no reference to the removed items.

## Adapter contract

Disclosure is `custodian_disclosure::DisclosureService`, wired by `custodian_cli::Service::disclosure_service`
over the one shared `LifecycleEligibility` (ADR 0082).

## Failure and recovery

Not applicable (code removal).

## Performance evidence plan

Not applicable.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Core disclosure port retired | yes | yes | n/a |

## Consequences, migration, exit

A downstream crate that imported `custodian_core::ports::Disclosure` or `InMemoryDisclosure` must use the
typed service. Within this workspace nothing did. Reintroducing a core disclosure seam would need its own ADR.

## Open risks and revisit triggers

None specific.
