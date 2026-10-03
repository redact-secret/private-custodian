# NNNN. Title

- Status: proposed | accepted | superseded by NNNN
- Date: YYYY-MM-DD
- Deciders (by role): ...
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The requirement from ARCHITECTURE.md or SECURITY.md that forces the decision, and the threat assumptions
that apply.

## Options

At least two real alternatives, including "defer", judged against the same criteria.

## Decision

Stated plainly.

## Security properties claimed

Each property tied to the failure test that will prove it. Say tamper-evident, not tamper-proof; do not treat
a container as an assurance statement.

## Adapter contract

The typed port the choice sits behind (authorization, corpus access, atomic budget/state, execution,
disclosure) so core contracts stay vendor-neutral.

## Failure and recovery

Crash after exposure, partial write, exhausted storage, expired lease, unavailable signer or store.
Fail-closed defaults.

## Performance evidence plan

What is measured separately, without relaxing isolation or audit.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| ... | yes/no | yes/no | yes/no |

## Consequences, migration, exit

Policy impact (approval, retention, budget, disclosure, signer) requires an explicit reviewed revision.

## Open risks and revisit triggers
