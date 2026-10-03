# 0001. Trust boundaries and threat model

- Status: accepted (design baseline)
- Date: 2026-10-02
- Deciders (by role): repository maintainer (single human operator)
- Maintenance: this repository is maintained by the Redact Secret project. Its controls and evidence are
  project-maintained and are not independent validation.

## Context

The custodian authorizes exact frozen candidates, reserves budgets, runs pinned engines in isolation and
discloses only approved projections (README.md, ARCHITECTURE.md). Candidate and scanner code, agents and
external content are untrusted; execution crashes; repeated aggregates can reveal a holdout (SECURITY.md).
This ADR freezes the trust boundaries and the threats the later issues (C2 to C12) must prove against.

## Options

1. Treat the private repository and filesystem permissions as the boundary. Rejected: repository privacy is
   not a security boundary for operational data (SECURITY.md), and permissions do not stop code that already
   runs as the same OS user.
2. Defer the threat model until implementation. Rejected: contracts (C2) and budgets (C4) depend on it.
3. Freeze an explicit boundary and threat model now, mark every control planned until tested. Chosen.

## Decision

### Trust zones

| Zone | Contents | Trust |
| --- | --- | --- |
| Z0 untrusted input | agent prompts, issue and PR text, GitHub events, scanner output, candidate bytes, engine output | Data only. Grants no authority. |
| Z1 request edge | request-facing App adapter | Authenticates the sender, normalizes and enqueues a request, posts sanitized status. Holds no corpus, signing, ledger or runtime-DB write access. |
| Z2 control | control service, policy/state core, runtime DB | Deterministic authority for authorization, plan binding, budgets, state, audit. |
| Z3 protected | protected storage adapter, corpus keys | Read only by the control service's corpus capability, only after a reservation. |
| Z4 execution | isolated worker holding the engine and scanner children | Receives staged inputs only. No credentials, no default egress. |
| Z5 attestation | receipt signer | Accepts only validated, approved projections. Isolated from Z0, Z1 and Z4. |
| Z6 export | ledger-writer and the private-ledger repository | Appends signed audit exports. Receives no corpus or runtime DB access. |
| Public | benchmarks (public review ledger, product policy), published receipts | Receives signed approved projections and revocation updates. Cannot read Z2 to Z6. |

Authority never flows from Z0 or Z1 into Z2 by a label, comment or message; Z2 re-derives it from an
authenticated actor, an exact plan digest and a stored authorization.

### Threats and required controls

**T1. Attacker-controlled candidate code.** The candidate, adapters and scanner children may be malicious or
buggy: read the corpus and exfiltrate it through stdout, stderr, error text, timing, file names, artifact
fields or network; forge or reshape results; fork, exhaust CPU/memory/disk; escape the sandbox; tamper with
the frozen bytes; write a symlink or archive path that escapes scratch; poison the engine's inputs.
Required: no default egress and no host credentials in the worker; bounded stdout/stderr, CPU, memory,
processes, storage and wall time; process-tree cleanup; immutable staging with digest checks before and after
execution; archive/path/symlink validation before materialization; results accepted only through schema,
plan, candidate, engine and roster validation; free-form worker text never reaches logs, Checks or
projections; the worker identity has no path to the DB, signer, ledger or App credentials. A manifest flag or
a container is not evidence of isolation; C6 must show enforcement with failure probes. Residual risk:
a sandbox-escape vulnerability, a covert channel through permitted aggregate fields, and a malicious engine
if the pinned engine itself is compromised. These are treated as incidents (SECURITY.md), not designed away.

**T2. Inference and repeated-query attacks.** An adaptive party extracts holdout content from aggregates:
small strata, overlapping totals, differencing between candidates, timing and error detail, repeated tuning
against a result, new candidate identities that are tuned copies of earlier ones, and failed or withheld
requests used as an oracle. Required: allowlisted projection fields; minimum stratum sizes and composition
rules enforced on the whole released set, not per cell; cumulative query and release budgets per population
epoch and per candidate lineage (a new digest alone is not a fresh budget); withheld and failed requests are
recorded and counted when policy says so; fixed reason codes; no per-case identifiers, ranges or value
hashes; no silent noise. Blind and holdout evidence consumed for tuning is contamination and rotates the
epoch (ADR 0003). Parameters belong to C8 and a versioned policy; this ADR fixes only that they exist before
any repeated public comparison is enabled.

**T3. Administrative limits.** The first deployment has one human operator who is also the maintainer. That
person, or anyone with host root, can read protected storage, edit the SQLite file, restore an old backup,
mint authorizations or hold the signing key. The design therefore claims only:
- no API, CLI or agent tool exists to reset, raise or refund a budget outside the refund rule; a budget
  change is a reviewed policy revision recorded as an audit event;
- the control service is the only process that writes the runtime DB, and state changes are audited;
- audit exports and checkpoints leave the writer's control (private-ledger, offsite digest) so rollback or
  edit is detectable after the fact, not prevented (tamper-evident, not tamper-proof);
- separation of proposal, execution approval and disclosure approval is procedural while one person holds
  all roles, and every receipt must say so (`organisationalIndependence: false` style statements, as the
  existing blind lifecycle does);
- custody does not establish independent ground truth, and signatures attest origin and binding, not truth.
Backup restore must not reset budgets: restoring a DB older than the last exported checkpoint puts the
service in a refuse-to-run state until reconciled against the ledger export (C4, C12).

**T4. Deployment prerequisites.** No protected execution is permitted until all of these are demonstrated and
recorded (each owned by the named issue):
1. a dedicated host or account boundary for Z2 to Z5 with its own OS users per identity (C12);
2. restricted directories for runtime DB and protected storage (mode 0700 and owner-only, not shared with
   developer or CI accounts), no symlinks, encrypted volume or sealed population format (C5, C12);
3. separate access scopes for corpus encryption, runtime state, authorization, receipt signing and ledger
   export, with rotation and revocation documented (C5, C7);
4. worker isolation probes passing for egress, filesystem, credentials, resources, output bounds and cleanup
   (C6);
5. conformance controls passing on public synthetic data for concurrency, duplicate dispatch, budget
   exhaustion, crash after exposure, cancellation, malicious output, invalid bindings, suppression, signing
   refusal and recovery (C4 to C8, C12);
6. backup and restore rehearsal proving budgets and audit history survive (C12);
7. the private-ledger repository exists with restricted access and the ledger-writer identity (C7);
8. a documented incident owner and a private reporting route (C12);
9. the legacy lifecycle handoff completed per ADR 0003 (C11).

### Planned, implemented, deployed

| Item | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Lifecycle rules, refund policy, ports, synthetic doubles | yes | scaffold only (synthetic, in-memory) | no |
| Request-facing App adapter | yes (C3) | no | no |
| SQLite runtime store | yes (C4) | no | no |
| Protected storage and sealing | yes (C5) | no | no |
| Isolated workers | yes (C6) | no | no |
| Receipt signer, ledger export | yes (C7) | no | no |
| Disclosure and suppression | yes (C8) | no | no |
| Anything protected | no live protected run exists in this repository | | |

## Security properties claimed

None are claimed as implemented. Each T1 to T4 control above is a requirement whose proof is a named failure
test in C4 to C8 or C12 (see `.agents/skills/conformance-controls`). The scaffold smoke test proves only
in-memory lifecycle mechanism: reservation before exposure, no refund after exposure, idempotent replay,
plan-binding rejection, disclosure separate from completion.

## Adapter contract

Ports in `crates/custodian-core/src/ports.rs`: `Authorizer`, `CorpusAccess`, `StateStore`, `Executor`,
`Disclosure`. Errors are fixed reason codes.

## Failure and recovery

Fail closed on uncertainty about plan identity, authorization or release state. Crash after exposure
consumes the budget. Crash before exposure may refund only under the core refund rule. Duplicate dispatch
replays the recorded run. Unavailable signer or store means no release and no new reservation.

## Performance evidence plan

Measure coordinator transaction latency, worker startup, artifact validation, utilization and engine time
separately (CONVENTIONS.md). No isolation, audit write or budget rule is relaxed for speed.

## Consequences, migration, exit

Later issues may not weaken a zone boundary without a superseding ADR. Policy changes (approval, retention,
budget, disclosure, signer) require an explicit reviewed revision.

## Open risks and revisit triggers

Single-operator limits (T3) persist until a second human holds a distinct role. Sandbox choice is open until
C6. Revisit when a second operator joins, when real personal data is proposed (needs separate governance),
or when any inference parameter in C8 changes.
