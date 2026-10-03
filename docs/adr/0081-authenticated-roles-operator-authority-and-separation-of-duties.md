# 0081. Authenticated roles, the operator authority and separation of duties

- Status: accepted (design); implemented in `custodian-cli` (C10); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

C9 left `OperatorAuthority` as a trait with no implementation ("the library has no default") and a rule that
an agent can only report. The issue requires authenticated roles (requester, approver, operator, auditor), a
requester that cannot approve its own request, agents and automation that can never approve, clear, retire,
rotate or publish, and every approval explicit and audited. ARCHITECTURE.md: the model is not the security
authority; authorization is deterministic and outside the agent. No credential may be in the repository.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Where roles come from | flags or request documents; GitHub labels; a reviewed policy file |
| How an identity is proven | the OS user alone; a bearer credential checked against a digest in the policy file; mutual TLS |
| Agent/automation limits | a prompt rule; policy-file convention; structural checks at load time and at every check |
| Self-approval | convention; a check in the CLI only; the CLI, the store transaction and a table constraint |
| Authorization reference for audit | none; a random id; an id derived from the policy revision, actor, action and key |

## Decision

1. **Roles come only from the reviewed operator policy file** (`private-custodian.operator-policy/1`):
   identities (`act_...`), their kind (`human`, `service`, `agent`), roles, and the SHA-256 digest of each
   credential, plus `policy_version`, a validity window and optional limits (approval lifetime, maximum
   activation age, reservation window; each can only be lowered below the contract caps). The file holds no
   credential. A policy outside its validity window authenticates nobody (`operator_policy_expired`).
   Changing it is a reviewed policy revision, not a CLI operation.
2. **Authentication.** The caller presents a credential from a file (`--token-file`, or
   `CUSTODIAN_TOKEN_FILE`), never as an argument. `PolicyAuthority::authenticate` hashes it with a domain tag,
   compares in constant time against the identity's digest and returns a `Principal`; that is the only way to
   construct one. An unknown identity, a wrong credential and a credential shorter than 32 bytes give the
   same `unauthenticated`, so the answer is no oracle for which identities exist. Credential digests must be
   unique across identities.
3. **Structural limits (checked when the policy loads and again at every check).** An `agent` may hold only
   `requester`. A `service` may hold only `requester` and `auditor`. Only a `human` may approve, cancel
   another principal's request, repair, run any lifecycle or feed action, or import a policy activation.
   Fixed reason codes distinguish `agent_not_permitted` and `automation_not_permitted`. This narrows C9's
   table (which let a service retire, rotate and publish) to the issue's stricter rule; a feed freshness
   renewal is therefore a human operator action until a reviewed revision says otherwise. An agent cannot
   report a contamination through the CLI either (it has no operator role); C9's library still allows an agent
   to report `unreviewed_change`, so a deployment that wants that wires its own principal, not this CLI.
4. **`PolicyAuthority` implements `custodian_lifecycle::OperatorAuthority`.** `permits` ignores the kind the
   caller claims: it re-derives the identity from the policy and permits only a human holding `operator`.
   The lifecycle library's own `authorize` rules (agents report only, clearing is human) still run on top.
5. **Separation of duties for approval, three independent layers.** (a) The control plane refuses an approver
   equal to the request's `asserted_actor` or to the principal that submitted it (`self_approval`, exit 4).
   (b) `approve_submission` refuses the same inside the transaction (`StoreError::SelfApproval`) and refuses an
   agent approver. (c) The `submissions` table has `CHECK` constraints that make an approved row with
   `decided_kind = 'agent'` or `decided_by = requester` unrepresentable. `Approval::validate` already rejects
   an agent approver at decode. The contract's `single_operator_procedural` separation is never produced by
   the CLI: it always composes `distinct_principals_procedural` for a distinct approver.
6. **A document cannot claim another requester.** `request submit` requires `asserted_actor` to equal the
   authenticated identity (`actor_mismatch`).
7. **A requester sees only its own requests.** Anyone else's request, or a missing one, is `not_found`.
8. **Every approval is explicit and audited.** The approval is composed by the CLI from the stored request
   (deterministic `apr_` id from the request and approver, so a retry composes the same record), bound to the
   exact plan digest the approver confirmed, and recorded with an `approval.granted` outbox event in the same
   transaction as the reservation. Every operator act records `authorization_ref`, an `apr_` id derived from
   the digest of the policy revision, the actor, the action and the idempotency key: it is traceable to the
   reviewed policy that permitted it and is the same on a retry.

## Security properties claimed

| Property | Evidence |
| --- | --- |
| No credential in policy or output; wrong, unknown, short and expired all refuse alike | `tests/operator.rs::a_wrong_unknown_short_or_expired_credential_authenticates_nobody`, `tests/binary.rs` |
| Policy cannot grant an agent or automation identity approval or operator authority | `...::the_policy_file_cannot_grant_an_agent_or_automation_identity_authority`, `...::a_malformed_policy_file_is_refused` |
| Agents never approve, clear, retire, rotate, publish, repair | `...::an_agent_identity_can_request_but_never_approve_cancel_others_or_repair` |
| Automation never approves, clears, retires, rotates, publishes | `...::an_automation_identity_can_never_approve_clear_retire_rotate_or_publish` |
| Self-approval refused at three layers | `...::the_requester_cannot_approve_their_own_request`, `custodian-store/tests/intake.rs::self_approval_is_refused_by_the_store_itself`, `...::an_agent_approver_cannot_even_be_constructed_and_the_database_refuses_one` |
| Repeat approval refused, no second charge or audit row | `...::a_repeat_approval_is_refused_and_changes_nothing`, `custodian-store/tests/intake.rs::a_repeat_approval_is_refused_and_charges_nothing` |

## Adapter contract

`OperatorAuthority::permits(who, action)` (C9) and `PolicyAuthority::authenticate(identity, credential, now)`.
A deployment may replace the credential check (for example a socket peer credential) behind the same
`Principal` type; roles and structural limits stay in the policy file.

## Failure and recovery

A lost credential is rotated by a reviewed policy revision (new digest, new `policy_version`); the old
credential stops working when the file is replaced. An expired policy file fails closed for everyone until
replaced. There is no break-glass role: recovery commands are human-operator commands with exact
confirmations (ADR 0082).

## Performance evidence plan

Not applicable.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Policy file, authentication, roles, structural limits, three-layer separation | yes | yes (synthetic tests) | no |
| A real policy file, credential issuance and storage | yes (C12) | no | no |

## Consequences, migration, exit

Single-operator reality: the same human may hold `requester` and `approver` under two identities, so
separation of duties is by principal, not by person; the runbook lists it as a human decision. This is
procedural, as C9 already states. ADR 0103 accepts this mode for the sole maintainer, with compensating rules.

## Open risks and revisit triggers

* A bearer credential in a file is only as strong as the file's permissions and the host. Revisit with a
  deployment that offers peer credentials or hardware-backed keys.
* The policy digest is SHA-256 over a high-entropy credential. A low-entropy credential would be guessable
  offline from the digest: the 32-byte minimum is a length check, not an entropy check. The runbook says to
  generate credentials from the system random source.
