# Incident response (C12)

Status: a procedure, not a service. **Nothing is deployed**, no incident owner is named, and no private reporting
route is verified. Those are human items in [deployment-runbook.md](deployment-runbook.md) (section 5) and a hard
requirement before the repository may be public (SECURITY.md, "Public release gate"). Source of truth:
[SECURITY.md](../SECURITY.md) "Incident handling" and the `incident-triage` skill. Mechanisms: [operator-runbook.md](operator-runbook.md),
[lifecycle-and-revocation.md](lifecycle-and-revocation.md), [ledger.md](ledger.md), [backup-recovery.md](backup-recovery.md).
This repository is maintained by the Redact Secret project. The controls are project-maintained, not independent
validation. A signature or a ledger entry attests origin, binding and history, never that a result was correct,
and revoking evidence says "do not rely on this", never "this was wrong".

## 1. Principles

1. **Contain first, investigate second.** Stop new use before you understand it. Containment commands below are
   reversible or fail closed; acting is the incident owner's decision.
2. **Preserve.** Never erase, edit or "correct" budget, audit, ledger or feed history to hide a failed run or an
   embarrassing fact. Failed runs consume budget. The CLI has no reset and no procedure here asks for one.
3. **Private channel only.** No corpus detail, operational identifier, key, token, raw log or exploit payload in a
   public issue, pull request, commit message, CI log or a chat that is not private. Do not paste a suspected
   secret anywhere, including an assistant session. Describe by identity (population, candidate digest, plan
   digest, projection id), never by content.
4. **Identities, not content.** Everything the CLI prints is a fixed code, a number, a digest or an opaque
   identifier. Do not open the protected-population directory, the database or the ledger by hand to
   "see what happened".
5. **Unknown is unknown.** Write "unknown" and who will find out. Do not fill gaps with likely stories.
6. **Humans decide.** Declaring contamination, publishing or revoking evidence, revoking a key, clearing a
   restore block and resuming are human decisions (operator-runbook section 8). An agent may help gather facts and
   draft; it holds no approval, signing or clearing authority.

## 2. People and routes **(human: name them)**

| Role | Needed before | Today |
| --- | --- | --- |
| Incident owner (decides containment, resumption, disclosure) | any protected run; any public release | not named |
| Backup incident owner | any protected run | not named |
| Monitored private reporting route (GitHub private vulnerability reporting once configured, plus a monitored mailbox not tied to one person's inbox) | public release | not configured |
| Ledger and signer custodians (hold the ledger deploy key, the signer host) | any protected run | not named |
| Benchmarks-side contact (to act on revocation) | first release | not named |

A report is acknowledged by the owner, who records receipt time, reporter, affected revision and the boundary
claimed, in the private operations log. No response time is promised until a human sets and staffs one.

## 3. First hour

Do these in order. Stop at the first step that needs a decision you cannot make and call the owner.

1. **Open the private incident record.** Time, reporter, how it was noticed, affected revision, systems named.
   Mark every unknown.
2. **Contain.** Pick what applies; each is an operator action under the usual role limits.
   | If it might be | Contain with | Effect |
   | --- | --- | --- |
   | exposure of protected contents or per-case detail, or tuning on results | `lifecycle report --epoch E --kind exposed\|used_for_tuning --reason results_exposed\|tuned_on_results --idempotency-key K` | new use of the epoch stops in the same transaction; a permanent kind retires it; a running attempt settles consumed |
   | only a suspected population or binding change | `lifecycle report --kind unreviewed_change --reason integrity_alarm` | blocks use; reversible only by a reviewed `lifecycle clear` |
   | a bad request or a stuck run | `request cancel --request-id R` (before start refunds; after exposure consumes) | stops that attempt |
   | a wrong or harmful policy activation | `policy import-activation` with a `revoked` state (exact id and sequence) | stops new approvals, reservations and dispatch at once |
   | a released projection that must not be relied on | `feed record-revocation --kind projection --target P --action revoked --reason error_correction\|newer_evidence\|contamination`, then `feed publish` | consumers see it on their next sync; a stale feed makes everything stale |
   | a compromised operator credential | reviewed operator-policy revision replacing its digest (runbook 2.2); an expired policy authenticates nobody | the old credential stops at once |
   | a compromised GitHub App credential or webhook | set the App webhook **Inactive**, remove the installation entry from the intake configuration; rotate key and secret (docs/github-app.md) | all intake stops without relying on events |
   | a compromised or misbehaving signer | stop the signer process; leave the control plane running so refusals stay `signer_unavailable` | nothing is signed; obligations stay pending; eligibility still refuses revoked things |
   | an isolation failure | stop dispatch (stop the service, or retire the epoch if the host is suspect); do not run any engine until the self-check passes again | no new exposure |
   | an untrusted or rolled-back ledger or database | do nothing that writes; the store is already write-blocked; section 4, class H | preserves evidence |
3. **Publish the feed immediately after a contamination or a revocation.** The obligation is durable and counts
   for eligibility the moment it is recorded, but consumers learn of it only from the signed feed. A projection
   released before the record stays usable to a consumer until its next sync, bounded by the feed's freshness
   (the one race the design cannot close; see release-readiness HG-1). Keep `ttl_secs` short.
4. **Preserve.** Copy the ledger clone and the independent checkpoint, take a database backup with `backup_to`
   (never copy the live file), keep the service-manager logs, and record the CLI outputs verbatim (they are
   safe to keep). Do not delete anything.
5. **Verify state, read-only.** `verify all`, `reconcile store`, `reconcile ledger`, `reconcile feed`. Expect
   `verified` and `consistent`. Anything else is its own incident (class H).
6. **Scope by identity** (section 4). 7. **Classify** the boundary crossed. 8. Decide with the owner whether to
   continue containing, escalate to the maintainer, and who tells the benchmarks side.

## 4. Classification and playbooks

| Class | Boundary crossed | Typical signal | Playbook |
| --- | --- | --- | --- |
| A. Agent authority | an agent approved, signed, cleared, retired or published | an audit actor of kind `agent` on a restricted event; `agent_not_permitted` bypassed | check the operator policy for kind and roles (an agent holds only `requester` structurally); review `approval.granted` and `epoch.standing` events by actor; rotate the credential; treat evidence approved this way as unauthorized (revoke) |
| B. Authorization or plan binding | a run used a plan that was not the approved one | `execution` and `approval` disagree on plan digest; `stale_policy` accepted | revoke the receipt and projection; compare plan digests across request, approval, reservation, execution, receipt in the ledger |
| C. Budget or race | a budget was exceeded, reset or double charged | invariants fail; consumed lower than the ledger; a request ran twice | stop; restore analysis in [backup-recovery.md](backup-recovery.md) section 4; do not adjust a count |
| D. Isolation or egress | a worker reached host files, the network or other runs | the self-check fails or a probe shows a path; unexplained egress | stop dispatch; treat every run since the last passing self-check on that host as exposed; contamination report for affected epochs |
| E. Artifact integrity | an engine, adapter, scanner, candidate or config changed between approval and use | `identity_mismatch`; staged hash differs | the run was refused before exposure (refunded) or rejected after (consumed); find who could write the allowlist directory |
| F. Disclosure or holdout leakage | a released projection reveals small cells, enables adaptive tuning, or carried a forbidden field | a consumer report; a composition review | revoke the projection; assess tuning risk (section 6); policy revision before any further release |
| G. Key or signer | signing key exposure, misuse or loss | an unexpected signature; signer host alert | [backup-recovery.md](backup-recovery.md) section 7; revocation makes the ledger untrusted to the control plane until it is re-attested under a new key with `repair reissue-ledger` (ADR 0131) |
| H. Ledger or database integrity | `ledger_untrusted`, `store_rolled_back`, `lineage_diverged`, conflicting or quarantined records | exit 8 from any command | do not clear the block to resume; when no copy reaches the ledger checkpoint, the only continuation is the explicit loss acceptance (`repair loss-plan`, `repair accept-loss`, ADR 0130) after you hold the independent checkpoint copy, and never for `lineage_diverged`; compare the ledger clone with its remote and the independent checkpoint out of band; corrections are new superseding records; a conflicting record is never repaired automatically |
| I. Repository, CI or log leakage | a secret, token, protected value or operational identifier in git history, CI, a log or an artifact | a scanner hit; a report | rotate the credential first; remove from the working tree; do **not** rewrite shared history without the owner's decision; assume the value is public; see the history sweep in release-readiness |
| J. Dependency or build compromise | a malicious or vulnerable dependency or action | an advisory; CI anomaly | pin and freeze; the `dependency-audit` CI job; rebuild from a reviewed lockfile; treat anything signed by a build from the affected window as suspect |
| K. Intake abuse | forged, replayed or out-of-scope webhooks | reason codes on Checks | webhook Inactive; review the allowlist; intake never approves |

### Scoping by identity

From the ledger and store, not from content: which populations (custody identity), candidates (digest), plans
(digest), authorizations (approval ids), reservations and runs are affected; which projections were released,
when, to which destination (`publication` records and the signed decision), and what query and release budget
was consumed. The feed lets a consumer match a projection id, receipt id, candidate digest, public population
reference or policy.

## 5. Key compromise, signer loss and credential events

See [backup-recovery.md](backup-recovery.md) section 7. In short: stop the signer, pin a new root out of band,
record `key_compromise` revocations for affected projections and receipts, publish the feed, preserve the ledger.
After a revocation the ledger walk reports findings and the control plane will not start until the affected
records are re-attested under the new key (`repair revoke-key`, `repair reissue-plan`, `repair reissue-ledger`,
then `repair clear-reconcile`; ADR 0131, backup-recovery.md 7.4). Protected execution does not resume until
that has run, `verify all` is clean and the incident record says why resuming is safe. Operator credentials and App secrets rotate as in the runbook and
docs/github-app.md; review the audit trail for the identity.

## 6. Holdout impact assessment

Answer, in the incident record, before anything is released again:

1. Could a released aggregate, a refusal, a timing or an error have revealed a small cell or enabled tuning?
   Compare against the disclosure policy's minimum stratum size, composition rules and cumulative budgets.
2. Was a candidate or detector adjusted using a population's results? That is `used_for_tuning`: never
   clearable, the epoch retires, evidence is withdrawn.
3. Which released projections must be withdrawn or superseded, and did the feed carry it?
4. Is a new reviewed epoch needed (`lifecycle rotate`, a new seal, a new budget; the old budget is never edited)?
5. Does any consumer need to re-evaluate support decisions derived from the withdrawn evidence? That decision is
   the consumer's; tell them through the feed and the owner's private contact.

## 7. Resuming

Resume only when all of these hold, each with evidence in the record: the root cause is understood or bounded;
`verify all` reports a trustworthy ledger and an intact store; `reconcile` is `consistent`; the self-check passed
on the current host; keys and credentials involved are rotated; affected evidence is revoked and the feed is
published and fresh; the failing boundary has a test that would have caught it (`conformance-controls`); policy
changes were reviewed; the incident owner signed off. A restore block is cleared only by the audited
`repair clear-reconcile` with the exact confirmations, after the ledger is trusted and the store is not behind it.

## 8. Communication

Private until the owner decides otherwise. Public statements say what is known, what users should do and what is
not yet known, and make no claim of independent validation or of ground truth. Do not name or accuse a private
individual. Third parties (a hosting provider, GitHub, a dependency's maintainers) are contacted by a human, not
by an agent and not from this repository's automation. Response times are not promised until staffed.

## 9. Practice

Run a tabletop exercise before the first protected run and after each material change, using synthetic data:
pick a row of section 4, walk section 3 with the commands in dry-run form (`--dry-run` where available), and
record gaps. The mechanisms the playbooks lean on are exercised on every CI run by the C12 suite
(`crates/custodian-cli/tests/c12_*.rs`): contamination and revocation reach the consumer
(`intake_to_bridge_consumer_end_to_end`), restores are refused (`c12_restore_drill.rs`), outages keep events
pending (`c12_keys_and_ledger.rs`), the one revocation race is pinned (`c12_revocation.rs`), and no canary
appears in any output (`c12_leakage.rs`). That is evidence of mechanism on synthetic data, not of a staffed
response.

## 10. Record template (identities only)

| Field | Content |
| --- | --- |
| Opened / closed | timestamps |
| Reporter and route | role, not personal data |
| Revision / deployment | commit, config version |
| Class and boundary | section 4 |
| Contained by / at | commands run, exit codes, who |
| Identities affected | populations, candidates, plans, approvals, projections |
| Released evidence | projection ids, destinations, feed sequence that revoked them |
| Holdout assessment | section 6 answers |
| Unknowns | each with an owner |
| Remediation and tests | links to commits and test names |
| Resumption sign-off | owner, date, evidence |
