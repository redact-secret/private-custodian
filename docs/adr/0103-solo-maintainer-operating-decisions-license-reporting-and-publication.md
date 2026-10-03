# 0103. Solo-maintainer operating decisions: license, reporting route, requester and approver, and publication of a clean snapshot

- Status: accepted
- Date: 2026-10-03
- Deciders (by role): project maintainer (sole maintainer)
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

`docs/release-readiness.md` left four human decisions open (P1, P2, P4 and the single-person question in ADR
0081). The repository has one maintainer, no second reviewer, and no public contact address other than a
personal mailbox that must not become the reporting route. The decisions below follow what the other Redact
Secret repositories already do (`redact-secret-benchmarks` is MIT; `credential-eval` and `credential-evidence`
take reports through GitHub Security Advisories).

## Decisions

1. **License: MIT.** `LICENSE` is added by the maintainer. `Cargo.toml` and the README state it. The license
   covers the source code only. It grants no right to protected corpora, seeds, ledgers, keys, or to execute or
   query the protected evaluation (README "Publication and licensing" keeps that sentence).
2. **Reporting route: GitHub private vulnerability reporting, no email.** While the repository is private, the
   only people who can read it are collaborators, so reports reach the maintainer through the repository
   itself. Enabling private vulnerability reporting on the repository is a publication-gate step (it is not
   offered on a private repository). No personal address is published. Response timelines stay unpromised.
3. **Incident owner: the repository maintainer.** With one maintainer there is no backup owner. The incident
   procedure stands (`docs/incident-response.md`), and the single point of failure is recorded as a known
   limitation, not hidden.
4. **One person may hold `requester` and `approver`, as two separate principals with two separate credentials**
   ("solo-maintainer mode"). This is the only workable mode for a one-person project and it is the same
   procedural separation ADR 0081 and the legacy vocabulary already describe. The compensating rules are:
   * the two credentials live in different stores and are never used from one shell session or one credential
     file;
   * approval stays an explicit command with exact object IDs and is audited in the ledger like any other;
   * no agent or automation identity may hold `approver` (enforced by the policy loader, unchanged);
   * any evidence produced in this mode is labelled `procedural-separation` or `custodian-declared`. Nothing may
     claim organizational independence (`not_claimed` stays the only value) or independent ground truth.
   If a second maintainer joins, the policy is revised so the two roles belong to two people, through a
   reviewed policy revision.
5. **Personal data and tooling: publish a clean snapshot, do not rewrite history.** All 16 commits carry a
   personal author address, and `.claude/` plus `.mcp.json` hold developer tooling with a local path and a
   floating `@latest` package. This private repository keeps its history (it is the audit trail of how the
   design was built and rewriting it would break references to pull requests). At publication, code is
   exported as a new repository with one initial commit:
   * export the tracked tree minus `.claude/` and `.mcp.json` (the tooling stays in the private development
     repository);
   * author the commit with the GitHub noreply address (`<id>+<login>@users.noreply.github.com`);
   * re-run the publication gate (secret sweep, dependency audit, isolation job) on the exported tree;
   * the private repository's history is never made public.
   From now on every commit in this repository uses the noreply address. In GitHub account settings, "Keep my
   email addresses private" and "Block command line pushes that expose my email" are turned on.

## Consequences

* P1 is closed; P2 is closed as a decision (the setting itself is enabled at publication); P4 is closed as a
  decision (the export is performed at publication).
* The existing author address stays in the private history. That is accepted because the repository is private.
* Solo-maintainer mode weakens separation of duties and is stated as such in `SECURITY.md`; it never
  strengthens any public claim.

## Open risks and revisit triggers

* A single maintainer is a single point of failure for incidents, key custody and recovery. Revisit when a
  second maintainer exists.
* The clean-snapshot export loses the pull-request history; keep the private repository as the record.
