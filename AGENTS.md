# Agent instructions

@\~/.codex/RTK.md

Read `README.md` and `ARCHITECTURE.md` before changing this repository. They
define the canonical ownership and dependency direction.

## Repository boundary

`credential-evidence` owns scanner-neutral credential knowledge: providers,
credential families, format contracts, provenance, cases, benign siblings, and
fixture lineage. It does not own scanner implementation or execution,
measurement results, product support policy, release decisions, or site
presentation.

The primary architectural test is: would this record still make sense if
Redact Secret did not exist?

## Working rules

- Start from a provider, credential family, case, or source claim—not a
  detector name.
- Author expectations from evidence and case reasoning, never from a scanner
  majority or current output.
- Give every material claim traceable provenance and an observed-at date.
- Preserve authored-versus-generated lineage. Generated fixtures are derived
  artifacts, not canonical evidence.
- Use stable, URL-safe identities independent of scanner versions.
- Prefer additive schema changes and explicit migrations. Never silently
  reinterpret an existing record.
- Use only unmistakably synthetic or documented public-test values. Active,
  revoked-but-real, customer, incident, or personal data is forbidden.
- Disclose that the repository is maintained by the Redact Secret project;
  never describe project-maintained evidence as independent validation.

## Before finishing

Run all validation, schema, reference, generation, and formatting checks that
exist in the repository. If implementation is not present yet, report that
fact rather than inventing commands. Verify that new fixtures trace to an
authored case, reviewed contract, or documented generation rule and that no
scanner-specific support status entered the canonical model.

## Local skills

Workflows under `.agents/skills/` are specialized for this evidence
repository. Security scans must distinguish intentional synthetic
credential-shaped fixtures from accidental real material.