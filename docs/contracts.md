# Contracts

Maintained by the Redact Secret project. These contracts are implemented as types and checks in
`crates/custodian-contracts`; no service, store, signer or feed publisher exists yet, and nothing is
deployed. Decisions: [ADR 0004](adr/0004-canonical-encoding-digests-and-contract-dependencies.md) (encoding,
digests, domain separation, time, dependencies) and
[ADR 0005](adr/0005-contract-set-freshness-and-versioning.md) (contract set, public split, freshness,
versioning).

## 1. Map

| Contract | Rust type | Schema (`crates/custodian-contracts/schemas/v1/`) | Side |
| --- | --- | --- | --- |
| Request and plan | `request::EvaluationRequest`, `EvaluationPlan` | `request.schema.json` | internal |
| Approval (execute, release) | `approval::Approval` | `approval.schema.json` | internal |
| Reservation | `reservation::Reservation` | `reservation.schema.json` | internal |
| Execution | `execution::ExecutionRecord` | `execution.schema.json` | internal |
| Internal receipt | `execution::InternalReceipt` | `internal-receipt.schema.json` | internal |
| Policy activation | `policy::PolicyActivation` | `policy-activation.schema.json` | internal |
| Public projection | `public::PublicProjectionEnvelope` | `public-projection.schema.json` | public |
| Revocation and supersession | `revocation::SignedRevocationEnvelope` | `revocation-envelope.schema.json` | public |

Internal contracts never leave the control service, signer or private ledger. Public contracts are the
only shapes benchmarks sees. Benchmarks reads no private-ledger content; it receives signed projections and
signed revocation envelopes.

## 2. Canonical encoding and digests

`custodian-canonical-json/1`: a subset of RFC 8785 (JCS). Compact JSON, keys sorted, integers
`0..=2^53-1` only, printable ASCII strings without `"` or `\`, no `null`, optional fields omitted.

```
digest        = "sha256:" + lowercase_hex( SHA-256( domain || 0x00 || canonical_bytes ) )
signing input = domain || 0x00 || canonical_bytes        (signature is outside the signed bytes)
candidate id  = "sha256:" + lowercase_hex( SHA-256( candidate_bytes ) )      (no domain prefix)
```

Domain strings (`DomainTag`): `private-custodian/v1/` followed by `request`, `plan`, `approval`,
`reservation`, `execution`, `internal-receipt`, `public-projection`, `revocation-envelope` or
`policy-activation`. A signature or digest made under one domain is not valid under another.

Golden vectors are in `crates/custodian-contracts/testdata/golden/` (`*.canonical.json` and `digests.txt`).
To re-implement elsewhere, canonicalize the `.canonical.json` content (it is already canonical), prepend the
domain and a zero byte, hash, and compare with `digests.txt`. Example check:

```
(printf 'private-custodian/v1/approval\0'; cat approval-execute.canonical.json) | shasum -a 256
```

Time is integer seconds since the Unix epoch (UTC). Contracts have no clock; the control service supplies
`now`.

## 3. Bounds and allowlists

Every string is a validated type with a pattern and maximum length (identities `prefix_[a-z0-9]{16,64}`,
labels `[a-z0-9][a-z0-9._-]{0,63}`, digests exactly 71 characters). Arrays have maximum lengths (scanners 8,
cells 256, revocation entries per envelope 128). Integers have maximums. A document is at most 65,536 bytes
and is checked before parsing. Objects reject unknown and duplicate fields. Schema tags reject other
types and versions. Schemas are generated from the types, checked in, and tested for drift and boundedness.

## 4. What the public contracts exclude

A public projection has no field for: seeds; case, file or path identities; input text; raw ranges or
offsets; value-level hashes of any kind; free-form errors or messages; internal plan, population, corpus,
epoch, family or lineage identities; budgets, limits or actors; scanner or adapter configuration. Population
identity is an opaque random reference or a keyed commitment (HMAC with a custodian-held key), never a plain
hash. Aggregates are integer counts per policy-defined stratum and metric, or `suppressed` with no value.
The only hash-shaped public fields are the candidate digest, component artifact digests and the feed chain
link, which identify bytes the consumer already holds or chain public documents. Tests enforce this on the
schemas and on decoding (`tests/schemas.rs`, `tests/negative.rs`). Small-cell and composition rules are C8;
this contract only makes suppression representable.

## 5. Bindings and freshness

Plan digest is the plan identity. An execution approval binds request, plan digest, candidate, population,
budget scope and policy activation, and expires. A release approval binds the execution, projection digest
and disclosure policy and is separate: completing a run does not authorize release. Agents cannot approve.

Policy activations are append-only states with a rising sequence. Before every reservation, execution start,
release or reuse of a prior receipt, the control service reads current activation state and calls the check:
it fails closed when the state is old (at most 300 s, and the caller may require less), dated in the future,
for another activation, revoked, superseded, expired, not yet active, or changed since the binding.
A prior success is evidence, never permission.

Public consumers hold a `RevocationLog`: a chain of signed envelopes with increasing sequence, previous-digest
links, cumulative entries and a `fresh_until`. A projection is usable only if the log is for its feed, at or
beyond its minimum sequence, fresh, the projection itself is within its `fresh_until`, and no entry revokes,
contaminates or supersedes it. Revocation is decided from whatever state is held, so a stale feed can revoke
but never validate.

## 6. Independence and attestation (stated accurately)

- Custody, signatures and the private ledger attest origin, binding and history. They do not establish true
  expectations, an independent reviewer or scanner quality. `ground_truth` is always `not_established`.
- The first deployment has one human operator, so separation of proposal, execution approval and disclosure
  approval is procedural (`single_operator_procedural`, or `distinct_principals_procedural` when different
  principals act). Organizational independence is `not_claimed`; no other value is representable.
- The legacy vocabulary is preserved verbatim and none of it means independent: `public-control` (public
  synthetic control, mechanism evidence only), `custodian-declared` (declared by the custodian operator),
  `procedural-separation` (role separation by procedure, as in the legacy blind lifecycle).
- Expectation attestations record who authored and who reviewed the expectations, as declared by the
  project: `project_authored` or `external_authored_unverified`; `not_reviewed`, `project_reviewed` or
  `external_reviewed_unverified`. The `unverified` values are declarations; this system does not verify an
  external party. Authored-versus-reviewed provenance of cases lives with the corpus authors
  (for example `credential-evidence`); the custodian carries a statement, not the evidence.
- This repository is maintained by the Redact Secret project. Project-maintained controls and evidence are
  not independent validation.

## 7. Budget scopes and refunds

Holdout: `population_epoch` (per corpus and epoch, optionally per family). Blind:
`candidate_lineage_epoch` (per candidate lineage per epoch). A new candidate digest in the same lineage uses
the same budget. A reservation is refunded only if no protected bytes were acquired and the attempt failed,
was cancelled or expired (`Reservation::settled_state`, which applies the core rule). Imports of legacy
attempts record consumption and never recompute it (ADR 0003).

## 8. Versioning and compatibility

- Each document has a schema tag ending in a major number (`private-custodian.request/1`). Schemas live in
  `schemas/v<major>/`.
- A reader of major N accepts exactly major N: any other tag and any unknown field is rejected. There is no
  "ignore unknown fields". This is deliberate: an allowlist that silently grows is a leak path.
- Additive change (a new optional field, a new enum value, a larger bound) is a new major. A producer emits
  the major its consumer declares. New-major readers should accept the previous major for a documented
  overlap period so stored documents stay readable; golden vectors for every released major stay in the
  repository and must keep decoding.
- Never reinterpret an existing record. Stored documents are immutable evidence; migration writes new
  records with a link to the old one.
- Domain tags, document schemas, policies (including disclosure and approval policy versions), engine
  protocols and store migrations are versioned separately. A policy revision is an explicit reviewed change
  recorded as a new policy version and activation, never an in-place edit.
- A change to canonical encoding or a digest rule is a new domain tag version (`.../v2/...`) and a new
  schema major, never an edit to the v1 rules.
- Process: update the types, regenerate schemas (`UPDATE_SCHEMAS=1 cargo test -p custodian-contracts
  --test schemas`), review the schema diff, add golden vectors for the new major, keep the old ones
  (`UPDATE_GOLDEN=1` only for deliberate additions), and record the change in an ADR.

## 9. Planned, implemented, deployed

| Item | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Types, canonical encoding, digests, schemas, checks, golden vectors, negative tests | yes | yes | no |
| Intake, authentication, persistence of these documents | yes (C3, C4) | no | no |
| Signing, key lifecycle, ledger export | yes (C7) | no | no |
| Disclosure policy, suppression, budgets, release approval workflow | yes (C8) | yes (docs/disclosure.md) | no |
| Feed publication and epoch contamination records | yes (C9) | yes (docs/lifecycle-and-revocation.md) | no |
| Consumer validation and legacy import | yes (C11) | yes (`custodian-bridge`, synthetic; see docs/benchmarks-integration.md) | no |
