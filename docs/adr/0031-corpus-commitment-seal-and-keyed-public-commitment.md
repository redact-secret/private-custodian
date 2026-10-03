# 0031. Corpus commitment, seal and keyed public commitment

- Status: accepted (design); implemented in `custodian-corpus` against synthetic data
- Date: 2026-10-02
- Deciders (by role): custodian maintainer, security reviewer (project-maintained; not independent)
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0004 left the sealing format and key provider for C5. `PopulationBinding.population_digest` must be an
exact commitment to the corpus; `PublicPopulationRef` may carry a keyed commitment whose key the custodian
manages (ADR 0002, C2). Disclosure-safe identifiers must not be guessable hashes of protected content.

## Options

1. Merkle tree over entries. Rejected for now: no partial proof is needed, a flat manifest is simpler and
   fully verifiable.
2. Hash of concatenated bytes. Rejected: ambiguous (no names or boundaries) and not auditable per entry.
3. **Sorted canonical manifest of (name, size, SHA-256), hashed with a domain tag** (chosen).
4. Public commitment as a plain hash. Rejected: a guessable, low-entropy corpus could be confirmed.

## Decision

**Manifest.** Entries sorted by name; canonical JSON with sorted keys (`entries`, `manifest_version`;
`name`, `sha256`, `size`), compact, ASCII, same rules as ADR 0004 but written in `custodian-corpus` because
`custodian-contracts` caps documents at 64 KiB and a manifest scales with the corpus (hard limits: 100,000
entries, 16 MiB per entry, 32 MiB manifest).

**Exact corpus commitment** (`PopulationBinding.population_digest`, internal, never public):
`SHA-256("private-custodian/v1/corpus-manifest" || 0x00 || canonical_manifest)`. It commits to every entry
name, length and content hash. Decoding requires byte-identity with the canonical form.

**Seal record** (`SealRecord`, canonical JSON, `deny_unknown_fields`, 64 KiB cap), stored as `SEAL`:
`seal_version`, `binding` (`PopulationBinding` with domain, corpus ID, opaque epoch ID, optional family ID,
population digest, custody version), `config_digest` (frozen configuration), `budget`
(`BudgetScope`, which must cover the binding), `provenance` (origin from a closed synthetic-only set,
optional generator name, observed-at), `review` (reviewer, reviewed-at, C2 `Attestation`), `sealed_by`,
`sealed_at`, `entry_count`, `total_bytes`. Seal digest:
`SHA-256("private-custodian/v1/corpus-seal" || 0x00 || canonical_seal)`, recorded in the registry.
Domain strings are local to this crate so that shared `DomainTag` is not changed by C5; folding them into
`DomainTag` is a reviewed follow-up.

**Rules.** Sealing refuses `review: not_reviewed`, an empty corpus, and a budget scope that does not cover the
binding. The attestation vocabulary is C2's: independence stays `custodian-declared` or weaker,
`organisational_independence` is `not_claimed`, `ground_truth` is `not_established`. Structural validation
cannot prove independent human review; the seal attests who declared what, not that it is true.

**Verification on every access** (see `populations.rs`): registry row exists; seal canonical and names this
epoch; seal digest equals the registry digest and agrees with the row; manifest canonical and its commitment
equals the sealed population digest; storage entry list equals the manifest; and before returning bytes,
length and SHA-256 equal the manifest entry. Any mismatch is `integrity_mismatch` (or a more specific fixed
code), never used.

**Keyed public commitment.** `HMAC-SHA-256(key, "private-custodian/v1/public-population-commitment" || 0x00 ||
population_digest_string)`, rendered as `hmac-sha256:<64 hex>` (`KeyedCommitment`). The 256-bit key is
generated from the OS, stored at `keys/commitment.key` (0600), redacted in `Debug`, absent from the registry
and from logs. HMAC is implemented over the already-pinned `sha2` (about 15 lines) and checked against RFC
4231 test cases 1, 2 and 6, which avoids adding a dependency whose only use is this primitive. The
alternative is the `hmac` crate (`=0.12.1`); revisit if more MAC uses appear.

**Epoch IDs** are `epo_` plus 128 random bits, independent of content, scanner versions and order.

## Security properties claimed

| Property | Test |
| --- | --- |
| Commitment equals manifest digest; order independent; content and name sensitive | `manifest::tests::digest_is_order_independent_and_content_sensitive`, `seal_activate_open_read_round_trip` |
| Non-canonical or unknown-field manifest or seal rejected | `manifest::tests::*`, `tampered_manifest_or_seal_is_detected` |
| Review, budget binding and non-empty corpus required | `seal_requires_review_matching_budget_and_entries` |
| Public commitment keyed, stable, not the digest | `public_commitment_is_keyed_stable_and_not_the_digest` |
| HMAC correct | `secret::tests::rfc4231_*` |
| Registry edit, reorder, interior deletion, torn write detected | `registry_chain_detects_edits_and_interior_deletion` |

## Adapter contract

None beyond ADR 0030; commitment and seal logic is adapter-independent.

## Failure and recovery

Key file missing on first start: generated. Key file unreadable, wrongly permissioned or malformed: start
fails (`key_invalid` or `permission_violation`); the key is never regenerated over an existing corrupt file.
Key rotation produces new public commitments; old ones cannot be verified with the new key, so rotation is a
reviewed event that must also re-issue public references. Losing the key makes existing public commitments
unverifiable but does not affect sealed data.

## Performance evidence plan

Seal hashes each entry once; open hashes every entry; reads hash one entry. Measure with synthetic corpora
before production.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Manifest commitment, seal record, registry digest binding | yes | yes | no |
| Keyed public commitment, key at rest in the protected root | yes | yes | no |
| External key provider / KMS, key rotation procedure | yes | no | no |
| External checkpoint of registry head | yes | no (head digest exposed) | no |

## Consequences, migration, exit

A different commitment scheme is a new domain string and `manifest_version`/`seal_version`, with both
digests verified during any transition. Never reinterpret an old seal.

## Open risks and revisit triggers

The key shares a trust root with the data (same root directory); production should move it to a separate
provider or volume. SHA-256 collision resistance is assumed. Revisit with a KMS decision (C7 signer work)
or if partial-corpus proofs are required.
