# Synthetic verification bundles

Everything here is generated, public and synthetic. Nothing is protected data.

- **Lineage:** derived artifacts of `crates/custodian-verify/tests/support/mod.rs`
  (the generation rule). They are not canonical evidence and not authored
  cases. Regenerate with
  `UPDATE_FIXTURES=1 cargo test -p custodian-verify --test fixtures`; the
  ordinary test fails if a file differs from the generator.
- **Keys:** `keys.json` pins the public half of a throwaway Ed25519 test key.
  Its seed is the public constant `TEST_SEED` in the generator, belongs to no
  deployment and signs nothing real. There is no production key anywhere in
  this directory.
- **Identities and digests:** placeholders from the contracts test helpers
  (`...synthetic...` ids, digests of fixed labels).
- **Cases:** `positive` (accepted, exit 0); `stale-feed`, `wrong-domain`,
  `wrong-candidate`, `revoked`, `tampered` (each exit 10, one fixed reason);
  `feed-gap` (exit 11). Each `case.json` states the expected exit code and
  reason, and `now`.
- **Meaning:** a pass is functional verification on public synthetic data. It
  is not an independent protected evaluation. This repository is maintained
  by the Redact Secret project.
