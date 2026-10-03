# 0129. Daemon verification claims, fixtures and release-readiness dispositions

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

Nothing is deployed. The daemon can only be shown to work against doubles and synthetic data. The wording of
that claim has to stay honest in code, docs and CI.

## Decision

1. Everything the daemon tests show is **functional verification on public synthetic data, not independent
   protected evaluation**. The project that maintains the repository wrote the code and the tests.
2. Tests use a real listener, a real signer process socket, a Git ledger in a temp directory, a directory feed,
   an offline GitHub fake with a throwaway RS256 key, and a synthetic engine fixture. No network, no real key,
   no protected corpus, no real ledger.
3. The Linux test `linux_pipeline.rs` runs the engine inside the real bubblewrap boundary after the real
   self-check. It joins the existing `worker-isolation` CI job as an additional step (existing steps are not
   weakened) with `CUSTODIAN_REQUIRE_ISOLATION=1`; a skip fails there, and the step greps for
   `PIPELINE-ISOLATION-VERIFIED`. Elsewhere it logs `ISOLATION-TEST-SKIPPED` and proves nothing.
4. Canary scans cover the event log, the ledger, the feed and the queue outcomes.
5. `custodian-verify` accepted no v2 projection because its key file had no purpose for the v2 domain; the
   purpose `projection_v2` was added and the released output is verified with it in tests.
6. Dispositions in `docs/release-readiness.md`: HG-4 and HG-7 move from "no daemon/listener" to "implemented in
   code, not deployed"; R-3 is closed in code against the fixture, not against a real engine. R-1, R-4, the
   HTTPS client, a real engine emitter and every human provisioning step remain open.

## Security properties claimed

See ADRs 0123 to 0128 for the per-component tests. No claim is made about production behaviour.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Synthetic end-to-end proof | yes | yes | no |
| Isolation proof in CI | yes | yes (Linux job) | no |
| Protected run | no | no | no |

## Consequences, migration, exit

Dispositions change only through a reviewed revision of the readiness document.

## Open risks and revisit triggers

Doubles can diverge from real GitHub and real engines. Revisit when either is first exercised.
