---
name: publication-readiness
description: Assess whether private-custodian code or documents can be published, against the SECURITY.md public release gate and README publication terms. Use before making the repository or any part of it public. Report-only; it never publishes or changes visibility.
---

# Publication readiness

Shared rules: [_shared/README.md](../_shared/README.md). Report shape: [_shared/finding-format.md](../_shared/finding-format.md).

Source: `SECURITY.md` "Public release gate", `CONVENTIONS.md` "Review and publication", `README.md`
"Publication and licensing". "Private" describes custody, not secrecy; security must not depend on source
obscurity, and publishing source grants no permission to execute or query protected evaluation.

## Gate (pass / fail / not assessable for each)

1. **History and assets**: full-history secret and protected-data review done (`scan-secrets-in-history`,
   `protected-asset-sweep`); release assets, images, logs, and examples reviewed.
2. **Deployment material**: deployment-specific names, inventories, accounts, and paths replaced with safe
   examples.
3. **Reporting**: private vulnerability reporting configured and a verified route and incident owner
   documented in `SECURITY.md`.
4. **License**: selected and added. Currently none is granted; do not choose one on the maintainers' behalf.
5. **Isolation**: worker isolation demonstrated by failure tests (`isolation-verify`).
6. **Concurrency and recovery**: budget, concurrency, crash, and recovery tests pass (`conformance-controls`).
7. **Disclosure**: allowlist, suppression, composition, query-budget, and signing-refusal tests pass
   (`disclosure-review`).
8. **Keys**: verification documented and does not require a private key; rotation and revocation described.
9. **Limitations**: documented honestly, including that public synthetic controls prove mechanism only and
   that the system is not a claim of independent validation.
10. **Authorized data use unchanged**: nothing implies public access to protected corpora or evaluation.
11. **Supply chain**: `dependency-audit` and `scorecard-check` reviewed; CI holds no protected secrets.

Return a go / no-go with each failed or unassessable item and the owner role who must resolve it. Do not
change repository visibility, add a license, or edit `SECURITY.md` unless asked.
