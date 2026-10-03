# Ledger remote setup (example, placeholders only)

Nothing here has been run. The commands show the order of the human steps in `docs/ledger.md`
("Manual private-ledger provisioning") and `docs/server-prerequisites-checklist.md`. Replace every
`PLACEHOLDER`; keep real values in the private operations store, never in this repository.

The private ledger is a Git repository holding signed, tamper-evident audit records. It is not the budget
authority and it holds no corpus, key or database content.

1. Confirm the repository exists, is private, has forking disabled, and is empty or holds only an initial
   README that says it is project-maintained and private.
2. Create a deploy key for **this repository only**, with write access, on the ledger-writer identity (not the
   GitHub App, CI or a personal account):

   ```
   ssh-keygen -t ed25519 -N '' -C 'ledger-writer PLACEHOLDER' -f /PLACEHOLDER/ledger-writer-key
   ```

   Register the **public** half as a deploy key on the repository. The private half stays on the writer
   identity (mode 0600) and nowhere else.
3. Protect `main`: no force-push, no deletion, linear history, pushes only from the writer identity; alert on
   any other push.
4. Clone for the writer (the `ledger_dir` of `cli-config.example.json`), pointing at the placeholder remote:

   ```
   git clone git@git.example.invalid:PLACEHOLDER-ORG/PLACEHOLDER-LEDGER.git /srv/custodian/ledger-clone
   ```

5. Pin the signing key's **public** key out of band (`pinned-roots.example.json`, the independent checkpoint
   location and every consumer). Never take a key from the ledger or the feed.
6. Choose the independent checkpoint copy (an offline note, or a mirror written by a different identity), the
   review cadence, and record the first checkpoint after the first export.
7. Verify (each review): the writer cannot force-push or read other repositories; benchmarks, CI, the App and
   agent identities cannot read the repository; a push from a non-writer is rejected or alerts;
   `custodian verify all` is clean with the pinned roots.

Disclosure: this repository is maintained by the Redact Secret project. A passing check here shows the ledger
is internally consistent under the pinned keys; it is not independent validation and it does not show that any
result was correct.
