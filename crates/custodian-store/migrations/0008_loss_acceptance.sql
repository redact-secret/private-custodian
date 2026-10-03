-- Migration 0008: explicit, recorded acceptance of a restore loss (R-1,
-- ADR 0130).
--
-- Forward-only and checksummed like 0001 to 0007. Nothing here edits or drops
-- an existing table, lowers a counter or reinterprets a column. Two new
-- append-only tables record the one operation that lets a store that was
-- restored behind the private ledger, with no newer copy, continue: the
-- operator accepts the loss, the store adopts the ledger's acknowledged
-- audit tail, and every budget is raised (never lowered) to what the ledger
-- shows consumed. `verify_invariants` requires `budgets.consumed_units` to
-- equal settled consumption plus disclosure charges plus legacy imports plus
-- the units recorded here. No statement here may contain input values,
-- secrets or deployment identifiers; rows hold identities, digests, counters
-- and fixed vocabulary.

-- One row per accepted loss. `plan_digest` is the digest of the plan the
-- operator confirmed, so the same acceptance is idempotent and a different
-- plan is a different row.
CREATE TABLE loss_acceptances (
    acceptance_id    TEXT PRIMARY KEY
        CHECK (length(acceptance_id) = 36 AND substr(acceptance_id, 1, 4) = 'lac_'),
    plan_digest      TEXT NOT NULL UNIQUE CHECK (length(plan_digest) = 71),
    store_seq_before INTEGER NOT NULL CHECK (store_seq_before >= 0),
    ledger_from_seq  INTEGER NOT NULL CHECK (ledger_from_seq >= 1),
    ledger_to_seq    INTEGER NOT NULL CHECK (ledger_to_seq >= ledger_from_seq),
    adopted_events   INTEGER NOT NULL CHECK (adopted_events >= 1),
    recovered_scopes INTEGER NOT NULL CHECK (recovered_scopes >= 0),
    recovered_units  INTEGER NOT NULL CHECK (recovered_units >= 0),
    accepted_by      TEXT NOT NULL,
    accepted_at      INTEGER NOT NULL
) STRICT;

-- Units added to a budget scope by an acceptance. `scope_key` has no foreign
-- key on purpose: a scope created in the lost window is unknown to the
-- restored store, and a budget provisioned for it later starts with these
-- units already consumed.
CREATE TABLE budget_recoveries (
    acceptance_id TEXT NOT NULL REFERENCES loss_acceptances (acceptance_id),
    scope_key     TEXT NOT NULL,
    units         INTEGER NOT NULL CHECK (units >= 0),
    saturated     INTEGER NOT NULL CHECK (saturated IN (0, 1)),
    PRIMARY KEY (acceptance_id, scope_key)
) STRICT;

CREATE INDEX budget_recoveries_scope ON budget_recoveries (scope_key);

CREATE TRIGGER loss_acceptances_immutable BEFORE UPDATE ON loss_acceptances
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER loss_acceptances_no_delete BEFORE DELETE ON loss_acceptances
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER budget_recoveries_immutable BEFORE UPDATE ON budget_recoveries
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER budget_recoveries_no_delete BEFORE DELETE ON budget_recoveries
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
