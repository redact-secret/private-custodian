-- Migration 0005: legacy consumption import (HG-3, ADR 0102, ADR 0115).
--
-- Forward-only and checksummed like 0001 to 0004. Nothing here edits or drops
-- an existing table, lowers a counter or reinterprets a column. The new table
-- is an append-only ledger of the legacy consumption the operator wrote into
-- the runtime budget store; the budget row itself stays the only counter, and
-- `verify_invariants` requires that its consumed units equal settled
-- consumption plus disclosure charges plus the units recorded here. No
-- statement here may contain input values, secrets or deployment
-- identifiers; rows hold identities, digests, counters and fixed vocabulary.

-- One row per applied legacy import record. `import_id` is the importer's
-- facts-only `lgi_` identity; `record_digest` is the digest of the full
-- canonical record, so the same id with other bytes is a conflict, not a
-- no-op. `legacy_units` is the legacy scope's total consumed units as stated
-- by the record; `applied_units` is what this row added to the budget (the
-- non-negative difference to the record it supersedes, plus the headroom of a
-- budget the record declares exhausted). Rows are never updated or deleted.
CREATE TABLE budget_imports (
    import_id        TEXT PRIMARY KEY
        CHECK (length(import_id) = 36 AND substr(import_id, 1, 4) = 'lgi_'),
    record_digest    TEXT NOT NULL CHECK (length(record_digest) = 71),
    source_scope_key TEXT NOT NULL,
    scope_key        TEXT NOT NULL REFERENCES budgets (scope_key),
    legacy_units     INTEGER NOT NULL CHECK (legacy_units >= 0),
    applied_units    INTEGER NOT NULL CHECK (applied_units >= 0),
    exhausted        INTEGER NOT NULL CHECK (exhausted IN (0, 1)),
    declared_limit   INTEGER CHECK (declared_limit IS NULL OR declared_limit >= 0),
    supersedes       TEXT UNIQUE REFERENCES budget_imports (import_id),
    handoff_digest   TEXT NOT NULL,
    report_digest    TEXT NOT NULL,
    applied_by       TEXT NOT NULL,
    applied_at       INTEGER NOT NULL
) STRICT;

CREATE INDEX budget_imports_scope ON budget_imports (scope_key);
CREATE INDEX budget_imports_source ON budget_imports (source_scope_key);

CREATE TRIGGER budget_imports_immutable BEFORE UPDATE ON budget_imports
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER budget_imports_no_delete BEFORE DELETE ON budget_imports
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
