-- Migration 0002: disclosure charges and composition history (C8, ADR 0060 to 0062).
--
-- Forward-only and checksummed like 0001. Release and query budgets reuse the
-- `budgets` table (kind 'release_query'); a charge is final, so it adds to
-- `consumed_units` and is recorded here, never refunded. The history table
-- holds what past releases made public (never protected values), so a later
-- release can be checked against everything already revealed. No statement
-- here may contain input values, secrets or deployment identifiers.

CREATE TABLE disclosure_charges (
    charge_id  TEXT NOT NULL,
    scope_key  TEXT NOT NULL REFERENCES budgets (scope_key),
    units      INTEGER NOT NULL CHECK (units > 0),
    actor      TEXT NOT NULL,
    charged_at INTEGER NOT NULL,
    PRIMARY KEY (charge_id, scope_key)
) STRICT;

CREATE TRIGGER disclosure_charges_immutable BEFORE UPDATE ON disclosure_charges
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER disclosure_charges_no_delete BEFORE DELETE ON disclosure_charges
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

CREATE TABLE disclosure_history (
    series_key  TEXT NOT NULL,
    seq         INTEGER NOT NULL CHECK (seq >= 1),
    release_id  TEXT NOT NULL,
    payload     TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (series_key, seq),
    UNIQUE (series_key, release_id)
) STRICT;

CREATE TRIGGER disclosure_history_immutable BEFORE UPDATE ON disclosure_history
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER disclosure_history_no_delete BEFORE DELETE ON disclosure_history
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
