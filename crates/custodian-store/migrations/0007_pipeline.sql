-- Migration 0007: queue outcomes, request links and request-to-projection
-- pipeline state for the service daemon (S5, ADR 0125, ADR 0126, ADR 0127).
--
-- Forward-only and checksummed like 0001 to 0006. Additive only: four new
-- tables and their guards. Nothing here edits or drops an existing table,
-- touches a budget, lowers a counter or reinterprets a column. The charging
-- paths (`reserve_tx`, `start`, `record_exposure`, `finish`, `recover`) are
-- unchanged and remain the only ones that change budget state. No statement
-- here may contain input values, secrets or deployment identifiers; rows hold
-- identities, digests, counters, fixed vocabulary and one private aggregate
-- artifact (restricted operational metadata like `requests.document`).

-- ---- Queue outcomes ---------------------------------------------------------

-- What became of each queue item the daemon consumed: a submission, a
-- fixed-code denial, or a poison message set aside after bounded retries.
-- There is deliberately no foreign key to `intake_queue`: the retention purge
-- of migration 0006 deletes finished queue rows and must stay able to. A
-- row is written in the same transaction that marks the item done, so an
-- item is never done without an outcome.
CREATE TABLE queue_outcomes (
    seq        INTEGER PRIMARY KEY,
    outcome    TEXT NOT NULL CHECK (outcome IN ('submitted', 'denied', 'poisoned')),
    reason     TEXT NOT NULL,
    request_id TEXT,
    attempts   INTEGER NOT NULL CHECK (attempts >= 0),
    settled_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER queue_outcomes_immutable BEFORE UPDATE ON queue_outcomes
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER queue_outcomes_no_delete BEFORE DELETE ON queue_outcomes
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- ---- Request links ----------------------------------------------------------

-- Which pull request commit a submitted request came from, so a Check can be
-- posted for it. Identifiers only, the same as the queue row it was copied
-- from. Absent for requests submitted through the CLI.
CREATE TABLE request_links (
    request_id      TEXT PRIMARY KEY,
    delivery_id     TEXT NOT NULL,
    installation_id INTEGER NOT NULL CHECK (installation_id >= 1),
    repository_id   INTEGER NOT NULL CHECK (repository_id >= 1),
    pull_request    INTEGER NOT NULL CHECK (pull_request >= 1),
    head_sha        TEXT NOT NULL,
    linked_at       INTEGER NOT NULL
) STRICT;

CREATE TRIGGER request_links_immutable BEFORE UPDATE ON request_links
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER request_links_no_delete BEFORE DELETE ON request_links
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- ---- Pipeline ---------------------------------------------------------------

-- One row per approved attempt the daemon drives. `step` only moves forward:
-- enrolled -> dispatched -> assembled -> prepared -> released, or to the
-- terminal `closed` from any step with a fixed `reason`. `released` and
-- `closed` are final. Identity columns never change; the prepared-release
-- columns, once set, never change (a resumed pipeline must prove it is
-- continuing the same projection, not producing another).
CREATE TABLE pipeline_runs (
    attempt_id        TEXT PRIMARY KEY REFERENCES attempts (attempt_id),
    request_id        TEXT NOT NULL,
    approval_id       TEXT NOT NULL,
    step              TEXT NOT NULL CHECK (step IN (
        'enrolled', 'dispatched', 'assembled', 'prepared', 'released', 'closed')),
    reason            TEXT NOT NULL,
    execution_id      TEXT,
    prepared_at       INTEGER,
    release_key       TEXT,
    projection_digest TEXT,
    enrolled_at       INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    CHECK ((release_key IS NULL) = (projection_digest IS NULL)),
    CHECK ((release_key IS NULL) = (prepared_at IS NULL))
) STRICT;

CREATE TRIGGER pipeline_runs_guard BEFORE UPDATE ON pipeline_runs
WHEN NEW.attempt_id <> OLD.attempt_id
  OR NEW.request_id <> OLD.request_id
  OR NEW.approval_id <> OLD.approval_id
  OR NEW.enrolled_at <> OLD.enrolled_at
  OR OLD.step IN ('released', 'closed')
  OR (CASE NEW.step WHEN 'enrolled' THEN 1 WHEN 'dispatched' THEN 2 WHEN 'assembled' THEN 3
                    WHEN 'prepared' THEN 4 ELSE 5 END)
     < (CASE OLD.step WHEN 'enrolled' THEN 1 WHEN 'dispatched' THEN 2 WHEN 'assembled' THEN 3
                    WHEN 'prepared' THEN 4 ELSE 5 END)
  OR (OLD.execution_id IS NOT NULL AND NEW.execution_id IS NOT OLD.execution_id)
  OR (OLD.release_key IS NOT NULL AND NEW.release_key IS NOT OLD.release_key)
  OR (OLD.projection_digest IS NOT NULL AND NEW.projection_digest IS NOT OLD.projection_digest)
  OR (OLD.prepared_at IS NOT NULL AND NEW.prepared_at IS NOT OLD.prepared_at)
BEGIN
    SELECT RAISE(ABORT, 'pipeline_monotonic');
END;
CREATE TRIGGER pipeline_runs_no_delete BEFORE DELETE ON pipeline_runs
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- The private records of a run. Each column is written once: a second write
-- of different bytes is refused, so the aggregate artifact the receipt names
-- and the receipt itself cannot drift after the fact.
CREATE TABLE pipeline_artifacts (
    attempt_id     TEXT PRIMARY KEY REFERENCES pipeline_runs (attempt_id),
    aggregates     BLOB,
    execution      TEXT,
    receipt        TEXT,
    receipt_digest TEXT,
    stored_at      INTEGER NOT NULL,
    CHECK ((receipt IS NULL) = (receipt_digest IS NULL))
) STRICT;

CREATE TRIGGER pipeline_artifacts_guard BEFORE UPDATE ON pipeline_artifacts
WHEN NEW.attempt_id <> OLD.attempt_id
  OR (OLD.aggregates IS NOT NULL AND NEW.aggregates IS NOT OLD.aggregates)
  OR (OLD.execution IS NOT NULL AND NEW.execution IS NOT OLD.execution)
  OR (OLD.receipt IS NOT NULL AND NEW.receipt IS NOT OLD.receipt)
  OR (OLD.receipt_digest IS NOT NULL AND NEW.receipt_digest IS NOT OLD.receipt_digest)
BEGIN
    SELECT RAISE(ABORT, 'pipeline_artifact_write_once');
END;
CREATE TRIGGER pipeline_artifacts_no_delete BEFORE DELETE ON pipeline_artifacts
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
