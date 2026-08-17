-- Append-only job revision audit trail.
--
-- The compact indexed columns support operator queries. The JSONB event preserves the
-- provider-neutral wire record without duplicating scan findings or other potentially sensitive
-- evidence from the mutable job document.

CREATE TABLE scan_job_audit_events (
    id          BIGSERIAL PRIMARY KEY,
    job_id      UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    revision    BIGINT NOT NULL CHECK (revision >= 0),
    state       TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'cancelling', 'cancelled', 'succeeded', 'failed', 'interrupted')
    ),
    occurred_at TIMESTAMPTZ NOT NULL,
    event       JSONB NOT NULL,
    UNIQUE (job_id, revision)
);

CREATE INDEX idx_scan_job_audit_events_state
    ON scan_job_audit_events(state, occurred_at);
