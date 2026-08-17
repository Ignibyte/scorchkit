-- Durable provider-neutral scan jobs.
--
-- The JSONB document is the versioned domain record. Lifecycle columns duplicate the small indexed
-- subset needed for ordering, recovery, and optimistic compare-and-swap without teaching the job
-- contract about PostgreSQL.

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY,
    root_job_id     UUID NOT NULL,
    parent_job_id   UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    attempt         INTEGER NOT NULL CHECK (attempt > 0),
    state           TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'cancelling', 'cancelled', 'succeeded', 'failed', 'interrupted')
    ),
    revision        BIGINT NOT NULL CHECK (revision >= 0),
    owner_id        UUID,
    lease_expires_at TIMESTAMPTZ,
    document        JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    finished_at     TIMESTAMPTZ
);

CREATE INDEX idx_scan_jobs_created ON scan_jobs(created_at, id);
CREATE INDEX idx_scan_jobs_state ON scan_jobs(state) WHERE state IN ('queued', 'running', 'cancelling');
CREATE INDEX idx_scan_jobs_recovery ON scan_jobs(lease_expires_at)
    WHERE state IN ('queued', 'running', 'cancelling');
CREATE INDEX idx_scan_jobs_root ON scan_jobs(root_job_id, attempt);
