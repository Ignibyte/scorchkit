-- Scan schedules: recurring scan definitions per project
-- Triggered explicitly via CLI `schedule run-due` or MCP `run-due-scans`

CREATE TABLE scan_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_url      TEXT NOT NULL,
    profile         TEXT NOT NULL DEFAULT 'standard',
    cron_expression TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run        TIMESTAMPTZ,
    next_run        TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_schedules_project ON scan_schedules(project_id);
CREATE INDEX idx_scan_schedules_due ON scan_schedules(next_run) WHERE enabled = true;
