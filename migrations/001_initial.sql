-- ScorchKit initial schema
-- Projects, targets, scan records, and tracked findings

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Projects: named security assessment scopes
CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    settings    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Project targets: URLs associated with a project
CREATE TABLE project_targets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, url)
);

CREATE INDEX idx_project_targets_project ON project_targets(project_id);

-- Scan records: one row per scan execution
CREATE TABLE scan_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_url      TEXT NOT NULL,
    profile         TEXT NOT NULL DEFAULT 'standard',
    started_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    modules_run     TEXT[] NOT NULL DEFAULT '{}',
    modules_skipped TEXT[] NOT NULL DEFAULT '{}',
    summary         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_records_project ON scan_records(project_id);
CREATE INDEX idx_scan_records_started ON scan_records(started_at DESC);

-- Tracked findings: deduplicated vulnerability records with lifecycle
CREATE TABLE tracked_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scan_records(id) ON DELETE CASCADE,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL,
    module_id       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    affected_target TEXT NOT NULL,
    evidence        TEXT,
    remediation     TEXT,
    owasp_category  TEXT,
    cwe_id          INTEGER,
    raw_finding     JSONB NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_count      INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'new',
    found_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tracked_findings_project ON tracked_findings(project_id);
CREATE INDEX idx_tracked_findings_scan ON tracked_findings(scan_id);
CREATE INDEX idx_tracked_findings_fingerprint ON tracked_findings(project_id, fingerprint);
CREATE INDEX idx_tracked_findings_severity ON tracked_findings(severity);
CREATE INDEX idx_tracked_findings_status ON tracked_findings(status);
