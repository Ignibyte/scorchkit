-- Exact ScorchKit v2.1.0 schema: migrations 001 through 004 in release order.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    settings    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_targets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, url)
);

CREATE INDEX idx_project_targets_project ON project_targets(project_id);

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

ALTER TABLE tracked_findings ADD COLUMN confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5;

ALTER TABLE tracked_findings ADD COLUMN status_note TEXT;

-- SQLx's v2.1.0 migration ledger. The SHA-384 checksums are for the exact four migration files
-- above, so the current embedded migrator verifies history before applying migration 005 onward.
CREATE TABLE _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);

INSERT INTO _sqlx_migrations (
    version, description, installed_on, success, checksum, execution_time
)
VALUES
    (
        1,
        'initial',
        '2025-01-01T00:00:00Z',
        true,
        decode('83c6101fdb218287b1b7fa6aea8c461966626d69dff91d50f4032e3c10b22d1b71021d690b9d000ac6f3a4d188498f5d', 'hex'),
        1
    ),
    (
        2,
        'scan schedules',
        '2025-01-01T00:00:01Z',
        true,
        decode('a987f4b9276f9bbf12ef95ac1134e35afbe7244a1a78cb25cb798f30b8533eaac765ba3c3db596d6e7403653d053a6d7', 'hex'),
        1
    ),
    (
        3,
        'add confidence',
        '2025-01-01T00:00:02Z',
        true,
        decode('9e3666376c156b793c0066fb0e76ddc5f03007eb3956bb86e2c9205d3e39e9ce1c35081550c8d47595b185ee48e5ccf8', 'hex'),
        1
    ),
    (
        4,
        'add status note',
        '2025-01-01T00:00:03Z',
        true,
        decode('a9d5efee283ff6f9ffbec365c5c6bd67d88983acc9b0ddda3b035e0c5438367610c34cf03b3531b076b11c6086e11182', 'hex'),
        1
    );
