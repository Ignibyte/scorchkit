-- Versioned application-security identity, evidence history, and agent analysis.

ALTER TABLE tracked_findings
    ADD COLUMN identity_schema TEXT NOT NULL DEFAULT 'scorchkit.finding-identity/legacy-v1',
    ADD COLUMN stable_identity TEXT,
    ADD COLUMN correlation_keys JSONB NOT NULL DEFAULT '[]'::jsonb;

WITH ranked AS (
    SELECT id,
           fingerprint,
           row_number() OVER (PARTITION BY project_id, fingerprint ORDER BY first_seen, id) AS rank
    FROM tracked_findings
)
UPDATE tracked_findings AS finding
SET stable_identity = CASE
    WHEN ranked.rank = 1 THEN 'legacy:' || ranked.fingerprint
    ELSE 'legacy:' || ranked.fingerprint || ':' || finding.id::text
END
FROM ranked
WHERE finding.id = ranked.id;

ALTER TABLE tracked_findings
    ALTER COLUMN stable_identity SET NOT NULL;

CREATE UNIQUE INDEX idx_tracked_findings_stable_identity
    ON tracked_findings(project_id, stable_identity);

CREATE TABLE finding_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracked_finding_id  UUID NOT NULL REFERENCES tracked_findings(id) ON DELETE CASCADE,
    scan_id             UUID NOT NULL REFERENCES scan_records(id) ON DELETE CASCADE,
    evidence_identity   TEXT NOT NULL,
    evidence_schema     TEXT NOT NULL,
    raw_evidence        JSONB NOT NULL,
    collected_at        TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tracked_finding_id, scan_id, evidence_identity)
);

CREATE INDEX idx_finding_evidence_finding
    ON finding_evidence(tracked_finding_id, collected_at DESC);

CREATE TABLE finding_agent_analysis (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracked_finding_id  UUID NOT NULL REFERENCES tracked_findings(id) ON DELETE CASCADE,
    analysis_identity   TEXT NOT NULL,
    analysis_schema     TEXT NOT NULL,
    raw_analysis        JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    stored_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tracked_finding_id, analysis_identity)
);

CREATE INDEX idx_finding_agent_analysis_finding
    ON finding_agent_analysis(tracked_finding_id, created_at DESC);
