-- Add confidence score column to tracked_findings.
-- Defaults to 0.5 (medium confidence) for existing findings.
ALTER TABLE tracked_findings ADD COLUMN confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5;
