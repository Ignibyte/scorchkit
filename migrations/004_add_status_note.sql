-- Add status_note column for triage rationale on findings.
ALTER TABLE tracked_findings ADD COLUMN status_note TEXT;
