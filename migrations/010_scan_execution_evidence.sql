-- Preserve typed execution integrity and application supply-chain evidence with scan records.
ALTER TABLE scan_records
    ADD COLUMN execution_evidence JSONB NOT NULL DEFAULT '{}'::jsonb;
