-- An interrupted attempt may have only one successor, and an attempt number may occur only once
-- within a root job chain. These indexes make concurrent resume requests converge on one winner.

CREATE UNIQUE INDEX idx_scan_jobs_one_successor
    ON scan_jobs(parent_job_id)
    WHERE parent_job_id IS NOT NULL;

CREATE UNIQUE INDEX idx_scan_jobs_one_root_attempt
    ON scan_jobs(root_job_id, attempt);
