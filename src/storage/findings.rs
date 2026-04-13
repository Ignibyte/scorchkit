//! Finding persistence with fingerprint-based deduplication.
//!
//! When a finding is saved, its fingerprint (SHA-256 of `module_id` + title +
//! `affected_target`) is checked against existing findings for the same project.
//! If a match exists, `seen_count` is incremented and `last_seen` is updated
//! instead of creating a duplicate row.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::models::{TrackedFinding, VulnStatus};
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;

/// Compute a stable fingerprint for deduplication.
///
/// Uses SHA-256 of `module_id || title || affected_target`. This deliberately
/// excludes evidence and timestamp so the same vulnerability found on
/// different scans maps to the same tracked finding.
#[must_use]
pub fn fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.module_id.as_bytes());
    hasher.update(b"|");
    hasher.update(finding.title.as_bytes());
    hasher.update(b"|");
    hasher.update(finding.affected_target.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Save a batch of findings from a scan, deduplicating against existing
/// findings in the same project.
///
/// For each finding:
/// - If the fingerprint already exists for this project, update
///   `last_seen`, `seen_count`, and `scan_id` on the existing row.
/// - Otherwise, insert a new tracked finding.
///
/// Returns the number of new findings created (not counting updates).
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn save_findings(
    pool: &PgPool,
    project_id: Uuid,
    scan_id: Uuid,
    findings: &[Finding],
) -> Result<usize> {
    let mut new_count = 0;

    for finding in findings {
        let fp = fingerprint(finding);
        let raw_json = serde_json::to_value(finding)
            .map_err(|e| ScorchError::Database(format!("serialize finding: {e}")))?;

        // Try to update existing finding with same fingerprint
        let updated = sqlx::query(
            "UPDATE tracked_findings \
             SET last_seen = now(), seen_count = seen_count + 1, scan_id = $3, \
                 evidence = COALESCE($4, evidence), \
                 raw_finding = $5, confidence = $6 \
             WHERE project_id = $1 AND fingerprint = $2",
        )
        .bind(project_id)
        .bind(&fp)
        .bind(scan_id)
        .bind(&finding.evidence)
        .bind(&raw_json)
        .bind(finding.confidence)
        .execute(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("update finding: {e}")))?;

        if updated.rows_affected() == 0 {
            // No existing finding — insert new
            sqlx::query(
                "INSERT INTO tracked_findings \
                 (scan_id, project_id, fingerprint, module_id, severity, \
                  title, description, affected_target, evidence, \
                  remediation, owasp_category, cwe_id, raw_finding, confidence) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(scan_id)
            .bind(project_id)
            .bind(&fp)
            .bind(&finding.module_id)
            .bind(finding.severity.to_string())
            .bind(&finding.title)
            .bind(&finding.description)
            .bind(&finding.affected_target)
            .bind(&finding.evidence)
            .bind(&finding.remediation)
            .bind(&finding.owasp_category)
            .bind(finding.cwe_id.map(u32::cast_signed))
            .bind(&raw_json)
            .bind(finding.confidence)
            .execute(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("insert finding: {e}")))?;

            new_count += 1;
        }
    }

    Ok(new_count)
}

/// Update the lifecycle status of a tracked finding with an optional note.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn update_finding_status(
    pool: &PgPool,
    finding_id: Uuid,
    status: VulnStatus,
    note: Option<&str>,
) -> Result<bool> {
    let result =
        sqlx::query("UPDATE tracked_findings SET status = $2, status_note = $3 WHERE id = $1")
            .bind(finding_id)
            .bind(status.as_db_str())
            .bind(note)
            .execute(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("update finding status: {e}")))?;

    Ok(result.rows_affected() > 0)
}

/// Query findings for a project filtered by severity.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_by_severity(
    pool: &PgPool,
    project_id: Uuid,
    severity: &str,
) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 AND severity = $2 \
         ORDER BY last_seen DESC",
    )
    .bind(project_id)
    .bind(severity)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find by severity: {e}")))
}

/// Query findings for a project filtered by lifecycle status.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_by_status(
    pool: &PgPool,
    project_id: Uuid,
    status: VulnStatus,
) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 AND status = $2 \
         ORDER BY last_seen DESC",
    )
    .bind(project_id)
    .bind(status.as_db_str())
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find by status: {e}")))
}

/// Get all findings for a specific scan.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_by_scan(pool: &PgPool, scan_id: Uuid) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings WHERE scan_id = $1 \
         ORDER BY severity DESC, title",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find by scan: {e}")))
}

/// List all findings for a project, newest first.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_findings(pool: &PgPool, project_id: Uuid) -> Result<Vec<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>(
        "SELECT * FROM tracked_findings \
         WHERE project_id = $1 \
         ORDER BY last_seen DESC",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list findings: {e}")))
}

/// Get a single tracked finding by ID.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_finding(pool: &PgPool, id: Uuid) -> Result<Option<TrackedFinding>> {
    sqlx::query_as::<_, TrackedFinding>("SELECT * FROM tracked_findings WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get finding: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    /// Verify that the same finding inputs always produce the same
    /// fingerprint hash, ensuring deterministic deduplication.
    #[test]
    fn test_finding_fingerprint_deterministic() {
        let f1 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        );
        let f2 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        );

        assert_eq!(fingerprint(&f1), fingerprint(&f2));
    }

    /// Verify that different affected targets produce different
    /// fingerprints, so the same vuln type on different pages
    /// tracks separately.
    #[test]
    fn test_fingerprint_differs_by_target() {
        let f1 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        );
        let f2 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/register",
        );

        assert_ne!(fingerprint(&f1), fingerprint(&f2));
    }

    /// Verify that evidence and timestamp do NOT affect the
    /// fingerprint — same vuln found at different times with
    /// different evidence should still dedup.
    #[test]
    fn test_fingerprint_ignores_evidence_and_timestamp() {
        let f1 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        )
        .with_evidence("evidence 1");
        let f2 = Finding::new(
            "xss",
            Severity::High,
            "Reflected XSS",
            "desc",
            "https://example.com/login",
        )
        .with_evidence("evidence 2");

        assert_eq!(fingerprint(&f1), fingerprint(&f2));
    }
}
