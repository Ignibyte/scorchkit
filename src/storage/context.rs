//! Project context builder for AI analysis.
//!
//! Queries scan history and finding lifecycle data to build a
//! [`ProjectContext`] that enriches AI prompts with trend information.

use sqlx::PgPool;
use uuid::Uuid;

use crate::ai::types::{FindingTrends, ProjectContext, StatusBreakdown};
use crate::engine::error::{Result, ScorchError};

/// Build project context from database queries for AI prompt enrichment.
///
/// Aggregates scan count, latest scan date, and finding status breakdown
/// for the given project.
///
/// # Errors
///
/// Returns an error if any database query fails.
pub async fn build_project_context(
    pool: &PgPool,
    project_id: Uuid,
    project_name: &str,
) -> Result<ProjectContext> {
    let scan_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scan_records WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("count scans: {e}")))?;

    let latest_scan_date: Option<String> = sqlx::query_scalar(
        "SELECT to_char(started_at, 'YYYY-MM-DD HH24:MI') \
         FROM scan_records WHERE project_id = $1 \
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("latest scan date: {e}")))?;

    let total_tracked: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tracked_findings WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("count findings: {e}")))?;

    let status_counts = count_findings_by_status(pool, project_id).await?;

    // JUSTIFICATION: values bounded by DB row counts, always < usize::MAX on 64-bit
    #[allow(clippy::cast_possible_truncation)]
    let total_scans = scan_count.unsigned_abs() as usize;
    // JUSTIFICATION: values bounded by DB row counts, always < usize::MAX on 64-bit
    #[allow(clippy::cast_possible_truncation)]
    let total_tracked_usize = total_tracked.unsigned_abs() as usize;

    Ok(ProjectContext {
        project_name: project_name.to_string(),
        total_scans,
        latest_scan_date,
        finding_trends: FindingTrends {
            total_tracked: total_tracked_usize,
            by_status: status_counts,
        },
    })
}

/// Count findings by lifecycle status for a project.
async fn count_findings_by_status(pool: &PgPool, project_id: Uuid) -> Result<StatusBreakdown> {
    // Single query to count all statuses at once
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) as cnt FROM tracked_findings \
         WHERE project_id = $1 GROUP BY status",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("count by status: {e}")))?;

    let mut breakdown =
        StatusBreakdown { new: 0, acknowledged: 0, false_positive: 0, remediated: 0, verified: 0 };

    for (status, count) in &rows {
        // JUSTIFICATION: values bounded by DB row counts, always < usize::MAX on 64-bit
        #[allow(clippy::cast_possible_truncation)]
        let count_usize = count.unsigned_abs() as usize;
        match status.as_str() {
            "new" => breakdown.new = count_usize,
            "acknowledged" => breakdown.acknowledged = count_usize,
            "false_positive" => breakdown.false_positive = count_usize,
            "remediated" => breakdown.remediated = count_usize,
            "verified" => breakdown.verified = count_usize,
            _ => {} // Unknown statuses are ignored
        }
    }

    Ok(breakdown)
}
