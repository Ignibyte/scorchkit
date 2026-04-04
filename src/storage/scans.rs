//! Scan record persistence.
//!
//! Stores and retrieves scan execution records linked to projects.
//! Each scan record captures what was scanned, which modules ran,
//! and summary statistics.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::models::ScanRecord;
use crate::engine::error::{Result, ScorchError};

/// Save a new scan record for a project.
///
/// # Errors
///
/// Returns an error if the database query fails.
// JUSTIFICATION: save_scan maps directly to the scan_records table columns;
// bundling into a struct would add unnecessary indirection for an internal API.
#[allow(clippy::too_many_arguments)]
pub async fn save_scan(
    pool: &PgPool,
    project_id: Uuid,
    target_url: &str,
    profile: &str,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    modules_run: &[String],
    modules_skipped: &[String],
    summary: &serde_json::Value,
) -> Result<ScanRecord> {
    sqlx::query_as::<_, ScanRecord>(
        "INSERT INTO scan_records \
         (project_id, target_url, profile, started_at, completed_at, \
          modules_run, modules_skipped, summary) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
    )
    .bind(project_id)
    .bind(target_url)
    .bind(profile)
    .bind(started_at)
    .bind(completed_at)
    .bind(modules_run)
    .bind(modules_skipped)
    .bind(summary)
    .fetch_one(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("save scan: {e}")))
}

/// Get a scan record by ID.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_scan(pool: &PgPool, id: Uuid) -> Result<Option<ScanRecord>> {
    sqlx::query_as::<_, ScanRecord>("SELECT * FROM scan_records WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get scan: {e}")))
}

/// List all scans for a project, newest first.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_scans(pool: &PgPool, project_id: Uuid) -> Result<Vec<ScanRecord>> {
    sqlx::query_as::<_, ScanRecord>(
        "SELECT * FROM scan_records WHERE project_id = $1 \
         ORDER BY started_at DESC",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list scans: {e}")))
}
