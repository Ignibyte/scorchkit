//! Scan schedule persistence and cron computation.
//!
//! Provides CRUD operations for recurring scan schedules and
//! cron-based next-run computation via the `croner` crate.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use croner::Cron;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::models::ScanSchedule;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::Engagement;

/// Compute the next run time from a cron expression relative to now.
///
/// Returns `None` if the cron expression is invalid or has no future
/// occurrence.
#[must_use]
pub fn compute_next_run(cron_expression: &str) -> Option<DateTime<Utc>> {
    let cron = Cron::from_str(cron_expression).ok()?;
    cron.find_next_occurrence(&Utc::now(), false).ok()
}

/// Compute the next run time from a cron expression relative to a given time.
///
/// Useful for testing with deterministic timestamps.
#[must_use]
pub fn compute_next_run_after(
    cron_expression: &str,
    after: &DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let cron = Cron::from_str(cron_expression).ok()?;
    cron.find_next_occurrence(after, false).ok()
}

/// Create a new scan schedule for a project.
///
/// Validates the cron expression before saving. The `next_run` is computed
/// from the cron expression relative to the current time.
///
/// # Errors
///
/// Returns an error if the cron expression is invalid or the database
/// query fails.
pub async fn create_schedule(
    pool: &PgPool,
    project_id: Uuid,
    target_url: &str,
    profile: &str,
    cron_expression: &str,
    engagement: &Engagement,
) -> Result<ScanSchedule> {
    let next_run = compute_next_run(cron_expression).ok_or_else(|| {
        ScorchError::Config(format!("invalid cron expression: '{cron_expression}'"))
    })?;

    let engagement_snapshot = serde_json::to_value(engagement).map_err(|error| {
        ScorchError::Config(format!("serialize schedule engagement snapshot: {error}"))
    })?;

    sqlx::query_as::<_, ScanSchedule>(
        "INSERT INTO scan_schedules \
         (project_id, target_url, profile, cron_expression, next_run, engagement_snapshot) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
    )
    .bind(project_id)
    .bind(target_url)
    .bind(profile)
    .bind(cron_expression)
    .bind(next_run)
    .bind(engagement_snapshot)
    .fetch_one(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("create schedule: {e}")))
}

/// List all schedules for a project.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_schedules(pool: &PgPool, project_id: Uuid) -> Result<Vec<ScanSchedule>> {
    sqlx::query_as::<_, ScanSchedule>(
        "SELECT * FROM scan_schedules WHERE project_id = $1 ORDER BY created_at",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list schedules: {e}")))
}

/// Get a single schedule by ID.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_schedule(pool: &PgPool, id: Uuid) -> Result<Option<ScanSchedule>> {
    sqlx::query_as::<_, ScanSchedule>("SELECT * FROM scan_schedules WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get schedule: {e}")))
}

/// Enable or disable a schedule.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn update_schedule_enabled(pool: &PgPool, id: Uuid, enabled: bool) -> Result<bool> {
    let result = sqlx::query("UPDATE scan_schedules SET enabled = $2 WHERE id = $1")
        .bind(id)
        .bind(enabled)
        .execute(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("update schedule enabled: {e}")))?;
    Ok(result.rows_affected() > 0)
}

/// Delete a schedule.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn delete_schedule(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scan_schedules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("delete schedule: {e}")))?;
    Ok(result.rows_affected() > 0)
}

/// Find all schedules that are due for execution.
///
/// Returns enabled schedules whose `next_run` is at or before the current time.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn find_due_schedules(pool: &PgPool) -> Result<Vec<ScanSchedule>> {
    sqlx::query_as::<_, ScanSchedule>(
        "SELECT * FROM scan_schedules \
         WHERE enabled = true AND next_run <= now() \
         ORDER BY next_run",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("find due schedules: {e}")))
}

/// Atomically claim every schedule that is currently due.
///
/// Rows are locked with `SKIP LOCKED`, advanced inside one short transaction,
/// and returned only after the claim commits. No transaction or pooled
/// connection remains held while the caller performs scan effects. Advancing
/// before execution gives each due occurrence at-most-once semantics: a
/// failed or interrupted scan is recorded as an attempt and is not silently
/// retried by another overlapping caller.
///
/// # Errors
///
/// Returns an error if rows cannot be selected, advanced, or committed.
pub async fn claim_due_schedules(pool: &PgPool) -> Result<Vec<ScanSchedule>> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| ScorchError::Database(format!("begin schedule claim: {error}")))?;
    let due = sqlx::query_as::<_, ScanSchedule>(
        "SELECT * FROM scan_schedules \
         WHERE enabled = true AND next_run <= now() \
         ORDER BY next_run, id \
         FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(|error| ScorchError::Database(format!("claim due schedules: {error}")))?;

    let claimed_at = Utc::now();
    for schedule in &due {
        advance_claimed_schedule(&mut transaction, schedule, &claimed_at).await?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| ScorchError::Database(format!("commit schedule claim: {error}")))?;
    Ok(due)
}

async fn advance_claimed_schedule(
    transaction: &mut Transaction<'_, Postgres>,
    schedule: &ScanSchedule,
    claimed_at: &DateTime<Utc>,
) -> Result<()> {
    match compute_next_run_after(&schedule.cron_expression, claimed_at) {
        Some(next_run) => {
            sqlx::query(
                "UPDATE scan_schedules \
                 SET last_run = $2, next_run = $3 \
                 WHERE id = $1",
            )
            .bind(schedule.id)
            .bind(claimed_at)
            .bind(next_run)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("advance claimed schedule {}: {error}", schedule.id))
            })?;
        }
        None => {
            sqlx::query(
                "UPDATE scan_schedules \
                 SET last_run = $2, enabled = false \
                 WHERE id = $1",
            )
            .bind(schedule.id)
            .bind(claimed_at)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("disable claimed schedule {}: {error}", schedule.id))
            })?;
        }
    }
    Ok(())
}

/// Mark a schedule as run and compute the next execution time.
///
/// Updates `last_run` to now and `next_run` to the next occurrence
/// of the cron expression. If the cron expression no longer has a
/// future occurrence, disables the schedule.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn mark_schedule_run(pool: &PgPool, schedule: &ScanSchedule) -> Result<()> {
    let next = compute_next_run(&schedule.cron_expression);

    match next {
        Some(next_run) => {
            sqlx::query("UPDATE scan_schedules SET last_run = now(), next_run = $2 WHERE id = $1")
                .bind(schedule.id)
                .bind(next_run)
                .execute(pool)
                .await
                .map_err(|e| ScorchError::Database(format!("mark schedule run: {e}")))?;
        }
        None => {
            // No future occurrence — disable the schedule
            sqlx::query(
                "UPDATE scan_schedules SET last_run = now(), enabled = false WHERE id = $1",
            )
            .bind(schedule.id)
            .execute(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("disable exhausted schedule: {e}")))?;
        }
    }

    Ok(())
}
