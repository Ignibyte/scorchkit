//! `PostgreSQL` implementation of the provider-neutral scan job store.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use crate::runner::job::{JobStore, ScanJob, ScanJobAuditEvent};

/// PostgreSQL-backed scan job store.
#[derive(Debug, Clone)]
pub struct PostgresJobStore {
    pool: PgPool,
}

impl PostgresJobStore {
    /// Bind the job store to an existing migrated pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Borrow the underlying pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn revision_to_i64(revision: u64) -> Result<i64> {
    i64::try_from(revision)
        .map_err(|_| ScorchError::Database(format!("scan job revision {revision} exceeds BIGINT")))
}

fn decode_document(value: serde_json::Value) -> Result<ScanJob> {
    serde_json::from_value(value)
        .map_err(|error| ScorchError::Database(format!("invalid stored scan job: {error}")))
}

fn decode_audit_event(value: serde_json::Value) -> Result<ScanJobAuditEvent> {
    serde_json::from_value(value)
        .map_err(|error| ScorchError::Database(format!("invalid scan job audit event: {error}")))
}

#[async_trait]
impl JobStore for PostgresJobStore {
    async fn create(&self, job: &ScanJob) -> Result<()> {
        scorchkit_executor::integration::validate_job_create(job)?;
        let document = serde_json::to_value(job)?;
        let audit_event = ScanJobAuditEvent::from(job);
        let audit_document = serde_json::to_value(&audit_event)?;
        let mut transaction = self.pool.begin().await.map_err(|error| {
            ScorchError::Database(format!("begin scan job creation failed: {error}"))
        })?;
        if let Some(parent_id) = job.parent_job_id {
            let parent_row = sqlx::query("SELECT document FROM scan_jobs WHERE id = $1 FOR SHARE")
                .bind(parent_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| {
                    ScorchError::Database(format!("load scan job parent failed: {error}"))
                })?
                .ok_or_else(|| {
                    ScorchError::Job(format!("scan job parent {parent_id} was not found"))
                })?;
            let parent = parent_row
                .try_get::<serde_json::Value, _>("document")
                .map_err(|error| {
                    ScorchError::Database(format!("read scan job parent failed: {error}"))
                })
                .and_then(decode_document)?;
            scorchkit_executor::integration::validate_job_successor(job, &parent)?;
        }
        sqlx::query(
            "INSERT INTO scan_jobs (
                id, root_job_id, parent_job_id, attempt, state, revision,
                owner_id, lease_expires_at, document, created_at, updated_at, finished_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(job.id)
        .bind(job.root_job_id)
        .bind(job.parent_job_id)
        .bind(i32::try_from(job.attempt).map_err(|_| {
            ScorchError::Database(format!("scan job attempt {} exceeds INTEGER", job.attempt))
        })?)
        .bind(job.state.as_str())
        .bind(revision_to_i64(job.revision)?)
        .bind(job.owner_id)
        .bind(job.lease_expires_at)
        .bind(document)
        .bind(job.created_at)
        .bind(job.updated_at)
        .bind(job.finished_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("create scan job failed: {error}")))?;
        sqlx::query(
            "INSERT INTO scan_job_audit_events
                (job_id, revision, state, occurred_at, event)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(audit_event.job_id)
        .bind(revision_to_i64(audit_event.revision)?)
        .bind(audit_event.state.as_str())
        .bind(audit_event.occurred_at)
        .bind(audit_document)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("audit scan job creation failed: {error}"))
        })?;
        transaction.commit().await.map_err(|error| {
            ScorchError::Database(format!("commit scan job creation failed: {error}"))
        })?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ScanJob>> {
        let row = sqlx::query("SELECT document FROM scan_jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| ScorchError::Database(format!("load scan job failed: {error}")))?;
        row.map(|row| row.try_get::<serde_json::Value, _>("document"))
            .transpose()
            .map_err(|error| {
                ScorchError::Database(format!("read scan job document failed: {error}"))
            })?
            .map(decode_document)
            .transpose()
    }

    async fn list(&self) -> Result<Vec<ScanJob>> {
        let rows = sqlx::query("SELECT document FROM scan_jobs ORDER BY created_at, id LIMIT 1000")
            .fetch_all(&self.pool)
            .await
            .map_err(|error| ScorchError::Database(format!("list scan jobs failed: {error}")))?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("document")
                    .map_err(|error| {
                        ScorchError::Database(format!("read scan job document failed: {error}"))
                    })
                    .and_then(decode_document)
            })
            .collect()
    }

    async fn list_recoverable(&self, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<ScanJob>> {
        let rows = sqlx::query(
            "SELECT document FROM scan_jobs
             WHERE state IN ('queued', 'running', 'cancelling')
               AND (lease_expires_at IS NULL OR lease_expires_at <= $1)
             ORDER BY created_at, id
             LIMIT 1000",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("list recoverable scan jobs failed: {error}"))
        })?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("document")
                    .map_err(|error| {
                        ScorchError::Database(format!("read scan job document failed: {error}"))
                    })
                    .and_then(decode_document)
            })
            .collect()
    }

    async fn compare_and_swap(&self, expected_revision: u64, job: &ScanJob) -> Result<bool> {
        let mut transaction = self.pool.begin().await.map_err(|error| {
            ScorchError::Database(format!("begin scan job update failed: {error}"))
        })?;
        let existing_row = sqlx::query(
            "SELECT document FROM scan_jobs
             WHERE id = $1 AND revision = $2
             FOR UPDATE",
        )
        .bind(job.id)
        .bind(revision_to_i64(expected_revision)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("lock scan job update failed: {error}")))?;
        let Some(existing_row) = existing_row else {
            transaction.commit().await.map_err(|error| {
                ScorchError::Database(format!("commit stale scan job update failed: {error}"))
            })?;
            return Ok(false);
        };
        let existing = existing_row
            .try_get::<serde_json::Value, _>("document")
            .map_err(|error| {
                ScorchError::Database(format!("read locked scan job document failed: {error}"))
            })
            .and_then(decode_document)?;
        scorchkit_executor::integration::validate_job_replacement(
            job,
            &existing,
            expected_revision,
        )?;
        let document = serde_json::to_value(job)?;
        let audit_event = ScanJobAuditEvent::from(job);
        let audit_document = serde_json::to_value(&audit_event)?;
        let result = sqlx::query(
            "UPDATE scan_jobs
             SET state = $1, revision = $2, owner_id = $3, lease_expires_at = $4,
                 document = $5, updated_at = $6, finished_at = $7
             WHERE id = $8 AND revision = $9",
        )
        .bind(job.state.as_str())
        .bind(revision_to_i64(job.revision)?)
        .bind(job.owner_id)
        .bind(job.lease_expires_at)
        .bind(document)
        .bind(job.updated_at)
        .bind(job.finished_at)
        .bind(job.id)
        .bind(revision_to_i64(expected_revision)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| ScorchError::Database(format!("update scan job failed: {error}")))?;
        if result.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO scan_job_audit_events
                    (job_id, revision, state, occurred_at, event)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(audit_event.job_id)
            .bind(revision_to_i64(audit_event.revision)?)
            .bind(audit_event.state.as_str())
            .bind(audit_event.occurred_at)
            .bind(audit_document)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("audit scan job update failed: {error}"))
            })?;
        }
        transaction.commit().await.map_err(|error| {
            ScorchError::Database(format!("commit scan job update failed: {error}"))
        })?;
        Ok(result.rows_affected() == 1)
    }

    async fn audit_events(&self, id: Uuid) -> Result<Vec<ScanJobAuditEvent>> {
        let rows = sqlx::query(
            "SELECT event FROM scan_job_audit_events
             WHERE job_id = $1 ORDER BY revision",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("list scan job audit events failed: {error}"))
        })?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("event")
                    .map_err(|error| {
                        ScorchError::Database(format!("read scan job audit event failed: {error}"))
                    })
                    .and_then(decode_audit_event)
            })
            .collect()
    }
}
