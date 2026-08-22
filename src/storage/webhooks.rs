//! `PostgreSQL` implementation of the provider-neutral webhook queue.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use scorchkit_executor::webhook::{WebhookDelivery, WebhookDeliveryAuditEvent, WebhookStore};

/// PostgreSQL-backed webhook store.
#[derive(Debug, Clone)]
pub struct PostgresWebhookStore {
    pool: PgPool,
}

impl PostgresWebhookStore {
    /// Bind the store to an existing migrated pool.
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
    i64::try_from(revision).map_err(|_| {
        ScorchError::Database(format!("webhook delivery revision {revision} exceeds BIGINT"))
    })
}

fn attempts_to_i32(attempts: u32) -> Result<i32> {
    i32::try_from(attempts).map_err(|_| {
        ScorchError::Database(format!("webhook delivery attempts {attempts} exceeds INTEGER"))
    })
}

fn limit_to_i64(limit: usize) -> i64 {
    i64::try_from(limit.min(1_000)).unwrap_or(1_000)
}

fn decode_document(value: serde_json::Value) -> Result<WebhookDelivery> {
    serde_json::from_value(value)
        .map_err(|error| ScorchError::Database(format!("invalid stored webhook delivery: {error}")))
}

fn decode_audit(value: serde_json::Value) -> Result<WebhookDeliveryAuditEvent> {
    serde_json::from_value(value).map_err(|error| {
        ScorchError::Database(format!("invalid webhook delivery audit event: {error}"))
    })
}

#[async_trait]
impl WebhookStore for PostgresWebhookStore {
    async fn create(&self, delivery: &WebhookDelivery, max_pending: usize) -> Result<()> {
        scorchkit_executor::webhook_integration::validate_delivery_create(delivery)?;
        let document = serde_json::to_value(delivery)?;
        let audit = WebhookDeliveryAuditEvent::from(delivery);
        let audit_document = serde_json::to_value(&audit)?;
        let mut transaction = self.pool.begin().await.map_err(|error| {
            ScorchError::Database(format!("begin webhook delivery creation failed: {error}"))
        })?;

        // Serialize enqueue capacity checks. Queue insertion is not scan-time
        // network work, and a hard bound is more important than enqueue throughput.
        sqlx::query("LOCK TABLE webhook_deliveries IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("lock webhook queue capacity failed: {error}"))
            })?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM webhook_deliveries
             WHERE destination_id = $1 AND state IN ('queued', 'delivering')",
        )
        .bind(&delivery.destination_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("count pending webhook deliveries failed: {error}"))
        })?;
        if pending >= i64::try_from(max_pending).unwrap_or(i64::MAX) {
            return Err(ScorchError::Webhook(format!(
                "destination '{}' pending queue reached its configured bound",
                delivery.destination_id
            )));
        }

        sqlx::query(
            "INSERT INTO webhook_deliveries (
                id, destination_id, event_kind, state, revision, attempts,
                owner_id, lease_expires_at, next_attempt_at, document,
                created_at, updated_at, finished_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(delivery.id)
        .bind(&delivery.destination_id)
        .bind(&delivery.event_kind)
        .bind(delivery.state.as_str())
        .bind(revision_to_i64(delivery.revision)?)
        .bind(attempts_to_i32(delivery.attempts)?)
        .bind(delivery.owner_id)
        .bind(delivery.lease_expires_at)
        .bind(delivery.next_attempt_at)
        .bind(document)
        .bind(delivery.created_at)
        .bind(delivery.updated_at)
        .bind(delivery.finished_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("create webhook delivery failed: {error}"))
        })?;
        sqlx::query(
            "INSERT INTO webhook_delivery_audit_events
                (delivery_id, revision, state, attempts, occurred_at, event)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(audit.delivery_id)
        .bind(revision_to_i64(audit.revision)?)
        .bind(audit.state.as_str())
        .bind(attempts_to_i32(audit.attempts)?)
        .bind(audit.occurred_at)
        .bind(audit_document)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("audit webhook delivery creation failed: {error}"))
        })?;
        transaction.commit().await.map_err(|error| {
            ScorchError::Database(format!("commit webhook delivery creation failed: {error}"))
        })?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<WebhookDelivery>> {
        let row = sqlx::query("SELECT document FROM webhook_deliveries WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("load webhook delivery failed: {error}"))
            })?;
        row.map(|row| row.try_get::<serde_json::Value, _>("document"))
            .transpose()
            .map_err(|error| {
                ScorchError::Database(format!("read webhook delivery failed: {error}"))
            })?
            .map(decode_document)
            .transpose()
    }

    async fn list(&self) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT document FROM webhook_deliveries ORDER BY created_at, id LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("list webhook deliveries failed: {error}"))
        })?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("document")
                    .map_err(|error| {
                        ScorchError::Database(format!("read webhook delivery failed: {error}"))
                    })
                    .and_then(decode_document)
            })
            .collect()
    }

    async fn list_due(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT document FROM webhook_deliveries
             WHERE state = 'queued' AND next_attempt_at <= $1
             ORDER BY next_attempt_at, created_at, id LIMIT $2",
        )
        .bind(now)
        .bind(limit_to_i64(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("list due webhook deliveries failed: {error}"))
        })?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("document")
                    .map_err(|error| {
                        ScorchError::Database(format!("read due webhook delivery failed: {error}"))
                    })
                    .and_then(decode_document)
            })
            .collect()
    }

    async fn list_recoverable(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookDelivery>> {
        let rows = sqlx::query(
            "SELECT document FROM webhook_deliveries
             WHERE state = 'delivering'
               AND (lease_expires_at IS NULL OR lease_expires_at <= $1)
             ORDER BY lease_expires_at, created_at, id LIMIT $2",
        )
        .bind(now)
        .bind(limit_to_i64(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("list recoverable webhook deliveries failed: {error}"))
        })?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("document")
                    .map_err(|error| {
                        ScorchError::Database(format!(
                            "read recoverable webhook delivery failed: {error}"
                        ))
                    })
                    .and_then(decode_document)
            })
            .collect()
    }

    async fn compare_and_swap(
        &self,
        expected_revision: u64,
        delivery: &WebhookDelivery,
    ) -> Result<bool> {
        let mut transaction = self.pool.begin().await.map_err(|error| {
            ScorchError::Database(format!("begin webhook delivery update failed: {error}"))
        })?;
        let row = sqlx::query(
            "SELECT document FROM webhook_deliveries
             WHERE id = $1 AND revision = $2 FOR UPDATE",
        )
        .bind(delivery.id)
        .bind(revision_to_i64(expected_revision)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("lock webhook delivery update failed: {error}"))
        })?;
        let Some(row) = row else {
            transaction.commit().await.map_err(|error| {
                ScorchError::Database(format!("commit stale webhook update failed: {error}"))
            })?;
            return Ok(false);
        };
        let existing = row
            .try_get::<serde_json::Value, _>("document")
            .map_err(|error| {
                ScorchError::Database(format!("read locked webhook delivery failed: {error}"))
            })
            .and_then(decode_document)?;
        scorchkit_executor::webhook_integration::validate_delivery_replacement(
            delivery,
            &existing,
            expected_revision,
        )?;
        let document = serde_json::to_value(delivery)?;
        let audit = WebhookDeliveryAuditEvent::from(delivery);
        let audit_document = serde_json::to_value(&audit)?;
        let result = sqlx::query(
            "UPDATE webhook_deliveries
             SET state = $1, revision = $2, attempts = $3, owner_id = $4,
                 lease_expires_at = $5, next_attempt_at = $6, document = $7,
                 updated_at = $8, finished_at = $9
             WHERE id = $10 AND revision = $11",
        )
        .bind(delivery.state.as_str())
        .bind(revision_to_i64(delivery.revision)?)
        .bind(attempts_to_i32(delivery.attempts)?)
        .bind(delivery.owner_id)
        .bind(delivery.lease_expires_at)
        .bind(delivery.next_attempt_at)
        .bind(document)
        .bind(delivery.updated_at)
        .bind(delivery.finished_at)
        .bind(delivery.id)
        .bind(revision_to_i64(expected_revision)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("update webhook delivery failed: {error}"))
        })?;
        if result.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO webhook_delivery_audit_events
                    (delivery_id, revision, state, attempts, occurred_at, event)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(audit.delivery_id)
            .bind(revision_to_i64(audit.revision)?)
            .bind(audit.state.as_str())
            .bind(attempts_to_i32(audit.attempts)?)
            .bind(audit.occurred_at)
            .bind(audit_document)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                ScorchError::Database(format!("audit webhook delivery update failed: {error}"))
            })?;
        }
        transaction.commit().await.map_err(|error| {
            ScorchError::Database(format!("commit webhook delivery update failed: {error}"))
        })?;
        Ok(result.rows_affected() == 1)
    }

    async fn audit_events(&self, id: Uuid) -> Result<Vec<WebhookDeliveryAuditEvent>> {
        let rows = sqlx::query(
            "SELECT event FROM webhook_delivery_audit_events
             WHERE delivery_id = $1 ORDER BY revision",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            ScorchError::Database(format!("list webhook delivery audits failed: {error}"))
        })?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<serde_json::Value, _>("event")
                    .map_err(|error| {
                        ScorchError::Database(format!(
                            "read webhook delivery audit failed: {error}"
                        ))
                    })
                    .and_then(decode_audit)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_projection_helpers_preserve_exact_values_and_overflow() {
        assert_eq!(attempts_to_i32(0).unwrap(), 0);
        assert_eq!(attempts_to_i32(1).unwrap(), 1);
        assert_eq!(attempts_to_i32(i32::MAX as u32).unwrap(), i32::MAX);
        assert!(attempts_to_i32(u32::MAX).is_err());
        assert_eq!(revision_to_i64(0).unwrap(), 0);
        assert_eq!(revision_to_i64(1).unwrap(), 1);
    }
}
