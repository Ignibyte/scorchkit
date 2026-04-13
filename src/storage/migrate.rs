//! Database migration runner.
//!
//! Embeds SQL migration files from the `migrations/` directory and
//! applies them to the connected database. Migrations are idempotent —
//! already-applied migrations are skipped.

use sqlx::PgPool;

use crate::engine::error::{Result, ScorchError};

/// Run all pending database migrations.
///
/// Uses `sqlx::migrate!()` to embed migration files at compile time
/// from the `migrations/` directory at the crate root.
///
/// # Errors
///
/// Returns an error if a migration fails to apply.
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("migration failed: {e}")))?;
    Ok(())
}
