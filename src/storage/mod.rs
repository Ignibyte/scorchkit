//! Persistent storage layer for `ScorchKit`.
//!
//! Provides async `PostgreSQL` access via `sqlx` for storing projects,
//! scan records, and tracked findings. This module is feature-gated
//! behind the `storage` Cargo feature — it is not compiled into the
//! default CLI-only build.
//!
//! # Usage
//!
//! ```no_run
//! use scorchkit::storage;
//!
//! # async fn example() -> scorchkit::engine::error::Result<()> {
//! let pool = storage::connect("postgresql://localhost/scorchkit").await?;
//! storage::migrate::run_migrations(&pool).await?;
//! # Ok(())
//! # }
//! ```

pub mod context;
pub mod findings;
pub mod intelligence;
pub mod metrics;
pub mod migrate;
pub mod models;
pub mod projects;
pub mod scans;
pub mod schedules;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::engine::error::{Result, ScorchError};

/// Connect to a `PostgreSQL` database and return a connection pool.
///
/// The `database_url` should be a full `PostgreSQL` connection string,
/// e.g., `postgresql://user:password@localhost:5432/scorchkit`.
///
/// # Errors
///
/// Returns an error if the database connection fails.
pub async fn connect(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| ScorchError::Database(format!("connection failed: {e}")))
}

/// Connect with a custom maximum connection count.
///
/// # Errors
///
/// Returns an error if the database connection fails.
pub async fn connect_with_max(database_url: &str, max_connections: u32) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await
        .map_err(|e| ScorchError::Database(format!("connection failed: {e}")))
}

/// Connect using application configuration.
///
/// Resolves the database URL with the following precedence:
/// 1. `url_override` parameter (from CLI `--database-url` flag)
/// 2. `config.url` (from `config.toml` `[database]` section)
/// 3. `DATABASE_URL` environment variable
///
/// If `config.migrate_on_startup` is true, runs pending migrations
/// after connecting.
///
/// # Errors
///
/// Returns an error if no database URL is configured, the connection
/// fails, or migration execution fails.
pub async fn connect_from_config(
    config: &crate::config::DatabaseConfig,
    url_override: Option<&str>,
) -> Result<PgPool> {
    let url = url_override
        .map(String::from)
        .or_else(|| config.url.clone())
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .ok_or_else(|| {
            ScorchError::Config(
                "no database URL configured. Set database.url in config.toml, \
                 pass --database-url, or set DATABASE_URL environment variable"
                    .to_string(),
            )
        })?;

    let pool = connect_with_max(&url, config.max_connections).await?;

    if config.migrate_on_startup {
        migrate::run_migrations(&pool).await?;
    }

    Ok(pool)
}
