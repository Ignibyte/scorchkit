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

pub mod attack_paths;
pub mod context;
pub mod findings;
pub mod intelligence;
pub mod jobs;
pub mod metrics;
pub mod migrate;
pub mod models;
pub mod projects;
pub mod scans;
pub mod schedules;
pub mod triage;
pub mod webhooks;

use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
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
    let options = connection_options(database_url)?;
    PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(|e| ScorchError::Database(format!("connection failed: {e}")))
}

/// Connect with a custom maximum connection count.
///
/// # Errors
///
/// Returns an error if the database connection fails.
pub async fn connect_with_max(database_url: &str, max_connections: u32) -> Result<PgPool> {
    let options = connection_options(database_url)?;
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .map_err(|e| ScorchError::Database(format!("connection failed: {e}")))
}

fn connection_options(database_url: &str) -> Result<PgConnectOptions> {
    let parsed_url = url::Url::parse(database_url).map_err(|_| {
        ScorchError::Database("connection failed: connection URL is invalid".to_string())
    })?;
    let options = PgConnectOptions::from_str(database_url).map_err(|_| {
        ScorchError::Database("connection failed: connection URL is invalid".to_string())
    })?;

    let username_is_explicit =
        !parsed_url.username().is_empty() || parsed_url.query_pairs().any(|(key, _)| key == "user");
    if !username_is_explicit {
        let expected_username = std::env::var("PGUSER")
            .ok()
            .or_else(|| whoami::username().ok())
            .unwrap_or_else(|| "unknown".to_string());
        if options.get_username() != expected_username {
            return Err(ScorchError::Database(
                "connection URL omitted a username, but the local PostgreSQL username could not be resolved"
                    .to_string(),
            ));
        }
    }

    Ok(options)
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

#[cfg(test)]
mod tests {
    use super::connection_options;

    #[test]
    fn omitted_username_uses_the_local_postgresql_identity() {
        let options = connection_options("postgresql:///scorchkit_test").expect("valid options");
        let expected = std::env::var("PGUSER")
            .ok()
            .or_else(|| whoami::username().ok())
            .unwrap_or_else(|| "unknown".to_string());

        assert_eq!(options.get_username(), expected);
    }

    #[test]
    fn explicit_username_is_preserved() {
        let options = connection_options("postgresql://scorch_user@localhost/scorchkit_test")
            .expect("valid options");

        assert_eq!(options.get_username(), "scorch_user");
    }

    #[test]
    fn query_username_is_preserved() {
        let options = connection_options("postgresql:///scorchkit_test?user=query_user")
            .expect("valid options");

        assert_eq!(options.get_username(), "query_user");
    }

    #[test]
    fn invalid_connection_url_is_rejected_without_echoing_it() {
        let invalid_url = "postgresql://user:secret@[invalid/scorchkit";
        let error = connection_options(invalid_url).expect_err("invalid URL must fail");
        let message = error.to_string();

        assert!(message.contains("connection URL is invalid"));
        assert!(!message.contains("secret"));
    }

    #[test]
    fn invalid_connection_option_is_rejected_without_echoing_it() {
        let invalid_url =
            "postgresql://user:secret@localhost/scorchkit?sslmode=invalid-secret-mode";
        let error = connection_options(invalid_url).expect_err("invalid option must fail");
        let message = error.to_string();

        assert!(message.contains("connection URL is invalid"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("invalid-secret-mode"));
    }
}
