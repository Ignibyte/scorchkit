//! Database management CLI handlers.
//!
//! Provides the `db migrate` command for initializing and updating
//! the `PostgreSQL` schema.

use colored::Colorize;

use crate::config::AppConfig;
use crate::engine::error::Result;
use crate::storage;

/// Run pending database migrations.
///
/// # Errors
///
/// Returns an error if the database URL is not configured or if
/// the connection or migration execution fails.
pub async fn run_migrate(config: &AppConfig) -> Result<()> {
    println!("{}", "Running database migrations...".bold());

    let url =
        config.database.url.clone().or_else(|| std::env::var("DATABASE_URL").ok()).ok_or_else(
            || {
                crate::engine::error::ScorchError::Config(
                    "no database URL configured. Set database.url in config.toml \
                 or set DATABASE_URL environment variable"
                        .to_string(),
                )
            },
        )?;

    let pool = storage::connect(&url).await?;
    storage::migrate::run_migrations(&pool).await?;

    println!("{} Database migrations complete.", "success:".green().bold());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrate_observes_connection_errors() {
        let mut config = AppConfig::default();
        config.database.url = Some("invalid-database-scheme://localhost/scorchkit".to_string());

        assert!(run_migrate(&config).await.is_err());
    }
}
