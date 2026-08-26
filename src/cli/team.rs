//! CLI adapter for the optional authenticated team service.

use std::sync::Arc;

use crate::config::AppConfig;
use crate::engine::error::Result;

/// Start the fully preflighted loopback team backend.
///
/// # Errors
///
/// Returns before listening when any profile, secret, cell, database, object root, or policy
/// invariant fails.
pub async fn run_team_api(config: Arc<AppConfig>) -> Result<()> {
    crate::team::transport::serve(config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_configuration_cannot_start_team_service() {
        let error = run_team_api(Arc::new(AppConfig::default()))
            .await
            .expect_err("default config is inert");
        assert!(matches!(error, crate::engine::error::ScorchError::Config(_)));
    }
}
