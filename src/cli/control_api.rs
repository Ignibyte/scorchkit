//! CLI adapter for the explicit loopback control API listener.

use std::sync::Arc;

use crate::config::AppConfig;
use crate::engine::error::Result;

/// Start the configured authenticated loopback control API.
///
/// # Errors
///
/// Returns an error before listening when configuration, credential resolution, storage,
/// webhook composition, or listener startup fails.
pub async fn run_control_api(config: &Arc<AppConfig>, database_url: Option<&str>) -> Result<()> {
    crate::control::transport::serve(Arc::clone(config), database_url).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listener_adapter_propagates_preflight_failure() {
        let error = run_control_api(&Arc::new(AppConfig::default()), None)
            .await
            .expect_err("default configuration cannot start a control listener");
        assert!(matches!(error, crate::engine::error::ScorchError::Config(_)));
    }
}
