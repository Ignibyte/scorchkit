use std::sync::Arc;

use crate::config::AppConfig;

use super::target::Target;

/// Shared context passed to every scan module.
#[derive(Clone, Debug)]
pub struct ScanContext {
    /// The target being scanned.
    pub target: Target,
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// Shared HTTP client (connection pooling, TLS, timeouts).
    pub http_client: reqwest::Client,
}

impl ScanContext {
    #[must_use]
    pub const fn new(target: Target, config: Arc<AppConfig>, http_client: reqwest::Client) -> Self {
        Self { target, config, http_client }
    }
}
