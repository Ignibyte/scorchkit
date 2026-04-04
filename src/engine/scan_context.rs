use std::sync::Arc;

use crate::config::AppConfig;

use super::shared_data::SharedData;
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
    /// Shared data store for inter-module communication.
    ///
    /// Modules publish discovered data (URLs, forms, technologies) and
    /// downstream modules read it. Thread-safe via internal `RwLock`.
    pub shared_data: Arc<SharedData>,
}

impl ScanContext {
    /// Create a new scan context with an empty shared data store.
    #[must_use]
    pub fn new(target: Target, config: Arc<AppConfig>, http_client: reqwest::Client) -> Self {
        Self { target, config, http_client, shared_data: Arc::new(SharedData::new()) }
    }
}
