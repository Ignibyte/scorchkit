//! Provider-neutral application configuration for `ScorchKit`.

mod types;

#[cfg(feature = "cloud")]
pub mod cloud_credentials;
pub mod control_api;
pub mod cve;
pub mod extension;
pub mod mcp;
pub mod model_analysis;
pub mod network_credentials;
pub mod run_pipeline;
#[cfg(feature = "team")]
pub mod team;
pub mod webhook;

#[cfg(feature = "cloud")]
pub use cloud_credentials::CloudCredentials;
pub use control_api::ControlApiConfig;
pub use cve::{CompositeConfig, CompositeSource, CveBackendKind, CveConfig, NvdConfig};
pub use extension::ExtensionConfig;
pub use mcp::{McpConfig, RemoteMcpConfig, RemoteMcpPrincipalBinding, RemoteMcpTlsTermination};
pub use model_analysis::{
    ModelAdapterConfig, ModelAnalysisConfig, ModelRoleBindingConfig, ModelServiceDataPolicy,
    ModelServiceRedactionPolicy, ModelServiceRetentionPolicy, MAX_MODEL_SERVICE_OUTPUT_BYTES,
    MAX_MODEL_TIMEOUT_MILLIS, MIN_MODEL_TIMEOUT_MILLIS,
};
pub use network_credentials::NetworkCredentials;
pub use run_pipeline::RunProcessorConfig;
#[cfg(feature = "team")]
pub use team::{
    TeamCellConfig, TeamKeyReferenceConfig, TeamPrincipalBindingConfig, TeamQuotaConfig,
    TeamRetentionConfig, TeamServiceConfig, TeamTlsTermination,
};
pub use types::*;
pub use webhook::WebhookConfig;

/// Compatibility namespace retained inside mechanically extracted source.
pub mod engine {
    #[cfg(feature = "cloud")]
    pub use crate::cloud_credentials;
    pub use crate::network_credentials;
    pub use scorchkit_core::{error, events};
    pub use scorchkit_policy::{policy, scope};
}

/// Compatibility namespace for the configuration-owned webhook shape.
pub mod runner {
    pub mod hooks {
        pub use crate::webhook::*;
    }
}

#[cfg(test)]
pub(crate) static TEST_ENVIRONMENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
