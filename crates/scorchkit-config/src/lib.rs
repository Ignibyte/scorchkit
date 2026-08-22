//! Provider-neutral application configuration for `ScorchKit`.

mod types;

#[cfg(feature = "cloud")]
pub mod cloud_credentials;
pub mod cve;
pub mod mcp;
pub mod network_credentials;
pub mod webhook;

#[cfg(feature = "cloud")]
pub use cloud_credentials::CloudCredentials;
pub use cve::{CompositeConfig, CompositeSource, CveBackendKind, CveConfig, NvdConfig};
pub use mcp::{McpConfig, RemoteMcpConfig, RemoteMcpPrincipalBinding, RemoteMcpTlsTermination};
pub use network_credentials::NetworkCredentials;
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
