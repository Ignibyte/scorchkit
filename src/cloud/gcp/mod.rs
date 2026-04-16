//! Native GCP posture checks via `google-cloud-auth` + REST (WORK-127).
//!
//! Four built-in cloud modules that call GCP REST APIs directly:
//!
//! - [`iam::GcpIamCloudModule`] — user-managed service account keys
//! - [`gcs::GcsCloudModule`] — public access, encryption, uniform bucket-level access
//! - [`firewall::GcpFirewallCloudModule`] — open VPC firewall rules
//! - [`audit::GcpAuditCloudModule`] — admin activity + data access logging
//!
//! Uses `google-cloud-auth` for credential resolution
//! (`GOOGLE_APPLICATION_CREDENTIALS` / ADC / workload identity) and
//! `reqwest` for REST calls. Feature gate: `gcp-native`.

pub mod audit;
pub mod firewall;
pub mod gcs;
pub mod iam;

use crate::engine::cloud_credentials::CloudCredentials;
use crate::engine::cloud_module::CloudModule;
use crate::engine::cloud_target::CloudTarget;
use crate::engine::error::{Result, ScorchError};

// ---------------------------------------------------------------
// Intermediate types
// ---------------------------------------------------------------

/// A GCP service account key.
#[derive(Debug, Clone)]
pub struct GcpServiceAccountKey {
    /// Service account email.
    pub service_account: String,
    /// Key ID.
    pub key_id: String,
    /// Key type: `"USER_MANAGED"` or `"SYSTEM_MANAGED"`.
    pub key_type: String,
}

/// GCS bucket posture.
#[derive(Debug, Clone)]
pub struct GcsBucketPosture {
    /// Bucket name.
    pub name: String,
    /// Whether the bucket has public access prevention enabled.
    pub public_access_prevented: bool,
    /// Whether uniform bucket-level access (UBLA) is enabled.
    pub uniform_access: bool,
    /// Whether CMEK (customer-managed encryption key) is configured.
    pub cmek_configured: bool,
}

/// A GCP VPC firewall rule that allows open ingress.
#[derive(Debug, Clone)]
pub struct GcpFirewallRule {
    /// Firewall rule name.
    pub name: String,
    /// Network name.
    pub network: String,
    /// Destination port.
    pub port: u16,
    /// Protocol (`"tcp"`, `"udp"`, `"all"`).
    pub protocol: String,
    /// Source range (e.g. `"0.0.0.0/0"`).
    pub source_range: String,
    /// Whether this is a default rule.
    pub is_default: bool,
}

/// GCP audit logging configuration for a service.
#[derive(Debug, Clone)]
pub struct GcpAuditConfig {
    /// The service being audited (e.g. `"allServices"`).
    pub service: String,
    /// Whether admin read logging is enabled.
    pub admin_read_enabled: bool,
    /// Whether data read logging is enabled.
    pub data_read_enabled: bool,
    /// Whether data write logging is enabled.
    pub data_write_enabled: bool,
}

/// Sensitive ports that should never be open to `0.0.0.0/0` in GCP.
pub const SENSITIVE_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (3389, "RDP"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (1433, "MSSQL"),
    (27017, "MongoDB"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
];

// ---------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------

/// Resolve the GCP project ID from the target and credentials.
///
/// # Errors
///
/// Returns [`ScorchError::Config`] if no project ID can be determined.
pub fn resolve_project_id(
    target: &CloudTarget,
    creds: Option<&CloudCredentials>,
) -> Result<String> {
    match target {
        CloudTarget::Project(id) => Ok(id.clone()),
        CloudTarget::All => creds
            .and_then(|c| c.gcp_project_id.as_deref())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or_else(|| {
                ScorchError::Config(
                    "GCP native modules require gcp_project_id in [cloud] config or a \
                     gcp:<project-id> target"
                        .into(),
                )
            }),
        CloudTarget::Account(_) => Err(ScorchError::Config(
            "GCP native modules do not support AWS targets — use aws-iam/s3/sg/cloudtrail".into(),
        )),
        CloudTarget::Subscription(_) => Err(ScorchError::Config(
            "GCP native modules do not support Azure targets — use azure-native modules".into(),
        )),
        CloudTarget::KubeContext(_) => Err(ScorchError::Config(
            "GCP native modules do not support Kubernetes targets — use kubescape-cloud".into(),
        )),
    }
}

/// Build an authenticated reqwest client with a GCP access token.
///
/// Uses `google-cloud-auth` to resolve credentials from the standard
/// GCP chain (`GOOGLE_APPLICATION_CREDENTIALS` / ADC / workload identity).
/// If `CloudCredentials.gcp_service_account_path` is set, it is
/// exported as `GOOGLE_APPLICATION_CREDENTIALS` so the auth library
/// picks it up.
///
/// # Errors
///
/// Returns [`ScorchError::Config`] if authentication fails.
pub async fn build_gcp_client(
    creds: Option<&CloudCredentials>,
    scopes: &[&str],
) -> Result<(reqwest::Client, String)> {
    use google_cloud_auth::credentials::Builder;

    // If a service account path is configured, ensure the env var is set
    // so the auth library discovers it via ADC.
    if let Some(path) =
        creds.and_then(|c| c.gcp_service_account_path.as_deref()).filter(|s| !s.is_empty())
    {
        std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", path);
    }

    let at_creds = Builder::default()
        .with_scopes(scopes.iter().copied())
        .build_access_token_credentials()
        .map_err(|e| ScorchError::Config(format!("GCP auth build failed: {e}")))?;

    let token = at_creds
        .access_token()
        .await
        .map_err(|e| ScorchError::Config(format!("GCP token acquisition failed: {e}")))?;

    let client = reqwest::Client::new();
    Ok((client, token.token))
}

/// Returns all built-in GCP native cloud modules.
///
/// Order is lexicographic by module id: `gcp-audit`, `gcp-firewall`,
/// `gcp-gcs`, `gcp-iam`.
#[must_use]
pub fn register_gcp_modules() -> Vec<Box<dyn CloudModule>> {
    vec![
        Box::new(audit::GcpAuditCloudModule),
        Box::new(firewall::GcpFirewallCloudModule),
        Box::new(gcs::GcsCloudModule),
        Box::new(iam::GcpIamCloudModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the GCP registry shape: 4 modules in lex order.
    #[test]
    fn test_register_gcp_modules_count() {
        let modules = register_gcp_modules();
        assert_eq!(modules.len(), 4);
        assert_eq!(modules[0].id(), "gcp-audit");
        assert_eq!(modules[1].id(), "gcp-firewall");
        assert_eq!(modules[2].id(), "gcp-gcs");
        assert_eq!(modules[3].id(), "gcp-iam");
    }

    /// GCP targets accepted, non-GCP targets rejected.
    #[test]
    fn test_validate_gcp_target() {
        assert!(resolve_project_id(&CloudTarget::Project("my-proj".into()), None).is_ok());
        assert!(resolve_project_id(&CloudTarget::Account("123".into()), None).is_err());
        assert!(resolve_project_id(&CloudTarget::Subscription("s".into()), None).is_err());
        assert!(resolve_project_id(&CloudTarget::KubeContext("k".into()), None).is_err());

        // All target needs gcp_project_id in creds
        assert!(resolve_project_id(&CloudTarget::All, None).is_err());
        let creds =
            CloudCredentials { gcp_project_id: Some("my-project".into()), ..Default::default() };
        assert!(resolve_project_id(&CloudTarget::All, Some(&creds)).is_ok());
    }
}
