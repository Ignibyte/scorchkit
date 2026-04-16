//! Native Azure posture checks via `azure_identity` + REST (WORK-128).
//!
//! Four built-in cloud modules that call Azure ARM REST APIs:
//!
//! - [`rbac::AzureRbacCloudModule`] — subscription-level Owner sprawl
//! - [`storage::AzureStorageCloudModule`] — public access, encryption, soft delete
//! - [`nsg::AzureNsgCloudModule`] — open NSG ingress on management ports
//! - [`keyvault::AzureKeyVaultCloudModule`] — purge protection, soft delete, network access
//!
//! Uses `azure_identity` (`DefaultAzureCredential`) for credential
//! resolution (environment, managed identity, `az` CLI) and `reqwest`
//! for REST calls. Feature gate: `azure-native`.

pub mod keyvault;
pub mod nsg;
pub mod rbac;
pub mod storage;

use azure_core::credentials::TokenCredential;
use azure_identity::DefaultAzureCredential;

use crate::engine::cloud_credentials::CloudCredentials;
use crate::engine::cloud_module::CloudModule;
use crate::engine::cloud_target::CloudTarget;
use crate::engine::error::{Result, ScorchError};

/// Azure ARM API version for common resource queries.
pub const ARM_API_VERSION_AUTHZ: &str = "2022-04-01";
/// ARM API version for storage accounts.
pub const ARM_API_VERSION_STORAGE: &str = "2023-05-01";
/// ARM API version for network security groups.
pub const ARM_API_VERSION_NETWORK: &str = "2024-01-01";
/// ARM API version for Key Vault.
pub const ARM_API_VERSION_KEYVAULT: &str = "2023-07-01";

// ---------------------------------------------------------------
// Intermediate types
// ---------------------------------------------------------------

/// An Azure RBAC role assignment at subscription scope.
#[derive(Debug, Clone)]
pub struct AzureRoleAssignment {
    /// Principal display name or ID.
    pub principal_id: String,
    /// Role definition name (e.g. `"Owner"`).
    pub role_name: String,
    /// Scope of the assignment.
    pub scope: String,
}

/// Azure storage account posture.
#[derive(Debug, Clone)]
pub struct AzureStoragePosture {
    /// Storage account name.
    pub name: String,
    /// Whether public blob access is disabled.
    pub public_access_disabled: bool,
    /// Whether infrastructure encryption (double encryption) is enabled.
    pub infrastructure_encryption: bool,
    /// Whether blob soft delete is enabled.
    pub soft_delete_enabled: bool,
}

/// An Azure NSG rule allowing open ingress.
#[derive(Debug, Clone)]
pub struct AzureNsgRule {
    /// NSG name.
    pub nsg_name: String,
    /// Rule name.
    pub rule_name: String,
    /// Destination port.
    pub port: String,
    /// Source address prefix (e.g. `"*"` or `"0.0.0.0/0"`).
    pub source: String,
}

/// Azure Key Vault posture.
#[derive(Debug, Clone)]
pub struct AzureKeyVaultPosture {
    /// Vault name.
    pub name: String,
    /// Whether purge protection is enabled.
    pub purge_protection: bool,
    /// Whether soft delete is enabled.
    pub soft_delete: bool,
    /// Whether public network access is disabled.
    pub public_network_disabled: bool,
}

/// Management ports that should not be exposed via NSGs.
pub const MGMT_PORTS: &[(&str, &str)] =
    &[("22", "SSH"), ("3389", "RDP"), ("5985", "WinRM-HTTP"), ("5986", "WinRM-HTTPS")];

// ---------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------

/// Resolve the Azure subscription ID from the target and credentials.
///
/// # Errors
///
/// Returns [`ScorchError::Config`] if no subscription ID can be determined.
pub fn resolve_subscription_id(
    target: &CloudTarget,
    creds: Option<&CloudCredentials>,
) -> Result<String> {
    match target {
        CloudTarget::Subscription(id) => Ok(id.clone()),
        CloudTarget::All => creds
            .and_then(|c| c.azure_subscription_id.as_deref())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or_else(|| {
                ScorchError::Config(
                    "Azure native modules require azure_subscription_id in [cloud] config \
                     or an azure:<subscription-id> target"
                        .into(),
                )
            }),
        CloudTarget::Account(_) => Err(ScorchError::Config(
            "Azure native modules do not support AWS targets — use aws-native modules".into(),
        )),
        CloudTarget::Project(_) => Err(ScorchError::Config(
            "Azure native modules do not support GCP targets — use gcp-native modules".into(),
        )),
        CloudTarget::KubeContext(_) => Err(ScorchError::Config(
            "Azure native modules do not support Kubernetes targets — use kubescape-cloud".into(),
        )),
    }
}

/// Build an authenticated reqwest client with an Azure bearer token.
///
/// Uses `DefaultAzureCredential` which tries environment, managed
/// identity, and `az` CLI in sequence.
///
/// # Errors
///
/// Returns [`ScorchError::Config`] if authentication fails.
pub async fn build_azure_client() -> Result<(reqwest::Client, String)> {
    let credential = DefaultAzureCredential::new()
        .map_err(|e| ScorchError::Config(format!("Azure auth failed: {e}")))?;

    let token = credential
        .get_token(&["https://management.azure.com/.default"])
        .await
        .map_err(|e| ScorchError::Config(format!("Azure token acquisition failed: {e}")))?;

    let client = reqwest::Client::new();
    Ok((client, token.token.secret().to_string()))
}

/// Returns all built-in Azure native cloud modules.
///
/// Order is lexicographic by module id: `azure-keyvault`,
/// `azure-nsg`, `azure-rbac`, `azure-storage`.
#[must_use]
pub fn register_azure_modules() -> Vec<Box<dyn CloudModule>> {
    vec![
        Box::new(keyvault::AzureKeyVaultCloudModule),
        Box::new(nsg::AzureNsgCloudModule),
        Box::new(rbac::AzureRbacCloudModule),
        Box::new(storage::AzureStorageCloudModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the Azure registry shape: 4 modules in lex order.
    #[test]
    fn test_register_azure_modules_count() {
        let modules = register_azure_modules();
        assert_eq!(modules.len(), 4);
        assert_eq!(modules[0].id(), "azure-keyvault");
        assert_eq!(modules[1].id(), "azure-nsg");
        assert_eq!(modules[2].id(), "azure-rbac");
        assert_eq!(modules[3].id(), "azure-storage");
    }

    /// Azure targets accepted, non-Azure targets rejected.
    #[test]
    fn test_validate_azure_target() {
        assert!(
            resolve_subscription_id(&CloudTarget::Subscription("sub-1234".into()), None).is_ok()
        );
        assert!(resolve_subscription_id(&CloudTarget::Account("123".into()), None).is_err());
        assert!(resolve_subscription_id(&CloudTarget::Project("p".into()), None).is_err());
        assert!(resolve_subscription_id(&CloudTarget::KubeContext("k".into()), None).is_err());

        // All target needs subscription_id in creds
        assert!(resolve_subscription_id(&CloudTarget::All, None).is_err());
        let creds = CloudCredentials {
            azure_subscription_id: Some("sub-abc".into()),
            ..Default::default()
        };
        assert!(resolve_subscription_id(&CloudTarget::All, Some(&creds)).is_ok());
    }
}
