//! Azure Key Vault posture checks — purge protection, soft delete, network access.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{
    build_azure_client, resolve_subscription_id, AzureKeyVaultPosture, ARM_API_VERSION_KEYVAULT,
};

/// Built-in Azure Key Vault posture module.
#[derive(Debug)]
pub struct AzureKeyVaultCloudModule;

#[async_trait]
impl CloudModule for AzureKeyVaultCloudModule {
    fn name(&self) -> &'static str {
        "Azure Key Vault Posture"
    }
    fn id(&self) -> &'static str {
        "azure-keyvault"
    }
    fn category(&self) -> CloudCategory {
        CloudCategory::Compliance
    }
    fn description(&self) -> &'static str {
        "Built-in Azure Key Vault checks: purge protection, soft delete, network access"
    }
    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Azure]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let sub_id = resolve_subscription_id(&ctx.target, creds)?;
        let (client, token) = build_azure_client().await?;
        let target_label = ctx.target.display_raw();

        let vaults = match fetch_keyvault_postures(&client, &token, &sub_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("azure-keyvault: failed to list key vaults: {e}");
                return Ok(vec![]);
            }
        };

        let mut findings = Vec::new();
        for vault in &vaults {
            findings.extend(check_keyvault_posture(vault, &target_label));
        }
        Ok(findings)
    }
}

/// Fetch Key Vault postures.
async fn fetch_keyvault_postures(
    client: &reqwest::Client,
    token: &str,
    subscription_id: &str,
) -> std::result::Result<Vec<AzureKeyVaultPosture>, reqwest::Error> {
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/providers/\
         Microsoft.KeyVault/vaults?api-version={ARM_API_VERSION_KEYVAULT}"
    );
    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let items = resp["value"].as_array().cloned().unwrap_or_default();
    Ok(items
        .iter()
        .map(|item| {
            let props = &item["properties"];
            AzureKeyVaultPosture {
                name: item["name"].as_str().unwrap_or("unnamed").to_string(),
                purge_protection: props["enablePurgeProtection"].as_bool().unwrap_or(false),
                soft_delete: props["enableSoftDelete"].as_bool().unwrap_or(false),
                public_network_disabled: props["publicNetworkAccess"]
                    .as_str()
                    .is_some_and(|v| v == "Disabled"),
            }
        })
        .collect())
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Check a single Key Vault posture.
#[must_use]
pub fn check_keyvault_posture(vault: &AzureKeyVaultPosture, target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !vault.purge_protection {
        let evidence = CloudEvidence::new(CloudProvider::Azure, "kms")
            .with_check_id("azure-keyvault-no-purge-protection")
            .with_resource(&vault.name);
        let finding = Finding::new(
            "azure-keyvault",
            Severity::High,
            format!("Azure Key Vault: '{}' purge protection disabled", vault.name),
            format!("Key Vault '{}' does not have purge protection enabled. Deleted keys/secrets can be permanently purged.", vault.name),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable purge protection on this Key Vault to prevent permanent deletion.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "kms"));
    }

    if !vault.soft_delete {
        let evidence = CloudEvidence::new(CloudProvider::Azure, "kms")
            .with_check_id("azure-keyvault-no-soft-delete")
            .with_resource(&vault.name);
        let finding = Finding::new(
            "azure-keyvault",
            Severity::High,
            format!("Azure Key Vault: '{}' soft delete disabled", vault.name),
            format!("Key Vault '{}' does not have soft delete enabled. Deleted keys/secrets are immediately permanent.", vault.name),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable soft delete on this Key Vault.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "kms"));
    }

    if !vault.public_network_disabled {
        let evidence = CloudEvidence::new(CloudProvider::Azure, "kms")
            .with_check_id("azure-keyvault-public-network")
            .with_resource(&vault.name);
        let finding = Finding::new(
            "azure-keyvault",
            Severity::Medium,
            format!("Azure Key Vault: '{}' public network access enabled", vault.name),
            format!("Key Vault '{}' allows public network access. Use private endpoints to restrict access.", vault.name),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Disable public network access and configure private endpoints.")
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "kms"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_keyvault_no_purge_protection() {
        let vault = AzureKeyVaultPosture {
            name: "myvault".into(),
            purge_protection: false,
            soft_delete: true,
            public_network_disabled: true,
        };
        let findings = check_keyvault_posture(&vault, "azure:sub-123");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("purge protection"));
        assert!(findings[0].compliance.is_some());
    }

    #[test]
    fn test_azure_keyvault_secure() {
        let vault = AzureKeyVaultPosture {
            name: "secure-vault".into(),
            purge_protection: true,
            soft_delete: true,
            public_network_disabled: true,
        };
        assert!(check_keyvault_posture(&vault, "azure:sub-123").is_empty());
    }

    #[test]
    fn test_azure_keyvault_all_issues() {
        let vault = AzureKeyVaultPosture {
            name: "bad-vault".into(),
            purge_protection: false,
            soft_delete: false,
            public_network_disabled: false,
        };
        assert_eq!(check_keyvault_posture(&vault, "azure:sub-123").len(), 3);
    }

    #[test]
    fn test_azure_keyvault_metadata() {
        let m = AzureKeyVaultCloudModule;
        assert_eq!(m.id(), "azure-keyvault");
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(m.providers(), &[CloudProvider::Azure]);
    }
}
