//! Azure Storage Account posture checks — public access, encryption, soft delete.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{
    build_azure_client, resolve_subscription_id, AzureStoragePosture, ARM_API_VERSION_STORAGE,
};

/// Built-in Azure Storage posture module.
#[derive(Debug)]
pub struct AzureStorageCloudModule;

#[async_trait]
impl CloudModule for AzureStorageCloudModule {
    fn name(&self) -> &'static str {
        "Azure Storage Posture"
    }
    fn id(&self) -> &'static str {
        "azure-storage"
    }
    fn category(&self) -> CloudCategory {
        CloudCategory::Storage
    }
    fn description(&self) -> &'static str {
        "Built-in Azure storage checks: public access, encryption, soft delete"
    }
    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Azure]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let sub_id = resolve_subscription_id(&ctx.target, creds)?;
        let (client, token) = build_azure_client().await?;
        let target_label = ctx.target.display_raw();

        let accounts = match fetch_storage_postures(&client, &token, &sub_id).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("azure-storage: failed to list storage accounts: {e}");
                return Ok(vec![]);
            }
        };

        let mut findings = Vec::new();
        for acct in &accounts {
            findings.extend(check_storage_posture(acct, &target_label));
        }
        Ok(findings)
    }
}

/// Fetch storage account postures.
async fn fetch_storage_postures(
    client: &reqwest::Client,
    token: &str,
    subscription_id: &str,
) -> std::result::Result<Vec<AzureStoragePosture>, reqwest::Error> {
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/providers/\
         Microsoft.Storage/storageAccounts?api-version={ARM_API_VERSION_STORAGE}"
    );
    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let items = resp["value"].as_array().cloned().unwrap_or_default();
    Ok(items
        .iter()
        .map(|item| {
            let props = &item["properties"];
            AzureStoragePosture {
                name: item["name"].as_str().unwrap_or("unnamed").to_string(),
                public_access_disabled: !props["allowBlobPublicAccess"].as_bool().unwrap_or(true),
                infrastructure_encryption: props["encryption"]["requireInfrastructureEncryption"]
                    .as_bool()
                    .unwrap_or(false),
                soft_delete_enabled: props["deleteRetentionPolicy"]["enabled"]
                    .as_bool()
                    .unwrap_or(false),
            }
        })
        .collect())
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Check a single storage account posture.
#[must_use]
pub fn check_storage_posture(acct: &AzureStoragePosture, target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !acct.public_access_disabled {
        let evidence = CloudEvidence::new(CloudProvider::Azure, "storage")
            .with_check_id("azure-storage-public-access")
            .with_resource(&acct.name);
        let finding = Finding::new(
            "azure-storage",
            Severity::Critical,
            format!("Azure Storage: '{}' allows public blob access", acct.name),
            format!("Storage account '{}' has public blob access enabled. Data may be publicly accessible.", acct.name),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Disable 'Allow Blob public access' on this storage account.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "storage"));
    }

    if !acct.infrastructure_encryption {
        let evidence = CloudEvidence::new(CloudProvider::Azure, "storage")
            .with_check_id("azure-storage-no-infra-encryption")
            .with_resource(&acct.name);
        let finding = Finding::new(
            "azure-storage",
            Severity::Medium,
            format!("Azure Storage: '{}' no infrastructure encryption", acct.name),
            format!(
                "Storage account '{}' does not have infrastructure (double) encryption enabled.",
                acct.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable infrastructure encryption for double encryption at rest.")
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "storage"));
    }

    if !acct.soft_delete_enabled {
        let evidence = CloudEvidence::new(CloudProvider::Azure, "storage")
            .with_check_id("azure-storage-no-soft-delete")
            .with_resource(&acct.name);
        let finding = Finding::new(
            "azure-storage",
            Severity::Medium,
            format!("Azure Storage: '{}' soft delete disabled", acct.name),
            format!("Storage account '{}' does not have blob soft delete enabled. Deleted data cannot be recovered.", acct.name),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable blob soft delete with an appropriate retention period.")
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "storage"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_storage_public_access() {
        let acct = AzureStoragePosture {
            name: "publicstore".into(),
            public_access_disabled: false,
            infrastructure_encryption: true,
            soft_delete_enabled: true,
        };
        let findings = check_storage_posture(&acct, "azure:sub-123");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_azure_storage_secure() {
        let acct = AzureStoragePosture {
            name: "secure".into(),
            public_access_disabled: true,
            infrastructure_encryption: true,
            soft_delete_enabled: true,
        };
        assert!(check_storage_posture(&acct, "azure:sub-123").is_empty());
    }

    #[test]
    fn test_azure_storage_metadata() {
        let m = AzureStorageCloudModule;
        assert_eq!(m.id(), "azure-storage");
        assert_eq!(m.category(), CloudCategory::Storage);
        assert_eq!(m.providers(), &[CloudProvider::Azure]);
    }
}
