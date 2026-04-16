//! GCP IAM posture checks — user-managed service account keys.
//!
//! Calls the IAM Admin REST API to enumerate service account keys
//! and flags user-managed keys as a security risk.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_gcp_client, resolve_project_id, GcpServiceAccountKey};

/// Built-in GCP IAM posture module.
#[derive(Debug)]
pub struct GcpIamCloudModule;

#[async_trait]
impl CloudModule for GcpIamCloudModule {
    fn name(&self) -> &'static str {
        "GCP IAM Posture"
    }

    fn id(&self) -> &'static str {
        "gcp-iam"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Iam
    }

    fn description(&self) -> &'static str {
        "Built-in GCP IAM checks: user-managed service account keys"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Gcp]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let project = resolve_project_id(&ctx.target, creds)?;
        let (client, token) =
            build_gcp_client(creds, &["https://www.googleapis.com/auth/cloud-platform"]).await?;
        let target_label = ctx.target.display_raw();

        let keys = match fetch_service_account_keys(&client, &token, &project).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("gcp-iam: failed to list service account keys: {e}");
                return Ok(vec![]);
            }
        };

        Ok(check_service_account_keys(&keys, &target_label))
    }
}

/// Fetch user-managed service account keys for all service accounts.
async fn fetch_service_account_keys(
    client: &reqwest::Client,
    token: &str,
    project: &str,
) -> std::result::Result<Vec<GcpServiceAccountKey>, reqwest::Error> {
    // List service accounts
    let url = format!("https://iam.googleapis.com/v1/projects/{project}/serviceAccounts");
    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let mut keys = Vec::new();
    let accounts = resp["accounts"].as_array().cloned().unwrap_or_default();

    for account in &accounts {
        let email = account["email"].as_str().unwrap_or("unknown");
        let keys_url = format!(
            "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{email}/keys"
        );
        let keys_resp: serde_json::Value =
            client.get(&keys_url).bearer_auth(token).send().await?.json().await?;

        for key in keys_resp["keys"].as_array().cloned().unwrap_or_default() {
            let key_type = key["keyType"].as_str().unwrap_or("").to_string();
            if key_type == "USER_MANAGED" {
                let key_id = key["name"]
                    .as_str()
                    .and_then(|n| n.rsplit('/').next())
                    .unwrap_or("unknown")
                    .to_string();
                keys.push(GcpServiceAccountKey {
                    service_account: email.to_string(),
                    key_id,
                    key_type,
                });
            }
        }
    }

    Ok(keys)
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Check for user-managed service account keys.
#[must_use]
pub fn check_service_account_keys(
    keys: &[GcpServiceAccountKey],
    target_label: &str,
) -> Vec<Finding> {
    keys.iter()
        .map(|key| {
            let evidence = CloudEvidence::new(CloudProvider::Gcp, "iam")
                .with_check_id("gcp-iam-user-managed-key")
                .with_resource(&key.service_account)
                .with_detail("key_id", &key.key_id);

            let finding = Finding::new(
                "gcp-iam",
                Severity::High,
                format!("GCP IAM: User-managed key on {}", key.service_account),
                format!(
                    "Service account '{}' has user-managed key '{}'. User-managed keys \
                     are long-lived credentials that should be replaced with workload \
                     identity or short-lived tokens.",
                    key.service_account, key.key_id
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation(
                "Delete user-managed keys and use workload identity federation or \
                 impersonation instead.",
            )
            .with_confidence(0.9);
            enrich_cloud_finding(finding, "iam")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// User-managed keys produce High findings.
    #[test]
    fn test_gcp_iam_user_managed_keys() {
        let keys = vec![GcpServiceAccountKey {
            service_account: "test@proj.iam.gserviceaccount.com".into(),
            key_id: "abc123".into(),
            key_type: "USER_MANAGED".into(),
        }];
        let findings = check_service_account_keys(&keys, "gcp:my-project");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("User-managed key"));
        assert!(findings[0].compliance.is_some());
    }

    /// No user-managed keys → zero findings.
    #[test]
    fn test_gcp_iam_clean() {
        let findings = check_service_account_keys(&[], "gcp:my-project");
        assert!(findings.is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_gcp_iam_module_metadata() {
        let m = GcpIamCloudModule;
        assert_eq!(m.id(), "gcp-iam");
        assert_eq!(m.category(), CloudCategory::Iam);
        assert_eq!(m.providers(), &[CloudProvider::Gcp]);
    }
}
