//! Azure RBAC posture checks — subscription-level Owner sprawl.
//!
//! Calls the Azure Authorization REST API to enumerate role assignments
//! and flags excessive Owner-role assignments at subscription scope.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{
    build_azure_client, resolve_subscription_id, AzureRoleAssignment, ARM_API_VERSION_AUTHZ,
};

/// Built-in Azure RBAC posture module.
#[derive(Debug)]
pub struct AzureRbacCloudModule;

#[async_trait]
impl CloudModule for AzureRbacCloudModule {
    fn name(&self) -> &'static str {
        "Azure RBAC Posture"
    }

    fn id(&self) -> &'static str {
        "azure-rbac"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Iam
    }

    fn description(&self) -> &'static str {
        "Built-in Azure RBAC checks: subscription-level Owner sprawl"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Azure]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let sub_id = resolve_subscription_id(&ctx.target, creds)?;
        let (client, token) = build_azure_client().await?;
        let target_label = ctx.target.display_raw();

        let assignments = match fetch_owner_assignments(&client, &token, &sub_id).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("azure-rbac: failed to list role assignments: {e}");
                return Ok(vec![]);
            }
        };

        Ok(check_owner_assignments(&assignments, &target_label))
    }
}

/// Fetch subscription-level Owner role assignments.
async fn fetch_owner_assignments(
    client: &reqwest::Client,
    token: &str,
    subscription_id: &str,
) -> std::result::Result<Vec<AzureRoleAssignment>, reqwest::Error> {
    // Owner role definition ID is well-known across all Azure tenants
    let owner_role_def = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/providers/\
         Microsoft.Authorization/roleAssignments?api-version={ARM_API_VERSION_AUTHZ}\
         &$filter=atScope()"
    );

    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let items = resp["value"].as_array().cloned().unwrap_or_default();
    Ok(items
        .iter()
        .filter(|item| {
            item["properties"]["roleDefinitionId"]
                .as_str()
                .is_some_and(|id| id.contains(owner_role_def))
        })
        .map(|item| AzureRoleAssignment {
            principal_id: item["properties"]["principalId"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            role_name: "Owner".to_string(),
            scope: item["properties"]["scope"].as_str().unwrap_or("unknown").to_string(),
        })
        .collect())
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Check for excessive Owner assignments. More than 3 is flagged.
#[must_use]
pub fn check_owner_assignments(
    assignments: &[AzureRoleAssignment],
    target_label: &str,
) -> Vec<Finding> {
    if assignments.len() <= 3 {
        return Vec::new();
    }

    let evidence = CloudEvidence::new(CloudProvider::Azure, "iam")
        .with_check_id("azure-rbac-owner-sprawl")
        .with_detail("owner_count", assignments.len().to_string());

    let finding = Finding::new(
        "azure-rbac",
        Severity::High,
        format!("Azure RBAC: {} Owner assignments at subscription scope", assignments.len()),
        format!(
            "The subscription has {} principals with Owner role. \
             Excessive Owner assignments increase the blast radius of account compromise. \
             CIS recommends no more than 3.",
            assignments.len()
        ),
        format!("cloud://{target_label}"),
    )
    .with_evidence(evidence.to_string())
    .with_remediation(
        "Review Owner role assignments and downgrade to Contributor or custom roles \
         where full control is not required.",
    )
    .with_confidence(0.85);
    vec![enrich_cloud_finding(finding, "iam")]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Excessive Owners → High finding.
    #[test]
    fn test_rbac_owner_sprawl() {
        let assignments: Vec<_> = (0..5)
            .map(|i| AzureRoleAssignment {
                principal_id: format!("principal-{i}"),
                role_name: "Owner".into(),
                scope: "/subscriptions/sub-123".into(),
            })
            .collect();
        let findings = check_owner_assignments(&assignments, "azure:sub-123");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("5 Owner"));
        assert!(findings[0].compliance.is_some());
    }

    /// 3 or fewer Owners → zero findings.
    #[test]
    fn test_rbac_clean() {
        let assignments: Vec<_> = (0..3)
            .map(|i| AzureRoleAssignment {
                principal_id: format!("principal-{i}"),
                role_name: "Owner".into(),
                scope: "/subscriptions/sub-123".into(),
            })
            .collect();
        let findings = check_owner_assignments(&assignments, "azure:sub-123");
        assert!(findings.is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_rbac_module_metadata() {
        let m = AzureRbacCloudModule;
        assert_eq!(m.id(), "azure-rbac");
        assert_eq!(m.category(), CloudCategory::Iam);
        assert_eq!(m.providers(), &[CloudProvider::Azure]);
    }
}
