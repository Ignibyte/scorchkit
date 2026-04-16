//! Azure NSG posture checks — open management ports.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{
    build_azure_client, resolve_subscription_id, AzureNsgRule, ARM_API_VERSION_NETWORK, MGMT_PORTS,
};

/// Built-in Azure NSG posture module.
#[derive(Debug)]
pub struct AzureNsgCloudModule;

#[async_trait]
impl CloudModule for AzureNsgCloudModule {
    fn name(&self) -> &'static str {
        "Azure NSG Posture"
    }
    fn id(&self) -> &'static str {
        "azure-nsg"
    }
    fn category(&self) -> CloudCategory {
        CloudCategory::Network
    }
    fn description(&self) -> &'static str {
        "Built-in Azure NSG checks: open management ports"
    }
    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Azure]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let sub_id = resolve_subscription_id(&ctx.target, creds)?;
        let (client, token) = build_azure_client().await?;
        let target_label = ctx.target.display_raw();

        let rules = match fetch_open_nsg_rules(&client, &token, &sub_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("azure-nsg: failed to list NSGs: {e}");
                return Ok(vec![]);
            }
        };

        Ok(check_nsg_rules(&rules, &target_label))
    }
}

/// Fetch NSG rules that allow open ingress on management ports.
async fn fetch_open_nsg_rules(
    client: &reqwest::Client,
    token: &str,
    subscription_id: &str,
) -> std::result::Result<Vec<AzureNsgRule>, reqwest::Error> {
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/providers/\
         Microsoft.Network/networkSecurityGroups?api-version={ARM_API_VERSION_NETWORK}"
    );
    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let mut rules = Vec::new();
    let nsgs = resp["value"].as_array().cloned().unwrap_or_default();

    for nsg in &nsgs {
        let nsg_name = nsg["name"].as_str().unwrap_or("unknown");
        let sec_rules = nsg["properties"]["securityRules"].as_array().cloned().unwrap_or_default();

        for rule in &sec_rules {
            let props = &rule["properties"];
            // Only inbound Allow rules
            if props["direction"].as_str() != Some("Inbound")
                || props["access"].as_str() != Some("Allow")
            {
                continue;
            }

            let source = props["sourceAddressPrefix"].as_str().unwrap_or("");
            if source != "*" && source != "0.0.0.0/0" && source != "Internet" {
                continue;
            }

            let dest_port = props["destinationPortRange"].as_str().unwrap_or("");
            let rule_name = rule["name"].as_str().unwrap_or("unknown");

            for &(port, _) in MGMT_PORTS {
                if dest_port == port || dest_port == "*" {
                    rules.push(AzureNsgRule {
                        nsg_name: nsg_name.to_string(),
                        rule_name: rule_name.to_string(),
                        port: port.to_string(),
                        source: source.to_string(),
                    });
                }
            }
        }
    }

    Ok(rules)
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Produce findings from open NSG rules.
#[must_use]
pub fn check_nsg_rules(rules: &[AzureNsgRule], target_label: &str) -> Vec<Finding> {
    rules
        .iter()
        .map(|rule| {
            let port_label = MGMT_PORTS
                .iter()
                .find(|(p, _)| *p == rule.port)
                .map_or_else(|| format!("port {}", rule.port), |(_, name)| (*name).to_string());

            let evidence = CloudEvidence::new(CloudProvider::Azure, "network")
                .with_check_id("azure-nsg-open-mgmt")
                .with_resource(&rule.nsg_name)
                .with_detail("port", &rule.port)
                .with_detail("source", &rule.source)
                .with_detail("rule", &rule.rule_name);

            let finding = Finding::new(
                "azure-nsg",
                Severity::Critical,
                format!(
                    "Azure NSG: {} ({}) open to {} in NSG '{}'",
                    port_label, rule.port, rule.source, rule.nsg_name
                ),
                format!(
                    "NSG '{}' rule '{}' allows inbound {} ({}) from {}",
                    rule.nsg_name, rule.rule_name, port_label, rule.port, rule.source,
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation(
                "Restrict NSG source to specific IP ranges or use Just-in-Time VM access.",
            )
            .with_confidence(0.95);
            enrich_cloud_finding(finding, "network")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_nsg_open_ssh() {
        let rules = vec![AzureNsgRule {
            nsg_name: "web-nsg".into(),
            rule_name: "AllowSSH".into(),
            port: "22".into(),
            source: "*".into(),
        }];
        let findings = check_nsg_rules(&rules, "azure:sub-123");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("SSH"));
        assert!(findings[0].compliance.is_some());
    }

    #[test]
    fn test_azure_nsg_clean() {
        assert!(check_nsg_rules(&[], "azure:sub-123").is_empty());
    }

    #[test]
    fn test_azure_nsg_metadata() {
        let m = AzureNsgCloudModule;
        assert_eq!(m.id(), "azure-nsg");
        assert_eq!(m.category(), CloudCategory::Network);
        assert_eq!(m.providers(), &[CloudProvider::Azure]);
    }
}
