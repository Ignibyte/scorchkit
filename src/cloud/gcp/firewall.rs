//! GCP VPC firewall posture checks — open ingress rules.
//!
//! Calls the Compute Engine REST API to enumerate firewall rules
//! and flags rules allowing `0.0.0.0/0` ingress on sensitive ports.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_gcp_client, resolve_project_id, GcpFirewallRule, SENSITIVE_PORTS};

/// Built-in GCP VPC firewall posture module.
#[derive(Debug)]
pub struct GcpFirewallCloudModule;

#[async_trait]
impl CloudModule for GcpFirewallCloudModule {
    fn name(&self) -> &'static str {
        "GCP VPC Firewall Posture"
    }

    fn id(&self) -> &'static str {
        "gcp-firewall"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Network
    }

    fn description(&self) -> &'static str {
        "Built-in GCP firewall checks: open ingress on sensitive ports"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Gcp]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let project = resolve_project_id(&ctx.target, creds)?;
        let (client, token) =
            build_gcp_client(creds, &["https://www.googleapis.com/auth/compute.readonly"]).await?;
        let target_label = ctx.target.display_raw();

        let rules = match fetch_open_firewall_rules(&client, &token, &project).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("gcp-firewall: failed to list firewall rules: {e}");
                return Ok(vec![]);
            }
        };

        Ok(check_firewall_rules(&rules, &target_label))
    }
}

/// Fetch firewall rules that allow open ingress on sensitive ports.
async fn fetch_open_firewall_rules(
    client: &reqwest::Client,
    token: &str,
    project: &str,
) -> std::result::Result<Vec<GcpFirewallRule>, reqwest::Error> {
    let url =
        format!("https://compute.googleapis.com/compute/v1/projects/{project}/global/firewalls");
    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let mut rules = Vec::new();
    let items = resp["items"].as_array().cloned().unwrap_or_default();

    for item in &items {
        // Only check INGRESS rules
        if item["direction"].as_str().unwrap_or("") != "INGRESS" {
            continue;
        }

        let name = item["name"].as_str().unwrap_or("unknown").to_string();
        let network = item["network"]
            .as_str()
            .and_then(|n| n.rsplit('/').next())
            .unwrap_or("unknown")
            .to_string();
        let is_default = name.starts_with("default-");

        // Check source ranges for 0.0.0.0/0
        let source_ranges = item["sourceRanges"].as_array().cloned().unwrap_or_default();
        let has_open_source = source_ranges.iter().any(|r| r.as_str() == Some("0.0.0.0/0"));

        if !has_open_source {
            continue;
        }

        // Check allowed ports
        let allowed = item["allowed"].as_array().cloned().unwrap_or_default();
        for allow_entry in &allowed {
            let protocol = allow_entry["IPProtocol"].as_str().unwrap_or("").to_string();
            let ports = allow_entry["ports"].as_array().cloned().unwrap_or_default();

            if ports.is_empty() && (protocol == "tcp" || protocol == "udp" || protocol == "all") {
                // All ports open for this protocol
                for &(port, _) in SENSITIVE_PORTS {
                    rules.push(GcpFirewallRule {
                        name: name.clone(),
                        network: network.clone(),
                        port,
                        protocol: protocol.clone(),
                        source_range: "0.0.0.0/0".into(),
                        is_default,
                    });
                }
            } else {
                for port_spec in &ports {
                    let port_str = port_spec.as_str().unwrap_or("");
                    // Handle port ranges ("22", "8080-8443")
                    if let Some((start_s, end_s)) = port_str.split_once('-') {
                        let start: u16 = start_s.parse().unwrap_or(0);
                        let end: u16 = end_s.parse().unwrap_or(0);
                        for &(port, _) in SENSITIVE_PORTS {
                            if port >= start && port <= end {
                                rules.push(GcpFirewallRule {
                                    name: name.clone(),
                                    network: network.clone(),
                                    port,
                                    protocol: protocol.clone(),
                                    source_range: "0.0.0.0/0".into(),
                                    is_default,
                                });
                            }
                        }
                    } else if let Ok(single) = port_str.parse::<u16>() {
                        if SENSITIVE_PORTS.iter().any(|(p, _)| *p == single) {
                            rules.push(GcpFirewallRule {
                                name: name.clone(),
                                network: network.clone(),
                                port: single,
                                protocol: protocol.clone(),
                                source_range: "0.0.0.0/0".into(),
                                is_default,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(rules)
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Produce findings from open firewall rules.
#[must_use]
pub fn check_firewall_rules(rules: &[GcpFirewallRule], target_label: &str) -> Vec<Finding> {
    rules
        .iter()
        .map(|rule| {
            let port_label = SENSITIVE_PORTS
                .iter()
                .find(|(p, _)| *p == rule.port)
                .map_or_else(|| format!("port {}", rule.port), |(_, name)| (*name).to_string());

            let evidence = CloudEvidence::new(CloudProvider::Gcp, "firewall")
                .with_check_id("gcp-firewall-open-ingress")
                .with_resource(&rule.name)
                .with_detail("port", rule.port.to_string())
                .with_detail("network", &rule.network)
                .with_detail("source", &rule.source_range);

            let severity = if rule.is_default { Severity::High } else { Severity::Critical };

            let finding = Finding::new(
                "gcp-firewall",
                severity,
                format!(
                    "GCP Firewall: {} ({}) open to {} in rule '{}'",
                    port_label, rule.port, rule.source_range, rule.name
                ),
                format!(
                    "Firewall rule '{}' on network '{}' allows {} ingress on port {} ({}) \
                     from {}",
                    rule.name,
                    rule.network,
                    rule.protocol,
                    rule.port,
                    port_label,
                    rule.source_range,
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation("Restrict the firewall rule source ranges to specific IP ranges.")
            .with_confidence(0.95);
            enrich_cloud_finding(finding, "firewall")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Open SSH → Critical finding.
    #[test]
    fn test_firewall_open_ssh() {
        let rules = vec![GcpFirewallRule {
            name: "allow-all-ssh".into(),
            network: "default".into(),
            port: 22,
            protocol: "tcp".into(),
            source_range: "0.0.0.0/0".into(),
            is_default: false,
        }];
        let findings = check_firewall_rules(&rules, "gcp:my-project");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("SSH"));
        assert!(findings[0].compliance.is_some());
    }

    /// Default rule → High (not Critical) since defaults are expected.
    #[test]
    fn test_firewall_default_rule_severity() {
        let rules = vec![GcpFirewallRule {
            name: "default-allow-ssh".into(),
            network: "default".into(),
            port: 22,
            protocol: "tcp".into(),
            source_range: "0.0.0.0/0".into(),
            is_default: true,
        }];
        let findings = check_firewall_rules(&rules, "gcp:my-project");
        assert_eq!(findings[0].severity, Severity::High);
    }

    /// Restricted rules → zero findings.
    #[test]
    fn test_firewall_clean() {
        let findings = check_firewall_rules(&[], "gcp:my-project");
        assert!(findings.is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_firewall_module_metadata() {
        let m = GcpFirewallCloudModule;
        assert_eq!(m.id(), "gcp-firewall");
        assert_eq!(m.category(), CloudCategory::Network);
        assert_eq!(m.providers(), &[CloudProvider::Gcp]);
    }
}
