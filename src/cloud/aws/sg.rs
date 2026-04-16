//! AWS Security Group posture checks — open ingress on sensitive ports.
//!
//! Uses `aws-sdk-ec2` to enumerate security groups and flag rules
//! that allow `0.0.0.0/0` or `::/0` ingress on commonly exploited ports.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_aws_sdk_config, SecurityGroupRule, SENSITIVE_PORTS};

/// Built-in AWS security group posture module.
///
/// Flags security groups that allow unrestricted ingress
/// (`0.0.0.0/0` or `::/0`) on sensitive ports like SSH, RDP,
/// database ports, and management interfaces.
#[derive(Debug)]
pub struct SecurityGroupCloudModule;

#[async_trait]
impl CloudModule for SecurityGroupCloudModule {
    fn name(&self) -> &'static str {
        "AWS Security Group Posture"
    }

    fn id(&self) -> &'static str {
        "aws-sg"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Network
    }

    fn description(&self) -> &'static str {
        "Built-in AWS security group checks: open ingress on sensitive ports"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Aws]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let sdk_config = build_aws_sdk_config(&ctx.target, ctx.credentials.as_deref()).await?;
        let client = aws_sdk_ec2::Client::new(&sdk_config);
        let target_label = ctx.target.display_raw();

        let open_rules = match fetch_open_rules(&client).await {
            Ok(rules) => rules,
            Err(e) => {
                tracing::warn!("aws-sg: failed to describe security groups: {e}");
                return Ok(vec![permission_finding(&target_label)]);
            }
        };

        Ok(check_open_rules(&open_rules, &target_label))
    }
}

/// Fetch security group rules that have open CIDRs on sensitive ports.
async fn fetch_open_rules(
    client: &aws_sdk_ec2::Client,
) -> std::result::Result<Vec<SecurityGroupRule>, aws_sdk_ec2::Error> {
    let resp = client.describe_security_groups().send().await?;
    let mut rules = Vec::new();

    for sg in resp.security_groups() {
        let group_id = sg.group_id().unwrap_or("unknown");
        let group_name = sg.group_name().unwrap_or("unknown");

        for perm in sg.ip_permissions() {
            let from_port = perm.from_port().unwrap_or(-1);
            let to_port = perm.to_port().unwrap_or(-1);
            let protocol = perm.ip_protocol().unwrap_or("-1");

            // Collect open CIDRs (IPv4 + IPv6)
            let mut open_cidrs = Vec::new();
            for range in perm.ip_ranges() {
                if let Some(cidr) = range.cidr_ip() {
                    if cidr == "0.0.0.0/0" {
                        open_cidrs.push(cidr.to_string());
                    }
                }
            }
            for range in perm.ipv6_ranges() {
                if let Some(cidr) = range.cidr_ipv6() {
                    if cidr == "::/0" {
                        open_cidrs.push(cidr.to_string());
                    }
                }
            }

            if open_cidrs.is_empty() {
                continue;
            }

            // Check if any sensitive port falls in the from_port..=to_port range
            // Protocol "-1" means all traffic (all ports)
            let all_traffic = protocol == "-1";
            for &(port, _) in SENSITIVE_PORTS {
                let port_i32 = i32::from(port);
                let in_range = all_traffic || (from_port <= port_i32 && port_i32 <= to_port);
                if in_range {
                    for cidr in &open_cidrs {
                        rules.push(SecurityGroupRule {
                            group_id: group_id.to_string(),
                            group_name: group_name.to_string(),
                            port,
                            protocol: protocol.to_string(),
                            source_cidr: cidr.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok(rules)
}

/// Generate an Info-level "insufficient permissions" finding.
fn permission_finding(target_label: &str) -> Finding {
    let finding = Finding::new(
        "aws-sg",
        Severity::Info,
        "AWS SG: Insufficient permissions for DescribeSecurityGroups",
        "The credentials lack ec2:DescribeSecurityGroups permission.",
        format!("cloud://{target_label}"),
    )
    .with_evidence(
        CloudEvidence::new(CloudProvider::Aws, "vpc")
            .with_check_id("sg-permission-describesecuritygroups")
            .to_string(),
    )
    .with_confidence(0.5);
    enrich_cloud_finding(finding, "vpc")
}

// ---------------------------------------------------------------
// Pure check functions — testable without AWS SDK
// ---------------------------------------------------------------

/// Produce findings from open security group rules.
#[must_use]
pub fn check_open_rules(rules: &[SecurityGroupRule], target_label: &str) -> Vec<Finding> {
    rules
        .iter()
        .map(|rule| {
            let port_label = SENSITIVE_PORTS
                .iter()
                .find(|(p, _)| *p == rule.port)
                .map_or_else(|| format!("port {}", rule.port), |(_, name)| (*name).to_string());

            let evidence = CloudEvidence::new(CloudProvider::Aws, "securitygroup")
                .with_check_id("sg-open-ingress")
                .with_resource(&rule.group_id)
                .with_detail("port", rule.port.to_string())
                .with_detail("protocol", &rule.protocol)
                .with_detail("source", &rule.source_cidr)
                .with_detail("group_name", &rule.group_name);

            let finding = Finding::new(
                "aws-sg",
                Severity::Critical,
                format!(
                    "AWS SG: {} ({}) open to {} in {}",
                    port_label, rule.port, rule.source_cidr, rule.group_id
                ),
                format!(
                    "Security group '{}' ({}) allows {} ingress on port {} ({}) from {}",
                    rule.group_name,
                    rule.group_id,
                    rule.protocol,
                    rule.port,
                    port_label,
                    rule.source_cidr,
                ),
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation(
                "Restrict the security group rule to specific IP ranges instead of 0.0.0.0/0.",
            )
            .with_confidence(0.95);
            enrich_cloud_finding(finding, "securitygroup")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single open SSH rule → Critical finding.
    #[test]
    fn test_sg_open_ssh() {
        let rules = vec![SecurityGroupRule {
            group_id: "sg-12345".into(),
            group_name: "web-server".into(),
            port: 22,
            protocol: "tcp".into(),
            source_cidr: "0.0.0.0/0".into(),
        }];
        let findings = check_open_rules(&rules, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("SSH"));
        assert!(findings[0].title.contains("sg-12345"));
        assert!(findings[0].compliance.is_some());
    }

    /// Multiple open ports → multiple findings.
    #[test]
    fn test_sg_open_multiple_ports() {
        let rules = vec![
            SecurityGroupRule {
                group_id: "sg-abc".into(),
                group_name: "db".into(),
                port: 3306,
                protocol: "tcp".into(),
                source_cidr: "0.0.0.0/0".into(),
            },
            SecurityGroupRule {
                group_id: "sg-abc".into(),
                group_name: "db".into(),
                port: 5432,
                protocol: "tcp".into(),
                source_cidr: "0.0.0.0/0".into(),
            },
        ];
        let findings = check_open_rules(&rules, "aws:123456789012");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("MySQL"));
        assert!(findings[1].title.contains("PostgreSQL"));
    }

    /// Restricted CIDRs → zero findings (empty input).
    #[test]
    fn test_sg_restricted_rules_clean() {
        let findings = check_open_rules(&[], "aws:123456789012");
        assert!(findings.is_empty());
    }

    /// IPv6 open CIDR produces findings too.
    #[test]
    fn test_sg_ipv6_open_cidr() {
        let rules = vec![SecurityGroupRule {
            group_id: "sg-ipv6".into(),
            group_name: "test".into(),
            port: 3389,
            protocol: "tcp".into(),
            source_cidr: "::/0".into(),
        }];
        let findings = check_open_rules(&rules, "aws:123456789012");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("RDP"));
        assert!(findings[0].title.contains("::/0"));
    }

    /// Module metadata pins.
    #[test]
    fn test_sg_module_metadata() {
        let m = SecurityGroupCloudModule;
        assert_eq!(m.id(), "aws-sg");
        assert_eq!(m.category(), CloudCategory::Network);
        assert_eq!(m.providers(), &[CloudProvider::Aws]);
    }
}
