//! GCP audit logging posture checks — admin activity + data access.
//!
//! Calls the Cloud Resource Manager REST API to check the project's
//! IAM policy for audit log configuration.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_gcp_client, resolve_project_id, GcpAuditConfig};

/// Built-in GCP audit logging posture module.
#[derive(Debug)]
pub struct GcpAuditCloudModule;

#[async_trait]
impl CloudModule for GcpAuditCloudModule {
    fn name(&self) -> &'static str {
        "GCP Audit Logging Posture"
    }

    fn id(&self) -> &'static str {
        "gcp-audit"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Compliance
    }

    fn description(&self) -> &'static str {
        "Built-in GCP audit logging checks: admin activity + data access logging"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Gcp]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let project = resolve_project_id(&ctx.target, creds)?;
        let (client, token) =
            build_gcp_client(creds, &["https://www.googleapis.com/auth/cloud-platform.read-only"])
                .await?;
        let target_label = ctx.target.display_raw();

        let configs = match fetch_audit_configs(&client, &token, &project).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("gcp-audit: failed to fetch audit configs: {e}");
                return Ok(vec![]);
            }
        };

        Ok(check_audit_configs(&configs, &target_label))
    }
}

/// Fetch audit log configuration from the project IAM policy.
async fn fetch_audit_configs(
    client: &reqwest::Client,
    token: &str,
    project: &str,
) -> std::result::Result<Vec<GcpAuditConfig>, reqwest::Error> {
    let url =
        format!("https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy");
    let resp: serde_json::Value = client
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({}))
        .send()
        .await?
        .json()
        .await?;

    let audit_configs = resp["auditConfigs"].as_array().cloned().unwrap_or_default();

    Ok(audit_configs
        .iter()
        .map(|ac| {
            let service = ac["service"].as_str().unwrap_or("unknown").to_string();
            let log_configs = ac["auditLogConfigs"].as_array().cloned().unwrap_or_default();

            let mut admin_read = false;
            let mut data_read = false;
            let mut data_write = false;
            for lc in &log_configs {
                match lc["logType"].as_str().unwrap_or("") {
                    "ADMIN_READ" => admin_read = true,
                    "DATA_READ" => data_read = true,
                    "DATA_WRITE" => data_write = true,
                    _ => {}
                }
            }

            GcpAuditConfig {
                service,
                admin_read_enabled: admin_read,
                data_read_enabled: data_read,
                data_write_enabled: data_write,
            }
        })
        .collect())
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Check audit logging configuration for completeness.
#[must_use]
pub fn check_audit_configs(configs: &[GcpAuditConfig], target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for allServices audit config
    let all_services = configs.iter().find(|c| c.service == "allServices");

    match all_services {
        None => {
            let evidence = CloudEvidence::new(CloudProvider::Gcp, "logging")
                .with_check_id("gcp-audit-no-all-services");
            let finding = Finding::new(
                "gcp-audit",
                Severity::High,
                "GCP Audit: No allServices audit logging configured",
                "The project has no audit logging configured for allServices. \
                 API calls may not be captured in audit logs.",
                format!("cloud://{target_label}"),
            )
            .with_evidence(evidence.to_string())
            .with_remediation(
                "Configure audit logging for allServices with ADMIN_READ, DATA_READ, \
                 and DATA_WRITE log types.",
            )
            .with_confidence(0.9);
            findings.push(enrich_cloud_finding(finding, "logging"));
        }
        Some(config) => {
            let mut missing = Vec::new();
            if !config.admin_read_enabled {
                missing.push("ADMIN_READ");
            }
            if !config.data_read_enabled {
                missing.push("DATA_READ");
            }
            if !config.data_write_enabled {
                missing.push("DATA_WRITE");
            }

            if !missing.is_empty() {
                let evidence = CloudEvidence::new(CloudProvider::Gcp, "logging")
                    .with_check_id("gcp-audit-incomplete")
                    .with_detail("missing", missing.join(", "));

                let finding = Finding::new(
                    "gcp-audit",
                    Severity::Medium,
                    "GCP Audit: Incomplete allServices audit logging",
                    format!(
                        "The allServices audit config is missing log types: {}. \
                         Some API activity may not be captured.",
                        missing.join(", ")
                    ),
                    format!("cloud://{target_label}"),
                )
                .with_evidence(evidence.to_string())
                .with_remediation("Enable all three log types (ADMIN_READ, DATA_READ, DATA_WRITE) for allServices.")
                .with_confidence(0.85);
                findings.push(enrich_cloud_finding(finding, "logging"));
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No audit config → High finding.
    #[test]
    fn test_audit_logging_disabled() {
        let findings = check_audit_configs(&[], "gcp:my-project");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("No allServices"));
        assert!(findings[0].compliance.is_some());
    }

    /// Incomplete logging → Medium finding.
    #[test]
    fn test_audit_logging_incomplete() {
        let configs = vec![GcpAuditConfig {
            service: "allServices".into(),
            admin_read_enabled: true,
            data_read_enabled: false,
            data_write_enabled: false,
        }];
        let findings = check_audit_configs(&configs, "gcp:my-project");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("Incomplete"));
    }

    /// Full logging → zero findings.
    #[test]
    fn test_audit_logging_healthy() {
        let configs = vec![GcpAuditConfig {
            service: "allServices".into(),
            admin_read_enabled: true,
            data_read_enabled: true,
            data_write_enabled: true,
        }];
        let findings = check_audit_configs(&configs, "gcp:my-project");
        assert!(findings.is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_audit_module_metadata() {
        let m = GcpAuditCloudModule;
        assert_eq!(m.id(), "gcp-audit");
        assert_eq!(m.category(), CloudCategory::Compliance);
        assert_eq!(m.providers(), &[CloudProvider::Gcp]);
    }
}
