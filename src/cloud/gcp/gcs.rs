//! GCP Cloud Storage posture checks — public access, encryption, UBLA.
//!
//! Calls the Cloud Storage JSON API to enumerate buckets and check
//! each for public access prevention, CMEK encryption, and uniform
//! bucket-level access.

use async_trait::async_trait;

use crate::engine::cloud_context::CloudContext;
use crate::engine::cloud_evidence::{enrich_cloud_finding, CloudEvidence};
use crate::engine::cloud_module::{CloudCategory, CloudModule, CloudProvider};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

use super::{build_gcp_client, resolve_project_id, GcsBucketPosture};

/// Built-in GCP Cloud Storage posture module.
#[derive(Debug)]
pub struct GcsCloudModule;

#[async_trait]
impl CloudModule for GcsCloudModule {
    fn name(&self) -> &'static str {
        "GCP Cloud Storage Posture"
    }

    fn id(&self) -> &'static str {
        "gcp-gcs"
    }

    fn category(&self) -> CloudCategory {
        CloudCategory::Storage
    }

    fn description(&self) -> &'static str {
        "Built-in GCP GCS checks: public access, encryption, uniform bucket-level access"
    }

    fn providers(&self) -> &'static [CloudProvider] {
        &[CloudProvider::Gcp]
    }

    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>> {
        let creds = ctx.credentials.as_deref();
        let project = resolve_project_id(&ctx.target, creds)?;
        let (client, token) =
            build_gcp_client(creds, &["https://www.googleapis.com/auth/devstorage.read_only"])
                .await?;
        let target_label = ctx.target.display_raw();

        let buckets = match fetch_bucket_postures(&client, &token, &project).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("gcp-gcs: failed to list buckets: {e}");
                return Ok(vec![]);
            }
        };

        let mut findings = Vec::new();
        for bucket in &buckets {
            findings.extend(check_bucket_posture(bucket, &target_label));
        }
        Ok(findings)
    }
}

/// Fetch posture for all buckets in the project.
async fn fetch_bucket_postures(
    client: &reqwest::Client,
    token: &str,
    project: &str,
) -> std::result::Result<Vec<GcsBucketPosture>, reqwest::Error> {
    let url = format!("https://storage.googleapis.com/storage/v1/b?project={project}");
    let resp: serde_json::Value = client.get(&url).bearer_auth(token).send().await?.json().await?;

    let items = resp["items"].as_array().cloned().unwrap_or_default();
    Ok(items
        .iter()
        .map(|b| {
            let name = b["name"].as_str().unwrap_or("unnamed").to_string();
            let public_access_prevented = b["iamConfiguration"]["publicAccessPrevention"]
                .as_str()
                .is_some_and(|v| v == "enforced");
            let uniform_access = b["iamConfiguration"]["uniformBucketLevelAccess"]["enabled"]
                .as_bool()
                .unwrap_or(false);
            let cmek_configured = b["encryption"]["defaultKmsKeyName"].as_str().is_some();

            GcsBucketPosture { name, public_access_prevented, uniform_access, cmek_configured }
        })
        .collect())
}

// ---------------------------------------------------------------
// Pure check functions
// ---------------------------------------------------------------

/// Check a single GCS bucket posture.
#[must_use]
pub fn check_bucket_posture(bucket: &GcsBucketPosture, target_label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !bucket.public_access_prevented {
        let evidence = CloudEvidence::new(CloudProvider::Gcp, "storage")
            .with_check_id("gcs-public-access")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "gcp-gcs",
            Severity::Critical,
            format!("GCP GCS: Bucket '{}' public access not prevented", bucket.name),
            format!(
                "GCS bucket '{}' does not enforce public access prevention. \
                 Data may be publicly accessible.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Set publicAccessPrevention to 'enforced' on this bucket.")
        .with_confidence(0.9);
        findings.push(enrich_cloud_finding(finding, "storage"));
    }

    if !bucket.uniform_access {
        let evidence = CloudEvidence::new(CloudProvider::Gcp, "storage")
            .with_check_id("gcs-no-ubla")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "gcp-gcs",
            Severity::Medium,
            format!("GCP GCS: Bucket '{}' uniform access disabled", bucket.name),
            format!(
                "GCS bucket '{}' does not use uniform bucket-level access. \
                 Mixed ACL + IAM permissions create confused-deputy risks.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation("Enable uniform bucket-level access (UBLA) on this bucket.")
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "storage"));
    }

    if !bucket.cmek_configured {
        let evidence = CloudEvidence::new(CloudProvider::Gcp, "storage")
            .with_check_id("gcs-no-cmek")
            .with_resource(&bucket.name);
        let finding = Finding::new(
            "gcp-gcs",
            Severity::High,
            format!("GCP GCS: Bucket '{}' no CMEK encryption", bucket.name),
            format!(
                "GCS bucket '{}' uses Google-managed encryption, not customer-managed. \
                 CMEK provides key rotation control and audit logging via Cloud KMS.",
                bucket.name
            ),
            format!("cloud://{target_label}"),
        )
        .with_evidence(evidence.to_string())
        .with_remediation(
            "Configure a Cloud KMS key as the default encryption key for this bucket.",
        )
        .with_confidence(0.85);
        findings.push(enrich_cloud_finding(finding, "storage"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public bucket → Critical finding.
    #[test]
    fn test_gcs_public_bucket() {
        let bucket = GcsBucketPosture {
            name: "public-data".into(),
            public_access_prevented: false,
            uniform_access: true,
            cmek_configured: true,
        };
        let findings = check_bucket_posture(&bucket, "gcp:my-project");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("public access"));
        assert!(findings[0].compliance.is_some());
    }

    /// No CMEK → High finding.
    #[test]
    fn test_gcs_no_encryption() {
        let bucket = GcsBucketPosture {
            name: "no-cmek".into(),
            public_access_prevented: true,
            uniform_access: true,
            cmek_configured: false,
        };
        let findings = check_bucket_posture(&bucket, "gcp:my-project");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("CMEK"));
    }

    /// Fully secured bucket → zero findings.
    #[test]
    fn test_gcs_secure_bucket() {
        let bucket = GcsBucketPosture {
            name: "secure".into(),
            public_access_prevented: true,
            uniform_access: true,
            cmek_configured: true,
        };
        let findings = check_bucket_posture(&bucket, "gcp:my-project");
        assert!(findings.is_empty());
    }

    /// Module metadata.
    #[test]
    fn test_gcs_module_metadata() {
        let m = GcsCloudModule;
        assert_eq!(m.id(), "gcp-gcs");
        assert_eq!(m.category(), CloudCategory::Storage);
        assert_eq!(m.providers(), &[CloudProvider::Gcp]);
    }
}
