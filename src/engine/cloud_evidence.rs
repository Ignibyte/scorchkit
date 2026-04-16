//! Structured evidence builder and compliance enrichment for cloud findings.
//!
//! Provides [`CloudEvidence`] as a typed alternative to the freeform
//! pipe-delimited evidence strings previously used by cloud modules, and
//! [`enrich_cloud_finding`] to auto-populate OWASP / CWE / compliance
//! fields based on the cloud service that produced the finding.
//!
//! ## Backward compatibility
//!
//! [`CloudEvidence`] implements [`std::fmt::Display`] to produce the same
//! pipe-delimited format that downstream consumers already parse
//! (`"provider:aws | service:s3 | ..."`). Cloud modules call
//! `finding.with_evidence(evidence.to_string())` — the [`Finding`]
//! struct is unchanged.
//!
//! ## Usage
//!
//! ```
//! use scorchkit::engine::cloud_evidence::{CloudEvidence, enrich_cloud_finding};
//! use scorchkit::engine::cloud_module::CloudProvider;
//! use scorchkit::engine::finding::Finding;
//! use scorchkit::engine::severity::Severity;
//!
//! let evidence = CloudEvidence::new(CloudProvider::Aws, "s3")
//!     .with_check_id("s3-bucket-public-access")
//!     .with_detail("severity", "critical");
//!
//! let finding = Finding::new(
//!     "prowler-cloud",
//!     Severity::Critical,
//!     "S3 Bucket Public Access",
//!     "Bucket allows public read",
//!     "cloud://aws:123456789012",
//! )
//! .with_evidence(evidence.to_string())
//! .with_confidence(0.8);
//!
//! let finding = enrich_cloud_finding(finding, "s3");
//! assert!(finding.compliance.is_some());
//! ```

use std::collections::BTreeMap;
use std::fmt;

use super::cloud_module::CloudProvider;
use super::compliance::{compliance_for_cwe, compliance_for_owasp};
use super::finding::Finding;

/// Structured evidence for cloud-posture findings.
///
/// Replaces the freeform pipe-delimited evidence strings previously
/// assembled by cloud modules. All fields are accessible for
/// programmatic consumption; [`Display`] serializes to the legacy
/// pipe-delimited format for backward compatibility.
#[derive(Debug, Clone)]
pub struct CloudEvidence {
    /// Cloud provider that produced this evidence.
    pub provider: CloudProvider,
    /// Cloud service name (e.g. `"s3"`, `"iam"`, `"ec2"`).
    pub service: String,
    /// Tool-specific check identifier (e.g. Prowler check code,
    /// Scout rule ID, Kubescape control ID).
    pub check_id: Option<String>,
    /// Affected cloud resource identifier.
    pub resource: Option<String>,
    /// Additional key-value pairs (e.g. `"severity" → "critical"`,
    /// `"flagged" → "3"`). [`BTreeMap`] for deterministic display order.
    pub detail: BTreeMap<String, String>,
}

impl CloudEvidence {
    /// Create a new cloud evidence builder with required fields.
    #[must_use]
    pub fn new(provider: CloudProvider, service: impl Into<String>) -> Self {
        Self {
            provider,
            service: service.into(),
            check_id: None,
            resource: None,
            detail: BTreeMap::new(),
        }
    }

    /// Set the tool-specific check identifier.
    #[must_use]
    pub fn with_check_id(mut self, check_id: impl Into<String>) -> Self {
        self.check_id = Some(check_id.into());
        self
    }

    /// Set the affected cloud resource identifier.
    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Add a key-value detail pair.
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.detail.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for CloudEvidence {
    /// Serialize to the pipe-delimited format consumed by downstream
    /// parsers: `"provider:aws | service:s3 | check_id:... | ..."`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "provider:{} | service:{}", self.provider, self.service)?;
        if let Some(ref id) = self.check_id {
            write!(f, " | check_id:{id}")?;
        }
        if let Some(ref res) = self.resource {
            write!(f, " | resource:{res}")?;
        }
        for (k, v) in &self.detail {
            write!(f, " | {k}:{v}")?;
        }
        Ok(())
    }
}

/// OWASP category and CWE ID pair for a cloud service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwaspCwe {
    /// OWASP Top 10 category string (e.g. `"A01:2021 Broken Access Control"`).
    pub owasp: &'static str,
    /// CWE identifier.
    pub cwe: u32,
}

/// Map a cloud service name to the most appropriate OWASP / CWE pair.
///
/// Service names are lowercased before matching. Unknown services fall
/// back to A05 (Security Misconfiguration) / CWE-1188 (Insecure
/// Default Initialization), preserving backward compatibility with the
/// pre-WORK-154 blanket mapping.
#[must_use]
pub fn cloud_service_owasp_cwe(service: &str) -> OwaspCwe {
    match service.to_lowercase().as_str() {
        // Identity & access management (incl. K8s RBAC) → Broken Access Control
        "iam" | "identitymanagement" | "identity" | "accessanalyzer" | "sso" | "organizations"
        | "rbac" | "clusterrole" | "rolebinding" => {
            OwaspCwe { owasp: "A01:2021 Broken Access Control", cwe: 287 }
        }

        // Storage → Broken Access Control (data exposure)
        "s3" | "storage" | "gcs" | "blob" | "efs" | "fsx" => {
            OwaspCwe { owasp: "A01:2021 Broken Access Control", cwe: 200 }
        }

        // Compute (incl. K8s workloads) + Database → Security Misconfiguration
        "ec2" | "compute" | "vm" | "lightsail" | "lambda" | "ecs" | "eks" | "batch"
        | "apprunner" | "rds" | "database" | "dynamodb" | "redshift" | "elasticache"
        | "neptune" | "documentdb" | "sql" | "bigtable" | "spanner" | "cloudsql" | "pod"
        | "container" | "workload" | "deployment" | "daemonset" | "statefulset" => {
            OwaspCwe { owasp: "A05:2021 Security Misconfiguration", cwe: 16 }
        }

        // Network (incl. K8s network policies) → Security Misconfiguration (access control)
        "vpc" | "network" | "firewall" | "securitygroup" | "elb" | "elbv2" | "cloudfront"
        | "route53" | "apigateway" | "waf" | "shield" | "networkfirewall" | "networkpolicy"
        | "ingress" | "service" => {
            OwaspCwe { owasp: "A05:2021 Security Misconfiguration", cwe: 284 }
        }

        // Logging & monitoring → Security Logging Failures
        "cloudtrail" | "logging" | "monitoring" | "cloudwatch" | "config" | "guardduty"
        | "securityhub" | "inspector" | "detective" | "auditmanager" => {
            OwaspCwe { owasp: "A09:2021 Security Logging and Monitoring Failures", cwe: 778 }
        }

        // Encryption & key management → Cryptographic Failures
        "kms" | "encryption" | "crypto" | "acm" | "secretsmanager" | "ssm" => {
            OwaspCwe { owasp: "A02:2021 Cryptographic Failures", cwe: 311 }
        }

        // Default fallback — preserves pre-WORK-154 behavior
        _ => OwaspCwe { owasp: "A05:2021 Security Misconfiguration", cwe: 1188 },
    }
}

/// Enrich a cloud finding with per-service OWASP / CWE / compliance.
///
/// Replaces the blanket `A05:2021 / CWE-1188` that all cloud modules
/// previously applied. Looks up the service name via
/// [`cloud_service_owasp_cwe`], sets the OWASP and CWE fields, then
/// auto-populates the compliance field from
/// [`compliance_for_owasp`] and [`compliance_for_cwe`].
///
/// Designed as a builder-chain function: consumes and returns `Finding`.
#[must_use]
pub fn enrich_cloud_finding(finding: Finding, service: &str) -> Finding {
    let mapping = cloud_service_owasp_cwe(service);

    let mut controls: Vec<String> =
        compliance_for_owasp(mapping.owasp).into_iter().map(String::from).collect();

    for ctrl in compliance_for_cwe(mapping.cwe) {
        let s = String::from(ctrl);
        if !controls.contains(&s) {
            controls.push(s);
        }
    }

    let mut finding = finding.with_owasp(mapping.owasp).with_cwe(mapping.cwe);

    if !controls.is_empty() {
        finding = finding.with_compliance(controls);
    }

    finding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    // -----------------------------------------------------------------
    // CloudEvidence builder
    // -----------------------------------------------------------------

    /// All fields set correctly via the builder chain.
    #[test]
    fn test_cloud_evidence_builder_all_fields() {
        let ev = CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id("s3-bucket-public-access")
            .with_resource("arn:aws:s3:::my-bucket")
            .with_detail("severity", "critical")
            .with_detail("flagged", "3");

        assert_eq!(ev.provider, CloudProvider::Aws);
        assert_eq!(ev.service, "s3");
        assert_eq!(ev.check_id.as_deref(), Some("s3-bucket-public-access"));
        assert_eq!(ev.resource.as_deref(), Some("arn:aws:s3:::my-bucket"));
        assert_eq!(ev.detail.get("severity").map(String::as_str), Some("critical"));
        assert_eq!(ev.detail.get("flagged").map(String::as_str), Some("3"));
    }

    /// Display output matches the pipe-delimited format with all fields.
    #[test]
    fn test_cloud_evidence_display_format() {
        let ev = CloudEvidence::new(CloudProvider::Aws, "s3")
            .with_check_id("s3-public")
            .with_resource("my-bucket")
            .with_detail("severity", "critical");

        let s = ev.to_string();
        assert_eq!(
            s,
            "provider:aws | service:s3 | check_id:s3-public | resource:my-bucket | severity:critical"
        );
    }

    /// Optional fields omitted from Display when None.
    #[test]
    fn test_cloud_evidence_optional_fields_omitted() {
        let ev = CloudEvidence::new(CloudProvider::Kubernetes, "pod");
        let s = ev.to_string();
        assert_eq!(s, "provider:kubernetes | service:pod");
    }

    /// Detail keys are sorted alphabetically (BTreeMap).
    #[test]
    fn test_cloud_evidence_detail_sorted() {
        let ev = CloudEvidence::new(CloudProvider::Gcp, "storage")
            .with_detail("zebra", "last")
            .with_detail("alpha", "first");
        let s = ev.to_string();
        assert!(s.contains("alpha:first | zebra:last"), "details must be sorted: {s}");
    }

    // -----------------------------------------------------------------
    // cloud_service_owasp_cwe mapping
    // -----------------------------------------------------------------

    /// All known service families return the correct OWASP/CWE.
    #[test]
    fn test_cloud_service_owasp_cwe_known_services() {
        // IAM family → A01 / CWE-287
        let m = cloud_service_owasp_cwe("iam");
        assert!(m.owasp.contains("A01"), "iam owasp: {}", m.owasp);
        assert_eq!(m.cwe, 287);

        // Storage family → A01 / CWE-200
        let m = cloud_service_owasp_cwe("s3");
        assert!(m.owasp.contains("A01"), "s3 owasp: {}", m.owasp);
        assert_eq!(m.cwe, 200);

        // Compute family → A05 / CWE-16
        let m = cloud_service_owasp_cwe("ec2");
        assert!(m.owasp.contains("A05"), "ec2 owasp: {}", m.owasp);
        assert_eq!(m.cwe, 16);

        // Network family → A05 / CWE-284
        let m = cloud_service_owasp_cwe("vpc");
        assert!(m.owasp.contains("A05"), "vpc owasp: {}", m.owasp);
        assert_eq!(m.cwe, 284);

        // Logging family → A09 / CWE-778
        let m = cloud_service_owasp_cwe("cloudtrail");
        assert!(m.owasp.contains("A09"), "cloudtrail owasp: {}", m.owasp);
        assert_eq!(m.cwe, 778);

        // Crypto family → A02 / CWE-311
        let m = cloud_service_owasp_cwe("kms");
        assert!(m.owasp.contains("A02"), "kms owasp: {}", m.owasp);
        assert_eq!(m.cwe, 311);

        // Database family → A05 / CWE-16
        let m = cloud_service_owasp_cwe("rds");
        assert!(m.owasp.contains("A05"), "rds owasp: {}", m.owasp);
        assert_eq!(m.cwe, 16);

        // K8s RBAC → A01 / CWE-287
        let m = cloud_service_owasp_cwe("rbac");
        assert!(m.owasp.contains("A01"), "rbac owasp: {}", m.owasp);
        assert_eq!(m.cwe, 287);
    }

    /// Unknown service falls back to A05 / CWE-1188.
    #[test]
    fn test_cloud_service_owasp_cwe_unknown_fallback() {
        let m = cloud_service_owasp_cwe("totally-unknown-service");
        assert!(m.owasp.contains("A05"), "fallback owasp: {}", m.owasp);
        assert_eq!(m.cwe, 1188);
    }

    /// Case-insensitive matching works.
    #[test]
    fn test_cloud_service_owasp_cwe_case_insensitive() {
        let upper = cloud_service_owasp_cwe("IAM");
        let lower = cloud_service_owasp_cwe("iam");
        assert_eq!(upper, lower);
    }

    // -----------------------------------------------------------------
    // enrich_cloud_finding
    // -----------------------------------------------------------------

    /// Enrichment sets OWASP, CWE, and populates compliance.
    #[test]
    fn test_enrich_cloud_finding_sets_compliance() {
        let f = Finding::new("test", Severity::High, "T", "D", "cloud://aws:123");
        let f = enrich_cloud_finding(f, "s3");

        assert!(f.owasp_category.as_deref().is_some_and(|o| o.contains("A01")));
        assert_eq!(f.cwe_id, Some(200));
        assert!(f.compliance.is_some(), "compliance must be populated");
        let controls = f.compliance.as_ref().expect("compliance");
        assert!(!controls.is_empty());
    }

    /// IAM service produces A01 + CWE-287 + NIST/PCI/HIPAA controls.
    #[test]
    fn test_enrich_cloud_finding_iam_service() {
        let f = Finding::new("test", Severity::High, "T", "D", "cloud://aws:123");
        let f = enrich_cloud_finding(f, "iam");

        assert!(f.owasp_category.as_deref().is_some_and(|o| o.contains("A01")));
        assert_eq!(f.cwe_id, Some(287));
        let controls = f.compliance.as_ref().expect("compliance");
        // A01 maps to NIST AC-3, PCI-DSS 7.2, SOC2 CC6.1, HIPAA
        assert!(controls.iter().any(|c| c.contains("NIST AC-3")));
        assert!(controls.iter().any(|c| c.contains("PCI-DSS")));
        // CWE-287 maps to NIST IA-2, PCI-DSS 8.2, HIPAA
        assert!(controls.iter().any(|c| c.contains("NIST IA-2")));
    }

    /// Logging service produces A09 + CWE-778 + audit controls.
    #[test]
    fn test_enrich_cloud_finding_logging_service() {
        let f = Finding::new("test", Severity::Medium, "T", "D", "cloud://aws:123");
        let f = enrich_cloud_finding(f, "cloudtrail");

        assert!(f.owasp_category.as_deref().is_some_and(|o| o.contains("A09")));
        assert_eq!(f.cwe_id, Some(778));
        let controls = f.compliance.as_ref().expect("compliance");
        assert!(controls.iter().any(|c| c.contains("NIST AU-2")));
    }

    /// Unknown service still gets compliance from fallback A05/CWE-1188.
    #[test]
    fn test_enrich_cloud_finding_unknown_service_gets_fallback_compliance() {
        let f = Finding::new("test", Severity::Low, "T", "D", "cloud://aws:123");
        let f = enrich_cloud_finding(f, "unknown-svc");

        assert!(f.owasp_category.as_deref().is_some_and(|o| o.contains("A05")));
        assert_eq!(f.cwe_id, Some(1188));
        // A05 has NIST CM-6 mapping
        let controls = f.compliance.as_ref().expect("compliance");
        assert!(controls.iter().any(|c| c.contains("NIST CM-6")));
    }
}
