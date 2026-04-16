//! Compliance framework engine — trait, controls, registry, and assessment.
//!
//! Builds on the static OWASP/CWE→control mappings in [`super::compliance`]
//! with a dynamic [`ComplianceFramework`] trait, typed [`Control`]s, and a
//! [`ComplianceRegistry`] that evaluates findings against registered
//! frameworks to produce a [`ComplianceReport`].
//!
//! ## Built-in frameworks
//!
//! - [`Nist80053Framework`] — NIST 800-53 Rev 5
//! - [`PciDss4Framework`] — PCI-DSS 4.0
//! - [`Soc2TscFramework`] — SOC 2 Trust Services Criteria
//! - [`HipaaFramework`] — HIPAA Security Rule
//!
//! ## Usage
//!
//! ```
//! use scorchkit::engine::compliance_framework::{
//!     ComplianceRegistry, default_registry, assess_compliance,
//! };
//! use scorchkit::engine::finding::Finding;
//! use scorchkit::engine::severity::Severity;
//!
//! let registry = default_registry();
//! let findings = vec![
//!     Finding::new("test", Severity::High, "T", "D", "url")
//!         .with_owasp("A01:2021 Broken Access Control")
//!         .with_compliance(vec!["NIST AC-3 (Access Enforcement)".into()]),
//! ];
//! let report = assess_compliance(&findings, &registry);
//! assert!(!report.frameworks.is_empty());
//! ```

use serde::{Deserialize, Serialize};

use super::finding::Finding;

/// A single control within a compliance framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    /// Control identifier (e.g. `"AC-3"`, `"7.2"`, `"CC6.1"`).
    pub id: String,
    /// Human-readable control name.
    pub name: String,
    /// The framework this control belongs to.
    pub framework: String,
}

/// A match between a finding and a compliance control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMatch {
    /// The matched control.
    pub control: Control,
    /// Number of findings that matched this control.
    pub finding_count: usize,
    /// Whether this control is satisfied (no findings) or violated.
    pub status: ControlStatus,
}

/// Status of a compliance control after assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    /// No findings matched — control is satisfied.
    Pass,
    /// At least one finding matched — control is violated.
    Fail,
    /// Control was not assessed (no mapping exists).
    NotAssessed,
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => f.write_str("PASS"),
            Self::Fail => f.write_str("FAIL"),
            Self::NotAssessed => f.write_str("N/A"),
        }
    }
}

/// A compliance framework that can assess findings.
pub trait ComplianceFramework: Send + Sync {
    /// Framework identifier (e.g. `"nist-800-53"`, `"pci-dss-4"`).
    fn id(&self) -> &'static str;

    /// Human-readable framework name.
    fn name(&self) -> &'static str;

    /// All controls defined by this framework.
    fn controls(&self) -> &[Control];

    /// Check if a finding's compliance tags match any controls in this
    /// framework. Returns the matched control IDs.
    fn match_finding(&self, finding: &Finding) -> Vec<String>;
}

/// Registry holding all available compliance frameworks.
#[derive(Default)]
pub struct ComplianceRegistry {
    frameworks: Vec<Box<dyn ComplianceFramework>>,
}

impl ComplianceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a compliance framework.
    pub fn register(&mut self, framework: Box<dyn ComplianceFramework>) {
        self.frameworks.push(framework);
    }

    /// All registered frameworks.
    #[must_use]
    pub fn frameworks(&self) -> &[Box<dyn ComplianceFramework>] {
        &self.frameworks
    }
}

/// Assessment report for a single framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkReport {
    /// Framework identifier.
    pub framework_id: String,
    /// Framework name.
    pub framework_name: String,
    /// Per-control assessment results.
    pub controls: Vec<ControlMatch>,
    /// Total controls assessed.
    pub total_controls: usize,
    /// Controls that passed (no findings matched).
    pub pass_count: usize,
    /// Controls that failed (findings matched).
    pub fail_count: usize,
    /// Compliance percentage (pass / total * 100).
    pub compliance_pct: f64,
}

/// Full compliance report across all frameworks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Per-framework reports.
    pub frameworks: Vec<FrameworkReport>,
    /// Total findings assessed.
    pub total_findings: usize,
}

/// Assess a set of findings against all frameworks in the registry.
///
/// For each framework, checks every control against the findings'
/// compliance tags and produces a [`ComplianceReport`].
#[must_use]
pub fn assess_compliance(findings: &[Finding], registry: &ComplianceRegistry) -> ComplianceReport {
    let mut framework_reports = Vec::new();

    for fw in registry.frameworks() {
        let mut control_matches = Vec::new();

        for control in fw.controls() {
            let matched_count = findings
                .iter()
                .filter(|f| {
                    f.compliance
                        .as_ref()
                        .is_some_and(|tags| tags.iter().any(|t| t.contains(&control.id)))
                })
                .count();

            let status = if matched_count > 0 { ControlStatus::Fail } else { ControlStatus::Pass };

            control_matches.push(ControlMatch {
                control: control.clone(),
                finding_count: matched_count,
                status,
            });
        }

        let total = control_matches.len();
        let pass_count = control_matches.iter().filter(|m| m.status == ControlStatus::Pass).count();
        let fail_count = total - pass_count;
        // JUSTIFICATION: control counts are small (<100); f64 precision is not
        // a concern for percentage display.
        #[allow(clippy::cast_precision_loss)]
        let compliance_pct =
            if total > 0 { (pass_count as f64 / total as f64) * 100.0 } else { 100.0 };

        framework_reports.push(FrameworkReport {
            framework_id: fw.id().to_string(),
            framework_name: fw.name().to_string(),
            controls: control_matches,
            total_controls: total,
            pass_count,
            fail_count,
            compliance_pct,
        });
    }

    ComplianceReport { frameworks: framework_reports, total_findings: findings.len() }
}

// ---------------------------------------------------------------
// Built-in frameworks
// ---------------------------------------------------------------

/// NIST 800-53 Rev 5 compliance framework.
#[derive(Debug)]
pub struct Nist80053Framework {
    controls: Vec<Control>,
}

impl Default for Nist80053Framework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("AC-3", "Access Enforcement", "nist-800-53"),
                ctrl("AC-4", "Information Flow Enforcement", "nist-800-53"),
                ctrl("AC-6", "Least Privilege", "nist-800-53"),
                ctrl("AU-2", "Event Logging", "nist-800-53"),
                ctrl("AU-6", "Audit Record Review", "nist-800-53"),
                ctrl("CM-6", "Configuration Settings", "nist-800-53"),
                ctrl("CM-7", "Least Functionality", "nist-800-53"),
                ctrl("IA-2", "Identification and Authentication", "nist-800-53"),
                ctrl("IA-5", "Authenticator Management", "nist-800-53"),
                ctrl("RA-5", "Vulnerability Monitoring and Scanning", "nist-800-53"),
                ctrl("SC-7", "Boundary Protection", "nist-800-53"),
                ctrl("SC-8", "Transmission Confidentiality", "nist-800-53"),
                ctrl("SC-12", "Cryptographic Key Management", "nist-800-53"),
                ctrl("SC-28", "Protection of Information at Rest", "nist-800-53"),
                ctrl("SI-2", "Flaw Remediation", "nist-800-53"),
                ctrl("SI-10", "Information Input Validation", "nist-800-53"),
            ],
        }
    }
}

impl ComplianceFramework for Nist80053Framework {
    fn id(&self) -> &'static str {
        "nist-800-53"
    }
    fn name(&self) -> &'static str {
        "NIST 800-53 Rev 5"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        match_by_tag_prefix(finding, "NIST")
    }
}

/// PCI-DSS 4.0 compliance framework.
#[derive(Debug)]
pub struct PciDss4Framework {
    controls: Vec<Control>,
}

impl Default for PciDss4Framework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("2.2", "System Configuration Standards", "pci-dss-4"),
                ctrl("3.4", "Render PAN Unreadable", "pci-dss-4"),
                ctrl("4.1", "Strong Cryptography for Transmission", "pci-dss-4"),
                ctrl("6.2.4", "Software Engineering Techniques", "pci-dss-4"),
                ctrl("6.3", "Vulnerability Management", "pci-dss-4"),
                ctrl("6.5.8", "Improper Access Control", "pci-dss-4"),
                ctrl("7.2", "Access Control Systems", "pci-dss-4"),
                ctrl("8.2", "User Identification", "pci-dss-4"),
                ctrl("8.3", "Strong Cryptography for Authentication", "pci-dss-4"),
                ctrl("8.6", "Application/System Account Management", "pci-dss-4"),
                ctrl("10.2", "Audit Logs", "pci-dss-4"),
            ],
        }
    }
}

impl ComplianceFramework for PciDss4Framework {
    fn id(&self) -> &'static str {
        "pci-dss-4"
    }
    fn name(&self) -> &'static str {
        "PCI-DSS 4.0"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        match_by_tag_prefix(finding, "PCI-DSS")
    }
}

/// SOC 2 Trust Services Criteria compliance framework.
#[derive(Debug)]
pub struct Soc2TscFramework {
    controls: Vec<Control>,
}

impl Default for Soc2TscFramework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("CC6.1", "Logical Access Security", "soc2-tsc"),
                ctrl("CC6.7", "Restriction of Data Transmission", "soc2-tsc"),
                ctrl("CC7.1", "System Change Management", "soc2-tsc"),
                ctrl("CC7.2", "Monitoring Activities", "soc2-tsc"),
                ctrl("CC8.1", "Change Control Process", "soc2-tsc"),
            ],
        }
    }
}

impl ComplianceFramework for Soc2TscFramework {
    fn id(&self) -> &'static str {
        "soc2-tsc"
    }
    fn name(&self) -> &'static str {
        "SOC 2 Trust Services Criteria"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        match_by_tag_prefix(finding, "SOC2")
    }
}

/// HIPAA Security Rule compliance framework.
#[derive(Debug)]
pub struct HipaaFramework {
    controls: Vec<Control>,
}

impl Default for HipaaFramework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("§164.308(a)(5)(ii)(B)", "Protection from Malicious Software", "hipaa"),
                ctrl("§164.312(a)(1)", "Access Control", "hipaa"),
                ctrl("§164.312(a)(2)(iv)", "Encryption and Decryption", "hipaa"),
                ctrl("§164.312(b)", "Audit Controls", "hipaa"),
                ctrl("§164.312(c)(1)", "Integrity Controls", "hipaa"),
                ctrl("§164.312(d)", "Person or Entity Authentication", "hipaa"),
                ctrl("§164.312(e)(1)", "Transmission Security", "hipaa"),
            ],
        }
    }
}

impl ComplianceFramework for HipaaFramework {
    fn id(&self) -> &'static str {
        "hipaa"
    }
    fn name(&self) -> &'static str {
        "HIPAA Security Rule"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        match_by_tag_prefix(finding, "HIPAA")
    }
}

// ---------------------------------------------------------------
// CIS Benchmark frameworks (WORK-132)
// ---------------------------------------------------------------

/// CIS Docker Benchmark compliance framework.
#[derive(Debug)]
pub struct CisDockerFramework {
    controls: Vec<Control>,
}

impl Default for CisDockerFramework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("1.1", "Host Configuration — Kernel", "cis-docker"),
                ctrl("1.2", "Host Configuration — Docker Daemon", "cis-docker"),
                ctrl("2.1", "Docker Daemon — Restrict Network Traffic", "cis-docker"),
                ctrl("2.2", "Docker Daemon — Logging Level", "cis-docker"),
                ctrl("2.3", "Docker Daemon — Allow Iptables", "cis-docker"),
                ctrl("2.5", "Docker Daemon — TLS Authentication", "cis-docker"),
                ctrl("2.14", "Docker Daemon — Live Restore", "cis-docker"),
                ctrl("3.1", "Docker Daemon Files — Ownership", "cis-docker"),
                ctrl("4.1", "Container Images — Use Trusted Base", "cis-docker"),
                ctrl("4.5", "Container Images — Content Trust", "cis-docker"),
                ctrl("4.6", "Container Images — HEALTHCHECK", "cis-docker"),
                ctrl("5.1", "Container Runtime — AppArmor Profile", "cis-docker"),
                ctrl("5.2", "Container Runtime — SELinux Security", "cis-docker"),
                ctrl("5.3", "Container Runtime — Linux Capabilities", "cis-docker"),
                ctrl("5.4", "Container Runtime — Privileged Containers", "cis-docker"),
                ctrl("5.7", "Container Runtime — Open Ports", "cis-docker"),
                ctrl("5.10", "Container Runtime — Memory Limit", "cis-docker"),
                ctrl("5.12", "Container Runtime — Root Filesystem Read-Only", "cis-docker"),
                ctrl("5.25", "Container Runtime — PID cgroup Limit", "cis-docker"),
            ],
        }
    }
}

impl ComplianceFramework for CisDockerFramework {
    fn id(&self) -> &'static str {
        "cis-docker"
    }
    fn name(&self) -> &'static str {
        "CIS Docker Benchmark"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        match_by_tag_prefix(finding, "CIS-Docker")
    }
}

/// CIS Kubernetes Benchmark compliance framework.
#[derive(Debug)]
pub struct CisKubernetesFramework {
    controls: Vec<Control>,
}

impl Default for CisKubernetesFramework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("1.1.1", "API Server — Anonymous Auth", "cis-kubernetes"),
                ctrl("1.1.2", "API Server — Basic Auth", "cis-kubernetes"),
                ctrl("1.2.1", "API Server — Audit Logging", "cis-kubernetes"),
                ctrl("2.1", "etcd — Client Certificate Auth", "cis-kubernetes"),
                ctrl("2.2", "etcd — Peer Certificate Auth", "cis-kubernetes"),
                ctrl("3.1", "Controller Manager — Service Account Keys", "cis-kubernetes"),
                ctrl("4.1.1", "Worker Node — Kubelet Auth", "cis-kubernetes"),
                ctrl("4.2.1", "Worker Node — Kubelet TLS", "cis-kubernetes"),
                ctrl("5.1.1", "RBAC — Cluster Admin Usage", "cis-kubernetes"),
                ctrl("5.1.3", "RBAC — Wildcard Permissions", "cis-kubernetes"),
                ctrl("5.2.1", "Pod Security — Privileged Containers", "cis-kubernetes"),
                ctrl("5.2.2", "Pod Security — Host PID", "cis-kubernetes"),
                ctrl("5.2.3", "Pod Security — Host Network", "cis-kubernetes"),
                ctrl("5.3.1", "Network Policies — Default Deny", "cis-kubernetes"),
                ctrl("5.4.1", "Secrets — Encryption at Rest", "cis-kubernetes"),
                ctrl("5.7.1", "General — Namespace Usage", "cis-kubernetes"),
            ],
        }
    }
}

impl ComplianceFramework for CisKubernetesFramework {
    fn id(&self) -> &'static str {
        "cis-kubernetes"
    }
    fn name(&self) -> &'static str {
        "CIS Kubernetes Benchmark"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        match_by_tag_prefix(finding, "CIS-K8s")
    }
}

/// CIS AWS Foundations Benchmark compliance framework.
#[derive(Debug)]
pub struct CisAwsFramework {
    controls: Vec<Control>,
}

impl Default for CisAwsFramework {
    fn default() -> Self {
        Self {
            controls: vec![
                ctrl("1.1", "IAM — Root Account Usage", "cis-aws"),
                ctrl("1.4", "IAM — Root MFA", "cis-aws"),
                ctrl("1.5", "IAM — Hardware MFA for Root", "cis-aws"),
                ctrl("1.8", "IAM — Password Policy Length", "cis-aws"),
                ctrl("1.14", "IAM — Access Key Rotation", "cis-aws"),
                ctrl("1.16", "IAM — No Policies Attached to Users", "cis-aws"),
                ctrl("2.1.1", "S3 — Deny HTTP Requests", "cis-aws"),
                ctrl("2.1.2", "S3 — MFA Delete", "cis-aws"),
                ctrl("2.1.4", "S3 — Public Access Block", "cis-aws"),
                ctrl("2.2.1", "EBS — Default Encryption", "cis-aws"),
                ctrl("2.3.1", "RDS — Encryption at Rest", "cis-aws"),
                ctrl("3.1", "CloudTrail — Multi-Region", "cis-aws"),
                ctrl("3.2", "CloudTrail — Log File Validation", "cis-aws"),
                ctrl("3.4", "CloudTrail — Integration with CloudWatch", "cis-aws"),
                ctrl("3.7", "CloudTrail — S3 Bucket Logging", "cis-aws"),
                ctrl("4.1", "Monitoring — Unauthorized API Calls", "cis-aws"),
                ctrl("4.3", "Monitoring — Root Account Usage", "cis-aws"),
                ctrl("5.1", "Networking — No NACL Default Allow All", "cis-aws"),
                ctrl("5.2", "Networking — SG Restrict SSH", "cis-aws"),
                ctrl("5.3", "Networking — SG Restrict RDP", "cis-aws"),
                ctrl("5.4", "Networking — Default SG Restrict All", "cis-aws"),
            ],
        }
    }
}

impl ComplianceFramework for CisAwsFramework {
    fn id(&self) -> &'static str {
        "cis-aws"
    }
    fn name(&self) -> &'static str {
        "CIS AWS Foundations Benchmark"
    }
    fn controls(&self) -> &[Control] {
        &self.controls
    }
    fn match_finding(&self, finding: &Finding) -> Vec<String> {
        // Match CIS- prefixed tags and also Prowler-native CIS control IDs
        match_by_tag_prefix(finding, "CIS")
    }
}

// ---------------------------------------------------------------
// Compliance reporter (WORK-135)
// ---------------------------------------------------------------

/// Format a [`ComplianceReport`] as a human-readable summary string.
///
/// Produces a per-framework table with control status, compliance
/// percentage, and a summary line. Suitable for terminal output or
/// inclusion in reports.
#[must_use]
pub fn format_compliance_report(report: &ComplianceReport) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "=== Compliance Assessment ({} findings assessed) ===\n",
        report.total_findings
    );

    for fw in &report.frameworks {
        let _ = writeln!(out, "--- {} ({}) ---", fw.framework_name, fw.framework_id);
        let _ = writeln!(
            out,
            "Compliance: {:.1}% ({} pass / {} fail / {} total)\n",
            fw.compliance_pct, fw.pass_count, fw.fail_count, fw.total_controls
        );

        let failures: Vec<_> =
            fw.controls.iter().filter(|c| c.status == ControlStatus::Fail).collect();

        if failures.is_empty() {
            let _ = writeln!(out, "  All controls passing.");
        } else {
            for cm in &failures {
                let _ = writeln!(
                    out,
                    "  [FAIL] {} — {} ({} finding{})",
                    cm.control.id,
                    cm.control.name,
                    cm.finding_count,
                    if cm.finding_count == 1 { "" } else { "s" }
                );
            }
        }
        out.push('\n');
    }

    out
}

/// Format a [`ComplianceReport`] as a JSON string.
///
/// # Errors
///
/// Returns `Err` if serialization fails (should not happen for
/// well-formed reports).
pub fn compliance_report_to_json(report: &ComplianceReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Create a `Control` with the given fields.
fn ctrl(id: &str, name: &str, framework: &str) -> Control {
    Control { id: id.to_string(), name: name.to_string(), framework: framework.to_string() }
}

/// Match a finding's compliance tags against a prefix (e.g. `"NIST"`, `"PCI-DSS"`).
fn match_by_tag_prefix(finding: &Finding, prefix: &str) -> Vec<String> {
    finding
        .compliance
        .as_ref()
        .map(|tags| tags.iter().filter(|t| t.starts_with(prefix)).cloned().collect())
        .unwrap_or_default()
}

/// Create a [`ComplianceRegistry`] with all 7 built-in frameworks.
#[must_use]
pub fn default_registry() -> ComplianceRegistry {
    let mut registry = ComplianceRegistry::new();
    // Core frameworks (WORK-131)
    registry.register(Box::new(Nist80053Framework::default()));
    registry.register(Box::new(PciDss4Framework::default()));
    registry.register(Box::new(Soc2TscFramework::default()));
    registry.register(Box::new(HipaaFramework::default()));
    // CIS benchmarks (WORK-132)
    registry.register(Box::new(CisDockerFramework::default()));
    registry.register(Box::new(CisKubernetesFramework::default()));
    registry.register(Box::new(CisAwsFramework::default()));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    /// Default registry has 7 frameworks (4 core + 3 CIS).
    #[test]
    fn test_default_registry_has_seven_frameworks() {
        let reg = default_registry();
        assert_eq!(reg.frameworks().len(), 7);
        assert_eq!(reg.frameworks()[0].id(), "nist-800-53");
        assert_eq!(reg.frameworks()[1].id(), "pci-dss-4");
        assert_eq!(reg.frameworks()[2].id(), "soc2-tsc");
        assert_eq!(reg.frameworks()[3].id(), "hipaa");
        assert_eq!(reg.frameworks()[4].id(), "cis-docker");
        assert_eq!(reg.frameworks()[5].id(), "cis-kubernetes");
        assert_eq!(reg.frameworks()[6].id(), "cis-aws");
    }

    /// NIST framework has expected controls.
    #[test]
    fn test_nist_framework_controls() {
        let fw = Nist80053Framework::default();
        assert!(fw.controls().len() >= 10);
        assert!(fw.controls().iter().any(|c| c.id == "AC-3"));
        assert!(fw.controls().iter().any(|c| c.id == "SI-10"));
    }

    /// Finding with NIST compliance tags matches NIST controls.
    #[test]
    fn test_nist_match_finding() {
        let fw = Nist80053Framework::default();
        let finding = Finding::new("test", Severity::High, "T", "D", "url")
            .with_compliance(vec!["NIST AC-3 (Access Enforcement)".into()]);
        let matches = fw.match_finding(&finding);
        assert!(!matches.is_empty());
        assert!(matches[0].contains("NIST AC-3"));
    }

    /// Assessment produces report with pass/fail per control.
    #[test]
    fn test_assess_compliance_report() {
        let reg = default_registry();
        let findings =
            vec![Finding::new("test", Severity::High, "T", "D", "url").with_compliance(vec![
                "NIST AC-3 (Access Enforcement)".into(),
                "PCI-DSS 7.2 (Access Control Systems)".into(),
            ])];
        let report = assess_compliance(&findings, &reg);
        assert_eq!(report.total_findings, 1);
        assert_eq!(report.frameworks.len(), 7);

        // NIST: AC-3 should fail, others pass
        let nist = &report.frameworks[0];
        assert_eq!(nist.framework_id, "nist-800-53");
        assert!(nist.fail_count >= 1);
        assert!(nist.compliance_pct < 100.0);

        // PCI-DSS: 7.2 should fail
        let pci = &report.frameworks[1];
        assert!(pci.fail_count >= 1);
    }

    /// No findings → 100% compliance across all frameworks.
    #[test]
    fn test_assess_compliance_no_findings() {
        let reg = default_registry();
        let report = assess_compliance(&[], &reg);
        for fw in &report.frameworks {
            assert!((fw.compliance_pct - 100.0).abs() < f64::EPSILON);
            assert_eq!(fw.fail_count, 0);
        }
    }

    /// `ControlStatus` display.
    #[test]
    fn test_control_status_display() {
        assert_eq!(ControlStatus::Pass.to_string(), "PASS");
        assert_eq!(ControlStatus::Fail.to_string(), "FAIL");
        assert_eq!(ControlStatus::NotAssessed.to_string(), "N/A");
    }

    /// HIPAA framework matches HIPAA-prefixed tags.
    #[test]
    fn test_hipaa_match() {
        let fw = HipaaFramework::default();
        let finding = Finding::new("test", Severity::Medium, "T", "D", "url")
            .with_compliance(vec!["HIPAA §164.312(b) (Audit Controls)".into()]);
        let matches = fw.match_finding(&finding);
        assert!(!matches.is_empty());
    }

    /// `ComplianceReport` serializes to JSON.
    #[test]
    fn test_compliance_report_serialization() {
        let reg = default_registry();
        let report = assess_compliance(&[], &reg);
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("nist-800-53"));
        assert!(json.contains("compliance_pct"));
    }

    // -----------------------------------------------------------------
    // CIS frameworks (WORK-132)
    // -----------------------------------------------------------------

    /// CIS Docker framework has expected controls.
    #[test]
    fn test_cis_docker_framework() {
        let fw = CisDockerFramework::default();
        assert!(fw.controls().len() >= 15);
        assert!(fw.controls().iter().any(|c| c.id == "5.4"));
        assert_eq!(fw.id(), "cis-docker");
    }

    /// CIS Kubernetes framework has expected controls.
    #[test]
    fn test_cis_kubernetes_framework() {
        let fw = CisKubernetesFramework::default();
        assert!(fw.controls().len() >= 10);
        assert!(fw.controls().iter().any(|c| c.id == "5.1.1"));
        assert_eq!(fw.id(), "cis-kubernetes");
    }

    /// CIS AWS framework has expected controls.
    #[test]
    fn test_cis_aws_framework() {
        let fw = CisAwsFramework::default();
        assert!(fw.controls().len() >= 15);
        assert!(fw.controls().iter().any(|c| c.id == "1.4"));
        assert!(fw.controls().iter().any(|c| c.id == "3.1"));
        assert_eq!(fw.id(), "cis-aws");
    }

    /// CIS AWS matches CIS-prefixed compliance tags from Prowler.
    #[test]
    fn test_cis_aws_matches_prowler_tags() {
        let fw = CisAwsFramework::default();
        let finding = Finding::new("test", Severity::High, "T", "D", "url")
            .with_compliance(vec!["CIS-1.4".into()]);
        let matches = fw.match_finding(&finding);
        assert!(!matches.is_empty());
    }

    // -----------------------------------------------------------------
    // Reporter (WORK-135)
    // -----------------------------------------------------------------

    /// Format produces readable output with framework summaries.
    #[test]
    fn test_format_compliance_report() {
        let reg = default_registry();
        let findings = vec![Finding::new("test", Severity::High, "T", "D", "url")
            .with_compliance(vec!["NIST AC-3 (Access Enforcement)".into()])];
        let report = assess_compliance(&findings, &reg);
        let formatted = format_compliance_report(&report);
        assert!(formatted.contains("Compliance Assessment"));
        assert!(formatted.contains("NIST 800-53"));
        assert!(formatted.contains("[FAIL] AC-3"));
        assert!(formatted.contains("All controls passing")); // other frameworks pass
    }

    /// Format with no findings shows all passing.
    #[test]
    fn test_format_compliance_report_all_passing() {
        let reg = default_registry();
        let report = assess_compliance(&[], &reg);
        let formatted = format_compliance_report(&report);
        assert!(formatted.contains("100.0%"));
    }

    /// JSON reporter produces valid JSON.
    #[test]
    fn test_compliance_report_json() {
        let reg = default_registry();
        let report = assess_compliance(&[], &reg);
        let json = compliance_report_to_json(&report).expect("json");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(parsed["frameworks"].is_array());
        assert_eq!(parsed["frameworks"].as_array().map(Vec::len), Some(7));
    }
}
