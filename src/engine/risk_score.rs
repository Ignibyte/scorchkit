//! Multi-factor risk scoring engine (WORK-138).
//!
//! Computes a `risk_score: f64 (0.0–100.0)` for each finding based
//! on multiple factors: base severity, confidence, exposure context,
//! and compliance impact.
//!
//! ## Factors
//!
//! - **Base severity** (0–40): Critical=40, High=30, Medium=20, Low=10, Info=5
//! - **Confidence** (0–20): `finding.confidence * 20`
//! - **Exposure** (0–20): internet-facing targets score higher
//! - **Compliance impact** (0–20): more compliance controls = higher score

use super::finding::Finding;
use super::severity::Severity;

/// Compute a risk score (0.0–100.0) for a single finding.
///
/// Higher values indicate greater risk. The score combines severity,
/// detection confidence, exposure context, and compliance impact.
#[must_use]
pub fn compute_risk_score(finding: &Finding) -> f64 {
    let base = severity_base(finding.severity);
    let confidence_factor = finding.confidence * 20.0;
    let exposure = exposure_score(finding);
    let compliance = compliance_impact(finding);

    (base + confidence_factor + exposure + compliance).clamp(0.0, 100.0)
}

/// Batch-compute risk scores for all findings, returning `(index, score)` pairs
/// sorted by score descending.
#[must_use]
pub fn rank_findings(findings: &[Finding]) -> Vec<(usize, f64)> {
    let mut scored: Vec<(usize, f64)> =
        findings.iter().enumerate().map(|(i, f)| (i, compute_risk_score(f))).collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

/// Risk letter grade from a score.
#[must_use]
pub fn risk_grade(score: f64) -> &'static str {
    if score >= 80.0 {
        "A" // Critical risk
    } else if score >= 60.0 {
        "B" // High risk
    } else if score >= 40.0 {
        "C" // Medium risk
    } else if score >= 20.0 {
        "D" // Low risk
    } else {
        "F" // Minimal risk
    }
}

/// Base score from severity.
const fn severity_base(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 40.0,
        Severity::High => 30.0,
        Severity::Medium => 20.0,
        Severity::Low => 10.0,
        Severity::Info => 5.0,
    }
}

/// Exposure score based on target context.
fn exposure_score(finding: &Finding) -> f64 {
    let target = &finding.affected_target;
    if target.starts_with("https://") || target.starts_with("http://") {
        15.0 // Internet-facing web target
    } else if target.starts_with("cloud://") {
        12.0 // Cloud resource (API-accessible)
    } else if target.starts_with("infra://") {
        10.0 // Network infrastructure
    } else if target.starts_with("file://") {
        5.0 // Source code (requires repo access)
    } else {
        8.0 // Unknown context
    }
}

/// Compliance impact based on number of controls affected.
fn compliance_impact(finding: &Finding) -> f64 {
    let count = finding.compliance.as_ref().map_or(0, Vec::len);

    if count >= 5 {
        20.0
    } else if count >= 3 {
        15.0
    } else if count >= 1 {
        10.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_with(severity: Severity, target: &str, confidence: f64) -> Finding {
        Finding::new("test", severity, "T", "D", target).with_confidence(confidence)
    }

    /// Critical + high confidence + web target → high score.
    #[test]
    fn test_risk_score_critical_web() {
        let f = finding_with(Severity::Critical, "https://example.com", 0.95);
        let score = compute_risk_score(&f);
        assert!(score >= 70.0, "critical web should score high: {score}");
    }

    /// Info + low confidence + file target → low score.
    #[test]
    fn test_risk_score_info_file() {
        let f = finding_with(Severity::Info, "file:///src/main.rs", 0.3);
        let score = compute_risk_score(&f);
        assert!(score < 30.0, "info file should score low: {score}");
    }

    /// Compliance controls increase score.
    #[test]
    fn test_risk_score_compliance_impact() {
        let base = finding_with(Severity::Medium, "https://example.com", 0.8);
        let with_compliance = base.clone().with_compliance(vec![
            "NIST AC-3".into(),
            "PCI-DSS 7.2".into(),
            "HIPAA 312(a)".into(),
            "SOC2 CC6.1".into(),
            "NIST AC-6".into(),
        ]);
        let base_score =
            compute_risk_score(&finding_with(Severity::Medium, "https://example.com", 0.8));
        let compliance_score = compute_risk_score(&with_compliance);
        assert!(compliance_score > base_score, "compliance should increase score");
    }

    /// Cloud targets get exposure score.
    #[test]
    fn test_risk_score_cloud_exposure() {
        let f = finding_with(Severity::High, "cloud://aws:123456789012", 0.9);
        let score = compute_risk_score(&f);
        assert!(score >= 55.0, "cloud high should score well: {score}");
    }

    /// Rank findings sorts by score descending.
    #[test]
    fn test_rank_findings() {
        let findings = vec![
            finding_with(Severity::Low, "file:///x", 0.5),
            finding_with(Severity::Critical, "https://example.com", 0.95),
            finding_with(Severity::Medium, "https://example.com", 0.7),
        ];
        let ranked = rank_findings(&findings);
        assert_eq!(ranked[0].0, 1, "critical should rank first");
        assert_eq!(ranked[2].0, 0, "low should rank last");
    }

    /// Risk grades.
    #[test]
    fn test_risk_grade() {
        assert_eq!(risk_grade(90.0), "A");
        assert_eq!(risk_grade(70.0), "B");
        assert_eq!(risk_grade(50.0), "C");
        assert_eq!(risk_grade(30.0), "D");
        assert_eq!(risk_grade(10.0), "F");
    }

    /// Score is clamped to 0–100.
    #[test]
    fn test_risk_score_clamped() {
        let f = finding_with(Severity::Critical, "https://example.com", 1.0).with_compliance(vec![
            "A".into(),
            "B".into(),
            "C".into(),
            "D".into(),
            "E".into(),
        ]);
        let score = compute_risk_score(&f);
        assert!(score <= 100.0);
        assert!(score >= 0.0);
    }
}
