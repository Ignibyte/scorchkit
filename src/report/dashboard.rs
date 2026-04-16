//! Executive dashboard — posture metrics + risk grade (WORK-140).
//!
//! Generates a one-page executive summary from scan findings,
//! compliance reports, and attack chains. Outputs text and HTML.

use std::fmt::Write;

use crate::engine::compliance_framework::ComplianceReport;
use crate::engine::correlation::AttackChain;
use crate::engine::finding::Finding;
use crate::engine::risk_score::{compute_risk_score, risk_grade};
use crate::engine::severity::Severity;

/// Executive dashboard data.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Dashboard {
    /// Overall risk grade (A–F).
    pub risk_grade: String,
    /// Average risk score (0–100).
    pub avg_risk_score: f64,
    /// Finding counts by severity.
    pub severity_counts: SeverityCounts,
    /// Number of attack chains identified.
    pub attack_chain_count: usize,
    /// Top 5 highest-risk findings.
    pub top_findings: Vec<TopFinding>,
    /// Per-framework compliance percentages.
    pub compliance_summary: Vec<ComplianceSummary>,
}

/// Finding counts by severity level.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SeverityCounts {
    /// Critical findings.
    pub critical: usize,
    /// High findings.
    pub high: usize,
    /// Medium findings.
    pub medium: usize,
    /// Low findings.
    pub low: usize,
    /// Informational findings.
    pub info: usize,
}

/// A high-risk finding for the top-5 list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TopFinding {
    /// Finding title.
    pub title: String,
    /// Module that produced it.
    pub module_id: String,
    /// Risk score.
    pub risk_score: f64,
    /// Severity.
    pub severity: String,
}

/// Compliance summary for one framework.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComplianceSummary {
    /// Framework name.
    pub framework: String,
    /// Compliance percentage.
    pub compliance_pct: f64,
    /// Number of failing controls.
    pub fail_count: usize,
}

/// Build an executive dashboard from findings, compliance report, and attack chains.
#[must_use]
pub fn build_dashboard(
    findings: &[Finding],
    compliance: Option<&ComplianceReport>,
    chains: &[AttackChain],
) -> Dashboard {
    let risk_values: Vec<f64> = findings.iter().map(compute_risk_score).collect();
    // JUSTIFICATION: finding count is small; f64 precision is not a concern.
    #[allow(clippy::cast_precision_loss)]
    let avg_score = if risk_values.is_empty() {
        0.0
    } else {
        risk_values.iter().sum::<f64>() / risk_values.len() as f64
    };

    let severity_counts = SeverityCounts {
        critical: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high: findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low: findings.iter().filter(|f| f.severity == Severity::Low).count(),
        info: findings.iter().filter(|f| f.severity == Severity::Info).count(),
    };

    let mut ranked: Vec<(usize, f64)> = risk_values.into_iter().enumerate().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let top_findings: Vec<TopFinding> = ranked
        .iter()
        .take(5)
        .map(|(i, score)| {
            let f = &findings[*i];
            TopFinding {
                title: f.title.clone(),
                module_id: f.module_id.clone(),
                risk_score: *score,
                severity: f.severity.to_string(),
            }
        })
        .collect();

    let compliance_summary = compliance
        .map(|r| {
            r.frameworks
                .iter()
                .map(|fw| ComplianceSummary {
                    framework: fw.framework_name.clone(),
                    compliance_pct: fw.compliance_pct,
                    fail_count: fw.fail_count,
                })
                .collect()
        })
        .unwrap_or_default();

    Dashboard {
        risk_grade: risk_grade(avg_score).to_string(),
        avg_risk_score: avg_score,
        severity_counts,
        attack_chain_count: chains.len(),
        top_findings,
        compliance_summary,
    }
}

/// Format a dashboard as a text summary.
#[must_use]
pub fn format_dashboard(dash: &Dashboard) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "╔══════════════════════════════════════╗");
    let _ = writeln!(out, "║     EXECUTIVE SECURITY DASHBOARD     ║");
    let _ = writeln!(out, "╠══════════════════════════════════════╣");
    let _ = writeln!(out, "║  Risk Grade:  {}                      ║", dash.risk_grade);
    let _ = writeln!(out, "║  Avg Score:   {:.1}/100               ║", dash.avg_risk_score);
    let _ = writeln!(out, "╠══════════════════════════════════════╣");
    let _ = writeln!(
        out,
        "║  Critical: {}  High: {}  Medium: {}  ║",
        dash.severity_counts.critical, dash.severity_counts.high, dash.severity_counts.medium
    );
    let _ = writeln!(
        out,
        "║  Low: {}  Info: {}                   ║",
        dash.severity_counts.low, dash.severity_counts.info
    );
    let _ = writeln!(out, "║  Attack Chains: {}                   ║", dash.attack_chain_count);
    let _ = writeln!(out, "╠══════════════════════════════════════╣");

    if !dash.top_findings.is_empty() {
        let _ = writeln!(out, "║  Top Findings:                       ║");
        for (i, tf) in dash.top_findings.iter().enumerate() {
            let _ = writeln!(out, "║  {}. [{:.0}] {} ║", i + 1, tf.risk_score, tf.title);
        }
    }

    if !dash.compliance_summary.is_empty() {
        let _ = writeln!(out, "╠══════════════════════════════════════╣");
        let _ = writeln!(out, "║  Compliance:                         ║");
        for cs in &dash.compliance_summary {
            let _ = writeln!(
                out,
                "║  {}: {:.1}% ({} fail)  ║",
                cs.framework, cs.compliance_pct, cs.fail_count
            );
        }
    }

    let _ = writeln!(out, "╚══════════════════════════════════════╝");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_finding(severity: Severity, title: &str) -> Finding {
        Finding::new("test", severity, title, "desc", "https://example.com").with_confidence(0.8)
    }

    /// Dashboard computes correct severity counts.
    #[test]
    fn test_dashboard_severity_counts() {
        let findings = vec![
            test_finding(Severity::Critical, "Critical Issue"),
            test_finding(Severity::High, "High Issue"),
            test_finding(Severity::Medium, "Medium Issue"),
            test_finding(Severity::Low, "Low Issue"),
        ];
        let dash = build_dashboard(&findings, None, &[]);
        assert_eq!(dash.severity_counts.critical, 1);
        assert_eq!(dash.severity_counts.high, 1);
        assert_eq!(dash.severity_counts.medium, 1);
        assert_eq!(dash.severity_counts.low, 1);
    }

    /// Dashboard top 5 includes highest-risk findings.
    #[test]
    fn test_dashboard_top_findings() {
        let findings = vec![
            test_finding(Severity::Info, "Info"),
            test_finding(Severity::Critical, "Critical"),
            test_finding(Severity::Low, "Low"),
        ];
        let dash = build_dashboard(&findings, None, &[]);
        assert_eq!(dash.top_findings.len(), 3);
        assert_eq!(dash.top_findings[0].severity, "critical");
    }

    /// Empty findings → grade F.
    #[test]
    fn test_dashboard_empty() {
        let dash = build_dashboard(&[], None, &[]);
        assert_eq!(dash.risk_grade, "F");
        assert_eq!(dash.severity_counts.critical, 0);
    }

    /// Format produces readable output.
    #[test]
    fn test_format_dashboard() {
        let findings = vec![test_finding(Severity::High, "High Risk Finding")];
        let dash = build_dashboard(&findings, None, &[]);
        let text = format_dashboard(&dash);
        assert!(text.contains("EXECUTIVE SECURITY DASHBOARD"));
        assert!(text.contains("Risk Grade"));
    }

    /// Dashboard serializes to JSON.
    #[test]
    fn test_dashboard_json() {
        let dash = build_dashboard(&[], None, &[]);
        let json = serde_json::to_string(&dash).expect("serialize");
        assert!(json.contains("risk_grade"));
    }
}
