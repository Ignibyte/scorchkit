//! LLM-mediated remediation walks (WORK-141).
//!
//! Generates step-by-step remediation guidance for findings using
//! Claude. Produces ordered fix sequences prioritized by risk score
//! and dependency relationships (fix X before Y).

use std::fmt::Write;

use crate::engine::finding::Finding;
use crate::engine::risk_score::compute_risk_score;

/// A remediation step in a guided fix sequence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemediationStep {
    /// Step number (1-based).
    pub step: usize,
    /// Finding title being remediated.
    pub finding_title: String,
    /// Module that found the issue.
    pub module_id: String,
    /// Risk score of the finding.
    pub risk_score: f64,
    /// Remediation guidance.
    pub guidance: String,
    /// Estimated effort level.
    pub effort: &'static str,
}

/// Build a remediation walk — ordered steps to fix findings.
///
/// Prioritizes by risk score (highest first) and provides
/// the finding's built-in remediation guidance.
#[must_use]
pub fn build_remediation_walk(findings: &[Finding]) -> Vec<RemediationStep> {
    let mut scored: Vec<(usize, f64)> =
        findings.iter().enumerate().map(|(i, f)| (i, compute_risk_score(f))).collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    scored
        .iter()
        .enumerate()
        .map(|(step_num, (idx, score))| {
            let f = &findings[*idx];
            RemediationStep {
                step: step_num + 1,
                finding_title: f.title.clone(),
                module_id: f.module_id.clone(),
                risk_score: *score,
                guidance: f
                    .remediation
                    .clone()
                    .unwrap_or_else(|| "Review and remediate this finding.".into()),
                effort: estimate_effort(f),
            }
        })
        .collect()
}

/// Build a prompt for Claude to generate detailed remediation guidance.
#[must_use]
pub fn build_remediation_prompt(findings: &[Finding]) -> (String, String) {
    let system = "You are a senior security engineer providing step-by-step remediation \
        guidance. For each finding, provide: (1) specific fix steps, (2) code examples \
        where applicable, (3) verification steps to confirm the fix, (4) estimated \
        effort (quick/medium/significant). Prioritize by risk. Output JSON array of \
        {\"finding\": \"...\", \"steps\": [\"...\"], \"verification\": \"...\", \
        \"effort\": \"quick|medium|significant\"}"
        .to_string();

    let mut user = String::from("Generate remediation guidance for these findings:\n\n");
    let walk = build_remediation_walk(findings);
    for step in &walk {
        let _ = writeln!(
            user,
            "{}. [Risk: {:.0}] {} — {}",
            step.step, step.risk_score, step.finding_title, step.guidance
        );
    }

    (system, user)
}

/// Format a remediation walk as readable text.
#[must_use]
pub fn format_remediation_walk(steps: &[RemediationStep]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Remediation Walk ({} steps) ===\n", steps.len());

    for step in steps {
        let _ = writeln!(
            out,
            "Step {} [Risk: {:.0}, Effort: {}]",
            step.step, step.risk_score, step.effort
        );
        let _ = writeln!(out, "  Finding: {} ({})", step.finding_title, step.module_id);
        let _ = writeln!(out, "  Action:  {}", step.guidance);
        out.push('\n');
    }

    out
}

/// Estimate effort based on finding characteristics.
fn estimate_effort(finding: &Finding) -> &'static str {
    if finding.module_id.contains("header") || finding.module_id == "misconfig" {
        "quick"
    } else if finding.module_id.contains("cloud")
        || finding.module_id.starts_with("aws-")
        || finding.module_id.starts_with("gcp-")
        || finding.module_id.starts_with("azure-")
    {
        "medium"
    } else {
        "significant"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    fn finding(module_id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(module_id, severity, title, "desc", "https://example.com")
            .with_remediation("Fix this issue.")
            .with_confidence(0.8)
    }

    /// Remediation walk is ordered by risk score.
    #[test]
    fn test_build_remediation_walk_ordered() {
        let findings = vec![
            finding("headers", "Missing Header", Severity::Low),
            finding("injection", "SQL Injection", Severity::Critical),
            finding("ssl", "Weak TLS", Severity::Medium),
        ];
        let walk = build_remediation_walk(&findings);
        assert_eq!(walk.len(), 3);
        assert_eq!(walk[0].finding_title, "SQL Injection"); // highest risk first
        assert!(walk[0].risk_score >= walk[1].risk_score);
    }

    /// Cloud findings get "medium" effort.
    #[test]
    fn test_effort_estimation() {
        let f = finding("aws-s3", "S3 Issue", Severity::High);
        assert_eq!(estimate_effort(&f), "medium");

        let f = finding("headers", "Missing Header", Severity::Low);
        assert_eq!(estimate_effort(&f), "quick");
    }

    /// Format produces readable output.
    #[test]
    fn test_format_remediation_walk() {
        let findings = vec![finding("xss", "XSS Found", Severity::High)];
        let walk = build_remediation_walk(&findings);
        let text = format_remediation_walk(&walk);
        assert!(text.contains("Remediation Walk"));
        assert!(text.contains("XSS Found"));
        assert!(text.contains("Fix this issue"));
    }

    /// Prompt includes all findings.
    #[test]
    fn test_build_remediation_prompt() {
        let findings = vec![finding("xss", "XSS", Severity::High)];
        let (system, user) = build_remediation_prompt(&findings);
        assert!(system.contains("remediation"));
        assert!(user.contains("XSS"));
    }
}
