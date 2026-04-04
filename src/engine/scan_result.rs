use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::finding::Finding;
use super::severity::Severity;
use super::target::Target;

/// Aggregated results from a complete scan.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique scan identifier.
    pub scan_id: String,
    /// The target that was scanned.
    pub target: Target,
    /// When the scan started.
    pub started_at: DateTime<Utc>,
    /// When the scan completed.
    pub completed_at: DateTime<Utc>,
    /// All findings from all modules.
    pub findings: Vec<Finding>,
    /// Which modules were run.
    pub modules_run: Vec<String>,
    /// Which modules were skipped (`module_id`, reason).
    pub modules_skipped: Vec<(String, String)>,
    /// Summary statistics.
    pub summary: ScanSummary,
}

/// Summary statistics for a scan.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanSummary {
    /// Build a summary from a list of findings.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self {
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        };
        for f in findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }
}

impl ScanResult {
    /// Create a new `ScanResult` with computed summary.
    #[must_use]
    pub fn new(
        scan_id: String,
        target: Target,
        started_at: DateTime<Utc>,
        findings: Vec<Finding>,
        modules_run: Vec<String>,
        modules_skipped: Vec<(String, String)>,
    ) -> Self {
        let summary = ScanSummary::from_findings(&findings);
        Self {
            scan_id,
            target,
            started_at,
            completed_at: Utc::now(),
            findings,
            modules_run,
            modules_skipped,
            summary,
        }
    }

    /// Remove findings below the given confidence threshold and recompute the summary.
    ///
    /// Findings with confidence >= `min_confidence` are kept.
    pub fn filter_by_confidence(&mut self, min_confidence: f64) {
        self.findings.retain(|f| f.confidence >= min_confidence);
        self.summary = ScanSummary::from_findings(&self.findings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::target::Target;

    /// Helper to build a test `ScanResult` with findings at varying confidence levels.
    fn test_result_with_confidences(confidences: &[(Severity, f64)]) -> ScanResult {
        let target = Target::parse("https://example.com").expect("valid target");
        let findings: Vec<Finding> = confidences
            .iter()
            .enumerate()
            .map(|(i, (sev, conf))| {
                Finding::new("test", *sev, format!("Finding {i}"), "desc", "url")
                    .with_confidence(*conf)
            })
            .collect();
        let now = chrono::Utc::now();
        ScanResult {
            scan_id: "test".to_string(),
            target,
            started_at: now,
            completed_at: now,
            modules_run: vec!["test".to_string()],
            modules_skipped: Vec::new(),
            summary: ScanSummary::from_findings(&findings),
            findings,
        }
    }

    /// Verify that `filter_by_confidence` removes findings below the threshold.
    #[test]
    fn filter_by_confidence_removes_below() {
        let mut result = test_result_with_confidences(&[
            (Severity::High, 0.9),
            (Severity::Medium, 0.5),
            (Severity::Low, 0.3),
        ]);
        result.filter_by_confidence(0.5);
        assert_eq!(result.findings.len(), 2);
        assert!(result.findings.iter().all(|f| f.confidence >= 0.5));
    }

    /// Verify that the summary is recomputed after filtering by confidence.
    #[test]
    fn filter_by_confidence_recomputes_summary() {
        let mut result = test_result_with_confidences(&[
            (Severity::Critical, 0.9),
            (Severity::High, 0.8),
            (Severity::Low, 0.2),
        ]);
        assert_eq!(result.summary.total_findings, 3);

        result.filter_by_confidence(0.5);
        assert_eq!(result.summary.total_findings, 2);
        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.high, 1);
        assert_eq!(result.summary.low, 0);
    }

    /// Verify that findings exactly at the threshold are kept (>= semantics).
    #[test]
    fn filter_by_confidence_keeps_at_threshold() {
        let mut result = test_result_with_confidences(&[
            (Severity::High, 0.7),
            (Severity::Medium, 0.7),
            (Severity::Low, 0.6),
        ]);
        result.filter_by_confidence(0.7);
        assert_eq!(result.findings.len(), 2);
    }
}
