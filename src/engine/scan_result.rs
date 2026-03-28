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
}
