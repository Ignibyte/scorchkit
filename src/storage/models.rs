//! Data models for persistent storage.
//!
//! These types map directly to database tables and are used by the
//! storage CRUD modules. They are separate from the engine types
//! to maintain a clean abstraction boundary between the scan engine
//! and the persistence layer.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A security assessment project — a named scope containing targets,
/// scans, and tracked findings.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Project {
    /// Unique project identifier.
    pub id: Uuid,
    /// Human-readable project name (unique).
    pub name: String,
    /// Optional description of the project scope.
    pub description: String,
    /// Arbitrary settings stored as JSON (scan profiles, auth, etc.).
    pub settings: serde_json::Value,
    /// When the project was created.
    pub created_at: DateTime<Utc>,
    /// When the project was last updated.
    pub updated_at: DateTime<Utc>,
}

/// A target URL associated with a project.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProjectTarget {
    /// Unique target identifier.
    pub id: Uuid,
    /// The owning project.
    pub project_id: Uuid,
    /// Target URL.
    pub url: String,
    /// Optional human-readable label.
    pub label: String,
    /// When this target was added.
    pub created_at: DateTime<Utc>,
}

/// A record of a single scan execution.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanRecord {
    /// Unique scan identifier.
    pub id: Uuid,
    /// The project this scan belongs to.
    pub project_id: Uuid,
    /// The URL that was scanned.
    pub target_url: String,
    /// Scan profile used (quick, standard, thorough).
    pub profile: String,
    /// When the scan started.
    pub started_at: DateTime<Utc>,
    /// When the scan completed (None if still running).
    pub completed_at: Option<DateTime<Utc>>,
    /// Module IDs that were executed.
    pub modules_run: Vec<String>,
    /// Module IDs that were skipped.
    pub modules_skipped: Vec<String>,
    /// Summary statistics as JSON.
    pub summary: serde_json::Value,
    /// When this record was created.
    pub created_at: DateTime<Utc>,
}

/// A tracked vulnerability finding with lifecycle management.
///
/// Findings are deduplicated across scans using a fingerprint hash.
/// The same vulnerability found in multiple scans increments `seen_count`
/// and updates `last_seen` rather than creating duplicates.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TrackedFinding {
    /// Unique finding identifier.
    pub id: Uuid,
    /// The scan that last detected this finding.
    pub scan_id: Uuid,
    /// The project this finding belongs to.
    pub project_id: Uuid,
    /// Stable dedup hash: SHA-256(module_id || title || `affected_target`).
    pub fingerprint: String,
    /// Which module produced this finding.
    pub module_id: String,
    /// Severity level as string (critical, high, medium, low, info).
    pub severity: String,
    /// Short title of the finding.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// The affected URL, parameter, or resource.
    pub affected_target: String,
    /// Raw evidence from the scan.
    pub evidence: Option<String>,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// OWASP category (e.g., "A01:2021").
    pub owasp_category: Option<String>,
    /// CWE identifier.
    pub cwe_id: Option<i32>,
    /// Full original finding as JSON for lossless round-tripping.
    pub raw_finding: serde_json::Value,
    /// Confidence score (0.0–1.0) indicating false-positive likelihood.
    pub confidence: f64,
    /// When this finding was first detected.
    pub first_seen: DateTime<Utc>,
    /// When this finding was most recently detected.
    pub last_seen: DateTime<Utc>,
    /// How many scans have detected this finding.
    pub seen_count: i32,
    /// Current lifecycle status.
    pub status: String,
    /// Rationale for the current status (e.g., why it's `false_positive` or `wont_fix`).
    pub status_note: Option<String>,
    /// Timestamp of initial detection.
    pub found_at: DateTime<Utc>,
}

/// Vulnerability lifecycle status.
///
/// Tracks the progression of a finding from initial detection
/// through acknowledgement, resolution, and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnStatus {
    /// Newly detected, not yet reviewed.
    New,
    /// Reviewed and acknowledged as a real issue.
    Acknowledged,
    /// Determined to be a false positive.
    FalsePositive,
    /// Known issue, deliberately not fixing (with rationale).
    WontFix,
    /// Risk accepted — real issue but mitigated by other controls.
    AcceptedRisk,
    /// Fix has been applied.
    Remediated,
    /// Fix verified by a subsequent scan.
    Verified,
}

impl VulnStatus {
    /// Convert from a database string value.
    ///
    /// Returns `None` for unrecognized values.
    #[must_use]
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "new" => Some(Self::New),
            "acknowledged" => Some(Self::Acknowledged),
            "false_positive" => Some(Self::FalsePositive),
            "wont_fix" => Some(Self::WontFix),
            "accepted_risk" => Some(Self::AcceptedRisk),
            "remediated" => Some(Self::Remediated),
            "verified" => Some(Self::Verified),
            _ => None,
        }
    }

    /// Convert to the database string representation.
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Acknowledged => "acknowledged",
            Self::FalsePositive => "false_positive",
            Self::WontFix => "wont_fix",
            Self::AcceptedRisk => "accepted_risk",
            Self::Remediated => "remediated",
            Self::Verified => "verified",
        }
    }
}

impl fmt::Display for VulnStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_db_str())
    }
}

/// A recurring scan schedule for a project.
///
/// Defines a target URL, scan profile, and cron expression for
/// automated recurring scans. Schedules are triggered explicitly
/// via `schedule run-due` CLI or `run-due-scans` MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanSchedule {
    /// Unique schedule identifier.
    pub id: Uuid,
    /// The project this schedule belongs to.
    pub project_id: Uuid,
    /// Target URL to scan.
    pub target_url: String,
    /// Scan profile (quick, standard, thorough).
    pub profile: String,
    /// Cron expression defining the recurrence pattern.
    pub cron_expression: String,
    /// Whether this schedule is active.
    pub enabled: bool,
    /// When this schedule was last executed.
    pub last_run: Option<DateTime<Utc>>,
    /// When this schedule should next execute.
    pub next_run: DateTime<Utc>,
    /// When this schedule was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify VulnStatus round-trips through database string
    /// representation without data loss.
    #[test]
    fn vuln_status_round_trip() {
        let statuses = [
            VulnStatus::New,
            VulnStatus::Acknowledged,
            VulnStatus::FalsePositive,
            VulnStatus::WontFix,
            VulnStatus::AcceptedRisk,
            VulnStatus::Remediated,
            VulnStatus::Verified,
        ];
        for status in statuses {
            let db_str = status.as_db_str();
            let parsed = VulnStatus::from_db(db_str);
            assert_eq!(parsed, Some(status), "round-trip failed for {db_str}");
        }
    }

    /// Verify unrecognized strings return None instead of panicking.
    #[test]
    fn vuln_status_unknown_returns_none() {
        assert_eq!(VulnStatus::from_db("unknown"), None);
        assert_eq!(VulnStatus::from_db(""), None);
    }

    /// Verify Display impl matches database string.
    #[test]
    fn vuln_status_display() {
        assert_eq!(VulnStatus::New.to_string(), "new");
        assert_eq!(VulnStatus::FalsePositive.to_string(), "false_positive");
    }
}
