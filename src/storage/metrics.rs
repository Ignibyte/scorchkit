//! Posture metrics and trend analysis for security assessment projects.
//!
//! Computes aggregate security posture metrics from existing `scan_records`
//! and `tracked_findings` tables. All metrics are computed on-the-fly via
//! SQL aggregate queries — no additional tables or migrations required.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};

// ── Trend direction ────────────────────────────────────────────────────

/// Overall trend direction for a project's security posture.
///
/// Computed from the ratio of resolved (remediated + verified + `false_positive`)
/// to active (new + acknowledged) findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    /// More findings resolved than active — posture is getting better.
    Improving,
    /// Active findings exist but none resolved — posture is getting worse.
    Declining,
    /// Mixed progress, no findings, or equal active/resolved — no clear trend.
    Stable,
}

impl TrendDirection {
    /// Compute trend direction from active and resolved finding counts.
    ///
    /// - `Improving`: resolved > active (majority addressed)
    /// - `Declining`: active > 0 and resolved == 0 (nothing addressed)
    /// - `Stable`: everything else
    #[must_use]
    pub const fn compute(active: usize, resolved: usize) -> Self {
        if active == 0 && resolved == 0 {
            return Self::Stable;
        }
        if resolved > active {
            return Self::Improving;
        }
        if active > 0 && resolved == 0 {
            return Self::Declining;
        }
        Self::Stable
    }

    /// Human-readable label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Improving => "Improving",
            Self::Declining => "Declining",
            Self::Stable => "Stable",
        }
    }
}

// ── Metric types ───────────────────────────────────────────────────────

/// Complete posture metrics for a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureMetrics {
    /// Project name.
    pub project_name: String,
    /// Scan execution summary.
    pub scan_summary: ScanSummary,
    /// High-level finding counts.
    pub finding_summary: FindingSummary,
    /// Finding counts grouped by severity, ordered critical to info.
    pub severity_breakdown: Vec<SeverityCount>,
    /// Finding counts grouped by lifecycle status.
    pub status_breakdown: Vec<StatusCount>,
    /// Findings previously remediated/verified that reappeared in the latest scan.
    pub regressions: Vec<RegressionFinding>,
    /// Top 10 active findings ordered by severity priority.
    pub top_unresolved: Vec<UnresolvedFinding>,
    /// Overall posture trend direction.
    pub trend: TrendDirection,
    /// Mean time to remediate in days. Currently always `None` because
    /// the schema lacks a `status_changed_at` column on `tracked_findings`.
    pub mttr_days: Option<f64>,
}

/// Scan execution summary for a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total number of scans ever run.
    pub total_scans: usize,
    /// Date of the most recent scan, if any.
    pub latest_scan_date: Option<String>,
    /// UUID of the most recent scan, if any.
    pub latest_scan_id: Option<String>,
    /// Number of scans in the last 30 days.
    pub scans_last_30_days: usize,
}

/// High-level finding count summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Total tracked findings across all scans.
    pub total_findings: usize,
    /// Findings that are new or acknowledged (not yet resolved).
    pub active_findings: usize,
    /// Findings that are remediated, verified, or false positive.
    pub resolved_findings: usize,
}

/// Count of findings at a particular severity level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCount {
    /// Severity level (critical, high, medium, low, info).
    pub severity: String,
    /// Number of findings at this severity.
    pub count: usize,
}

/// Count of findings in a particular lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusCount {
    /// Lifecycle status (new, acknowledged, `false_positive`, remediated, verified).
    pub status: String,
    /// Number of findings in this status.
    pub count: usize,
}

/// A finding that regressed — was remediated or verified but reappeared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionFinding {
    /// Finding UUID.
    pub id: String,
    /// Finding title.
    pub title: String,
    /// Severity level.
    pub severity: String,
    /// Module that detected this finding.
    pub module_id: String,
    /// The affected URL, parameter, or resource.
    pub affected_target: String,
    /// The status before regression (remediated or verified).
    pub previous_status: String,
}

/// An active finding that has not been resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedFinding {
    /// Finding UUID.
    pub id: String,
    /// Finding title.
    pub title: String,
    /// Severity level.
    pub severity: String,
    /// Current lifecycle status (new or acknowledged).
    pub status: String,
    /// When this finding was first detected.
    pub first_seen: String,
    /// How many scans have detected this finding.
    pub seen_count: i32,
}

// ── Query function ─────────────────────────────────────────────────────

/// Build complete posture metrics for a project.
///
/// Runs aggregate SQL queries against `scan_records` and `tracked_findings`
/// to compute all metrics on-the-fly. No additional tables required.
///
/// # Errors
///
/// Returns an error if any database query fails.
pub async fn build_posture_metrics(
    pool: &PgPool,
    project_id: Uuid,
    project_name: &str,
) -> Result<PostureMetrics> {
    let scan_summary = query_scan_summary(pool, project_id).await?;
    let severity_breakdown = query_severity_breakdown(pool, project_id).await?;
    let status_breakdown = query_status_breakdown(pool, project_id).await?;
    let finding_summary = compute_finding_summary(&status_breakdown);
    let regressions = query_regressions(pool, project_id).await?;
    let top_unresolved = query_top_unresolved(pool, project_id).await?;
    let trend =
        TrendDirection::compute(finding_summary.active_findings, finding_summary.resolved_findings);

    Ok(PostureMetrics {
        project_name: project_name.to_string(),
        scan_summary,
        finding_summary,
        severity_breakdown,
        status_breakdown,
        regressions,
        top_unresolved,
        trend,
        mttr_days: None,
    })
}

/// Query scan execution summary.
// JUSTIFICATION: PostgreSQL COUNT(*) returns i64. Row counts will never
// exceed usize::MAX on any supported target (even 32-bit).
#[allow(clippy::cast_possible_truncation)]
async fn query_scan_summary(pool: &PgPool, project_id: Uuid) -> Result<ScanSummary> {
    let total_scans: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scan_records WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("count scans: {e}")))?;

    let latest: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, to_char(started_at, 'YYYY-MM-DD HH24:MI') as started \
         FROM scan_records WHERE project_id = $1 \
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("latest scan: {e}")))?;

    let scans_last_30: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_records \
         WHERE project_id = $1 AND started_at >= now() - interval '30 days'",
    )
    .bind(project_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("scans last 30 days: {e}")))?;

    Ok(ScanSummary {
        total_scans: total_scans.unsigned_abs() as usize,
        latest_scan_date: latest.as_ref().map(|(_, d)| d.clone()),
        latest_scan_id: latest.as_ref().map(|(id, _)| id.to_string()),
        scans_last_30_days: scans_last_30.unsigned_abs() as usize,
    })
}

/// Query finding counts grouped by severity, ordered by priority.
// JUSTIFICATION: PostgreSQL COUNT(*) returns i64. Row counts will never
// exceed usize::MAX on any supported target.
#[allow(clippy::cast_possible_truncation)]
async fn query_severity_breakdown(pool: &PgPool, project_id: Uuid) -> Result<Vec<SeverityCount>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) as cnt FROM tracked_findings \
         WHERE project_id = $1 GROUP BY severity \
         ORDER BY CASE severity \
           WHEN 'critical' THEN 1 \
           WHEN 'high' THEN 2 \
           WHEN 'medium' THEN 3 \
           WHEN 'low' THEN 4 \
           WHEN 'info' THEN 5 \
           ELSE 6 END",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("severity breakdown: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(severity, count)| SeverityCount { severity, count: count.unsigned_abs() as usize })
        .collect())
}

/// Query finding counts grouped by lifecycle status.
// JUSTIFICATION: PostgreSQL COUNT(*) returns i64. Row counts will never
// exceed usize::MAX on any supported target.
#[allow(clippy::cast_possible_truncation)]
async fn query_status_breakdown(pool: &PgPool, project_id: Uuid) -> Result<Vec<StatusCount>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) as cnt FROM tracked_findings \
         WHERE project_id = $1 GROUP BY status \
         ORDER BY CASE status \
           WHEN 'new' THEN 1 \
           WHEN 'acknowledged' THEN 2 \
           WHEN 'remediated' THEN 3 \
           WHEN 'verified' THEN 4 \
           WHEN 'false_positive' THEN 5 \
           ELSE 6 END",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("status breakdown: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(status, count)| StatusCount { status, count: count.unsigned_abs() as usize })
        .collect())
}

/// Compute the high-level finding summary from the status breakdown.
#[must_use]
pub fn compute_finding_summary(status_breakdown: &[StatusCount]) -> FindingSummary {
    let mut total = 0usize;
    let mut active = 0usize;
    let mut resolved = 0usize;

    for sc in status_breakdown {
        total += sc.count;
        match sc.status.as_str() {
            "new" | "acknowledged" => active += sc.count,
            "remediated" | "verified" | "false_positive" => resolved += sc.count,
            _ => {}
        }
    }

    FindingSummary { total_findings: total, active_findings: active, resolved_findings: resolved }
}

/// Query findings that regressed — status is remediated/verified but
/// reappeared in the project's latest scan.
async fn query_regressions(pool: &PgPool, project_id: Uuid) -> Result<Vec<RegressionFinding>> {
    let rows: Vec<(Uuid, String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, title, severity, module_id, affected_target, status \
         FROM tracked_findings \
         WHERE project_id = $1 \
           AND status IN ('remediated', 'verified') \
           AND scan_id = ( \
             SELECT id FROM scan_records \
             WHERE project_id = $1 \
             ORDER BY started_at DESC LIMIT 1 \
           ) \
         ORDER BY CASE severity \
           WHEN 'critical' THEN 1 \
           WHEN 'high' THEN 2 \
           WHEN 'medium' THEN 3 \
           WHEN 'low' THEN 4 \
           WHEN 'info' THEN 5 \
           ELSE 6 END",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("regressions: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(id, title, severity, module_id, affected_target, status)| RegressionFinding {
            id: id.to_string(),
            title,
            severity,
            module_id,
            affected_target,
            previous_status: status,
        })
        .collect())
}

/// Query top 10 active (new/acknowledged) findings by severity priority.
async fn query_top_unresolved(pool: &PgPool, project_id: Uuid) -> Result<Vec<UnresolvedFinding>> {
    let rows: Vec<(Uuid, String, String, String, String, i32)> = sqlx::query_as(
        "SELECT id, title, severity, status, \
                to_char(first_seen, 'YYYY-MM-DD HH24:MI') as first, \
                seen_count \
         FROM tracked_findings \
         WHERE project_id = $1 \
           AND status IN ('new', 'acknowledged') \
         ORDER BY CASE severity \
           WHEN 'critical' THEN 1 \
           WHEN 'high' THEN 2 \
           WHEN 'medium' THEN 3 \
           WHEN 'low' THEN 4 \
           WHEN 'info' THEN 5 \
           ELSE 6 END, last_seen DESC \
         LIMIT 10",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("top unresolved: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(id, title, severity, status, first_seen, seen_count)| UnresolvedFinding {
            id: id.to_string(),
            title,
            severity,
            status,
            first_seen,
            seen_count,
        })
        .collect())
}
