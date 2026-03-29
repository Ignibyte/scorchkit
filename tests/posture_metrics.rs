//! Tests for posture metrics types and computed values.
//!
//! Verifies serde round-trip correctness for all metric types,
//! `TrendDirection` computation logic, and `FindingSummary` aggregation
//! from status breakdowns.

#[cfg(feature = "storage")]
use scorchkit::storage::metrics::{
    FindingSummary, PostureMetrics, RegressionFinding, ScanSummary, SeverityCount, StatusCount,
    TrendDirection, UnresolvedFinding,
};

#[cfg(feature = "storage")]
use scorchkit::storage::metrics::compute_finding_summary;

/// Verify `PostureMetrics` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_posture_metrics_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let metrics = PostureMetrics {
        project_name: "test-project".to_string(),
        scan_summary: ScanSummary {
            total_scans: 5,
            latest_scan_date: Some("2026-03-29 12:00".to_string()),
            latest_scan_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            scans_last_30_days: 3,
        },
        finding_summary: FindingSummary {
            total_findings: 10,
            active_findings: 4,
            resolved_findings: 6,
        },
        severity_breakdown: vec![
            SeverityCount { severity: "high".to_string(), count: 3 },
            SeverityCount { severity: "medium".to_string(), count: 7 },
        ],
        status_breakdown: vec![
            StatusCount { status: "new".to_string(), count: 4 },
            StatusCount { status: "remediated".to_string(), count: 6 },
        ],
        regressions: vec![],
        top_unresolved: vec![],
        trend: TrendDirection::Improving,
        mttr_days: None,
    };

    let json = serde_json::to_string(&metrics)?;
    let parsed: PostureMetrics = serde_json::from_str(&json)?;

    assert_eq!(parsed.project_name, "test-project");
    assert_eq!(parsed.finding_summary.total_findings, 10);
    assert_eq!(parsed.trend, TrendDirection::Improving);
    assert!(parsed.mttr_days.is_none());
    Ok(())
}

/// Verify `ScanSummary` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_scan_summary_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let summary = ScanSummary {
        total_scans: 12,
        latest_scan_date: Some("2026-03-28 09:15".to_string()),
        latest_scan_id: Some("abc-123".to_string()),
        scans_last_30_days: 8,
    };

    let json = serde_json::to_string(&summary)?;
    let parsed: ScanSummary = serde_json::from_str(&json)?;

    assert_eq!(parsed.total_scans, 12);
    assert_eq!(parsed.scans_last_30_days, 8);
    assert_eq!(parsed.latest_scan_date.as_deref(), Some("2026-03-28 09:15"));
    Ok(())
}

/// Verify `FindingSummary` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_finding_summary_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let summary = FindingSummary { total_findings: 20, active_findings: 8, resolved_findings: 12 };

    let json = serde_json::to_string(&summary)?;
    let parsed: FindingSummary = serde_json::from_str(&json)?;

    assert_eq!(parsed.total_findings, 20);
    assert_eq!(parsed.active_findings, 8);
    assert_eq!(parsed.resolved_findings, 12);
    Ok(())
}

/// Verify `SeverityCount` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_severity_count_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let sc = SeverityCount { severity: "critical".to_string(), count: 5 };
    let json = serde_json::to_string(&sc)?;
    let parsed: SeverityCount = serde_json::from_str(&json)?;

    assert_eq!(parsed.severity, "critical");
    assert_eq!(parsed.count, 5);
    Ok(())
}

/// Verify `StatusCount` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_status_count_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let sc = StatusCount { status: "acknowledged".to_string(), count: 3 };
    let json = serde_json::to_string(&sc)?;
    let parsed: StatusCount = serde_json::from_str(&json)?;

    assert_eq!(parsed.status, "acknowledged");
    assert_eq!(parsed.count, 3);
    Ok(())
}

/// Verify `RegressionFinding` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_regression_finding_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let rf = RegressionFinding {
        id: "uuid-1".to_string(),
        title: "SQL Injection".to_string(),
        severity: "critical".to_string(),
        module_id: "injection".to_string(),
        affected_target: "https://example.com/login".to_string(),
        previous_status: "remediated".to_string(),
    };

    let json = serde_json::to_string(&rf)?;
    let parsed: RegressionFinding = serde_json::from_str(&json)?;

    assert_eq!(parsed.title, "SQL Injection");
    assert_eq!(parsed.previous_status, "remediated");
    Ok(())
}

/// Verify `UnresolvedFinding` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_unresolved_finding_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let uf = UnresolvedFinding {
        id: "uuid-2".to_string(),
        title: "Missing CSP".to_string(),
        severity: "medium".to_string(),
        status: "new".to_string(),
        first_seen: "2026-03-01 10:00".to_string(),
        seen_count: 4,
    };

    let json = serde_json::to_string(&uf)?;
    let parsed: UnresolvedFinding = serde_json::from_str(&json)?;

    assert_eq!(parsed.title, "Missing CSP");
    assert_eq!(parsed.seen_count, 4);
    Ok(())
}

/// Verify `TrendDirection` round-trips through JSON with snake_case.
#[cfg(feature = "storage")]
#[test]
fn test_trend_direction_serde() -> Result<(), Box<dyn std::error::Error>> {
    let trend = TrendDirection::Improving;
    let json = serde_json::to_string(&trend)?;
    assert_eq!(json, "\"improving\"");

    let parsed: TrendDirection = serde_json::from_str("\"declining\"")?;
    assert_eq!(parsed, TrendDirection::Declining);

    let parsed: TrendDirection = serde_json::from_str("\"stable\"")?;
    assert_eq!(parsed, TrendDirection::Stable);
    Ok(())
}

/// Verify `TrendDirection::label()` returns human-readable strings.
#[cfg(feature = "storage")]
#[test]
fn test_trend_direction_labels() {
    assert_eq!(TrendDirection::Improving.label(), "Improving");
    assert_eq!(TrendDirection::Declining.label(), "Declining");
    assert_eq!(TrendDirection::Stable.label(), "Stable");
}

/// Verify `TrendDirection::compute()` produces correct results for all cases.
#[cfg(feature = "storage")]
#[test]
fn test_trend_direction_compute() {
    // No findings → Stable
    assert_eq!(TrendDirection::compute(0, 0), TrendDirection::Stable);

    // More resolved than active → Improving
    assert_eq!(TrendDirection::compute(2, 5), TrendDirection::Improving);

    // Active but nothing resolved → Declining
    assert_eq!(TrendDirection::compute(5, 0), TrendDirection::Declining);

    // Equal active and resolved → Stable
    assert_eq!(TrendDirection::compute(3, 3), TrendDirection::Stable);

    // More active than resolved → Stable (not declining because some resolved)
    assert_eq!(TrendDirection::compute(5, 2), TrendDirection::Stable);

    // One active, zero resolved → Declining
    assert_eq!(TrendDirection::compute(1, 0), TrendDirection::Declining);

    // Zero active, some resolved → Improving
    assert_eq!(TrendDirection::compute(0, 3), TrendDirection::Improving);
}

/// Verify `compute_finding_summary` correctly aggregates status counts
/// into active and resolved categories.
#[cfg(feature = "storage")]
#[test]
fn test_compute_finding_summary() {
    let statuses = vec![
        StatusCount { status: "new".to_string(), count: 3 },
        StatusCount { status: "acknowledged".to_string(), count: 2 },
        StatusCount { status: "remediated".to_string(), count: 4 },
        StatusCount { status: "verified".to_string(), count: 1 },
        StatusCount { status: "false_positive".to_string(), count: 2 },
    ];

    let summary = compute_finding_summary(&statuses);

    assert_eq!(summary.total_findings, 12);
    assert_eq!(summary.active_findings, 5); // new(3) + acknowledged(2)
    assert_eq!(summary.resolved_findings, 7); // remediated(4) + verified(1) + false_positive(2)
}

/// Verify metrics are valid for a project with zero scans and findings.
#[cfg(feature = "storage")]
#[test]
fn test_posture_metrics_empty_project() -> Result<(), Box<dyn std::error::Error>> {
    let metrics = PostureMetrics {
        project_name: "empty-project".to_string(),
        scan_summary: ScanSummary {
            total_scans: 0,
            latest_scan_date: None,
            latest_scan_id: None,
            scans_last_30_days: 0,
        },
        finding_summary: FindingSummary {
            total_findings: 0,
            active_findings: 0,
            resolved_findings: 0,
        },
        severity_breakdown: vec![],
        status_breakdown: vec![],
        regressions: vec![],
        top_unresolved: vec![],
        trend: TrendDirection::Stable,
        mttr_days: None,
    };

    let json = serde_json::to_string(&metrics)?;
    let parsed: PostureMetrics = serde_json::from_str(&json)?;

    assert_eq!(parsed.scan_summary.total_scans, 0);
    assert_eq!(parsed.finding_summary.total_findings, 0);
    assert_eq!(parsed.trend, TrendDirection::Stable);
    assert!(parsed.severity_breakdown.is_empty());
    Ok(())
}

/// Verify MCP `ProjectStatusParams` deserializes from JSON correctly.
#[cfg(feature = "mcp")]
#[test]
fn test_project_status_params_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"project": "my-project"}"#;
    let params: scorchkit::mcp::types::ProjectStatusParams = serde_json::from_str(json)?;
    assert_eq!(params.project, "my-project");
    Ok(())
}
