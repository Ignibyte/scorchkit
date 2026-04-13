//! Tests for scan scheduling types and cron computation.
//!
//! Verifies serde round-trip correctness for `ScanSchedule`,
//! `compute_next_run()` with various cron expressions, and
//! MCP parameter deserialization.

#[cfg(feature = "storage")]
use chrono::{Datelike, TimeZone, Timelike, Utc};

#[cfg(feature = "storage")]
use scorchkit::storage::models::ScanSchedule;

#[cfg(feature = "storage")]
use scorchkit::storage::schedules::{compute_next_run, compute_next_run_after};

/// Verify `ScanSchedule` round-trips through JSON serialization.
#[cfg(feature = "storage")]
#[test]
fn test_scan_schedule_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let schedule = ScanSchedule {
        id: uuid::Uuid::new_v4(),
        project_id: uuid::Uuid::new_v4(),
        target_url: "https://example.com".to_string(),
        profile: "standard".to_string(),
        cron_expression: "0 0 * * *".to_string(),
        enabled: true,
        last_run: None,
        next_run: Utc::now(),
        created_at: Utc::now(),
    };

    let json = serde_json::to_string(&schedule)?;
    let parsed: ScanSchedule = serde_json::from_str(&json)?;

    assert_eq!(parsed.target_url, "https://example.com");
    assert_eq!(parsed.profile, "standard");
    assert_eq!(parsed.cron_expression, "0 0 * * *");
    assert!(parsed.enabled);
    assert!(parsed.last_run.is_none());
    Ok(())
}

/// Verify `compute_next_run` returns Some for a valid cron expression.
#[cfg(feature = "storage")]
#[test]
fn test_compute_next_run_valid() {
    let result = compute_next_run("0 * * * *");
    assert!(result.is_some(), "valid cron should return Some");
    let next = result.unwrap_or_else(|| unreachable!());
    assert!(next > Utc::now(), "next run should be in the future");
}

/// Verify `compute_next_run` returns None for an invalid cron expression.
#[cfg(feature = "storage")]
#[test]
fn test_compute_next_run_invalid() {
    assert!(compute_next_run("not a cron").is_none());
    assert!(compute_next_run("").is_none());
    assert!(compute_next_run("* * *").is_none());
}

/// Verify `compute_next_run_after` for hourly cron produces the next hour boundary.
#[cfg(feature = "storage")]
#[test]
fn test_compute_next_run_every_hour() {
    // "0 * * * *" = at minute 0 of every hour
    let base = Utc.with_ymd_and_hms(2026, 3, 29, 10, 30, 0).unwrap();
    let result = compute_next_run_after("0 * * * *", &base);
    assert!(result.is_some());
    let next = result.unwrap_or_else(|| unreachable!());
    // Should be 11:00 on the same day
    assert_eq!(next.hour(), 11);
    assert_eq!(next.minute(), 0);
}

/// Verify `compute_next_run_after` for daily midnight cron.
#[cfg(feature = "storage")]
#[test]
fn test_compute_next_run_daily() {
    // "0 0 * * *" = daily at midnight
    let base = Utc.with_ymd_and_hms(2026, 3, 29, 15, 0, 0).unwrap();
    let result = compute_next_run_after("0 0 * * *", &base);
    assert!(result.is_some());
    let next = result.unwrap_or_else(|| unreachable!());
    // Should be midnight on March 30
    assert_eq!(next.day(), 30);
    assert_eq!(next.hour(), 0);
    assert_eq!(next.minute(), 0);
}

/// Verify MCP `ScheduleScanParams` deserializes from JSON correctly.
#[cfg(feature = "mcp")]
#[test]
fn test_schedule_scan_params_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"project": "my-project", "target": "https://example.com", "cron": "0 0 * * *"}"#;
    let params: scorchkit::mcp::types::ScheduleScanParams = serde_json::from_str(json)?;
    assert_eq!(params.project, "my-project");
    assert_eq!(params.target, "https://example.com");
    assert_eq!(params.cron, "0 0 * * *");
    assert_eq!(params.profile, "standard"); // default
    Ok(())
}
