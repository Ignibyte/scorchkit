//! Project intelligence — per-module effectiveness tracking.
//!
//! Computes and persists module-level scan statistics in the
//! `Project.settings` JSONB field. No new migrations required.
//! Intelligence accumulates across scans, enabling data-driven
//! module selection and AI planner enhancement.

use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::engine::error::{Result, ScorchError};
use crate::engine::scan_result::ScanResult;
use crate::engine::severity::Severity;

/// Per-module effectiveness statistics accumulated across scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStats {
    /// Number of scans this module was executed in.
    pub total_runs: u32,
    /// Total findings produced across all runs.
    pub total_findings: u32,
    /// Critical severity findings.
    pub critical: u32,
    /// High severity findings.
    pub high: u32,
    /// Medium severity findings.
    pub medium: u32,
    /// Low severity findings.
    pub low: u32,
    /// Informational findings.
    pub info: u32,
    /// Effectiveness score: `total_findings / total_runs`. Zero if no runs.
    pub effectiveness_score: f64,
}

impl Default for ModuleStats {
    fn default() -> Self {
        Self {
            total_runs: 0,
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            effectiveness_score: 0.0,
        }
    }
}

impl ModuleStats {
    /// Recompute the effectiveness score from current totals.
    pub fn recompute_score(&mut self) {
        self.effectiveness_score = if self.total_runs > 0 {
            f64::from(self.total_findings) / f64::from(self.total_runs)
        } else {
            0.0
        };
    }

    /// Record that this module ran in a scan, producing findings with given severities.
    pub fn record_run(&mut self, critical: u32, high: u32, medium: u32, low: u32, info: u32) {
        self.total_runs += 1;
        let findings = critical + high + medium + low + info;
        self.total_findings += findings;
        self.critical += critical;
        self.high += high;
        self.medium += medium;
        self.low += low;
        self.info += info;
        self.recompute_score();
    }
}

/// Structured target fingerprint for machine consumption.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetProfile {
    /// Server software (e.g., "nginx/1.24").
    pub server: Option<String>,
    /// Detected technologies (e.g., \["PHP", "jQuery"\]).
    pub technologies: Vec<String>,
    /// Content management system (e.g., "`WordPress`").
    pub cms: Option<String>,
    /// Web application firewall (e.g., "Cloudflare").
    pub waf: Option<String>,
    /// Whether the target uses HTTPS.
    pub is_https: bool,
}

/// Aggregated project intelligence stored in `Project.settings`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectIntelligence {
    /// Per-module effectiveness statistics keyed by module ID.
    pub modules: HashMap<String, ModuleStats>,
    /// Structured target fingerprint from init or first scan.
    pub target_profile: Option<TargetProfile>,
    /// Total number of scans contributing to these statistics.
    pub total_scans: u32,
    /// ISO 8601 datetime of last intelligence update.
    pub last_updated: Option<String>,
}

impl ProjectIntelligence {
    /// Parse intelligence from a project's settings JSON.
    /// Returns default if the JSON doesn't contain intelligence data.
    #[must_use]
    pub fn from_settings(settings: &serde_json::Value) -> Self {
        settings
            .get("intelligence")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// Serialize intelligence back into a settings JSON value.
    /// Merges into an existing settings object, preserving other keys.
    #[must_use]
    pub fn to_settings(&self, existing: &serde_json::Value) -> serde_json::Value {
        let mut settings = existing.clone();
        if let Some(obj) = settings.as_object_mut() {
            if let Ok(intel_value) = serde_json::to_value(self) {
                obj.insert("intelligence".to_string(), intel_value);
            }
        } else {
            // If settings isn't an object, create one
            let mut obj = serde_json::Map::new();
            if let Ok(intel_value) = serde_json::to_value(self) {
                obj.insert("intelligence".to_string(), intel_value);
            }
            settings = serde_json::Value::Object(obj);
        }
        settings
    }

    /// Update intelligence with results from a completed scan.
    pub fn record_scan(&mut self, scan_result: &ScanResult) {
        // Mark each module that ran
        for module_id in &scan_result.modules_run {
            self.modules.entry(module_id.clone()).or_default();
        }

        // Count findings per module by severity
        let mut module_findings: HashMap<String, (u32, u32, u32, u32, u32)> = HashMap::new();
        for finding in &scan_result.findings {
            let entry = module_findings.entry(finding.module_id.clone()).or_default();
            match finding.severity {
                Severity::Critical => entry.0 += 1,
                Severity::High => entry.1 += 1,
                Severity::Medium => entry.2 += 1,
                Severity::Low => entry.3 += 1,
                Severity::Info => entry.4 += 1,
            }
        }

        // Record run for each module (with or without findings)
        for module_id in &scan_result.modules_run {
            let stats = self.modules.entry(module_id.clone()).or_default();
            let (critical, high, medium, low, info) =
                module_findings.get(module_id).copied().unwrap_or_default();
            stats.record_run(critical, high, medium, low, info);
        }

        self.total_scans += 1;
        self.last_updated = Some(Utc::now().to_rfc3339());
    }

    /// Format intelligence as a compact summary for AI planner context.
    #[must_use]
    pub fn format_for_planner(&self) -> Option<String> {
        if self.modules.is_empty() {
            return None;
        }

        let mut lines = Vec::new();
        lines.push(format!("Project scanned {} time(s).", self.total_scans));

        if let Some(ref profile) = self.target_profile {
            let mut desc = Vec::new();
            if let Some(ref s) = profile.server {
                desc.push(format!("Server: {s}"));
            }
            if let Some(ref c) = profile.cms {
                desc.push(format!("CMS: {c}"));
            }
            if !profile.technologies.is_empty() {
                desc.push(format!("Tech: {}", profile.technologies.join(", ")));
            }
            if let Some(ref w) = profile.waf {
                desc.push(format!("WAF: {w}"));
            }
            if !desc.is_empty() {
                lines.push(format!("Target profile: {}", desc.join(" | ")));
            }
        }

        lines.push("Module effectiveness (sorted by findings):".to_string());

        let mut sorted: Vec<_> = self.modules.iter().collect();
        sorted
            .sort_by(|a, b| b.1.total_findings.cmp(&a.1.total_findings).then_with(|| a.0.cmp(b.0)));

        for (id, stats) in &sorted {
            lines.push(format!(
                "  {id}: {runs} runs, {findings} findings (C:{c} H:{h} M:{m} L:{l} I:{i}), score {score:.1}",
                runs = stats.total_runs,
                findings = stats.total_findings,
                c = stats.critical,
                h = stats.high,
                m = stats.medium,
                l = stats.low,
                i = stats.info,
                score = stats.effectiveness_score,
            ));
        }

        Some(lines.join("\n"))
    }
}

/// Update project intelligence after a completed scan.
///
/// Reads existing intelligence from `Project.settings`, merges
/// the new scan results, and writes back. Silently returns `Ok(())`
/// if the project doesn't exist or settings are malformed.
///
/// # Errors
///
/// Returns an error if the database write fails.
pub async fn update_intelligence(
    pool: &PgPool,
    project_id: Uuid,
    scan_result: &ScanResult,
) -> Result<()> {
    // Read current project settings
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT settings FROM projects WHERE id = $1")
            .bind(project_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("read settings: {e}")))?;

    let Some((current_settings,)) = row else {
        return Ok(()); // Project not found — skip silently
    };

    // Merge new scan data
    let mut intel = ProjectIntelligence::from_settings(&current_settings);
    intel.record_scan(scan_result);

    // Write back
    let new_settings = intel.to_settings(&current_settings);
    sqlx::query("UPDATE projects SET settings = $2, updated_at = now() WHERE id = $1")
        .bind(project_id)
        .bind(&new_settings)
        .execute(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("update intelligence: {e}")))?;

    Ok(())
}

/// Read project intelligence from the database.
///
/// # Errors
///
/// Returns an error if the database read fails.
pub async fn get_intelligence(pool: &PgPool, project_id: Uuid) -> Result<ProjectIntelligence> {
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT settings FROM projects WHERE id = $1")
            .bind(project_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| ScorchError::Database(format!("read settings: {e}")))?;

    let Some((settings,)) = row else {
        return Ok(ProjectIntelligence::default());
    };

    Ok(ProjectIntelligence::from_settings(&settings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_stats_merge() {
        let mut stats = ModuleStats::default();
        stats.record_run(1, 2, 0, 1, 3); // 7 findings
        assert_eq!(stats.total_runs, 1);
        assert_eq!(stats.total_findings, 7);
        assert_eq!(stats.critical, 1);
        assert_eq!(stats.high, 2);
        assert_eq!(stats.info, 3);

        // Second run
        stats.record_run(0, 1, 1, 0, 0); // 2 findings
        assert_eq!(stats.total_runs, 2);
        assert_eq!(stats.total_findings, 9);
        assert_eq!(stats.high, 3); // accumulated
    }

    #[test]
    fn test_effectiveness_score() {
        let mut stats = ModuleStats::default();
        // Zero runs = zero score
        assert!((stats.effectiveness_score - 0.0).abs() < f64::EPSILON);

        stats.record_run(0, 0, 0, 0, 0); // 1 run, 0 findings
        assert!((stats.effectiveness_score - 0.0).abs() < f64::EPSILON);

        stats.record_run(1, 1, 0, 0, 0); // 2 runs total, 2 findings
        assert!((stats.effectiveness_score - 1.0).abs() < f64::EPSILON); // 2/2 = 1.0

        stats.record_run(0, 0, 3, 0, 0); // 3 runs, 5 findings
        let expected = 5.0 / 3.0;
        assert!((stats.effectiveness_score - expected).abs() < 0.01);
    }

    #[test]
    fn test_intelligence_serde_roundtrip() {
        let mut intel = ProjectIntelligence::default();
        intel.total_scans = 5;
        intel.last_updated = Some("2026-03-30T12:00:00Z".to_string());

        let mut stats = ModuleStats::default();
        stats.record_run(2, 1, 0, 0, 3);
        intel.modules.insert("headers".to_string(), stats);

        intel.target_profile = Some(TargetProfile {
            server: Some("nginx".to_string()),
            cms: Some("WordPress".to_string()),
            ..Default::default()
        });

        let json = serde_json::to_value(&intel).expect("serialize");
        let roundtrip: ProjectIntelligence = serde_json::from_value(json).expect("deserialize");

        assert_eq!(roundtrip.total_scans, 5);
        assert_eq!(roundtrip.modules.len(), 1);
        assert_eq!(roundtrip.modules["headers"].total_findings, 6);
        assert_eq!(
            roundtrip.target_profile.as_ref().and_then(|p| p.cms.as_deref()),
            Some("WordPress")
        );
    }

    #[test]
    fn test_intelligence_from_empty_settings() {
        let empty = serde_json::json!({});
        let intel = ProjectIntelligence::from_settings(&empty);
        assert_eq!(intel.total_scans, 0);
        assert!(intel.modules.is_empty());
    }

    #[test]
    fn test_intelligence_from_invalid_json() {
        // Settings with intelligence key but wrong type
        let bad = serde_json::json!({"intelligence": "not an object"});
        let intel = ProjectIntelligence::from_settings(&bad);
        assert_eq!(intel.total_scans, 0); // graceful default

        // Settings that isn't even an object
        let null = serde_json::Value::Null;
        let intel = ProjectIntelligence::from_settings(&null);
        assert_eq!(intel.total_scans, 0);
    }

    #[test]
    fn test_target_profile_serde() {
        let profile = TargetProfile {
            server: Some("Apache/2.4".to_string()),
            technologies: vec!["PHP".to_string(), "Laravel".to_string()],
            cms: None,
            waf: Some("Cloudflare".to_string()),
            is_https: true,
        };

        let json = serde_json::to_value(&profile).expect("serialize");
        let roundtrip: TargetProfile = serde_json::from_value(json).expect("deserialize");

        assert_eq!(roundtrip.server.as_deref(), Some("Apache/2.4"));
        assert_eq!(roundtrip.technologies.len(), 2);
        assert!(roundtrip.is_https);
        assert_eq!(roundtrip.waf.as_deref(), Some("Cloudflare"));
    }

    #[test]
    fn test_to_settings_preserves_existing() {
        let existing = serde_json::json!({"custom_key": "custom_value"});
        let intel = ProjectIntelligence { total_scans: 3, ..Default::default() };
        let merged = intel.to_settings(&existing);

        assert_eq!(merged["custom_key"], "custom_value");
        assert_eq!(merged["intelligence"]["total_scans"], 3);
    }

    #[test]
    fn test_format_for_planner_empty() {
        let intel = ProjectIntelligence::default();
        assert!(intel.format_for_planner().is_none());
    }

    #[test]
    fn test_format_for_planner_with_data() {
        let mut intel = ProjectIntelligence::default();
        intel.total_scans = 2;
        let mut stats = ModuleStats::default();
        stats.record_run(1, 0, 0, 0, 0);
        intel.modules.insert("ssl".to_string(), stats);

        let output = intel.format_for_planner().expect("should produce output");
        assert!(output.contains("scanned 2 time(s)"));
        assert!(output.contains("ssl:"));
        assert!(output.contains("1 findings"));
    }
}
