use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::finding::Finding;
use super::severity::Severity;
use super::target::Target;

/// Overall execution integrity of a scan result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanExecutionStatus {
    /// Every selected module either ran or had a non-failure coverage disposition.
    #[default]
    Complete,
    /// At least one selected module failed during execution or output validation.
    Degraded,
}

/// Typed execution state for one selected scan module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleOutcomeStatus {
    /// The module ran to completion, with or without findings.
    Ran,
    /// The module does not apply to the detected target or language.
    NotApplicable,
    /// The module was eligible but could not start, such as when a tool is absent.
    Skipped,
    /// The module started but execution or output validation failed.
    Failed,
}

/// Machine-readable reason for a module that did not produce a normal run outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModuleOutcomeReason {
    /// None of the detected languages is supported by the selected analyzer.
    UnsupportedLanguage {
        /// Explicitly selected or detected project languages.
        detected: Vec<String>,
        /// Languages declared by the analyzer.
        supported: Vec<String>,
    },
    /// No project language could be determined for a language-specific analyzer.
    LanguageUndetected {
        /// Languages declared by the analyzer.
        supported: Vec<String>,
    },
    /// The declared external tool could not be resolved.
    MissingTool {
        /// Executable name declared by the adapter.
        tool: String,
    },
    /// The module failed during execution or output validation.
    ExecutionFailed {
        /// Existing human-readable failure detail.
        #[serde(
            serialize_with = "serialize_redacted_message",
            deserialize_with = "deserialize_redacted_message"
        )]
        message: String,
    },
}

fn serialize_redacted_message<S>(message: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&crate::observation::redact_text(message))
}

fn deserialize_redacted_message<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(|message| crate::observation::redact_text(&message))
}

fn serialize_redacted_skips<S>(
    skipped: &[(String, String)],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let redacted: Vec<(&str, String)> = skipped
        .iter()
        .map(|(module_id, reason)| (module_id.as_str(), crate::observation::redact_text(reason)))
        .collect();
    redacted.serialize(serializer)
}

fn deserialize_redacted_skips<'de, D>(deserializer: D) -> Result<Vec<(String, String)>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<(String, String)>::deserialize(deserializer).map(|skipped| {
        skipped
            .into_iter()
            .map(|(module_id, reason)| (module_id, crate::observation::redact_text(&reason)))
            .collect()
    })
}

/// Typed coverage and execution result for one selected module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleOutcome {
    /// Stable module identifier.
    pub module_id: String,
    /// Terminal execution state.
    pub status: ModuleOutcomeStatus,
    /// Finding count for successful runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings_count: Option<usize>,
    /// Machine-readable reason for non-run states.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ModuleOutcomeReason>,
}

impl ModuleOutcome {
    /// Record one completed module run.
    #[must_use]
    pub fn ran(module_id: impl Into<String>, findings_count: usize) -> Self {
        Self {
            module_id: module_id.into(),
            status: ModuleOutcomeStatus::Ran,
            findings_count: Some(findings_count),
            reason: None,
        }
    }

    /// Record one module that was not applicable to the target.
    #[must_use]
    pub fn not_applicable(module_id: impl Into<String>, reason: ModuleOutcomeReason) -> Self {
        Self {
            module_id: module_id.into(),
            status: ModuleOutcomeStatus::NotApplicable,
            findings_count: None,
            reason: Some(reason),
        }
    }

    /// Record one eligible module whose external prerequisite was absent.
    #[must_use]
    pub fn skipped(module_id: impl Into<String>, reason: ModuleOutcomeReason) -> Self {
        Self {
            module_id: module_id.into(),
            status: ModuleOutcomeStatus::Skipped,
            findings_count: None,
            reason: Some(reason),
        }
    }

    /// Record one module execution or parser failure.
    #[must_use]
    pub fn failed(module_id: impl Into<String>, reason: ModuleOutcomeReason) -> Self {
        let reason = match reason {
            ModuleOutcomeReason::ExecutionFailed { message } => {
                ModuleOutcomeReason::ExecutionFailed {
                    message: crate::observation::redact_text(&message),
                }
            }
            other => other,
        };
        Self {
            module_id: module_id.into(),
            status: ModuleOutcomeStatus::Failed,
            findings_count: None,
            reason: Some(reason),
        }
    }
}

/// Aggregated results from a complete scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(
        serialize_with = "serialize_redacted_skips",
        deserialize_with = "deserialize_redacted_skips"
    )]
    pub modules_skipped: Vec<(String, String)>,
    /// Typed per-module coverage and execution outcomes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_outcomes: Vec<ModuleOutcome>,
    /// Overall status derived from the typed module outcomes.
    #[serde(default)]
    pub execution_status: ScanExecutionStatus,
    /// Summary statistics.
    pub summary: ScanSummary,
}

/// Summary statistics for a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            module_outcomes: Vec::new(),
            execution_status: ScanExecutionStatus::Complete,
            summary,
        }
    }

    /// Replace typed outcomes and derive the overall execution status from them.
    #[must_use]
    pub fn with_module_outcomes(mut self, module_outcomes: Vec<ModuleOutcome>) -> Self {
        self.module_outcomes = module_outcomes;
        self.refresh_execution_status();
        self
    }

    /// Return whether at least one selected module failed to execute or validate its output.
    #[must_use]
    pub fn has_failed_modules(&self) -> bool {
        self.module_outcomes.iter().any(|outcome| outcome.status == ModuleOutcomeStatus::Failed)
    }

    /// Return the SARIF-compatible execution-success value for this result.
    #[must_use]
    pub fn execution_successful(&self) -> bool {
        !self.has_failed_modules() && self.execution_status == ScanExecutionStatus::Complete
    }

    /// Recompute the top-level status after outcome collection or merge.
    pub fn refresh_execution_status(&mut self) {
        self.execution_status = if self.has_failed_modules() {
            ScanExecutionStatus::Degraded
        } else {
            ScanExecutionStatus::Complete
        };
    }

    /// Preserve a fatal module or scan-family failure in a partial result.
    ///
    /// The diagnostic is redacted before it reaches either the legacy skipped-module field or the
    /// typed outcome. This keeps partial findings available while making incomplete coverage
    /// explicit to JSON, MCP, CLI, and report consumers.
    pub fn record_execution_failure(
        &mut self,
        module_id: impl Into<String>,
        message: impl AsRef<str>,
    ) {
        let module_id = module_id.into();
        let message = crate::observation::redact_text(message.as_ref());
        self.modules_skipped.push((module_id.clone(), message.clone()));
        self.module_outcomes.push(ModuleOutcome::failed(
            module_id,
            ModuleOutcomeReason::ExecutionFailed { message },
        ));
        self.refresh_execution_status();
    }

    /// Remove findings below the given confidence threshold and recompute the summary.
    ///
    /// Findings with confidence >= `min_confidence` are kept.
    pub fn filter_by_confidence(&mut self, min_confidence: f64) {
        self.findings.retain(|f| f.confidence >= min_confidence);
        self.summary = ScanSummary::from_findings(&self.findings);
    }

    /// Merge another scan result into this one.
    ///
    /// Combines findings, modules run, and modules skipped from `other`
    /// into `self`. The target, scan ID, and timing from `self` are preserved.
    /// The summary is recomputed from the merged findings.
    ///
    /// This is used to combine DAST and SAST results into a single report.
    pub fn merge(&mut self, other: Self) {
        self.findings.extend(other.findings);
        self.modules_run.extend(other.modules_run);
        self.modules_skipped.extend(other.modules_skipped);
        self.module_outcomes.extend(other.module_outcomes);
        self.refresh_execution_status();
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
            module_outcomes: Vec::new(),
            execution_status: ScanExecutionStatus::Complete,
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

    /// Verify that merging two scan results combines findings, modules,
    /// and recomputes the summary correctly.
    #[test]
    fn test_merge_results() {
        let mut dast =
            test_result_with_confidences(&[(Severity::High, 0.9), (Severity::Medium, 0.7)]);
        dast.modules_run = vec!["headers".to_string(), "ssl".to_string()];

        let sast = {
            let mut r =
                test_result_with_confidences(&[(Severity::Critical, 0.85), (Severity::Low, 0.6)]);
            r.modules_run = vec!["semgrep".to_string(), "dep-audit".to_string()];
            r.modules_skipped = vec![("bandit".to_string(), "not installed".to_string())];
            r.module_outcomes = vec![
                ModuleOutcome::ran("semgrep", 1),
                ModuleOutcome::skipped(
                    "bandit",
                    ModuleOutcomeReason::MissingTool { tool: "bandit".to_string() },
                ),
            ];
            r
        };

        dast.merge(sast);

        assert_eq!(dast.findings.len(), 4);
        assert_eq!(dast.modules_run.len(), 4);
        assert_eq!(dast.modules_skipped.len(), 1);
        assert_eq!(dast.module_outcomes.len(), 2);
        assert_eq!(dast.execution_status, ScanExecutionStatus::Complete);
        assert_eq!(dast.module_outcomes[0], ModuleOutcome::ran("semgrep", 1));
        assert_eq!(dast.summary.total_findings, 4);
        assert_eq!(dast.summary.critical, 1);
        assert_eq!(dast.summary.high, 1);
        assert_eq!(dast.summary.medium, 1);
        assert_eq!(dast.summary.low, 1);
    }

    /// Verify that merging an empty result is a no-op.
    #[test]
    fn test_merge_empty() {
        let mut result = test_result_with_confidences(&[(Severity::High, 0.9)]);
        let original_count = result.findings.len();
        let original_modules = result.modules_run.len();

        let empty = ScanResult::new(
            "empty".to_string(),
            Target::parse("https://example.com").expect("valid target"),
            chrono::Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        result.merge(empty);
        assert_eq!(result.findings.len(), original_count);
        assert_eq!(result.modules_run.len(), original_modules);
    }

    #[test]
    fn legacy_scan_result_without_typed_outcomes_remains_readable() {
        let result = test_result_with_confidences(&[(Severity::High, 0.9)]);
        let mut value = serde_json::to_value(result).expect("serialize result");
        value.as_object_mut().expect("scan result object").remove("module_outcomes");

        let restored: ScanResult = serde_json::from_value(value).expect("read legacy result");
        assert!(restored.module_outcomes.is_empty());
        assert_eq!(restored.modules_run, ["test"]);
    }

    #[test]
    fn typed_outcome_reason_has_a_stable_serialized_shape() {
        let outcome = ModuleOutcome::not_applicable(
            "codeql",
            ModuleOutcomeReason::UnsupportedLanguage {
                detected: vec!["php".to_string()],
                supported: vec!["javascript".to_string(), "python".to_string()],
            },
        );
        let value = serde_json::to_value(outcome).expect("serialize module outcome");
        assert_eq!(value["status"], "not_applicable");
        assert_eq!(value["reason"]["kind"], "unsupported_language");
        assert_eq!(value["reason"]["detected"], serde_json::json!(["php"]));
        assert_eq!(value["reason"]["supported"], serde_json::json!(["javascript", "python"]));
    }

    #[test]
    fn failed_module_degrades_serialized_scan_and_merge() {
        let failed = ModuleOutcome::failed(
            "codeql",
            ModuleOutcomeReason::ExecutionFailed { message: "redacted failure".to_string() },
        );
        let mut result = test_result_with_confidences(&[]).with_module_outcomes(vec![failed]);

        assert!(result.has_failed_modules());
        assert!(!result.execution_successful());
        assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
        let encoded = serde_json::to_value(&result).expect("serialize degraded scan");
        assert_eq!(encoded["execution_status"], "degraded");

        let clean = test_result_with_confidences(&[]);
        result.execution_status = ScanExecutionStatus::Complete;
        result.merge(clean);
        assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
    }

    #[test]
    fn recording_partial_failure_updates_legacy_and_typed_status_without_leaking() {
        let mut result = test_result_with_confidences(&[]);
        result.record_execution_failure("code-scan", "api_key=family-fixture-secret");

        assert_eq!(result.execution_status, ScanExecutionStatus::Degraded);
        assert!(!result.execution_successful());
        assert_eq!(result.modules_skipped.len(), 1);
        assert_eq!(result.modules_skipped[0].0, "code-scan");
        assert!(!result.modules_skipped[0].1.contains("family-fixture-secret"));
        assert_eq!(result.module_outcomes.len(), 1);
        assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);

        let encoded = serde_json::to_string(&result).expect("serialize partial result");
        assert!(!encoded.contains("family-fixture-secret"));
        assert!(encoded.contains("REDACTED"));
    }

    #[test]
    fn legacy_scan_without_execution_status_defaults_complete() {
        let result = test_result_with_confidences(&[]);
        let mut value = serde_json::to_value(&result).expect("serialize scan");
        value.as_object_mut().expect("scan object").remove("execution_status");
        let restored: ScanResult = serde_json::from_value(value).expect("deserialize legacy scan");
        assert_eq!(restored.execution_status, ScanExecutionStatus::Complete);
        assert!(restored.execution_successful());
    }

    #[test]
    fn failed_outcome_redacts_diagnostics_on_construction_and_wire_boundaries() {
        let mut outcome = ModuleOutcome::failed(
            "codeql",
            ModuleOutcomeReason::ExecutionFailed {
                message: "api_key=constructor-secret".to_string(),
            },
        );
        let encoded = serde_json::to_string(&outcome).expect("serialize failed outcome");
        assert!(!encoded.contains("constructor-secret"));

        outcome.reason = Some(ModuleOutcomeReason::ExecutionFailed {
            message: "password = \"mutated-secret\"".to_string(),
        });
        let encoded = serde_json::to_string(&outcome).expect("serialize mutated outcome");
        assert!(!encoded.contains("mutated-secret"));
        let restored: ModuleOutcome = serde_json::from_str(&encoded).expect("deserialize outcome");
        let Some(ModuleOutcomeReason::ExecutionFailed { message }) = restored.reason else {
            panic!("expected execution failure reason");
        };
        assert!(!message.contains("secret"));
    }

    #[test]
    fn failed_outcome_deserialization_preserves_safe_context_while_redacting() {
        let raw = serde_json::json!({
            "module_id": "codeql",
            "status": "failed",
            "reason": {
                "kind": "execution_failed",
                "message": "prefix api_key=wire-secret suffix"
            }
        });
        let restored: ModuleOutcome = serde_json::from_value(raw).expect("deserialize outcome");
        let Some(ModuleOutcomeReason::ExecutionFailed { message }) = restored.reason else {
            panic!("expected execution failure reason");
        };
        assert_eq!(message, crate::observation::redact_text("prefix api_key=wire-secret suffix"));
        assert!(message.starts_with("prefix "));
        assert!(message.ends_with(" suffix"));
    }
}
