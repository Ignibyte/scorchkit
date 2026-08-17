use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::ai::types::ProjectContext;
use crate::engine::finding::Finding;
use crate::engine::scan_result::ScanResult;

/// Analysis focus modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisFocus {
    /// Executive summary with business impact.
    Summary,
    /// Rank findings by exploitability and attack chain potential.
    Prioritize,
    /// Detailed remediation recommendations per finding.
    Remediate,
    /// Identify likely false positives with reasoning.
    Filter,
}

impl AnalysisFocus {
    /// Parse a focus mode from a user-supplied string.
    ///
    /// Accepts common aliases; defaults to [`AnalysisFocus::Summary`] for
    /// unrecognized input.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "prioritize" | "priority" | "prio" => Self::Prioritize,
            "remediate" | "remediation" | "fix" => Self::Remediate,
            "filter" | "false-positives" | "fp" => Self::Filter,
            _ => Self::Summary,
        }
    }

    /// Human-readable label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Summary => "Executive Summary",
            Self::Prioritize => "Prioritized Risk Assessment",
            Self::Remediate => "Remediation Guide",
            Self::Filter => "False Positive Analysis",
        }
    }
}

/// Build the full prompt for an AI provider based on findings, focus mode, and
/// optional project history context.
#[must_use]
pub fn build_prompt(
    result: &ScanResult,
    focus: AnalysisFocus,
    project_context: Option<&ProjectContext>,
) -> String {
    let findings_json = serialize_findings_compact(&result.findings);
    let target = &result.target.raw;
    let summary = &result.summary;

    let mut system_context = format!(
        "You are a senior penetration tester and application security expert. \
         You are analyzing the results of an automated web security scan against {target}.\n\n\
         Scan summary: {total} findings ({critical} critical, {high} high, {medium} medium, \
         {low} low, {info} info) from {modules} modules.",
        total = summary.total_findings,
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        info = summary.info,
        modules = result.modules_run.len(),
    );

    if let Some(ctx) = project_context {
        system_context.push_str(&format_project_context(ctx));
    }

    let _ = write!(system_context, "\n\nFindings (JSON):\n{findings_json}");

    let task = build_task_instructions(focus);

    format!("{system_context}\n\n---\n\nTASK:\n{task}")
}

/// Format project history context for injection into the prompt.
fn format_project_context(ctx: &ProjectContext) -> String {
    let trends = &ctx.finding_trends;
    let status = &trends.by_status;

    let mut section = format!(
        "\n\n--- PROJECT HISTORY ---\n\
         Project: {name}\n\
         Total scans: {scans}",
        name = ctx.project_name,
        scans = ctx.total_scans,
    );

    if let Some(ref date) = ctx.latest_scan_date {
        let _ = write!(section, "\nLatest scan: {date}");
    }

    let _ = write!(
        section,
        "\nTracked findings: {total}\n\
         Status breakdown: {new} new, {ack} acknowledged, {fp} false positive, \
         {rem} remediated, {ver} verified",
        total = trends.total_tracked,
        new = status.new,
        ack = status.acknowledged,
        fp = status.false_positive,
        rem = status.remediated,
        ver = status.verified,
    );

    section
}

/// Build focus-specific task instructions requesting JSON output.
fn build_task_instructions(focus: AnalysisFocus) -> String {
    match focus {
        AnalysisFocus::Summary => SUMMARY_TASK.to_string(),
        AnalysisFocus::Prioritize => PRIORITIZE_TASK.to_string(),
        AnalysisFocus::Remediate => REMEDIATE_TASK.to_string(),
        AnalysisFocus::Filter => FILTER_TASK.to_string(),
    }
}

const SUMMARY_TASK: &str = "\
Provide an executive summary of these security findings.

You MUST respond with a single JSON object (no markdown, no commentary outside the JSON).

Use this exact schema:
{
  \"risk_score\": <number 0.0-10.0>,
  \"executive_summary\": \"<1-2 paragraphs>\",
  \"key_findings\": [
    {
      \"finding_index\": <number>,
      \"severity\": \"<critical|high|medium|low|info>\",
      \"title\": \"<finding title>\",
      \"business_impact\": \"<why this matters>\",
      \"exploitability\": \"<critical|high|medium|low|theoretical>\"
    }
  ],
  \"attack_surface\": \"<attack surface assessment>\",
  \"business_impact\": \"<overall business impact>\"
}

Include the 3-5 most important findings in key_findings. Write for a technical audience. No filler.";

const PRIORITIZE_TASK: &str = "\
Analyze these findings and rank them by real-world exploitability.

You MUST respond with a single JSON object (no markdown, no commentary outside the JSON).

Use this exact schema:
{
  \"prioritized_findings\": [
    {
      \"finding_index\": <number>,
      \"title\": \"<finding title>\",
      \"severity\": \"<critical|high|medium|low|info>\",
      \"exploitability\": \"<critical|high|medium|low|theoretical>\",
      \"business_impact_score\": <number 0.0-10.0>,
      \"effort_to_exploit\": \"<trivial|low|medium|high|major>\",
      \"rationale\": \"<why this ranking>\"
    }
  ],
  \"attack_chains\": [
    {
      \"name\": \"<chain name>\",
      \"finding_indices\": [<numbers>],
      \"combined_impact\": \"<what attacker achieves>\",
      \"likelihood\": \"<high|medium|low>\"
    }
  ],
  \"recommended_fix_order\": [<finding indices in fix priority order>]
}

Rank from highest to lowest priority. Group findings that form natural attack chains.";

const REMEDIATE_TASK: &str = "\
Provide specific, actionable remediation steps for each finding.

You MUST respond with a single JSON object (no markdown, no commentary outside the JSON).

Use this exact schema:
{
  \"remediations\": [
    {
      \"finding_index\": <number>,
      \"title\": \"<finding title>\",
      \"severity\": \"<critical|high|medium|low|info>\",
      \"fix_description\": \"<exact fix needed>\",
      \"code_example\": \"<config/code snippet or null>\",
      \"effort\": \"<trivial|low|medium|high|major>\",
      \"priority\": <number, 1=highest>,
      \"verification_steps\": [\"<step1>\", \"<step2>\"]
    }
  ],
  \"quick_wins\": [<finding indices for easy fixes>],
  \"total_estimated_effort\": \"<human-readable estimate>\"
}

Tailor fixes to the detected technology stack. Be specific enough to implement directly.";

const FILTER_TASK: &str = "\
Review these findings and identify likely false positives.

You MUST respond with a single JSON object (no markdown, no commentary outside the JSON).

Use this exact schema:
{
  \"findings\": [
    {
      \"finding_index\": <number>,
      \"title\": \"<finding title>\",
      \"classification\": \"<confirmed|likely_true|uncertain|likely_false_positive|false_positive>\",
      \"confidence\": <number 0.0-1.0>,
      \"rationale\": \"<reasoning>\"
    }
  ],
  \"false_positive_count\": <number>,
  \"confirmed_count\": <number>,
  \"uncertain_count\": <number>
}

Common false positive patterns: generic 404 pages returning 200, WAF/CDN artifacts, \
cookie flags on non-session cookies, admin panels behind login redirects, \
self-signed certs on internal envs behind reverse proxies.";

// ── Scan planning prompt ───────────────────────────────────────────────

/// Build a planning prompt from recon findings, target info, and module catalog.
#[must_use]
pub fn build_planning_prompt(
    target: &str,
    recon_findings: &[Finding],
    module_catalog: &str,
    intelligence: Option<&str>,
) -> String {
    let recon_json = serialize_findings_compact(recon_findings);

    let mut prompt = format!(
        "You are a senior penetration tester planning a targeted security scan.\n\n\
         Target: {target}\n\n\
         The following reconnaissance has already been performed. \
         Based on these recon findings, decide which scan modules to run next.\n\n\
         RECON FINDINGS:\n{recon_json}\n\n\
         AVAILABLE MODULES:\n{module_catalog}\n\n"
    );

    if let Some(intel) = intelligence {
        let _ = write!(
            prompt,
            "HISTORICAL MODULE EFFECTIVENESS (from previous scans on this project):\n\
             {intel}\n\n"
        );
    }

    let _ = write!(prompt, "---\n\nTASK:\n{PLANNING_TASK}");
    prompt
}

/// Build a compact JSON catalog of available modules for the planning prompt.
///
/// Each entry contains the module's id, name, description, category, and
/// whether it requires an external tool.
#[must_use]
pub fn build_module_catalog(
    modules: &[Box<dyn crate::engine::module_trait::ScanModule>],
) -> String {
    let catalog: Vec<serde_json::Value> = modules
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.id(),
                "name": m.name(),
                "description": m.description(),
                "category": m.category().to_string(),
                "requires_external_tool": m.requires_external_tool(),
            })
        })
        .collect();

    serde_json::to_string_pretty(&catalog).unwrap_or_else(|_| "[]".to_string())
}

const PLANNING_TASK: &str = "\
Based on the recon findings above, create a scan plan selecting the most relevant modules.

You MUST respond with a single JSON object (no markdown, no commentary outside the JSON).

Use this exact schema:
{
  \"target\": \"<the target URL>\",
  \"recommendations\": [
    {
      \"module_id\": \"<exact module ID from the catalog>\",
      \"priority\": <number, 1=highest>,
      \"rationale\": \"<why this module is relevant for this target>\",
      \"category\": \"<recon|scanner>\"
    }
  ],
  \"skipped_modules\": [
    {
      \"module_id\": \"<module ID>\",
      \"reason\": \"<why this module is not relevant>\"
    }
  ],
  \"overall_strategy\": \"<1-2 sentence description of the scanning approach>\",
  \"estimated_scan_time\": \"<rough estimate or null>\"
}

Guidelines:
- Only recommend modules from the AVAILABLE MODULES catalog. Use exact module IDs.
- Prioritize modules that target the detected technology stack and attack surface.
- Skip modules that are irrelevant to the detected tech (e.g., skip wpscan if not WordPress).
- Order by priority: critical security checks first, then enumeration, then edge cases.
- If external tools are required but the target warrants them, still recommend them.
- Include recon modules only if deeper recon is warranted (e.g., subdomain enumeration for large scope).";

/// Serialize findings to a compact JSON format for the prompt.
fn serialize_findings_compact(findings: &[Finding]) -> String {
    // Build a compact representation to minimize token usage
    let compact: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mut obj = serde_json::json!({
                "#": i + 1,
                "severity": f.severity.to_string(),
                "title": f.title,
                "target": f.affected_target,
            });

            if let Some(ref evidence) = f.evidence {
                obj["evidence"] = serde_json::Value::String(evidence.clone());
            }
            if let Some(ref owasp) = f.owasp_category {
                obj["owasp"] = serde_json::Value::String(owasp.clone());
            }
            if let Some(cwe) = f.cwe_id {
                obj["cwe"] = serde_json::Value::Number(cwe.into());
            }
            if let Some(ref remediation) = f.remediation {
                obj["remediation"] = serde_json::Value::String(remediation.clone());
            }

            obj
        })
        .collect();

    serde_json::to_string_pretty(&compact).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::types::{FindingTrends, StatusBreakdown};
    use crate::engine::scan_result::ScanSummary;
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;

    fn finding(severity: Severity, title: &str) -> Finding {
        Finding::new(
            "fixture-module",
            severity,
            title,
            "fixture description",
            "https://owned.example/path",
        )
    }

    fn enriched_finding() -> Finding {
        finding(Severity::Critical, "Enriched finding")
            .with_evidence("request reached the vulnerable branch")
            .with_owasp("A03:2021")
            .with_cwe(79)
            .with_remediation("encode untrusted output")
    }

    fn scan_result() -> ScanResult {
        let findings = vec![
            enriched_finding(),
            finding(Severity::Critical, "Critical two"),
            finding(Severity::High, "High one"),
            finding(Severity::Medium, "Medium one"),
            finding(Severity::Medium, "Medium two"),
            finding(Severity::Medium, "Medium three"),
            finding(Severity::Low, "Low one"),
            finding(Severity::Info, "Info one"),
            finding(Severity::Info, "Info two"),
            finding(Severity::Info, "Info three"),
            finding(Severity::Info, "Info four"),
        ];
        ScanResult {
            scan_id: "prompt-fixture".to_string(),
            target: Target::parse("https://owned.example").expect("fixture target"),
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            summary: ScanSummary::from_findings(&findings),
            findings,
            modules_run: vec!["one".to_string(), "two".to_string(), "three".to_string()],
            modules_skipped: Vec::new(),
        }
    }

    fn project_context() -> ProjectContext {
        ProjectContext {
            project_name: "owned-project".to_string(),
            total_scans: 7,
            latest_scan_date: Some("2026-08-16".to_string()),
            finding_trends: FindingTrends {
                total_tracked: 11,
                by_status: StatusBreakdown {
                    new: 1,
                    acknowledged: 2,
                    false_positive: 3,
                    remediated: 4,
                    verified: 1,
                },
            },
        }
    }

    #[test]
    fn analysis_prompt_preserves_scan_and_optional_project_context() {
        let result = scan_result();
        let without_project = build_prompt(&result, AnalysisFocus::Summary, None);
        for expected in [
            "https://owned.example",
            "11 findings (2 critical, 1 high, 3 medium, 1 low, 4 info)",
            "from 3 modules",
            "Enriched finding",
            "request reached the vulnerable branch",
            "\"risk_score\"",
        ] {
            assert!(
                without_project.contains(expected),
                "analysis prompt omitted {expected:?}: {without_project}"
            );
        }
        assert!(!without_project.contains("PROJECT HISTORY"));

        let with_project = build_prompt(&result, AnalysisFocus::Summary, Some(&project_context()));
        for expected in [
            "PROJECT HISTORY",
            "Project: owned-project",
            "Total scans: 7",
            "Latest scan: 2026-08-16",
            "Tracked findings: 11",
            "1 new, 2 acknowledged, 3 false positive, 4 remediated, 1 verified",
        ] {
            assert!(with_project.contains(expected), "project context omitted {expected:?}");
        }
    }

    #[test]
    fn focus_tasks_have_distinct_structured_contracts() {
        let cases = [
            (AnalysisFocus::Summary, "\"risk_score\""),
            (AnalysisFocus::Prioritize, "\"prioritized_findings\""),
            (AnalysisFocus::Remediate, "\"remediations\""),
            (AnalysisFocus::Filter, "\"false_positive_count\""),
        ];

        for (focus, schema_marker) in cases {
            let instructions = build_task_instructions(focus);
            assert!(instructions.contains("single JSON object"));
            assert!(instructions.contains(schema_marker));
        }
    }

    #[test]
    fn compact_findings_json_preserves_optional_evidence_fields() {
        let serialized = serialize_findings_compact(&[enriched_finding()]);
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(&serialized).expect("compact findings JSON");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["#"], 1);
        assert_eq!(row["severity"], Severity::Critical.to_string());
        assert_eq!(row["title"], "Enriched finding");
        assert_eq!(row["target"], "https://owned.example/path");
        assert_eq!(row["evidence"], "request reached the vulnerable branch");
        assert_eq!(row["owasp"], "A03:2021");
        assert_eq!(row["cwe"], 79);
        assert_eq!(row["remediation"], "encode untrusted output");
    }

    #[test]
    fn test_planning_prompt_with_intelligence() {
        let recon = enriched_finding();
        let prompt = build_planning_prompt(
            "https://example.com",
            &[recon],
            r#"[{"id":"xss"}]"#,
            Some("ssl: 3 runs, 5 findings"),
        );
        assert!(prompt.contains("HISTORICAL MODULE EFFECTIVENESS"));
        assert!(prompt.contains("ssl: 3 runs, 5 findings"));
        assert!(prompt.contains("Enriched finding"));
        assert!(prompt.contains("request reached the vulnerable branch"));
        assert!(prompt.contains(r#"{"id":"xss"}"#));
        assert!(prompt.contains("\"recommendations\""));
    }

    #[test]
    fn test_planning_prompt_without_intelligence() {
        let prompt = build_planning_prompt("https://example.com", &[], "[]", None);
        assert!(!prompt.contains("HISTORICAL MODULE EFFECTIVENESS"));
        assert!(prompt.contains("TASK:"));
    }
}
