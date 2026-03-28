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

/// Build the full prompt for Claude based on findings, focus mode, and
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
