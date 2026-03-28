use crate::engine::finding::Finding;
use crate::engine::scan_result::ScanResult;

/// Analysis focus modes.
#[derive(Debug, Clone, Copy)]
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
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "prioritize" | "priority" | "prio" => Self::Prioritize,
            "remediate" | "remediation" | "fix" => Self::Remediate,
            "filter" | "false-positives" | "fp" => Self::Filter,
            _ => Self::Summary,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Executive Summary",
            Self::Prioritize => "Prioritized Risk Assessment",
            Self::Remediate => "Remediation Guide",
            Self::Filter => "False Positive Analysis",
        }
    }
}

/// Build the full prompt for Claude based on findings and focus mode.
pub fn build_prompt(result: &ScanResult, focus: AnalysisFocus) -> String {
    let findings_json = serialize_findings_compact(&result.findings);
    let target = &result.target.raw;
    let summary = &result.summary;

    let system_context = format!(
        "You are a senior penetration tester and application security expert. \
         You are analyzing the results of an automated web security scan against {target}.\n\n\
         Scan summary: {total} findings ({critical} critical, {high} high, {medium} medium, \
         {low} low, {info} info) from {modules} modules.\n\n\
         Findings (JSON):\n{findings_json}",
        total = summary.total_findings,
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        info = summary.info,
        modules = result.modules_run.len(),
    );

    let task = match focus {
        AnalysisFocus::Summary => {
            "Provide an executive summary of these security findings.\n\n\
             Structure your response as:\n\
             1. **Overall Risk Assessment** - One paragraph summarizing the security posture\n\
             2. **Key Risks** - The 3-5 most important findings and why they matter to the business\n\
             3. **Attack Scenarios** - Brief realistic attack scenarios an adversary could execute\n\
             4. **Recommended Actions** - Prioritized list of what to fix first and why\n\n\
             Write for a technical audience but keep it concise. No filler."
        }
        AnalysisFocus::Prioritize => {
            "Analyze these findings and rank them by real-world exploitability.\n\n\
             For each finding, assess:\n\
             1. **Exploitation difficulty** - How easy is this to exploit? (trivial/moderate/difficult)\n\
             2. **Impact** - What can an attacker gain? (data theft, account takeover, RCE, etc.)\n\
             3. **Attack chains** - Can this finding be combined with others for greater impact?\n\
             4. **Priority rank** - Number each finding from highest to lowest priority\n\n\
             Group findings that form natural attack chains. \
             Flag any findings that are likely more severe than their automated severity suggests."
        }
        AnalysisFocus::Remediate => {
            "Provide specific, actionable remediation steps for each finding.\n\n\
             For each finding:\n\
             1. **What to do** - Exact configuration change, code fix, or architectural change needed\n\
             2. **Where** - Which file, config, or service to modify (based on the detected tech stack)\n\
             3. **Example** - Show the actual config snippet, header value, or code change\n\
             4. **Verification** - How to verify the fix worked\n\n\
             Tailor recommendations to the detected technology stack. \
             Be specific enough that a developer can implement the fix directly."
        }
        AnalysisFocus::Filter => {
            "Review these findings and identify likely false positives.\n\n\
             For each finding, assess:\n\
             1. **Confidence** - How likely is this a true positive? (high/medium/low)\n\
             2. **Reasoning** - Why you believe it's real or false positive\n\
             3. **Verification steps** - How to manually confirm or deny this finding\n\n\
             Common false positive patterns to watch for:\n\
             - Generic 404 pages that return 200 status codes\n\
             - WAF/CDN artifacts that look like misconfigurations\n\
             - Cookie flags on non-session cookies (analytics, preferences)\n\
             - Admin panels that are actually login redirects\n\
             - Self-signed certs on internal/staging environments behind a reverse proxy\n\n\
             Flag definite false positives and explain why."
        }
    };

    format!("{system_context}\n\n---\n\nTASK:\n{task}")
}

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
