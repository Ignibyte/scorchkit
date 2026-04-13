//! Claude CLI response parsing with structured JSON extraction.
//!
//! Parses the Claude CLI JSON output envelope, extracts the analysis text,
//! and attempts to parse it into typed structs. Falls back to raw text when
//! JSON extraction fails.

use serde::de::DeserializeOwned;

use crate::ai::prompts::AnalysisFocus;
use crate::ai::types::{
    AiAnalysis, FilterAnalysis, PrioritizedAnalysis, RemediationAnalysis, ScanPlan,
    StructuredAnalysis, SummaryAnalysis,
};

/// Parse the Claude CLI JSON output into an [`AiAnalysis`].
///
/// Extracts the analysis text from the Claude CLI response envelope, then
/// attempts to parse it into the appropriate structured type based on the
/// focus mode. Falls back to [`StructuredAnalysis::Raw`] if parsing fails.
#[must_use]
pub fn parse_claude_response(output: &str, focus: AnalysisFocus) -> AiAnalysis {
    // Claude CLI --output-format json returns:
    // {"type":"result","subtype":"success","cost_usd":0.05,"is_error":false,
    //  "duration_ms":3000,"duration_api_ms":2800,"num_turns":1,
    //  "result":"the analysis text...","session_id":"..."}

    let (content, cost_usd, model) = serde_json::from_str::<serde_json::Value>(output).map_or_else(
        |_| (output.to_string(), None, None),
        |json| {
            let text = json["result"]
                .as_str()
                .or_else(|| json["content"].as_str())
                .unwrap_or(output)
                .to_string();

            let cost = json["cost_usd"].as_f64();
            let model_val = json["model"].as_str().map(String::from);

            (text, cost, model_val)
        },
    );

    let analysis = parse_structured_analysis(&content, focus);

    AiAnalysis { focus, analysis, raw_response: content, cost_usd, model }
}

/// Attempt to parse the analysis text into a structured type based on focus.
///
/// Uses a multi-tier extraction strategy:
/// 1. Direct JSON parse of the full text
/// 2. Extract from markdown code fences (` ```json ... ``` `)
/// 3. Find the first `{...}` block in the text
/// 4. Fall back to [`StructuredAnalysis::Raw`]
fn parse_structured_analysis(content: &str, focus: AnalysisFocus) -> StructuredAnalysis {
    match focus {
        AnalysisFocus::Summary => try_extract::<SummaryAnalysis>(content).map_or_else(
            || StructuredAnalysis::Raw { content: content.to_string() },
            StructuredAnalysis::Summary,
        ),
        AnalysisFocus::Prioritize => try_extract::<PrioritizedAnalysis>(content).map_or_else(
            || StructuredAnalysis::Raw { content: content.to_string() },
            StructuredAnalysis::Prioritized,
        ),
        AnalysisFocus::Remediate => try_extract::<RemediationAnalysis>(content).map_or_else(
            || StructuredAnalysis::Raw { content: content.to_string() },
            StructuredAnalysis::Remediation,
        ),
        AnalysisFocus::Filter => try_extract::<FilterAnalysis>(content).map_or_else(
            || StructuredAnalysis::Raw { content: content.to_string() },
            StructuredAnalysis::Filter,
        ),
    }
}

/// Multi-tier JSON extraction from a string that may contain JSON.
///
/// Tries three strategies in order:
/// 1. Direct parse of the entire string
/// 2. Extract content from markdown ` ```json ``` ` code fences
/// 3. Find the first `{` ... `}` balanced block
///
/// Returns `None` if all strategies fail.
#[must_use]
pub fn try_extract<T: DeserializeOwned>(raw: &str) -> Option<T> {
    let trimmed = raw.trim();

    // Strategy 1: Direct parse
    if let Ok(val) = serde_json::from_str(trimmed) {
        return Some(val);
    }

    // Strategy 2: Extract from code fence
    if let Some(fenced) = extract_code_fence(trimmed) {
        if let Ok(val) = serde_json::from_str(fenced) {
            return Some(val);
        }
    }

    // Strategy 3: Find first balanced JSON block
    if let Some(block) = extract_json_block(trimmed) {
        if let Ok(val) = serde_json::from_str(block) {
            return Some(val);
        }
    }

    None
}

/// Extract content from a markdown JSON code fence.
///
/// Looks for ` ```json\n...\n``` ` and returns the inner content.
fn extract_code_fence(text: &str) -> Option<&str> {
    let start_markers = ["```json\n", "```json\r\n", "```JSON\n"];
    for marker in &start_markers {
        if let Some(start) = text.find(marker) {
            let content_start = start + marker.len();
            if let Some(end) = text[content_start..].find("```") {
                return Some(text[content_start..content_start + end].trim());
            }
        }
    }
    None
}

/// Find the first balanced `{...}` block in the text.
///
/// Handles nested braces and strings (to avoid counting braces inside strings).
fn extract_json_block(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let bytes = text.as_bytes();
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, &byte) in bytes[start..].iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match byte {
            b'\\' if in_string => escape_next = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=(start + i)]);
                }
            }
            _ => {}
        }
    }

    None
}

/// Parse a Claude CLI response into a [`ScanPlan`].
///
/// Extracts the result text from the Claude CLI JSON envelope, then
/// attempts to parse it into a `ScanPlan`. Returns an empty plan if
/// parsing fails (graceful degradation).
#[must_use]
pub fn parse_plan_response(output: &str, target: &str) -> ScanPlan {
    let content = serde_json::from_str::<serde_json::Value>(output).map_or_else(
        |_| output.to_string(),
        |json| {
            json["result"]
                .as_str()
                .or_else(|| json["content"].as_str())
                .unwrap_or(output)
                .to_string()
        },
    );

    try_extract::<ScanPlan>(&content).unwrap_or_else(|| ScanPlan {
        target: target.to_string(),
        recommendations: Vec::new(),
        skipped_modules: Vec::new(),
        overall_strategy: "Plan parsing failed — using empty plan.".to_string(),
        estimated_scan_time: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that parse_claude_response extracts structured summary from
    /// a Claude CLI JSON envelope containing valid JSON analysis.
    #[test]
    fn test_parse_claude_response_structured() {
        let summary_json = r#"{
            "risk_score": 7.5,
            "executive_summary": "The target has significant vulnerabilities.",
            "key_findings": [],
            "attack_surface": "Wide attack surface with exposed admin panels.",
            "business_impact": "Potential data breach risk."
        }"#;
        let envelope = serde_json::json!({
            "type": "result",
            "result": summary_json,
            "cost_usd": 0.05,
            "model": "sonnet"
        });

        let result = parse_claude_response(&envelope.to_string(), AnalysisFocus::Summary);

        assert!(matches!(result.analysis, StructuredAnalysis::Summary(_)));
        assert_eq!(result.cost_usd, Some(0.05));
        assert_eq!(result.model.as_deref(), Some("sonnet"));
        assert_eq!(result.focus, AnalysisFocus::Summary);
    }

    /// Verify that unparseable content falls back to StructuredAnalysis::Raw.
    #[test]
    fn test_parse_claude_response_raw_fallback() {
        let envelope = serde_json::json!({
            "type": "result",
            "result": "This is plain text analysis, not JSON."
        });

        let result = parse_claude_response(&envelope.to_string(), AnalysisFocus::Summary);

        assert!(matches!(result.analysis, StructuredAnalysis::Raw { .. }));
    }

    /// Verify direct JSON parsing works for a clean JSON string.
    #[test]
    fn test_extract_json_direct() {
        let json = r#"{"risk_score": 5.0, "executive_summary": "ok", "key_findings": [], "attack_surface": "narrow", "business_impact": "low"}"#;
        let result: Option<SummaryAnalysis> = try_extract(json);
        assert!(result.is_some());
        let summary = result.expect("should parse");
        assert!((summary.risk_score - 5.0).abs() < f64::EPSILON);
    }

    /// Verify JSON extraction from markdown code fences.
    #[test]
    fn test_extract_json_code_fence() {
        let text = "Here is my analysis:\n\n```json\n{\"risk_score\": 8.0, \"executive_summary\": \"critical\", \"key_findings\": [], \"attack_surface\": \"wide\", \"business_impact\": \"high\"}\n```\n\nLet me know if you need more.";
        let result: Option<SummaryAnalysis> = try_extract(text);
        assert!(result.is_some());
        let summary = result.expect("should parse from code fence");
        assert!((summary.risk_score - 8.0).abs() < f64::EPSILON);
    }

    /// Verify JSON extraction from text with preamble and postamble.
    #[test]
    fn test_extract_json_mixed_text() {
        let text = "Based on my analysis, here are the results:\n{\"risk_score\": 3.0, \"executive_summary\": \"low risk\", \"key_findings\": [], \"attack_surface\": \"minimal\", \"business_impact\": \"negligible\"}\nThat concludes my review.";
        let result: Option<SummaryAnalysis> = try_extract(text);
        assert!(result.is_some());
    }

    /// Verify that try_extract returns None when no valid JSON is found.
    #[test]
    fn test_extract_json_fallback() {
        let text = "This is just plain text with no JSON at all.";
        let result: Option<SummaryAnalysis> = try_extract(text);
        assert!(result.is_none());
    }

    /// Verify that nested braces in strings don't break JSON block extraction.
    #[test]
    fn test_extract_json_block_nested_braces() {
        let text = r#"Preamble text {"key": "value with {braces}", "nested": {"inner": 1}} after"#;
        let block = extract_json_block(text);
        assert!(block.is_some());
        let parsed: serde_json::Value =
            serde_json::from_str(block.expect("should find block")).expect("should parse");
        assert_eq!(parsed["nested"]["inner"], 1);
    }

    /// Verify code fence extraction handles different markers.
    #[test]
    fn test_extract_code_fence_json_marker() {
        let text = "```json\n{\"a\": 1}\n```";
        assert_eq!(extract_code_fence(text), Some("{\"a\": 1}"));
    }

    /// Verify code fence returns None when no fence is present.
    #[test]
    fn test_extract_code_fence_none() {
        assert!(extract_code_fence("no fences here").is_none());
    }
}
