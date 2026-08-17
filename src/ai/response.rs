//! Provider-neutral AI response parsing with structured JSON extraction.
//!
//! Attempts to parse normalized provider text into typed structs. Legacy
//! Claude CLI envelopes remain accepted at this boundary for compatibility.

use serde::de::DeserializeOwned;

use crate::ai::prompts::AnalysisFocus;
use crate::ai::types::{
    AiAnalysis, FilterAnalysis, PrioritizedAnalysis, RemediationAnalysis, ScanPlan,
    StructuredAnalysis, SummaryAnalysis,
};

/// Parse normalized provider output into an [`AiAnalysis`].
#[must_use]
pub fn parse_analysis_response(
    content: &str,
    focus: AnalysisFocus,
    cost_usd: Option<f64>,
    model: Option<String>,
) -> AiAnalysis {
    let analysis = parse_structured_analysis(content, focus);
    AiAnalysis { focus, analysis, raw_response: content.to_string(), cost_usd, model }
}

/// Parse a legacy Claude CLI JSON envelope into an [`AiAnalysis`].
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

    parse_analysis_response(&content, focus, cost_usd, model)
}

/// Attempt to parse the analysis text into a structured type based on focus.
///
/// Uses a multi-tier extraction strategy:
/// 1. Direct JSON parse of the full text
/// 2. Extract from markdown code fences (` ```json ... ``` `)
/// 3. Deserialize the first JSON object after the first `{`
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
/// 3. Deserialize the first object beginning at the first `{`
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

    // Strategy 3: Let serde_json own string escaping, nesting, and object boundaries.
    let start = trimmed.find('{')?;
    serde_json::Deserializer::from_str(&trimmed[start..])
        .into_iter::<T>()
        .next()
        .and_then(std::result::Result::ok)
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

/// Parse normalized or legacy provider output into a [`ScanPlan`].
///
/// Extracts the result text from a legacy JSON envelope when present, then
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

    /// Verify that `parse_claude_response` extracts structured summary from
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

    /// Verify that unparsable content falls back to `StructuredAnalysis::Raw`.
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

    /// Verify that `try_extract` returns None when no valid JSON is found.
    #[test]
    fn test_extract_json_fallback() {
        let text = "This is just plain text with no JSON at all.";
        let result: Option<SummaryAnalysis> = try_extract(text);
        assert!(result.is_none());
    }

    /// Verify serde-owned extraction handles escaped quotes, slashes, braces, and nesting.
    #[test]
    fn test_extract_json_with_escaped_content_and_nested_object() {
        let text =
            r#"Preamble text {"key":"quote: \" slash: \\ brace: }","nested":{"inner":1}} after"#;
        let parsed: serde_json::Value = try_extract(text).expect("should parse first object");
        assert_eq!(parsed["key"], "quote: \" slash: \\ brace: }");
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
