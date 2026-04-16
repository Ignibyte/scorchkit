//! Claude-driven attack-chain correlation (WORK-137).
//!
//! Layers Claude reasoning on top of the rule-based
//! [`engine::correlation`] engine. When AI is available, feeds
//! findings to Claude with structured prompts for attack-chain
//! analysis. Falls back gracefully to rule-based output when AI
//! is disabled or unavailable.

use crate::engine::correlation::{correlate, AttackChain};
use crate::engine::finding::Finding;

/// Build the prompt for Claude to analyze findings and identify attack chains.
///
/// Returns a system prompt + user prompt pair suitable for the
/// Claude CLI or API.
#[must_use]
pub fn build_correlation_prompt(findings: &[Finding]) -> (String, String) {
    let system = "You are a senior penetration tester analyzing security scan results. \
        Identify attack chains — sequences of findings that combine to create \
        exploit paths more severe than any individual finding. For each chain, \
        explain the attack narrative, list the contributing findings, and rate \
        the combined severity. Focus on cross-domain chains (DAST + SAST + Infra + Cloud). \
        Output JSON: [{\"name\": \"...\", \"severity\": \"critical|high|medium|low\", \
        \"description\": \"...\", \"steps\": [{\"module_id\": \"...\", \"title\": \"...\", \
        \"role\": \"...\"}], \"remediation_priority\": \"immediate|high|medium|low\"}]"
        .to_string();

    let mut user = String::from("Analyze these security findings for attack chains:\n\n");
    for (i, f) in findings.iter().enumerate() {
        use std::fmt::Write;
        let _ = writeln!(
            user,
            "{}. [{}] {} (module: {}, target: {})",
            i + 1,
            f.severity,
            f.title,
            f.module_id,
            f.affected_target,
        );
    }
    user.push_str("\nIdentify all compound attack paths. Return JSON array.");

    (system, user)
}

/// Parse Claude's response into attack chains.
///
/// Falls back to empty vec on parse failure — the caller should
/// merge with rule-based results.
#[must_use]
pub fn parse_correlation_response(response: &str) -> Vec<AttackChain> {
    // Try to extract JSON from the response (Claude may wrap in markdown)
    let json_str = extract_json_array(response);
    serde_json::from_str(json_str).unwrap_or_default()
}

/// Correlate findings using both rule-based and AI-driven analysis.
///
/// When `ai_response` is `Some`, merges AI-identified chains with
/// rule-based chains (deduplicating by name). When `None`, returns
/// only rule-based chains.
#[must_use]
pub fn correlate_with_ai(findings: &[Finding], ai_response: Option<&str>) -> Vec<AttackChain> {
    let mut chains = correlate(findings);

    if let Some(response) = ai_response {
        let ai_chains = parse_correlation_response(response);
        for ai_chain in ai_chains {
            if !chains.iter().any(|c| c.name == ai_chain.name) {
                chains.push(ai_chain);
            }
        }
    }

    chains
}

/// Extract a JSON array from a response that may contain markdown fences.
fn extract_json_array(text: &str) -> &str {
    // Try to find ```json ... ``` block
    if let Some(start) = text.find("```json") {
        let content_start = start + 7;
        if let Some(end) = text[content_start..].find("```") {
            return text[content_start..content_start + end].trim();
        }
    }
    // Try to find bare ``` ... ``` block
    if let Some(start) = text.find("```") {
        let content_start = start + 3;
        if let Some(end) = text[content_start..].find("```") {
            return text[content_start..content_start + end].trim();
        }
    }
    // Try the raw text
    text.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    fn finding(module_id: &str, title: &str, severity: Severity) -> Finding {
        Finding::new(module_id, severity, title, "desc", "https://example.com")
    }

    /// Prompt includes all findings.
    #[test]
    fn test_build_correlation_prompt() {
        let findings = vec![
            finding("xss", "Reflected XSS", Severity::High),
            finding("headers", "Missing CSP", Severity::Medium),
        ];
        let (system, user) = build_correlation_prompt(&findings);
        assert!(system.contains("attack chains"));
        assert!(user.contains("Reflected XSS"));
        assert!(user.contains("Missing CSP"));
    }

    /// Parse valid JSON response.
    #[test]
    fn test_parse_correlation_response() {
        let response = r#"[{"name": "Test Chain", "severity": "high", "description": "A test", "steps": [{"module_id": "xss", "title": "XSS", "role": "entry"}], "remediation_priority": "high"}]"#;
        let chains = parse_correlation_response(response);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "Test Chain");
    }

    /// Parse response with markdown fences.
    #[test]
    fn test_parse_correlation_response_markdown() {
        let response = "Here's my analysis:\n```json\n[{\"name\": \"Fenced\", \"severity\": \"critical\", \"description\": \"test\", \"steps\": [], \"remediation_priority\": \"immediate\"}]\n```\n";
        let chains = parse_correlation_response(response);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "Fenced");
    }

    /// Invalid response → empty vec (graceful fallback).
    #[test]
    fn test_parse_correlation_response_invalid() {
        assert!(parse_correlation_response("not json").is_empty());
        assert!(parse_correlation_response("").is_empty());
    }

    /// `correlate_with_ai` merges AI + rule-based chains.
    #[test]
    fn test_correlate_with_ai_merges() {
        let findings = vec![
            finding("xss", "Reflected XSS", Severity::High),
            finding("headers", "Missing CSP", Severity::Medium),
        ];
        let ai_response = r#"[{"name": "AI-Discovered Chain", "severity": "high", "description": "AI found this", "steps": [], "remediation_priority": "high"}]"#;
        let chains = correlate_with_ai(&findings, Some(ai_response));
        // Should have rule-based chain + AI chain
        assert!(chains.iter().any(|c| c.name.contains("Session Hijacking")));
        assert!(chains.iter().any(|c| c.name.contains("AI-Discovered")));
    }

    /// `correlate_with_ai` without AI response = rule-based only.
    #[test]
    fn test_correlate_with_ai_fallback() {
        let findings = vec![
            finding("xss", "Reflected XSS", Severity::High),
            finding("headers", "Missing CSP", Severity::Medium),
        ];
        let chains = correlate_with_ai(&findings, None);
        assert!(chains.iter().any(|c| c.name.contains("Session Hijacking")));
    }

    /// AI duplicates are deduped by name.
    #[test]
    fn test_correlate_with_ai_dedup() {
        let findings = vec![
            finding("xss", "Reflected XSS", Severity::High),
            finding("headers", "Missing CSP", Severity::Medium),
        ];
        let ai_response = r#"[{"name": "Session Hijacking via XSS + Weak CSP", "severity": "high", "description": "same as rule", "steps": [], "remediation_priority": "high"}]"#;
        let chains = correlate_with_ai(&findings, Some(ai_response));
        let session_count = chains.iter().filter(|c| c.name.contains("Session Hijacking")).count();
        assert_eq!(session_count, 1, "duplicate should be deduped");
    }
}
