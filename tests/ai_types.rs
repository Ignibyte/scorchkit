//! Tests for structured AI analysis types.
//!
//! Verifies serde round-trip correctness for all analysis types, JSON
//! extraction from various response formats, and enum serialization
//! with the expected snake_case conventions.

use scorchkit::ai::prompts::AnalysisFocus;
use scorchkit::ai::response::try_extract;
use scorchkit::ai::types::{
    AttackChain, EffortLevel, ExploitabilityRating, FilterAnalysis, FilteredFinding,
    FindingClassification, FindingTrends, KeyFinding, PrioritizedAnalysis, PrioritizedFinding,
    ProjectContext, RemediationAnalysis, RemediationStep, StatusBreakdown, StructuredAnalysis,
    SummaryAnalysis,
};

/// Verify `SummaryAnalysis` round-trips through JSON serialization.
#[test]
fn test_summary_analysis_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let summary = SummaryAnalysis {
        risk_score: 7.5,
        executive_summary: "The target has critical vulnerabilities.".to_string(),
        key_findings: vec![KeyFinding {
            finding_index: 1,
            severity: "critical".to_string(),
            title: "SQL Injection".to_string(),
            business_impact: "Full database access".to_string(),
            exploitability: ExploitabilityRating::Critical,
        }],
        attack_surface: "Wide exposure via public APIs.".to_string(),
        business_impact: "Potential data breach.".to_string(),
    };

    let json = serde_json::to_string(&summary)?;
    let parsed: SummaryAnalysis = serde_json::from_str(&json)?;

    assert!((parsed.risk_score - 7.5).abs() < f64::EPSILON);
    assert_eq!(parsed.key_findings.len(), 1);
    assert_eq!(parsed.key_findings[0].finding_index, 1);
    assert_eq!(parsed.key_findings[0].exploitability, ExploitabilityRating::Critical);
    Ok(())
}

/// Verify `PrioritizedAnalysis` round-trips through JSON serialization.
#[test]
fn test_prioritized_analysis_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = PrioritizedAnalysis {
        prioritized_findings: vec![PrioritizedFinding {
            finding_index: 2,
            title: "XSS".to_string(),
            severity: "high".to_string(),
            exploitability: ExploitabilityRating::High,
            business_impact_score: 6.0,
            effort_to_exploit: EffortLevel::Low,
            rationale: "Reflected XSS in search parameter.".to_string(),
        }],
        attack_chains: vec![AttackChain {
            name: "XSS to session hijack".to_string(),
            finding_indices: vec![2, 3],
            combined_impact: "Account takeover".to_string(),
            likelihood: "high".to_string(),
        }],
        recommended_fix_order: vec![2, 3, 1],
    };

    let json = serde_json::to_string(&analysis)?;
    let parsed: PrioritizedAnalysis = serde_json::from_str(&json)?;

    assert_eq!(parsed.prioritized_findings.len(), 1);
    assert_eq!(parsed.attack_chains.len(), 1);
    assert_eq!(parsed.recommended_fix_order, vec![2, 3, 1]);
    Ok(())
}

/// Verify `RemediationAnalysis` round-trips through JSON serialization.
#[test]
fn test_remediation_analysis_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = RemediationAnalysis {
        remediations: vec![RemediationStep {
            finding_index: 1,
            title: "Missing CSP".to_string(),
            severity: "medium".to_string(),
            fix_description: "Add Content-Security-Policy header.".to_string(),
            code_example: Some("Content-Security-Policy: default-src 'self'".to_string()),
            effort: EffortLevel::Trivial,
            priority: 1,
            verification_steps: vec!["Check response headers with curl.".to_string()],
        }],
        quick_wins: vec![1],
        total_estimated_effort: "2 hours".to_string(),
    };

    let json = serde_json::to_string(&analysis)?;
    let parsed: RemediationAnalysis = serde_json::from_str(&json)?;

    assert_eq!(parsed.remediations.len(), 1);
    assert_eq!(parsed.remediations[0].effort, EffortLevel::Trivial);
    assert_eq!(parsed.quick_wins, vec![1]);
    Ok(())
}

/// Verify `FilterAnalysis` round-trips through JSON serialization.
#[test]
fn test_filter_analysis_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = FilterAnalysis {
        findings: vec![FilteredFinding {
            finding_index: 1,
            title: "Missing X-Frame-Options".to_string(),
            classification: FindingClassification::LikelyFalsePositive,
            confidence: 0.85,
            rationale: "Site uses CSP frame-ancestors instead.".to_string(),
        }],
        false_positive_count: 1,
        confirmed_count: 0,
        uncertain_count: 0,
    };

    let json = serde_json::to_string(&analysis)?;
    let parsed: FilterAnalysis = serde_json::from_str(&json)?;

    assert_eq!(parsed.false_positive_count, 1);
    assert_eq!(parsed.findings[0].classification, FindingClassification::LikelyFalsePositive);
    assert!((parsed.findings[0].confidence - 0.85).abs() < f64::EPSILON);
    Ok(())
}

/// Verify `StructuredAnalysis` tagged enum serializes with the `type` discriminant.
#[test]
fn test_structured_analysis_tagged_enum() -> Result<(), Box<dyn std::error::Error>> {
    let raw = StructuredAnalysis::Raw { content: "plain text".to_string() };
    let json = serde_json::to_string(&raw)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;

    assert_eq!(value["type"], "raw");
    assert_eq!(value["content"], "plain text");

    let summary = StructuredAnalysis::Summary(SummaryAnalysis {
        risk_score: 5.0,
        executive_summary: "moderate risk".to_string(),
        key_findings: vec![],
        attack_surface: "narrow".to_string(),
        business_impact: "limited".to_string(),
    });
    let json = serde_json::to_string(&summary)?;
    let value: serde_json::Value = serde_json::from_str(&json)?;
    assert_eq!(value["type"], "summary");
    assert_eq!(value["risk_score"], 5.0);
    Ok(())
}

/// Verify `ExploitabilityRating` serializes with snake_case.
#[test]
fn test_exploitability_rating_serde() -> Result<(), Box<dyn std::error::Error>> {
    let rating = ExploitabilityRating::Theoretical;
    let json = serde_json::to_string(&rating)?;
    assert_eq!(json, "\"theoretical\"");

    let parsed: ExploitabilityRating = serde_json::from_str("\"critical\"")?;
    assert_eq!(parsed, ExploitabilityRating::Critical);
    Ok(())
}

/// Verify `EffortLevel` serializes with snake_case.
#[test]
fn test_effort_level_serde() -> Result<(), Box<dyn std::error::Error>> {
    let effort = EffortLevel::Major;
    let json = serde_json::to_string(&effort)?;
    assert_eq!(json, "\"major\"");

    let parsed: EffortLevel = serde_json::from_str("\"trivial\"")?;
    assert_eq!(parsed, EffortLevel::Trivial);
    Ok(())
}

/// Verify `FindingClassification` serializes with snake_case.
#[test]
fn test_finding_classification_serde() -> Result<(), Box<dyn std::error::Error>> {
    let cls = FindingClassification::LikelyFalsePositive;
    let json = serde_json::to_string(&cls)?;
    assert_eq!(json, "\"likely_false_positive\"");

    let parsed: FindingClassification = serde_json::from_str("\"confirmed\"")?;
    assert_eq!(parsed, FindingClassification::Confirmed);
    Ok(())
}

/// Verify `ProjectContext` round-trips through JSON serialization.
#[test]
fn test_project_context_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ProjectContext {
        project_name: "test-project".to_string(),
        total_scans: 5,
        latest_scan_date: Some("2026-03-28 15:30".to_string()),
        finding_trends: FindingTrends {
            total_tracked: 12,
            by_status: StatusBreakdown {
                new: 3,
                acknowledged: 2,
                false_positive: 1,
                remediated: 4,
                verified: 2,
            },
        },
    };

    let json = serde_json::to_string(&ctx)?;
    let parsed: ProjectContext = serde_json::from_str(&json)?;

    assert_eq!(parsed.project_name, "test-project");
    assert_eq!(parsed.total_scans, 5);
    assert_eq!(parsed.finding_trends.total_tracked, 12);
    assert_eq!(parsed.finding_trends.by_status.remediated, 4);
    Ok(())
}

/// Verify `AnalysisFocus` round-trips through JSON with snake_case.
#[test]
fn test_analysis_focus_serde() -> Result<(), Box<dyn std::error::Error>> {
    let focus = AnalysisFocus::Remediate;
    let json = serde_json::to_string(&focus)?;
    assert_eq!(json, "\"remediate\"");

    let parsed: AnalysisFocus = serde_json::from_str("\"prioritize\"")?;
    assert_eq!(parsed, AnalysisFocus::Prioritize);
    Ok(())
}

/// Verify `AnalysisFocus::parse` handles common aliases.
#[test]
fn test_analysis_focus_parse_aliases() {
    assert_eq!(AnalysisFocus::parse("summary"), AnalysisFocus::Summary);
    assert_eq!(AnalysisFocus::parse("prioritize"), AnalysisFocus::Prioritize);
    assert_eq!(AnalysisFocus::parse("prio"), AnalysisFocus::Prioritize);
    assert_eq!(AnalysisFocus::parse("remediate"), AnalysisFocus::Remediate);
    assert_eq!(AnalysisFocus::parse("fix"), AnalysisFocus::Remediate);
    assert_eq!(AnalysisFocus::parse("filter"), AnalysisFocus::Filter);
    assert_eq!(AnalysisFocus::parse("fp"), AnalysisFocus::Filter);
    assert_eq!(AnalysisFocus::parse("unknown"), AnalysisFocus::Summary);
}

/// Verify `try_extract` returns `None` for completely invalid input.
#[test]
fn test_try_extract_returns_none_for_garbage() {
    let result: Option<SummaryAnalysis> = try_extract("not json at all {{{broken");
    assert!(result.is_none());
}

/// Verify `try_extract` handles whitespace-wrapped JSON.
#[test]
fn test_try_extract_handles_whitespace() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"
        {
            "risk_score": 2.0,
            "executive_summary": "low risk",
            "key_findings": [],
            "attack_surface": "minimal",
            "business_impact": "negligible"
        }
    "#;
    let result: Option<SummaryAnalysis> = try_extract(json);
    assert!(result.is_some());
    Ok(())
}

/// Verify `AnalyzeFindingsParams` MCP parameter type deserializes correctly.
#[cfg(feature = "mcp")]
#[test]
fn test_analyze_findings_params_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"project": "my-project", "focus": "remediate"}"#;
    let params: scorchkit::mcp::types::AnalyzeFindingsParams = serde_json::from_str(json)?;
    assert_eq!(params.project, "my-project");
    assert_eq!(params.focus, "remediate");
    assert!(params.scan_id.is_none());
    Ok(())
}
