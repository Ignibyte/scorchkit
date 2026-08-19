//! Tests for AI scan planning types and validation logic.
//!
//! Verifies serde round-trip correctness for plan types,
//! plan validation against registered modules and typed module catalog
//! generation.

use scorchkit::ai::contracts::{AiContractResponse, AiModuleInput, AiTask, AI_CONTRACT_SCHEMA};
use scorchkit::ai::response::try_extract;
use scorchkit::ai::types::{validate_plan, ModuleRecommendation, ScanPlan, SkippedModule};

/// Verify `ScanPlan` round-trips through JSON serialization.
#[test]
fn test_scan_plan_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let plan = ScanPlan {
        target: "https://example.com".to_string(),
        recommendations: vec![ModuleRecommendation {
            module_id: "ssl".to_string(),
            priority: 1,
            rationale: "TLS check is essential".to_string(),
            category: "scanner".to_string(),
        }],
        skipped_modules: vec![SkippedModule {
            module_id: "wpscan".to_string(),
            reason: "Not a WordPress site".to_string(),
        }],
        overall_strategy: "Focus on web app security".to_string(),
        estimated_scan_time: Some("5 minutes".to_string()),
    };

    let json = serde_json::to_string(&plan)?;
    let parsed: ScanPlan = serde_json::from_str(&json)?;

    assert_eq!(parsed.target, "https://example.com");
    assert_eq!(parsed.recommendations.len(), 1);
    assert_eq!(parsed.recommendations[0].module_id, "ssl");
    assert_eq!(parsed.skipped_modules.len(), 1);
    assert_eq!(parsed.overall_strategy, "Focus on web app security");
    assert_eq!(parsed.estimated_scan_time.as_deref(), Some("5 minutes"));
    Ok(())
}

/// Verify `ModuleRecommendation` round-trips through JSON serialization.
#[test]
fn test_module_recommendation_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let rec = ModuleRecommendation {
        module_id: "injection".to_string(),
        priority: 2,
        rationale: "SQL injection detected in recon".to_string(),
        category: "scanner".to_string(),
    };

    let json = serde_json::to_string(&rec)?;
    let parsed: ModuleRecommendation = serde_json::from_str(&json)?;

    assert_eq!(parsed.module_id, "injection");
    assert_eq!(parsed.priority, 2);
    assert_eq!(parsed.category, "scanner");
    Ok(())
}

/// Verify `SkippedModule` round-trips through JSON serialization.
#[test]
fn test_skipped_module_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let skipped = SkippedModule {
        module_id: "droopescan".to_string(),
        reason: "Not a Drupal site".to_string(),
    };

    let json = serde_json::to_string(&skipped)?;
    let parsed: SkippedModule = serde_json::from_str(&json)?;

    assert_eq!(parsed.module_id, "droopescan");
    assert_eq!(parsed.reason, "Not a Drupal site");
    Ok(())
}

/// Verify an empty plan (no recommendations) is valid.
#[test]
fn test_scan_plan_empty() -> Result<(), Box<dyn std::error::Error>> {
    let plan = ScanPlan {
        target: "https://example.com".to_string(),
        recommendations: vec![],
        skipped_modules: vec![],
        overall_strategy: "No modules needed".to_string(),
        estimated_scan_time: None,
    };

    let json = serde_json::to_string(&plan)?;
    let parsed: ScanPlan = serde_json::from_str(&json)?;

    assert!(parsed.recommendations.is_empty());
    assert!(parsed.skipped_modules.is_empty());
    assert!(parsed.estimated_scan_time.is_none());
    Ok(())
}

/// Verify validation passes when all module IDs are known.
#[test]
fn test_validate_plan_all_valid() {
    let plan = ScanPlan {
        target: "https://example.com".to_string(),
        recommendations: vec![
            ModuleRecommendation {
                module_id: "ssl".to_string(),
                priority: 1,
                rationale: "check TLS".to_string(),
                category: "scanner".to_string(),
            },
            ModuleRecommendation {
                module_id: "headers".to_string(),
                priority: 2,
                rationale: "check headers".to_string(),
                category: "recon".to_string(),
            },
        ],
        skipped_modules: vec![],
        overall_strategy: "test".to_string(),
        estimated_scan_time: None,
    };

    let known = &["ssl", "headers", "tech", "injection"];
    let result = validate_plan(&plan, known);

    assert_eq!(result.valid_recommendations.len(), 2);
    assert!(result.unknown_modules.is_empty());
}

/// Verify validation removes unknown module IDs.
#[test]
fn test_validate_plan_unknown_modules() {
    let plan = ScanPlan {
        target: "https://example.com".to_string(),
        recommendations: vec![
            ModuleRecommendation {
                module_id: "hallucinated_module".to_string(),
                priority: 1,
                rationale: "fake".to_string(),
                category: "scanner".to_string(),
            },
            ModuleRecommendation {
                module_id: "nonexistent".to_string(),
                priority: 2,
                rationale: "also fake".to_string(),
                category: "scanner".to_string(),
            },
        ],
        skipped_modules: vec![],
        overall_strategy: "test".to_string(),
        estimated_scan_time: None,
    };

    let known = &["ssl", "headers"];
    let result = validate_plan(&plan, known);

    assert!(result.valid_recommendations.is_empty());
    assert_eq!(result.unknown_modules.len(), 2);
    assert!(result.unknown_modules.contains(&"hallucinated_module".to_string()));
    assert!(result.unknown_modules.contains(&"nonexistent".to_string()));
}

/// Verify validation handles a mix of valid and unknown IDs.
#[test]
fn test_validate_plan_mixed() {
    let plan = ScanPlan {
        target: "https://example.com".to_string(),
        recommendations: vec![
            ModuleRecommendation {
                module_id: "ssl".to_string(),
                priority: 1,
                rationale: "real".to_string(),
                category: "scanner".to_string(),
            },
            ModuleRecommendation {
                module_id: "fake_module".to_string(),
                priority: 2,
                rationale: "hallucinated".to_string(),
                category: "scanner".to_string(),
            },
            ModuleRecommendation {
                module_id: "headers".to_string(),
                priority: 3,
                rationale: "also real".to_string(),
                category: "recon".to_string(),
            },
        ],
        skipped_modules: vec![],
        overall_strategy: "test".to_string(),
        estimated_scan_time: None,
    };

    let known = &["ssl", "headers", "tech"];
    let result = validate_plan(&plan, known);

    assert_eq!(result.valid_recommendations.len(), 2);
    assert_eq!(result.valid_recommendations[0].module_id, "ssl");
    assert_eq!(result.valid_recommendations[1].module_id, "headers");
    assert_eq!(result.unknown_modules, vec!["fake_module"]);
}

/// Verify the module catalog contains all registered module IDs.
#[test]
fn test_module_catalog_contains_all() {
    let modules = scorchkit::runner::orchestrator::all_modules();
    let catalog = AiModuleInput::collect(&modules);

    // Every module ID should appear in the catalog
    for module in &modules {
        let id = module.id();
        assert!(catalog.iter().any(|entry| entry.id == id), "module '{id}' missing from catalog");
    }
}

/// Verify catalog entries have required fields.
#[test]
fn test_module_catalog_format() {
    let modules = scorchkit::runner::orchestrator::application_modules();
    let catalog = AiModuleInput::collect(&modules);

    assert!(!catalog.is_empty(), "catalog should not be empty");

    for entry in &catalog {
        assert!(!entry.id.is_empty(), "entry missing 'id'");
        assert!(!entry.name.is_empty(), "entry missing 'name'");
        assert!(!entry.description.is_empty(), "entry missing 'description'");
        assert!(matches!(entry.category.as_str(), "recon" | "scanner"));
        assert_eq!(entry.adapter_schema, scorchkit_core::ADAPTER_CONTRACT_V1);
        assert!(entry.security_domain.is_application_security());
    }
}

/// Verify the versioned response envelope round-trips a typed plan.
#[test]
fn test_versioned_plan_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let response = AiContractResponse {
        schema: AI_CONTRACT_SCHEMA.to_string(),
        task: AiTask::Plan,
        payload: ScanPlan {
            target: "https://example.com".to_string(),
            recommendations: vec![ModuleRecommendation {
                module_id: "ssl".to_string(),
                priority: 1,
                rationale: "TLS check".to_string(),
                category: "scanner".to_string(),
            }],
            skipped_modules: Vec::new(),
            overall_strategy: "Focus on TLS".to_string(),
            estimated_scan_time: Some("2 minutes".to_string()),
        },
    };
    let encoded = serde_json::to_string(&response)?;
    let decoded: AiContractResponse<ScanPlan> = serde_json::from_str(&encoded)?;
    assert_eq!(decoded.schema, AI_CONTRACT_SCHEMA);
    assert_eq!(decoded.task, AiTask::Plan);
    assert_eq!(decoded.payload.recommendations[0].module_id, "ssl");
    Ok(())
}

/// Verify `try_extract` can parse a `ScanPlan` from raw JSON.
#[test]
fn test_try_extract_scan_plan() {
    let json = r#"{
        "target": "https://example.com",
        "recommendations": [],
        "skipped_modules": [],
        "overall_strategy": "minimal",
        "estimated_scan_time": null
    }"#;
    let result: Option<ScanPlan> = try_extract(json);
    assert!(result.is_some());
    let plan = result.unwrap_or_else(|| unreachable!());
    assert_eq!(plan.target, "https://example.com");
}

/// Verify MCP `PlanScanParams` deserializes from JSON correctly.
#[cfg(feature = "mcp")]
#[test]
fn test_plan_scan_params_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"target": "https://example.com"}"#;
    let params: scorchkit::mcp::types::PlanScanParams = serde_json::from_str(json)?;
    assert_eq!(params.target, "https://example.com");
    Ok(())
}
