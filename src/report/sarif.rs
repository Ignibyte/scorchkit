use std::path::PathBuf;

use crate::config::ReportConfig;
use crate::engine::error::Result;
use crate::engine::observation::{redact_text, redact_url, ObservationLocation};
use crate::engine::scan_result::ScanResult;
use crate::engine::severity::Severity;

/// Save a scan result as a SARIF (Static Analysis Results Interchange Format) file.
/// SARIF is consumed by GitHub Advanced Security, Azure DevOps, and other CI/CD tools.
///
/// # Errors
///
/// Returns an error if serialization fails or the file cannot be written.
pub fn save_report(result: &ScanResult, config: &ReportConfig) -> Result<PathBuf> {
    let output_dir = &config.output_dir;
    std::fs::create_dir_all(output_dir)?;

    let filename = format!("scorchkit-{}.sarif", result.scan_id);
    let path = output_dir.join(&filename);

    let sarif = build_sarif(result);
    let json = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(&path, json)?;

    Ok(path)
}

fn build_sarif(result: &ScanResult) -> serde_json::Value {
    let execution_status = projected_execution_status(result);
    let rules: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            let title = redact_text(&f.title);
            let description = redact_text(&f.description);
            let mut rule = serde_json::json!({
                "id": format!("scorchkit/{}", f.module_id),
                "name": title,
                "shortDescription": { "text": title },
                "fullDescription": { "text": description },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity)
                },
            });

            if let Some(ref owasp) = f.owasp_category {
                rule["properties"] = serde_json::json!({
                    "tags": [owasp, f.module_id],
                });
            }

            if let Some(cwe) = f.cwe_id {
                rule["relationships"] = serde_json::json!([{
                    "target": {
                        "id": format!("CWE-{cwe}"),
                        "index": -1,
                        "toolComponent": { "name": "CWE" }
                    },
                    "kinds": ["superset"]
                }]);
            }

            rule
        })
        .collect();

    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            let appsec = f.canonical_appsec();
            let description = redact_text(&f.description);
            let affected_target = redact_url(&f.affected_target).0;
            let mut r = serde_json::json!({
                "ruleId": format!("scorchkit/{}", f.module_id),
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": description },
                "locations": [sarif_location(&appsec.location, &affected_target)],
                "partialFingerprints": {
                    "scorchkitFinding/v2": appsec.identity.value,
                },
                "properties": {
                    "scorchkit/schema": appsec.schema,
                    "scorchkit/provenance": appsec.provenance,
                    "scorchkit/correlationKeys": appsec.correlation_keys,
                    "scorchkit/evidence": appsec.evidence,
                    "scorchkit/agentAnalysis": appsec.agent_analysis,
                },
            });
            if !appsec.code_flows.is_empty() {
                r["codeFlows"] = serde_json::Value::Array(
                    appsec.code_flows.iter().map(sarif_code_flow).collect(),
                );
            }

            // SARIF rank: confidence mapped to 0–100 integer scale
            // JUSTIFICATION: confidence is 0.0–1.0, result fits in u8
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let rank = (f.confidence * 100.0) as u8;
            r["rank"] = serde_json::json!(rank);

            if let Some(ref remediation) = f.remediation {
                let remediation = redact_text(remediation);
                r["fixes"] = serde_json::json!([{
                    "description": { "text": remediation }
                }]);
            }

            r
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ScorchKit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/chadpeppers/scorchkit",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": result.execution_successful(),
                "startTimeUtc": result.started_at.to_rfc3339(),
                "endTimeUtc": result.completed_at.to_rfc3339(),
                "properties": {
                    "scorchkit/executionStatus": execution_status,
                    "scorchkit/moduleOutcomes": result.module_outcomes,
                    "scorchkit/supplyChain": result.supply_chain,
                    "scorchkit/applicationDast": result.application_dast,
                },
            }]
        }]
    })
}

const fn projected_execution_status(
    result: &ScanResult,
) -> crate::engine::scan_result::ScanExecutionStatus {
    result.execution_status
}

fn sarif_code_flow(flow: &crate::engine::observation::CodeFlow) -> serde_json::Value {
    let mut encoded = serde_json::json!({
        "threadFlows": flow
            .thread_flows
            .iter()
            .map(|thread| {
                let mut encoded = serde_json::json!({
                    "locations": thread
                        .steps
                        .iter()
                        .map(|step| {
                            let mut encoded = serde_json::json!({
                                "location": sarif_location(&step.location, "source://unknown"),
                            });
                            if let Some(message) = &step.message {
                                encoded["location"]["message"] =
                                    serde_json::json!({ "text": message });
                            }
                            if !step.kinds.is_empty() {
                                encoded["kinds"] = serde_json::json!(step.kinds);
                            }
                            if let Some(level) = step.nesting_level {
                                encoded["nestingLevel"] = serde_json::json!(level);
                            }
                            if let Some(order) = step.execution_order {
                                encoded["executionOrder"] = serde_json::json!(order);
                            }
                            encoded
                        })
                        .collect::<Vec<_>>(),
                });
                if let Some(message) = &thread.message {
                    encoded["message"] = serde_json::json!({ "text": message });
                }
                encoded
            })
            .collect::<Vec<_>>(),
    });
    if let Some(message) = &flow.message {
        encoded["message"] = serde_json::json!({ "text": message });
    }
    encoded
}

fn sarif_location(location: &ObservationLocation, fallback: &str) -> serde_json::Value {
    match location {
        ObservationLocation::Source { path, region } => {
            let mut physical = serde_json::json!({
                "artifactLocation": { "uri": path },
            });
            if let Some(region) = region {
                let mut sarif_region = serde_json::json!({ "startLine": region.start_line });
                if let Some(column) = region.start_column {
                    sarif_region["startColumn"] = serde_json::json!(column);
                }
                if let Some(line) = region.end_line {
                    sarif_region["endLine"] = serde_json::json!(line);
                }
                if let Some(column) = region.end_column {
                    sarif_region["endColumn"] = serde_json::json!(column);
                }
                physical["region"] = sarif_region;
            }
            serde_json::json!({ "physicalLocation": physical })
        }
        ObservationLocation::Runtime { uri, route, parameter } => serde_json::json!({
            "physicalLocation": { "artifactLocation": { "uri": uri } },
            "logicalLocations": [{
                "name": route.as_deref().unwrap_or(uri),
                "kind": "route",
                "properties": { "parameter": parameter },
            }],
        }),
        ObservationLocation::Package { ecosystem, name, version, manifest_path } => {
            let version = version.as_deref().map_or_else(String::new, |value| format!("@{value}"));
            serde_json::json!({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": manifest_path.as_deref().unwrap_or(fallback),
                    }
                },
                "logicalLocations": [{
                    "fullyQualifiedName": format!("pkg:{ecosystem}/{name}{version}"),
                    "kind": "package",
                }],
            })
        }
        ObservationLocation::Artifact { uri, digest } => serde_json::json!({
            "physicalLocation": { "artifactLocation": { "uri": uri } },
            "properties": { "digest": digest },
        }),
        ObservationLocation::Legacy { value } => serde_json::json!({
            "physicalLocation": {
                "artifactLocation": { "uri": if value.is_empty() { fallback } else { value } }
            }
        }),
    }
}

const fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::engine::finding::Finding;
    use crate::engine::observation::{
        AgentAnalysisRecord, CodeFlow, CodeFlowStep, ObservationLocation, SourceRegion, ThreadFlow,
    };
    use crate::engine::scan_result::ScanResult;
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;
    use crate::{
        ApplicationDastAssessment, ApplicationDastCoverageGap, ApplicationDastGapKind,
        ApplicationDastPhase, ApplicationDastProfile, SupplyChainAssessment,
        SupplyChainCoverageGap, SupplyChainGapKind, SupplyChainPhase, SupplyChainTarget,
        SupplyChainTargetKind,
    };

    fn result_with(finding: Finding) -> ScanResult {
        ScanResult::new(
            "sarif-test".to_string(),
            Target::parse("https://example.com").expect("valid target"),
            Utc::now(),
            vec![finding],
            vec!["semgrep".to_string()],
            Vec::new(),
        )
    }

    #[test]
    fn sarif_uses_typed_source_location_and_stable_partial_fingerprint() {
        let finding = Finding::new("semgrep", Severity::High, "Rule", "Description", "legacy")
            .with_location(ObservationLocation::Source {
                path: "src/main.rs".to_string(),
                region: Some(SourceRegion::new(12).with_bounds(Some(4), Some(12), Some(9))),
            })
            .with_cwe(95)
            .with_evidence("proof");
        let identity = finding.canonical_appsec().identity.value;
        let sarif = build_sarif(&result_with(finding));
        let output = &sarif["runs"][0]["results"][0];
        assert_eq!(
            output["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );
        assert_eq!(output["locations"][0]["physicalLocation"]["region"]["startLine"], 12);
        assert_eq!(output["partialFingerprints"]["scorchkitFinding/v2"], identity);
        assert!(output.get("fingerprints").is_none());
    }

    #[test]
    fn sarif_keeps_redacted_evidence_and_labeled_analysis_out_of_fingerprints() {
        let finding = Finding::new(
            "nuclei",
            Severity::Medium,
            "Login probe",
            "Description",
            "https://example.com/login",
        )
        .with_evidence("password=secret")
        .with_agent_analysis(AgentAnalysisRecord::new(
            "codex-security",
            Some("trusted-security".to_string()),
            "Validated",
            Vec::new(),
            Utc::now(),
        ));
        let sarif = build_sarif(&result_with(finding));
        let encoded = serde_json::to_string(&sarif).expect("serialize SARIF");
        assert!(!encoded.contains("password=secret"));
        assert!(!encoded.contains("\"fingerprints\""));
        assert!(encoded.contains("scorchkit/agentAnalysis"));
        assert!(encoded.contains("codex-security"));
    }

    #[test]
    fn sarif_marks_failed_module_results_degraded_and_keeps_outcomes() {
        let mut result = result_with(Finding::new(
            "semgrep",
            Severity::Low,
            "Rule",
            "Description",
            "src/main.rs:1",
        ));
        result.module_outcomes = vec![crate::engine::scan_result::ModuleOutcome::failed(
            "codeql",
            crate::engine::scan_result::ModuleOutcomeReason::ExecutionFailed {
                message: "api_key=sarif-secret".to_string(),
            },
        )];
        result.refresh_execution_status();

        let sarif = build_sarif(&result);
        let invocation = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
        assert_eq!(invocation["properties"]["scorchkit/executionStatus"], "degraded");
        assert_eq!(invocation["properties"]["scorchkit/moduleOutcomes"][0]["status"], "failed");
        assert!(!serde_json::to_string(&sarif).expect("serialize SARIF").contains("sarif-secret"));
    }

    #[test]
    fn sarif_marks_missing_supply_chain_coverage_incomplete_and_projects_exact_gap() {
        let mut assessment = SupplyChainAssessment::new(SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: PathBuf::from("/owned/source"),
            revision: Some("revision-1".to_string()),
            sha256: None,
        });
        assessment.record_gap(SupplyChainCoverageGap::new(
            SupplyChainPhase::SourceDependencyScan,
            SupplyChainGapKind::MissingProviderSnapshot,
            Some("osv".to_string()),
            "OSV snapshot is unavailable",
        ));
        let result = result_with(Finding::new(
            "dep-audit",
            Severity::Info,
            "Dependency inventory",
            "Inventory completed",
            "Cargo.lock",
        ))
        .with_supply_chain(assessment);

        let sarif = build_sarif(&result);
        let invocation = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
        assert_eq!(invocation["properties"]["scorchkit/executionStatus"], "incomplete");
        assert_eq!(
            invocation["properties"]["scorchkit/supplyChain"]["coverage_status"],
            "incomplete"
        );
        assert_eq!(
            invocation["properties"]["scorchkit/supplyChain"]["gaps"][0]["kind"],
            "missing_provider_snapshot"
        );
    }

    #[test]
    fn sarif_projects_degraded_application_dast_coverage_without_secrets() {
        let mut assessment =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        assessment.zap_version = "2.17.0".to_string();
        assessment.record_gap(ApplicationDastCoverageGap::new(
            "user",
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::AuthenticationFailed,
            "password=sarif-dast-secret",
        ));
        let result = result_with(Finding::new(
            "zap",
            Severity::Info,
            "DAST coverage",
            "No alert",
            "https://example.com",
        ))
        .with_application_dast(assessment);

        let sarif = build_sarif(&result);
        let invocation = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
        assert_eq!(invocation["properties"]["scorchkit/executionStatus"], "degraded");
        assert_eq!(
            invocation["properties"]["scorchkit/applicationDast"]["gaps"][0]["kind"],
            "authentication_failed"
        );
        assert!(!serde_json::to_string(&sarif)
            .expect("serialize SARIF")
            .contains("sarif-dast-secret"));
    }

    #[test]
    fn sarif_redacts_mutated_finding_text_fields() {
        let mut finding =
            Finding::new("semgrep", Severity::High, "Rule", "Description", "src/main.rs:1");
        finding.title = "api_key=title-secret".to_string();
        finding.description = "password = \"description-secret\"".to_string();
        finding.remediation = Some("token='remediation-secret'".to_string());

        let encoded =
            serde_json::to_string(&build_sarif(&result_with(finding))).expect("serialize SARIF");
        assert!(!encoded.contains("title-secret"));
        assert!(!encoded.contains("description-secret"));
        assert!(!encoded.contains("remediation-secret"));
    }

    #[test]
    fn sarif_projects_every_flow_path_step_and_order_field() {
        let mut source = CodeFlowStep::new(ObservationLocation::Source {
            path: "src/input.rs".to_string(),
            region: Some(SourceRegion::new(4)),
        });
        source.message = Some("request input".to_string());
        source.kinds = vec!["source".to_string()];
        source.execution_order = Some(0);
        let mut sink = CodeFlowStep::new(ObservationLocation::Source {
            path: "src/query.rs".to_string(),
            region: Some(SourceRegion::new(18)),
        });
        sink.kinds = vec!["sink".to_string()];
        sink.execution_order = Some(1);
        let finding = Finding::new(
            "codeql",
            Severity::High,
            "SQL injection",
            "Tainted input reaches SQL",
            "src/query.rs:18",
        )
        .with_code_flows(vec![CodeFlow {
            message: Some("request to query".to_string()),
            thread_flows: vec![ThreadFlow {
                message: Some("primary path".to_string()),
                steps: vec![source, sink],
            }],
        }]);

        let sarif = build_sarif(&result_with(finding));
        let flow = &sarif["runs"][0]["results"][0]["codeFlows"][0];
        assert_eq!(flow["message"]["text"], "request to query");
        assert_eq!(flow["threadFlows"][0]["message"]["text"], "primary path");
        let steps = flow["threadFlows"][0]["locations"].as_array().expect("flow locations");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["kinds"], serde_json::json!(["source"]));
        assert_eq!(steps[0]["executionOrder"], 0);
        assert_eq!(
            steps[1]["location"]["physicalLocation"]["artifactLocation"]["uri"],
            "src/query.rs"
        );
        assert_eq!(steps[1]["executionOrder"], 1);
    }
}
