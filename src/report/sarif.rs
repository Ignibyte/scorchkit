use std::path::PathBuf;

use crate::config::ReportConfig;
use crate::engine::error::Result;
use crate::engine::observation::ObservationLocation;
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
    let rules: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            let mut rule = serde_json::json!({
                "id": format!("scorchkit/{}", f.module_id),
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
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
            let mut r = serde_json::json!({
                "ruleId": format!("scorchkit/{}", f.module_id),
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": f.description },
                "locations": [sarif_location(&appsec.location, &f.affected_target)],
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

            // SARIF rank: confidence mapped to 0–100 integer scale
            // JUSTIFICATION: confidence is 0.0–1.0, result fits in u8
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let rank = (f.confidence * 100.0) as u8;
            r["rank"] = serde_json::json!(rank);

            if let Some(ref remediation) = f.remediation {
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
                "executionSuccessful": true,
                "startTimeUtc": result.started_at.to_rfc3339(),
                "endTimeUtc": result.completed_at.to_rfc3339(),
            }]
        }]
    })
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
    use crate::engine::observation::{AgentAnalysisRecord, ObservationLocation, SourceRegion};
    use crate::engine::scan_result::ScanResult;
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;

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
}
