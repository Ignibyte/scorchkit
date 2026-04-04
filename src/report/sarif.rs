use std::path::PathBuf;

use crate::config::ReportConfig;
use crate::engine::error::Result;
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
            let mut r = serde_json::json!({
                "ruleId": format!("scorchkit/{}", f.module_id),
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": f.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.affected_target,
                        }
                    }
                }],
            });

            // SARIF rank: confidence mapped to 0–100 integer scale
            // JUSTIFICATION: confidence is 0.0–1.0, result fits in u8
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let rank = (f.confidence * 100.0) as u8;
            r["rank"] = serde_json::json!(rank);

            if let Some(ref evidence) = f.evidence {
                r["fingerprints"] = serde_json::json!({
                    "evidence": evidence
                });
            }

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

const fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
