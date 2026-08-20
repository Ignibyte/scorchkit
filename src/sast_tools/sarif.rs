//! Strict shared SARIF ingestion for file-producing static analyzers.

use std::io::Read;
use std::path::Path;

use scorchkit_core::{
    canonical_json_sha256, AdapterParseOutcome, CodeFlow, CodeFlowStep, ObservationLocation,
    ScannerProvenance, SourceRegion, ThreadFlow,
};

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

pub(super) const MAX_SARIF_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub(super) struct SarifAdapter<'a> {
    pub scanner_id: &'a str,
    pub config_identity: &'a str,
    pub default_confidence: f64,
}

pub(super) fn read_bounded_sarif(path: &Path, scanner_id: &str) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ScorchError::Config(format!(
            "{scanner_id} did not produce a readable SARIF report: {error}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(ScorchError::Config(format!(
            "{scanner_id} SARIF report is not a regular file"
        )));
    }
    if metadata.len() > u64::try_from(MAX_SARIF_BYTES).unwrap_or(u64::MAX) {
        return Err(ScorchError::ToolOutputLimit {
            tool: scanner_id.to_string(),
            stream: "SARIF artifact",
            limit_bytes: MAX_SARIF_BYTES,
        });
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(u64::try_from(MAX_SARIF_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SARIF_BYTES {
        return Err(ScorchError::ToolOutputLimit {
            tool: scanner_id.to_string(),
            stream: "SARIF artifact",
            limit_bytes: MAX_SARIF_BYTES,
        });
    }
    String::from_utf8(bytes)
        .map_err(|error| ScorchError::Config(format!("{scanner_id} SARIF is not UTF-8: {error}")))
}

pub(super) fn parse_sarif_output(
    input: &str,
    adapter: SarifAdapter<'_>,
) -> AdapterParseOutcome<Vec<Finding>> {
    let root = match serde_json::from_str::<serde_json::Value>(input) {
        Ok(root) => root,
        Err(error) => {
            return AdapterParseOutcome::malformed(format!("invalid SARIF JSON: {error}"));
        }
    };
    if root["version"].as_str() != Some("2.1.0") {
        return AdapterParseOutcome::malformed("SARIF version must be 2.1.0");
    }
    let Some(runs) = root["runs"].as_array().filter(|runs| !runs.is_empty()) else {
        return AdapterParseOutcome::malformed("SARIF document has no runs");
    };

    let mut findings = Vec::new();
    for (run_index, run) in runs.iter().enumerate() {
        if let Err(detail) = validate_sarif_run(run, adapter.scanner_id) {
            return AdapterParseOutcome::malformed(format!(
                "SARIF run {}: {detail}",
                run_index + 1,
            ));
        }
        let Some(results) = run["results"].as_array() else {
            return AdapterParseOutcome::malformed(format!(
                "SARIF run {} has no results array",
                run_index + 1
            ));
        };
        for (result_index, result) in results.iter().enumerate() {
            match decode_result(run, result, adapter) {
                Ok(finding) => findings.push(finding),
                Err(detail) => {
                    return AdapterParseOutcome::malformed(format!(
                        "SARIF run {} result {}: {detail}",
                        run_index + 1,
                        result_index + 1
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        AdapterParseOutcome::NoFindings
    } else {
        AdapterParseOutcome::Findings(findings)
    }
}

fn validate_sarif_run(
    run: &serde_json::Value,
    expected_driver: &str,
) -> std::result::Result<(), String> {
    let Some(driver_name) = run["tool"]["driver"]["name"].as_str() else {
        return Err("tool driver has no name".to_string());
    };
    if driver_name.is_empty() {
        return Err("tool driver has no name".to_string());
    }
    if !driver_name.eq_ignore_ascii_case(expected_driver) {
        return Err(format!(
            "tool driver {driver_name:?} does not match expected analyzer {expected_driver:?}"
        ));
    }
    let Some(invocations) = run.get("invocations") else {
        return Ok(());
    };
    let invocations =
        invocations.as_array().ok_or_else(|| "invocations must be an array".to_string())?;
    for (index, invocation) in invocations.iter().enumerate() {
        let Some(success) = invocation.get("executionSuccessful") else {
            continue;
        };
        match success.as_bool() {
            Some(true) => {}
            Some(false) => {
                return Err(format!("invocation {} reports unsuccessful execution", index + 1));
            }
            None => return Err(format!("invocation {} has a non-boolean status", index + 1)),
        }
    }
    Ok(())
}

fn decode_result(
    run: &serde_json::Value,
    result: &serde_json::Value,
    adapter: SarifAdapter<'_>,
) -> std::result::Result<Finding, String> {
    let rule_id = result["ruleId"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing ruleId".to_string())?;
    let message = sarif_message(&result["message"])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing result message".to_string())?;
    let rule = find_rule(run, rule_id);
    let code_flows = decode_code_flows(result, run)?;
    let location = result["locations"]
        .as_array()
        .and_then(|locations| locations.first())
        .map(|location| decode_location(location, run))
        .transpose()?
        .or_else(|| last_flow_location(&code_flows))
        .ok_or_else(|| "missing physical source location".to_string())?;
    let affected = source_target(&location);
    let severity = rule.and_then(security_severity).unwrap_or_else(|| sarif_level(result, rule));
    let confidence = rule.and_then(rule_confidence).unwrap_or(adapter.default_confidence);
    let title = rule.and_then(rule_title).unwrap_or_else(|| rule_id.to_string());

    let mut finding = Finding::new(adapter.scanner_id, severity, title, message, affected)
        .with_location(location)
        .with_confidence(confidence);
    if let Some(cwe) = rule.and_then(rule_cwe) {
        finding = finding.with_cwe(cwe);
    }

    let mut provenance = ScannerProvenance::new(adapter.scanner_id, finding.timestamp)
        .with_rule(rule_id, rule.map(canonical_json_sha256))
        .with_config(run_config_identity(run, adapter.config_identity));
    if let Some(version) = scanner_version(run) {
        provenance = provenance.with_version(version);
    }
    if let Some(revision) = run["versionControlProvenance"]
        .as_array()
        .and_then(|values| values.first())
        .and_then(|value| value["revisionId"].as_str())
    {
        provenance = provenance.with_target_revision(revision);
    }
    finding = finding.with_provenance(provenance).with_code_flows(code_flows);

    let evidence = serde_json::json!({
        "result": result,
        "rule": rule,
    });
    Ok(finding.with_structured_evidence(evidence))
}

fn find_rule<'a>(run: &'a serde_json::Value, rule_id: &str) -> Option<&'a serde_json::Value> {
    std::iter::once(&run["tool"]["driver"])
        .chain(run["tool"]["extensions"].as_array().into_iter().flatten())
        .filter_map(|component| component["rules"].as_array())
        .flatten()
        .find(|rule| rule["id"].as_str() == Some(rule_id))
}

fn scanner_version(run: &serde_json::Value) -> Option<&str> {
    let driver = &run["tool"]["driver"];
    driver["semanticVersion"].as_str().or_else(|| driver["version"].as_str())
}

fn run_config_identity(run: &serde_json::Value, base: &str) -> String {
    run["automationDetails"]["id"]
        .as_str()
        .map_or_else(|| base.to_string(), |automation| format!("{base};automation={automation}"))
}

fn rule_title(rule: &serde_json::Value) -> Option<String> {
    sarif_message(&rule["shortDescription"])
        .or_else(|| sarif_message(&rule["fullDescription"]))
        .or_else(|| rule["name"].as_str().map(str::to_string))
}

fn sarif_message(value: &serde_json::Value) -> Option<String> {
    value["text"].as_str().or_else(|| value["markdown"].as_str()).map(str::to_string)
}

fn security_severity(rule: &serde_json::Value) -> Option<Severity> {
    let value = &rule["properties"]["security-severity"];
    let score = value.as_f64().or_else(|| value.as_str()?.parse().ok())?;
    Some(if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    })
}

fn sarif_level(result: &serde_json::Value, rule: Option<&serde_json::Value>) -> Severity {
    let level = result["level"]
        .as_str()
        .or_else(|| rule.and_then(|rule| rule["defaultConfiguration"]["level"].as_str()))
        .unwrap_or("none");
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" => Severity::Low,
        _ => Severity::Info,
    }
}

fn rule_confidence(rule: &serde_json::Value) -> Option<f64> {
    let precision = rule["properties"]["precision"].as_str()?;
    match precision {
        "very-high" => Some(0.95),
        "high" => Some(0.85),
        "medium" => Some(0.7),
        "low" => Some(0.5),
        _ => None,
    }
}

fn rule_cwe(rule: &serde_json::Value) -> Option<u32> {
    rule["properties"]["tags"]
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find_map(parse_cwe)
}

fn parse_cwe(value: &str) -> Option<u32> {
    let lowercase = value.to_ascii_lowercase();
    let suffix = lowercase.rsplit_once("cwe-").map_or(lowercase.as_str(), |(_, suffix)| suffix);
    let digits: String = suffix.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

fn decode_code_flows(
    result: &serde_json::Value,
    run: &serde_json::Value,
) -> std::result::Result<Vec<CodeFlow>, String> {
    let Some(flows) = result["codeFlows"].as_array() else {
        return Ok(Vec::new());
    };
    let mut decoded = Vec::with_capacity(flows.len());
    for flow in flows {
        let thread_flows = flow["threadFlows"]
            .as_array()
            .ok_or_else(|| "codeFlow has no threadFlows array".to_string())?;
        let mut decoded_threads = Vec::with_capacity(thread_flows.len());
        for thread in thread_flows {
            let locations = thread["locations"]
                .as_array()
                .ok_or_else(|| "threadFlow has no locations array".to_string())?;
            let mut steps = Vec::with_capacity(locations.len());
            for location in locations {
                let mut step = CodeFlowStep::new(decode_location(&location["location"], run)?);
                step.message = sarif_message(&location["location"]["message"]);
                step.kinds = decode_string_array(&location["kinds"])?;
                step.nesting_level = location["nestingLevel"].as_u64();
                step.execution_order = location["executionOrder"].as_u64();
                steps.push(step);
            }
            decoded_threads.push(ThreadFlow { message: sarif_message(&thread["message"]), steps });
        }
        decoded.push(CodeFlow {
            message: sarif_message(&flow["message"]),
            thread_flows: decoded_threads,
        });
    }
    Ok(decoded)
}

fn decode_string_array(value: &serde_json::Value) -> std::result::Result<Vec<String>, String> {
    let Some(values) = value.as_array() else {
        return Ok(Vec::new());
    };
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| "non-string flow kind".to_string())
        })
        .collect()
}

fn decode_location(
    value: &serde_json::Value,
    run: &serde_json::Value,
) -> std::result::Result<ObservationLocation, String> {
    let physical = &value["physicalLocation"];
    let artifact = &physical["artifactLocation"];
    let path = artifact["uri"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            let index = artifact["index"].as_u64()?;
            let index = usize::try_from(index).ok()?;
            run["artifacts"][index]["location"]["uri"].as_str().map(str::to_string)
        })
        .ok_or_else(|| "physical location has no artifact URI".to_string())?;
    let region = &physical["region"];
    let region = region["startLine"].as_u64().map(|start_line| {
        SourceRegion::new(start_line).with_bounds(
            region["startColumn"].as_u64(),
            region["endLine"].as_u64(),
            region["endColumn"].as_u64(),
        )
    });
    Ok(ObservationLocation::Source { path, region })
}

fn last_flow_location(flows: &[CodeFlow]) -> Option<ObservationLocation> {
    flows
        .iter()
        .rev()
        .flat_map(|flow| flow.thread_flows.iter().rev())
        .flat_map(|thread| thread.steps.iter().rev())
        .map(|step| step.location.clone())
        .next()
}

fn source_target(location: &ObservationLocation) -> String {
    match location {
        ObservationLocation::Source { path, region } => region
            .as_ref()
            .map_or_else(|| path.clone(), |region| format!("{path}:{}", region.start_line)),
        _ => "source://unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_unsuccessful_sarif() {
        let adapter = SarifAdapter {
            scanner_id: "fixture",
            config_identity: "fixture/v1",
            default_confidence: 0.8,
        };
        for malformed in [
            "",
            r#"{"version":"2.1.0","runs":[]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fixture"}},"invocations":[{"executionSuccessful":false}],"results":[]}]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{}},"results":[]}]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fixture"}},"invocations":"invalid","results":[]}]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fixture"}},"invocations":[{"executionSuccessful":"yes"}],"results":[]}]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"different"}},"results":[]}]}"#,
        ] {
            assert!(matches!(
                parse_sarif_output(malformed, adapter),
                AdapterParseOutcome::Malformed { .. }
            ));
        }
    }

    #[test]
    fn valid_empty_sarif_is_distinct_from_malformed_output() {
        let adapter = SarifAdapter {
            scanner_id: "fixture",
            config_identity: "fixture/v1",
            default_confidence: 0.8,
        };
        let empty = r#"{
            "version":"2.1.0",
            "runs":[{
                "tool":{"driver":{"name":"fixture","version":"1.0"}},
                "invocations":[{"executionSuccessful":true}],
                "results":[]
            }]
        }"#;
        assert!(matches!(parse_sarif_output(empty, adapter), AdapterParseOutcome::NoFindings));
    }

    #[test]
    fn bounded_sarif_reader_rejects_missing_oversized_and_symlink_artifacts() {
        let directory = tempfile::tempdir().expect("temporary SARIF directory");
        let missing = directory.path().join("missing.sarif");
        assert!(read_bounded_sarif(&missing, "fixture").is_err());

        let oversized = directory.path().join("oversized.sarif");
        let file = std::fs::File::create(&oversized).expect("create sparse SARIF file");
        file.set_len(u64::try_from(MAX_SARIF_BYTES).expect("SARIF limit") + 1)
            .expect("size sparse SARIF file");
        assert!(matches!(
            read_bounded_sarif(&oversized, "fixture"),
            Err(ScorchError::ToolOutputLimit { .. })
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let target = directory.path().join("target.sarif");
            std::fs::write(&target, "{}").expect("write symlink target");
            let link = directory.path().join("link.sarif");
            symlink(&target, &link).expect("create SARIF symlink");
            assert!(read_bounded_sarif(&link, "fixture").is_err());
        }
    }

    #[test]
    fn cwe_tag_parser_accepts_standard_codeql_shapes() {
        assert_eq!(parse_cwe("external/cwe/cwe-089"), Some(89));
        assert_eq!(parse_cwe("CWE-78"), Some(78));
        assert_eq!(parse_cwe("security"), None);
    }

    #[test]
    fn sarif_size_limit_accepts_the_exact_boundary() {
        assert_eq!(MAX_SARIF_BYTES, 67_108_864);
        let directory = tempfile::tempdir().expect("temporary SARIF directory");
        let exact = directory.path().join("exact-limit.sarif");
        let file = std::fs::File::create(&exact).expect("create sparse SARIF file");
        file.set_len(u64::try_from(MAX_SARIF_BYTES).expect("SARIF limit"))
            .expect("size sparse SARIF file");
        let decoded = read_bounded_sarif(&exact, "fixture").expect("accept exact SARIF limit");
        assert_eq!(decoded.len(), MAX_SARIF_BYTES);

        let production =
            include_str!("sarif.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains(".take(u64::try_from(MAX_SARIF_BYTES).unwrap_or(u64::MAX)+1)"));
    }

    #[test]
    fn sarif_metadata_helpers_preserve_exact_fallbacks() {
        let semantic = serde_json::json!({
            "tool": {"driver": {"semanticVersion": "2.3.4", "version": "1.0"}}
        });
        let version = serde_json::json!({"tool": {"driver": {"version": "1.0"}}});
        assert_eq!(scanner_version(&semantic), Some("2.3.4"));
        assert_eq!(scanner_version(&version), Some("1.0"));
        assert_eq!(scanner_version(&serde_json::json!({})), None);

        let all_titles = serde_json::json!({
            "shortDescription": {"text": "short"},
            "fullDescription": {"text": "full"},
            "name": "name"
        });
        let full_title = serde_json::json!({
            "fullDescription": {"markdown": "full"},
            "name": "name"
        });
        assert_eq!(rule_title(&all_titles).as_deref(), Some("short"));
        assert_eq!(rule_title(&full_title).as_deref(), Some("full"));
        assert_eq!(rule_title(&serde_json::json!({"name": "name"})).as_deref(), Some("name"));
        assert_eq!(rule_title(&serde_json::json!({})), None);

        assert_eq!(sarif_message(&serde_json::json!({"text": "plain"})).as_deref(), Some("plain"));
        assert_eq!(
            sarif_message(&serde_json::json!({"markdown": "formatted"})).as_deref(),
            Some("formatted")
        );
        assert_eq!(sarif_message(&serde_json::json!({})), None);
    }

    #[test]
    fn sarif_severity_and_confidence_boundaries_are_exact() {
        for (score, expected) in [
            (9.0, Severity::Critical),
            (7.0, Severity::High),
            (4.0, Severity::Medium),
            (0.1, Severity::Low),
            (0.0, Severity::Info),
        ] {
            let rule = serde_json::json!({"properties": {"security-severity": score}});
            assert_eq!(security_severity(&rule), Some(expected), "score {score}");
        }
        assert_eq!(
            security_severity(&serde_json::json!({
                "properties": {"security-severity": "8.5"}
            })),
            Some(Severity::High)
        );
        assert_eq!(security_severity(&serde_json::json!({})), None);

        for (level, expected) in [
            ("error", Severity::High),
            ("warning", Severity::Medium),
            ("note", Severity::Low),
            ("none", Severity::Info),
        ] {
            assert_eq!(
                sarif_level(&serde_json::json!({"level": level}), None),
                expected,
                "level {level}"
            );
        }

        for (precision, expected) in [
            ("very-high", Some(0.95)),
            ("high", Some(0.85)),
            ("medium", Some(0.7)),
            ("low", Some(0.5)),
            ("unknown", None),
        ] {
            let rule = serde_json::json!({"properties": {"precision": precision}});
            assert_eq!(rule_confidence(&rule), expected, "precision {precision}");
        }
    }

    #[test]
    fn flow_sink_and_source_target_projection_are_exact() {
        let first = ObservationLocation::Source {
            path: "src/source.rs".to_string(),
            region: Some(SourceRegion::new(2)),
        };
        let last = ObservationLocation::Source {
            path: "src/sink.rs".to_string(),
            region: Some(SourceRegion::new(9)),
        };
        let flow = CodeFlow {
            message: None,
            thread_flows: vec![ThreadFlow {
                message: None,
                steps: vec![CodeFlowStep::new(first), CodeFlowStep::new(last.clone())],
            }],
        };
        assert_eq!(last_flow_location(&[flow]), Some(last.clone()));
        assert_eq!(source_target(&last), "src/sink.rs:9");
        assert_eq!(
            source_target(&ObservationLocation::Source {
                path: "src/no-region.rs".to_string(),
                region: None,
            }),
            "src/no-region.rs"
        );
        assert_eq!(
            source_target(&ObservationLocation::Legacy { value: "opaque".to_string() }),
            "source://unknown"
        );
    }
}
