//! Semgrep wrapper for multi-language static analysis.
//!
//! Wraps the `semgrep` tool which performs rule-based static analysis
//! across many languages including Python, JavaScript, Go, Java, Ruby, and more.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::observation::redact_text;
use crate::engine::severity::Severity;
use scorchkit_core::{
    sha256_hex, AdapterParseOutcome, CodeFlow, CodeFlowStep, ObservationLocation,
    ScannerProvenance, SourceRegion, ThreadFlow,
};

const BUILTIN_RULES: &[u8] = include_bytes!("../../rules/semgrep/scorchkit-appsec.yml");
const BUILTIN_RULE_PACK: &str = "scorchkit-semgrep-appsec/v1";
const MAX_RULE_PACK_BYTES: u64 = 2 * 1024 * 1024;

struct ResolvedRulePack {
    path: PathBuf,
    identity: String,
    _owned_file: Option<tempfile::NamedTempFile>,
}

/// Multi-language static analysis via Semgrep.
#[derive(Debug)]
pub struct SemgrepModule;

#[async_trait]
impl CodeModule for SemgrepModule {
    fn name(&self) -> &'static str {
        "Semgrep SAST"
    }
    fn id(&self) -> &'static str {
        "semgrep"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Multi-language static analysis for security vulnerabilities via Semgrep"
    }
    fn languages(&self) -> &'static [&'static str] {
        &["python", "javascript", "typescript", "php", "ruby", "java", "go"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("semgrep")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let rule_pack = resolve_rule_pack(&ctx.config.sast.semgrep)?;
        let path_str = ctx.path.display().to_string();
        let rule_path = rule_pack.path.display().to_string();
        let output = ctx
            .run_tool(
                "semgrep",
                &[
                    "scan",
                    "--config",
                    &rule_path,
                    "--json",
                    "--dataflow-traces",
                    "--quiet",
                    "--metrics=off",
                    "--disable-version-check",
                    &path_str,
                ],
                Duration::from_mins(5),
            )
            .await?;
        parse_semgrep_output_v1(&output.stdout, &rule_pack.identity).into_result("semgrep")
    }
}

fn resolve_rule_pack(config: &crate::config::SemgrepConfig) -> Result<ResolvedRulePack> {
    match (&config.local_rule_file, &config.local_rule_sha256) {
        (None, None) => materialize_builtin_rule_pack(),
        (Some(path), Some(expected_digest)) => {
            resolve_pinned_local_rule_pack(path, expected_digest)
        }
        _ => Err(ScorchError::Config(
            "Semgrep local_rule_file and local_rule_sha256 must be configured together".to_string(),
        )),
    }
}

fn materialize_builtin_rule_pack() -> Result<ResolvedRulePack> {
    validate_rule_pack_yaml(BUILTIN_RULES)?;
    let mut owned_file = tempfile::NamedTempFile::new()?;
    owned_file.write_all(BUILTIN_RULES)?;
    owned_file.flush()?;
    let digest = sha256_hex(BUILTIN_RULES);
    Ok(ResolvedRulePack {
        path: owned_file.path().to_path_buf(),
        identity: format!("{BUILTIN_RULE_PACK}@sha256:{digest}"),
        _owned_file: Some(owned_file),
    })
}

fn resolve_pinned_local_rule_pack(path: &Path, expected_digest: &str) -> Result<ResolvedRulePack> {
    if !path.is_absolute() {
        return Err(ScorchError::Config(format!(
            "Semgrep local rule path must be absolute; automatic, registry, and URL configurations are not allowed: {}",
            path.display()
        )));
    }
    if expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ScorchError::Config(
            "Semgrep local rule digest must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    let canonical_path = std::fs::canonicalize(path).map_err(|error| {
        ScorchError::Config(format!(
            "failed to resolve Semgrep rule file {}: {error}",
            path.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical_path)?;
    if !metadata.is_file() {
        return Err(ScorchError::Config(format!(
            "Semgrep rule path is not a regular file: {}",
            canonical_path.display()
        )));
    }
    if metadata.len() > MAX_RULE_PACK_BYTES {
        return Err(ScorchError::Config(format!(
            "Semgrep rule file exceeds the {MAX_RULE_PACK_BYTES}-byte limit"
        )));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&canonical_path)?.take(MAX_RULE_PACK_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RULE_PACK_BYTES {
        return Err(ScorchError::Config(format!(
            "Semgrep rule file exceeds the {MAX_RULE_PACK_BYTES}-byte limit"
        )));
    }
    validate_rule_pack_yaml(&bytes)?;
    let actual_digest = sha256_hex(&bytes);
    if actual_digest != expected_digest {
        return Err(ScorchError::Config(format!(
            "Semgrep rule digest mismatch: expected {expected_digest}, got {actual_digest}"
        )));
    }
    let mut owned_file = tempfile::NamedTempFile::new()?;
    owned_file.write_all(&bytes)?;
    owned_file.flush()?;
    Ok(ResolvedRulePack {
        path: owned_file.path().to_path_buf(),
        identity: format!("local-semgrep-rules@sha256:{actual_digest}"),
        _owned_file: Some(owned_file),
    })
}

fn validate_rule_pack_yaml(bytes: &[u8]) -> Result<()> {
    let value: serde_yaml::Value = serde_yaml::from_slice(bytes)
        .map_err(|error| ScorchError::Config(format!("invalid Semgrep rule-pack YAML: {error}")))?;
    let mapping = value.as_mapping().ok_or_else(|| {
        ScorchError::Config("Semgrep rule pack must be a YAML mapping".to_string())
    })?;
    let rules_key = serde_yaml::Value::String("rules".to_string());
    let rules =
        mapping.get(&rules_key).and_then(serde_yaml::Value::as_sequence).ok_or_else(|| {
            ScorchError::Config("Semgrep rule pack must contain a rules sequence".to_string())
        })?;
    if rules.is_empty() {
        return Err(ScorchError::Config(
            "Semgrep rule pack must contain at least one rule".to_string(),
        ));
    }
    if contains_yaml_key(&value, "validators") {
        return Err(ScorchError::Config(
            "Semgrep network validators are not allowed in reproducible rule packs".to_string(),
        ));
    }
    Ok(())
}

fn contains_yaml_key(value: &serde_yaml::Value, forbidden: &str) -> bool {
    match value {
        serde_yaml::Value::Mapping(mapping) => mapping.iter().any(|(key, value)| {
            key.as_str().is_some_and(|key| key.eq_ignore_ascii_case(forbidden))
                || contains_yaml_key(value, forbidden)
        }),
        serde_yaml::Value::Sequence(sequence) => {
            sequence.iter().any(|value| contains_yaml_key(value, forbidden))
        }
        _ => false,
    }
}

/// Map Semgrep severity strings to `ScorchKit` severity levels.
fn map_semgrep_severity(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        "INFO" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse Semgrep JSON output into findings.
///
/// Semgrep outputs a JSON object with a `results` array. Each result
/// contains `check_id`, `path`, `start`/`end` positions, `extra.severity`,
/// `extra.message`, and optional `extra.metadata` (CWE, OWASP).
#[must_use]
pub fn parse_semgrep_output(stdout: &str) -> Vec<Finding> {
    let identity = format!("{BUILTIN_RULE_PACK}@sha256:{}", sha256_hex(BUILTIN_RULES));
    parse_semgrep_output_v1(stdout, &identity).into_legacy()
}

fn parse_semgrep_output_v1(
    stdout: &str,
    config_identity: &str,
) -> AdapterParseOutcome<Vec<Finding>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return AdapterParseOutcome::NoFindings;
    }

    let root = match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(root) => root,
        Err(error) => {
            return AdapterParseOutcome::malformed(format!("invalid JSON document: {error}"));
        }
    };

    let Some(results) = root["results"].as_array() else {
        return AdapterParseOutcome::malformed("JSON document has no results array");
    };
    if root["errors"].as_array().is_some_and(|errors| !errors.is_empty()) {
        return AdapterParseOutcome::malformed("JSON document reports one or more scan errors");
    }

    if results.is_empty() {
        return AdapterParseOutcome::NoFindings;
    }

    let mut findings = Vec::with_capacity(results.len());
    let scanner_version = root["version"].as_str();
    let target_revision = root["git_meta"]["commit"].as_str();
    for (index, result) in results.iter().enumerate() {
        match decode_semgrep_result(result, config_identity, scanner_version, target_revision) {
            Ok(finding) => findings.push(finding),
            Err(detail) => {
                return AdapterParseOutcome::malformed(format!("result {}: {detail}", index + 1));
            }
        }
    }

    AdapterParseOutcome::Findings(findings)
}

fn decode_semgrep_result(
    result: &serde_json::Value,
    config_identity: &str,
    scanner_version: Option<&str>,
    target_revision: Option<&str>,
) -> std::result::Result<Finding, String> {
    let check_id = result["check_id"].as_str().ok_or("has no check_id")?;
    let path = result["path"].as_str().ok_or("has no path")?;
    let line = result["start"]["line"].as_u64().ok_or("has no start.line")?;
    let message = result["extra"]["message"].as_str().ok_or("has no extra.message")?;
    let severity = result["extra"]["severity"].as_str().unwrap_or("INFO");
    let start_column = result["start"]["col"].as_u64();
    let end_line = result["end"]["line"].as_u64();
    let end_column = result["end"]["col"].as_u64();
    let code_flows = decode_semgrep_dataflow(result)
        .map_err(|detail| format!("has invalid dataflow_trace: {detail}"))?;

    let mut finding = Finding::new(
        "semgrep",
        map_semgrep_severity(severity),
        check_id,
        message,
        format!("{path}:{line}"),
    )
    .with_location(ObservationLocation::Source {
        path: path.to_string(),
        region: Some(SourceRegion::new(line).with_bounds(start_column, end_line, end_column)),
    })
    .with_confidence(0.8);

    let mut provenance = ScannerProvenance::new("semgrep", finding.timestamp)
        .with_rule(check_id, None)
        .with_config(config_identity);
    if let Some(version) = scanner_version {
        provenance = provenance.with_version(version);
    }
    if let Some(revision) = target_revision {
        provenance = provenance.with_target_revision(revision);
    }
    finding = finding
        .with_provenance(provenance)
        .with_code_flows(code_flows)
        .with_structured_evidence(result.clone());

    if let Some(lines) = result["extra"]["lines"].as_str().filter(|lines| !lines.is_empty()) {
        finding = finding.with_evidence(lines);
    }
    if let Some(cwe) = result["extra"]["metadata"]["cwe"]
        .as_array()
        .and_then(|values| values.first())
        .and_then(|value| value.as_str())
        .and_then(|value| value.strip_prefix("CWE-"))
        .and_then(|value| value.parse::<u32>().ok())
    {
        finding = finding.with_cwe(cwe);
    }
    if let Some(owasp) = result["extra"]["metadata"]["owasp"]
        .as_array()
        .and_then(|values| values.first())
        .and_then(|value| value.as_str())
    {
        finding = finding.with_owasp(owasp);
    }

    Ok(finding.with_remediation(format!(
        "Review and fix the issue identified by Semgrep rule: {check_id}"
    )))
}

fn decode_semgrep_dataflow(
    result: &serde_json::Value,
) -> std::result::Result<Vec<CodeFlow>, String> {
    let trace = &result["extra"]["dataflow_trace"];
    if trace.is_null() {
        return Ok(Vec::new());
    }
    let trace = trace.as_object().ok_or_else(|| "expected an object".to_string())?;
    let mut steps = Vec::new();

    if let Some(source) = trace.get("taint_source").filter(|value| !value.is_null()) {
        decode_semgrep_call_trace(source, "source", &mut steps)?;
    }
    if let Some(intermediate) = trace.get("intermediate_vars") {
        let intermediate = intermediate
            .as_array()
            .ok_or_else(|| "intermediate_vars must be an array".to_string())?;
        for variable in intermediate {
            steps.push(decode_semgrep_intermediate(variable)?);
        }
    }
    if let Some(sink) = trace.get("taint_sink").filter(|value| !value.is_null()) {
        decode_semgrep_call_trace(sink, "sink", &mut steps)?;
    }

    if steps.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![CodeFlow { message: None, thread_flows: vec![ThreadFlow { message: None, steps }] }])
}

fn decode_semgrep_call_trace(
    value: &serde_json::Value,
    boundary_kind: &str,
    steps: &mut Vec<CodeFlowStep>,
) -> std::result::Result<(), String> {
    let encoded = value
        .as_array()
        .filter(|encoded| encoded.len() == 2)
        .ok_or_else(|| "call trace must be a two-item tagged array".to_string())?;
    let tag = encoded[0].as_str().ok_or_else(|| "call trace tag must be a string".to_string())?;
    match tag {
        "CliLoc" => steps.push(decode_semgrep_loc_and_content(&encoded[1], boundary_kind)?),
        "CliCall" => {
            let call = encoded[1].as_array().filter(|call| call.len() == 3).ok_or_else(|| {
                "CliCall payload must contain location, variables, and trace".to_string()
            })?;
            steps.push(decode_semgrep_loc_and_content(&call[0], boundary_kind)?);
            let variables = call[1]
                .as_array()
                .ok_or_else(|| "CliCall variables must be an array".to_string())?;
            for variable in variables {
                steps.push(decode_semgrep_intermediate(variable)?);
            }
            decode_semgrep_call_trace(&call[2], boundary_kind, steps)?;
        }
        _ => return Err(format!("unsupported call trace tag {tag}")),
    }
    Ok(())
}

fn decode_semgrep_loc_and_content(
    value: &serde_json::Value,
    kind: &str,
) -> std::result::Result<CodeFlowStep, String> {
    let pair = value
        .as_array()
        .filter(|pair| pair.len() == 2)
        .ok_or_else(|| "location/content value must be a two-item array".to_string())?;
    let content =
        pair[1].as_str().ok_or_else(|| "location content must be a string".to_string())?;
    semgrep_flow_step(&pair[0], content, kind)
}

fn decode_semgrep_intermediate(
    value: &serde_json::Value,
) -> std::result::Result<CodeFlowStep, String> {
    let content = value["content"]
        .as_str()
        .ok_or_else(|| "intermediate variable has no content".to_string())?;
    semgrep_flow_step(&value["location"], content, "propagation")
}

fn semgrep_flow_step(
    location: &serde_json::Value,
    content: &str,
    kind: &str,
) -> std::result::Result<CodeFlowStep, String> {
    let path = location["path"]
        .as_str()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| "flow location has no path".to_string())?;
    let start_line = location["start"]["line"]
        .as_u64()
        .filter(|line| *line > 0)
        .ok_or_else(|| "flow location has no positive start line".to_string())?;
    let mut step = CodeFlowStep::new(ObservationLocation::Source {
        path: path.to_string(),
        region: Some(SourceRegion::new(start_line).with_bounds(
            location["start"]["col"].as_u64(),
            location["end"]["line"].as_u64(),
            location["end"]["col"].as_u64(),
        )),
    });
    if !content.is_empty() {
        step.message = Some(redact_text(content));
    }
    step.kinds.push(kind.to_string());
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Semgrep JSON output is correctly parsed into findings.
    #[test]
    fn test_parse_semgrep_output() {
        let output = r#"{
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "app/views.py",
                    "start": {"line": 42, "col": 5},
                    "end": {"line": 42, "col": 20},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Detected use of eval(). This is dangerous.",
                        "lines": "    result = eval(user_input)",
                        "metadata": {
                            "cwe": ["CWE-95"],
                            "owasp": ["A03:2021 Injection"]
                        }
                    }
                }
            ]
        }"#;

        let findings = parse_semgrep_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_target, "app/views.py:42");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe_id, Some(95));
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("eval")));
        assert!(matches!(
            findings[0].appsec.location,
            ObservationLocation::Source {
                ref path,
                region: Some(SourceRegion { start_line: 42, start_column: Some(5), .. })
            } if path == "app/views.py"
        ));
        assert_eq!(
            findings[0].appsec.provenance.rule_id.as_deref(),
            Some("python.lang.security.audit.eval-detected")
        );
        assert!(findings[0]
            .appsec
            .provenance
            .config_identity
            .as_deref()
            .is_some_and(|identity| identity.starts_with(BUILTIN_RULE_PACK)));
        assert!(!findings[0].appsec.evidence.is_empty());
    }

    /// Verify empty or missing results produce no findings.
    #[test]
    fn test_parse_semgrep_empty() {
        assert!(parse_semgrep_output("").is_empty());
        assert!(parse_semgrep_output(r#"{"results": []}"#).is_empty());
        assert!(parse_semgrep_output("not json").is_empty());
    }

    #[test]
    fn malformed_semgrep_json_is_not_reported_as_no_findings() {
        for malformed in [
            "not json",
            r#"{"errors": []}"#,
            r#"{"results": [], "errors": [{}]}"#,
            r#"{"results": [{"check_id": "partial"}]}"#,
            r#"{
                "results": [{
                    "check_id": "taint",
                    "path": "app.py",
                    "start": {"line": 2},
                    "extra": {
                        "message": "taint",
                        "dataflow_trace": {"intermediate_vars": "invalid"}
                    }
                }]
            }"#,
        ] {
            assert!(matches!(
                parse_semgrep_output_v1(malformed, "fixture-rules@sha256:00"),
                AdapterParseOutcome::Malformed { .. }
            ));
        }
    }

    #[test]
    fn semgrep_taint_trace_preserves_source_intermediate_and_sink_order() {
        let location = |path: &str, line: u64| {
            serde_json::json!({
                "path": path,
                "start": {"line": line, "col": 1},
                "end": {"line": line, "col": 8}
            })
        };
        let output = serde_json::json!({
            "version": "1.156.0",
            "errors": [],
            "results": [{
                "check_id": "scorchkit.python.tainted-sql",
                "path": "app.py",
                "start": {"line": 9, "col": 1},
                "end": {"line": 9, "col": 8},
                "extra": {
                    "severity": "ERROR",
                    "message": "Tainted input reaches SQL",
                    "dataflow_trace": {
                        "taint_source": ["CliLoc", [location("app.py", 2), "password=secret"]],
                        "intermediate_vars": [{
                            "location": location("app.py", 5),
                            "content": "query = user_input"
                        }],
                        "taint_sink": ["CliLoc", [location("app.py", 9), "db.execute(query)"]]
                    }
                }
            }]
        });

        let AdapterParseOutcome::Findings(findings) =
            parse_semgrep_output_v1(&output.to_string(), "fixture@sha256:00")
        else {
            panic!("expected one Semgrep taint finding");
        };
        let steps = &findings[0].appsec.code_flows[0].thread_flows[0].steps;
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].kinds, ["source"]);
        assert_eq!(steps[1].kinds, ["propagation"]);
        assert_eq!(steps[2].kinds, ["sink"]);
        assert_eq!(steps[0].message.as_deref(), Some("password=%5BREDACTED%5D"));
        assert!(!serde_json::to_string(&findings[0])
            .expect("serialize finding")
            .contains("secret"));
    }

    #[test]
    fn builtin_rule_pack_has_stable_digest_identity_and_owned_file() {
        let resolved = resolve_rule_pack(&crate::config::SemgrepConfig::default())
            .expect("resolve built-in rules");
        assert!(resolved.path.is_file());
        assert_eq!(std::fs::read(&resolved.path).expect("read materialized rules"), BUILTIN_RULES);
        assert_eq!(
            resolved.identity,
            format!("{BUILTIN_RULE_PACK}@sha256:{}", sha256_hex(BUILTIN_RULES))
        );
    }

    #[test]
    fn local_rule_pack_requires_absolute_path_and_exact_digest() {
        let mut local = tempfile::NamedTempFile::new().expect("local rules");
        local.write_all(BUILTIN_RULES).expect("write rules");
        local.flush().expect("flush rules");
        let digest = sha256_hex(BUILTIN_RULES);
        let accepted = resolve_rule_pack(&crate::config::SemgrepConfig {
            local_rule_file: Some(local.path().to_path_buf()),
            local_rule_sha256: Some(digest.clone()),
        })
        .expect("accept pinned local rules");
        assert_eq!(accepted.identity, format!("local-semgrep-rules@sha256:{digest}"));
        assert_ne!(accepted.path, local.path());
        assert_eq!(std::fs::read(&accepted.path).expect("read owned copy"), BUILTIN_RULES);
        local.as_file_mut().set_len(0).expect("mutate source after verification");
        local.write_all(b"rules: []\n").expect("replace source rules");
        local.flush().expect("flush replacement");
        assert_eq!(
            std::fs::read(&accepted.path).expect("read immutable execution copy"),
            BUILTIN_RULES,
            "Semgrep must execute the exact bytes whose digest was verified"
        );

        for rejected in [
            crate::config::SemgrepConfig {
                local_rule_file: Some(PathBuf::from("auto")),
                local_rule_sha256: Some(digest.clone()),
            },
            crate::config::SemgrepConfig {
                local_rule_file: Some(PathBuf::from("p/default")),
                local_rule_sha256: Some(digest.clone()),
            },
            crate::config::SemgrepConfig {
                local_rule_file: Some(PathBuf::from("https://semgrep.dev/p/default")),
                local_rule_sha256: Some(digest),
            },
            crate::config::SemgrepConfig {
                local_rule_file: Some(local.path().to_path_buf()),
                local_rule_sha256: Some("0".repeat(64)),
            },
            crate::config::SemgrepConfig {
                local_rule_file: Some(local.path().to_path_buf()),
                local_rule_sha256: None,
            },
        ] {
            assert!(resolve_rule_pack(&rejected).is_err());
        }
    }

    #[test]
    fn oversized_rule_pack_is_rejected_before_reading_or_parsing() {
        let local = tempfile::NamedTempFile::new().expect("oversized local rules");
        local.as_file().set_len(MAX_RULE_PACK_BYTES + 1).expect("size sparse rules file");
        let Err(error) = resolve_rule_pack(&crate::config::SemgrepConfig {
            local_rule_file: Some(local.path().to_path_buf()),
            local_rule_sha256: Some("0".repeat(64)),
        }) else {
            panic!("oversized rules must fail");
        };
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn network_validator_rule_pack_is_rejected() {
        let rules = br"rules:
  - id: forbidden
    languages: [python]
    message: forbidden
    severity: ERROR
    pattern: eval(...)
    validators:
      - http:
          request: https://validator.example
";
        let error = validate_rule_pack_yaml(rules).expect_err("validator must fail");
        assert!(error.to_string().contains("network validators"));
    }

    #[test]
    fn semgrep_declares_only_languages_covered_by_the_owned_rule_pack() {
        assert_eq!(
            SemgrepModule.languages(),
            ["python", "javascript", "typescript", "php", "ruby", "java", "go"]
        );
        assert!(!SemgrepModule.languages().contains(&"rust"));
    }

    #[test]
    fn semgrep_message_and_source_text_are_redacted() {
        let output = serde_json::json!({
            "errors": [],
            "results": [{
                "check_id": "fixture.secret-message",
                "path": "app.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 20},
                "extra": {
                    "severity": "ERROR",
                    "message": "api_key=message-secret",
                    "lines": "eval(password = \"source-secret\")"
                }
            }]
        });
        let AdapterParseOutcome::Findings(findings) =
            parse_semgrep_output_v1(&output.to_string(), "fixture@sha256:00")
        else {
            panic!("expected Semgrep finding");
        };
        let encoded = serde_json::to_string(&findings).expect("serialize findings");
        assert!(!encoded.contains("message-secret"));
        assert!(!encoded.contains("source-secret"));
        assert!(encoded.contains("REDACTED"));
    }

    #[test]
    fn local_rule_pack_limit_and_digest_syntax_are_exact() {
        assert_eq!(MAX_RULE_PACK_BYTES, 2_097_152);
        let mut local = tempfile::NamedTempFile::new().expect("local rules");
        let mut bytes = BUILTIN_RULES.to_vec();
        bytes.resize(usize::try_from(MAX_RULE_PACK_BYTES).expect("rule limit"), b' ');
        local.write_all(&bytes).expect("write exact-limit rules");
        local.flush().expect("flush exact-limit rules");
        let digest = sha256_hex(&bytes);
        let resolved = resolve_pinned_local_rule_pack(local.path(), &digest)
            .expect("exact-limit rule pack must be accepted");
        assert_eq!(
            std::fs::metadata(&resolved.path).expect("owned rules metadata").len(),
            MAX_RULE_PACK_BYTES
        );

        for invalid in ["a".repeat(63), "A".repeat(64)] {
            let Err(error) = resolve_pinned_local_rule_pack(local.path(), &invalid) else {
                panic!("invalid digest syntax must fail before hashing");
            };
            assert!(
                error.to_string().contains("64 lowercase hexadecimal characters"),
                "unexpected error: {error}"
            );
        }

        let production =
            include_str!("semgrep.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains(".take(MAX_RULE_PACK_BYTES+1).read_to_end(&mutbytes)?;"));
    }

    #[test]
    fn nested_cli_call_trace_preserves_call_variables_and_sink() {
        let location = |path: &str, line: u64| {
            serde_json::json!({
                "path": path,
                "start": {"line": line, "col": 1},
                "end": {"line": line, "col": 8}
            })
        };
        let trace = serde_json::json!([
            "CliCall",
            [
                [location("src/source.py", 2), "source"],
                [{
                    "location": location("src/flow.py", 4),
                    "content": "propagation"
                }],
                ["CliLoc", [location("src/sink.py", 7), "sink"]]
            ]
        ]);
        let mut steps = Vec::new();
        decode_semgrep_call_trace(&trace, "source", &mut steps).expect("decode nested call");
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].kinds, ["source"]);
        assert_eq!(steps[1].kinds, ["propagation"]);
        assert_eq!(steps[2].kinds, ["source"]);
        assert!(matches!(
            steps[2].location,
            ObservationLocation::Source { ref path, .. } if path == "src/sink.py"
        ));
    }

    #[test]
    fn semgrep_flow_step_rejects_zero_line_locations() {
        let zero = serde_json::json!({
            "path": "src/app.py",
            "start": {"line": 0, "col": 1},
            "end": {"line": 0, "col": 2}
        });
        assert!(semgrep_flow_step(&zero, "fixture", "source").is_err());
    }
}
