//! `PHPStan` wrapper for PHP static analysis.
//!
//! Wraps the `phpstan` tool which performs static analysis on PHP code
//! to find bugs, type errors, and potential security issues.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use scorchkit_core::{AdapterParseOutcome, ObservationLocation, ScannerProvenance, SourceRegion};

/// PHP static analysis via `PHPStan`.
#[derive(Debug)]
pub struct PhpstanModule;

#[async_trait]
impl CodeModule for PhpstanModule {
    fn name(&self) -> &'static str {
        "PHPStan"
    }
    fn id(&self) -> &'static str {
        "phpstan"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Correctness
    }
    fn description(&self) -> &'static str {
        "PHP static correctness and type analysis via PHPStan"
    }
    fn languages(&self) -> &[&str] {
        &["php"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("phpstan")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = ctx
            .run_tool_lenient(
                "phpstan",
                &["analyse", "--error-format", "json", "--no-progress", &path_str],
                Duration::from_mins(5),
            )
            .await?;

        if !matches!(output.exit_code, 0 | 1) {
            return Err(ScorchError::ToolFailed {
                tool: "phpstan".to_string(),
                status: output.exit_code,
                stderr: crate::engine::observation::redact_text(&output.stderr),
            });
        }

        parse_phpstan_output_v1(&output.stdout).into_result("phpstan")
    }
}

/// Parse `PHPStan` JSON output into findings.
///
/// `PHPStan` outputs a JSON object with `totals` and `files` map.
/// Each file entry has a `messages` array with `message`, `line`,
/// and optionally `tip`.
#[must_use]
pub fn parse_phpstan_output(stdout: &str) -> Vec<Finding> {
    parse_phpstan_output_v1(stdout).into_legacy()
}

fn parse_phpstan_output_v1(stdout: &str) -> AdapterParseOutcome<Vec<Finding>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return AdapterParseOutcome::malformed("empty output is not a PHPStan JSON result");
    }

    let root = match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(root) => root,
        Err(error) => {
            return AdapterParseOutcome::malformed(format!("invalid JSON document: {error}"));
        }
    };

    let (files, total_file_errors) = match phpstan_files_and_total(&root) {
        Ok(contract) => contract,
        Err(detail) => return AdapterParseOutcome::malformed(detail),
    };

    let mut findings = Vec::new();
    let mut observed_file_errors = 0_u64;

    for (file_path, file_data) in files {
        let Some(file_error_count) = file_data["errors"].as_u64() else {
            return AdapterParseOutcome::malformed(format!(
                "file {file_path} has no unsigned errors count"
            ));
        };
        let Some(messages) = file_data["messages"].as_array() else {
            return AdapterParseOutcome::malformed(format!(
                "file {file_path} has no messages array"
            ));
        };
        if u64::try_from(messages.len()).unwrap_or(u64::MAX) != file_error_count {
            return AdapterParseOutcome::malformed(format!(
                "file {file_path} errors count does not match messages array"
            ));
        }
        observed_file_errors = observed_file_errors.saturating_add(file_error_count);

        for (index, msg) in messages.iter().enumerate() {
            let Some(message) = msg["message"].as_str() else {
                return AdapterParseOutcome::malformed(format!(
                    "message {} in {file_path} has no message text",
                    index + 1
                ));
            };
            let Some(line) = msg["line"].as_u64().filter(|line| *line > 0) else {
                return AdapterParseOutcome::malformed(format!(
                    "message {} in {file_path} has no valid line",
                    index + 1
                ));
            };
            let tip = msg["tip"].as_str().unwrap_or("");
            let identifier = msg["identifier"].as_str();

            let affected = format!("{file_path}:{line}");

            let mut finding = Finding::new(
                "phpstan",
                Severity::Info,
                format!("PHPStan: {message}"),
                message,
                &affected,
            )
            .with_location(ObservationLocation::Source {
                path: file_path.clone(),
                region: Some(SourceRegion::new(line)),
            })
            .with_confidence(0.7);

            let mut provenance = ScannerProvenance::new("phpstan", finding.timestamp);
            if let Some(identifier) = identifier {
                provenance = provenance.with_rule(identifier, None);
            }
            finding = finding.with_provenance(provenance).with_structured_evidence(msg.clone());

            if tip.is_empty() {
                finding =
                    finding.with_remediation(format!("Review and fix the issue in {file_path}"));
            } else {
                finding = finding.with_remediation(tip);
            }

            findings.push(finding);
        }
    }

    if observed_file_errors != total_file_errors {
        return AdapterParseOutcome::malformed(
            "totals.file_errors does not match file message counts",
        );
    }

    if findings.is_empty() {
        AdapterParseOutcome::NoFindings
    } else {
        AdapterParseOutcome::Findings(findings)
    }
}

fn phpstan_files_and_total(
    root: &serde_json::Value,
) -> std::result::Result<(&serde_json::Map<String, serde_json::Value>, u64), String> {
    let totals = root["totals"]
        .as_object()
        .ok_or_else(|| "JSON document has no totals object".to_string())?;
    let total_errors = totals
        .get("errors")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "totals.errors is not an unsigned integer".to_string())?;
    let total_file_errors = totals
        .get("file_errors")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "totals.file_errors is not an unsigned integer".to_string())?;
    let files =
        root["files"].as_object().ok_or_else(|| "JSON document has no files object".to_string())?;
    let errors =
        root["errors"].as_array().ok_or_else(|| "JSON document has no errors array".to_string())?;
    if u64::try_from(errors.len()).unwrap_or(u64::MAX) != total_errors {
        return Err("totals.errors does not match errors array".to_string());
    }
    if !errors.is_empty() {
        return Err("PHPStan reported one or more analysis errors".to_string());
    }
    Ok((files, total_file_errors))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `PHPStan` JSON output is correctly parsed with file paths,
    /// line numbers, messages, and optional tips as remediation.
    #[test]
    fn test_parse_phpstan_output() {
        let output = r#"{
            "totals": {"errors": 0, "file_errors": 2},
            "errors": [],
            "files": {
                "/app/src/Controller/UserController.php": {
                    "errors": 2,
                    "messages": [
                        {
                            "message": "Call to an undefined method App\\Entity\\User::getPasswd().",
                            "line": 45,
                            "tip": "Did you mean getPassword()?",
                            "identifier": "method.notFound"
                        },
                        {
                            "message": "Parameter $id of method expects int, string given.",
                            "line": 78
                        }
                    ]
                }
            }
        }"#;

        let findings = parse_phpstan_output(output);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("getPasswd"));
        assert_eq!(findings[0].affected_target, "/app/src/Controller/UserController.php:45");
        assert!(findings[0].remediation.as_ref().is_some_and(|r| r.contains("getPassword")));
        assert_eq!(findings[1].severity, Severity::Info);
        assert_eq!(findings[0].owasp_category, None);
        assert_eq!(findings[0].cwe_id, None);
        assert_eq!(findings[0].appsec.provenance.rule_id.as_deref(), Some("method.notFound"));
        assert!(matches!(
            findings[0].appsec.location,
            ObservationLocation::Source { ref path, region: Some(SourceRegion { start_line: 45, .. }) }
                if path == "/app/src/Controller/UserController.php"
        ));
    }

    /// Verify empty or invalid input produces no findings.
    #[test]
    fn test_parse_phpstan_empty() {
        assert!(parse_phpstan_output("").is_empty());
        assert!(parse_phpstan_output("not json").is_empty());
        assert!(parse_phpstan_output(
            r#"{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}"#
        )
        .is_empty());
    }

    #[test]
    fn malformed_phpstan_output_is_not_a_clean_result() {
        for malformed in [
            "not json",
            "",
            r#"{"totals": {}}"#,
            r#"{"totals":{"errors":0,"file_errors":1},"files":{"src/a.php":{}},"errors":[]}"#,
            r#"{"totals":{"errors":0,"file_errors":1},"files":{"src/a.php":{"errors":1,"messages":[{"line":1}]}},"errors":[]}"#,
            r#"{"totals":{"errors":1,"file_errors":0},"files":{},"errors":["configuration failed"]}"#,
            r#"{"totals":{"errors":0,"file_errors":1},"files":{},"errors":[]}"#,
        ] {
            assert!(matches!(
                parse_phpstan_output_v1(malformed),
                AdapterParseOutcome::Malformed { .. }
            ));
        }
    }

    #[test]
    fn phpstan_is_a_correctness_module() {
        assert_eq!(PhpstanModule.category(), CodeCategory::Correctness);
    }

    #[derive(Debug)]
    struct PhpstanOutputExecutor {
        exit_code: i32,
        stdout: String,
        stderr: String,
    }

    #[async_trait::async_trait]
    impl crate::runner::subprocess::ToolExecutor for PhpstanOutputExecutor {
        async fn execute(
            &self,
            _invocation: crate::runner::subprocess::ToolInvocation,
        ) -> Result<crate::runner::subprocess::ToolOutput> {
            Ok(crate::runner::subprocess::ToolOutput {
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
                exit_code: self.exit_code,
                duration: Duration::ZERO,
                resolved_program: std::path::PathBuf::from("/mock/phpstan"),
            })
        }
    }

    fn phpstan_context(root: &std::path::Path, executor: PhpstanOutputExecutor) -> CodeContext {
        CodeContext::new(
            root.to_path_buf(),
            Some("php".to_string()),
            std::sync::Arc::new(crate::config::AppConfig::default()),
            Vec::new(),
        )
        .with_tool_executor(std::sync::Arc::new(executor))
    }

    #[tokio::test]
    async fn phpstan_accepts_documented_finding_exit_with_valid_json() {
        let root = tempfile::tempdir().expect("PHP fixture");
        let stdout = r#"{
            "totals":{"errors":0,"file_errors":1},
            "files":{"src/App.php":{"errors":1,"messages":[{
                "message":"Undefined method","line":3,"identifier":"method.notFound"
            }]}},
            "errors":[]
        }"#;
        let context = phpstan_context(
            root.path(),
            PhpstanOutputExecutor {
                exit_code: 1,
                stdout: stdout.to_string(),
                stderr: String::new(),
            },
        );

        let findings = PhpstanModule.run(&context).await.expect("valid findings exit");
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn phpstan_rejects_empty_or_undocumented_exit_output() {
        let root = tempfile::tempdir().expect("PHP fixture");
        for executor in [
            PhpstanOutputExecutor {
                exit_code: 1,
                stdout: String::new(),
                stderr: "fatal".to_string(),
            },
            PhpstanOutputExecutor {
                exit_code: 2,
                stdout: String::new(),
                stderr: "api_key=diagnostic-secret".to_string(),
            },
        ] {
            let context = phpstan_context(root.path(), executor);
            let error = PhpstanModule.run(&context).await.expect_err("invalid output must fail");
            assert!(!error.to_string().contains("diagnostic-secret"));
        }
    }

    #[test]
    fn phpstan_descriptor_and_positive_line_contract_are_exact() {
        assert_eq!(
            PhpstanModule.description(),
            "PHP static correctness and type analysis via PHPStan"
        );
        let zero_line = r#"{
            "totals":{"errors":0,"file_errors":1},
            "errors":[],
            "files":{"src/a.php":{"errors":1,"messages":[{"message":"fixture","line":0}]}}
        }"#;
        assert!(matches!(
            parse_phpstan_output_v1(zero_line),
            AdapterParseOutcome::Malformed { .. }
        ));
    }
}
