//! Gitleaks wrapper for secret detection in source code.
//!
//! Wraps the `gitleaks` tool which detects hardcoded secrets, API keys,
//! credentials, and tokens in source code and git history.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Secret detection via Gitleaks.
#[derive(Debug)]
pub struct GitleaksModule;

#[async_trait]
impl CodeModule for GitleaksModule {
    fn name(&self) -> &'static str {
        "Gitleaks Secret Scanner"
    }
    fn id(&self) -> &'static str {
        "gitleaks"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Secrets
    }
    fn description(&self) -> &'static str {
        "Detect hardcoded secrets, API keys, and credentials via Gitleaks"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("gitleaks")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // gitleaks exits 1 when leaks found — that's normal, not an error.
        // Use run_tool_lenient to capture stdout regardless of exit code.
        let output = subprocess::run_tool_lenient(
            "gitleaks",
            &[
                "detect",
                "--source",
                &path_str,
                "--report-format",
                "json",
                "--report-path",
                "/dev/stdout",
                "--no-git",
            ],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_gitleaks_output(&output.stdout))
    }
}

/// Redact a secret value, showing only the first 8 characters.
fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        "*".repeat(secret.len())
    } else {
        format!("{}...", &secret[..8])
    }
}

/// Parse Gitleaks JSON output into findings.
///
/// Gitleaks outputs a JSON array of leak objects with fields:
/// `Description`, `RuleID`, `File`, `StartLine`, `Match`, `Entropy`.
#[must_use]
pub fn parse_gitleaks_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let Ok(leaks) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) else {
        return Vec::new();
    };

    leaks
        .iter()
        .filter_map(|leak| {
            let description = leak["Description"].as_str()?;
            let rule_id = leak["RuleID"].as_str().unwrap_or("unknown");
            let file = leak["File"].as_str().unwrap_or("unknown");
            let line = leak["StartLine"].as_u64().unwrap_or(0);
            let secret = leak["Match"].as_str().unwrap_or("");

            let affected = format!("{file}:{line}");
            let redacted = redact_secret(secret);

            // Higher entropy = higher confidence it's a real secret
            let confidence = leak["Entropy"].as_f64().map_or(0.7, |entropy| {
                if entropy > 4.5 {
                    0.9
                } else if entropy > 3.5 {
                    0.8
                } else {
                    0.7
                }
            });

            Some(
                Finding::new(
                    "gitleaks",
                    Severity::High,
                    format!("Exposed secret: {description}"),
                    format!("Hardcoded {description} detected by rule {rule_id}."),
                    &affected,
                )
                .with_evidence(format!("Matched: {redacted} (redacted)"))
                .with_remediation(format!(
                    "Remove the hardcoded secret from {file}. \
                     Rotate the credential immediately. \
                     Use environment variables or a secrets manager instead."
                ))
                .with_owasp("A07:2021 Identification and Authentication Failures")
                .with_cwe(798)
                .with_confidence(confidence),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Gitleaks JSON output is parsed with redacted evidence.
    #[test]
    fn test_parse_gitleaks_output() {
        let output = r#"[
            {
                "Description": "AWS Access Key",
                "RuleID": "aws-access-key-id",
                "File": "config/settings.py",
                "StartLine": 15,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Entropy": 4.8
            }
        ]"#;

        let findings = parse_gitleaks_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected_target, "config/settings.py:15");
        assert_eq!(findings[0].severity, Severity::High);
        // Evidence should be redacted
        assert!(findings[0].evidence.as_ref().is_some_and(|e| e.contains("AKIAIOSF...")));
        assert!(!findings[0].evidence.as_ref().is_some_and(|e| e.contains("EXAMPLE")));
        assert_eq!(findings[0].cwe_id, Some(798));
    }

    /// Verify empty input produces no findings.
    #[test]
    fn test_parse_gitleaks_empty() {
        assert!(parse_gitleaks_output("").is_empty());
        assert!(parse_gitleaks_output("[]").is_empty());
        assert!(parse_gitleaks_output("not json").is_empty());
    }

    /// Verify short secrets are fully redacted.
    #[test]
    fn test_redact_secret() {
        assert_eq!(redact_secret("abc"), "***");
        assert_eq!(redact_secret("12345678901234"), "12345678...");
    }
}
