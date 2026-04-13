//! `Trufflehog` wrapper for secret scanning.
//!
//! Wraps the `trufflehog` tool which scans filesystems, git repositories,
//! and other sources for leaked secrets, API keys, and credentials.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Secret scanning via Trufflehog (API keys, credentials, tokens).
#[derive(Debug)]
pub struct TrufflehogModule;

#[async_trait]
impl ScanModule for TrufflehogModule {
    fn name(&self) -> &'static str {
        "Trufflehog Secret Scanner"
    }

    fn id(&self) -> &'static str {
        "trufflehog"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Secret scanning for API keys, credentials, and tokens via Trufflehog"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("trufflehog")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "trufflehog",
            &["filesystem", "--json", "--no-update", target],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_trufflehog_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse Trufflehog JSON-lines output into findings.
///
/// Each line is a JSON object with `DetectorName`, `Verified`, `Raw`,
/// and `SourceMetadata` fields. Verified secrets are High severity,
/// unverified are Medium.
#[must_use]
fn parse_trufflehog_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        let detector = obj["DetectorName"].as_str().unwrap_or("unknown");
        let verified = obj["Verified"].as_bool().unwrap_or(false);
        let raw = obj["Raw"].as_str().unwrap_or("");
        let source_file =
            obj["SourceMetadata"]["Data"]["Filesystem"]["file"].as_str().unwrap_or("unknown");

        let severity = if verified { Severity::High } else { Severity::Medium };

        let status = if verified { "VERIFIED" } else { "unverified" };

        // Redact the raw secret for safe reporting
        let redacted = if raw.len() > 8 {
            format!("{}...{}", &raw[..4], &raw[raw.len() - 4..])
        } else {
            "***REDACTED***".to_string()
        };

        findings.push(
            Finding::new(
                "trufflehog",
                severity,
                format!("Secret Detected: {detector} ({status})"),
                format!(
                    "Trufflehog detected a {status} {detector} secret in {source_file}. \
                     Redacted value: {redacted}"
                ),
                target_url,
            )
            .with_evidence(format!(
                "Detector: {detector} | Verified: {verified} | File: {source_file}"
            ))
            .with_remediation(
                "Rotate the exposed credential immediately. Remove from source code \
                 and use environment variables or a secrets manager instead.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(798)
            .with_confidence(0.8),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify Trufflehog JSON-lines output parsing with verified and
    /// unverified secrets.
    #[test]
    fn test_parse_trufflehog_output() {
        let output = r#"{"DetectorName":"AWS","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/.env"}}}}
{"DetectorName":"GitHub","Verified":false,"Raw":"ghp_xxxxxxxxxxxxxxxxxxxx1234","SourceMetadata":{"Data":{"Filesystem":{"file":"/app/config.yml"}}}}"#;

        let findings = parse_trufflehog_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("AWS"));
        assert!(findings[0].title.contains("VERIFIED"));
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[1].title.contains("GitHub"));
        assert!(findings[1].title.contains("unverified"));
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_trufflehog_empty() {
        let findings = parse_trufflehog_output("", "https://example.com");
        assert!(findings.is_empty());

        let findings = parse_trufflehog_output("\n\n", "https://example.com");
        assert!(findings.is_empty());
    }
}
