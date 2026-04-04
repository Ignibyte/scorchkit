use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// TLS/SSL analysis via testssl.sh.
#[derive(Debug)]
pub struct TestsslModule;

#[async_trait]
impl ScanModule for TestsslModule {
    fn name(&self) -> &'static str {
        "testssl.sh TLS Analyzer"
    }
    fn id(&self) -> &'static str {
        "testssl"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Comprehensive TLS/SSL testing via testssl.sh"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("testssl.sh")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = format!("{}:{}", ctx.target.domain.as_deref().unwrap_or(""), ctx.target.port);

        let output = subprocess::run_tool(
            "testssl.sh",
            &["--jsonfile", "/dev/stdout", "--quiet", &target],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_testssl_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_testssl_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // testssl.sh --jsonfile outputs JSON-lines
    for line in output.lines() {
        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = json["id"].as_str().unwrap_or("");
        let sev = json["severity"].as_str().unwrap_or("INFO");
        let finding_text = json["finding"].as_str().unwrap_or("");

        if finding_text.is_empty() || sev == "OK" || sev == "INFO" {
            continue;
        }

        let severity = match sev {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        };

        findings.push(
            Finding::new("testssl", severity, format!("testssl: {id}"), finding_text, target_url)
                .with_evidence(format!("{id}: {finding_text}"))
                .with_owasp("A02:2021 Cryptographic Failures")
                .with_confidence(0.9),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for testssl.sh JSON-lines output parser.

    /// Verify that `parse_testssl_output` correctly extracts findings from
    /// testssl.sh JSON-lines output with severity classification.
    #[test]
    fn test_parse_testssl_output() {
        let output = r#"{"id":"heartbleed","severity":"CRITICAL","finding":"VULNERABLE -- serverass responded with 65535 bytes"}
{"id":"ccs-injection","severity":"HIGH","finding":"VULNERABLE (NOT ok)"}
{"id":"secure_renego","severity":"OK","finding":"Not vulnerable"}
{"id":"cert_chain","severity":"INFO","finding":"Certificate chain ok"}"#;

        let findings = parse_testssl_output(output, "https://example.com");
        // OK and INFO are skipped
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("heartbleed"));
        assert_eq!(findings[1].severity, Severity::High);
    }

    /// Verify that `parse_testssl_output` handles empty input gracefully.
    #[test]
    fn test_parse_testssl_output_empty() {
        let findings = parse_testssl_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
