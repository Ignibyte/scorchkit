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

        parse_testssl_output(&output.stdout, ctx.target.url.as_str())
    }
}

fn parse_testssl_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
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
                .with_owasp("A02:2021 Cryptographic Failures"),
        );
    }

    Ok(findings)
}
