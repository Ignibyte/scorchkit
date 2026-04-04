use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct DalfoxModule;

#[async_trait]
impl ScanModule for DalfoxModule {
    fn name(&self) -> &'static str {
        "Dalfox XSS Scanner"
    }
    fn id(&self) -> &'static str {
        "dalfox"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Advanced XSS scanning via Dalfox"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("dalfox")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();
        let output = subprocess::run_tool(
            "dalfox",
            &["url", target, "--format", "json", "--silence"],
            Duration::from_secs(300),
        )
        .await?;
        Ok(parse_dalfox_output(&output.stdout, target))
    }
}

fn parse_dalfox_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in output.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let msg = json["data"].as_str().or_else(|| json["message"].as_str()).unwrap_or("");
            let severity_str = json["type"].as_str().unwrap_or("V");
            let poc = json["poc"].as_str().unwrap_or("");
            let param = json["param"].as_str().unwrap_or("");

            let severity = if severity_str == "V" { Severity::High } else { Severity::Info };

            if !msg.is_empty() {
                let mut f = Finding::new(
                    "dalfox",
                    severity,
                    format!("Dalfox XSS: {param}"),
                    msg,
                    target_url,
                )
                .with_owasp("A03:2021 Injection")
                .with_cwe(79);
                if !poc.is_empty() {
                    f = f.with_evidence(format!("PoC: {poc}"));
                }
                findings.push(f.with_confidence(0.8));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for Dalfox JSON-lines output parser.

    /// Verify that `parse_dalfox_output` correctly extracts XSS findings
    /// from Dalfox JSON-lines output including PoC evidence.
    #[test]
    fn test_parse_dalfox_output() {
        let output = r#"{"type":"V","data":"Reflected XSS found","param":"q","poc":"https://example.com/search?q=<script>alert(1)</script>"}"#;

        let findings = parse_dalfox_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("q"));
        assert_eq!(findings[0].cwe_id, Some(79));
    }

    /// Verify that `parse_dalfox_output` handles empty input gracefully.
    #[test]
    fn test_parse_dalfox_output_empty() {
        let findings = parse_dalfox_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
