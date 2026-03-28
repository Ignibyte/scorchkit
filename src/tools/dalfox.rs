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
        parse_dalfox_output(&output.stdout, target)
    }
}

fn parse_dalfox_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for line in output.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let msg = json["data"].as_str().or(json["message"].as_str()).unwrap_or("");
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
                findings.push(f);
            }
        }
    }
    Ok(findings)
}
