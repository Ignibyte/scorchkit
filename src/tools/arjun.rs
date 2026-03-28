use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct ArjunModule;

#[async_trait]
impl ScanModule for ArjunModule {
    fn name(&self) -> &'static str {
        "Arjun Parameter Discovery"
    }
    fn id(&self) -> &'static str {
        "arjun"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Hidden HTTP parameter discovery via Arjun"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("arjun")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();
        let output = subprocess::run_tool(
            "arjun",
            &["-u", target, "--json", "/dev/stdout", "-q"],
            Duration::from_secs(120),
        )
        .await?;

        parse_arjun_output(&output.stdout, target)
    }
}

fn parse_arjun_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(obj) = json.as_object() {
            for (url, params) in obj {
                if let Some(arr) = params.as_array() {
                    let param_list: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                    if !param_list.is_empty() {
                        findings.push(
                            Finding::new("arjun", Severity::Low, format!("{} Hidden Parameters Found", param_list.len()), format!("Arjun discovered hidden parameters that may accept user input."), url)
                                .with_evidence(format!("Parameters: {}", param_list.join(", ")))
                                .with_remediation("Test discovered parameters for injection vulnerabilities"),
                        );
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        // Try plain text output
        for line in output.lines() {
            if line.contains("parameter") || line.contains("param") {
                findings.push(
                    Finding::new(
                        "arjun",
                        Severity::Info,
                        "Parameters Discovered",
                        line.trim(),
                        target_url,
                    )
                    .with_evidence(line.trim().to_string()),
                );
            }
        }
    }

    Ok(findings)
}
