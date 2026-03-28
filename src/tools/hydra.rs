use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct HydraModule;

#[async_trait]
impl ScanModule for HydraModule {
    fn name(&self) -> &'static str {
        "Hydra Login Tester"
    }
    fn id(&self) -> &'static str {
        "hydra"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Default credential testing via Hydra"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("hydra")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let port = ctx.target.port.to_string();
        let proto = if ctx.target.is_https { "https-get" } else { "http-get" };

        // Only test a very small set of default credentials
        let output = subprocess::run_tool(
            "hydra",
            &["-l", "admin", "-p", "admin", "-s", &port, "-f", target, proto, "/admin"],
            Duration::from_secs(30),
        )
        .await?;

        parse_hydra_output(&output.stdout, ctx.target.url.as_str())
    }
}

fn parse_hydra_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for line in output.lines() {
        if line.contains("login:") && line.contains("password:") {
            findings.push(
                Finding::new(
                    "hydra",
                    Severity::Critical,
                    "Default Credentials Found",
                    format!("Hydra found valid credentials: {}", line.trim()),
                    target_url,
                )
                .with_evidence(line.trim().to_string())
                .with_remediation("Change default credentials immediately")
                .with_owasp("A07:2021 Identification and Authentication Failures")
                .with_cwe(798),
            );
        }
    }
    Ok(findings)
}
