use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// WordPress vulnerability scanning via WPScan.
#[derive(Debug)]
pub struct WpscanModule;

#[async_trait]
impl ScanModule for WpscanModule {
    fn name(&self) -> &'static str {
        "WPScan WordPress Scanner"
    }
    fn id(&self) -> &'static str {
        "wpscan"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "WordPress vulnerability scanning via WPScan"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("wpscan")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "wpscan",
            &["--url", target, "--format", "json", "--no-banner", "--random-user-agent"],
            Duration::from_secs(300),
        )
        .await?;

        parse_wpscan_output(&output.stdout, target)
    }
}

fn parse_wpscan_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return Ok(findings),
    };

    // WordPress version vulnerabilities
    if let Some(version) = json["version"].as_object() {
        let wp_ver = version.get("number").and_then(|v| v.as_str()).unwrap_or("unknown");
        findings.push(
            Finding::new(
                "wpscan",
                Severity::Info,
                format!("WordPress {wp_ver} Detected"),
                format!("WordPress version {wp_ver} is installed."),
                target_url,
            )
            .with_evidence(format!("WordPress version: {wp_ver}")),
        );

        if let Some(vulns) = version.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulns {
                let title = vuln["title"].as_str().unwrap_or("WordPress Vulnerability");
                let vuln_type = vuln["vuln_type"].as_str().unwrap_or("");
                let fixed_in = vuln["fixed_in"].as_str();

                let mut f = Finding::new(
                    "wpscan",
                    Severity::High,
                    format!("WP: {title}"),
                    title,
                    target_url,
                )
                .with_owasp("A06:2021 Vulnerable and Outdated Components");
                if let Some(fix) = fixed_in {
                    f = f.with_remediation(format!("Update WordPress to {fix} or later"));
                }
                if !vuln_type.is_empty() {
                    f = f.with_evidence(format!("Type: {vuln_type}"));
                }
                findings.push(f);
            }
        }
    }

    // Plugin vulnerabilities
    if let Some(plugins) = json["plugins"].as_object() {
        for (name, plugin) in plugins {
            if let Some(vulns) = plugin["vulnerabilities"].as_array() {
                for vuln in vulns {
                    let title = vuln["title"].as_str().unwrap_or("Plugin Vulnerability");
                    let fixed_in = vuln["fixed_in"].as_str();

                    let mut f = Finding::new(
                        "wpscan",
                        Severity::High,
                        format!("WP Plugin {name}: {title}"),
                        title,
                        target_url,
                    )
                    .with_owasp("A06:2021 Vulnerable and Outdated Components");
                    if let Some(fix) = fixed_in {
                        f = f.with_remediation(format!("Update {name} to {fix} or later"));
                    }
                    findings.push(f);
                }
            }
        }
    }

    Ok(findings)
}
