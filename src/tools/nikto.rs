use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Web server vulnerability scanning via nikto.
#[derive(Debug)]
pub struct NiktoModule;

#[async_trait]
impl ScanModule for NiktoModule {
    fn name(&self) -> &'static str {
        "Nikto Web Scanner"
    }

    fn id(&self) -> &'static str {
        "nikto"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Web server vulnerability scanning via nikto"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nikto")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "nikto",
            &["-h", target, "-Format", "json", "-output", "-"],
            Duration::from_secs(600),
        )
        .await?;

        parse_nikto_output(&output.stdout, target)
    }
}

/// Parse nikto JSON output into findings.
fn parse_nikto_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Nikto JSON output can be a single JSON object or array
    // Try parsing as JSON value
    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => {
            // Try parsing line by line
            for line in output.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    parse_nikto_item(&v, target_url, &mut findings);
                }
            }
            return Ok(findings);
        }
    };

    // Handle array or single object
    if let Some(arr) = json.as_array() {
        for item in arr {
            if let Some(vulns) = item["vulnerabilities"].as_array() {
                for vuln in vulns {
                    parse_nikto_item(vuln, target_url, &mut findings);
                }
            }
        }
    } else if let Some(vulns) = json["vulnerabilities"].as_array() {
        for vuln in vulns {
            parse_nikto_item(vuln, target_url, &mut findings);
        }
    }

    Ok(findings)
}

fn parse_nikto_item(item: &serde_json::Value, target_url: &str, findings: &mut Vec<Finding>) {
    let id = item["id"].as_str().or(item["OSVDB"].as_str()).unwrap_or("unknown");
    let msg = item["msg"].as_str().or(item["message"].as_str()).unwrap_or("Nikto finding");
    let url = item["url"].as_str().unwrap_or(target_url);
    let method = item["method"].as_str().unwrap_or("GET");

    let severity = classify_nikto_severity(msg);

    findings.push(
        Finding::new("nikto", severity, format!("Nikto: {msg}"), msg, url)
            .with_evidence(format!("Nikto ID: {id} | Method: {method} | URL: {url}"))
            .with_owasp("A05:2021 Security Misconfiguration"),
    );
}

fn classify_nikto_severity(msg: &str) -> Severity {
    let lower = msg.to_lowercase();

    if lower.contains("remote code")
        || lower.contains("command injection")
        || lower.contains("backdoor")
        || lower.contains("rce")
    {
        Severity::Critical
    } else if lower.contains("sql injection")
        || lower.contains("xss")
        || lower.contains("directory traversal")
        || lower.contains("file inclusion")
    {
        Severity::High
    } else if lower.contains("information disclosure")
        || lower.contains("default file")
        || lower.contains("version")
    {
        Severity::Medium
    } else if lower.contains("header") || lower.contains("cookie") {
        Severity::Low
    } else {
        Severity::Info
    }
}
