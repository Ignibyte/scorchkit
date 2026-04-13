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

        Ok(parse_nikto_output(&output.stdout, target))
    }
}

/// Parse nikto JSON output into findings.
fn parse_nikto_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Nikto JSON output can be a single JSON object or array
    // Try parsing as JSON value
    let json: serde_json::Value = if let Ok(v) = serde_json::from_str(output) {
        v
    } else {
        // Try parsing line by line
        for line in output.lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                parse_nikto_item(&v, target_url, &mut findings);
            }
        }
        return findings;
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

    findings
}

fn parse_nikto_item(item: &serde_json::Value, target_url: &str, findings: &mut Vec<Finding>) {
    let id = item["id"].as_str().or_else(|| item["OSVDB"].as_str()).unwrap_or("unknown");
    let msg = item["msg"].as_str().or_else(|| item["message"].as_str()).unwrap_or("Nikto finding");
    let url = item["url"].as_str().unwrap_or(target_url);
    let method = item["method"].as_str().unwrap_or("GET");

    let severity = classify_nikto_severity(msg);

    findings.push(
        Finding::new("nikto", severity, format!("Nikto: {msg}"), msg, url)
            .with_evidence(format!("Nikto ID: {id} | Method: {method} | URL: {url}"))
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.6),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for nikto JSON output parser.

    /// Verify that `parse_nikto_output` correctly extracts findings from
    /// nikto JSON output with vulnerabilities array.
    #[test]
    fn test_parse_nikto_output() {
        let output = r#"[{"vulnerabilities":[{"id":"999990","msg":"Retrieved X-Powered-By header: Express","url":"/","method":"GET"},{"id":"999986","msg":"SQL injection in search parameter","url":"/search","method":"POST"}]}]"#;

        let findings = parse_nikto_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("X-Powered-By"));
        assert!(findings[1].title.contains("SQL injection"));
        assert_eq!(findings[1].severity, Severity::High);
    }

    /// Verify that `parse_nikto_output` handles empty input gracefully.
    #[test]
    fn test_parse_nikto_output_empty() {
        let findings = parse_nikto_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
