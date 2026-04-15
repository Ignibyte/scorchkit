//! `wapiti` wrapper — full web vulnerability scanner.
//!
//! Wraps [Wapiti](https://wapiti-scanner.github.io/) — a
//! batteries-included alternative to `OWASP` `ZAP`. Performs `SQLi`,
//! XSS, command injection, file disclosure, CRLF, and more.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Web vulnerability scanner via Wapiti.
#[derive(Debug)]
pub struct WapitiModule;

#[async_trait]
impl ScanModule for WapitiModule {
    fn name(&self) -> &'static str {
        "Wapiti Web Vuln Scanner"
    }
    fn id(&self) -> &'static str {
        "wapiti"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Full web vulnerability scan (SQLi / XSS / cmdi / file disclosure / CRLF) via Wapiti"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("wapiti")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let Ok(tmp) = tempfile::NamedTempFile::new() else {
            return Ok(Vec::new());
        };
        let report_path = tmp.path().to_string_lossy().to_string();
        let _output = subprocess::run_tool_lenient(
            "wapiti",
            &["-u", url, "-f", "json", "-o", &report_path],
            Duration::from_secs(300),
        )
        .await?;
        let json = std::fs::read_to_string(&report_path).unwrap_or_default();
        Ok(parse_wapiti_output(&json, url))
    }
}

/// Parse Wapiti JSON report into findings.
///
/// Format: `{"vulnerabilities": {"<category>": [{"info": "...", "level": N,
/// "method": "...", "path": "..."}]}}`. `level` is 1 (Info) to 4 (High).
#[must_use]
fn parse_wapiti_output(json: &str, target_url: &str) -> Vec<Finding> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(map) = v["vulnerabilities"].as_object() else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (category, entries) in map {
        let Some(arr) = entries.as_array() else { continue };
        for entry in arr {
            let level = entry["level"].as_i64().unwrap_or(2);
            let severity = match level {
                4 => Severity::High,
                3 => Severity::Medium,
                2 => Severity::Low,
                _ => Severity::Info,
            };
            let info = entry["info"].as_str().unwrap_or("");
            let method = entry["method"].as_str().unwrap_or("?");
            let path = entry["path"].as_str().unwrap_or("?");
            findings.push(
                Finding::new(
                    "wapiti",
                    severity,
                    format!("Wapiti {category}: {method} {path}"),
                    info.to_string(),
                    format!("{target_url}{path}"),
                )
                .with_evidence(format!("category={category} method={method} path={path}"))
                .with_owasp("A03:2021 Injection")
                .with_confidence(0.85),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wapiti_output_with_vulns() {
        let json = r#"{"vulnerabilities": {
            "SQL Injection": [{"info": "MySQL error", "level": 4, "method": "GET", "path": "/?id=1"}],
            "XSS Reflected": [{"info": "<script>", "level": 3, "method": "GET", "path": "/?q=x"}]
        }}"#;
        let findings = parse_wapiti_output(json, "https://example.com");
        assert_eq!(findings.len(), 2);
        let high = findings.iter().find(|f| f.title.contains("SQL")).expect("sql");
        assert_eq!(high.severity, Severity::High);
    }

    #[test]
    fn parse_wapiti_output_empty() {
        assert!(parse_wapiti_output("", "https://example.com").is_empty());
        assert!(parse_wapiti_output(r#"{"vulnerabilities": {}}"#, "https://example.com").is_empty());
    }
}
