use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// OWASP ZAP automated scanning via CLI.
#[derive(Debug)]
pub struct ZapModule;

#[async_trait]
impl ScanModule for ZapModule {
    fn name(&self) -> &'static str {
        "OWASP ZAP Scanner"
    }
    fn id(&self) -> &'static str {
        "zap"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Active web application scanning via OWASP ZAP"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("zap-cli")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "zap-cli",
            &["quick-scan", "--self-contained", "--spider", "-r", "-o", "json", target],
            Duration::from_secs(600),
        )
        .await?;

        Ok(parse_zap_output(&output.stdout, target))
    }
}

fn parse_zap_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    if let Some(alerts) = json["alerts"].as_array().or_else(|| {
        json["site"].as_array().and_then(|s| s.first()).and_then(|s| s["alerts"].as_array())
    }) {
        for alert in alerts {
            let name =
                alert["name"].as_str().or_else(|| alert["alert"].as_str()).unwrap_or("ZAP Finding");
            let desc =
                alert["desc"].as_str().or_else(|| alert["description"].as_str()).unwrap_or("");
            let risk = alert["riskcode"].as_str().or_else(|| alert["risk"].as_str()).unwrap_or("0");
            let url = alert["url"].as_str().unwrap_or(target_url);
            let solution = alert["solution"].as_str();
            let cweid = alert["cweid"].as_str().or_else(|| alert["cwe"].as_str());

            let severity = match risk {
                "3" => Severity::High,
                "2" => Severity::Medium,
                "1" => Severity::Low,
                _ => Severity::Info,
            };

            let mut f = Finding::new("zap", severity, format!("ZAP: {name}"), desc, url)
                .with_owasp("A05:2021 Security Misconfiguration");

            if let Some(sol) = solution {
                f = f.with_remediation(sol);
            }
            if let Some(cwe) = cweid {
                if let Ok(id) = cwe.parse::<u32>() {
                    f = f.with_cwe(id);
                }
            }

            findings.push(f.with_confidence(0.7));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for OWASP ZAP JSON output parser.

    /// Verify that `parse_zap_output` correctly extracts alerts with severity
    /// mapping and CWE extraction from ZAP JSON output.
    #[test]
    fn test_parse_zap_output() {
        let output = r#"{"alerts":[{"name":"X-Frame-Options Header Not Set","desc":"Missing anti-clickjacking header.","riskcode":"2","url":"https://example.com","solution":"Set X-Frame-Options to DENY or SAMEORIGIN.","cweid":"1021"},{"name":"Server Leaks Version","desc":"Server header discloses version info.","riskcode":"1","url":"https://example.com","solution":"Remove version info from Server header.","cweid":"200"}]}"#;

        let findings = parse_zap_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Medium); // riskcode 2
        assert_eq!(findings[0].cwe_id, Some(1021));
        assert_eq!(findings[1].severity, Severity::Low); // riskcode 1
    }

    /// Verify that `parse_zap_output` handles empty input gracefully.
    #[test]
    fn test_parse_zap_output_empty() {
        let findings = parse_zap_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
