use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;
use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug)]
pub struct HttpxModule;

#[async_trait]
impl ScanModule for HttpxModule {
    fn name(&self) -> &'static str {
        "httpx HTTP Prober"
    }
    fn id(&self) -> &'static str {
        "httpx"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "HTTP technology probing via httpx"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("httpx")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().ok_or_else(|| ScorchError::InvalidTarget {
            target: ctx.target.raw.clone(),
            reason: "no domain".to_string(),
        })?;

        let output = subprocess::run_tool(
            "httpx",
            &[
                "-target",
                domain,
                "-json",
                "-silent",
                "-tech-detect",
                "-status-code",
                "-title",
                "-web-server",
                "-cdn",
            ],
            Duration::from_secs(60),
        )
        .await?;

        Ok(parse_httpx_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_httpx_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in output.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let url = json["url"].as_str().unwrap_or(target_url);
            let title = json["title"].as_str().unwrap_or("");
            let server = json["webserver"].as_str().unwrap_or("");
            let tech = json["tech"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            let cdn = json["cdn"].as_bool().unwrap_or(false);

            let mut evidence_parts = Vec::new();
            if !title.is_empty() {
                evidence_parts.push(format!("Title: {title}"));
            }
            if !server.is_empty() {
                evidence_parts.push(format!("Server: {server}"));
            }
            if !tech.is_empty() {
                evidence_parts.push(format!("Tech: {tech}"));
            }
            if cdn {
                evidence_parts.push("CDN: yes".to_string());
            }

            if !evidence_parts.is_empty() {
                findings.push(
                    Finding::new(
                        "httpx",
                        Severity::Info,
                        "httpx Probe Results",
                        format!("HTTP probe results for {url}"),
                        url,
                    )
                    .with_evidence(evidence_parts.join(" | "))
                    .with_confidence(0.8),
                );
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for httpx JSON-lines output parser.

    /// Verify that `parse_httpx_output` correctly extracts probe results
    /// including title, server, technology, and CDN detection.
    #[test]
    fn test_parse_httpx_output() {
        let output = r#"{"url":"https://example.com","title":"Example Domain","webserver":"nginx/1.21.0","tech":["Nginx","Bootstrap"],"cdn":true,"status_code":200}"#;

        let findings = parse_httpx_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        let evidence = findings[0].evidence.as_deref().unwrap_or("");
        assert!(evidence.contains("nginx"));
        assert!(evidence.contains("CDN: yes"));
    }

    /// Verify that `parse_httpx_output` handles empty input gracefully.
    #[test]
    fn test_parse_httpx_output_empty() {
        let findings = parse_httpx_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
