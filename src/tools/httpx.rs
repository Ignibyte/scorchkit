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

        parse_httpx_output(&output.stdout, ctx.target.url.as_str())
    }
}

fn parse_httpx_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
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
                    .with_evidence(evidence_parts.join(" | ")),
                );
            }
        }
    }
    Ok(findings)
}
