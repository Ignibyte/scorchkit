use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Fast web fuzzer via ffuf.
#[derive(Debug)]
pub struct FfufModule;

#[async_trait]
impl ScanModule for FfufModule {
    fn name(&self) -> &'static str {
        "ffuf Web Fuzzer"
    }
    fn id(&self) -> &'static str {
        "ffuf"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Fast content discovery and fuzzing via ffuf"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("ffuf")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = format!("{}/FUZZ", ctx.target.base_url());

        let wordlist = ctx.config.wordlists.directory.as_deref().map_or_else(
            || "/usr/share/wordlists/dirb/common.txt".to_string(),
            |p| p.to_string_lossy().into_owned(),
        );

        let output = subprocess::run_tool(
            "ffuf",
            &[
                "-u",
                &target,
                "-w",
                &wordlist,
                "-mc",
                "200,301,302,403",
                "-fc",
                "404",
                "-t",
                "20",
                "-maxtime",
                "120",
                "-o",
                "/dev/stdout",
                "-of",
                "json",
                "-s",
            ],
            Duration::from_secs(180),
        )
        .await?;

        Ok(parse_ffuf_output(&output.stdout, ctx.target.url.as_str()))
    }
}

fn parse_ffuf_output(output: &str, _target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    if let Some(results) = json["results"].as_array() {
        for result in results {
            let url = result["url"].as_str().unwrap_or("");
            let status = result["status"].as_u64().unwrap_or(0);
            let length = result["length"].as_u64().unwrap_or(0);
            let input = result["input"]
                .as_object()
                .and_then(|i| i.get("FUZZ"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if url.is_empty() {
                continue;
            }

            findings.push(
                Finding::new(
                    "ffuf",
                    Severity::Info,
                    format!("Discovered: /{input}"),
                    format!("ffuf discovered path: {url}"),
                    url,
                )
                .with_evidence(format!("HTTP {status} | Size: {length} bytes"))
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.6),
            );
        }
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings.truncate(50);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for ffuf JSON output parser.

    /// Verify that `parse_ffuf_output` correctly extracts discovered paths
    /// from ffuf JSON output with status codes and sizes.
    #[test]
    fn test_parse_ffuf_output() {
        let output = r#"{"results":[{"url":"https://example.com/admin","status":200,"length":1024,"input":{"FUZZ":"admin"}},{"url":"https://example.com/robots.txt","status":200,"length":56,"input":{"FUZZ":"robots.txt"}}]}"#;

        let findings = parse_ffuf_output(output, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("admin"));
        assert!(findings[1].title.contains("robots.txt"));
    }

    /// Verify that `parse_ffuf_output` handles empty input gracefully.
    #[test]
    fn test_parse_ffuf_output_empty() {
        let findings = parse_ffuf_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
