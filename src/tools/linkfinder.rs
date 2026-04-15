//! `linkfinder` wrapper — JavaScript endpoint extraction.
//!
//! Wraps [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
//! to extract API endpoints from JavaScript files. Complements
//! `ScorchKit`'s built-in `js_analysis` module with deeper
//! endpoint-discovery heuristics.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// `JavaScript` endpoint extractor via `LinkFinder`.
#[derive(Debug)]
pub struct LinkfinderModule;

#[async_trait]
impl ScanModule for LinkfinderModule {
    fn name(&self) -> &'static str {
        "LinkFinder JS Endpoint Extractor"
    }
    fn id(&self) -> &'static str {
        "linkfinder"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Extract API endpoints from JavaScript via LinkFinder"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("linkfinder")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let output = subprocess::run_tool_lenient(
            "linkfinder",
            &["-i", url, "-o", "cli"],
            Duration::from_secs(120),
        )
        .await?;
        Ok(parse_linkfinder_output(&output.stdout, url))
    }
}

/// Parse `LinkFinder` CLI output for discovered endpoints.
///
/// `-o cli` mode prints one URL per line. We aggregate into a
/// single Info finding listing the first 50.
#[must_use]
fn parse_linkfinder_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let endpoints: Vec<&str> =
        stdout.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('[')).collect();
    if endpoints.is_empty() {
        return Vec::new();
    }
    let count = endpoints.len();
    let sample: Vec<String> = endpoints.iter().take(50).map(|s| (*s).to_string()).collect();
    vec![Finding::new(
        "linkfinder",
        Severity::Info,
        format!("LinkFinder: {count} endpoint(s) extracted from JavaScript"),
        format!("LinkFinder mined {count} endpoint(s) from JavaScript on {target_url}."),
        target_url,
    )
    .with_evidence(format!("Sample: {}", sample.join(", ")))
    .with_remediation(
        "Audit each discovered endpoint for authentication, authorisation, and input \
         validation; some may be intended for internal use only.",
    )
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.85)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_linkfinder_output_with_endpoints() {
        let stdout = "[+] Found 3 endpoints\n\
                      /api/v1/users\n\
                      /api/v1/sessions\n\
                      /admin/dashboard\n";
        let findings = parse_linkfinder_output(stdout, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("3 endpoint"));
    }

    #[test]
    fn parse_linkfinder_output_empty() {
        assert!(parse_linkfinder_output("", "https://example.com").is_empty());
        assert!(parse_linkfinder_output("[*] no endpoints\n", "https://example.com").is_empty());
    }
}
