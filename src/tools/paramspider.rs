//! `ParamSpider` wrapper for URL parameter mining.
//!
//! Wraps `ParamSpider` to discover URLs with query parameters from
//! web archives. These parameterized URLs are valuable injection points
//! for fuzzing, `SQLi`, XSS, and SSRF testing.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// URL parameter mining via `ParamSpider`.
#[derive(Debug)]
pub struct ParamSpiderModule;

#[async_trait]
impl ScanModule for ParamSpiderModule {
    fn name(&self) -> &'static str {
        "ParamSpider Parameter Miner"
    }

    fn id(&self) -> &'static str {
        "paramspider"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Mine URLs with query parameters for injection point discovery"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("paramspider")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "paramspider",
            &["-d", domain, "--quiet"],
            Duration::from_secs(120),
        )
        .await?;

        Ok(parse_paramspider_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse `ParamSpider` output (one parameterized URL per line) into findings.
///
/// Only includes URLs containing query parameters (`?` followed by `=`).
#[must_use]
fn parse_paramspider_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let urls: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && line.contains('?') && line.contains('='))
        .collect();

    if urls.is_empty() {
        return Vec::new();
    }

    let count = urls.len();
    let sample: Vec<&str> = urls.iter().copied().take(10).collect();

    // Extract unique parameter names
    let param_names: Vec<String> = urls
        .iter()
        .filter_map(|url| url.split('?').nth(1))
        .flat_map(|query| query.split('&'))
        .filter_map(|pair| pair.split('=').next())
        .map(String::from)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .take(15)
        .collect();

    vec![Finding::new(
        "paramspider",
        Severity::Info,
        format!("ParamSpider: {count} Parameterized URLs Found"),
        format!(
            "ParamSpider discovered {count} URLs with query parameters. \
             Unique parameters: {}. These are potential injection points \
             for SQL injection, XSS, SSRF, and other parameter-based attacks. \
             Sample: {}",
            param_names.join(", "),
            sample.join(", ")
        ),
        target_url,
    )
    .with_evidence(format!("{count} parameterized URLs, {} unique params", param_names.len()))
    .with_owasp("A03:2021 Injection")
    .with_confidence(0.6)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify ParamSpider output parsing filters for parameterized URLs.
    #[test]
    fn test_parse_paramspider_output() {
        let output = "https://example.com/search?q=FUZZ\n\
                       https://example.com/page?id=1&lang=en\n\
                       https://example.com/static/style.css\n\
                       https://example.com/api?token=FUZZ&action=view\n";

        let findings = parse_paramspider_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        // Only 3 URLs have params (style.css line filtered out)
        assert!(findings[0].title.contains("3 Parameterized"));
    }

    /// Verify empty and non-parameterized output produces no findings.
    #[test]
    fn test_parse_paramspider_empty() {
        let findings = parse_paramspider_output("", "https://example.com");
        assert!(findings.is_empty());

        // No query parameters
        let no_params = "https://example.com/page\nhttps://example.com/about\n";
        let findings = parse_paramspider_output(no_params, "https://example.com");
        assert!(findings.is_empty());
    }
}
