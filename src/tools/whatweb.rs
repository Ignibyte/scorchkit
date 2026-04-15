//! `whatweb` wrapper — web technology fingerprinting.
//!
//! Wraps [WhatWeb](https://github.com/urbanadventurer/WhatWeb) for
//! deep web-technology identification. Complements `ScorchKit`'s
//! built-in `tech` recon module with a much larger plugin database.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Web technology fingerprinting via `WhatWeb`.
#[derive(Debug)]
pub struct WhatwebModule;

#[async_trait]
impl ScanModule for WhatwebModule {
    fn name(&self) -> &'static str {
        "WhatWeb Tech Fingerprinter"
    }
    fn id(&self) -> &'static str {
        "whatweb"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Deep web-technology fingerprinting via WhatWeb's plugin database"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("whatweb")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let output = subprocess::run_tool_lenient(
            "whatweb",
            &["--log-json=-", "-q", url],
            Duration::from_secs(60),
        )
        .await?;
        Ok(parse_whatweb_output(&output.stdout, url))
    }
}

/// Parse `WhatWeb` JSON-Lines output into findings.
#[must_use]
fn parse_whatweb_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let plugins: Vec<String> = trimmed
        .lines()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
            let obj = v.get("plugins")?.as_object()?;
            Some(obj.keys().cloned().collect::<Vec<_>>().join(", "))
        })
        .filter(|s| !s.is_empty())
        .collect();
    if plugins.is_empty() {
        return Vec::new();
    }
    let combined = plugins.join(" | ");
    vec![Finding::new(
        "whatweb",
        Severity::Info,
        format!("WhatWeb: technology fingerprint for {target_url}"),
        format!("WhatWeb identified the following technologies: {combined}"),
        target_url,
    )
    .with_evidence(combined)
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.9)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_whatweb_output_with_plugins() {
        let stdout = r#"{"target":"https://example.com","plugins":{"Apache":{},"PHP":{}}}"#;
        let findings = parse_whatweb_output(stdout, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.as_ref().unwrap().contains("Apache"));
    }

    #[test]
    fn parse_whatweb_output_empty() {
        assert!(parse_whatweb_output("", "https://example.com").is_empty());
    }
}
