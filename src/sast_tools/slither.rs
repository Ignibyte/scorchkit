//! `slither` wrapper — Solidity static analyzer.
//!
//! Wraps [slither](https://github.com/crytic/slither) — the
//! Trail of Bits Solidity static analysis framework. Detects
//! common smart-contract vulnerabilities (reentrancy, integer
//! overflow patterns, locked ether, suicidal contracts).

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Solidity static analysis via slither.
#[derive(Debug)]
pub struct SlitherModule;

#[async_trait]
impl CodeModule for SlitherModule {
    fn name(&self) -> &'static str {
        "slither Solidity SAST"
    }
    fn id(&self) -> &'static str {
        "slither"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }
    fn description(&self) -> &'static str {
        "Solidity static analysis: reentrancy, integer issues, locked ether, suicidal contracts"
    }
    fn languages(&self) -> &[&str] {
        &["solidity"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("slither")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "slither",
            &[&path_str, "--json", "-"],
            Duration::from_secs(180),
        )
        .await?;
        Ok(parse_slither_output(&output.stdout))
    }
}

/// Parse slither JSON output into findings.
///
/// Format: `{"results": {"detectors": [{"check": "...", "impact": "...",
/// "confidence": "...", "description": "...", "elements": [{"source_mapping": {...}}]}]}}`.
#[must_use]
pub fn parse_slither_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(detectors) = v["results"]["detectors"].as_array() else {
        return Vec::new();
    };
    detectors
        .iter()
        .map(|d| {
            let check = d["check"].as_str().unwrap_or("?");
            let description = d["description"].as_str().unwrap_or("");
            let impact = d["impact"].as_str().unwrap_or("Informational");
            let severity = match impact {
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Info,
            };
            let location =
                d["elements"][0]["source_mapping"]["filename_relative"].as_str().unwrap_or("?");
            Finding::new(
                "slither",
                severity,
                format!("slither {check}"),
                description.lines().next().unwrap_or("").to_string(),
                location.to_string(),
            )
            .with_evidence(format!("check={check} impact={impact}"))
            .with_owasp("A04:2021 Insecure Design")
            .with_confidence(0.85)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_slither_output_with_detectors() {
        let stdout = r#"{"results": {"detectors": [
            {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
             "description": "Reentrancy in withdraw()",
             "elements": [{"source_mapping": {"filename_relative": "Bank.sol"}}]},
            {"check": "locked-ether", "impact": "Medium", "confidence": "High",
             "description": "Contract locks ether",
             "elements": [{"source_mapping": {"filename_relative": "Vault.sol"}}]}
        ]}}"#;
        let findings = parse_slither_output(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn parse_slither_output_empty() {
        assert!(parse_slither_output("").is_empty());
        assert!(parse_slither_output(r#"{"results": {"detectors": []}}"#).is_empty());
    }
}
