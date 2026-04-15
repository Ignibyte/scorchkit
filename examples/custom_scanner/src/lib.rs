//! Example third-party ScorchKit scan module.
//!
//! This crate demonstrates how to implement a custom DAST [`ScanModule`]
//! for the ScorchKit scanner. A plugin author:
//!
//! 1. Adds `scorchkit = "1.0"` and `async-trait = "0.1"` to `Cargo.toml`.
//! 2. Imports types from [`scorchkit::prelude`].
//! 3. Defines a struct implementing [`ScanModule`].
//! 4. Registers it with an orchestrator (typically by building a custom
//!    binary that wraps ScorchKit's `Engine` or `Orchestrator`).
//!
//! # The ScanModule Contract
//!
//! Every scan module is an `async` trait object that:
//! - Has a stable string `id` for CLI/config reference
//! - Has a human-readable `name` and `description`
//! - Belongs to a [`ModuleCategory`] (`Recon` or `Scanner`)
//! - Receives a [`ScanContext`] with target, HTTP client, and config
//! - Returns `Result<Vec<Finding>>`
//!
//! # Finding Builder
//!
//! Findings use a fluent builder:
//!
//! ```
//! use scorchkit::prelude::*;
//!
//! let finding = Finding::new(
//!     "my-module",
//!     Severity::Medium,
//!     "Example Issue Title",
//!     "Longer description of what was found.",
//!     "https://example.com/endpoint",
//! )
//! .with_evidence("Response snippet or exploit proof")
//! .with_remediation("How to fix this")
//! .with_owasp("A03:2021 Injection")
//! .with_cwe(89)
//! .with_confidence(0.85);
//! # let _ = finding;
//! ```

use async_trait::async_trait;
use scorchkit::prelude::*;

/// Example custom scanner — flags any response containing the word "debug".
///
/// Demonstrates the minimal viable `ScanModule` implementation. A real
/// plugin would do meaningful security analysis here.
#[derive(Debug, Default)]
pub struct DebugMarkerScanner;

#[async_trait]
impl ScanModule for DebugMarkerScanner {
    fn name(&self) -> &'static str {
        "Debug Marker Scanner"
    }

    fn id(&self) -> &'static str {
        "debug-marker"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Example plugin: flags responses containing the word 'debug'"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        // Fetch the target URL using the context's HTTP client.
        // The client is preconfigured with auth, proxy, and TLS settings.
        let response = ctx
            .http_client
            .get(ctx.target.url.as_str())
            .send()
            .await
            .map_err(|e| ScorchError::Config(format!("request failed: {e}")))?;

        let body = response
            .text()
            .await
            .map_err(|e| ScorchError::Config(format!("body read failed: {e}")))?;

        let mut findings = Vec::new();
        if body.to_lowercase().contains("debug") {
            findings.push(
                Finding::new(
                    self.id(),
                    Severity::Low,
                    "Debug marker detected in response",
                    "The response body contains the word 'debug', which may indicate \
                     a debugging feature left enabled in production.",
                    ctx.target.url.as_str(),
                )
                .with_evidence("Response body contains 'debug' (case-insensitive)")
                .with_remediation(
                    "Disable debugging features before deploying to production. \
                     Audit the codebase for leftover debug flags.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(489)
                .with_confidence(0.6),
            );
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify module metadata matches the trait contract.
    #[test]
    fn test_module_metadata() {
        let module = DebugMarkerScanner;
        assert_eq!(module.id(), "debug-marker");
        assert_eq!(module.name(), "Debug Marker Scanner");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify Finding builder works with the plugin's module ID.
    #[test]
    fn test_build_finding() {
        let finding = Finding::new(
            "debug-marker",
            Severity::Low,
            "Test finding",
            "Test description",
            "https://example.com",
        )
        .with_confidence(0.7);

        assert_eq!(finding.module_id, "debug-marker");
        assert_eq!(finding.severity, Severity::Low);
        assert!((finding.confidence - 0.7).abs() < f64::EPSILON);
    }
}
