//! `dockle` wrapper — container image linting (CIS Docker bench).
//!
//! Wraps [dockle](https://github.com/goodwithtech/dockle) for
//! built-image security checks. Complements `hadolint` (which lints
//! the Dockerfile) by inspecting the runtime image: layer
//! inefficiencies, suspicious files, missing user, exposed
//! secrets in image history.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Container image linter via dockle.
#[derive(Debug)]
pub struct DockleModule;

#[async_trait]
impl CodeModule for DockleModule {
    fn name(&self) -> &'static str {
        "dockle Container Image Linter"
    }
    fn id(&self) -> &'static str {
        "dockle"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Container
    }
    fn description(&self) -> &'static str {
        "Container-image security check (CIS Docker bench, image-history secrets)"
    }
    fn languages(&self) -> &[&str] {
        &["docker"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("dockle")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // dockle takes an image reference; for SAST we treat the
        // path as the image tag (operators wire this via CI: build
        // image, then `scorchkit code <image-tag>`).
        let output = subprocess::run_tool_lenient(
            "dockle",
            &["--format", "json", &path_str],
            Duration::from_secs(120),
        )
        .await?;
        Ok(parse_dockle_output(&output.stdout))
    }
}

/// Parse dockle JSON output into findings.
///
/// Format: `{"details": [{"code": "...", "title": "...", "level": "...",
/// "alerts": ["..."]}]}`.
#[must_use]
pub fn parse_dockle_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(details) = v["details"].as_array() else {
        return Vec::new();
    };
    details
        .iter()
        .map(|d| {
            let code = d["code"].as_str().unwrap_or("?");
            let title = d["title"].as_str().unwrap_or("");
            let level_str = d["level"].as_str().unwrap_or("INFO");
            let severity = match level_str {
                "FATAL" => Severity::Critical,
                "WARN" => Severity::High,
                "INFO" => Severity::Medium,
                _ => Severity::Low,
            };
            let alerts = d["alerts"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .unwrap_or_default();
            Finding::new(
                "dockle",
                severity,
                format!("dockle {code}: {title}"),
                alerts,
                "container-image".to_string(),
            )
            .with_evidence(format!("code={code} level={level_str}"))
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.85)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dockle_output_with_details() {
        let stdout = r#"{"details": [
            {"code": "CIS-DI-0001", "title": "Create user", "level": "WARN", "alerts": ["Last user is root"]},
            {"code": "DKL-DI-0006", "title": "ADD instead of COPY", "level": "FATAL", "alerts": ["Found ADD"]}
        ]}"#;
        let findings = parse_dockle_output(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn parse_dockle_output_empty() {
        assert!(parse_dockle_output("").is_empty());
        assert!(parse_dockle_output(r#"{"details": []}"#).is_empty());
    }
}
