//! `cargo-deny` wrapper — Rust dependency policy + advisory check.
//!
//! Wraps [cargo-deny](https://github.com/EmbarkStudios/cargo-deny)
//! for license compliance and supply-chain advisory enforcement on
//! Rust projects. Complements `cargo-audit` (advisories only) by
//! also checking license policy, banned crates, and source registry
//! restrictions.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Rust dependency policy + advisory check via cargo-deny.
#[derive(Debug)]
pub struct CargoDenyModule;

#[async_trait]
impl CodeModule for CargoDenyModule {
    fn name(&self) -> &'static str {
        "cargo-deny Policy + Advisories"
    }
    fn id(&self) -> &'static str {
        "cargo_deny"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sca
    }
    fn description(&self) -> &'static str {
        "License compliance + supply-chain advisory enforcement for Rust projects"
    }
    fn languages(&self) -> &[&str] {
        &["rust"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("cargo-deny")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        // cargo-deny exits non-zero on policy violations; that's
        // expected — use lenient runner. JSON output via --format json.
        let output = subprocess::run_tool_lenient(
            "cargo-deny",
            &["--manifest-path", &format!("{path_str}/Cargo.toml"), "--format", "json", "check"],
            Duration::from_secs(120),
        )
        .await?;
        Ok(parse_cargo_deny_output(&output.stdout, &output.stderr))
    }
}

/// Parse cargo-deny output into findings.
///
/// cargo-deny emits diagnostics on stderr in JSON-Lines when
/// `--format json` is set. Each line is a JSON object with
/// `type`, `fields.severity`, `fields.message`, `fields.code`.
#[must_use]
pub fn parse_cargo_deny_output(_stdout: &str, stderr: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
            continue;
        };
        if v["type"].as_str() != Some("diagnostic") {
            continue;
        }
        let fields = &v["fields"];
        let severity_str = fields["severity"].as_str().unwrap_or("warning");
        let severity = match severity_str {
            "error" => Severity::High,
            "warning" => Severity::Medium,
            "note" | "help" => Severity::Low,
            _ => Severity::Info,
        };
        let message = fields["message"].as_str().unwrap_or("(no message)");
        let code = fields["code"].as_str().unwrap_or("?");
        findings.push(
            Finding::new(
                "cargo_deny",
                severity,
                format!("cargo-deny {code}: {message}"),
                message.to_string(),
                "Cargo.toml".to_string(),
            )
            .with_evidence(format!("severity={severity_str} code={code}"))
            .with_remediation(
                "Resolve per cargo-deny's diagnostic — adjust deny.toml, update the crate, \
                 or add an explicit ignore with rationale.",
            )
            .with_confidence(0.85),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Coverage for cargo-deny JSON-Lines parser.
    use super::*;

    /// JSON-Lines diagnostics on stderr produce one finding per line.
    #[test]
    fn parse_cargo_deny_output_diagnostics() {
        let stderr = r#"{"type":"diagnostic","fields":{"severity":"error","code":"banned","message":"crate banned"}}
{"type":"diagnostic","fields":{"severity":"warning","code":"unmaintained","message":"crate unmaintained"}}
{"type":"diagnostic","fields":{"severity":"note","code":"info","message":"context only"}}"#;
        let findings = parse_cargo_deny_output("", stderr);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[2].severity, Severity::Low);
    }

    /// Non-diagnostic lines (cargo summary, blank lines, garbage) are skipped.
    #[test]
    fn parse_cargo_deny_output_skips_non_diagnostic() {
        let stderr = "\nnot json\n{\"type\":\"summary\"}\n";
        assert!(parse_cargo_deny_output("", stderr).is_empty());
    }
}
