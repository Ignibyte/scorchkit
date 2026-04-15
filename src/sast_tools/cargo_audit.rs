//! `cargo-audit` wrapper — Rust SCA via the `RustSec` advisory DB.
//!
//! Wraps [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
//! to scan a Rust project's `Cargo.lock` for known vulnerabilities.
//! `ScorchKit` already uses cargo-audit in its own CI; this wrapper
//! makes the same check available to library consumers and the
//! `code` subcommand against any Rust project.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Rust SCA via cargo-audit.
#[derive(Debug)]
pub struct CargoAuditModule;

#[async_trait]
impl CodeModule for CargoAuditModule {
    fn name(&self) -> &'static str {
        "cargo-audit Rust SCA"
    }
    fn id(&self) -> &'static str {
        "cargo_audit"
    }
    fn category(&self) -> CodeCategory {
        CodeCategory::Sca
    }
    fn description(&self) -> &'static str {
        "Scan Cargo.lock for known vulnerabilities via the RustSec advisory database"
    }
    fn languages(&self) -> &[&str] {
        &["rust"]
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("cargo-audit")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let path_str = ctx.path.display().to_string();
        let output = subprocess::run_tool_lenient(
            "cargo-audit",
            &["audit", "--json", "--file", &format!("{path_str}/Cargo.lock")],
            Duration::from_secs(60),
        )
        .await?;
        Ok(parse_cargo_audit_output(&output.stdout))
    }
}

/// Parse cargo-audit JSON into findings.
///
/// Output shape: `{"vulnerabilities": {"list": [{"advisory": {...}, "package": {...}}, ...]}}`.
#[must_use]
pub fn parse_cargo_audit_output(stdout: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let Some(list) = v["vulnerabilities"]["list"].as_array() else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|entry| {
            let id = entry["advisory"]["id"].as_str()?;
            let title = entry["advisory"]["title"].as_str().unwrap_or("");
            let pkg = entry["package"]["name"].as_str().unwrap_or("?");
            let ver = entry["package"]["version"].as_str().unwrap_or("?");
            let sev = match entry["advisory"]["informational"].as_str() {
                Some("unmaintained" | "notice") => Severity::Low,
                _ => Severity::High,
            };
            Some(
                Finding::new(
                    "cargo_audit",
                    sev,
                    format!("{id}: {pkg} {ver}"),
                    format!("Rust dependency {pkg} {ver} affected by {id}: {title}"),
                    format!("Cargo.lock:{pkg}@{ver}"),
                )
                .with_evidence(format!("Advisory: {id} | Package: {pkg} {ver}"))
                .with_remediation(format!(
                    "Update {pkg} per the advisory at https://rustsec.org/advisories/{id}"
                ))
                .with_owasp("A06:2021 Vulnerable and Outdated Components")
                .with_cwe(1104)
                .with_confidence(0.95),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Coverage for cargo-audit JSON parser.
    use super::*;

    /// Real-shape cargo-audit JSON yields one finding per advisory.
    #[test]
    fn parse_cargo_audit_output_with_vulns() {
        let stdout = r#"{"vulnerabilities": {"list": [
            {"advisory": {"id": "RUSTSEC-2024-0001", "title": "Buffer overflow in foo"},
             "package": {"name": "foo", "version": "0.1.0"}},
            {"advisory": {"id": "RUSTSEC-2024-0002", "title": "Use after free", "informational": "unmaintained"},
             "package": {"name": "bar", "version": "1.0.0"}}
        ]}}"#;
        let findings = parse_cargo_audit_output(stdout);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("RUSTSEC-2024-0001"));
        assert_eq!(findings[1].severity, Severity::Low);
    }

    /// Empty / no-vulns output yields zero findings.
    #[test]
    fn parse_cargo_audit_output_empty() {
        assert!(parse_cargo_audit_output("").is_empty());
        assert!(parse_cargo_audit_output(r#"{"vulnerabilities": {"list": []}}"#).is_empty());
    }
}
