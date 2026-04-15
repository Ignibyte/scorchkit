//! `ssh-audit` wrapper — SSH server hardening check.
//!
//! Wraps [ssh-audit](https://github.com/jtesta/ssh-audit) to evaluate
//! an SSH server's negotiated KEX algorithms, ciphers, MACs, and host
//! keys against current best practice. Sister module to `tls_infra`
//! for the SSH protocol.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// SSH hardening audit via ssh-audit.
#[derive(Debug)]
pub struct SshAuditModule;

#[async_trait]
impl ScanModule for SshAuditModule {
    fn name(&self) -> &'static str {
        "ssh-audit SSH Hardening Check"
    }

    fn id(&self) -> &'static str {
        "ssh_audit"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Audit SSH server algorithms, ciphers, MACs, and host keys against best practice"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("ssh-audit")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let output =
            subprocess::run_tool("ssh-audit", &["-j", host], Duration::from_secs(45)).await?;
        Ok(parse_ssh_audit_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Parse ssh-audit JSON output into findings.
///
/// ssh-audit's `-j` flag emits a JSON document with `kex`, `key`,
/// `enc`, `mac` arrays. Each entry has a `notes` object with
/// `fail` / `warn` / `info` arrays. We aggregate the `fail` items
/// (definitively weak) into a Medium finding and surface a banner
/// Info finding regardless.
#[must_use]
fn parse_ssh_audit_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_str(trimmed) else {
        return Vec::new();
    };
    let mut fails: Vec<String> = Vec::new();
    for section_key in ["kex", "key", "enc", "mac"] {
        let Some(arr) = v[section_key].as_array() else {
            continue;
        };
        for entry in arr {
            let name = entry["algorithm"].as_str().or_else(|| entry["name"].as_str());
            let has_fail = entry["notes"]["fail"].as_array().is_some_and(|a| !a.is_empty());
            if let (Some(name), true) = (name, has_fail) {
                fails.push(format!("{section_key}:{name}"));
            }
        }
    }
    let mut findings = Vec::new();
    if !fails.is_empty() {
        findings.push(
            Finding::new(
                "ssh_audit",
                Severity::Medium,
                format!("ssh-audit: {} weak SSH algorithm(s)", fails.len()),
                format!(
                    "ssh-audit flagged {} algorithm(s) on {host}'s SSH server as definitively \
                     weak (e.g. legacy CBC ciphers, MD5 MACs, 1024-bit DH groups). These reduce \
                     the cost of MITM and downgrade attacks.",
                    fails.len()
                ),
                target_url,
            )
            .with_evidence(format!("Weak: {}", fails.join(", ")))
            .with_remediation(
                "Update sshd_config to disable weak KexAlgorithms / Ciphers / MACs; \
                 prefer ChaCha20-Poly1305, AES-GCM, curve25519-sha256.",
            )
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(327)
            .with_confidence(0.9),
        );
    }
    if let Some(banner) = v["banner"]["raw"].as_str() {
        findings.push(
            Finding::new(
                "ssh_audit",
                Severity::Info,
                format!("ssh-audit: SSH banner on {host}"),
                "ssh-audit recorded the SSH server banner.".to_string(),
                target_url,
            )
            .with_evidence(banner.to_string())
            .with_confidence(0.95),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Coverage for ssh-audit JSON parser.
    use super::*;

    /// Output with one failing KEX algorithm yields a Medium finding.
    #[test]
    fn parse_ssh_audit_output_weak_kex() {
        let stdout = r#"{
            "banner": {"raw": "SSH-2.0-OpenSSH_8.2"},
            "kex": [
                {"algorithm": "diffie-hellman-group1-sha1", "notes": {"fail": ["broken"]}}
            ]
        }"#;
        let findings = parse_ssh_audit_output(stdout, "https://example.com", "example.com");
        let weak = findings.iter().find(|f| f.title.contains("weak SSH")).expect("weak");
        assert_eq!(weak.severity, Severity::Medium);
        assert!(findings.iter().any(|f| f.title.contains("banner")));
    }

    /// All-strong output yields only the banner Info finding.
    #[test]
    fn parse_ssh_audit_output_all_strong() {
        let stdout = r#"{
            "banner": {"raw": "SSH-2.0-OpenSSH_9.0"},
            "kex": [
                {"algorithm": "curve25519-sha256", "notes": {"fail": []}}
            ]
        }"#;
        let findings = parse_ssh_audit_output(stdout, "https://example.com", "example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// Empty / non-JSON output yields zero findings.
    #[test]
    fn parse_ssh_audit_output_empty() {
        assert!(parse_ssh_audit_output("", "https://example.com", "example.com").is_empty());
        assert!(parse_ssh_audit_output("not json", "https://example.com", "example.com").is_empty());
    }
}
