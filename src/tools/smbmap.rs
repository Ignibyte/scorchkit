//! `smbmap` wrapper — SMB share enumeration.
//!
//! Wraps [smbmap](https://github.com/ShawnDEvans/smbmap) for
//! enumerating SMB shares on a target host. With no credentials,
//! checks for null-session access. World-readable or world-writable
//! shares are surfaced as Medium / High findings respectively.

use std::time::Duration;

use async_trait::async_trait;
use tracing::debug;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::network_credentials::{format_redacted_argv, NetworkCredentials};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// SMB share enumerator via smbmap.
#[derive(Debug)]
pub struct SmbmapModule;

#[async_trait]
impl ScanModule for SmbmapModule {
    fn name(&self) -> &'static str {
        "smbmap SMB Share Enumerator"
    }

    fn id(&self) -> &'static str {
        "smbmap"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Enumerate SMB shares on the target; flag null-session and world-writable access"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("smbmap")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let creds = NetworkCredentials::from_config_with_env(&ctx.config.network_credentials);
        let owned = build_argv(&creds, host);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        debug!("smbmap: {}", format_redacted_argv(&args));
        let output = subprocess::run_tool("smbmap", &args, Duration::from_secs(120)).await?;
        Ok(parse_smbmap_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Build the smbmap argv. With SMB credentials present, forwards them
/// via `-u USER -p PASS`. Without credentials, preserves the existing
/// anonymous probe (`-u anonymous -p ""`).
#[must_use]
fn build_argv(creds: &NetworkCredentials, host: &str) -> Vec<String> {
    let (user, password) = match (&creds.smb_username, &creds.smb_password) {
        (Some(u), Some(p)) if !u.is_empty() => (u.clone(), p.clone()),
        _ => ("anonymous".to_string(), String::new()),
    };
    vec!["-H".to_string(), host.to_string(), "-u".to_string(), user, "-p".to_string(), password]
}

/// Parse smbmap text output into findings.
///
/// smbmap prints a table-style view with `Disk` rows, each carrying
/// a permission hint (`READ ONLY`, `READ, WRITE`, `NO ACCESS`). We
/// promote any `READ` access from an anonymous session to a Medium
/// finding (info disclosure) and any `WRITE` access to a High
/// finding (potential foothold).
#[must_use]
fn parse_smbmap_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut readable: Vec<String> = Vec::new();
    let mut writable: Vec<String> = Vec::new();

    // smbmap prints a table whose data rows are `<share>  <permissions>  [comment]`.
    // The header line contains `Disk` and `Permissions`; data rows do not. We
    // accept any row that mentions READ or WRITE and isn't a header / separator /
    // status line.
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let upper = trimmed.to_uppercase();
        // Skip headers, separators, status banners.
        if upper.starts_with("DISK")
            || upper.contains("PERMISSIONS")
            || trimmed.starts_with("---")
            || trimmed.starts_with('[')
        {
            continue;
        }
        if !upper.contains("READ") && !upper.contains("WRITE") {
            continue;
        }
        let share = trimmed.split_whitespace().next().unwrap_or("?").to_string();
        if upper.contains("WRITE") {
            writable.push(share);
        } else {
            readable.push(share);
        }
    }

    if !writable.is_empty() {
        findings.push(
            Finding::new(
                "smbmap",
                Severity::High,
                format!("Anonymous WRITE access to {} SMB share(s)", writable.len()),
                "smbmap mounted SMB shares with WRITE permission via an anonymous \
                 null session. An attacker can drop arbitrary files (potentially \
                 including code) onto the target."
                    .to_string(),
                target_url,
            )
            .with_evidence(format!("Writable shares on {host}: {}", writable.join(", ")))
            .with_remediation(
                "Disable null-session access; require authentication; restrict share \
                 permissions to least-privilege users.",
            )
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(284)
            .with_confidence(0.9),
        );
    }
    if !readable.is_empty() {
        findings.push(
            Finding::new(
                "smbmap",
                Severity::Medium,
                format!("Anonymous READ access to {} SMB share(s)", readable.len()),
                "smbmap mounted SMB shares with READ permission via an anonymous \
                 null session. Files exposed in these shares may contain credentials, \
                 internal documentation, or PII."
                    .to_string(),
                target_url,
            )
            .with_evidence(format!("Readable shares on {host}: {}", readable.join(", ")))
            .with_remediation("Disable null-session access; require authentication.")
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(284)
            .with_confidence(0.9),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Coverage for smbmap text parser.
    use super::*;

    /// Output with a writable share yields a High finding.
    #[test]
    fn parse_smbmap_output_writable_share() {
        let stdout = "        Disk        Permissions\n\
                      ----        -----------\n\
                      Public      READ, WRITE\n";
        let findings = parse_smbmap_output(stdout, "https://example.com", "example.com");
        let high = findings.iter().find(|f| f.title.contains("WRITE")).expect("write finding");
        assert_eq!(high.severity, Severity::High);
    }

    /// Output with read-only share yields a Medium finding.
    #[test]
    fn parse_smbmap_output_readonly_share() {
        let stdout = "        Disk        Permissions\n\
                      Backups     READ ONLY\n";
        let findings = parse_smbmap_output(stdout, "https://example.com", "example.com");
        let med = findings.iter().find(|f| f.title.contains("READ")).expect("read finding");
        assert_eq!(med.severity, Severity::Medium);
    }

    /// No-access output yields zero findings.
    #[test]
    fn parse_smbmap_output_no_access() {
        let stdout = "Disk        Permissions\n\
                      C$          NO ACCESS\n";
        let findings = parse_smbmap_output(stdout, "https://example.com", "example.com");
        assert!(findings.is_empty());
    }

    /// With SMB credentials configured, argv carries `-u <user> -p <pass>`.
    #[test]
    fn smbmap_argv_with_credentials() {
        let creds = NetworkCredentials {
            smb_username: Some("alice".to_string()),
            smb_password: Some("s3cret".to_string()),
            ..Default::default()
        };
        let argv = build_argv(&creds, "example.com");
        assert_eq!(argv, vec!["-H", "example.com", "-u", "alice", "-p", "s3cret"]);
    }

    /// Without credentials, argv falls back to the anonymous probe.
    #[test]
    fn smbmap_argv_without_credentials() {
        let creds = NetworkCredentials::default();
        let argv = build_argv(&creds, "example.com");
        assert_eq!(argv, vec!["-H", "example.com", "-u", "anonymous", "-p", ""]);
    }
}
