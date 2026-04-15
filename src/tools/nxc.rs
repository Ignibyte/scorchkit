//! `nxc` wrapper — `NetExec` (formerly `CrackMapExec`).
//!
//! Wraps [nxc](https://github.com/Pennyw0rth/NetExec) — the standard
//! pentest tool for SMB / AD assessment. v1 scope: SMB protocol auth
//! check (anonymous + guest fallbacks). Future passes can add the
//! `WinRM` / MSSQL / RDP / SSH protocol modes nxc supports.

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

/// SMB / AD assessment via nxc (`NetExec`).
#[derive(Debug)]
pub struct NxcModule;

#[async_trait]
impl ScanModule for NxcModule {
    fn name(&self) -> &'static str {
        "nxc (NetExec) SMB Probe"
    }

    fn id(&self) -> &'static str {
        "nxc"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "SMB host info + null-session check via NetExec (formerly crackmapexec)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nxc")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        let creds = NetworkCredentials::from_config_with_env(&ctx.config.network_credentials);
        let owned = build_argv(&creds, host);
        // Borrow into &[&str] for subprocess::run_tool + argv logging.
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        debug!("nxc: {}", format_redacted_argv(&args));
        let output = subprocess::run_tool("nxc", &args, Duration::from_secs(60)).await?;
        Ok(parse_nxc_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Build the nxc argv. With SMB credentials present, forwards them via
/// `-u USER -p PASS`. Without credentials, preserves the existing
/// null-session probe (`-u "" -p ""`).
#[must_use]
fn build_argv(creds: &NetworkCredentials, host: &str) -> Vec<String> {
    let user = creds.smb_username.as_deref().unwrap_or("");
    let password = creds.smb_password.as_deref().unwrap_or("");
    vec![
        "smb".to_string(),
        host.to_string(),
        "-u".to_string(),
        user.to_string(),
        "-p".to_string(),
        password.to_string(),
        "--no-progress".to_string(),
    ]
}

/// Parse nxc text output into findings.
///
/// nxc lines look like:
/// `SMB         host    445   HOSTNAME         [+] domain\\user (Pwn3d!)`
/// or `[+] DOMAIN\\` for null-session success. We surface a Medium
/// finding when nxc reports successful auth (`[+]`) for the
/// anonymous user, and an Info finding listing the discovered host
/// info regardless.
#[must_use]
fn parse_nxc_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let null_session = stdout.lines().any(|line| {
        line.contains("[+]") && (line.contains("\\:") || line.contains("Authentication"))
    });
    if null_session {
        findings.push(
            Finding::new(
                "nxc",
                Severity::Medium,
                "SMB Null Session Permitted",
                format!(
                    "nxc successfully authenticated to SMB on {host} with empty \
                     credentials. Anonymous (null) sessions can enumerate users, \
                     groups, and shares."
                ),
                target_url,
            )
            .with_evidence(format!("nxc reported `[+]` (success) for null session on {host}"))
            .with_remediation(
                "Disable null sessions: set `RestrictAnonymous = 2` (or equivalent) \
                 on the SMB server.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(521)
            .with_confidence(0.85),
        );
    }
    // Always surface the SMB host-info banner if present so operators see what nxc found.
    if stdout.lines().any(|l| l.starts_with("SMB")) {
        let snippet: String =
            stdout.lines().filter(|l| l.starts_with("SMB")).take(3).collect::<Vec<_>>().join(" | ");
        findings.push(
            Finding::new(
                "nxc",
                Severity::Info,
                format!("nxc: SMB host info for {host}"),
                "nxc enumerated SMB host information (OS, hostname, domain).".to_string(),
                target_url,
            )
            .with_evidence(snippet)
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_confidence(0.85),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    //! Coverage for nxc text parser.
    use super::*;

    /// nxc output with `[+]` success line yields a Medium null-session
    /// finding plus the Info SMB-banner finding.
    #[test]
    fn parse_nxc_output_null_session_success() {
        let stdout = "SMB         1.2.3.4    445   HOSTNAME         [*] Windows Server 2019\n\
                      SMB         1.2.3.4    445   HOSTNAME         [+] DOMAIN\\: (Pwn3d!)\n";
        let findings = parse_nxc_output(stdout, "https://example.com", "example.com");
        assert!(findings.iter().any(|f| f.title.contains("Null Session")));
        assert!(findings.iter().any(|f| f.title.contains("host info")));
    }

    /// nxc with only banner lines yields just the Info finding.
    #[test]
    fn parse_nxc_output_banner_only() {
        let stdout = "SMB         1.2.3.4    445   HOSTNAME         [*] Windows 10\n";
        let findings = parse_nxc_output(stdout, "https://example.com", "example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// Empty output yields zero findings.
    #[test]
    fn parse_nxc_output_empty() {
        assert!(parse_nxc_output("", "https://example.com", "example.com").is_empty());
    }

    /// With credentials configured, argv carries `-u alice -p s3cret`.
    #[test]
    fn nxc_argv_with_credentials() {
        let creds = NetworkCredentials {
            smb_username: Some("alice".to_string()),
            smb_password: Some("s3cret".to_string()),
            ..Default::default()
        };
        let argv = build_argv(&creds, "example.com");
        assert_eq!(
            argv,
            vec!["smb", "example.com", "-u", "alice", "-p", "s3cret", "--no-progress"]
        );
    }

    /// Without credentials, argv preserves the null-session behaviour.
    #[test]
    fn nxc_argv_without_credentials() {
        let creds = NetworkCredentials::default();
        let argv = build_argv(&creds, "example.com");
        assert_eq!(argv, vec!["smb", "example.com", "-u", "", "-p", "", "--no-progress"]);
    }
}
