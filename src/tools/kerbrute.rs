//! `kerbrute` wrapper — Kerberos user enumeration.
//!
//! Wraps [kerbrute](https://github.com/ropnop/kerbrute) for
//! pre-authentication user enumeration against an Active Directory
//! domain controller. Uses a small built-in user list (10 common
//! account names) so the probe runs fast and produces signal without
//! needing operator-supplied wordlists. For deeper enumeration,
//! operators run `kerbrute` directly with their own user lists.

use std::io::Write as _;
use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Built-in user list. Tiny by design — operators with bigger lists
/// invoke kerbrute directly.
const DEFAULT_USERS: &[&str] = &[
    "administrator",
    "admin",
    "guest",
    "krbtgt",
    "service",
    "test",
    "user",
    "backup",
    "operator",
    "support",
];

/// Kerberos user enumerator via kerbrute.
#[derive(Debug)]
pub struct KerbruteModule;

#[async_trait]
impl ScanModule for KerbruteModule {
    fn name(&self) -> &'static str {
        "kerbrute Kerberos User Enumerator"
    }

    fn id(&self) -> &'static str {
        "kerbrute"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Pre-auth Kerberos user enumeration with a small default user list"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("kerbrute")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let host = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());
        // Write the user list to a temp file so kerbrute can read it.
        let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
            return Ok(Vec::new());
        };
        for u in DEFAULT_USERS {
            if writeln!(tmp, "{u}").is_err() {
                return Ok(Vec::new());
            }
        }
        let path = tmp.path().to_string_lossy().to_string();
        // kerbrute userenum --dc <host> --domain <host> <user-file>
        let output = subprocess::run_tool(
            "kerbrute",
            &["userenum", "--dc", host, "--domain", host, &path],
            Duration::from_secs(60),
        )
        .await?;
        Ok(parse_kerbrute_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Parse kerbrute output for `[+] VALID USERNAME:` lines.
#[must_use]
fn parse_kerbrute_output(stdout: &str, target_url: &str, host: &str) -> Vec<Finding> {
    let valid: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.contains("VALID USERNAME") {
                return None;
            }
            // Format: `<timestamp> [+] VALID USERNAME: admin@example.com`
            trimmed.split("VALID USERNAME:").nth(1).map(|s| s.trim().to_string())
        })
        .collect();
    if valid.is_empty() {
        return Vec::new();
    }
    let count = valid.len();
    vec![Finding::new(
        "kerbrute",
        Severity::Medium,
        format!("kerbrute: {count} valid Kerberos user(s) enumerated"),
        format!(
            "kerbrute confirmed {count} valid usernames against the KDC at {host} via \
             Kerberos pre-auth probing. Pre-auth enumeration leaks the existence of \
             accounts and is the first step of an AS-REP roasting attack."
        ),
        target_url,
    )
    .with_evidence(format!("Valid users: {}", valid.join(", ")))
    .with_remediation(
        "Disable account-name disclosure in Kerberos pre-auth responses where possible; \
         monitor and rate-limit AS-REQ floods.",
    )
    .with_owasp("A07:2021 Identification and Authentication Failures")
    .with_cwe(204)
    .with_confidence(0.85)]
}

#[cfg(test)]
mod tests {
    //! Coverage for kerbrute output parser.
    use super::*;

    /// kerbrute output with two `VALID USERNAME` lines yields one
    /// consolidated finding.
    #[test]
    fn parse_kerbrute_output_valid_users() {
        let stdout = "2026/04/15 00:00:00 >  Using KDC(s):\n\
                      2026/04/15 00:00:00 >\tkdc.example.com:88\n\
                      2026/04/15 00:00:00 >  [+] VALID USERNAME:\t admin@example.com\n\
                      2026/04/15 00:00:00 >  [+] VALID USERNAME:\t backup@example.com\n";
        let findings = parse_kerbrute_output(stdout, "https://example.com", "example.com");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("2 valid"));
    }

    /// Empty / non-matching output yields zero findings.
    #[test]
    fn parse_kerbrute_output_empty() {
        assert!(parse_kerbrute_output("", "https://example.com", "example.com").is_empty());
        assert!(parse_kerbrute_output("no users here\n", "https://example.com", "example.com")
            .is_empty());
    }

    /// Built-in user list invariant: at least 10 names, all
    /// non-empty, each on its own line.
    #[test]
    fn default_users_invariant() {
        assert!(DEFAULT_USERS.len() >= 10);
        for u in DEFAULT_USERS {
            assert!(!u.is_empty());
            assert!(!u.contains('\n'));
        }
    }
}
