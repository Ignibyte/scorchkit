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
use tracing::debug;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::network_credentials::{format_redacted_argv, NetworkCredentials};
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
        let creds = NetworkCredentials::from_config_with_env(&ctx.config.network_credentials);
        let owned = build_argv(&creds, host, &path);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        debug!("kerbrute: {}", format_redacted_argv(&args));
        let output = subprocess::run_tool("kerbrute", &args, Duration::from_secs(60)).await?;
        Ok(parse_kerbrute_output(&output.stdout, ctx.target.url.as_str(), host))
    }
}

/// Build the kerbrute argv. When a Kerberos principal is configured
/// (`alice@CORP.EXAMPLE`), extract the domain portion and forward via
/// `--domain <DOMAIN>`. Without a principal (or with an unparseable
/// one), fall back to the existing host-based default.
#[must_use]
fn build_argv(creds: &NetworkCredentials, host: &str, user_file: &str) -> Vec<String> {
    let domain = creds
        .kerberos_principal
        .as_deref()
        .and_then(|p| p.split_once('@').map(|(_, d)| d.to_string()))
        .unwrap_or_else(|| host.to_string());
    vec![
        "userenum".to_string(),
        "--dc".to_string(),
        host.to_string(),
        "--domain".to_string(),
        domain,
        user_file.to_string(),
    ]
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

    /// A configured Kerberos principal contributes its domain portion
    /// to kerbrute's `--domain` flag.
    #[test]
    fn kerbrute_argv_with_principal_extracts_domain() {
        let creds = NetworkCredentials {
            kerberos_principal: Some("alice@CORP.EXAMPLE".to_string()),
            ..Default::default()
        };
        let argv = build_argv(&creds, "dc1.corp.example", "/tmp/users.txt");
        assert_eq!(
            argv,
            vec![
                "userenum",
                "--dc",
                "dc1.corp.example",
                "--domain",
                "CORP.EXAMPLE",
                "/tmp/users.txt"
            ]
        );
    }

    /// Without a principal, the domain falls back to the target host.
    #[test]
    fn kerbrute_argv_without_principal_uses_host() {
        let creds = NetworkCredentials::default();
        let argv = build_argv(&creds, "example.com", "/tmp/users.txt");
        assert_eq!(
            argv,
            vec!["userenum", "--dc", "example.com", "--domain", "example.com", "/tmp/users.txt"]
        );
    }

    /// A principal without an `@` (unparseable) falls back to the host.
    #[test]
    fn kerbrute_argv_unparseable_principal_falls_back() {
        let creds = NetworkCredentials {
            kerberos_principal: Some("no-at-sign".to_string()),
            ..Default::default()
        };
        let argv = build_argv(&creds, "example.com", "/tmp/users.txt");
        assert!(argv.contains(&"example.com".to_string()));
    }
}
