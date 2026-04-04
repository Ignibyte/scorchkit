//! `enum4linux` wrapper for SMB and network service enumeration.
//!
//! Wraps the `enum4linux` tool for Windows/Samba host enumeration:
//! share listing, user enumeration via RID cycling, group membership,
//! and password policy extraction.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// SMB and network service enumeration via enum4linux.
#[derive(Debug)]
pub struct Enum4linuxModule;

#[async_trait]
impl ScanModule for Enum4linuxModule {
    fn name(&self) -> &'static str {
        "enum4linux SMB Enumerator"
    }

    fn id(&self) -> &'static str {
        "enum4linux"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "SMB share, user, group, and password policy enumeration via enum4linux"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("enum4linux")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let output =
            subprocess::run_tool("enum4linux", &["-a", target], Duration::from_secs(300)).await?;

        Ok(parse_enum4linux_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse enum4linux text output into findings.
///
/// enum4linux produces sections delimited by headers like
/// `====( Share Enumeration on ... )====`. Each section with
/// results produces a finding.
#[must_use]
fn parse_enum4linux_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Extract shares
    let shares = extract_section_items(stdout, "Sharename", "Type");
    if !shares.is_empty() {
        findings.push(
            Finding::new(
                "enum4linux",
                Severity::Medium,
                format!("SMB: {} Shares Enumerated", shares.len()),
                format!("enum4linux enumerated {} SMB shares: {}", shares.len(), shares.join(", ")),
                target_url,
            )
            .with_evidence(format!("{} shares found", shares.len()))
            .with_remediation("Restrict anonymous access to SMB shares. Disable null sessions.")
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }

    // Extract users via RID cycling
    let users = extract_rid_users(stdout);
    if !users.is_empty() {
        findings.push(
            Finding::new(
                "enum4linux",
                Severity::Medium,
                format!("SMB: {} Users Enumerated via RID Cycling", users.len()),
                format!(
                    "enum4linux enumerated {} users via RID cycling: {}",
                    users.len(),
                    users.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
                ),
                target_url,
            )
            .with_evidence(format!("{} users enumerated", users.len()))
            .with_remediation("Disable anonymous RID cycling. Restrict SMB access.")
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }

    // Check for weak password policy
    if let Some(policy) = extract_password_policy(stdout) {
        findings.push(
            Finding::new(
                "enum4linux",
                Severity::Medium,
                "SMB: Password Policy Retrieved".to_string(),
                format!("enum4linux retrieved the domain password policy: {policy}"),
                target_url,
            )
            .with_evidence(policy)
            .with_remediation(
                "Ensure minimum password length >= 12, complexity enabled, \
                 account lockout after 5 attempts.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(521)
            .with_confidence(0.7),
        );
    }

    findings
}

/// Extract share names from the share enumeration table.
fn extract_section_items(stdout: &str, col1: &str, col2: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut in_section = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains(col1) && trimmed.contains(col2) {
            in_section = true;
            continue;
        }
        if in_section {
            if trimmed.is_empty() || trimmed.starts_with("----") {
                if !items.is_empty() {
                    break;
                }
                continue;
            }
            if let Some(name) = trimmed.split_whitespace().next() {
                if !name.is_empty() && name != "----" {
                    items.push(name.to_string());
                }
            }
        }
    }

    items
}

/// Extract usernames from RID cycling output.
fn extract_rid_users(stdout: &str) -> Vec<String> {
    let mut users = Vec::new();

    for line in stdout.lines() {
        // Pattern: "S-1-5-21-...-1000 DOMAIN\username (Local User)"
        if line.contains("Local User") || line.contains("Domain User") {
            if let Some(user_part) = line.split('\\').nth(1) {
                if let Some(username) = user_part.split_whitespace().next() {
                    users.push(username.to_string());
                }
            }
        }
    }

    users
}

/// Extract password policy summary from output.
fn extract_password_policy(stdout: &str) -> Option<String> {
    let mut policy_lines = Vec::new();
    let mut in_policy = false;

    for line in stdout.lines() {
        if line.contains("Password Info") || line.contains("password policy") {
            in_policy = true;
            continue;
        }
        if in_policy {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("====") {
                if !policy_lines.is_empty() {
                    break;
                }
                continue;
            }
            policy_lines.push(trimmed.to_string());
        }
    }

    if policy_lines.is_empty() {
        None
    } else {
        Some(policy_lines.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify enum4linux output parsing with shares, users, and policy.
    #[test]
    fn test_parse_enum4linux_output() {
        let output = r#"
 ====( Share Enumeration on 10.0.0.1 )====

	Sharename       Type      Comment
	---------       ----      -------
	IPC$            IPC       IPC Service
	print$          Disk      Printer Drivers
	public          Disk      Public Share

 ====( Users on 10.0.0.1 via RID cycling )====

S-1-5-21-1234-5678-9012-500 WORKGROUP\Administrator (Local User)
S-1-5-21-1234-5678-9012-1000 WORKGROUP\jsmith (Local User)

 ====( Password Info for 10.0.0.1 )====

Minimum password length: 7
Password Complexity: Disabled
Account Lockout Threshold: None
"#;

        let findings = parse_enum4linux_output(output, "https://10.0.0.1");
        assert_eq!(findings.len(), 3);
        assert!(findings[0].title.contains("3 Shares"));
        assert!(findings[1].title.contains("2 Users"));
        assert!(findings[2].title.contains("Password Policy"));
    }

    /// Verify empty output produces no findings.
    #[test]
    fn test_parse_enum4linux_empty() {
        let findings = parse_enum4linux_output("", "https://10.0.0.1");
        assert!(findings.is_empty());

        let findings = parse_enum4linux_output("\n\n", "https://10.0.0.1");
        assert!(findings.is_empty());
    }
}
