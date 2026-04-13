use async_trait::async_trait;
use tokio::net;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Enumerates subdomains of the target domain.
#[derive(Debug)]
pub struct SubdomainModule;

#[async_trait]
impl ScanModule for SubdomainModule {
    fn name(&self) -> &'static str {
        "Subdomain Enumeration"
    }

    fn id(&self) -> &'static str {
        "subdomain"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Enumerate subdomains via DNS brute-force with common wordlist"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let domain = ctx.target.domain.as_deref().ok_or_else(|| ScorchError::InvalidTarget {
            target: ctx.target.raw.clone(),
            reason: "no domain for subdomain enumeration".to_string(),
        })?;

        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();
        let mut discovered: Vec<String> = Vec::new();

        // Use custom wordlist from config, or fall back to built-in
        let custom_words = ctx
            .config
            .wordlists
            .subdomain
            .as_deref()
            .and_then(|p| crate::config::load_wordlist(p).ok());
        let default_words: Vec<String> =
            SUBDOMAIN_WORDLIST.iter().map(|&s| String::from(s)).collect();
        let words = custom_words.as_ref().unwrap_or(&default_words);

        for prefix in words {
            let subdomain = format!("{prefix}.{domain}");

            // Use tokio's DNS resolution
            if let Ok(addrs) = net::lookup_host(format!("{subdomain}:80")).await {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                if !ips.is_empty() {
                    // Deduplicate IPs
                    let mut unique_ips = ips;
                    unique_ips.sort();
                    unique_ips.dedup();
                    discovered.push(format!("{subdomain} -> {}", unique_ips.join(", ")));
                }
            } else {
                // NXDOMAIN or resolution failure - subdomain doesn't exist
            }
        }

        if !discovered.is_empty() {
            let count = discovered.len();
            let list = discovered.join("\n    ");

            findings.push(
                Finding::new(
                    "subdomain",
                    Severity::Info,
                    format!("{count} Subdomains Discovered"),
                    format!(
                        "Subdomain enumeration found {count} active subdomain(s) for {domain}."
                    ),
                    url,
                )
                .with_evidence(format!("Discovered subdomains:\n    {list}"))
                .with_confidence(0.8),
            );

            // Check for potentially interesting subdomains
            for sub in &discovered {
                let sub_lower = sub.to_lowercase();
                for &(pattern, desc, severity) in INTERESTING_SUBDOMAINS {
                    if sub_lower.starts_with(pattern)
                        || sub_lower.starts_with(&format!("{pattern}."))
                    {
                        findings.push(
                            Finding::new(
                                "subdomain",
                                severity,
                                format!(
                                    "Interesting Subdomain: {}",
                                    sub.split(" ->").next().unwrap_or(sub)
                                ),
                                format!("{desc}: {sub}"),
                                url,
                            )
                            .with_evidence(sub.clone())
                            .with_confidence(0.8),
                        );
                        break;
                    }
                }
            }
        }

        // Publish discovered subdomains for downstream modules
        if !discovered.is_empty() {
            let subdomain_names: Vec<String> =
                discovered.iter().filter_map(|s| s.split(" ->").next().map(String::from)).collect();
            ctx.shared_data.publish(crate::engine::shared_data::keys::SUBDOMAINS, subdomain_names);
        }

        Ok(findings)
    }
}

const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "m",
    "shop",
    "ftp",
    "mail2",
    "test",
    "portal",
    "ns",
    "host",
    "support",
    "dev",
    "web",
    "mx",
    "email",
    "cloud",
    "admin",
    "api",
    "stage",
    "staging",
    "app",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "jira",
    "confluence",
    "wiki",
    "docs",
    "status",
    "monitor",
    "grafana",
    "kibana",
    "db",
    "cdn",
    "media",
    "static",
    "assets",
    "images",
    "internal",
    "intranet",
    "corp",
    "uat",
    "qa",
    "sandbox",
    "demo",
    "beta",
    "old",
    "legacy",
    "backup",
    "sso",
    "auth",
    "login",
    "id",
    "oauth",
];

const INTERESTING_SUBDOMAINS: &[(&str, &str, Severity)] = &[
    ("admin", "Administrative panel subdomain", Severity::Medium),
    ("staging", "Staging environment exposed", Severity::Medium),
    ("stage", "Staging environment exposed", Severity::Medium),
    ("dev", "Development environment exposed", Severity::Medium),
    ("test", "Test environment exposed", Severity::Medium),
    ("uat", "UAT environment exposed", Severity::Medium),
    ("internal", "Internal subdomain publicly resolvable", Severity::High),
    ("intranet", "Intranet subdomain publicly resolvable", Severity::High),
    ("jenkins", "CI/CD tool subdomain found", Severity::Medium),
    ("gitlab", "Source code platform subdomain", Severity::Medium),
    ("git", "Git server subdomain", Severity::Medium),
    ("jira", "Project management tool exposed", Severity::Low),
    ("grafana", "Monitoring dashboard exposed", Severity::Medium),
    ("kibana", "Log analysis dashboard exposed", Severity::Medium),
    ("db", "Database subdomain found", Severity::High),
    ("backup", "Backup system subdomain", Severity::Medium),
    ("vpn", "VPN endpoint found", Severity::Info),
    ("sso", "SSO endpoint found", Severity::Info),
];

#[cfg(test)]
mod tests {
    /// Unit tests for subdomain enumeration constant data integrity.
    use super::*;

    /// Verify the subdomain wordlist is non-empty.
    #[test]
    fn test_subdomain_wordlist_nonempty() {
        // Assert
        assert!(!SUBDOMAIN_WORDLIST.is_empty(), "SUBDOMAIN_WORDLIST must contain entries");
    }

    /// Verify every interesting subdomain entry has a non-empty description and a valid severity.
    #[test]
    fn test_interesting_subdomains_valid() {
        // Assert
        assert!(!INTERESTING_SUBDOMAINS.is_empty(), "INTERESTING_SUBDOMAINS must contain entries");

        for (i, &(pattern, desc, _severity)) in INTERESTING_SUBDOMAINS.iter().enumerate() {
            assert!(!pattern.is_empty(), "INTERESTING_SUBDOMAINS[{i}] pattern must not be empty");
            assert!(!desc.is_empty(), "INTERESTING_SUBDOMAINS[{i}] description must not be empty");
        }
    }

    /// Verify all wordlist entries are valid DNS hostname prefixes (lowercase alphanumeric and hyphens).
    #[test]
    fn test_wordlist_entries_valid_hostname_prefixes() {
        for (i, &prefix) in SUBDOMAIN_WORDLIST.iter().enumerate() {
            assert!(!prefix.is_empty(), "SUBDOMAIN_WORDLIST[{i}] must not be empty");
            assert!(
                prefix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "SUBDOMAIN_WORDLIST[{i}] = '{}' contains invalid hostname characters",
                prefix
            );
            assert!(
                !prefix.starts_with('-') && !prefix.ends_with('-'),
                "SUBDOMAIN_WORDLIST[{i}] = '{}' must not start or end with a hyphen",
                prefix
            );
        }
    }
}
