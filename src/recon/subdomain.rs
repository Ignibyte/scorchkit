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

        for prefix in SUBDOMAIN_WORDLIST {
            let subdomain = format!("{prefix}.{domain}");

            // Use tokio's DNS resolution
            match net::lookup_host(format!("{subdomain}:80")).await {
                Ok(addrs) => {
                    let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                    if !ips.is_empty() {
                        // Deduplicate IPs
                        let mut unique_ips = ips;
                        unique_ips.sort();
                        unique_ips.dedup();
                        discovered.push(format!("{subdomain} -> {}", unique_ips.join(", ")));
                    }
                }
                Err(_) => {
                    // NXDOMAIN or resolution failure - subdomain doesn't exist
                }
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
                .with_evidence(format!("Discovered subdomains:\n    {list}")),
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
                            .with_evidence(sub.clone()),
                        );
                        break;
                    }
                }
            }
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
