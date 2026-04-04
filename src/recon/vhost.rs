//! Virtual host discovery recon module.
//!
//! Discovers hidden virtual hosts by brute-forcing the `Host` header
//! against the target IP. Compares response size and status code against
//! a baseline to identify unique virtual hosts.

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Discovers hidden virtual hosts via Host header brute-force.
#[derive(Debug)]
pub struct VhostModule;

#[async_trait]
impl ScanModule for VhostModule {
    fn name(&self) -> &'static str {
        "Virtual Host Discovery"
    }

    fn id(&self) -> &'static str {
        "vhost"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Discover hidden virtual hosts via Host header brute-force"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        let domain = ctx.target.url.host_str().unwrap_or("");
        if domain.is_empty() {
            return Ok(findings);
        }

        // Get baseline response with a random invalid host
        let baseline = ctx
            .http_client
            .get(url)
            .header("Host", "scorch-invalid-vhost-probe.example.invalid")
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let baseline_status = baseline.status().as_u16();
        let baseline_body = baseline.text().await.unwrap_or_default();
        let baseline_len = baseline_body.len();

        // Test vhost prefixes: custom wordlist or built-in
        let mut discovered = Vec::new();
        let custom_words = ctx
            .config
            .wordlists
            .vhost
            .as_deref()
            .and_then(|p| crate::config::load_wordlist(p).ok());
        let default_words: Vec<String> = VHOST_PREFIXES.iter().map(|&s| String::from(s)).collect();
        let words = custom_words.as_ref().unwrap_or(&default_words);

        for prefix in words {
            let vhost = format!("{prefix}.{domain}");

            let Ok(response) = ctx.http_client.get(url).header("Host", &vhost).send().await else {
                continue;
            };

            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let body_len = body.len();

            // Different status or significantly different body = unique vhost
            // JUSTIFICATION: body lengths are bounded HTTP response sizes; i64 wrap is not possible
            #[allow(clippy::cast_possible_wrap)]
            let size_diff = (body_len as i64 - baseline_len as i64).unsigned_abs();
            let is_different = status != baseline_status
                || (baseline_len > 0 && size_diff > baseline_len as u64 / 4);

            if is_different && status < 500 {
                discovered.push((vhost, status, body_len));
            }
        }

        if !discovered.is_empty() {
            let vhost_list: Vec<String> = discovered
                .iter()
                .map(|(vhost, status, size)| format!("{vhost} (HTTP {status}, {size} bytes)"))
                .collect();

            findings.push(
                Finding::new(
                    "vhost",
                    Severity::Info,
                    format!("{} virtual hosts discovered", discovered.len()),
                    format!(
                        "Found {} unique virtual hosts on the target IP by brute-forcing \
                         the Host header. These may expose internal applications, staging \
                         environments, or admin panels.",
                        discovered.len(),
                    ),
                    url,
                )
                .with_evidence(format!("Vhosts: {}", vhost_list.join(" | ")))
                .with_remediation(
                    "Restrict virtual host access. Ensure internal/staging vhosts are not \
                     accessible from the internet. Use IP allowlists for admin vhosts.",
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(200)
                .with_confidence(0.6),
            );
        }

        Ok(findings)
    }
}

/// Common virtual host prefixes for brute-force discovery.
const VHOST_PREFIXES: &[&str] = &[
    "admin",
    "api",
    "app",
    "backend",
    "beta",
    "blog",
    "cdn",
    "cms",
    "dashboard",
    "dev",
    "development",
    "gateway",
    "git",
    "grafana",
    "internal",
    "intranet",
    "jenkins",
    "jira",
    "mail",
    "monitor",
    "monitoring",
    "new",
    "panel",
    "portal",
    "preview",
    "prod",
    "staging",
    "stage",
    "status",
    "test",
    "testing",
    "vpn",
    "webmail",
    "wiki",
    "www",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the virtual host discovery module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_vhost() {
        let module = VhostModule;
        assert_eq!(module.id(), "vhost");
        assert_eq!(module.category(), ModuleCategory::Recon);
    }

    /// Verify vhost prefix database is non-empty and covers key prefixes.
    #[test]
    fn test_vhost_prefixes_not_empty() {
        assert!(!VHOST_PREFIXES.is_empty());
        assert!(VHOST_PREFIXES.contains(&"admin"));
        assert!(VHOST_PREFIXES.contains(&"api"));
        assert!(VHOST_PREFIXES.contains(&"staging"));
        assert!(VHOST_PREFIXES.contains(&"internal"));
    }
}
