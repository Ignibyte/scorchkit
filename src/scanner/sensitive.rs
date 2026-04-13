use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Scans responses for exposed secrets, API keys, and sensitive data patterns.
#[derive(Debug)]
pub struct SensitiveDataModule;

#[async_trait]
impl ScanModule for SensitiveDataModule {
    fn name(&self) -> &'static str {
        "Sensitive Data Exposure"
    }
    fn id(&self) -> &'static str {
        "sensitive"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect exposed API keys, secrets, and PII in responses"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;
        let body = response.text().await.unwrap_or_default();

        // Check for secrets in response body
        check_secrets(&body, url, &mut findings);

        // Check for source maps
        check_source_maps(ctx, url, &body, &mut findings).await?;

        Ok(findings)
    }
}

fn check_secrets(body: &str, url: &str, findings: &mut Vec<Finding>) {
    for &(pattern, name, severity) in SECRET_PATTERNS {
        // Simple substring check for non-regex patterns
        if body.contains(pattern) {
            // Extract a snippet around the match
            let lower = body.to_lowercase();
            let pattern_lower = pattern.to_lowercase();
            if let Some(pos) = lower.find(&pattern_lower) {
                let start = pos.saturating_sub(10);
                let end = (pos + pattern.len() + 40).min(body.len());
                let snippet: String = body[start..end]
                    .chars()
                    .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                    .collect();

                // Avoid false positives from placeholder/example values
                let context = body[pos..].chars().take(80).collect::<String>().to_lowercase();
                if context.contains("example")
                    || context.contains("placeholder")
                    || context.contains("xxx")
                    || context.contains("your_")
                    || context.contains("insert")
                    || context.contains("todo")
                {
                    continue;
                }

                findings.push(
                    Finding::new("sensitive", severity, format!("Exposed {name}"), format!("{name} pattern found in response body. This may expose credentials or API access."), url)
                        .with_evidence(format!("...{snippet}..."))
                        .with_remediation(format!("Remove {name} from client-facing responses. Use environment variables server-side."))
                        .with_owasp("A02:2021 Cryptographic Failures")
                        .with_cwe(200)
                        .with_confidence(0.7),
                );
            }
        }
    }

    // Check for common API key patterns using simple heuristics
    let api_key_indicators = [
        ("api_key", "API Key"),
        ("apikey", "API Key"),
        ("api-key", "API Key"),
        ("secret_key", "Secret Key"),
        ("private_key", "Private Key"),
        ("access_token", "Access Token"),
        ("client_secret", "Client Secret"),
    ];

    for (indicator, name) in &api_key_indicators {
        // Look for "api_key": "actual_value" or api_key=actual_value patterns
        let patterns_to_check =
            [format!("\"{indicator}\""), format!("{indicator}="), format!("{indicator}:")];

        for p in &patterns_to_check {
            if let Some(pos) = body.to_lowercase().find(&p.to_lowercase()) {
                let after = &body[pos + p.len()..];
                let value_chars: String = after
                    .chars()
                    .skip_while(|c| *c == '"' || *c == '\'' || *c == ' ' || *c == ':')
                    .take_while(|c| {
                        c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.'
                    })
                    .collect();

                // Only flag if the value looks like a real key (long enough, not a placeholder)
                if value_chars.len() > 15 {
                    let lower_val = value_chars.to_lowercase();
                    if !lower_val.contains("example")
                        && !lower_val.contains("xxx")
                        && !lower_val.starts_with("your")
                    {
                        findings.push(
                            Finding::new("sensitive", Severity::High, format!("Possible {name} in Response"), format!("A pattern matching {name} was found with a value that appears to be a real credential."), url)
                                .with_evidence(format!("{p}{}", &value_chars[..value_chars.len().min(20)]))
                                .with_remediation("Remove credentials from client-facing responses.")
                                .with_owasp("A02:2021 Cryptographic Failures")
                                .with_cwe(200)
                                .with_confidence(0.7),
                        );
                        break; // One per indicator type
                    }
                }
            }
        }
    }
}

async fn check_source_maps(
    ctx: &ScanContext,
    url: &str,
    body: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Check for sourceMappingURL in JS files or inline
    if body.contains("sourceMappingURL=") {
        findings.push(
            Finding::new("sensitive", Severity::Low, "Source Map Reference Found", "The response contains a sourceMappingURL reference. Source maps expose original source code.", url)
                .with_remediation("Remove source maps from production builds")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(540)
                .with_confidence(0.7),
        );
    }

    // Check for common source map paths
    let base = ctx.target.base_url();
    for path in &["/main.js.map", "/app.js.map", "/bundle.js.map"] {
        let map_url = format!("{base}{path}");
        if let Ok(resp) = ctx.http_client.get(&map_url).send().await {
            if resp.status().is_success() {
                let map_body = resp.text().await.unwrap_or_default();
                if map_body.contains("\"sources\"") && map_body.contains("\"mappings\"") {
                    findings.push(
                        Finding::new("sensitive", Severity::Medium, format!("Source Map Exposed: {path}"), "A JavaScript source map is publicly accessible, exposing original source code.", &map_url)
                            .with_evidence(format!("HTTP 200 at {map_url}"))
                            .with_remediation("Remove .map files from production or restrict access")
                            .with_owasp("A05:2021 Security Misconfiguration")
                            .with_cwe(540)
                            .with_confidence(0.7),
                    );
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Secret patterns: (pattern, name, severity).
const SECRET_PATTERNS: &[(&str, &str, Severity)] = &[
    ("AKIA", "AWS Access Key ID", Severity::Critical),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", Severity::Critical),
    ("-----BEGIN PRIVATE KEY-----", "Private Key", Severity::Critical),
    ("-----BEGIN EC PRIVATE KEY-----", "EC Private Key", Severity::Critical),
    ("sk_live_", "Stripe Secret Key", Severity::Critical),
    ("sk_test_", "Stripe Test Key", Severity::Medium),
    ("ghp_", "GitHub Personal Access Token", Severity::High),
    ("gho_", "GitHub OAuth Token", Severity::High),
    ("glpat-", "GitLab Personal Access Token", Severity::High),
    ("xoxb-", "Slack Bot Token", Severity::High),
    ("xoxp-", "Slack User Token", Severity::High),
    ("SG.", "SendGrid API Key", Severity::High),
    ("sq0csp-", "Square Access Token", Severity::High),
    ("AIza", "Google API Key", Severity::Medium),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "Hardcoded JWT", Severity::Medium),
    ("password", "Password Reference", Severity::Info),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the sensitive data exposure module's secret detection logic.

    /// Verify that `check_secrets` detects an AWS access key pattern in the response body.
    #[test]
    fn test_check_secrets_aws_key() {
        // Use a realistic-looking key without false-positive trigger words like "example"
        let body = r#"config = { "aws_access_key": "AKIAIOSFODNN7REALKEYZ" }"#;
        let mut findings = Vec::new();

        check_secrets(body, "https://target.com", &mut findings);

        assert!(
            findings.iter().any(|f| f.title.contains("AWS")),
            "Should detect AWS Access Key ID pattern (AKIA)"
        );
    }

    /// Verify that `check_secrets` detects GitHub personal access token patterns.
    #[test]
    fn test_check_secrets_github_token() {
        let body = r#"{"token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"}"#;
        let mut findings = Vec::new();

        check_secrets(body, "https://example.com", &mut findings);

        assert!(
            findings.iter().any(|f| f.title.contains("GitHub")),
            "Should detect GitHub Personal Access Token pattern (ghp_)"
        );
    }

    /// Verify that `check_secrets` produces no findings for a clean body with
    /// no secret patterns.
    #[test]
    fn test_check_secrets_no_secrets() {
        let body =
            "<html><body><h1>Welcome to our site!</h1><p>Nothing to see here.</p></body></html>";
        let mut findings = Vec::new();

        check_secrets(body, "https://example.com", &mut findings);

        assert!(
            findings.is_empty(),
            "Should produce no findings for clean body, found: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    /// Verify that `check_secrets` detects multiple distinct secret patterns when
    /// the body contains more than one type of exposed credential.
    #[test]
    fn test_check_secrets_multiple() {
        let body = r#"
            keys:
              stripe: "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ123"
              slack: "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        "#;
        let mut findings = Vec::new();

        check_secrets(body, "https://example.com", &mut findings);

        assert!(
            findings.len() >= 2,
            "Should detect at least 2 different secret patterns, found {}",
            findings.len()
        );
        assert!(
            findings.iter().any(|f| f.title.contains("Stripe")),
            "Should detect Stripe secret key"
        );
        assert!(
            findings.iter().any(|f| f.title.contains("Slack")),
            "Should detect Slack bot token"
        );
    }
}
