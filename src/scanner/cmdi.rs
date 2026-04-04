use async_trait::async_trait;
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects OS command injection vulnerabilities.
#[derive(Debug)]
pub struct CmdiModule;

#[async_trait]
impl ScanModule for CmdiModule {
    fn name(&self) -> &'static str {
        "Command Injection Detection"
    }
    fn id(&self) -> &'static str {
        "cmdi"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect OS command injection via parameter fuzzing"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        test_url_params(ctx, url, &mut findings).await?;
        Ok(findings)
    }
}

async fn test_url_params(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let Ok(parsed) = Url::parse(url_str) else {
        return Ok(());
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    if params.is_empty() {
        return Ok(());
    }

    // Get baseline
    let baseline = ctx
        .http_client
        .get(url_str)
        .send()
        .await
        .map_err(|e| ScorchError::Http { url: url_str.to_string(), source: e })?;
    let baseline_body = baseline.text().await.unwrap_or_default();

    for (param_name, param_value) in &params {
        for &(payload, marker) in CMDI_PAYLOADS {
            let injected = format!("{param_value}{payload}");

            let mut test_url = parsed.clone();
            {
                let mut q = test_url.query_pairs_mut();
                q.clear();
                for (k, v) in &params {
                    if k == param_name {
                        q.append_pair(k, &injected);
                    } else {
                        q.append_pair(k, v);
                    }
                }
            }

            let Ok(response) = ctx.http_client.get(test_url.as_str()).send().await else {
                continue;
            };

            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Check for command output markers
            if body.contains(marker) && !baseline_body.contains(marker) {
                findings.push(
                    Finding::new("cmdi", Severity::Critical, format!("Command Injection in Parameter: {param_name}"), format!("The parameter '{param_name}' is vulnerable to OS command injection. The command output marker '{marker}' was found in the response."), url_str)
                        .with_evidence(format!("Parameter: {param_name} | Payload: {payload} | Marker: {marker}"))
                        .with_remediation("Never pass user input to shell commands. Use parameterized APIs instead of system()/exec().")
                        .with_owasp("A03:2021 Injection")
                        .with_cwe(78)
                        .with_confidence(0.8),
                );
                return Ok(());
            }

            // 500 error from injection is suspicious
            if status.as_u16() == 500 {
                findings.push(
                    Finding::new("cmdi", Severity::High, format!("Possible Command Injection: {param_name}"), format!("Injecting OS command metacharacters into '{param_name}' caused a 500 error."), url_str)
                        .with_evidence(format!("Parameter: {param_name} | Payload: {payload} | HTTP 500"))
                        .with_remediation("Investigate whether this parameter reaches a shell command.")
                        .with_owasp("A03:2021 Injection")
                        .with_cwe(78)
                        .with_confidence(0.8),
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Command injection payloads and their expected output markers.
const CMDI_PAYLOADS: &[(&str, &str)] = &[
    ("; echo scorchkit_cmdi_test", "scorchkit_cmdi_test"),
    ("| echo scorchkit_cmdi_test", "scorchkit_cmdi_test"),
    ("`echo scorchkit_cmdi_test`", "scorchkit_cmdi_test"),
    ("$(echo scorchkit_cmdi_test)", "scorchkit_cmdi_test"),
    ("; cat /etc/hostname", ""), // no marker - just check for 500
    ("| id", "uid="),
    ("; id", "uid="),
    ("$(id)", "uid="),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the command injection module's payload constant data integrity.

    /// Verify that `CMDI_PAYLOADS` is non-empty and contains a reasonable number of payloads.
    #[test]
    fn test_cmdi_payloads_nonempty() {
        assert!(
            CMDI_PAYLOADS.len() >= 4,
            "Expected at least 4 command injection payloads, found {}",
            CMDI_PAYLOADS.len()
        );
    }

    /// Verify that each payload has a non-empty payload string and that payloads with
    /// markers have non-empty marker strings.
    #[test]
    fn test_cmdi_payloads_structure() {
        for (i, &(payload, marker)) in CMDI_PAYLOADS.iter().enumerate() {
            assert!(!payload.is_empty(), "Payload at index {i} has an empty payload string");
            // Marker can be empty (e.g., "cat /etc/hostname" relies on 500 detection),
            // but if non-empty it should be a reasonable string
            if !marker.is_empty() {
                assert!(marker.len() >= 3, "Marker at index {i} is suspiciously short: '{marker}'");
            }
        }
    }

    /// Verify that payload strings contain shell metacharacters (`;`, `|`, `` ` ``, `$(`),
    /// confirming they are well-formed injection patterns.
    #[test]
    fn test_cmdi_payloads_contain_shell_metacharacters() {
        let metacharacters = [';', '|', '`', '$'];

        for &(payload, _) in CMDI_PAYLOADS {
            let has_meta = metacharacters.iter().any(|&c| payload.contains(c));
            assert!(has_meta, "Payload '{payload}' does not contain any shell metacharacter");
        }
    }
}
