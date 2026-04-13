//! Prototype pollution scanner module.
//!
//! Detects client-side and server-side prototype pollution by injecting
//! `__proto__` and `constructor.prototype` properties into JSON request
//! bodies and query parameters, then checking if the response reflects
//! or processes the polluted properties.

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects prototype pollution vulnerabilities.
#[derive(Debug)]
pub struct PrototypePollutionModule;

#[async_trait]
impl ScanModule for PrototypePollutionModule {
    fn name(&self) -> &'static str {
        "Prototype Pollution Detection"
    }

    fn id(&self) -> &'static str {
        "prototype_pollution"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect prototype pollution via __proto__ and constructor property injection"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Test JSON body pollution
        test_json_body_pollution(ctx, url, &mut findings).await?;

        // Test query param pollution
        test_query_param_pollution(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// JSON body payloads for prototype pollution testing.
const POLLUTION_JSON_PAYLOADS: &[(&str, &str)] = &[
    (r#"{"__proto__":{"scorch_polluted":"true"}}"#, "__proto__ object injection"),
    (
        r#"{"constructor":{"prototype":{"scorch_polluted":"true"}}}"#,
        "constructor.prototype injection",
    ),
    (r#"{"__proto__":{"toString":"polluted"}}"#, "__proto__ toString override"),
    (r#"{"__proto__":{"isAdmin":true}}"#, "__proto__ privilege escalation"),
];

/// Query parameter payloads for prototype pollution.
const POLLUTION_PARAM_PAYLOADS: &[(&str, &str)] = &[
    ("__proto__[scorch_polluted]=true", "__proto__ bracket notation"),
    ("__proto__.scorch_polluted=true", "__proto__ dot notation"),
    ("constructor[prototype][scorch_polluted]=true", "constructor.prototype bracket"),
];

/// Check if a response body contains evidence of prototype pollution.
///
/// Looks for the `scorch_polluted` canary value in the response.
fn check_pollution_reflected(body: &str) -> bool {
    body.contains("scorch_polluted")
}

/// Test JSON body prototype pollution.
async fn test_json_body_pollution(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Get baseline to ensure canary doesn't naturally appear
    let Ok(baseline) = ctx.http_client.get(url_str).send().await else {
        return Ok(());
    };
    let baseline_body = baseline.text().await.unwrap_or_default();
    if check_pollution_reflected(&baseline_body) {
        return Ok(());
    }

    for &(payload, description) in POLLUTION_JSON_PAYLOADS {
        let Ok(response) = ctx
            .http_client
            .post(url_str)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        else {
            continue;
        };

        let resp_status = response.status();
        let resp_body = response.text().await.unwrap_or_default();

        if check_pollution_reflected(&resp_body) {
            findings.push(
                Finding::new(
                    "prototype_pollution",
                    Severity::Medium,
                    format!("Prototype Pollution: {description}"),
                    format!(
                        "The server reflected a prototype pollution canary in the response \
                         after injecting {description}. This indicates the application \
                         may be vulnerable to prototype pollution, which can lead to \
                         property injection, denial of service, or privilege escalation.",
                    ),
                    url_str,
                )
                .with_evidence(format!("Payload: {payload} | Canary: scorch_polluted reflected"))
                .with_remediation(
                    "Freeze Object.prototype or use Object.create(null) for config objects. \
                     Sanitize user input to reject __proto__ and constructor keys. Use \
                     schema validation on all JSON input.",
                )
                .with_owasp("A08:2021 Software and Data Integrity")
                .with_cwe(1321)
                .with_confidence(0.5),
            );
            return Ok(());
        }

        // Check for server error (may indicate pollution affecting internals)
        if resp_status.as_u16() == 500 {
            findings.push(
                Finding::new(
                    "prototype_pollution",
                    Severity::Low,
                    format!("Potential Prototype Pollution: server error on {description}"),
                    format!(
                        "The server returned a 500 error when a prototype pollution payload \
                         ({description}) was submitted. This may indicate the __proto__ \
                         property is being processed and causing unexpected behavior.",
                    ),
                    url_str,
                )
                .with_evidence(format!("Payload: {payload} | Status: 500"))
                .with_remediation(
                    "Reject __proto__ and constructor keys in JSON input. Use schema validation.",
                )
                .with_owasp("A08:2021 Software and Data Integrity")
                .with_cwe(1321)
                .with_confidence(0.5),
            );
        }
    }

    Ok(())
}

/// Test query parameter prototype pollution.
async fn test_query_param_pollution(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for &(payload, description) in POLLUTION_PARAM_PAYLOADS {
        let test_url =
            format!("{}{}{}", url_str, if url_str.contains('?') { "&" } else { "?" }, payload);

        let Ok(response) = ctx.http_client.get(&test_url).send().await else {
            continue;
        };

        let resp_body = response.text().await.unwrap_or_default();

        if check_pollution_reflected(&resp_body) {
            findings.push(
                Finding::new(
                    "prototype_pollution",
                    Severity::Medium,
                    format!("Prototype Pollution via query parameter: {description}"),
                    format!(
                        "The canary value was reflected when injecting prototype pollution \
                         via query parameters ({description}). The application's query \
                         string parser may merge __proto__ properties into objects.",
                    ),
                    url_str,
                )
                .with_evidence(format!("Payload: {payload} | Canary reflected in response"))
                .with_remediation(
                    "Use a query parser that ignores __proto__ keys (e.g., qs with \
                     allowPrototypes: false). Validate and sanitize all query parameters.",
                )
                .with_owasp("A08:2021 Software and Data Integrity")
                .with_cwe(1321)
                .with_confidence(0.5),
            );
            return Ok(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the prototype pollution scanner module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_prototype_pollution() {
        let module = PrototypePollutionModule;
        assert_eq!(module.id(), "prototype_pollution");
        assert_eq!(module.name(), "Prototype Pollution Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
    }

    /// Verify payload databases are non-empty.
    #[test]
    fn test_pollution_payloads_not_empty() {
        assert!(!POLLUTION_JSON_PAYLOADS.is_empty());
        assert!(!POLLUTION_PARAM_PAYLOADS.is_empty());

        for (i, &(p, d)) in POLLUTION_JSON_PAYLOADS.iter().enumerate() {
            assert!(!p.is_empty(), "JSON payload {i} empty");
            assert!(!d.is_empty(), "JSON description {i} empty");
        }
        for (i, &(p, d)) in POLLUTION_PARAM_PAYLOADS.iter().enumerate() {
            assert!(!p.is_empty(), "param payload {i} empty");
            assert!(!d.is_empty(), "param description {i} empty");
        }
    }

    /// Verify canary detection.
    #[test]
    fn test_check_pollution_reflected() {
        assert!(check_pollution_reflected(r#"{"scorch_polluted":"true","name":"test"}"#));
        assert!(!check_pollution_reflected("<html><body>Normal page</body></html>"));
    }

    /// Verify payloads contain `__proto__` or constructor patterns.
    #[test]
    fn test_pollution_payload_patterns() {
        let all_payloads: Vec<&str> = POLLUTION_JSON_PAYLOADS
            .iter()
            .map(|&(p, _)| p)
            .chain(POLLUTION_PARAM_PAYLOADS.iter().map(|&(p, _)| p))
            .collect();

        assert!(
            all_payloads.iter().any(|p| p.contains("__proto__")),
            "must include __proto__ payloads"
        );
        assert!(
            all_payloads.iter().any(|p| p.contains("constructor")),
            "must include constructor payloads"
        );
    }
}
