use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects XML External Entity (XXE) injection vulnerabilities.
#[derive(Debug)]
pub struct XxeModule;

#[async_trait]
impl ScanModule for XxeModule {
    fn name(&self) -> &'static str {
        "XXE Detection"
    }
    fn id(&self) -> &'static str {
        "xxe"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect XML External Entity injection on XML-accepting endpoints"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let base = ctx.target.base_url();
        let mut findings = Vec::new();

        // Test common XML endpoints
        let xml_endpoints = [
            url.to_string(),
            format!("{base}/api"),
            format!("{base}/api/v1"),
            format!("{base}/xmlrpc.php"),
            format!("{base}/soap"),
            format!("{base}/wsdl"),
            format!("{base}/upload"),
        ];

        for endpoint in &xml_endpoints {
            test_xxe(ctx, endpoint, &mut findings).await?;
            if !findings.is_empty() {
                break;
            } // One confirmed XXE is enough
        }

        Ok(findings)
    }
}

async fn test_xxe(ctx: &ScanContext, url: &str, findings: &mut Vec<Finding>) -> Result<()> {
    // Test with a benign XML payload first to see if the endpoint accepts XML
    let normal_xml = r#"<?xml version="1.0" encoding="UTF-8"?><test>scorchkit</test>"#;

    let response = ctx
        .http_client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(normal_xml)
        .send()
        .await;

    let Ok(response) = response else {
        return Ok(()); // Endpoint doesn't accept requests
    };

    let status = response.status();
    // If endpoint returns 405, 404, or similar, it doesn't accept XML POST
    if status.as_u16() == 405 || status.as_u16() == 404 {
        return Ok(());
    }

    let normal_body = response.text().await.unwrap_or_default();

    // If endpoint seems to process XML, test for XXE
    if status.is_success() || status.as_u16() == 400 || status.as_u16() == 500 {
        // Test with entity expansion payload
        for &(payload, marker, desc) in XXE_PAYLOADS {
            let resp = ctx
                .http_client
                .post(url)
                .header("Content-Type", "application/xml")
                .body(payload.to_string())
                .send()
                .await;

            let Ok(resp) = resp else {
                continue;
            };

            let resp_status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            // Check for XXE indicators
            if body.contains(marker) {
                findings.push(
                    Finding::new("xxe", Severity::Critical, "XML External Entity Injection Confirmed", format!("{desc}. The server processes external XML entities, allowing file read, SSRF, and potentially RCE."), url)
                        .with_evidence(format!("Endpoint: {url} | Marker: {marker} found in response"))
                        .with_remediation("Disable external entity processing in your XML parser. Set DTD processing to prohibited.")
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(611)
                        .with_confidence(0.7),
                );
                return Ok(());
            }

            // 500 error specifically from XXE payloads is suspicious
            if resp_status.as_u16() == 500 && !normal_body.is_empty() && status.is_success() {
                findings.push(
                    Finding::new("xxe", Severity::Medium, "Possible XXE: Server Error on Entity Payload", format!("Sending XML with entity declarations to {url} caused a 500 error, suggesting the XML parser processes DTDs."), url)
                        .with_evidence(format!("Normal XML: HTTP {status} | XXE payload: HTTP 500"))
                        .with_remediation("Disable DTD processing in your XML parser.")
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(611)
                        .with_confidence(0.7),
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

const XXE_PAYLOADS: &[(&str, &str, &str)] = &[
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe "scorchkit_xxe_confirmed">]><test>&xxe;</test>"#,
        "scorchkit_xxe_confirmed",
        "Internal entity expansion confirmed",
    ),
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>"#,
        "", // Can't predict hostname, check for 500 instead
        "External file entity attempted",
    ),
];
