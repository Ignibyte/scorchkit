use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Comprehensive TLS/SSL analysis via sslyze.
#[derive(Debug)]
pub struct SslyzeModule;

#[async_trait]
impl ScanModule for SslyzeModule {
    fn name(&self) -> &'static str {
        "SSLyze TLS Analyzer"
    }

    fn id(&self) -> &'static str {
        "sslyze"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Comprehensive TLS/SSL configuration analysis via sslyze"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("sslyze")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref().unwrap_or(ctx.target.url.as_str());

        let target_with_port = if ctx.target.port == 443 {
            target.to_string()
        } else {
            format!("{target}:{}", ctx.target.port)
        };

        let output = subprocess::run_tool(
            "sslyze",
            &["--json_out=-", &target_with_port],
            Duration::from_secs(300),
        )
        .await?;

        Ok(parse_sslyze_output(&output.stdout, ctx.target.url.as_str()))
    }
}

/// Parse sslyze JSON output into findings.
fn parse_sslyze_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => {
            // Fall back to parsing text output
            return parse_sslyze_text(output, target_url);
        }
    };

    // Check server scan results
    let results = &json["server_scan_results"];
    if let Some(arr) = results.as_array() {
        for result in arr {
            let scan_result = &result["scan_result"];

            // Check for deprecated SSL/TLS protocols
            check_protocol(
                scan_result,
                "ssl_2_0_cipher_suites",
                "SSL 2.0",
                Severity::Critical,
                target_url,
                &mut findings,
            );
            check_protocol(
                scan_result,
                "ssl_3_0_cipher_suites",
                "SSL 3.0",
                Severity::Critical,
                target_url,
                &mut findings,
            );
            check_protocol(
                scan_result,
                "tls_1_0_cipher_suites",
                "TLS 1.0",
                Severity::High,
                target_url,
                &mut findings,
            );
            check_protocol(
                scan_result,
                "tls_1_1_cipher_suites",
                "TLS 1.1",
                Severity::High,
                target_url,
                &mut findings,
            );

            // Check certificate info
            if let Some(cert_info) = scan_result["certificate_info"]["result"].as_object() {
                check_certificate(cert_info, target_url, &mut findings);
            }

            // Check for Heartbleed
            if let Some(heartbleed) =
                scan_result["heartbleed"]["result"]["is_vulnerable_to_heartbleed"].as_bool()
            {
                if heartbleed {
                    findings.push(
                        Finding::new(
                            "sslyze",
                            Severity::Critical,
                            "Vulnerable to Heartbleed (CVE-2014-0160)",
                            "The server is vulnerable to the Heartbleed bug, allowing \
                             attackers to read server memory contents.",
                            target_url,
                        )
                        .with_remediation(
                            "Update OpenSSL immediately and revoke/reissue certificates",
                        )
                        .with_owasp("A02:2021 Cryptographic Failures")
                        .with_cwe(119)
                        .with_confidence(0.9),
                    );
                }
            }

            // Check for Robot attack
            if let Some(robot) = scan_result["robot"]["result"]["robot_result"].as_str() {
                if robot.contains("VULNERABLE") {
                    findings.push(
                        Finding::new(
                            "sslyze",
                            Severity::High,
                            "Vulnerable to ROBOT Attack",
                            "The server is vulnerable to the ROBOT attack, allowing \
                             decryption of RSA-encrypted TLS sessions.",
                            target_url,
                        )
                        .with_remediation("Disable RSA key exchange cipher suites")
                        .with_owasp("A02:2021 Cryptographic Failures")
                        .with_confidence(0.9),
                    );
                }
            }
        }
    }

    findings
}

fn check_protocol(
    scan_result: &serde_json::Value,
    key: &str,
    protocol_name: &str,
    severity: Severity,
    target_url: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(result) = scan_result[key]["result"].as_object() {
        if let Some(ciphers) = result.get("accepted_cipher_suites") {
            if let Some(arr) = ciphers.as_array() {
                if !arr.is_empty() {
                    let cipher_names: Vec<&str> = arr
                        .iter()
                        .filter_map(|c| c["cipher_suite"]["name"].as_str())
                        .take(5)
                        .collect();

                    findings.push(
                        Finding::new(
                            "sslyze",
                            severity,
                            format!("Deprecated Protocol Supported: {protocol_name}"),
                            format!(
                                "{protocol_name} is enabled with {} accepted cipher suite(s). \
                                 This protocol has known vulnerabilities.",
                                arr.len()
                            ),
                            target_url,
                        )
                        .with_evidence(format!(
                            "Protocol: {protocol_name} | Ciphers: {}",
                            cipher_names.join(", ")
                        ))
                        .with_remediation(format!("Disable {protocol_name} on the server"))
                        .with_owasp("A02:2021 Cryptographic Failures")
                        .with_cwe(326)
                        .with_confidence(0.9),
                    );
                }
            }
        }
    }
}

fn check_certificate(
    cert_info: &serde_json::Map<String, serde_json::Value>,
    target_url: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(deployments) = cert_info.get("certificate_deployments") {
        if let Some(arr) = deployments.as_array() {
            for deployment in arr {
                // Check leaf certificate trust
                if let Some(path_results) = deployment["path_validation_results"].as_array() {
                    let all_trusted = path_results
                        .iter()
                        .all(|r| r["was_validation_successful"].as_bool().unwrap_or(false));

                    if !all_trusted {
                        findings.push(
                            Finding::new(
                                "sslyze",
                                Severity::High,
                                "Certificate Not Trusted",
                                "The TLS certificate is not trusted by one or more certificate stores.",
                                target_url,
                            )
                            .with_remediation("Use a certificate from a trusted Certificate Authority")
                            .with_owasp("A02:2021 Cryptographic Failures")
                            .with_cwe(295)
                            .with_confidence(0.9),
                        );
                    }
                }

                // Check for must-staple without stapling
                if deployment["leaf_certificate_has_must_staple_extension"]
                    .as_bool()
                    .unwrap_or(false)
                    && !deployment["leaf_certificate_is_ev"].as_bool().unwrap_or(false)
                {
                    // This is informational
                }
            }
        }
    }
}

/// Fallback text parser for older sslyze versions or non-JSON output.
fn parse_sslyze_text(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.contains("VULNERABLE") && trimmed.contains("Heartbleed") {
            findings.push(
                Finding::new(
                    "sslyze",
                    Severity::Critical,
                    "Vulnerable to Heartbleed",
                    "The server is vulnerable to the Heartbleed bug.",
                    target_url,
                )
                .with_owasp("A02:2021 Cryptographic Failures")
                .with_cwe(119)
                .with_confidence(0.9),
            );
        }

        if trimmed.contains("SSL 2.0") && trimmed.contains("accepted") {
            findings.push(
                Finding::new(
                    "sslyze",
                    Severity::Critical,
                    "SSL 2.0 Supported",
                    "SSL 2.0 is enabled. This protocol is severely broken.",
                    target_url,
                )
                .with_owasp("A02:2021 Cryptographic Failures")
                .with_cwe(326)
                .with_confidence(0.9),
            );
        }

        if trimmed.contains("SSL 3.0") && trimmed.contains("accepted") {
            findings.push(
                Finding::new(
                    "sslyze",
                    Severity::Critical,
                    "SSL 3.0 Supported (POODLE)",
                    "SSL 3.0 is enabled. This protocol is vulnerable to POODLE.",
                    target_url,
                )
                .with_owasp("A02:2021 Cryptographic Failures")
                .with_cwe(326)
                .with_confidence(0.9),
            );
        }

        if trimmed.contains("TLS 1.0") && trimmed.contains("accepted") {
            findings.push(
                Finding::new(
                    "sslyze",
                    Severity::High,
                    "TLS 1.0 Supported (Deprecated)",
                    "TLS 1.0 is enabled. This protocol is deprecated and has known weaknesses.",
                    target_url,
                )
                .with_owasp("A02:2021 Cryptographic Failures")
                .with_cwe(326)
                .with_confidence(0.9),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for sslyze output parser (JSON and text fallback).

    /// Verify that `parse_sslyze_output` correctly extracts findings from
    /// sslyze JSON output including deprecated protocols and Heartbleed.
    #[test]
    fn test_parse_sslyze_output() {
        let json = r#"{
            "server_scan_results": [{
                "scan_result": {
                    "tls_1_0_cipher_suites": {
                        "result": {
                            "accepted_cipher_suites": [
                                {"cipher_suite": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}}
                            ]
                        }
                    },
                    "heartbleed": {
                        "result": {
                            "is_vulnerable_to_heartbleed": true
                        }
                    }
                }
            }]
        }"#;

        let findings = parse_sslyze_output(json, "https://example.com");
        assert!(findings.len() >= 2);
        let heartbleed = findings.iter().find(|f| f.title.contains("Heartbleed"));
        assert!(heartbleed.is_some());
        assert_eq!(
            heartbleed.expect("heartbleed finding should exist").severity,
            Severity::Critical
        );
        let tls10 = findings.iter().find(|f| f.title.contains("TLS 1.0"));
        assert!(tls10.is_some());
    }

    /// Verify that `parse_sslyze_output` handles empty input gracefully
    /// by falling through to the text parser, which also returns empty.
    #[test]
    fn test_parse_sslyze_output_empty() {
        let findings = parse_sslyze_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
