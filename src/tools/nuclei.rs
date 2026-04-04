use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Template-based vulnerability scanning via nuclei.
#[derive(Debug)]
pub struct NucleiModule;

#[async_trait]
impl ScanModule for NucleiModule {
    fn name(&self) -> &'static str {
        "Nuclei Vulnerability Scanner"
    }

    fn id(&self) -> &'static str {
        "nuclei"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Template-based vulnerability scanning via nuclei"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nuclei")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        let output = subprocess::run_tool(
            "nuclei",
            &[
                "-u",
                target,
                "-jsonl",
                "-silent",
                "-severity",
                "critical,high,medium,low",
                "-no-color",
            ],
            Duration::from_secs(600),
        )
        .await?;

        Ok(parse_nuclei_output(&output.stdout, target))
    }
}

/// Parse nuclei JSON-lines output into findings.
fn parse_nuclei_output(output: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let template_id = json["template-id"].as_str().unwrap_or("unknown");
        let name = json["info"]["name"].as_str().unwrap_or("Unknown Vulnerability");
        let description = json["info"]["description"]
            .as_str()
            .unwrap_or("Vulnerability detected by nuclei template.");
        let severity_str = json["info"]["severity"].as_str().unwrap_or("info");
        let matched_at = json["matched-at"].as_str().unwrap_or(target_url);
        let matcher_name = json["matcher-name"].as_str();
        let extracted_results = json["extracted-results"].as_array();

        let severity = match severity_str {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };

        let mut evidence_parts = vec![format!("Template: {template_id}")];
        if let Some(matcher) = matcher_name {
            evidence_parts.push(format!("Matcher: {matcher}"));
        }
        if let Some(results) = extracted_results {
            let extracted: Vec<&str> = results.iter().filter_map(|v| v.as_str()).take(3).collect();
            if !extracted.is_empty() {
                evidence_parts.push(format!("Extracted: {}", extracted.join(", ")));
            }
        }

        let mut finding = Finding::new(
            "nuclei",
            severity,
            format!("{name} [{template_id}]"),
            description,
            matched_at,
        )
        .with_evidence(evidence_parts.join(" | "));

        // Map nuclei tags to OWASP categories
        if let Some(tags) = json["info"]["tags"].as_str() {
            if let Some(owasp) = map_nuclei_tags_to_owasp(tags) {
                finding = finding.with_owasp(owasp);
            }
        }

        // Add reference if available
        if let Some(reference) = json["info"]["reference"].as_array() {
            let refs: Vec<&str> = reference.iter().filter_map(|v| v.as_str()).take(2).collect();
            if !refs.is_empty() {
                finding = finding.with_remediation(format!("See: {}", refs.join(", ")));
            }
        }

        // Extract CWE if present in classification
        if let Some(cwe) = json["info"]["classification"]["cwe-id"].as_array() {
            if let Some(first_cwe) = cwe.first().and_then(|v| v.as_str()) {
                if let Some(id_str) = first_cwe.strip_prefix("CWE-") {
                    if let Ok(id) = id_str.parse::<u32>() {
                        finding = finding.with_cwe(id);
                    }
                }
            }
        }

        findings.push(finding.with_confidence(0.8));
    }

    findings
}

/// Map nuclei tags to OWASP categories.
fn map_nuclei_tags_to_owasp(tags: &str) -> Option<&'static str> {
    let lower = tags.to_lowercase();

    if lower.contains("sqli")
        || lower.contains("injection")
        || lower.contains("xss")
        || lower.contains("ssti")
    {
        Some("A03:2021 Injection")
    } else if lower.contains("auth") || lower.contains("default-login") || lower.contains("brute") {
        Some("A07:2021 Identification and Authentication Failures")
    } else if lower.contains("misconfig")
        || lower.contains("exposure")
        || lower.contains("disclosure")
    {
        Some("A05:2021 Security Misconfiguration")
    } else if lower.contains("cve") || lower.contains("outdated") {
        Some("A06:2021 Vulnerable and Outdated Components")
    } else if lower.contains("ssl") || lower.contains("tls") || lower.contains("crypto") {
        Some("A02:2021 Cryptographic Failures")
    } else if lower.contains("ssrf") {
        Some("A10:2021 Server-Side Request Forgery")
    } else if lower.contains("idor") || lower.contains("access-control") {
        Some("A01:2021 Broken Access Control")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for nuclei JSON-lines output parser.

    /// Verify that `parse_nuclei_output` correctly extracts findings from
    /// JSON-lines output including severity, template ID, and CWE.
    #[test]
    fn test_parse_nuclei_output() {
        let output = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","description":"Remote code execution via Log4j.","severity":"critical","tags":"cve,rce","classification":{"cwe-id":["CWE-502"]},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},"matched-at":"https://example.com/api","matcher-name":"body"}"#;

        let findings = parse_nuclei_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Log4j RCE"));
        assert!(findings[0].title.contains("cve-2021-44228"));
        assert_eq!(findings[0].cwe_id, Some(502));
    }

    /// Verify that `parse_nuclei_output` handles empty input gracefully.
    #[test]
    fn test_parse_nuclei_output_empty() {
        let findings = parse_nuclei_output("", "https://example.com");
        assert!(findings.is_empty());
    }
}
