use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use scorchkit_core::{
    AdapterParseOutcome, HttpEvidence, HttpParameterIdentity, ObservationLocation,
    ScannerProvenance,
};

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

        let output = ctx
            .run_tool(
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
                Duration::from_mins(10),
            )
            .await?;

        parse_nuclei_output_v1(&output.stdout, target).into_result("nuclei")
    }
}

/// Parse nuclei JSON-lines output into findings.
#[cfg(test)]
fn parse_nuclei_output(output: &str, target_url: &str) -> Vec<Finding> {
    parse_nuclei_output_v1(output, target_url).into_legacy()
}

fn parse_nuclei_output_v1(output: &str, target_url: &str) -> AdapterParseOutcome<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut saw_record = false;

    for (index, line) in output.lines().enumerate() {
        saw_record = true;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(error) => {
                return AdapterParseOutcome::malformed(format!(
                    "invalid JSONL record {}: {error}",
                    index + 1
                ));
            }
        };

        match parse_nuclei_record(&json, target_url) {
            Ok(finding) => findings.push(finding),
            Err(reason) => {
                return AdapterParseOutcome::malformed(format!(
                    "JSONL record {} {reason}",
                    index + 1
                ));
            }
        }
    }

    if !saw_record || findings.is_empty() {
        AdapterParseOutcome::NoFindings
    } else {
        AdapterParseOutcome::Findings(findings)
    }
}

fn parse_nuclei_record(
    json: &serde_json::Value,
    target_url: &str,
) -> std::result::Result<Finding, &'static str> {
    let Some(record) = json.as_object() else {
        return Err("is not an object");
    };
    let Some(template_id) = record.get("template-id").and_then(serde_json::Value::as_str) else {
        return Err("has no template-id");
    };
    let Some(info) = record.get("info").and_then(serde_json::Value::as_object) else {
        return Err("has no info object");
    };
    let Some(name) = info.get("name").and_then(serde_json::Value::as_str) else {
        return Err("has no info.name");
    };
    let Some(severity_name) = info.get("severity").and_then(serde_json::Value::as_str) else {
        return Err("has no info.severity");
    };
    let severity = match severity_name {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    };
    let description = info
        .get("description")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Vulnerability detected by nuclei template.");
    let matched_at =
        record.get("matched-at").and_then(serde_json::Value::as_str).unwrap_or(target_url);

    let mut evidence_parts = vec![format!("Template: {template_id}")];
    if let Some(matcher) = record.get("matcher-name").and_then(serde_json::Value::as_str) {
        evidence_parts.push(format!("Matcher: {matcher}"));
    }
    if let Some(results) = record.get("extracted-results").and_then(serde_json::Value::as_array) {
        let extracted: Vec<&str> =
            results.iter().filter_map(serde_json::Value::as_str).take(3).collect();
        if !extracted.is_empty() {
            evidence_parts.push(format!("Extracted: {}", extracted.join(", ")));
        }
    }

    let route = url::Url::parse(matched_at).ok().map(|url| url.path().to_string());
    let parameter = record
        .get("parameter")
        .and_then(serde_json::Value::as_str)
        .map(|name| HttpParameterIdentity::new(name, "unknown"));
    let mut finding = Finding::new(
        "nuclei",
        severity,
        format!("{name} [{template_id}]"),
        description,
        matched_at,
    )
    .with_location(ObservationLocation::Runtime { uri: matched_at.to_string(), route, parameter })
    .with_evidence(evidence_parts.join(" | "));
    finding = attach_nuclei_context(finding, record, template_id, matched_at);
    if let Some(tags) = info.get("tags").and_then(serde_json::Value::as_str) {
        if let Some(owasp) = map_nuclei_tags_to_owasp(tags) {
            finding = finding.with_owasp(owasp);
        }
    }
    if let Some(references) = info.get("reference").and_then(serde_json::Value::as_array) {
        let refs: Vec<&str> =
            references.iter().filter_map(serde_json::Value::as_str).take(2).collect();
        if !refs.is_empty() {
            finding = finding.with_remediation(format!("See: {}", refs.join(", ")));
        }
    }
    if let Some(cwe) = info
        .get("classification")
        .and_then(|value| value.get("cwe-id"))
        .and_then(serde_json::Value::as_array)
    {
        if let Some(id) = cwe
            .first()
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.strip_prefix("CWE-"))
            .and_then(|value| value.parse::<u32>().ok())
        {
            finding = finding.with_cwe(id);
        }
    }
    Ok(finding.with_confidence(0.8))
}

fn attach_nuclei_context(
    mut finding: Finding,
    record: &serde_json::Map<String, serde_json::Value>,
    template_id: &str,
    matched_at: &str,
) -> Finding {
    let rule_digest =
        record.get("template-digest").and_then(serde_json::Value::as_str).map(str::to_string);
    let mut provenance =
        ScannerProvenance::new("nuclei", finding.timestamp).with_rule(template_id, rule_digest);
    if let Some(version) = record.get("nuclei-version").and_then(serde_json::Value::as_str) {
        provenance = provenance.with_version(version);
    }
    if let Some(template_path) = record.get("template-path").and_then(serde_json::Value::as_str) {
        provenance = provenance.with_config(template_path);
    }
    finding = finding.with_provenance(provenance);

    let Some(request) = record.get("request").and_then(serde_json::Value::as_str) else {
        return finding;
    };
    let method = request.split_whitespace().next().unwrap_or("UNKNOWN");
    let response = record.get("response").and_then(serde_json::Value::as_str);
    let status_code = response
        .and_then(|response| response.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or_default();
    let mut http = HttpEvidence::new(method, matched_at, status_code).with_request_body(request);
    if let Some(response) = response {
        http = http.with_response_body(response);
    }
    if let Some(persona) = record.get("auth-persona").and_then(serde_json::Value::as_str) {
        http = http.with_authentication_persona(persona);
    }
    finding.with_http_evidence(http)
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

    // Tests for nuclei JSON-lines output parser.

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

    #[test]
    fn malformed_nuclei_jsonl_is_not_reported_as_no_findings() {
        for malformed in ["not json", "[]", r#"{"info": {}}"#] {
            let outcome = parse_nuclei_output_v1(malformed, "https://example.com");
            assert!(matches!(outcome, AdapterParseOutcome::Malformed { .. }));
        }
    }

    #[test]
    fn whitespace_records_are_an_explicit_no_findings_outcome() {
        assert!(matches!(
            parse_nuclei_output_v1("  \n\t", "https://example.com"),
            AdapterParseOutcome::NoFindings
        ));
    }

    #[test]
    fn nuclei_severity_mapping_is_exact() {
        for (name, expected) in [
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("unknown", Severity::Info),
        ] {
            let record = serde_json::json!({
                "template-id": "severity-probe",
                "info": {"name": "Severity probe", "severity": name}
            });
            let finding = parse_nuclei_record(&record, "https://example.com")
                .expect("valid severity fixture");
            assert_eq!(finding.severity, expected, "severity {name}");
        }
    }

    #[test]
    fn nuclei_record_preserves_extracted_results_and_references() {
        let record = serde_json::json!({
            "template-id": "evidence-probe",
            "info": {
                "name": "Evidence probe",
                "severity": "low",
                "reference": ["https://example.com/advisory"]
            },
            "extracted-results": ["proof-token"]
        });
        let finding =
            parse_nuclei_record(&record, "https://example.com").expect("valid evidence fixture");
        assert!(finding
            .evidence
            .as_deref()
            .is_some_and(|value| { value.contains("Extracted: proof-token") }));
        assert_eq!(finding.remediation.as_deref(), Some("See: https://example.com/advisory"));
    }

    #[test]
    fn nuclei_record_preserves_runtime_provenance_and_redacted_http_evidence() {
        let record = serde_json::json!({
            "template-id": "login-probe",
            "template-digest": "sha256:abc",
            "template-path": "http/login-probe.yaml",
            "nuclei-version": "3.4.0",
            "info": {"name": "Login probe", "severity": "medium"},
            "matched-at": "https://example.com/login?access_token=secret",
            "parameter": "password",
            "auth-persona": "standard-user",
            "request": "POST /login HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\npassword=secret",
            "response": "HTTP/1.1 401 Unauthorized\r\nSet-Cookie: session=secret"
        });
        let finding = parse_nuclei_record(&record, "https://example.com").expect("valid record");
        assert!(matches!(
            finding.appsec.location,
            ObservationLocation::Runtime { ref route, ref parameter, .. }
                if route.as_deref() == Some("/login")
                    && parameter.as_ref().is_some_and(|value| value.name == "password")
        ));
        assert_eq!(finding.appsec.provenance.scanner_version.as_deref(), Some("3.4.0"));
        assert_eq!(finding.appsec.provenance.rule_digest.as_deref(), Some("sha256:abc"));
        let json = serde_json::to_string(&finding).expect("serialize finding");
        assert!(!json.contains("Bearer secret"));
        assert!(!json.contains("password=secret"));
        assert!(json.contains("standard-user"));
    }
}
