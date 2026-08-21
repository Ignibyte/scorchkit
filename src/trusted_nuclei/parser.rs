use std::collections::HashMap;

use scorchkit_core::{
    AdapterParseOutcome, Finding, HttpEvidence, HttpParameterIdentity, ObservationLocation,
    ScannerProvenance,
};
use url::Url;

use crate::engine::severity::Severity;

use super::collection::{VerifiedNucleiCollection, VerifiedNucleiTemplate};
use super::invocation::ResolvedNucleiTarget;

pub fn parse_nuclei_output(
    output: &str,
    target: &ResolvedNucleiTarget,
    collection: &VerifiedNucleiCollection,
    tool_version: &str,
) -> AdapterParseOutcome<Vec<Finding>> {
    let approved: HashMap<&str, &VerifiedNucleiTemplate> =
        collection.templates.iter().map(|template| (template.id.as_str(), template)).collect();
    let mut findings = Vec::new();
    let mut saw_nonempty = false;
    for (index, line) in output.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        saw_nonempty = true;
        let record: serde_json::Value = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(error) => {
                return AdapterParseOutcome::malformed(format!(
                    "invalid JSONL record {}: {error}",
                    index + 1
                ));
            }
        };
        match parse_record(&record, target, collection, &approved, tool_version) {
            Ok(finding) => findings.push(finding),
            Err(reason) => {
                return AdapterParseOutcome::malformed(format!(
                    "JSONL record {} {reason}",
                    index + 1
                ));
            }
        }
    }
    if !saw_nonempty || findings.is_empty() {
        AdapterParseOutcome::NoFindings
    } else {
        AdapterParseOutcome::Findings(findings)
    }
}

fn parse_record(
    json: &serde_json::Value,
    target: &ResolvedNucleiTarget,
    collection: &VerifiedNucleiCollection,
    approved: &HashMap<&str, &VerifiedNucleiTemplate>,
    tool_version: &str,
) -> Result<Finding, &'static str> {
    let record = json.as_object().ok_or("is not an object")?;
    let template_id = record
        .get("template-id")
        .and_then(serde_json::Value::as_str)
        .ok_or("has no template-id")?;
    let template = approved.get(template_id).copied().ok_or("names an unapproved template")?;
    let info =
        record.get("info").and_then(serde_json::Value::as_object).ok_or("has no info object")?;
    let name = info.get("name").and_then(serde_json::Value::as_str).ok_or("has no info.name")?;
    let severity_name =
        info.get("severity").and_then(serde_json::Value::as_str).ok_or("has no info.severity")?;
    let severity = match severity_name {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "unknown" => Severity::Info,
        _ => return Err("has an unsupported info.severity"),
    };
    let description = info
        .get("description")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Vulnerability detected by an approved Nuclei template.");
    let reported_match =
        record.get("matched-at").and_then(serde_json::Value::as_str).ok_or("has no matched-at")?;
    let matched = project_match_to_canonical(reported_match, target)?;

    let mut evidence = vec![format!("Template: {template_id}")];
    if let Some(matcher) = record.get("matcher-name").and_then(serde_json::Value::as_str) {
        evidence.push(format!("Matcher: {matcher}"));
    }
    if let Some(results) = record.get("extracted-results").and_then(serde_json::Value::as_array) {
        let extracted: Vec<&str> =
            results.iter().filter_map(serde_json::Value::as_str).take(3).collect();
        if !extracted.is_empty() {
            evidence.push(format!("Extracted: {}", extracted.join(", ")));
        }
    }
    let parameter = record
        .get("parameter")
        .and_then(serde_json::Value::as_str)
        .map(|name| HttpParameterIdentity::new(name, "unknown"));
    let route = Some(matched.path().to_string());
    let mut finding = Finding::new(
        "nuclei",
        severity,
        format!("{name} [{template_id}]"),
        description,
        matched.as_str(),
    )
    .with_location(ObservationLocation::Runtime {
        uri: matched.as_str().to_string(),
        route,
        parameter,
    })
    .with_evidence(evidence.join(" | "))
    .with_provenance(
        ScannerProvenance::new("nuclei", chrono::Utc::now())
            .with_version(tool_version)
            .with_rule(template_id, Some(template.sha256.clone()))
            .with_config(&collection.identity),
    );
    if let Some(tags) = tags(info) {
        if let Some(owasp) = map_tags_to_owasp(&tags) {
            finding = finding.with_owasp(owasp);
        }
    }
    if let Some(references) = info.get("reference").and_then(serde_json::Value::as_array) {
        let references: Vec<&str> =
            references.iter().filter_map(serde_json::Value::as_str).take(2).collect();
        if !references.is_empty() {
            finding = finding.with_remediation(format!("See: {}", references.join(", ")));
        }
    }
    if let Some(cwe) = info
        .get("classification")
        .and_then(|value| value.get("cwe-id"))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.first())
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.strip_prefix("CWE-"))
        .and_then(|value| value.parse::<u32>().ok())
    {
        finding = finding.with_cwe(cwe);
    }
    if let Some(request) = record.get("request").and_then(serde_json::Value::as_str) {
        let method = request.split_whitespace().next().unwrap_or("UNKNOWN");
        let response = record.get("response").and_then(serde_json::Value::as_str);
        let status = response
            .and_then(|response| response.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok())
            .unwrap_or_default();
        let mut http =
            HttpEvidence::new(method, matched.as_str(), status).with_request_body(request);
        if let Some(response) = response {
            http = http.with_response_body(response);
        }
        finding = finding.with_http_evidence(http);
    }
    Ok(finding.with_confidence(0.8))
}

fn project_match_to_canonical(
    reported_match: &str,
    target: &ResolvedNucleiTarget,
) -> Result<Url, &'static str> {
    let reported = Url::parse(reported_match).map_err(|_| "has an invalid matched-at URL")?;
    if !same_origin(&reported, &target.execution) && !same_origin(&reported, &target.canonical) {
        return Err("matched-at escaped the authorized execution origin");
    }
    let mut canonical = target.canonical.clone();
    canonical.set_path(reported.path());
    canonical.set_query(reported.query());
    canonical.set_fragment(None);
    Ok(canonical)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn tags(info: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let value = info.get("tags")?;
    if let Some(tags) = value.as_str() {
        return Some(tags.to_string());
    }
    value.as_array().map(|values| {
        values.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(",")
    })
}

fn map_tags_to_owasp(tags: &str) -> Option<&'static str> {
    let lower = tags.to_ascii_lowercase();
    if lower.contains("sqli")
        || lower.contains("injection")
        || lower.contains("xss")
        || lower.contains("ssti")
    {
        Some("A03:2021 Injection")
    } else if lower.contains("auth") || lower.contains("default-login") {
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
    use scorchkit_policy::EffectClass;

    fn collection() -> VerifiedNucleiCollection {
        VerifiedNucleiCollection {
            identity: "fixture@1:sha256:abc".to_string(),
            signer_identity: "fixture-signer".to_string(),
            certificate_bytes: Vec::new(),
            strongest_effect: EffectClass::ActiveSafe,
            templates: vec![VerifiedNucleiTemplate {
                id: "fixture-probe".to_string(),
                sha256: "b".repeat(64),
                bytes: Vec::new(),
            }],
        }
    }

    fn target() -> ResolvedNucleiTarget {
        ResolvedNucleiTarget {
            canonical: Url::parse("https://app.test:8443/base").expect("canonical"),
            execution: Url::parse("https://192.0.2.10:8443/base").expect("execution"),
            authority_header: Some("app.test:8443".to_string()),
            sni: Some("app.test".to_string()),
        }
    }

    #[test]
    fn verified_identity_overrides_scanner_provenance_and_projects_canonical_target() {
        let output = r#"{"template-id":"fixture-probe","template-digest":"attacker","template-path":"outside.yaml","info":{"name":"Fixture","severity":"medium","tags":["misconfig"]},"matched-at":"https://192.0.2.10:8443/base/check","matcher-name":"body"}"#;
        let parsed = parse_nuclei_output(output, &target(), &collection(), "3.11.1");
        let AdapterParseOutcome::Findings(findings) = parsed else { panic!("expected finding") };
        let provenance = &findings[0].appsec.provenance;
        let expected_digest = "b".repeat(64);
        assert_eq!(provenance.rule_digest.as_deref(), Some(expected_digest.as_str()));
        assert_eq!(provenance.config_identity.as_deref(), Some("fixture@1:sha256:abc"));
        assert_eq!(findings[0].affected_target, "https://app.test:8443/base/check");
    }

    #[test]
    fn malformed_unapproved_and_escaped_records_fail_instead_of_becoming_clean() {
        for output in [
            "not json",
            r#"{"template-id":"other","info":{"name":"Fixture","severity":"low"},"matched-at":"https://192.0.2.10:8443/"}"#,
            r#"{"template-id":"fixture-probe","info":{"name":"Fixture","severity":"low"},"matched-at":"https://outside.test/"}"#,
        ] {
            assert!(matches!(
                parse_nuclei_output(output, &target(), &collection(), "3.11.1"),
                AdapterParseOutcome::Malformed { .. }
            ));
        }
    }

    #[test]
    fn empty_success_is_distinct_from_malformed_output() {
        assert!(matches!(
            parse_nuclei_output("\n", &target(), &collection(), "3.11.1"),
            AdapterParseOutcome::NoFindings
        ));
    }

    #[test]
    fn request_response_evidence_is_redacted() {
        let output = r#"{"template-id":"fixture-probe","info":{"name":"Fixture","severity":"low"},"matched-at":"https://192.0.2.10:8443/base?access_token=fixture-secret","request":"GET /base?access_token=fixture-secret HTTP/1.1\r\nAuthorization: Bearer fixture-secret\r\n","response":"HTTP/1.1 200 OK\r\nSet-Cookie: session=fixture-secret\r\n"}"#;
        let AdapterParseOutcome::Findings(findings) =
            parse_nuclei_output(output, &target(), &collection(), "3.11.1")
        else {
            panic!("expected finding")
        };
        let encoded = serde_json::to_string(&findings[0]).expect("finding JSON");
        assert!(!encoded.contains("fixture-secret"));
    }
}
