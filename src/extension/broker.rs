use std::collections::BTreeSet;

use futures_util::StreamExt;
use scorchkit_core::{sha256_hex, Finding, ScannerProvenance, Severity};
use scorchkit_extension::{
    ExtensionCapabilityV1, ExtensionEffectDecisionV1, ExtensionEffectRequestV1,
    ExtensionEffectResultV1, ExtensionEffectV1, ExtensionFindingV1, ExtensionHttpMethodV1,
    ExtensionInvocationV1, ExtensionManifestV1, ExtensionOutputV1,
};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::events::ScanEvent;
use crate::engine::observation::redact_text;
use crate::engine::scan_context::ScanContext;

const MAX_EXTENSION_FINDINGS: usize = 256;
const MAX_EXTENSION_NESTED_ITEMS: usize = 256;
const MAX_EXTENSION_VALUE_BYTES: usize = 64 * 1024;

pub(super) async fn broker_effect(
    context: &ScanContext,
    manifest: &ExtensionManifestV1,
    invocation: &ExtensionInvocationV1,
    request: &ExtensionEffectRequestV1,
) -> ExtensionEffectResultV1 {
    let prepared = prepare_effect(context, manifest, invocation, request);
    let (decision, denial) = match &prepared {
        Ok(_) => (ExtensionEffectDecisionV1::Allowed, None),
        Err(reason) => (ExtensionEffectDecisionV1::Denied, Some(redact_text(reason))),
    };
    context
        .events
        .publish_durable(ScanEvent::Custom {
            kind: "extension.effect_decision".to_string(),
            data: serde_json::json!({
                "extension_id": manifest.id,
                "invocation_id": invocation.invocation_id,
                "request_id": redact_text(&request.request_id),
                "effect_kind": effect_kind(&request.effect),
                "decision": decision,
                "reason": denial.as_deref(),
            }),
        })
        .await;
    match prepared {
        Ok(prepared) => execute_prepared_effect(context, manifest, request, prepared)
            .await
            .unwrap_or_else(|reason| empty_effect_result(request, decision, Some(reason))),
        Err(_) => empty_effect_result(request, decision, denial),
    }
}

enum PreparedEffect {
    Http { method: ExtensionHttpMethodV1, url: Url },
    Input { media_type: String, bytes: Vec<u8> },
}

fn prepare_effect(
    context: &ScanContext,
    manifest: &ExtensionManifestV1,
    invocation: &ExtensionInvocationV1,
    request: &ExtensionEffectRequestV1,
) -> std::result::Result<PreparedEffect, String> {
    if !valid_id(&request.request_id) {
        return Err("extension effect request identity is invalid".to_string());
    }
    match &request.effect {
        ExtensionEffectV1::Http { method, url } => {
            require_capability(manifest, ExtensionCapabilityV1::NetworkHttp)?;
            let url = safe_url(url)?;
            context
                .authorize_extension_target(&url, manifest.adapter.strongest_effect)
                .map_err(|error| error.to_string())?;
            Ok(PreparedEffect::Http { method: *method, url })
        }
        ExtensionEffectV1::Input { input_id } => {
            require_capability(manifest, ExtensionCapabilityV1::InputRead)?;
            if !valid_id(input_id) {
                return Err("extension input identity is invalid".to_string());
            }
            let input = invocation
                .inputs
                .iter()
                .find(|input| input.id == *input_id)
                .ok_or_else(|| "extension input identity is unavailable".to_string())?;
            Ok(PreparedEffect::Input {
                media_type: input.media_type.clone(),
                bytes: input.bytes.clone(),
            })
        }
        ExtensionEffectV1::Filesystem { operation } => {
            require_capability(manifest, ExtensionCapabilityV1::Filesystem)?;
            if !valid_id(operation) {
                return Err("extension filesystem operation is invalid".to_string());
            }
            Err("filesystem effects are unsupported by extension protocol v1".to_string())
        }
        ExtensionEffectV1::Credential { operation } => {
            require_capability(manifest, ExtensionCapabilityV1::Credential)?;
            if !valid_id(operation) {
                return Err("extension credential operation is invalid".to_string());
            }
            Err("credential effects are unsupported by extension protocol v1".to_string())
        }
        ExtensionEffectV1::Subprocess { operation } => {
            require_capability(manifest, ExtensionCapabilityV1::Subprocess)?;
            if !valid_id(operation) {
                return Err("extension subprocess operation is invalid".to_string());
            }
            Err("subprocess effects are unsupported by extension protocol v1".to_string())
        }
    }
}

async fn execute_prepared_effect(
    context: &ScanContext,
    manifest: &ExtensionManifestV1,
    request: &ExtensionEffectRequestV1,
    prepared: PreparedEffect,
) -> std::result::Result<ExtensionEffectResultV1, String> {
    match prepared {
        PreparedEffect::Http { method, url } => {
            let client = context
                .extension_http_client(&url, manifest.adapter.strongest_effect)
                .map_err(|_| "extension HTTP client authorization failed".to_string())?;
            let builder = match method {
                ExtensionHttpMethodV1::Get => client.get(url),
                ExtensionHttpMethodV1::Head => client.head(url),
            };
            let response =
                builder.send().await.map_err(|_| "extension HTTP request failed".to_string())?;
            let status = response.status().as_u16();
            let media_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let limit = usize::try_from(manifest.budgets.input_bytes)
                .map_err(|_| "extension response limit is unsupported".to_string())?;
            let body = read_bounded_body(response.bytes_stream(), limit).await?;
            Ok(ExtensionEffectResultV1 {
                request_id: request.request_id.clone(),
                decision: ExtensionEffectDecisionV1::Allowed,
                status: Some(status),
                media_type,
                body,
                reason: None,
            })
        }
        PreparedEffect::Input { media_type, bytes } => Ok(ExtensionEffectResultV1 {
            request_id: request.request_id.clone(),
            decision: ExtensionEffectDecisionV1::Allowed,
            status: None,
            media_type: Some(media_type),
            body: bytes,
            reason: None,
        }),
    }
}

fn empty_effect_result(
    request: &ExtensionEffectRequestV1,
    decision: ExtensionEffectDecisionV1,
    reason: Option<String>,
) -> ExtensionEffectResultV1 {
    ExtensionEffectResultV1 {
        request_id: request.request_id.clone(),
        decision,
        status: None,
        media_type: None,
        body: Vec::new(),
        reason: reason.map(|reason| redact_text(&reason)),
    }
}

fn require_capability(
    manifest: &ExtensionManifestV1,
    capability: ExtensionCapabilityV1,
) -> std::result::Result<(), String> {
    manifest
        .capabilities
        .contains(&capability)
        .then_some(())
        .ok_or_else(|| "extension effect was not declared".to_string())
}

fn safe_url(value: &str) -> std::result::Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "extension HTTP URL is invalid".to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("extension HTTP URL is not a credential-free HTTP target".to_string());
    }
    Ok(url)
}

async fn read_bounded_body<S, B, E>(
    mut stream: S,
    limit: usize,
) -> std::result::Result<Vec<u8>, String>
where
    S: futures_util::Stream<Item = std::result::Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
{
    let mut body = Vec::with_capacity(limit.min(64 * 1024));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "extension HTTP body read failed".to_string())?;
        let chunk = chunk.as_ref();
        if body.len().saturating_add(chunk.len()) > limit {
            return Err("extension HTTP body exceeds its byte limit".to_string());
        }
        body.extend_from_slice(chunk);
    }
    Ok(body)
}

pub(super) fn convert_output(
    context: &ScanContext,
    manifest: &ExtensionManifestV1,
    invocation: &ExtensionInvocationV1,
    output: ExtensionOutputV1,
) -> Result<Vec<Finding>> {
    if output.findings.len() > MAX_EXTENSION_FINDINGS
        || output.diagnostics.len() > MAX_EXTENSION_NESTED_ITEMS
        || output.diagnostics.iter().any(|value| !valid_required_text(value))
    {
        return Err(output_error("extension output collection exceeds its limit"));
    }
    let artifact_count = output
        .findings
        .iter()
        .try_fold(0_usize, |total, finding| total.checked_add(finding.source_artifacts.len()))
        .ok_or_else(|| output_error("extension source artifact count overflowed"))?;
    let artifact_bytes = output
        .findings
        .iter()
        .flat_map(|finding| &finding.source_artifacts)
        .try_fold(0_u64, |total, artifact| {
            u64::try_from(artifact.bytes.len()).ok().and_then(|length| total.checked_add(length))
        })
        .ok_or_else(|| output_error("extension source artifact bytes overflowed"))?;
    if artifact_count > usize::try_from(manifest.budgets.artifacts).unwrap_or(usize::MAX)
        || artifact_bytes > manifest.budgets.artifact_bytes
    {
        return Err(output_error("extension source artifacts exceed invocation budgets"));
    }
    let mut findings = Vec::with_capacity(output.findings.len());
    for proposed in output.findings {
        findings.push(convert_finding(context, manifest, invocation, proposed)?);
    }
    Ok(findings)
}

fn convert_finding(
    context: &ScanContext,
    manifest: &ExtensionManifestV1,
    invocation: &ExtensionInvocationV1,
    proposed: ExtensionFindingV1,
) -> Result<Finding> {
    validate_finding(manifest, &proposed)?;
    let affected = safe_url(&proposed.affected_target)
        .map_err(|_| output_error("extension finding target is invalid"))?;
    context.authorize_extension_target(&affected, manifest.adapter.strongest_effect)?;
    let severity = parse_severity(&proposed.severity)?;
    let provenance = ScannerProvenance::new(&manifest.id, chrono::Utc::now())
        .with_version(&manifest.version)
        .with_rule("extension-module", Some(manifest.module.sha256.clone()))
        .with_config(format!("extension-invocation:{};parser:validated", invocation.invocation_id));
    let mut finding = Finding::new(
        &manifest.id,
        severity,
        proposed.title,
        proposed.description,
        affected.as_str(),
    )
    .with_confidence(proposed.confidence)
    .with_provenance(provenance);
    if let Some(remediation) = proposed.remediation {
        finding = finding.with_remediation(remediation);
    }
    if let Some(category) = proposed.owasp_category {
        finding = finding.with_owasp(redact_text(&category));
    }
    if let Some(cwe) = proposed.cwe_id {
        finding = finding.with_cwe(cwe);
    }
    for observation in proposed.observations {
        finding = finding.with_structured_evidence(serde_json::json!({
            "kind": "extension_observation",
            "observationKind": redact_text(&observation.kind),
            "message": redact_text(&observation.message),
            "location": observation.location.map(|value| redact_text(&value)),
        }));
    }
    for evidence in proposed.evidence {
        finding = finding.with_structured_evidence(serde_json::json!({
            "kind": redact_text(&evidence.kind),
            "value": evidence.value,
            "sourceArtifactIds": evidence.source_artifact_ids,
        }));
    }
    for artifact in proposed.source_artifacts {
        finding = finding.with_structured_evidence(serde_json::json!({
            "kind": "extension_source_artifact",
            "id": redact_text(&artifact.id),
            "mediaType": redact_text(&artifact.media_type),
            "sha256": artifact.sha256,
        }));
    }
    Ok(finding)
}

fn validate_finding(manifest: &ExtensionManifestV1, proposed: &ExtensionFindingV1) -> Result<()> {
    for value in
        [proposed.title.as_str(), proposed.description.as_str(), proposed.affected_target.as_str()]
    {
        if !valid_required_text(value) {
            return Err(output_error("extension finding contains an invalid required value"));
        }
    }
    for value in
        [proposed.remediation.as_deref(), proposed.owasp_category.as_deref()].into_iter().flatten()
    {
        if !valid_required_text(value) {
            return Err(output_error("extension finding contains an invalid optional value"));
        }
    }
    if !proposed.confidence.is_finite() || !(0.0..=1.0).contains(&proposed.confidence) {
        return Err(output_error("extension finding confidence is invalid"));
    }
    if proposed.observations.len() > MAX_EXTENSION_NESTED_ITEMS
        || proposed.evidence.len() > MAX_EXTENSION_NESTED_ITEMS
        || proposed.source_artifacts.len()
            > usize::try_from(manifest.budgets.artifacts).unwrap_or(usize::MAX)
    {
        return Err(output_error("extension finding nested collection exceeds its limit"));
    }
    for observation in &proposed.observations {
        if !valid_id(&observation.kind)
            || !valid_required_text(&observation.message)
            || observation.location.as_deref().is_some_and(|value| !valid_required_text(value))
        {
            return Err(output_error("extension observation is invalid"));
        }
    }
    let mut artifact_ids = BTreeSet::new();
    for artifact in &proposed.source_artifacts {
        if !valid_id(&artifact.id)
            || !valid_required_text(&artifact.media_type)
            || !lower_sha256(&artifact.sha256)
            || !artifact_ids.insert(artifact.id.clone())
            || sha256_hex(&artifact.bytes) != artifact.sha256
        {
            return Err(output_error("extension source artifact identity is invalid"));
        }
    }
    for evidence in &proposed.evidence {
        let mut references = BTreeSet::new();
        if !valid_id(&evidence.kind)
            || serde_json::to_vec(&evidence.value)
                .map_or(true, |value| value.len() > MAX_EXTENSION_VALUE_BYTES)
            || evidence.source_artifact_ids.iter().any(|identity| {
                !valid_id(identity)
                    || !artifact_ids.contains(identity)
                    || !references.insert(identity.as_str())
            })
        {
            return Err(output_error("extension evidence identity is invalid"));
        }
    }
    Ok(())
}

fn valid_required_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_EXTENSION_VALUE_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        })
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_severity(value: &str) -> Result<Severity> {
    match value {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        _ => Err(output_error("extension finding severity is invalid")),
    }
}

const fn effect_kind(effect: &ExtensionEffectV1) -> &'static str {
    match effect {
        ExtensionEffectV1::Http { .. } => "http",
        ExtensionEffectV1::Input { .. } => "input",
        ExtensionEffectV1::Filesystem { .. } => "filesystem",
        ExtensionEffectV1::Credential { .. } => "credential",
        ExtensionEffectV1::Subprocess { .. } => "subprocess",
    }
}

fn output_error(reason: &str) -> ScorchError {
    ScorchError::ToolOutputParse {
        tool: "scorchkit-extension".to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use scorchkit_extension::{
        ExtensionArtifactV1, ExtensionCapabilityV1, ExtensionEffectRequestV1, ExtensionEffectV1,
        ExtensionEvidenceV1, ExtensionObservationV1, ExtensionOutputV1,
    };

    use super::*;
    use crate::extension::test_support;

    fn assert_error_contains<T>(result: Result<T>, expected: &str) {
        let error = result.err().expect("expected rejection");
        assert!(error.to_string().contains(expected), "unexpected error: {error}");
    }

    #[test]
    fn broker_private_boundaries_keep_their_exact_contracts() {
        assert_eq!(MAX_EXTENSION_VALUE_BYTES, 65_536);

        assert!(valid_required_text("a"));
        assert!(valid_required_text(&"a".repeat(MAX_EXTENSION_VALUE_BYTES)));
        assert!(!valid_required_text(""));
        assert!(!valid_required_text(" \t"));
        assert!(!valid_required_text(&"a".repeat(MAX_EXTENSION_VALUE_BYTES + 1)));
        assert!(!valid_required_text("line\nbreak"));

        assert!(valid_id("a0-_. /".replace(' ', "").as_str()));
        assert!(valid_id(&"a".repeat(128)));
        assert!(!valid_id(""));
        assert!(!valid_id(&"a".repeat(129)));
        assert!(!valid_id("Upper"));
        assert!(!valid_id("bad:value"));

        assert!(lower_sha256(&"0".repeat(64)));
        assert!(lower_sha256(&"f".repeat(64)));
        assert!(!lower_sha256(&"0".repeat(63)));
        assert!(!lower_sha256(&"0".repeat(65)));
        assert!(!lower_sha256(&"A".repeat(64)));
        assert!(!lower_sha256(&"g".repeat(64)));

        for (name, severity) in [
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("info", Severity::Info),
        ] {
            assert_eq!(parse_severity(name).expect("known severity"), severity);
        }
        assert!(parse_severity("unknown").is_err());

        let production =
            include_str!("broker.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert_eq!(compact.matches("if!valid_id(operation){").count(), 3);
        assert!(compact.contains(
            "if!matches!(url.scheme(),\"http\"|\"https\")||url.host_str().is_none()||!url.username().is_empty()||url.password().is_some()||url.fragment().is_some(){"
        ));
        assert!(compact.contains(
            "ifoutput.findings.len()>MAX_EXTENSION_FINDINGS||output.diagnostics.len()>MAX_EXTENSION_NESTED_ITEMS||output.diagnostics.iter().any(|value|!valid_required_text(value)){"
        ));
        assert!(compact.contains(
            "ifartifact_count>usize::try_from(manifest.budgets.artifacts).unwrap_or(usize::MAX)||artifact_bytes>manifest.budgets.artifact_bytes{"
        ));
        assert!(compact.contains(
            "if!proposed.confidence.is_finite()||!(0.0..=1.0).contains(&proposed.confidence){"
        ));
        assert!(compact.contains(
            "ifproposed.observations.len()>MAX_EXTENSION_NESTED_ITEMS||proposed.evidence.len()>MAX_EXTENSION_NESTED_ITEMS||proposed.source_artifacts.len()>usize::try_from(manifest.budgets.artifacts).unwrap_or(usize::MAX){"
        ));
        assert!(compact.contains(
            "if!valid_id(&observation.kind)||!valid_required_text(&observation.message)||observation.location.as_deref().is_some_and(|value|!valid_required_text(value)){"
        ));
        assert!(compact.contains(
            "if!valid_id(&artifact.id)||!valid_required_text(&artifact.media_type)||!lower_sha256(&artifact.sha256)||!artifact_ids.insert(artifact.id.clone())||sha256_hex(&artifact.bytes)!=artifact.sha256{"
        ));
        assert!(compact.contains(
            "if!valid_id(&evidence.kind)||serde_json::to_vec(&evidence.value).map_or(true,|value|value.len()>MAX_EXTENSION_VALUE_BYTES)||evidence.source_artifact_ids.iter().any(|identity|{!valid_id(identity)||!artifact_ids.contains(identity)||!references.insert(identity.as_str())}){"
        ));
        assert!(compact.contains(
            "!value.trim().is_empty()&&value.len()<=MAX_EXTENSION_VALUE_BYTES&&!value.chars().any(char::is_control)"
        ));
        assert!(compact.contains(
            "!value.is_empty()&&value.len()<=128&&value.bytes().all(|byte|{byte.is_ascii_lowercase()||byte.is_ascii_digit()||matches!(byte,b'-'|b'_'|b'.'|b'/')})"
        ));
        assert!(compact.contains(
            "value.len()==64&&value.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))"
        ));
    }

    #[test]
    fn safe_http_urls_reject_each_credential_and_target_ambiguity() {
        assert!(safe_url("https://example.com/path?visible=yes").is_ok());
        for rejected in [
            "ftp://example.com/path",
            "https://user@example.com/path",
            "https://example.com:password@example.org/path",
            "https://example.com/path#fragment",
        ] {
            assert!(safe_url(rejected).is_err(), "accepted unsafe URL: {rejected}");
        }
    }

    #[test]
    fn unsupported_effects_validate_their_operation_identity_before_denial() {
        let context = test_support::context();
        let mut manifest = test_support::manifest(b"module");
        manifest.capabilities = vec![
            ExtensionCapabilityV1::Filesystem,
            ExtensionCapabilityV1::Credential,
            ExtensionCapabilityV1::Subprocess,
        ];
        let invocation = test_support::invocation();
        for effect in [
            ExtensionEffectV1::Filesystem { operation: "INVALID".to_string() },
            ExtensionEffectV1::Credential { operation: "INVALID".to_string() },
            ExtensionEffectV1::Subprocess { operation: "INVALID".to_string() },
        ] {
            let request = ExtensionEffectRequestV1 { request_id: "request-1".to_string(), effect };
            let reason = prepare_effect(&context, &manifest, &invocation, &request)
                .err()
                .expect("invalid operation");
            assert!(reason.contains("operation is invalid"), "unexpected reason: {reason}");
        }
    }

    #[tokio::test]
    async fn bounded_body_accepts_the_limit_and_rejects_one_byte_more() {
        let exact = stream::iter(vec![Ok::<_, ()>(b"ab".to_vec()), Ok(b"cd".to_vec())]);
        assert_eq!(read_bounded_body(exact, 4).await.expect("exact body"), b"abcd");

        let overflow = stream::iter(vec![Ok::<_, ()>(b"abcd".to_vec()), Ok(b"e".to_vec())]);
        assert!(read_bounded_body(overflow, 4).await.is_err());

        let failed = stream::iter(vec![Err::<Vec<u8>, _>(())]);
        assert!(read_bounded_body(failed, 4).await.is_err());
    }

    #[test]
    fn output_collection_and_artifact_budgets_are_exact_and_independent() {
        let context = test_support::context();
        let invocation = test_support::invocation();
        let mut manifest = test_support::manifest(b"module");
        manifest.budgets.artifacts = u32::try_from(MAX_EXTENSION_FINDINGS).unwrap();
        let finding = test_support::finding();

        let exact_findings = ExtensionOutputV1 {
            findings: vec![finding.clone(); MAX_EXTENSION_FINDINGS],
            diagnostics: vec!["diagnostic".to_string(); MAX_EXTENSION_NESTED_ITEMS],
        };
        assert_eq!(
            convert_output(&context, &manifest, &invocation, exact_findings)
                .expect("exact collection boundaries")
                .len(),
            MAX_EXTENSION_FINDINGS
        );

        let too_many_findings = ExtensionOutputV1 {
            findings: vec![finding.clone(); MAX_EXTENSION_FINDINGS + 1],
            diagnostics: Vec::new(),
        };
        assert_error_contains(
            convert_output(&context, &manifest, &invocation, too_many_findings),
            "collection exceeds",
        );
        let too_many_diagnostics = ExtensionOutputV1 {
            findings: Vec::new(),
            diagnostics: vec!["diagnostic".to_string(); MAX_EXTENSION_NESTED_ITEMS + 1],
        };
        assert_error_contains(
            convert_output(&context, &manifest, &invocation, too_many_diagnostics),
            "collection exceeds",
        );
        let invalid_diagnostic =
            ExtensionOutputV1 { findings: Vec::new(), diagnostics: vec![String::new()] };
        assert_error_contains(
            convert_output(&context, &manifest, &invocation, invalid_diagnostic),
            "collection exceeds",
        );

        manifest.budgets.artifacts = 1;
        manifest.budgets.artifact_bytes = 8;
        assert!(convert_output(
            &context,
            &manifest,
            &invocation,
            ExtensionOutputV1 { findings: vec![finding.clone()], diagnostics: Vec::new() },
        )
        .is_ok());

        let mut count_overflow = finding.clone();
        count_overflow.source_artifacts.push(count_overflow.source_artifacts[0].clone());
        assert_error_contains(
            convert_output(
                &context,
                &manifest,
                &invocation,
                ExtensionOutputV1 { findings: vec![count_overflow], diagnostics: Vec::new() },
            ),
            "artifacts exceed",
        );
        let mut bytes_overflow = finding;
        bytes_overflow.source_artifacts[0].bytes.push(b'x');
        bytes_overflow.source_artifacts[0].sha256 =
            sha256_hex(&bytes_overflow.source_artifacts[0].bytes);
        assert_error_contains(
            convert_output(
                &context,
                &manifest,
                &invocation,
                ExtensionOutputV1 { findings: vec![bytes_overflow], diagnostics: Vec::new() },
            ),
            "artifacts exceed",
        );
    }

    #[test]
    fn finding_validation_observes_every_scalar_boundary() {
        let manifest = test_support::manifest(b"module");
        let valid = test_support::finding();
        assert!(validate_finding(&manifest, &valid).is_ok());

        for mutate in [
            |finding: &mut ExtensionFindingV1| finding.title.clear(),
            |finding: &mut ExtensionFindingV1| finding.description.clear(),
            |finding: &mut ExtensionFindingV1| finding.affected_target.clear(),
        ] as [fn(&mut ExtensionFindingV1); 3]
        {
            let mut finding = valid.clone();
            mutate(&mut finding);
            assert!(validate_finding(&manifest, &finding).is_err());
        }
        for mutate in [
            |finding: &mut ExtensionFindingV1| finding.remediation = Some(String::new()),
            |finding: &mut ExtensionFindingV1| finding.owasp_category = Some(String::new()),
        ] as [fn(&mut ExtensionFindingV1); 2]
        {
            let mut finding = valid.clone();
            mutate(&mut finding);
            assert!(validate_finding(&manifest, &finding).is_err());
        }
        for confidence in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            let mut finding = valid.clone();
            finding.confidence = confidence;
            assert!(validate_finding(&manifest, &finding).is_err());
        }
        for confidence in [0.0, 1.0] {
            let mut finding = valid.clone();
            finding.confidence = confidence;
            assert!(validate_finding(&manifest, &finding).is_ok());
        }
    }

    #[test]
    fn finding_validation_observes_nested_collection_boundaries() {
        let mut manifest = test_support::manifest(b"module");
        let valid = test_support::finding();
        let observation = ExtensionObservationV1 {
            kind: "trace".to_string(),
            message: "message".to_string(),
            location: Some("location".to_string()),
        };
        let evidence = ExtensionEvidenceV1 {
            kind: "record".to_string(),
            value: serde_json::json!({"bounded": true}),
            source_artifact_ids: vec!["artifact-1".to_string()],
        };
        let mut unreferenced_evidence = evidence.clone();
        unreferenced_evidence.source_artifact_ids.clear();
        manifest.budgets.artifacts = u32::try_from(MAX_EXTENSION_NESTED_ITEMS).unwrap();
        let artifacts = |count: usize| {
            (0..count)
                .map(|index| {
                    let bytes = format!("artifact-{index}").into_bytes();
                    ExtensionArtifactV1 {
                        id: format!("artifact-{index}"),
                        media_type: "text/plain".to_string(),
                        sha256: sha256_hex(&bytes),
                        bytes,
                    }
                })
                .collect::<Vec<_>>()
        };
        for (observations, evidence_values, artifact_values) in [
            (vec![observation.clone(); MAX_EXTENSION_NESTED_ITEMS], Vec::new(), Vec::new()),
            (Vec::new(), vec![unreferenced_evidence; MAX_EXTENSION_NESTED_ITEMS], Vec::new()),
            (Vec::new(), Vec::new(), artifacts(MAX_EXTENSION_NESTED_ITEMS)),
        ] {
            let mut finding = valid.clone();
            finding.observations = observations;
            finding.evidence = evidence_values;
            finding.source_artifacts = artifact_values;
            assert!(validate_finding(&manifest, &finding).is_ok());
        }
        for (observations, evidence_values, artifact_values) in [
            (vec![observation; MAX_EXTENSION_NESTED_ITEMS + 1], Vec::new(), Vec::new()),
            (Vec::new(), vec![evidence; MAX_EXTENSION_NESTED_ITEMS + 1], Vec::new()),
            (Vec::new(), Vec::new(), artifacts(MAX_EXTENSION_NESTED_ITEMS + 1)),
        ] {
            let mut finding = valid.clone();
            finding.observations = observations;
            finding.evidence = evidence_values;
            finding.source_artifacts = artifact_values;
            assert!(validate_finding(&manifest, &finding).is_err());
        }
    }

    #[test]
    fn finding_validation_observes_nested_identity_boundaries() {
        let mut manifest = test_support::manifest(b"module");
        let valid = test_support::finding();
        let observation = ExtensionObservationV1 {
            kind: "trace".to_string(),
            message: "message".to_string(),
            location: Some("location".to_string()),
        };
        let evidence = ExtensionEvidenceV1 {
            kind: "record".to_string(),
            value: serde_json::json!({"bounded": true}),
            source_artifact_ids: vec!["artifact-1".to_string()],
        };
        for mutate in [
            |value: &mut ExtensionObservationV1| value.kind = "INVALID".to_string(),
            |value: &mut ExtensionObservationV1| value.message.clear(),
            |value: &mut ExtensionObservationV1| value.location = Some(String::new()),
        ] {
            let mut finding = valid.clone();
            let mut value = observation.clone();
            mutate(&mut value);
            finding.observations = vec![value];
            assert!(validate_finding(&manifest, &finding).is_err());
        }

        let artifact = valid.source_artifacts[0].clone();
        let artifact_mutations: [fn(&mut ExtensionArtifactV1); 5] = [
            |value| value.id = "INVALID".to_string(),
            |value| value.media_type.clear(),
            |value| value.sha256 = "A".repeat(64),
            |value| value.sha256 = "0".repeat(64),
            |value| value.id.clear(),
        ];
        for mutate in artifact_mutations {
            let mut finding = valid.clone();
            let mut value = artifact.clone();
            mutate(&mut value);
            finding.source_artifacts = vec![value];
            assert!(validate_finding(&manifest, &finding).is_err());
        }
        let mut duplicate_artifact = valid.clone();
        duplicate_artifact.source_artifacts.push(artifact);
        manifest.budgets.artifacts = 2;
        assert!(validate_finding(&manifest, &duplicate_artifact).is_err());

        let evidence_mutations: [fn(&mut ExtensionEvidenceV1); 4] = [
            |value| value.kind = "INVALID".to_string(),
            |value| value.source_artifact_ids = vec!["INVALID".to_string()],
            |value| value.source_artifact_ids = vec!["missing".to_string()],
            |value| {
                value.source_artifact_ids =
                    vec!["artifact-1".to_string(), "artifact-1".to_string()];
            },
        ];
        for mutate in evidence_mutations {
            let mut finding = valid.clone();
            let mut value = evidence.clone();
            mutate(&mut value);
            finding.evidence = vec![value];
            assert!(validate_finding(&manifest, &finding).is_err());
        }
        let mut oversized_evidence = valid;
        oversized_evidence.evidence = vec![ExtensionEvidenceV1 {
            kind: "record".to_string(),
            value: serde_json::Value::String("x".repeat(MAX_EXTENSION_VALUE_BYTES + 1)),
            source_artifact_ids: vec!["artifact-1".to_string()],
        }];
        assert!(validate_finding(&manifest, &oversized_evidence).is_err());
    }
}
