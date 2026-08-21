use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::Engine as _;
use scorchkit_core::{
    ApplicationDastAuthenticationState, ApplicationDastCoverageGap, ApplicationDastGapKind,
    ApplicationDastPersonaAssessment, ApplicationDastPhase, ApplicationDastPhaseOutcome,
    ApplicationDastProfile, ApplicationDastRouteCoverage, CorrelationKey, Finding, HttpEvidence,
    HttpParameterIdentity, ObservationLocation, Result, ScannerProvenance, ScorchError, Severity,
};
use serde_json::Value;
use url::Url;

use crate::config::DastConfig;

use super::path_is_under;
use super::plan::{ResolvedPersona, ResolvedPersonaKind, ZAP_VERSION};
use super::schema::{SchemaOperation, ValidatedDastSchema};
use super::workspace::{
    DastWorkspace, ALERT_REPORT_FILE, PERSONA_REPORT_FILE, PRE_DISCOVERY_TRACE_FILE,
    TRAFFIC_REPORT_FILE, URL_REPORT_FILE,
};

#[derive(Clone)]
struct ObservedRequest {
    method: String,
    url: Url,
}

pub struct ParsedPersonaRun {
    pub findings: Vec<Finding>,
    pub assessment: ApplicationDastPersonaAssessment,
    pub gaps: Vec<ApplicationDastCoverageGap>,
}

pub struct PersonaRunInput<'a> {
    pub workspace: &'a DastWorkspace,
    pub target: &'a Url,
    pub profile: ApplicationDastProfile,
    pub persona: &'a ResolvedPersona,
    pub schemas: &'a [ValidatedDastSchema],
    pub plan_sha256: &'a str,
    pub exit_code: i32,
    pub config: &'a DastConfig,
}

pub fn parse_persona_run(input: &PersonaRunInput<'_>) -> Result<ParsedPersonaRun> {
    let alert_bytes =
        input.workspace.read_artifact(ALERT_REPORT_FILE, input.config.output_limit_bytes)?;
    let url_bytes =
        input.workspace.read_artifact(URL_REPORT_FILE, input.config.output_limit_bytes)?;
    let traffic_bytes =
        input.workspace.read_artifact(TRAFFIC_REPORT_FILE, input.config.output_limit_bytes)?;
    let report: Value = serde_json::from_slice(&alert_bytes).map_err(|error| {
        ScorchError::ToolOutputParse { tool: "zap".to_string(), reason: error.to_string() }
    })?;
    let report = report.as_object().ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: "Traditional JSON Plus report root is not an object".to_string(),
    })?;
    let (errors, warnings) = automation_messages(report)?;
    let errors: Vec<_> =
        errors.into_iter().map(|error| input.persona.redact_known_secrets(&error)).collect();
    let warnings: Vec<_> =
        warnings.into_iter().map(|warning| input.persona.redact_known_secrets(&warning)).collect();
    if input.exit_code == 2 && errors.is_empty() && warnings.is_empty() {
        return Err(ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "Automation Framework exited 2 without a report warning or error".to_string(),
        });
    }
    let observed_urls = parse_url_export(&url_bytes, input.target)?;
    let observed_requests = parse_traffic_export(&traffic_bytes, input.target)?;
    let operations: Vec<SchemaOperation> =
        input.schemas.iter().flat_map(|schema| schema.operations.iter().cloned()).collect();
    let routes = route_coverage(&operations, &observed_urls, &observed_requests);
    let findings =
        parse_alerts(report, input.target, input.persona, input.plan_sha256, &operations)?;
    let (authentication, gaps) = persona_authentication(input)?;
    let gaps = coverage_gaps(input.persona, &routes, &warnings, &errors, gaps);
    let phases = phase_outcomes(
        input.profile,
        input.persona,
        !input.schemas.is_empty(),
        authentication,
        &warnings,
        &errors,
    );
    Ok(ParsedPersonaRun {
        findings,
        assessment: ApplicationDastPersonaAssessment {
            persona: input.persona.id.clone(),
            authentication,
            plan_sha256: input.plan_sha256.to_string(),
            phases,
            routes,
            warnings,
        },
        gaps,
    })
}

fn persona_authentication(
    input: &PersonaRunInput<'_>,
) -> Result<(ApplicationDastAuthenticationState, Vec<ApplicationDastCoverageGap>)> {
    if input.persona.is_anonymous() {
        return Ok((ApplicationDastAuthenticationState::Anonymous, Vec::new()));
    }
    let trace_bytes =
        input.workspace.read_artifact(PRE_DISCOVERY_TRACE_FILE, input.config.output_limit_bytes)?;
    let trace_state = parse_authentication_trace(&trace_bytes, input.persona)?;
    let report_bytes =
        input.workspace.read_artifact(PERSONA_REPORT_FILE, input.config.output_limit_bytes)?;
    let (report_state, mut gaps) = parse_authentication(&report_bytes, input.persona)?;
    let authentication = combine_authentication_state(trace_state, report_state);
    if authentication != ApplicationDastAuthenticationState::Unknown {
        gaps.retain(|gap| gap.kind != ApplicationDastGapKind::ArtifactInvalid);
    }
    if trace_state == ApplicationDastAuthenticationState::Failed {
        gaps.push(ApplicationDastCoverageGap::new(
            &input.persona.id,
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::AuthenticationFailed,
            "the pre-discovery verification response did not prove the authenticated state",
        ));
    }
    Ok((authentication, gaps))
}

fn coverage_gaps(
    persona: &ResolvedPersona,
    routes: &[ApplicationDastRouteCoverage],
    warnings: &[String],
    errors: &[String],
    mut gaps: Vec<ApplicationDastCoverageGap>,
) -> Vec<ApplicationDastCoverageGap> {
    for route in routes.iter().filter(|route| !route.observed) {
        gaps.push(ApplicationDastCoverageGap::new(
            &persona.id,
            ApplicationDastPhase::UrlExport,
            ApplicationDastGapKind::RouteUnobserved,
            format!(
                "schema operation {} {} was not present in the exported URL set",
                route.method.as_deref().unwrap_or("ANY"),
                route.route
            ),
        ));
    }
    for warning in warnings {
        gaps.push(ApplicationDastCoverageGap::new(
            &persona.id,
            ApplicationDastPhase::AlertReport,
            ApplicationDastGapKind::PlanWarning,
            warning,
        ));
    }
    for error in errors {
        gaps.push(ApplicationDastCoverageGap::new(
            &persona.id,
            ApplicationDastPhase::AlertReport,
            ApplicationDastGapKind::ExecutionFailed,
            error,
        ));
    }
    gaps
}

fn phase_outcomes(
    profile: ApplicationDastProfile,
    persona: &ResolvedPersona,
    has_schemas: bool,
    authentication: ApplicationDastAuthenticationState,
    warnings: &[String],
    errors: &[String],
) -> Vec<ApplicationDastPhaseOutcome> {
    let mut phases = selected_phases(profile, persona, has_schemas);
    if !warnings.is_empty() {
        replace_phase(
            &mut phases,
            ApplicationDastPhase::AlertReport,
            ApplicationDastPhaseOutcome::incomplete(
                ApplicationDastPhase::AlertReport,
                "Automation Framework reported one or more warnings",
            ),
        );
    }
    if !errors.is_empty() {
        replace_phase(
            &mut phases,
            ApplicationDastPhase::AlertReport,
            ApplicationDastPhaseOutcome::failed(
                ApplicationDastPhase::AlertReport,
                "Automation Framework reported one or more errors",
            ),
        );
    }
    if matches!(
        authentication,
        ApplicationDastAuthenticationState::Failed
            | ApplicationDastAuthenticationState::Lost
            | ApplicationDastAuthenticationState::Unknown
    ) {
        replace_phase(
            &mut phases,
            ApplicationDastPhase::Authentication,
            ApplicationDastPhaseOutcome::failed(
                ApplicationDastPhase::Authentication,
                "authenticated state was not proven for the complete persona run",
            ),
        );
    }
    phases
}

fn automation_messages(
    report: &serde_json::Map<String, Value>,
) -> Result<(Vec<String>, Vec<String>)> {
    let errors = report.get("afPlanErrors").or_else(|| {
        report
            .get("af")
            .or_else(|| report.get("automationFramework"))
            .and_then(Value::as_object)
            .and_then(|af| af.get("errors"))
    });
    let warnings = report.get("afPlanWarns").or_else(|| {
        report
            .get("af")
            .or_else(|| report.get("automationFramework"))
            .and_then(Value::as_object)
            .and_then(|af| af.get("warnings"))
    });
    if errors.is_none() || warnings.is_none() {
        return Err(ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "Traditional JSON Plus report has no Automation Framework state".to_string(),
        });
    }
    Ok((message_array(errors)?, message_array(warnings)?))
}

fn message_array(value: Option<&Value>) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: "Automation Framework diagnostics must be arrays".to_string(),
    })?;
    Ok(values
        .iter()
        .map(|value| match value {
            Value::String(value) => value.clone(),
            Value::Object(value) => value
                .get("message")
                .or_else(|| value.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("Automation Framework diagnostic")
                .to_string(),
            _ => "Automation Framework diagnostic".to_string(),
        })
        .collect())
}

fn parse_url_export(bytes: &[u8], target: &Url) -> Result<Vec<Url>> {
    let text = std::str::from_utf8(bytes).map_err(|error| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: format!("URL export is not UTF-8: {error}"),
    })?;
    let mut urls = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let url = Url::parse(line).map_err(|error| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: format!("URL export line {} is invalid: {error}", index.saturating_add(1)),
        })?;
        if !same_origin(target, &url) || !path_is_under(target.path(), url.path()) {
            return Err(ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: format!("URL export contains an out-of-scope URL: {url}"),
            });
        }
        urls.push(url);
    }
    urls.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    urls.dedup_by(|left, right| left.as_str() == right.as_str());
    Ok(urls)
}

fn parse_traffic_export(bytes: &[u8], target: &Url) -> Result<Vec<ObservedRequest>> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: format!("traffic HAR is invalid: {error}"),
        })?;
    let entries =
        value.get("log").and_then(|log| log.get("entries")).and_then(Value::as_array).ok_or_else(
            || ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "traffic HAR has no entries array".to_string(),
            },
        )?;
    let mut requests = Vec::with_capacity(entries.len());
    for entry in entries {
        let request = entry.get("request").and_then(Value::as_object).ok_or_else(|| {
            ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "traffic HAR entry has no request object".to_string(),
            }
        })?;
        let method = request.get("method").and_then(Value::as_str).ok_or_else(|| {
            ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "traffic HAR request has no method".to_string(),
            }
        })?;
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| {
            ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "traffic HAR request method is invalid".to_string(),
            }
        })?;
        let url = request.get("url").and_then(Value::as_str).ok_or_else(|| {
            ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "traffic HAR request has no URL".to_string(),
            }
        })?;
        let url = Url::parse(url).map_err(|error| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: format!("traffic HAR request URL is invalid: {error}"),
        })?;
        if !same_origin(target, &url) || !path_is_under(target.path(), url.path()) {
            return Err(ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "traffic HAR contains an out-of-scope request URL".to_string(),
            });
        }
        requests.push(ObservedRequest { method: method.as_str().to_string(), url });
    }
    requests.sort_by(|left, right| {
        (&left.url.as_str(), &left.method).cmp(&(&right.url.as_str(), &right.method))
    });
    requests.dedup_by(|left, right| left.method == right.method && left.url == right.url);
    Ok(requests)
}

fn route_coverage(
    operations: &[SchemaOperation],
    observed_urls: &[Url],
    observed_requests: &[ObservedRequest],
) -> Vec<ApplicationDastRouteCoverage> {
    let mut routes: Vec<_> = operations
        .iter()
        .map(|operation| ApplicationDastRouteCoverage {
            route: operation.route.clone(),
            method: Some(operation.method.clone()),
            operation_id: operation.operation_id.clone(),
            schema_sha256: Some(operation.schema_sha256.clone()),
            observed: observed_requests.iter().any(|request| {
                request.method.eq_ignore_ascii_case(&operation.method)
                    && route_matches(&operation.route, request.url.path())
            }),
        })
        .collect();
    let expected: BTreeSet<String> =
        operations.iter().map(|operation| operation.route.clone()).collect();
    let observed_paths: BTreeSet<_> = observed_urls.iter().map(Url::path).collect();
    for route in observed_paths {
        if !expected.iter().any(|expected| route_matches(expected, route)) {
            routes.push(ApplicationDastRouteCoverage {
                route: route.to_string(),
                method: None,
                operation_id: None,
                schema_sha256: None,
                observed: true,
            });
        }
    }
    routes.sort_by(|left, right| {
        (&left.route, &left.method, &left.operation_id).cmp(&(
            &right.route,
            &right.method,
            &right.operation_id,
        ))
    });
    routes
}

fn parse_alerts(
    report: &serde_json::Map<String, Value>,
    target: &Url,
    persona: &ResolvedPersona,
    plan_sha256: &str,
    operations: &[SchemaOperation],
) -> Result<Vec<Finding>> {
    let sites = report.get("site").map_or(Ok(&[][..]), value_as_slice)?;
    let mut findings = Vec::new();
    for site in sites {
        let site = site.as_object().ok_or_else(|| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "Traditional JSON Plus site entry is not an object".to_string(),
        })?;
        for alert in site.get("alerts").map_or(Ok(&[][..]), value_as_slice)? {
            parse_alert_instances(alert, target, persona, plan_sha256, operations, &mut findings)?;
        }
    }
    Ok(findings)
}

fn parse_alert_instances(
    alert: &Value,
    target: &Url,
    persona: &ResolvedPersona,
    plan_sha256: &str,
    operations: &[SchemaOperation],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let alert = alert.as_object().ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: "Traditional JSON Plus alert entry is not an object".to_string(),
    })?;
    let instances = alert.get("instances").map_or(Ok(&[][..]), value_as_slice)?;
    let parsed = ParsedAlert {
        plugin_id: required_text(alert, &["pluginid", "pluginId"])?,
        alert_ref: optional_text(alert, &["alertRef", "alertref"]),
        title: persona.redact_known_secrets(required_text(alert, &["alert", "name"])?),
        description: persona.redact_known_secrets(
            optional_text(alert, &["desc", "description"])
                .unwrap_or("OWASP ZAP reported an application security alert."),
        ),
        severity: severity(alert.get("riskcode").or_else(|| alert.get("riskCode"))),
        confidence: confidence(alert.get("confidence")),
        cwe: optional_u32(alert.get("cweid").or_else(|| alert.get("cweId"))),
        remediation: optional_text(alert, &["solution"])
            .map(|value| persona.redact_known_secrets(value)),
    };
    for instance in instances {
        findings.push(parse_alert_instance(
            &parsed,
            instance,
            target,
            persona,
            plan_sha256,
            operations,
        )?);
    }
    Ok(())
}

struct ParsedAlert<'a> {
    plugin_id: &'a str,
    alert_ref: Option<&'a str>,
    title: String,
    description: String,
    severity: Severity,
    confidence: f64,
    cwe: Option<u32>,
    remediation: Option<String>,
}

fn parse_alert_instance(
    alert: &ParsedAlert<'_>,
    instance: &Value,
    target: &Url,
    persona: &ResolvedPersona,
    plan_sha256: &str,
    operations: &[SchemaOperation],
) -> Result<Finding> {
    let instance = instance.as_object().ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: format!("ZAP alert {} has a non-object instance", alert.plugin_id),
    })?;
    let uri = required_text(instance, &["uri", "url"])?;
    let parsed_uri = Url::parse(uri).map_err(|error| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: format!("ZAP alert {} has an invalid URI: {error}", alert.plugin_id),
    })?;
    if !same_origin(target, &parsed_uri) || !path_is_under(target.path(), parsed_uri.path()) {
        return Err(ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: format!("ZAP alert {} contains an out-of-scope URI", alert.plugin_id),
        });
    }
    let public_uri = persona.redact_known_secrets(uri);
    let method = optional_text(instance, &["method"]).unwrap_or("UNKNOWN");
    let route = Some(parsed_uri.path().to_string());
    let parameter = optional_text(instance, &["param", "parameter"])
        .filter(|value| !value.is_empty())
        .map(|name| HttpParameterIdentity::new(name, "unknown"));
    let operation = route.as_deref().and_then(|route| {
        operations.iter().find(|operation| {
            operation.method.eq_ignore_ascii_case(method) && route_matches(&operation.route, route)
        })
    });
    let mut finding =
        Finding::new("zap", alert.severity, &alert.title, &alert.description, &public_uri)
            .with_confidence(alert.confidence)
            .with_location(ObservationLocation::Runtime {
                uri: public_uri.clone(),
                route: route.clone(),
                parameter: parameter.clone(),
            })
            .with_provenance(
                ScannerProvenance::new("zap", chrono::Utc::now())
                    .with_version(ZAP_VERSION)
                    .with_rule(alert.plugin_id, None)
                    .with_config(plan_sha256),
            )
            .with_correlation_key(CorrelationKey::new("dast-persona", &persona.id));
    if let Some(cwe) = alert.cwe {
        finding = finding.with_cwe(cwe);
    }
    if let Some(remediation) = &alert.remediation {
        finding = finding.with_remediation(remediation);
    }
    if let Some(evidence) = optional_text(instance, &["evidence"]).filter(|value| !value.is_empty())
    {
        finding = finding.with_evidence(persona.redact_known_secrets(evidence));
    }
    if let Some(operation) = operation {
        finding = finding
            .with_correlation_key(CorrelationKey::new("dast-schema", &operation.schema_sha256))
            .with_correlation_key(CorrelationKey::new(
                "dast-operation",
                operation.operation_id.as_deref().unwrap_or(operation.route.as_str()),
            ));
    }
    finding = finding.with_structured_evidence(serde_json::json!({
        "schema": "scorchkit.zap-alert/v1",
        "plugin_id": alert.plugin_id,
        "alert_ref": alert.alert_ref,
        "persona": persona.id,
        "route": route,
        "plan_sha256": plan_sha256,
        "operation_id": operation.and_then(|operation| operation.operation_id.as_deref()),
        "schema_sha256": operation.map(|operation| operation.schema_sha256.as_str()),
    }));
    let mut http = HttpEvidence::new(method, &public_uri, response_status(instance))
        .with_authentication_persona(&persona.id);
    if let Some(route) = route {
        http = http.with_route(route);
    }
    if let Some(parameter) = parameter {
        http = http.with_parameter(parameter);
    }
    if let Some(headers) = optional_text(instance, &["request-header", "requestHeader"]) {
        http = http.with_request_headers(redact_header_values(parse_headers(headers), persona));
    }
    if let Some(body) = optional_text(instance, &["request-body", "requestBody"]) {
        http = http.with_request_body(persona.redact_known_secrets(body));
    }
    if let Some(headers) = optional_text(instance, &["response-header", "responseHeader"]) {
        http = http.with_response_headers(redact_header_values(parse_headers(headers), persona));
    }
    if let Some(body) = optional_text(instance, &["response-body", "responseBody"]) {
        http = http.with_response_body(persona.redact_known_secrets(body));
    }
    Ok(finding.with_http_evidence(http))
}

fn parse_authentication_trace(
    bytes: &[u8],
    persona: &ResolvedPersona,
) -> Result<ApplicationDastAuthenticationState> {
    let verification = persona.verification().ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: "named persona has no authentication verification rule".to_string(),
    })?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: format!("authentication trace is invalid: {error}"),
        })?;
    let entries =
        value.get("log").and_then(|log| log.get("entries")).and_then(Value::as_array).ok_or_else(
            || ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "authentication trace has no HAR entries".to_string(),
            },
        )?;
    let expected_url = Url::parse(&verification.url).map_err(|_| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: "authentication verification URL is invalid".to_string(),
    })?;
    for entry in entries.iter().rev().filter(|entry| {
        entry
            .get("request")
            .and_then(|request| request.get("url"))
            .and_then(Value::as_str)
            .and_then(|url| Url::parse(url).ok())
            .is_some_and(|url| url == expected_url)
    }) {
        if authentication_trace_entry_is_verified(entry, persona, verification)? {
            return Ok(ApplicationDastAuthenticationState::Verified);
        }
    }
    Ok(ApplicationDastAuthenticationState::Failed)
}

fn authentication_trace_entry_is_verified(
    entry: &Value,
    persona: &ResolvedPersona,
    verification: &crate::config::DastVerificationConfig,
) -> Result<bool> {
    let request = entry.get("request").and_then(Value::as_object).ok_or_else(|| {
        ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "authentication trace request is not an object".to_string(),
        }
    })?;
    let response = entry.get("response").and_then(Value::as_object).ok_or_else(|| {
        ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "authentication trace response is not an object".to_string(),
        }
    })?;
    let method_matches = request
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method.eq_ignore_ascii_case("GET"));
    let status_matches = response
        .get("status")
        .and_then(Value::as_u64)
        .is_some_and(|status| status == u64::from(verification.expected_status));
    let header_matches = match &persona.kind {
        ResolvedPersonaKind::Header { header_name, header_value, .. } => {
            request.get("headers").and_then(Value::as_array).is_some_and(|headers| {
                headers.iter().any(|header| {
                    header
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name.eq_ignore_ascii_case(header_name))
                        && header.get("value").and_then(Value::as_str) == Some(header_value)
                })
            })
        }
        ResolvedPersonaKind::Browser { .. } => true,
        ResolvedPersonaKind::Anonymous => false,
    };
    let content = response.get("content").and_then(Value::as_object).ok_or_else(|| {
        ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "authentication trace response has no content".to_string(),
        }
    })?;
    let body = content.get("text").and_then(Value::as_str).unwrap_or_default();
    let body = match content.get("encoding").and_then(Value::as_str) {
        None => body.as_bytes().to_vec(),
        Some("base64") => base64::engine::general_purpose::STANDARD.decode(body).map_err(|_| {
            ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "authentication trace response has invalid base64 content".to_string(),
            }
        })?,
        Some(_) => {
            return Err(ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "authentication trace response uses an unsupported encoding".to_string(),
            });
        }
    };
    let body = String::from_utf8_lossy(&body);
    let logged_in = regex::Regex::new(&verification.logged_in_regex)
        .map_err(|_| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "authentication trace logged-in matcher is invalid".to_string(),
        })?
        .is_match(&body);
    let logged_out = regex::Regex::new(&verification.logged_out_regex)
        .map_err(|_| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "authentication trace logged-out matcher is invalid".to_string(),
        })?
        .is_match(&body);
    Ok(method_matches && status_matches && header_matches && logged_in && !logged_out)
}

fn combine_authentication_state(
    trace: ApplicationDastAuthenticationState,
    report: ApplicationDastAuthenticationState,
) -> ApplicationDastAuthenticationState {
    if trace == ApplicationDastAuthenticationState::Failed
        || report == ApplicationDastAuthenticationState::Failed
    {
        ApplicationDastAuthenticationState::Failed
    } else if report == ApplicationDastAuthenticationState::Lost {
        ApplicationDastAuthenticationState::Lost
    } else if trace == ApplicationDastAuthenticationState::Verified
        && matches!(
            report,
            ApplicationDastAuthenticationState::Verified
                | ApplicationDastAuthenticationState::Unknown
        )
    {
        ApplicationDastAuthenticationState::Verified
    } else {
        ApplicationDastAuthenticationState::Unknown
    }
}

fn parse_authentication(
    bytes: &[u8],
    persona: &ResolvedPersona,
) -> Result<(ApplicationDastAuthenticationState, Vec<ApplicationDastCoverageGap>)> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: format!("authentication report is invalid: {error}"),
        })?;
    if !value.is_object() {
        return Err(ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "authentication report root is not an object".to_string(),
        });
    }
    let mut numbers = BTreeMap::new();
    collect_numbers(&value, String::new(), &mut numbers);
    if let Some(statistics) = value.get("statistics").and_then(Value::as_array) {
        for statistic in statistics {
            if let Some(statistic) = statistic.as_object() {
                if let (Some(key), Some(number)) = (
                    statistic.get("key").and_then(Value::as_str),
                    statistic.get("value").and_then(number_value),
                ) {
                    numbers.insert(key.to_ascii_lowercase(), number);
                }
            }
        }
    }
    let success = statistic(&numbers, &["stats.auth.success", "auth.success"]);
    let logged_in = statistic(&numbers, &["stats.auth.state.loggedin", "loggedin"]);
    let logged_out = statistic(&numbers, &["stats.auth.state.loggedout", "loggedout"]);
    let explicit = auth_summary(&value).or_else(|| find_auth_boolean(&value));
    let max_logged_out =
        persona.verification().map_or(0, |verification| verification.max_logged_out);
    let state = if logged_out.is_some_and(|count| count > max_logged_out) {
        ApplicationDastAuthenticationState::Lost
    } else if explicit == Some(true)
        || success.is_some_and(|count| count > 0) && logged_in.is_some_and(|count| count > 0)
    {
        ApplicationDastAuthenticationState::Verified
    } else if explicit == Some(false) || success == Some(0) || logged_in == Some(0) {
        ApplicationDastAuthenticationState::Failed
    } else {
        ApplicationDastAuthenticationState::Unknown
    };
    let gap = match state {
        ApplicationDastAuthenticationState::Failed => Some(ApplicationDastCoverageGap::new(
            &persona.id,
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::AuthenticationFailed,
            "ZAP did not prove an authenticated state",
        )),
        ApplicationDastAuthenticationState::Lost => Some(ApplicationDastCoverageGap::new(
            &persona.id,
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::AuthenticationLost,
            "ZAP observed the persona in a logged-out state during the run",
        )),
        ApplicationDastAuthenticationState::Unknown => Some(ApplicationDastCoverageGap::new(
            &persona.id,
            ApplicationDastPhase::Authentication,
            ApplicationDastGapKind::ArtifactInvalid,
            "authentication report did not contain conclusive authentication statistics",
        )),
        ApplicationDastAuthenticationState::Anonymous
        | ApplicationDastAuthenticationState::Verified => None,
    };
    Ok((state, gap.into_iter().collect()))
}

fn collect_numbers(value: &Value, prefix: String, output: &mut BTreeMap<String, u64>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let key = key.to_ascii_lowercase();
                let path = if prefix.is_empty() { key } else { format!("{prefix}.{key}") };
                collect_numbers(value, path, output);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_numbers(value, prefix.clone(), output);
            }
        }
        Value::Number(number) => {
            if let Some(number) = number.as_u64() {
                output.insert(prefix, number);
            }
        }
        Value::String(number) => {
            if let Ok(number) = number.parse::<u64>() {
                output.insert(prefix, number);
            }
        }
        _ => {}
    }
}

fn number_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn auth_summary(value: &Value) -> Option<bool> {
    value
        .get("summaryItems")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_object)
        .find(|item| item.get("key").and_then(Value::as_str) == Some("auth.summary.auth"))
        .and_then(|item| item.get("passed"))
        .and_then(Value::as_bool)
}

fn statistic(numbers: &BTreeMap<String, u64>, endings: &[&str]) -> Option<u64> {
    numbers
        .iter()
        .filter_map(|(key, value)| {
            endings.iter().any(|ending| key.ends_with(ending)).then_some(*value)
        })
        .max()
}

fn find_auth_boolean(value: &Value) -> Option<bool> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "authenticated" | "authsuccessful" | "success"
                ) {
                    if let Some(value) = value.as_bool() {
                        return Some(value);
                    }
                }
                if let Some(value) = find_auth_boolean(value) {
                    return Some(value);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(find_auth_boolean),
        _ => None,
    }
}

fn selected_phases(
    profile: ApplicationDastProfile,
    persona: &ResolvedPersona,
    has_schemas: bool,
) -> Vec<ApplicationDastPhaseOutcome> {
    let mut phases = Vec::new();
    if !persona.is_anonymous() {
        phases.push(ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::Authentication));
    }
    if has_schemas {
        phases.push(ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::SchemaImport));
    }
    phases.extend([
        ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::TraditionalSpider),
        ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::PassiveScan),
    ]);
    if profile.uses_client_spider() {
        phases.push(ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::ClientSpider));
    }
    if profile.uses_active_scan() {
        phases.push(ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::ActiveScan));
    }
    phases.extend([
        ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::UrlExport),
        ApplicationDastPhaseOutcome::complete(ApplicationDastPhase::AlertReport),
    ]);
    if !persona.is_anonymous() {
        phases.push(ApplicationDastPhaseOutcome::complete(
            ApplicationDastPhase::AuthenticationReport,
        ));
    }
    phases
}

fn replace_phase(
    phases: &mut [ApplicationDastPhaseOutcome],
    phase: ApplicationDastPhase,
    replacement: ApplicationDastPhaseOutcome,
) {
    if let Some(value) = phases.iter_mut().find(|value| value.phase == phase) {
        *value = replacement;
    }
}

fn value_as_slice(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Array(values) => Ok(values),
        Value::Null => Ok(&[]),
        _ => Err(ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "Traditional JSON Plus collection is not an array".to_string(),
        }),
    }
}

fn required_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    names: &[&str],
) -> Result<&'a str> {
    optional_text(object, names).ok_or_else(|| ScorchError::ToolOutputParse {
        tool: "zap".to_string(),
        reason: format!("Traditional JSON Plus field '{}' is missing", names[0]),
    })
}

fn optional_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    names: &[&str],
) -> Option<&'a str> {
    names.iter().find_map(|name| object.get(*name).and_then(Value::as_str))
}

fn optional_u32(value: Option<&Value>) -> Option<u32> {
    value.and_then(|value| match value {
        Value::Number(value) => value.as_u64().and_then(|value| u32::try_from(value).ok()),
        Value::String(value) => value.parse().ok(),
        _ => None,
    })
}

fn severity(value: Option<&Value>) -> Severity {
    match numeric_text(value) {
        Some(4) => Severity::Critical,
        Some(3) => Severity::High,
        Some(2) => Severity::Medium,
        Some(1) => Severity::Low,
        _ => Severity::Info,
    }
}

fn confidence(value: Option<&Value>) -> f64 {
    match numeric_text(value) {
        Some(3) => 0.9,
        Some(2) => 0.75,
        Some(1) => 0.55,
        Some(0) => 0.2,
        _ => 0.5,
    }
}

fn numeric_text(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    })
}

fn response_status(instance: &serde_json::Map<String, Value>) -> u16 {
    optional_text(instance, &["response-header", "responseHeader"])
        .and_then(|headers| headers.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn parse_headers(value: &str) -> HashMap<String, String> {
    value
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn redact_header_values(
    headers: HashMap<String, String>,
    persona: &ResolvedPersona,
) -> HashMap<String, String> {
    headers.into_iter().map(|(name, value)| (name, persona.redact_known_secrets(&value))).collect()
}

fn route_matches(template: &str, observed: &str) -> bool {
    let expected: Vec<_> = template.trim_matches('/').split('/').collect();
    let observed: Vec<_> = observed.trim_matches('/').split('/').collect();
    expected.len() == observed.len()
        && expected.iter().zip(observed).all(|(expected, observed)| {
            (expected.starts_with('{') && expected.ends_with('}')) || *expected == observed
        })
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anonymous_persona() -> ResolvedPersona {
        ResolvedPersona {
            id: "anonymous".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Anonymous,
        }
    }

    fn header_persona() -> ResolvedPersona {
        ResolvedPersona {
            id: "user".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Header {
                header_name: "X-Session".to_string(),
                header_value: "fixture-secret".to_string(),
                verification: crate::config::DastVerificationConfig {
                    url: "https://example.com/app/account".to_string(),
                    expected_status: 200,
                    logged_in_regex: "Account".to_string(),
                    logged_out_regex: "Sign in".to_string(),
                    max_logged_out: 0,
                },
            },
        }
    }

    fn workspace_with_report(report: &[u8], urls: &[u8]) -> DastWorkspace {
        let workspace = DastWorkspace::create().expect("DAST workspace");
        std::fs::write(workspace.root().join(ALERT_REPORT_FILE), report).expect("alert report");
        std::fs::write(workspace.root().join(URL_REPORT_FILE), urls).expect("URL report");
        let entries = std::str::from_utf8(urls)
            .expect("URL fixture")
            .lines()
            .filter(|url| !url.trim().is_empty())
            .map(|url| {
                serde_json::json!({
                    "request": {"method": "GET", "url": url.trim()}
                })
            })
            .collect::<Vec<_>>();
        std::fs::write(
            workspace.root().join(TRAFFIC_REPORT_FILE),
            serde_json::to_vec(&serde_json::json!({"log": {"entries": entries}}))
                .expect("traffic HAR fixture"),
        )
        .expect("traffic HAR report");
        workspace
    }

    #[test]
    fn route_templates_match_one_segment_only() {
        assert!(route_matches("/users", "/users"));
        assert!(route_matches("/users/{id}", "/users/42"));
        assert!(route_matches("/users/{id}/posts", "/users/42/posts"));
        assert!(!route_matches("/users/{id}", "/users/42/profile"));
        assert!(!route_matches("/users/{id}", "/admin/42"));
        assert!(!route_matches("/users/{id", "/users/42"));
        assert!(!route_matches("/users/id}", "/users/42"));
    }

    #[test]
    fn route_coverage_requires_the_schema_operation_method() {
        let operation = SchemaOperation {
            route: "/app/users".to_string(),
            method: "POST".to_string(),
            operation_id: Some("createUser".to_string()),
            schema_sha256: "aa".to_string(),
        };
        let url = Url::parse("https://example.com/app/users").expect("URL");
        let get = ObservedRequest { method: "GET".to_string(), url: url.clone() };
        let post = ObservedRequest { method: "POST".to_string(), url: url.clone() };

        assert!(
            !route_coverage(std::slice::from_ref(&operation), std::slice::from_ref(&url), &[get])
                [0]
            .observed
        );
        assert!(route_coverage(&[operation], &[url], &[post])[0].observed);
    }

    #[test]
    fn traffic_export_rejects_out_of_scope_and_invalid_methods() {
        let target = Url::parse("https://example.com/app").expect("target");
        let outside = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://outside.example/app"}}]}}"#;
        assert!(parse_traffic_export(outside, &target).is_err());
        let sibling = br#"{"log":{"entries":[{"request":{"method":"GET","url":"https://example.com/application"}}]}}"#;
        assert!(parse_traffic_export(sibling, &target).is_err());
        let invalid = br#"{"log":{"entries":[{"request":{"method":"GET BAD","url":"https://example.com/app"}}]}}"#;
        assert!(parse_traffic_export(invalid, &target).is_err());

        let duplicate = br#"{"log":{"entries":[
            {"request":{"method":"POST","url":"https://example.com/app/items"}},
            {"request":{"method":"GET","url":"https://example.com/app/items"}},
            {"request":{"method":"POST","url":"https://example.com/app/items"}}
        ]}}"#;
        let requests = parse_traffic_export(duplicate, &target).expect("traffic export");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[1].method, "POST");
    }

    #[test]
    fn authentication_statistics_distinguish_loss() {
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Header {
                header_name: "Authorization".to_string(),
                header_value: "fixture-secret".to_string(),
                verification: crate::config::DastVerificationConfig {
                    url: "https://example.com/me".to_string(),
                    expected_status: 200,
                    logged_in_regex: "user".to_string(),
                    logged_out_regex: "login".to_string(),
                    max_logged_out: 0,
                },
            },
        };
        let (state, gaps) = parse_authentication(
            br#"{"statistics":{"stats.auth.success":1,"stats.auth.state.loggedin":2,"stats.auth.state.loggedout":1}}"#,
            &persona,
        )
        .expect("auth");
        assert_eq!(state, ApplicationDastAuthenticationState::Lost);
        assert_eq!(gaps[0].kind, ApplicationDastGapKind::AuthenticationLost);
    }

    #[test]
    fn authentication_statistics_use_the_safest_matching_count() {
        let numbers = BTreeMap::from([
            ("a.loggedout".to_string(), 0),
            ("z.stats.auth.state.loggedout".to_string(), 3),
        ]);

        assert_eq!(statistic(&numbers, &["stats.auth.state.loggedout", "loggedout"]), Some(3));
    }

    #[test]
    fn pre_discovery_trace_requires_the_secret_header_and_logged_in_response() {
        let persona = header_persona();
        let trace = br#"{
            "log":{"entries":[{
                "request":{
                    "method":"GET",
                    "url":"https://example.com/app/account",
                    "headers":[{"name":"X-Session","value":"fixture-secret"}]
                },
                "response":{"status":200,"content":{"text":"Account"}}
            }]}
        }"#;
        assert_eq!(
            parse_authentication_trace(trace, &persona).expect("authentication trace"),
            ApplicationDastAuthenticationState::Verified
        );

        let missing_header = String::from_utf8_lossy(trace).replace("fixture-secret", "wrong");
        assert_eq!(
            parse_authentication_trace(missing_header.as_bytes(), &persona)
                .expect("failed authentication trace"),
            ApplicationDastAuthenticationState::Failed
        );
        let logged_out = String::from_utf8_lossy(trace).replace("Account", "Sign in");
        assert_eq!(
            parse_authentication_trace(logged_out.as_bytes(), &persona)
                .expect("logged-out authentication trace"),
            ApplicationDastAuthenticationState::Failed
        );
    }

    #[test]
    fn trace_proof_survives_an_empty_manual_auth_report_but_not_loss() {
        for (trace, report, expected) in [
            (
                ApplicationDastAuthenticationState::Verified,
                ApplicationDastAuthenticationState::Unknown,
                ApplicationDastAuthenticationState::Verified,
            ),
            (
                ApplicationDastAuthenticationState::Verified,
                ApplicationDastAuthenticationState::Verified,
                ApplicationDastAuthenticationState::Verified,
            ),
            (
                ApplicationDastAuthenticationState::Verified,
                ApplicationDastAuthenticationState::Lost,
                ApplicationDastAuthenticationState::Lost,
            ),
            (
                ApplicationDastAuthenticationState::Failed,
                ApplicationDastAuthenticationState::Verified,
                ApplicationDastAuthenticationState::Failed,
            ),
            (
                ApplicationDastAuthenticationState::Unknown,
                ApplicationDastAuthenticationState::Failed,
                ApplicationDastAuthenticationState::Failed,
            ),
            (
                ApplicationDastAuthenticationState::Unknown,
                ApplicationDastAuthenticationState::Verified,
                ApplicationDastAuthenticationState::Unknown,
            ),
        ] {
            assert_eq!(combine_authentication_state(trace, report), expected);
        }
    }

    #[test]
    fn authentication_accepts_the_pinned_report_array_shape() {
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Header {
                header_name: "Authorization".to_string(),
                header_value: "fixture-secret".to_string(),
                verification: crate::config::DastVerificationConfig::default(),
            },
        };
        let (state, gaps) = parse_authentication(
            br#"{
                "summaryItems":[{"key":"auth.summary.auth","passed":true}],
                "statistics":[
                    {"key":"stats.auth.success","scope":"global","value":1},
                    {"key":"stats.auth.state.loggedin","scope":"site","value":2},
                    {"key":"stats.auth.state.loggedout","scope":"site","value":0}
                ],
                "afPlanErrors":[]
            }"#,
            &persona,
        )
        .expect("auth report");
        assert_eq!(state, ApplicationDastAuthenticationState::Verified);
        assert!(gaps.is_empty());
    }

    #[test]
    fn authentication_state_thresholds_are_exact() {
        let mut persona = header_persona();
        let ResolvedPersonaKind::Header { verification, .. } = &mut persona.kind else {
            panic!("header fixture");
        };
        verification.max_logged_out = 1;

        for (report, expected, gap) in [
            (
                r#"{"summaryItems":[{"key":"auth.summary.auth","passed":true}]}"#,
                ApplicationDastAuthenticationState::Verified,
                None,
            ),
            (
                r#"{"statistics":{"stats.auth.success":"1","stats.auth.state.loggedin":1,"stats.auth.state.loggedout":1}}"#,
                ApplicationDastAuthenticationState::Verified,
                None,
            ),
            (
                r#"{"statistics":{"stats.auth.success":1,"stats.auth.state.loggedin":1,"stats.auth.state.loggedout":2}}"#,
                ApplicationDastAuthenticationState::Lost,
                Some(ApplicationDastGapKind::AuthenticationLost),
            ),
            (
                r#"{"summaryItems":[{"key":"auth.summary.auth","passed":false}]}"#,
                ApplicationDastAuthenticationState::Failed,
                Some(ApplicationDastGapKind::AuthenticationFailed),
            ),
            (
                r#"{"statistics":{"stats.auth.success":0,"stats.auth.state.loggedin":3}}"#,
                ApplicationDastAuthenticationState::Failed,
                Some(ApplicationDastGapKind::AuthenticationFailed),
            ),
            (
                r#"{"statistics":{"stats.auth.success":3,"stats.auth.state.loggedin":0}}"#,
                ApplicationDastAuthenticationState::Failed,
                Some(ApplicationDastGapKind::AuthenticationFailed),
            ),
            (
                "{}",
                ApplicationDastAuthenticationState::Unknown,
                Some(ApplicationDastGapKind::ArtifactInvalid),
            ),
        ] {
            let (state, gaps) =
                parse_authentication(report.as_bytes(), &persona).expect("authentication report");
            assert_eq!(state, expected, "report: {report}");
            assert_eq!(gaps.first().map(|value| value.kind), gap, "report: {report}");
        }
    }

    #[test]
    fn authentication_helpers_accept_documented_nested_shapes() {
        let value = serde_json::json!({
            "outer": [{"Count": "7"}, {"authenticated": false}],
            "summaryItems": [{"key": "other", "passed": true},
                             {"key": "auth.summary.auth", "passed": false}],
            "statistics": [{"key": "stats.auth.success", "value": "3"}]
        });
        let mut numbers = BTreeMap::new();
        collect_numbers(&value, String::new(), &mut numbers);
        assert_eq!(numbers.get("outer.count"), Some(&7));
        assert_eq!(number_value(&serde_json::json!(4)), Some(4));
        assert_eq!(number_value(&serde_json::json!("5")), Some(5));
        assert_eq!(number_value(&Value::Bool(true)), None);
        assert_eq!(auth_summary(&value), Some(false));
        assert_eq!(auth_summary(&serde_json::json!({"summaryItems": []})), None);
        assert_eq!(find_auth_boolean(&value), Some(false));
        assert_eq!(
            find_auth_boolean(&serde_json::json!([{"nested": {"success": true}}])),
            Some(true)
        );
        assert_eq!(find_auth_boolean(&serde_json::json!({"nested": "none"})), None);
    }

    #[test]
    fn persona_authentication_combines_trace_and_report_without_stale_invalid_gap() {
        let persona = header_persona();
        let target = Url::parse("https://example.com/app").expect("target");
        let workspace = DastWorkspace::create().expect("workspace");
        let verified_trace = br#"{
            "log":{"entries":[{
                "request":{"method":"GET","url":"https://example.com/app/account",
                           "headers":[{"name":"X-Session","value":"fixture-secret"}]},
                "response":{"status":200,"content":{"text":"Account"}}
            }]}
        }"#;
        std::fs::write(workspace.root().join(PRE_DISCOVERY_TRACE_FILE), verified_trace)
            .expect("trace");
        std::fs::write(workspace.root().join(PERSONA_REPORT_FILE), b"{}")
            .expect("authentication report");
        let input = PersonaRunInput {
            workspace: &workspace,
            target: &target,
            profile: ApplicationDastProfile::Passive,
            persona: &persona,
            schemas: &[],
            plan_sha256: "aa",
            exit_code: 0,
            config: &DastConfig::default(),
        };
        let (state, gaps) = persona_authentication(&input).expect("combined authentication");
        assert_eq!(state, ApplicationDastAuthenticationState::Verified);
        assert!(gaps.is_empty());

        let failed_trace = String::from_utf8_lossy(verified_trace).replace("Account", "Sign in");
        std::fs::write(workspace.root().join(PRE_DISCOVERY_TRACE_FILE), failed_trace.as_bytes())
            .expect("failed trace");
        std::fs::write(
            workspace.root().join(PERSONA_REPORT_FILE),
            br#"{"summaryItems":[{"key":"auth.summary.auth","passed":true}]}"#,
        )
        .expect("verified report");
        let (state, gaps) = persona_authentication(&input).expect("failed trace combination");
        assert_eq!(state, ApplicationDastAuthenticationState::Failed);
        assert!(gaps.iter().any(|gap| gap.kind == ApplicationDastGapKind::AuthenticationFailed));
    }

    #[test]
    fn empty_and_warning_reports_have_distinct_coverage() {
        let target = Url::parse("https://example.com/app").expect("target");
        let empty = workspace_with_report(
            br#"{"site":[],"afPlanErrors":[],"afPlanWarns":[]}"#,
            b"https://example.com/app\n",
        );
        let parsed = parse_persona_run(&PersonaRunInput {
            workspace: &empty,
            target: &target,
            profile: ApplicationDastProfile::Passive,
            persona: &anonymous_persona(),
            schemas: &[],
            plan_sha256: "aa",
            exit_code: 0,
            config: &DastConfig::default(),
        })
        .expect("valid empty report");
        assert!(parsed.findings.is_empty());
        assert!(parsed.gaps.is_empty());
        assert!(parsed
            .assessment
            .phases
            .iter()
            .all(|phase| phase.status == scorchkit_core::ApplicationDastPhaseStatus::Complete));

        let warning = workspace_with_report(
            br#"{"site":[],"afPlanErrors":[],"afPlanWarns":["fixture warning"]}"#,
            b"https://example.com/app\n",
        );
        let parsed = parse_persona_run(&PersonaRunInput {
            workspace: &warning,
            target: &target,
            profile: ApplicationDastProfile::Passive,
            persona: &anonymous_persona(),
            schemas: &[],
            plan_sha256: "bb",
            exit_code: 2,
            config: &DastConfig::default(),
        })
        .expect("warning report");
        assert_eq!(parsed.gaps[0].kind, ApplicationDastGapKind::PlanWarning);
        assert!(parsed.assessment.phases.iter().any(|phase| {
            phase.phase == ApplicationDastPhase::AlertReport
                && phase.status == scorchkit_core::ApplicationDastPhaseStatus::Incomplete
        }));

        let schema = ValidatedDastSchema {
            bytes: b"schema".to_vec(),
            identity: scorchkit_core::ApplicationDastSchemaIdentity {
                kind: scorchkit_core::ApplicationDastSchemaKind::OpenApi,
                sha256: "schema-sha".to_string(),
                source_name: "schema.yaml".to_string(),
                endpoint: None,
            },
            operations: vec![SchemaOperation {
                route: "/app".to_string(),
                method: "GET".to_string(),
                operation_id: Some("root".to_string()),
                schema_sha256: "schema-sha".to_string(),
            }],
        };
        let with_schema = workspace_with_report(
            br#"{"site":[],"afPlanErrors":[],"afPlanWarns":[]}"#,
            b"https://example.com/app\n",
        );
        let parsed = parse_persona_run(&PersonaRunInput {
            workspace: &with_schema,
            target: &target,
            profile: ApplicationDastProfile::Passive,
            persona: &anonymous_persona(),
            schemas: &[schema],
            plan_sha256: "cc",
            exit_code: 0,
            config: &DastConfig::default(),
        })
        .expect("schema-backed report");
        assert!(parsed
            .assessment
            .phases
            .iter()
            .any(|phase| phase.phase == ApplicationDastPhase::SchemaImport));
    }

    #[test]
    fn alert_artifacts_enforce_scope_and_scrub_known_persona_values() {
        let target = Url::parse("https://example.com/app").expect("target");
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Header {
                header_name: "X-Custom".to_string(),
                header_value: "secret value".to_string(),
                verification: crate::config::DastVerificationConfig::default(),
            },
        };
        let alert = serde_json::json!({
            "pluginid": "10001",
            "alert": "fixture secret value",
            "desc": "observed secret value",
            "riskcode": "1",
            "confidence": "2",
            "instances": [{
                "uri": "https://example.com/app/account?value=secret%20value",
                "method": "GET",
                "request-header": "GET /app/account HTTP/1.1\r\nX-Custom: secret value\r\n",
                "request-body": "value=secret+value",
                "response-header": "HTTP/1.1 200 OK\r\nX-Custom: secret value\r\n",
                "response-body": "secret value"
            }]
        });
        let mut findings = Vec::new();
        parse_alert_instances(&alert, &target, &persona, "aa", &[], &mut findings)
            .expect("in-scope alert");
        let serialized = serde_json::to_string(&findings).expect("finding JSON");
        assert!(!serialized.contains("secret value"));
        assert!(!serialized.contains("secret%20value"));
        assert!(!serialized.contains("secret+value"));

        let mut out_of_scope = alert;
        out_of_scope["instances"][0]["uri"] =
            Value::String("https://example.com/application/account".to_string());
        let error =
            parse_alert_instances(&out_of_scope, &target, &persona, "aa", &[], &mut Vec::new())
                .expect_err("out-of-scope alert must fail");
        assert!(error.to_string().contains("out-of-scope"));
    }

    #[test]
    fn automation_diagnostics_require_both_arrays_and_preserve_supported_shapes() {
        for incomplete in
            [serde_json::json!({"afPlanErrors": []}), serde_json::json!({"afPlanWarns": []})]
        {
            assert!(automation_messages(incomplete.as_object().expect("object")).is_err());
        }
        let report = serde_json::json!({
            "automationFramework": {
                "errors": ["plain error", {"error": "object error"}],
                "warnings": [{"message": "object warning"}, 4]
            }
        });
        let (errors, warnings) =
            automation_messages(report.as_object().expect("object")).expect("diagnostics");
        assert_eq!(errors, ["plain error", "object error"]);
        assert_eq!(warnings, ["object warning", "Automation Framework diagnostic"]);
    }

    #[test]
    fn url_export_is_sorted_deduplicated_and_rejects_each_scope_boundary() {
        let target = Url::parse("https://example.com/app").expect("target");
        let urls = parse_url_export(
            b"https://example.com/app/z\nhttps://example.com/app/a\nhttps://example.com/app/z\n",
            &target,
        )
        .expect("URL export");
        assert_eq!(
            urls.iter().map(Url::as_str).collect::<Vec<_>>(),
            ["https://example.com/app/a", "https://example.com/app/z",]
        );
        assert!(parse_url_export(b"https://outside.example/app\n", &target).is_err());
        assert!(parse_url_export(b"https://example.com/application\n", &target).is_err());
    }

    #[test]
    fn alert_parser_preserves_exact_finding_and_http_identity() {
        let target = Url::parse("https://example.com/app").expect("target");
        let persona = header_persona();
        let report = serde_json::json!({
            "site": [{"alerts": [{
                "pluginid": "40012",
                "alertRef": "40012-1",
                "alert": "Reflected input",
                "desc": "description",
                "riskcode": 3,
                "confidence": 3,
                "cweid": "79",
                "instances": [{
                    "uri": "https://example.com/app/items/42",
                    "method": "POST",
                    "param": "query",
                    "evidence": "probe fixture-secret",
                    "request-header": "POST /app/items/42 HTTP/1.1\r\nX-Session: fixture-secret\r\n",
                    "response-header": "HTTP/1.1 201 Created\r\nX-Test: yes\r\n"
                }]
            }]}]
        });
        let operation = SchemaOperation {
            route: "/app/items/{id}".to_string(),
            method: "POST".to_string(),
            operation_id: Some("updateItem".to_string()),
            schema_sha256: "schema-sha".to_string(),
        };
        let findings = parse_alerts(
            report.as_object().expect("report"),
            &target,
            &persona,
            "plan-sha",
            &[operation],
        )
        .expect("alerts");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert!((finding.confidence - 0.9).abs() < 0.000_001);
        assert_eq!(finding.cwe_id, Some(79));
        assert_eq!(finding.evidence.as_deref(), Some("probe [REDACTED]"));
        let http = finding.http_evidence.as_ref().expect("HTTP evidence");
        assert_eq!(http.method, "POST");
        assert_eq!(http.route.as_deref(), Some("/app/items/42"));
        assert_eq!(http.parameter.as_ref().map(|value| value.name.as_str()), Some("query"));
        assert_eq!(http.status_code, 201);
        assert_eq!(http.request_headers.get("X-Session").map(String::as_str), Some("[REDACTED]"));

        let mut wrong_method = report.clone();
        wrong_method["site"][0]["alerts"][0]["instances"][0]["method"] =
            Value::String("GET".to_string());
        let mismatched = parse_alerts(
            wrong_method.as_object().expect("wrong-method report"),
            &target,
            &persona,
            "plan-sha",
            &[SchemaOperation {
                route: "/app/items/{id}".to_string(),
                method: "POST".to_string(),
                operation_id: Some("updateItem".to_string()),
                schema_sha256: "schema-sha".to_string(),
            }],
        )
        .expect("method-mismatched alert");
        assert!(mismatched[0]
            .appsec
            .correlation_keys
            .iter()
            .all(|key| key.namespace != "dast-operation" && key.namespace != "dast-schema"));

        let mut outside = report;
        outside["site"][0]["alerts"][0]["instances"][0]["uri"] =
            Value::String("https://outside.example/app/items/42".to_string());
        assert!(parse_alerts(
            outside.as_object().expect("outside report"),
            &target,
            &persona,
            "plan-sha",
            &[],
        )
        .is_err());
    }

    #[test]
    fn parser_scalar_helpers_have_exact_public_mappings() {
        assert!(value_as_slice(&Value::Null).expect("null collection").is_empty());
        assert_eq!(value_as_slice(&serde_json::json!([1, 2])).expect("array").len(), 2);
        assert!(value_as_slice(&Value::Bool(false)).is_err());

        assert_eq!(optional_u32(Some(&serde_json::json!(7))), Some(7));
        assert_eq!(optional_u32(Some(&serde_json::json!("8"))), Some(8));
        assert_eq!(optional_u32(Some(&serde_json::json!(u64::from(u32::MAX) + 1))), None);
        assert_eq!(optional_u32(Some(&Value::Bool(true))), None);
        assert_eq!(optional_u32(None), None);

        for (code, expected) in [
            (4, Severity::Critical),
            (3, Severity::High),
            (2, Severity::Medium),
            (1, Severity::Low),
            (0, Severity::Info),
        ] {
            assert_eq!(severity(Some(&serde_json::json!(code))), expected);
            assert_eq!(severity(Some(&Value::String(code.to_string()))), expected);
        }
        assert_eq!(severity(Some(&Value::String("invalid".to_string()))), Severity::Info);

        for (code, expected) in [(3, 0.9), (2, 0.75), (1, 0.55), (0, 0.2), (9, 0.5)] {
            assert!((confidence(Some(&serde_json::json!(code))) - expected).abs() < 0.000_001);
        }
        assert!((confidence(None) - 0.5).abs() < 0.000_001);
        assert_eq!(numeric_text(Some(&serde_json::json!(12))), Some(12));
        assert_eq!(numeric_text(Some(&Value::String("13".to_string()))), Some(13));
        assert_eq!(numeric_text(Some(&Value::String("bad".to_string()))), None);
        assert_eq!(numeric_text(None), None);
    }

    #[test]
    fn parser_header_and_status_helpers_preserve_and_redact_exact_values() {
        let instance = serde_json::json!({
            "response-header": "HTTP/1.1 204 No Content\r\nX-Test: yes\r\n"
        });
        assert_eq!(response_status(instance.as_object().expect("instance")), 204);
        assert_eq!(response_status(serde_json::json!({}).as_object().expect("empty")), 0);

        let headers =
            parse_headers("GET / HTTP/1.1\r\nX-Session: fixture-secret\r\nX-Other: value:tail\r\n");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("X-Session").map(String::as_str), Some("fixture-secret"));
        assert_eq!(headers.get("X-Other").map(String::as_str), Some("value:tail"));
        let redacted = redact_header_values(headers, &header_persona());
        assert_eq!(redacted.len(), 2);
        assert_eq!(redacted.get("X-Session").map(String::as_str), Some("[REDACTED]"));
        assert_eq!(redacted.get("X-Other").map(String::as_str), Some("value:tail"));
    }

    #[test]
    fn selected_phase_order_and_replacement_are_exact() {
        let anonymous =
            selected_phases(ApplicationDastProfile::Passive, &anonymous_persona(), false);
        assert_eq!(
            anonymous.iter().map(|value| value.phase).collect::<Vec<_>>(),
            [
                ApplicationDastPhase::TraditionalSpider,
                ApplicationDastPhase::PassiveScan,
                ApplicationDastPhase::UrlExport,
                ApplicationDastPhase::AlertReport,
            ]
        );

        let mut named = selected_phases(ApplicationDastProfile::Active, &header_persona(), true);
        assert_eq!(
            named.iter().map(|value| value.phase).collect::<Vec<_>>(),
            [
                ApplicationDastPhase::Authentication,
                ApplicationDastPhase::SchemaImport,
                ApplicationDastPhase::TraditionalSpider,
                ApplicationDastPhase::PassiveScan,
                ApplicationDastPhase::ClientSpider,
                ApplicationDastPhase::ActiveScan,
                ApplicationDastPhase::UrlExport,
                ApplicationDastPhase::AlertReport,
                ApplicationDastPhase::AuthenticationReport,
            ]
        );
        replace_phase(
            &mut named,
            ApplicationDastPhase::AlertReport,
            ApplicationDastPhaseOutcome::failed(ApplicationDastPhase::AlertReport, "failed"),
        );
        assert_eq!(
            named.iter().filter(|value| value.phase == ApplicationDastPhase::AlertReport).count(),
            1
        );
        assert_eq!(named[0].phase, ApplicationDastPhase::Authentication);
        assert_eq!(named[0].status, scorchkit_core::ApplicationDastPhaseStatus::Complete);
        assert_eq!(
            named
                .iter()
                .find(|value| value.phase == ApplicationDastPhase::AlertReport)
                .map(|value| value.status),
            Some(scorchkit_core::ApplicationDastPhaseStatus::Failed)
        );
    }
}
