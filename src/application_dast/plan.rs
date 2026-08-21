use std::collections::BTreeMap;
use std::path::PathBuf;

use scorchkit_core::{sha256_hex, ApplicationDastProfile, Result, ScorchError};
use serde::Serialize;
use serde_yaml::Value;
use url::Url;

use crate::config::{DastConfig, DastVerificationConfig};

use super::schema::ValidatedDastSchema;

pub const ZAP_VERSION: &str = "2.17.0";

#[derive(Clone)]
pub enum ResolvedPersonaKind {
    Anonymous,
    Header {
        header_name: String,
        header_value: String,
        verification: DastVerificationConfig,
    },
    Browser {
        login_url: String,
        username: String,
        password: String,
        verification: DastVerificationConfig,
    },
}

#[derive(Clone)]
pub struct ResolvedPersona {
    pub id: String,
    pub kind: ResolvedPersonaKind,
}

impl ResolvedPersona {
    pub(crate) fn environment(&self, target: &Url) -> BTreeMap<String, String> {
        let mut environment = BTreeMap::new();
        match &self.kind {
            ResolvedPersonaKind::Anonymous => {}
            ResolvedPersonaKind::Header { header_name, header_value, .. } => {
                environment.insert("ZAP_AUTH_HEADER".to_string(), header_name.clone());
                environment.insert("ZAP_AUTH_HEADER_VALUE".to_string(), header_value.clone());
                environment.insert(
                    "ZAP_AUTH_HEADER_SITE".to_string(),
                    target.host_str().unwrap_or_default().to_string(),
                );
            }
            ResolvedPersonaKind::Browser { username, password, .. } => {
                environment.insert("SCORCHKIT_ZAP_USERNAME".to_string(), username.clone());
                environment.insert("SCORCHKIT_ZAP_PASSWORD".to_string(), password.clone());
            }
        }
        environment
    }

    pub(crate) const fn verification(&self) -> Option<&DastVerificationConfig> {
        match &self.kind {
            ResolvedPersonaKind::Anonymous => None,
            ResolvedPersonaKind::Header { verification, .. }
            | ResolvedPersonaKind::Browser { verification, .. } => Some(verification),
        }
    }

    pub(crate) const fn is_anonymous(&self) -> bool {
        matches!(self.kind, ResolvedPersonaKind::Anonymous)
    }

    pub(crate) fn redact_known_secrets(&self, value: &str) -> String {
        let mut secrets: Vec<&str> = match &self.kind {
            ResolvedPersonaKind::Anonymous => Vec::new(),
            ResolvedPersonaKind::Header { header_value, .. } => vec![header_value],
            ResolvedPersonaKind::Browser { username, password, .. } => vec![username, password],
        };
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        let mut redacted = value.to_string();
        for secret in secrets.into_iter().filter(|secret| !secret.is_empty()) {
            let form_encoded = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("value", secret)
                .finish()
                .strip_prefix("value=")
                .unwrap_or_default()
                .to_string();
            let percent_encoded = form_encoded.replace('+', "%20");
            let percent_encoded_lowercase = lowercase_percent_escapes(&percent_encoded);
            let json_encoded = serde_json::to_string(secret).ok().and_then(|encoded| {
                encoded
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .map(str::to_string)
            });
            redacted = redacted.replace(secret, "[REDACTED]");
            if percent_encoded != secret {
                redacted = redacted.replace(&percent_encoded, "[REDACTED]");
            }
            if percent_encoded_lowercase != percent_encoded {
                redacted = redacted.replace(&percent_encoded_lowercase, "[REDACTED]");
            }
            if form_encoded != secret {
                redacted = redacted.replace(&form_encoded, "[REDACTED]");
            }
            if let Some(json_encoded) = json_encoded.filter(|encoded| encoded != secret) {
                redacted = redacted.replace(&json_encoded, "[REDACTED]");
            }
        }
        scorchkit_core::observation::redact_text(&redacted)
    }
}

fn lowercase_percent_escapes(value: &str) -> String {
    let mut chars = value.chars();
    let mut normalized = String::with_capacity(value.len());
    while let Some(character) = chars.next() {
        normalized.push(character);
        if character == '%' {
            if let Some(high) = chars.next() {
                normalized.push(high.to_ascii_lowercase());
            }
            if let Some(low) = chars.next() {
                normalized.push(low.to_ascii_lowercase());
            }
        }
    }
    normalized
}

#[derive(Serialize)]
struct AutomationPlan {
    env: PlanEnvironment,
    jobs: Vec<PlanJob>,
}

#[derive(Serialize)]
struct PlanEnvironment {
    contexts: Vec<PlanContext>,
    parameters: PlanEnvironmentParameters,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanEnvironmentParameters {
    fail_on_error: bool,
    fail_on_warning: bool,
    progress_to_stdout: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanContext {
    name: String,
    urls: Vec<String>,
    include_paths: Vec<String>,
    exclude_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication: Option<PlanAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_management: Option<PlanSessionManagement>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    users: Vec<PlanUser>,
}

#[derive(Serialize)]
struct PlanAuthentication {
    method: String,
    parameters: BTreeMap<String, Value>,
    verification: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct PlanSessionManagement {
    method: String,
    parameters: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct PlanUser {
    name: String,
    credentials: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct PlanJob {
    #[serde(rename = "type")]
    job_type: String,
    parameters: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requests: Vec<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sections: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sites: Vec<String>,
}

pub struct CompiledPlan {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub fn compile_plan(
    target: &Url,
    profile: ApplicationDastProfile,
    persona: &ResolvedPersona,
    schemas: &[ValidatedDastSchema],
    schema_paths: &[PathBuf],
    config: &DastConfig,
) -> Result<CompiledPlan> {
    if schemas.len() != schema_paths.len() {
        return Err(ScorchError::Config(
            "validated schema and workspace schema counts differ".to_string(),
        ));
    }
    let context_name = "scorchkit";
    let context = plan_context(target, persona, config, context_name)?;
    let user = (!persona.is_anonymous()).then_some(persona.id.as_str());
    let mut jobs =
        vec![job("passiveScan-config", values([("scanOnlyInScope", Value::Bool(true))]))];
    jobs.extend(verification_jobs(persona, context_name));
    jobs.extend(schema_import_jobs(target, schemas, schema_paths, context_name, user)?);
    jobs.extend(scan_jobs(target, profile, config, context_name, user));
    jobs.extend(evidence_jobs(target, persona, context_name));
    let plan = AutomationPlan {
        env: PlanEnvironment {
            contexts: vec![context],
            parameters: PlanEnvironmentParameters {
                fail_on_error: true,
                fail_on_warning: false,
                progress_to_stdout: false,
            },
        },
        jobs,
    };
    let bytes = serde_yaml::to_string(&plan)
        .map_err(|error| plan_serialization_error(&error))?
        .into_bytes();
    let sha256 = sha256_hex(&bytes);
    Ok(CompiledPlan { bytes, sha256 })
}

fn plan_context(
    target: &Url,
    persona: &ResolvedPersona,
    config: &DastConfig,
    context_name: &str,
) -> Result<PlanContext> {
    let (authentication, session_management, users) = authentication(persona, config);
    Ok(PlanContext {
        name: context_name.to_string(),
        urls: vec![target.as_str().to_string()],
        include_paths: vec![anchored_scope_pattern(target)?],
        exclude_paths: Vec::new(),
        authentication,
        session_management,
        users,
    })
}

fn verification_jobs(persona: &ResolvedPersona, context_name: &str) -> Vec<PlanJob> {
    let Some(verification) = persona.verification() else {
        return Vec::new();
    };
    vec![
        PlanJob {
            job_type: "requestor".to_string(),
            parameters: values([("user", string(&persona.id))]),
            requests: vec![values([
                ("url", string(&verification.url)),
                ("method", string("GET")),
                ("responseCode", Value::Number(verification.expected_status.into())),
            ])],
            sections: Vec::new(),
            sites: Vec::new(),
        },
        job(
            "export",
            values([
                ("context", string(context_name)),
                ("type", string("har")),
                ("source", string("history")),
                ("fileName", string(super::workspace::PRE_DISCOVERY_TRACE_FILE)),
            ]),
        ),
    ]
}

fn schema_import_jobs(
    target: &Url,
    schemas: &[ValidatedDastSchema],
    schema_paths: &[PathBuf],
    context_name: &str,
    user: Option<&str>,
) -> Result<Vec<PlanJob>> {
    schemas
        .iter()
        .zip(schema_paths)
        .map(|(schema, path)| match schema.identity.kind {
            scorchkit_core::ApplicationDastSchemaKind::OpenApi => {
                let parameters = optional_user_parameters(
                    values([
                        ("context", string(context_name)),
                        ("targetUrl", string(target.as_str())),
                        ("apiFile", string(&slash_path(path))),
                    ]),
                    user,
                );
                Ok(job("openapi", parameters))
            }
            scorchkit_core::ApplicationDastSchemaKind::GraphQl => {
                let endpoint = schema.identity.endpoint.as_deref().ok_or_else(|| {
                    ScorchError::Config("validated GraphQL schema has no endpoint".to_string())
                })?;
                Ok(job(
                    "graphql",
                    values([
                        ("endpoint", string(endpoint)),
                        ("schemaFile", string(&slash_path(path))),
                        ("queryGenEnabled", Value::Bool(true)),
                    ]),
                ))
            }
        })
        .collect()
}

fn scan_jobs(
    target: &Url,
    profile: ApplicationDastProfile,
    config: &DastConfig,
    context_name: &str,
    user: Option<&str>,
) -> Vec<PlanJob> {
    let mut jobs = vec![
        job(
            "spider",
            optional_user_parameters(
                values([
                    ("context", string(context_name)),
                    ("url", string(target.as_str())),
                    ("maxDuration", Value::Number(config.spider_minutes.into())),
                    ("acceptCookies", Value::Bool(true)),
                    ("handleODataParametersVisited", Value::Bool(false)),
                    ("postForm", Value::Bool(false)),
                ]),
                user,
            ),
        ),
        job(
            "passiveScan-wait",
            values([("maxDuration", Value::Number(config.spider_minutes.into()))]),
        ),
    ];
    if profile.uses_client_spider() {
        jobs.push(job(
            "spiderClient",
            optional_user_parameters(
                values([
                    ("context", string(context_name)),
                    ("url", string(target.as_str())),
                    ("maxDuration", Value::Number(config.client_spider_minutes.into())),
                    ("maxCrawlDepth", Value::Number(config.client_spider_depth.into())),
                    ("maxChildren", Value::Number(config.client_spider_children.into())),
                    ("numberOfBrowsers", Value::Number(1_u64.into())),
                    ("browserId", string(&config.browser_id)),
                    ("scopeCheck", string("Strict")),
                ]),
                user,
            ),
        ));
        jobs.push(job(
            "passiveScan-wait",
            values([("maxDuration", Value::Number(config.client_spider_minutes.into()))]),
        ));
    }
    if profile.uses_active_scan() {
        jobs.push(job(
            "activeScan",
            optional_user_parameters(
                values([
                    ("context", string(context_name)),
                    ("policy", string("Default Policy")),
                    ("maxScanDurationInMins", Value::Number(config.active_scan_minutes.into())),
                ]),
                user,
            ),
        ));
        jobs.push(job(
            "passiveScan-wait",
            values([("maxDuration", Value::Number(config.active_scan_minutes.into()))]),
        ));
    }
    jobs
}

fn evidence_jobs(target: &Url, persona: &ResolvedPersona, context_name: &str) -> Vec<PlanJob> {
    let mut jobs = vec![
        job(
            "export",
            values([
                ("context", string(context_name)),
                ("type", string("url")),
                ("source", string("history")),
                ("fileName", string(super::workspace::URL_REPORT_FILE)),
            ]),
        ),
        job(
            "export",
            values([
                ("context", string(context_name)),
                ("type", string("har")),
                ("source", string("history")),
                ("fileName", string(super::workspace::TRAFFIC_REPORT_FILE)),
            ]),
        ),
    ];
    let report_site = site_origin(target);
    jobs.push(report_job(
        values([
            ("template", string("traditional-json-plus")),
            ("reportDir", string("reports")),
            ("reportFile", string("zap-report.json")),
            ("reportTitle", string("ScorchKit application DAST")),
            ("reportDescription", string("Policy-authorized OWASP ZAP evidence")),
        ]),
        vec!["statistics".to_string(), "afstate".to_string()],
        vec![report_site.clone()],
    ));
    if !persona.is_anonymous() {
        jobs.push(report_job(
            values([
                ("template", string("auth-report-json")),
                ("reportDir", string("reports")),
                ("reportFile", string("auth-report.json")),
                ("reportTitle", string("ScorchKit authentication evidence")),
            ]),
            vec!["summary".to_string(), "statistics".to_string()],
            vec![report_site],
        ));
    }
    jobs
}

fn authentication(
    persona: &ResolvedPersona,
    config: &DastConfig,
) -> (Option<PlanAuthentication>, Option<PlanSessionManagement>, Vec<PlanUser>) {
    let Some(verification) = persona.verification() else {
        return (None, None, Vec::new());
    };
    let verification_parameters = values([
        ("method", string("poll")),
        ("loggedInRegex", string(&verification.logged_in_regex)),
        ("loggedOutRegex", string(&verification.logged_out_regex)),
        ("pollFrequency", Value::Number(5_u64.into())),
        ("pollUnits", string("seconds")),
        ("pollUrl", string(&verification.url)),
        ("pollPostData", string("")),
    ]);
    match &persona.kind {
        ResolvedPersonaKind::Anonymous => (None, None, Vec::new()),
        ResolvedPersonaKind::Header { .. } => (
            Some(PlanAuthentication {
                method: "manual".to_string(),
                parameters: BTreeMap::new(),
                verification: verification_parameters,
            }),
            None,
            vec![PlanUser { name: persona.id.clone(), credentials: BTreeMap::new() }],
        ),
        ResolvedPersonaKind::Browser { login_url, .. } => (
            Some(PlanAuthentication {
                method: "browser".to_string(),
                parameters: values([
                    ("loginPageUrl", string(login_url)),
                    ("loginPageWait", Value::Number(5_u64.into())),
                    ("browserId", string(&config.browser_id)),
                ]),
                verification: verification_parameters,
            }),
            Some(PlanSessionManagement {
                method: "autodetect".to_string(),
                parameters: BTreeMap::new(),
            }),
            vec![PlanUser {
                name: persona.id.clone(),
                credentials: BTreeMap::from([
                    ("username".to_string(), "${SCORCHKIT_ZAP_USERNAME}".to_string()),
                    ("password".to_string(), "${SCORCHKIT_ZAP_PASSWORD}".to_string()),
                ]),
            }],
        ),
    }
}

fn anchored_scope_pattern(target: &Url) -> Result<String> {
    let scheme = regex::escape(target.scheme());
    let host = regex::escape(target.host_str().ok_or_else(|| ScorchError::InvalidTarget {
        target: target.to_string(),
        reason: "application DAST target has no host".to_string(),
    })?);
    let port = target.port().map_or_else(String::new, |port| format!(":{port}"));
    let path = regex::escape(target.path().trim_end_matches('/'));
    Ok(format!("^{scheme}://{host}{port}{path}(?:/.*)?(?:\\?.*)?$"))
}

fn optional_user_parameters(
    mut parameters: BTreeMap<String, Value>,
    user: Option<&str>,
) -> BTreeMap<String, Value> {
    if let Some(user) = user {
        parameters.insert("user".to_string(), string(user));
    }
    parameters
}

fn job(job_type: &str, parameters: BTreeMap<String, Value>) -> PlanJob {
    PlanJob {
        job_type: job_type.to_string(),
        parameters,
        requests: Vec::new(),
        sections: Vec::new(),
        sites: Vec::new(),
    }
}

fn report_job(
    parameters: BTreeMap<String, Value>,
    sections: Vec<String>,
    sites: Vec<String>,
) -> PlanJob {
    PlanJob { job_type: "report".to_string(), parameters, requests: Vec::new(), sections, sites }
}

fn values<const N: usize>(entries: [(&str, Value); N]) -> BTreeMap<String, Value> {
    entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect()
}

fn string(value: &str) -> Value {
    Value::String(value.to_string())
}

fn slash_path(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn site_origin(target: &Url) -> String {
    let mut site = format!("{}://{}", target.scheme(), target.host_str().unwrap_or_default());
    if let Some(port) = target.port() {
        site = format!("{site}:{port}");
    }
    site
}

fn plan_serialization_error(error: &serde_yaml::Error) -> ScorchError {
    ScorchError::Config(format!("cannot serialize owned application DAST plan: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_core::{ApplicationDastSchemaIdentity, ApplicationDastSchemaKind};

    fn schema(kind: ApplicationDastSchemaKind, endpoint: Option<&str>) -> ValidatedDastSchema {
        ValidatedDastSchema {
            bytes: b"fixture".to_vec(),
            identity: ApplicationDastSchemaIdentity {
                kind,
                sha256: "a".repeat(64),
                source_name: "fixture".to_string(),
                endpoint: endpoint.map(str::to_string),
            },
            operations: Vec::new(),
        }
    }

    fn verification() -> DastVerificationConfig {
        DastVerificationConfig {
            url: "https://example.com/app/account".to_string(),
            expected_status: 200,
            logged_in_regex: "Account".to_string(),
            logged_out_regex: "Sign in".to_string(),
            max_logged_out: 0,
        }
    }

    #[test]
    fn persona_environments_are_exact_and_isolated() {
        let target = Url::parse("https://example.com/app").expect("target");
        let anonymous =
            ResolvedPersona { id: "anonymous".to_string(), kind: ResolvedPersonaKind::Anonymous };
        assert_eq!(anonymous.environment(&target), BTreeMap::new());

        let header = ResolvedPersona {
            id: "header".to_string(),
            kind: ResolvedPersonaKind::Header {
                header_name: "X-Session".to_string(),
                header_value: "header-secret".to_string(),
                verification: verification(),
            },
        };
        assert_eq!(
            header.environment(&target),
            BTreeMap::from([
                ("ZAP_AUTH_HEADER".to_string(), "X-Session".to_string()),
                ("ZAP_AUTH_HEADER_SITE".to_string(), "example.com".to_string()),
                ("ZAP_AUTH_HEADER_VALUE".to_string(), "header-secret".to_string()),
            ])
        );

        let browser = ResolvedPersona {
            id: "browser".to_string(),
            kind: ResolvedPersonaKind::Browser {
                login_url: "https://example.com/app/login".to_string(),
                username: "fixture-user".to_string(),
                password: "fixture-password".to_string(),
                verification: verification(),
            },
        };
        assert_eq!(
            browser.environment(&target),
            BTreeMap::from([
                ("SCORCHKIT_ZAP_PASSWORD".to_string(), "fixture-password".to_string()),
                ("SCORCHKIT_ZAP_USERNAME".to_string(), "fixture-user".to_string()),
            ])
        );
    }

    #[test]
    fn anonymous_plan_is_deterministic_and_profile_bounded() {
        let target = Url::parse("https://example.com/app").expect("target");
        let persona =
            ResolvedPersona { id: "anonymous".to_string(), kind: ResolvedPersonaKind::Anonymous };
        let first = compile_plan(
            &target,
            ApplicationDastProfile::Passive,
            &persona,
            &[],
            &[],
            &DastConfig::default(),
        )
        .expect("plan");
        let second = compile_plan(
            &target,
            ApplicationDastProfile::Passive,
            &persona,
            &[],
            &[],
            &DastConfig::default(),
        )
        .expect("plan");
        assert_eq!(first.bytes, second.bytes);
        assert_eq!(first.sha256, second.sha256);
        let text = String::from_utf8(first.bytes).expect("utf8");
        assert!(text.contains("passiveScan-wait"));
        assert!(!text.contains("activeScan"));
        assert!(!text.contains("SCORCHKIT_ZAP_PASSWORD"));
        assert!(!text.contains("user: anonymous"));
    }

    #[test]
    fn browser_plan_contains_placeholders_but_not_values() {
        let target = Url::parse("https://example.com/").expect("target");
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: ResolvedPersonaKind::Browser {
                login_url: "https://example.com/login".to_string(),
                username: "fixture-user".to_string(),
                password: "fixture-secret".to_string(),
                verification: DastVerificationConfig {
                    url: "https://example.com/account".to_string(),
                    expected_status: 200,
                    logged_in_regex: "Account".to_string(),
                    logged_out_regex: "Sign in".to_string(),
                    max_logged_out: 0,
                },
            },
        };
        let plan = compile_plan(
            &target,
            ApplicationDastProfile::Active,
            &persona,
            &[],
            &[],
            &DastConfig::default(),
        )
        .expect("plan");
        let text = String::from_utf8(plan.bytes).expect("utf8");
        assert!(text.contains("${SCORCHKIT_ZAP_PASSWORD}"));
        assert!(text.contains("activeScan"));
        assert!(text.contains("user: user"));
        assert!(!text.contains("fixture-secret"));
        assert!(!text.contains("fixture-user"));
    }

    #[test]
    fn plan_uses_installed_automation_framework_keys_and_restricted_reports() {
        let target = Url::parse("https://example.com/app").expect("target");
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: ResolvedPersonaKind::Browser {
                login_url: "https://example.com/app/login".to_string(),
                username: "fixture-user".to_string(),
                password: "fixture-secret".to_string(),
                verification: DastVerificationConfig {
                    url: "https://example.com/app/account".to_string(),
                    expected_status: 200,
                    logged_in_regex: "Account".to_string(),
                    logged_out_regex: "Sign in".to_string(),
                    max_logged_out: 0,
                },
            },
        };
        let schemas = vec![
            schema(ApplicationDastSchemaKind::OpenApi, None),
            schema(ApplicationDastSchemaKind::GraphQl, Some("https://example.com/app/graphql")),
        ];
        let paths = vec![
            PathBuf::from("schemas/schema-001.yaml"),
            PathBuf::from("schemas/schema-002.graphql"),
        ];
        let plan = compile_plan(
            &target,
            ApplicationDastProfile::Standard,
            &persona,
            &schemas,
            &paths,
            &DastConfig::default(),
        )
        .expect("plan");
        let yaml: serde_yaml::Value = serde_yaml::from_slice(&plan.bytes).expect("yaml");
        let document = serde_json::to_value(yaml).expect("json projection");
        let jobs = document["jobs"].as_array().expect("jobs");
        let find_job =
            |job_type: &str| jobs.iter().find(|job| job["type"] == job_type).expect("job");

        let requestor = find_job("requestor");
        assert!(requestor.get("requests").is_some());
        assert!(requestor["parameters"].get("requests").is_none());
        assert!(requestor.get("tests").is_none());
        assert_eq!(
            document["env"]["contexts"][0]["authentication"]["verification"]["method"],
            "poll"
        );
        assert_eq!(document["env"]["contexts"][0]["sessionManagement"]["method"], "autodetect");
        let requestor_index =
            jobs.iter().position(|job| job["type"] == "requestor").expect("requestor index");
        let authentication_export_index = jobs
            .iter()
            .position(|job| {
                job["type"] == "export"
                    && job["parameters"]["fileName"]
                        == super::super::workspace::PRE_DISCOVERY_TRACE_FILE
            })
            .expect("authentication export index");
        let traffic_export_index = jobs
            .iter()
            .position(|job| {
                job["type"] == "export"
                    && job["parameters"]["fileName"] == super::super::workspace::TRAFFIC_REPORT_FILE
            })
            .expect("traffic export index");
        let spider_index =
            jobs.iter().position(|job| job["type"] == "spider").expect("spider index");
        let report_index =
            jobs.iter().position(|job| job["type"] == "report").expect("report index");
        assert!(requestor_index < authentication_export_index);
        assert!(authentication_export_index < spider_index);
        assert!(spider_index < traffic_export_index);
        assert!(traffic_export_index < report_index);
        assert!(find_job("openapi")["parameters"].get("apiFile").is_some());
        assert_eq!(find_job("openapi")["parameters"]["user"], "user");
        assert!(find_job("graphql")["parameters"].get("schemaFile").is_some());
        assert!(find_job("spiderClient")["parameters"].get("maxCrawlDepth").is_some());

        let reports: Vec<_> = jobs.iter().filter(|job| job["type"] == "report").collect();
        assert_eq!(reports.len(), 2);
        for report in reports {
            assert_eq!(report["sites"][0], "https://example.com");
            assert!(report.get("sections").is_some());
            assert!(report["parameters"].get("sections").is_none());
        }
        let auth_report = jobs
            .iter()
            .find(|job| job["parameters"]["template"] == "auth-report-json")
            .expect("auth report");
        assert_eq!(auth_report["sections"], serde_json::json!(["summary", "statistics"]));
    }

    #[test]
    fn known_persona_values_are_redacted_from_public_diagnostics() {
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: ResolvedPersonaKind::Header {
                header_name: "Authorization".to_string(),
                header_value: "arbitrary-fixture-secret".to_string(),
                verification: DastVerificationConfig::default(),
            },
        };
        let redacted = persona
            .redact_known_secrets("external tool failed while sending arbitrary-fixture-secret");
        assert!(!redacted.contains("arbitrary-fixture-secret"));
        assert!(redacted.contains("[REDACTED]"));

        let encoded_persona = ResolvedPersona {
            id: "user".to_string(),
            kind: ResolvedPersonaKind::Header {
                header_name: "X-Session".to_string(),
                header_value: "secret value".to_string(),
                verification: DastVerificationConfig::default(),
            },
        };
        let encoded = encoded_persona
            .redact_known_secrets("query=secret%20value&form=secret+value&json=secret value");
        assert!(!encoded.contains("secret%20value"));
        assert!(!encoded.contains("secret+value"));
        assert!(!encoded.contains("secret value"));

        let escaped_persona = ResolvedPersona {
            id: "user".to_string(),
            kind: ResolvedPersonaKind::Browser {
                login_url: "https://example.com/app/login".to_string(),
                username: "user/name".to_string(),
                password: "quote\"secret".to_string(),
                verification: verification(),
            },
        };
        let escaped = escaped_persona.redact_known_secrets(
            r#"upper=user%2Fname lower=user%2fname json=quote\"secret plain=user/name"#,
        );
        assert!(!escaped.contains("user%2Fname"));
        assert!(!escaped.contains("user%2fname"));
        assert!(!escaped.contains("quote\\\"secret"));
        assert!(!escaped.contains("user/name"));

        let empty_persona = ResolvedPersona {
            id: "empty".to_string(),
            kind: ResolvedPersonaKind::Header {
                header_name: "X-Empty".to_string(),
                header_value: String::new(),
                verification: verification(),
            },
        };
        assert_eq!(empty_persona.redact_known_secrets("safe diagnostic"), "safe diagnostic");
        assert_eq!(lowercase_percent_escapes("A%2FB%2fC%"), "A%2fB%2fC%");
    }

    #[test]
    fn scope_and_workspace_path_rendering_are_exact() {
        let target = Url::parse("https://example.com:8443/app.v1/").expect("target");
        assert_eq!(
            anchored_scope_pattern(&target).expect("scope pattern"),
            r"^https://example\.com:8443/app\.v1(?:/.*)?(?:\?.*)?$"
        );
        assert_eq!(
            slash_path(std::path::Path::new("schemas/openapi.yaml")),
            "schemas/openapi.yaml"
        );
    }
}
