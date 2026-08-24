//! MCP tool implementations.
//!
//! The business logic is in `pub` methods on `ScorchKitServer` (the main
//! `impl` block). The `#[tool_router]` block contains thin `#[tool]`
//! wrappers that delegate to the public methods. Tests call the public
//! methods directly.

use std::{collections::BTreeMap, sync::Arc};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use scorchkit_control::{
    ControlCommandV1, ControlQueryV1, ControlRequestV1, ControlResultV1, FindingViewV1,
    ModuleViewV1, PageRequestV1, ProjectViewV1, TargetViewV1,
};
use uuid::Uuid;

use super::contract::{McpCallContext, McpToolCallResult};
use super::server::ScorchKitServer;
use super::types::{
    AnalyzeFindingsParams, ApplicationContextParams, ApplicationDastParams,
    ApplicationEvidenceImportParams, ApplicationPentestExecuteParams,
    ApplicationPentestPersonaParams, ApplicationPentestPlanParams,
    ApplicationPentestScenarioParams, ApplicationSecurityWorkflowParams, AutoScanParams,
    CorrelateFindingsParams, FindingListParams, FindingRefParams, FindingUpdateStatusParams,
    FocusedScannerSelectorParams, FocusedVerificationSelectionParams,
    ManualApplicationFindingParams, PlanScanParams, ProjectCreateParams, ProjectDeleteParams,
    ProjectRefParams, ProjectScanParams, ProjectStatusParams, ScanJobRefParams, ScanParams,
    ScanProgressParams, ScheduleScanParams, SupplyChainCacheRefreshParams, SupplyChainScanParams,
    TargetAddParams, TargetIntelligenceParams, TargetRemoveParams,
};
use crate::engine::error::ScorchError;
use crate::engine::policy::{Capability, EffectClass, PolicyTarget};
use crate::engine::target::Target;
use crate::facade::Engine;
use crate::runner::job::{DastJobRequest, ScanJob, ScanJobState};
use crate::runner::orchestrator::Orchestrator;
use crate::storage::{context, findings, metrics, projects, scans, schedules};

const MAX_LEGACY_CONTROL_ITEMS: usize = 10_000;

fn redacted_top_finding(finding: &crate::engine::finding::Finding) -> serde_json::Value {
    serde_json::json!({
        "severity": finding.severity.to_string(),
        "title": crate::engine::observation::redact_text(&finding.title),
        "target": crate::engine::observation::redact_url(&finding.affected_target).0,
    })
}

fn redacted_intelligence_finding(finding: &crate::engine::finding::Finding) -> serde_json::Value {
    serde_json::json!({
        "module": &finding.module_id,
        "severity": finding.severity.to_string(),
        "title": crate::engine::observation::redact_text(&finding.title),
        "description": crate::engine::observation::redact_text(&finding.description),
        "target": crate::engine::observation::redact_url(&finding.affected_target).0,
        "evidence": finding
            .evidence
            .as_deref()
            .map(crate::engine::observation::redact_text),
    })
}

fn canonical_correlation_inventory(
    tracked_findings: &[crate::storage::models::TrackedFinding],
    stored_evidence: Vec<crate::storage::models::FindingEvidence>,
) -> (Vec<crate::engine::finding::Finding>, Vec<crate::engine::attack_path::AttackPathCorrelationGap>)
{
    use crate::engine::attack_path::{AttackPathCorrelationGap, AttackPathCorrelationGapKind};

    let stable_identity_by_id: BTreeMap<Uuid, &str> = tracked_findings
        .iter()
        .map(|finding| (finding.id, finding.stable_identity.as_str()))
        .collect();
    let mut evidence_by_finding = BTreeMap::new();
    let mut gaps = Vec::new();
    for row in stored_evidence {
        let decoded = serde_json::from_value::<crate::engine::observation::EvidenceRecord>(
            row.raw_evidence.clone(),
        );
        let Ok(evidence) = decoded else {
            gaps.push(AttackPathCorrelationGap {
                kind: AttackPathCorrelationGapKind::MalformedFindingRecord,
                finding_identity: stable_identity_by_id
                    .get(&row.tracked_finding_id)
                    .map(ToString::to_string),
            });
            continue;
        };
        let normalized = evidence.normalized();
        if normalized.identity != row.evidence_identity
            || normalized.schema != row.evidence_schema
            || normalized.provenance.collected_at.timestamp_micros()
                != row.collected_at.timestamp_micros()
            || serde_json::to_value(&normalized).ok().as_ref() != Some(&row.raw_evidence)
        {
            gaps.push(AttackPathCorrelationGap {
                kind: AttackPathCorrelationGapKind::MalformedFindingRecord,
                finding_identity: stable_identity_by_id
                    .get(&row.tracked_finding_id)
                    .map(ToString::to_string),
            });
            continue;
        }
        evidence_by_finding.entry(row.tracked_finding_id).or_insert_with(Vec::new).push(normalized);
    }

    let findings = tracked_findings
        .iter()
        .filter_map(|tracked| {
            let decoded = serde_json::from_value::<crate::engine::finding::Finding>(
                tracked.raw_finding.clone(),
            );
            let Ok(mut finding) = decoded else {
                gaps.push(AttackPathCorrelationGap {
                    kind: AttackPathCorrelationGapKind::MalformedFindingRecord,
                    finding_identity: Some(tracked.stable_identity.clone()),
                });
                return None;
            };
            let canonical_raw = serde_json::to_value(&finding).ok();
            if canonical_raw.as_ref() != Some(&tracked.raw_finding)
                || !tracked_finding_columns_match(&finding, tracked)
            {
                gaps.push(AttackPathCorrelationGap {
                    kind: AttackPathCorrelationGapKind::MalformedFindingRecord,
                    finding_identity: Some(tracked.stable_identity.clone()),
                });
                return None;
            }
            if let Some(evidence) = evidence_by_finding.remove(&tracked.id) {
                finding.appsec.evidence.extend(evidence);
            }
            let canonical = finding.canonical_appsec();
            let correlation_keys_match =
                serde_json::to_value(&canonical.correlation_keys).ok().as_ref()
                    == Some(&tracked.correlation_keys);
            if canonical.identity.value != tracked.stable_identity
                || canonical.identity.schema != tracked.identity_schema
                || !correlation_keys_match
            {
                gaps.push(AttackPathCorrelationGap {
                    kind: AttackPathCorrelationGapKind::MalformedFindingRecord,
                    finding_identity: Some(tracked.stable_identity.clone()),
                });
                return None;
            }
            Some(finding)
        })
        .collect();
    gaps.sort();
    gaps.dedup();
    (findings, gaps)
}

fn tracked_finding_columns_match(
    finding: &crate::engine::finding::Finding,
    tracked: &crate::storage::models::TrackedFinding,
) -> bool {
    finding.module_id == tracked.module_id
        && finding.severity.to_string() == tracked.severity
        && finding.title == tracked.title
        && finding.description == tracked.description
        && finding.affected_target == tracked.affected_target
        && finding.evidence == tracked.evidence
        && finding.remediation == tracked.remediation
        && finding.owasp_category == tracked.owasp_category
        && finding.cwe_id.and_then(|value| i32::try_from(value).ok()) == tracked.cwe_id
        && finding.confidence.total_cmp(&tracked.confidence).is_eq()
}

fn finding_limit_correlation_output(project: &str, total: usize) -> Result<String, String> {
    use crate::engine::attack_path::{
        AttackPathCorrelationGap, AttackPathCorrelationGapKind, AttackPathCorrelationStatus,
        ATTACK_PATH_CORRELATION_SCHEMA_V1,
    };

    serde_json::to_string_pretty(&serde_json::json!({
        "schema": ATTACK_PATH_CORRELATION_SCHEMA_V1,
        "project": project,
        "total_findings_available": total,
        "total_findings_analyzed": 0,
        "status": AttackPathCorrelationStatus::Incomplete,
        "attack_paths_found": 0,
        "attack_paths": [],
        "gaps": [AttackPathCorrelationGap {
            kind: AttackPathCorrelationGapKind::FindingLimitExceeded,
            finding_identity: None,
        }],
        "legacy_unverified_attack_chains": {
            "status": "not_evaluated_resource_limit",
            "attack_chains_found": 0,
            "chains": [],
        },
    }))
    .map_err(|error| error.to_string())
}

/// Helper to resolve a project by name or UUID.
async fn resolve_project(
    pool: &sqlx::PgPool,
    project_ref: &str,
) -> Result<crate::storage::models::Project, ScorchError> {
    if let Ok(uuid) = Uuid::parse_str(project_ref) {
        if let Some(project) = projects::get_project(pool, uuid).await? {
            return Ok(project);
        }
    }
    projects::get_project_by_name(pool, project_ref)
        .await?
        .ok_or_else(|| ScorchError::Config(format!("project '{project_ref}' not found")))
}

fn comma_separated(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|item| !item.is_empty()).map(str::to_string).collect()
}

fn application_pentest_scenarios(
    params: Vec<ApplicationPentestScenarioParams>,
) -> Result<Vec<scorchkit_core::ApplicationPentestScenario>, String> {
    params.into_iter().map(application_pentest_scenario).collect()
}

fn focused_verification_selection(
    params: FocusedVerificationSelectionParams,
) -> scorchkit_core::FocusedVerificationSelection {
    scorchkit_core::FocusedVerificationSelection {
        schema: params.schema,
        identity: params.identity,
        path_identity: params.path_identity,
        static_rules: params.static_rules.into_iter().map(focused_scanner_selector).collect(),
        runtime_probes: params.runtime_probes.into_iter().map(focused_scanner_selector).collect(),
        requests: params
            .requests
            .into_iter()
            .map(|request| scorchkit_core::RequestVerificationSelector {
                method: request.method,
                route: request.route,
                parameter: request.parameter.map(|parameter| {
                    scorchkit_core::observation::HttpParameterIdentity {
                        name: parameter.name,
                        location: parameter.location,
                    }
                }),
                authentication_persona: request.authentication_persona,
            })
            .collect(),
        tests: params.tests,
    }
}

fn focused_scanner_selector(
    params: FocusedScannerSelectorParams,
) -> scorchkit_core::ScannerVerificationSelector {
    scorchkit_core::ScannerVerificationSelector {
        scanner_id: params.scanner_id,
        rule_id: params.rule_id,
        rule_digest: params.rule_digest,
        config_identity: params.config_identity,
    }
}

fn application_pentest_scenario(
    params: ApplicationPentestScenarioParams,
) -> Result<scorchkit_core::ApplicationPentestScenario, String> {
    let proposal_kind = application_pentest_proposal_kind(&params.proposal_kind)?;
    let class = application_pentest_class(&params.scenario_class)?;
    let payload_class = application_pentest_payload(&params.payload_class)?;
    let parameter =
        application_pentest_parameter(params.parameter_name, params.parameter_location)?;
    let personas = application_pentest_personas(params.personas)?;
    let cleanup = application_pentest_cleanup(&params.cleanup)?;
    let evidence_requirements = application_pentest_evidence(params.evidence_requirements)?;

    Ok(scorchkit_core::ApplicationPentestScenario {
        schema: String::new(),
        identity: String::new(),
        name: params.name,
        proposal_source: scorchkit_core::ApplicationPentestProposalSource {
            kind: proposal_kind,
            label: params.proposal_label,
        },
        class,
        payload_class,
        operation: scorchkit_core::ApplicationPentestOperation {
            method: params.method,
            route: params.route,
            parameter,
        },
        personas,
        blast_radius: scorchkit_core::ApplicationPentestBlastRadius {
            max_seconds: params.max_seconds,
            max_concurrency: params.max_concurrency,
        },
        cleanup,
        preconditions: params.preconditions,
        evidence_requirements,
        source_finding_identities: params.source_finding_identities,
        source_path_identities: params.source_path_identities,
        source_references_verified: false,
    })
}

fn application_pentest_proposal_kind(
    value: &str,
) -> Result<scorchkit_core::ApplicationPentestProposalKind, String> {
    match value {
        "human" => Ok(scorchkit_core::ApplicationPentestProposalKind::Human),
        "agent" => Ok(scorchkit_core::ApplicationPentestProposalKind::Agent),
        "tool" => Ok(scorchkit_core::ApplicationPentestProposalKind::Tool),
        other => Err(format!(
            "unknown application-pentest proposal kind '{other}'; expected human, agent, or tool"
        )),
    }
}

fn application_pentest_class(
    value: &str,
) -> Result<scorchkit_core::ApplicationPentestScenarioClass, String> {
    use scorchkit_core::ApplicationPentestScenarioClass as Class;
    match value {
        "authorization_invariant" => Ok(Class::AuthorizationInvariant),
        "business_logic_invariant" => Ok(Class::BusinessLogicInvariant),
        "injection" => Ok(Class::Injection),
        "ssrf" => Ok(Class::Ssrf),
        "path_traversal" => Ok(Class::PathTraversal),
        "api_object_binding" => Ok(Class::ApiObjectBinding),
        "command_injection" => Ok(Class::CommandInjection),
        "file_upload" => Ok(Class::FileUpload),
        other => Err(format!("unknown application-pentest scenario class '{other}'")),
    }
}

fn application_pentest_payload(
    value: &str,
) -> Result<scorchkit_core::ApplicationPentestPayloadClass, String> {
    use scorchkit_core::ApplicationPentestPayloadClass as Payload;
    match value {
        "persona_comparison" => Ok(Payload::PersonaComparison),
        "syntax_boundary" => Ok(Payload::SyntaxBoundary),
        "internal_destination" => Ok(Payload::InternalDestination),
        "path_normalization" => Ok(Payload::PathNormalization),
        "field_boundary" => Ok(Payload::FieldBoundary),
        "command_proof" => Ok(Payload::CommandProof),
        "inert_upload" => Ok(Payload::InertUpload),
        other => Err(format!("unknown application-pentest payload class '{other}'")),
    }
}

fn application_pentest_parameter(
    name: Option<String>,
    location: Option<String>,
) -> Result<Option<scorchkit_core::HttpParameterIdentity>, String> {
    match (name, location) {
        (None, None) => Ok(None),
        (Some(name), Some(location)) => {
            Ok(Some(scorchkit_core::HttpParameterIdentity::new(name, location)))
        }
        _ => Err(
            "application-pentest parameter_name and parameter_location must be supplied together"
                .to_string(),
        ),
    }
}

fn application_pentest_personas(
    personas: Vec<ApplicationPentestPersonaParams>,
) -> Result<Vec<scorchkit_core::ApplicationPentestPersonaExpectation>, String> {
    personas
        .into_iter()
        .map(|persona| {
            let expected = match persona.expected.as_str() {
                "allow" => scorchkit_core::ApplicationPentestAccessExpectation::Allow,
                "deny" => scorchkit_core::ApplicationPentestAccessExpectation::Deny,
                other => {
                    return Err(format!(
                        "unknown application-pentest access expectation '{other}'; expected allow or deny"
                    ));
                }
            };
            Ok(scorchkit_core::ApplicationPentestPersonaExpectation {
                persona: persona.persona,
                expected,
            })
        })
        .collect()
}

fn application_pentest_cleanup(
    value: &str,
) -> Result<scorchkit_core::ApplicationPentestCleanupDisposition, String> {
    match value {
        "not_required" => Ok(scorchkit_core::ApplicationPentestCleanupDisposition::NotRequired),
        "manual_required" => {
            Ok(scorchkit_core::ApplicationPentestCleanupDisposition::ManualRequired)
        }
        other => Err(format!(
            "unknown application-pentest cleanup disposition '{other}'; expected not_required or manual_required"
        )),
    }
}

fn application_pentest_evidence(
    requirements: Vec<String>,
) -> Result<Vec<scorchkit_core::ApplicationPentestEvidenceRequirement>, String> {
    use scorchkit_core::ApplicationPentestEvidenceRequirement as Evidence;
    requirements
        .into_iter()
        .map(|requirement| match requirement.as_str() {
            "status_code" => Ok(Evidence::StatusCode),
            "response_difference" => Ok(Evidence::ResponseDifference),
            "error_signature" => Ok(Evidence::ErrorSignature),
            "out_of_band_callback" => Ok(Evidence::OutOfBandCallback),
            "file_marker" => Ok(Evidence::FileMarker),
            "cleanup_proof" => Ok(Evidence::CleanupProof),
            other => Err(format!("unknown application-pentest evidence requirement '{other}'")),
        })
        .collect()
}

fn manual_application_finding(
    params: ManualApplicationFindingParams,
) -> Result<crate::application_pentest::ManualApplicationFinding, String> {
    let severity = match params.severity.as_str() {
        "critical" => scorchkit_core::Severity::Critical,
        "high" => scorchkit_core::Severity::High,
        "medium" => scorchkit_core::Severity::Medium,
        "low" => scorchkit_core::Severity::Low,
        "info" => scorchkit_core::Severity::Info,
        other => {
            return Err(format!(
                "unknown manual finding severity '{other}'; expected critical, high, medium, low, or info"
            ));
        }
    };
    Ok(crate::application_pentest::ManualApplicationFinding {
        severity,
        title: params.title,
        description: params.description,
        remediation: params.remediation,
        cwe_id: params.cwe_id,
    })
}

fn job_id(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|error| format!("invalid scan job UUID '{value}': {error}"))
}

fn legacy_finding_projection(finding: FindingViewV1) -> Result<serde_json::Value, String> {
    let canonical = finding.canonical;
    let object = canonical
        .as_object()
        .ok_or_else(|| "validated control finding is not a JSON object".to_string())?;
    let required = |field: &str| {
        object
            .get(field)
            .cloned()
            .ok_or_else(|| format!("validated control finding has no {field}"))
    };
    let module_id = required("module_id")?;
    let severity = required("severity")?;
    let title = required("title")?;
    let description = required("description")?;
    let affected_target = required("affected_target")?;
    let confidence = required("confidence")?;
    let optional = |field: &str| object.get(field).cloned().unwrap_or(serde_json::Value::Null);
    let evidence = optional("evidence");
    let remediation = optional("remediation");
    let owasp_category = optional("owasp_category");
    let cwe_id = optional("cwe_id");
    Ok(serde_json::json!({
        "id": finding.id,
        "scan_id": finding.scan_id,
        "project_id": finding.project_id,
        "fingerprint": finding.fingerprint,
        "identity_schema": finding.identity_schema,
        "stable_identity": finding.stable_identity,
        "correlation_keys": finding.correlation_keys,
        "module_id": module_id,
        "severity": severity,
        "title": title,
        "description": description,
        "affected_target": affected_target,
        "evidence": evidence,
        "remediation": remediation,
        "owasp_category": owasp_category,
        "cwe_id": cwe_id,
        "raw_finding": canonical,
        "confidence": confidence,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "seen_count": finding.seen_count,
        "status": finding.status,
        "status_note": finding.status_note,
        "triage": finding.triage,
        "found_at": finding.found_at,
    }))
}

fn completed_job_result(job: ScanJob) -> Result<String, String> {
    match job.state {
        ScanJobState::Succeeded => serde_json::to_string_pretty(
            job.result.as_ref().ok_or_else(|| "successful scan job has no result".to_string())?,
        )
        .map_err(|error| error.to_string()),
        _ => Err(job.error.unwrap_or_else(|| format!("scan job ended in {}", job.state.as_str()))),
    }
}

/// Public business logic methods — called by both `#[tool]` wrappers and tests.
impl ScorchKitServer {
    fn control_engagement_id(&self) -> Result<Uuid, String> {
        self.config.engagement.as_ref().map(|engagement| engagement.id).ok_or_else(|| {
            "no engagement authorization configured for control operation".to_string()
        })
    }

    async fn control_query(&self, query: ControlQueryV1) -> Result<ControlResultV1, String> {
        self.execute_control(ControlRequestV1::query(
            query,
            self.config.engagement.as_ref().map(|engagement| engagement.id),
        ))
        .await
    }

    async fn control_command(&self, command: ControlCommandV1) -> Result<ControlResultV1, String> {
        self.execute_control(ControlRequestV1::command(command, self.control_engagement_id()?))
            .await
    }

    async fn control_projects(&self) -> Result<Vec<ProjectViewV1>, String> {
        let mut projects = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .control_query(ControlQueryV1::ListProjects {
                    page: PageRequestV1 {
                        cursor,
                        limit: self.config.control_api.default_page_size,
                    },
                })
                .await?;
            let ControlResultV1::Projects(page) = result else {
                return Err("control service returned an unexpected project result".to_string());
            };
            projects.extend(page.items);
            if projects.len() > MAX_LEGACY_CONTROL_ITEMS {
                return Err(
                    "control project result exceeds the MCP compatibility limit".to_string()
                );
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(projects);
            }
        }
    }

    async fn resolve_control_project(&self, reference: &str) -> Result<ProjectViewV1, String> {
        if let Ok(id) = Uuid::parse_str(reference) {
            let result = self.control_query(ControlQueryV1::GetProject { id }).await?;
            let ControlResultV1::Project(project) = result else {
                return Err("control service returned an unexpected project result".to_string());
            };
            return Ok(project);
        }
        self.control_projects()
            .await?
            .into_iter()
            .find(|project| project.name == reference)
            .ok_or_else(|| format!("project '{reference}' not found"))
    }

    async fn control_targets(&self, project_id: Uuid) -> Result<Vec<TargetViewV1>, String> {
        let mut targets = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .control_query(ControlQueryV1::ListTargets {
                    project_id,
                    page: PageRequestV1 {
                        cursor,
                        limit: self.config.control_api.default_page_size,
                    },
                })
                .await?;
            let ControlResultV1::Targets(page) = result else {
                return Err("control service returned an unexpected target result".to_string());
            };
            targets.extend(page.items);
            if targets.len() > MAX_LEGACY_CONTROL_ITEMS {
                return Err("control target result exceeds the MCP compatibility limit".to_string());
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(targets);
            }
        }
    }

    async fn control_findings(&self, project_id: Uuid) -> Result<Vec<FindingViewV1>, String> {
        let mut findings = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .control_query(ControlQueryV1::ListFindings {
                    project_id,
                    page: PageRequestV1 {
                        cursor,
                        limit: self.config.control_api.default_page_size,
                    },
                })
                .await?;
            let ControlResultV1::Findings(page) = result else {
                return Err("control service returned an unexpected finding result".to_string());
            };
            findings.extend(page.items);
            if findings.len() > MAX_LEGACY_CONTROL_ITEMS {
                return Err(
                    "control finding result exceeds the MCP compatibility limit".to_string()
                );
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(findings);
            }
        }
    }

    async fn control_modules(&self, family: &str) -> Result<Vec<ModuleViewV1>, String> {
        let mut modules = Vec::new();
        let mut cursor = None;
        loop {
            let response = self
                .execute_control(ControlRequestV1::query(
                    ControlQueryV1::ListModules {
                        family: Some(family.to_string()),
                        page: PageRequestV1 {
                            cursor,
                            limit: self.config.control_api.default_page_size,
                        },
                    },
                    self.config.engagement.as_ref().map(|engagement| engagement.id),
                ))
                .await?;
            let ControlResultV1::Modules(page) = response else {
                return Err("control service returned an unexpected module result".to_string());
            };
            modules.extend(page.items);
            if modules.len() > MAX_LEGACY_CONTROL_ITEMS {
                return Err("control module result exceeds the MCP compatibility limit".to_string());
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(modules);
            }
        }
    }

    /// List the default application-security scan catalog as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared control query or legacy serialization fails.
    pub async fn do_list_modules(&self) -> Result<String, String> {
        let selected: std::collections::BTreeSet<_> =
            self.control_modules("web").await?.into_iter().map(|module| module.id).collect();
        let modules = crate::runner::orchestrator::application_modules();
        let info: Vec<serde_json::Value> = modules
            .iter()
            .filter(|module| selected.contains(module.id()))
            .map(|m| {
                serde_json::json!({
                    "id": m.id(),
                    "name": m.name(),
                    "category": m.category().to_string(),
                    "description": m.description(),
                    "requires_external_tool": m.requires_external_tool(),
                    "required_tool": m.required_tool(),
                    "adapter": m.descriptor().adapter,
                })
            })
            .collect();
        serde_json::to_string_pretty(&info).map_err(|error| error.to_string())
    }

    /// Check which external tools are installed as JSON.
    #[must_use]
    pub fn do_check_tools(&self) -> String {
        let tools = [
            "nmap",
            "nikto",
            "nuclei",
            "zap.sh",
            "wpscan",
            "droopescan",
            "sqlmap",
            "dalfox",
            "feroxbuster",
            "ffuf",
            "arjun",
            "cewl",
            "sslyze",
            "testssl.sh",
            "amass",
            "subfinder",
            "httpx",
            "theHarvester",
            "wafw00f",
            "hydra",
            "msfconsole",
        ];
        let results: Vec<serde_json::Value> = tools
            .iter()
            .map(|&t| {
                let available = crate::runner::subprocess::is_tool_available(t);
                serde_json::json!({ "tool": t, "installed": available })
            })
            .collect();
        serde_json::to_string_pretty(&results).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    /// Run a scan against a target URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, the HTTP client cannot
    /// be built, or the scan fails.
    pub async fn do_scan(&self, params: ScanParams) -> Result<String, String> {
        let job = self.submit_scan_job(params).await?;
        completed_job_result(self.jobs.run(job.id).await.map_err(|error| error.to_string())?)
    }

    /// Run the explicit isolated application DAST service.
    ///
    /// # Errors
    ///
    /// Returns a typed message when request validation, authorization, execution, or result
    /// serialization fails.
    pub async fn do_application_dast(
        &self,
        params: ApplicationDastParams,
    ) -> Result<String, String> {
        let profile = scorchkit_core::ApplicationDastProfile::from_name(&params.profile)
            .ok_or_else(|| {
                format!(
                    "unknown application DAST profile '{}'; expected passive, standard, or active",
                    params.profile
                )
            })?;
        let schemas = params
            .schemas
            .into_iter()
            .map(|schema| {
                let kind = match schema.kind.as_str() {
                    "open_api" | "openapi" => scorchkit_core::ApplicationDastSchemaKind::OpenApi,
                    "graph_ql" | "graphql" => {
                        scorchkit_core::ApplicationDastSchemaKind::GraphQl
                    }
                    other => {
                        return Err(format!(
                            "unknown application DAST schema kind '{other}'; expected open_api or graph_ql"
                        ));
                    }
                };
                Ok(crate::application_dast::ApplicationDastSchemaRequest {
                    kind,
                    path: std::path::PathBuf::from(schema.path),
                    sha256: schema.sha256,
                    endpoint: schema.endpoint,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let request = crate::application_dast::ApplicationDastRequest {
            target: params.target,
            profile,
            include_anonymous: params.include_anonymous,
            personas: params.personas,
            schemas,
        };
        let result = Engine::new(Arc::clone(&self.config))
            .application_dast(&request)
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    async fn application_security_context(
        &self,
        params: ApplicationContextParams,
    ) -> Result<scorchkit_core::ApplicationSecurityContext, String> {
        let engine = Engine::new(Arc::clone(&self.config));
        let requested_path = std::path::PathBuf::from(&params.path);
        let code_context =
            engine.code_context(&requested_path, None).map_err(|error| error.to_string())?;
        if !code_context.path.is_dir() {
            return Err("application context path must be a directory".to_string());
        }
        let manifests = code_context
            .manifests
            .iter()
            .map(|manifest| {
                manifest
                    .strip_prefix(&code_context.path)
                    .map(|relative| relative.to_string_lossy().into_owned())
                    .map_err(|_| "detected manifest escaped the canonical code root".to_string())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let (project, registered_targets) = if let Some(project_ref) = params.project {
            let project = resolve_project(self.require_pool()?, &project_ref)
                .await
                .map_err(|error| error.to_string())?;
            let targets = projects::list_targets(self.require_pool()?, project.id)
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|target| scorchkit_core::ApplicationContextTarget {
                    url: target.url,
                    label: (!target.label.is_empty()).then_some(target.label),
                    provenance: scorchkit_core::ApplicationContextProvenance::ProjectRegistered,
                })
                .collect();
            (Some(project.name), targets)
        } else {
            (None, Vec::new())
        };
        let change_set = params
            .change_set
            .map(|change_set| {
                scorchkit_core::compile_application_change_set(
                    &change_set.base_revision,
                    &change_set.head_revision,
                    change_set.changed_paths,
                )
                .map_err(|error| error.to_string())
            })
            .transpose()?;
        let engagement = engine
            .engagement()
            .ok_or_else(|| "application context requires a configured engagement".to_string())?;
        let input = scorchkit_core::ApplicationSecurityContextInput {
            code_root: code_context.path.to_string_lossy().into_owned(),
            languages: code_context.languages,
            manifests,
            change_set,
            routes: params
                .routes
                .into_iter()
                .map(|value| scorchkit_core::ApplicationContextValue {
                    value,
                    provenance: scorchkit_core::ApplicationContextProvenance::HostDeclared,
                })
                .collect(),
            artifacts: params
                .artifacts
                .into_iter()
                .map(|value| scorchkit_core::ApplicationContextValue {
                    value,
                    provenance: scorchkit_core::ApplicationContextProvenance::HostDeclared,
                })
                .collect(),
            project,
            registered_targets,
            persona_labels: self.config.dast.personas.keys().cloned().collect(),
            configured_capabilities: engagement.policy.capabilities.iter().copied().collect(),
            configured_effects: engagement.policy.effects.iter().copied().collect(),
        };
        scorchkit_core::compile_application_security_context(input)
            .map_err(|error| error.to_string())
    }

    /// Return the canonical provider-neutral application context without running a scanner.
    ///
    /// # Errors
    ///
    /// Returns an error before discovery for a denied root and for an invalid change set, declared
    /// input, project, registered target, or context limit.
    pub async fn do_application_context(
        &self,
        params: ApplicationContextParams,
    ) -> Result<String, String> {
        let context = self.application_security_context(params).await?;
        serde_json::to_string_pretty(&context).map_err(|error| error.to_string())
    }

    /// Compile one inert application-security workflow without running a named step.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid context, profile, or focused-selection identity.
    pub async fn do_plan_appsec_workflow(
        &self,
        params: ApplicationSecurityWorkflowParams,
    ) -> Result<String, String> {
        let profile = scorchkit_core::ApplicationSecurityWorkflowProfile::parse(&params.profile)
            .map_err(|error| error.to_string())?;
        let context = self.application_security_context(params.context).await?;
        let focused_selection = params.focused_selection.map(focused_verification_selection);
        let plan = scorchkit_core::compile_application_security_workflow(
            &context,
            profile,
            focused_selection,
        )
        .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&plan).map_err(|error| error.to_string())
    }

    /// Compile inert proposals into a canonical application-pentest plan without performing any
    /// target, credential, filesystem, or subprocess effect.
    ///
    /// # Errors
    ///
    /// Returns a typed message when a target, scenario, or closed executor mapping is invalid.
    pub fn do_plan_application_pentest(
        &self,
        params: ApplicationPentestPlanParams,
    ) -> Result<String, String> {
        let scenarios = application_pentest_scenarios(params.scenarios)?;
        let plan = Engine::new(Arc::clone(&self.config))
            .plan_application_pentest(&params.target, scenarios)
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&plan).map_err(|error| error.to_string())
    }

    /// Execute one exact, reviewed application-pentest plan and persist its typed coverage.
    ///
    /// # Errors
    ///
    /// Returns a typed message before target effects for an unknown project/target, plan mismatch,
    /// denied grant, invalid scenario, or persistence failure.
    pub async fn do_application_pentest(
        &self,
        params: ApplicationPentestExecuteParams,
    ) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|error| error.to_string())?;
        let target = Target::parse(&params.target).map_err(|error| error.to_string())?;
        require_registered_project_target(self.require_pool()?, project.id, &target)
            .await
            .map_err(|error| error.to_string())?;
        let scenarios = application_pentest_scenarios(params.scenarios)?;
        let engine = Engine::new(Arc::clone(&self.config));
        let plan = engine
            .plan_application_pentest(&params.target, scenarios.clone())
            .map_err(|error| error.to_string())?;
        let result = engine
            .application_pentest(&params.target, scenarios, &params.approved_plan_identity)
            .await
            .map_err(|error| error.to_string())?;
        let stored =
            findings::save_application_pentest_scan(self.require_pool()?, project.id, &result)
                .await
                .map_err(|error| error.to_string())?;
        let output = serde_json::json!({
            "scan_id": stored.scan.id,
            "project": project.name,
            "plan": plan,
            "assessment": result.application_pentest,
            "findings_total": result.findings.len(),
            "findings_new": stored.findings_new,
            "findings_updated": result.findings.len().saturating_sub(stored.findings_new),
            "summary": result.summary,
        });
        serde_json::to_string_pretty(&output).map_err(|error| error.to_string())
    }

    /// Verify, redact, and atomically persist one local manual/proxy application evidence file.
    ///
    /// # Errors
    ///
    /// Returns a typed message for an unknown project/target/finding, denied local-file grant,
    /// unsafe file, digest mismatch, malformed evidence, scope escape, or failed transaction.
    pub async fn do_import_application_evidence(
        &self,
        params: ApplicationEvidenceImportParams,
    ) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|error| error.to_string())?;
        let target = Target::parse(&params.target).map_err(|error| error.to_string())?;
        require_registered_project_target(self.require_pool()?, project.id, &target)
            .await
            .map_err(|error| error.to_string())?;
        let format = match params.format.as_str() {
            "har" => scorchkit_core::ApplicationEvidenceFormat::Har,
            "http_exchange" => scorchkit_core::ApplicationEvidenceFormat::HttpExchange,
            other => {
                return Err(format!(
                    "unknown application evidence format '{other}'; expected har or http_exchange"
                ));
            }
        };
        let source_kind = match params.source_kind.as_str() {
            "human" => scorchkit_core::ApplicationEvidenceSourceKind::Human,
            "proxy" => scorchkit_core::ApplicationEvidenceSourceKind::Proxy,
            "tool" => scorchkit_core::ApplicationEvidenceSourceKind::Tool,
            other => {
                return Err(format!(
                    "unknown application evidence source kind '{other}'; expected human, proxy, or tool"
                ));
            }
        };
        let finding_id = params
            .finding_id
            .map(|value| {
                Uuid::parse_str(&value)
                    .map_err(|error| format!("invalid application evidence finding UUID: {error}"))
            })
            .transpose()?;
        let new_finding = params.new_finding.map(manual_application_finding).transpose()?;
        let request = crate::application_pentest::ApplicationEvidenceImportRequest {
            target: params.target,
            path: std::path::PathBuf::from(params.path),
            expected_sha256: params.sha256,
            format,
            source_kind,
            source_label: params.source_label,
            finding_id,
            new_finding,
        };
        let prepared = Engine::new(Arc::clone(&self.config))
            .prepare_application_evidence_import(&request)
            .map_err(|error| error.to_string())?;
        let stored =
            findings::save_application_evidence_import(self.require_pool()?, project.id, &prepared)
                .await
                .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&stored).map_err(|error| error.to_string())
    }

    /// Submit a stateless DAST job and return before scanner modules complete.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization, request validation, or initial persistence fails.
    pub async fn do_scan_job_start(&self, params: ScanParams) -> Result<String, String> {
        let result = self
            .control_command(ControlCommandV1::StartJob {
                target: params.target,
                profile: params.profile,
                modules: params.modules.as_deref().map(comma_separated),
                skip: params.skip.as_deref().map_or_else(Vec::new, comma_separated),
            })
            .await?;
        let ControlResultV1::Job(job) = result else {
            return Err("control service returned an unexpected scan job result".to_string());
        };
        let stored = self.jobs.get(job.id).await.map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&stored).map_err(|error| error.to_string())
    }

    /// Return the complete persisted state of one scan job.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid or the job does not exist.
    pub async fn do_scan_job_status(&self, params: ScanJobRefParams) -> Result<String, String> {
        let id = job_id(&params.job_id)?;
        let result = self.control_query(ControlQueryV1::GetJob { id }).await?;
        if !matches!(result, ControlResultV1::Job(_)) {
            return Err("control service returned an unexpected scan job result".to_string());
        }
        let job = self.jobs.get(id).await.map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&job).map_err(|error| error.to_string())
    }

    /// Persist and signal cancellation for a queued or running job.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid, missing, or no longer cancellable.
    pub async fn do_scan_job_cancel(&self, params: ScanJobRefParams) -> Result<String, String> {
        let id = job_id(&params.job_id)?;
        let result = self.control_command(ControlCommandV1::CancelJob { id }).await?;
        if !matches!(result, ControlResultV1::Job(_)) {
            return Err("control service returned an unexpected scan job result".to_string());
        }
        let job = self.jobs.get(id).await.map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&job).map_err(|error| error.to_string())
    }

    /// Create and start a successor attempt for an interrupted job.
    ///
    /// # Errors
    ///
    /// Returns an error when the job is not interrupted or current authorization differs.
    pub async fn do_scan_job_resume(&self, params: ScanJobRefParams) -> Result<String, String> {
        let result = self
            .control_command(ControlCommandV1::ResumeJob { id: job_id(&params.job_id)? })
            .await?;
        let ControlResultV1::Job(job) = result else {
            return Err("control service returned an unexpected scan job result".to_string());
        };
        let stored = self.jobs.get(job.id).await.map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&stored).map_err(|error| error.to_string())
    }

    async fn submit_scan_job(&self, params: ScanParams) -> Result<ScanJob, String> {
        let engagement = self
            .config
            .engagement
            .clone()
            .ok_or_else(|| "no engagement authorization configured for scan job".to_string())?;
        let request = DastJobRequest::new(params.target, params.profile, engagement)
            .with_modules(params.modules.as_deref().map(comma_separated))
            .with_skip(params.skip.as_deref().map_or_else(Vec::new, comma_separated));
        self.jobs.submit(request).await.map_err(|error| error.to_string())
    }

    /// Create a new project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project name already exists or the database fails.
    pub async fn do_project_create(&self, params: ProjectCreateParams) -> Result<String, String> {
        let desc = params.description.as_deref().unwrap_or("");
        let result = self
            .control_command(ControlCommandV1::CreateProject {
                name: params.name,
                description: desc.to_string(),
            })
            .await?;
        let ControlResultV1::Project(project) = result else {
            return Err("control service returned an unexpected project result".to_string());
        };
        serde_json::to_string_pretty(&project).map_err(|error| error.to_string())
    }

    /// List all projects.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn do_project_list(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.control_projects().await?)
            .map_err(|error| error.to_string())
    }

    /// Show project details.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_show(&self, params: ProjectRefParams) -> Result<String, String> {
        let project = self.resolve_control_project(&params.project).await?;
        let targets = self.control_targets(project.id).await?;
        let report =
            self.control_query(ControlQueryV1::GetProjectReport { project_id: project.id }).await?;
        let ControlResultV1::Report(report) = report else {
            return Err("control service returned an unexpected project report".to_string());
        };
        let scan_list =
            scans::list_scans(self.require_pool()?, project.id).await.map_err(|e| e.to_string())?;

        let result = serde_json::json!({
            "project": project,
            "targets": targets,
            "scan_count": report.scan_count,
            "finding_count": report.finding_count,
            "recent_scans": scan_list.iter().take(5).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    /// Delete a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_delete(&self, params: ProjectDeleteParams) -> Result<String, String> {
        let project = self.resolve_control_project(&params.project).await?;

        if !params.force {
            return serde_json::to_string_pretty(&serde_json::json!({
                "warning": format!(
                    "This will delete project '{}' and ALL associated data. Set force=true to confirm.",
                    project.name
                ),
            }))
            .map_err(|error| error.to_string());
        }

        let result =
            self.control_command(ControlCommandV1::DeleteProject { id: project.id }).await?;
        if !matches!(result, ControlResultV1::Acknowledged { changed: true, affected: 1 }) {
            return Err("control service did not confirm project deletion".to_string());
        }
        serde_json::to_string_pretty(&serde_json::json!({
            "deleted": true,
            "project": project.name,
        }))
        .map_err(|error| error.to_string())
    }

    /// Scan within a project, persisting results.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the scan fails, or persistence fails.
    pub async fn do_project_scan(&self, params: ProjectScanParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        require_registered_project_target(self.require_pool()?, project.id, &target)
            .await
            .map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx =
            engine.dast_context_for_target(target, &params.profile).map_err(|e| e.to_string())?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        let modules = params.modules.as_deref().map(comma_separated);
        orchestrator.apply_selection(&params.profile, modules.as_deref());
        if let Some(skip) = params.skip.as_deref() {
            orchestrator.exclude_by_ids(&comma_separated(skip));
        }

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        let modules_run = result.modules_run.clone();
        let modules_skipped: Vec<String> =
            result.modules_skipped.iter().map(|(id, _)| id.clone()).collect();
        let summary_json = serde_json::to_value(&result.summary).map_err(|e| e.to_string())?;

        let scan = scans::save_scan_with_evidence(
            self.require_pool()?,
            project.id,
            result.target.url.as_str(),
            &params.profile,
            result.started_at,
            Some(result.completed_at),
            &modules_run,
            &modules_skipped,
            &summary_json,
            &scans::execution_evidence(&result),
        )
        .await
        .map_err(|e| e.to_string())?;

        let new_count =
            findings::save_findings(self.require_pool()?, project.id, scan.id, &result.findings)
                .await
                .map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "scan_id": scan.id,
            "project": project.name,
            "target": result.target.url.as_str(),
            "modules_run": modules_run,
            "modules_skipped": modules_skipped,
            "findings_total": result.findings.len(),
            "findings_new": new_count,
            "findings_updated": result.findings.len() - new_count,
            "summary": result.summary,
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// List findings for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_findings(&self, params: FindingListParams) -> Result<String, String> {
        let project = self.resolve_control_project(&params.project).await?;
        let mut finding_list = self.control_findings(project.id).await?;
        if let Some(severity) = params.severity.as_deref() {
            if !matches!(severity, "critical" | "high" | "medium" | "low" | "info") {
                return Err(format!("invalid severity '{severity}'"));
            }
            finding_list.retain(|finding| {
                finding.canonical.get("severity").and_then(serde_json::Value::as_str)
                    == Some(severity)
            });
        } else if let Some(status) = params.status.as_deref() {
            if crate::storage::models::VulnStatus::from_db(status).is_none() {
                return Err(format!(
                    "invalid status '{status}'. Valid: new, acknowledged, false_positive, \
                     remediated, verified"
                ));
            }
            finding_list.retain(|finding| finding.status == status);
        }
        let projected = finding_list
            .into_iter()
            .map(legacy_finding_projection)
            .collect::<Result<Vec<_>, _>>()?;
        serde_json::to_string_pretty(&projected).map_err(|error| error.to_string())
    }

    /// Show a single finding.
    ///
    /// # Errors
    ///
    /// Returns an error if the UUID is invalid or the finding is not found.
    pub async fn do_finding_show(&self, params: FindingRefParams) -> Result<String, String> {
        let id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid finding UUID '{}': {e}", params.id))?;
        let result = self.control_query(ControlQueryV1::GetFinding { id }).await?;
        let ControlResultV1::Finding(finding) = result else {
            return Err("control service returned an unexpected finding result".to_string());
        };
        serde_json::to_string_pretty(&legacy_finding_projection(finding)?)
            .map_err(|error| error.to_string())
    }

    /// Update a finding's lifecycle status.
    ///
    /// # Errors
    ///
    /// Returns an error if the UUID is invalid, the status is invalid, or
    /// the finding is not found.
    pub async fn do_finding_update_status(
        &self,
        params: FindingUpdateStatusParams,
    ) -> Result<String, String> {
        let id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid finding UUID '{}': {e}", params.id))?;
        let status =
            crate::storage::models::VulnStatus::from_db(&params.status).ok_or_else(|| {
                format!(
                    "invalid status '{}'. \
                     Valid: new, acknowledged, false_positive, remediated, verified",
                    params.status
                )
            })?;

        let state = scorchkit_core::triage_state_from_legacy(status.as_db_str())
            .ok_or_else(|| "legacy finding status has no triage mapping".to_string())?;
        let result = self
            .control_command(ControlCommandV1::TransitionFinding {
                finding_id: id,
                state: state.as_str().to_string(),
                reason: format!("Legacy MCP status update to {}", status.as_db_str()),
                evidence_ids: Vec::new(),
                model_analysis_identity: None,
            })
            .await?;
        let ControlResultV1::Finding(finding) = result else {
            return Err("control service returned an unexpected finding transition result".into());
        };
        serde_json::to_string_pretty(&serde_json::json!({
            "updated": true,
            "id": finding.id,
            "status": finding.status,
            "triage": finding.triage,
        }))
        .map_err(|error| error.to_string())
    }

    /// Add a target to a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_target_add(&self, params: TargetAddParams) -> Result<String, String> {
        let project = self.resolve_control_project(&params.project).await?;
        let label = params.label.as_deref().unwrap_or("");
        let result = self
            .control_command(ControlCommandV1::AddTarget {
                project_id: project.id,
                url: params.url,
                label: label.to_string(),
            })
            .await?;
        let ControlResultV1::Target(target) = result else {
            return Err("control service returned an unexpected target result".to_string());
        };
        serde_json::to_string_pretty(&target).map_err(|error| error.to_string())
    }

    /// List targets for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_target_list(&self, params: ProjectRefParams) -> Result<String, String> {
        let project = self.resolve_control_project(&params.project).await?;
        serde_json::to_string_pretty(&self.control_targets(project.id).await?)
            .map_err(|error| error.to_string())
    }

    /// Remove a target from a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project/target is not found or the database fails.
    pub async fn do_target_remove(&self, params: TargetRemoveParams) -> Result<String, String> {
        let project = self.resolve_control_project(&params.project).await?;
        let target_id = Uuid::parse_str(&params.id)
            .map_err(|e| format!("invalid target UUID '{}': {e}", params.id))?;
        let result = self
            .control_command(ControlCommandV1::RemoveTarget { project_id: project.id, target_id })
            .await?;
        if matches!(result, ControlResultV1::Acknowledged { changed: true, affected: 1 }) {
            Ok(format!("{{\"removed\": true, \"id\": \"{target_id}\"}}"))
        } else {
            Err(format!("target '{}' not found", params.id))
        }
    }

    /// Run database migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if migration execution fails.
    pub async fn do_db_migrate(&self) -> Result<String, String> {
        crate::storage::migrate::run_migrations(self.require_pool()?)
            .await
            .map_err(|e| e.to_string())?;
        Ok("{\"success\": true, \"message\": \"Database migrations complete\"}".to_string())
    }

    /// Create a recurring scan schedule for a project.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the cron expression
    /// is invalid, or the database fails.
    pub async fn do_schedule_scan(&self, params: ScheduleScanParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        require_registered_project_target(self.require_pool()?, project.id, &target)
            .await
            .map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        engine
            .authorize_web_scan_for_profile(&target.url, &params.profile)
            .map_err(|e| e.to_string())?;
        let schedule = schedules::create_schedule(
            self.require_pool()?,
            project.id,
            target.url.as_str(),
            &params.profile,
            &params.cron,
            engine.engagement().ok_or_else(|| {
                "schedule creation denied: no engagement authorization is configured".to_string()
            })?,
        )
        .await
        .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&schedule).map_err(|e| e.to_string())
    }

    /// Find and execute all due scan schedules.
    ///
    /// Returns a summary of executed scans and their results.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails. Individual scan
    /// failures are captured in the results, not propagated.
    pub async fn do_run_due_scans(&self) -> Result<String, String> {
        let outcomes =
            crate::cli::schedule::execute_due_schedules(self.require_pool()?, &self.config)
                .await
                .map_err(|e| e.to_string())?;

        if outcomes.is_empty() {
            return Ok("{\"executed\": 0, \"message\": \"No schedules are due\"}".to_string());
        }

        let executed = outcomes.len();
        let output = serde_json::json!({
            "executed": executed,
            "results": outcomes,
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Get security posture metrics and trend analysis for a project.
    ///
    /// Returns aggregate metrics including severity/status breakdowns,
    /// regression detection, trend direction, and top unresolved findings.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database fails.
    pub async fn do_project_status(&self, params: ProjectStatusParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let posture =
            metrics::build_posture_metrics(self.require_pool()?, project.id, &project.name)
                .await
                .map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&posture).map_err(|e| e.to_string())
    }

    /// Run AI-guided scan planning: recon first, then the configured provider decides modules.
    ///
    /// Returns a structured [`crate::ai::types::ScanPlan`] as JSON without executing the scan.
    /// The MCP client can inspect and approve the plan before calling `scan`
    /// or `project-scan` to execute.
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, AI is disabled, or
    /// the configured provider is unavailable.
    pub async fn do_plan_scan(&self, params: PlanScanParams) -> Result<String, String> {
        if !self.config.ai.enabled {
            return Err("AI is disabled in config — scan planning requires AI".to_string());
        }

        let planner = crate::ai::planner::ScanPlanner::from_config(&self.config.ai);
        if !planner.is_available() {
            return Err(format!(
                "{} not found. Install or configure the selected AI provider.",
                planner.provider_name()
            ));
        }

        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        engine.dast_context_for_target(target.clone(), "quick").map_err(|e| e.to_string())?;
        engine
            .require_authorized(
                PolicyTarget::Web(target.url.clone()),
                Capability::ExternalTool,
                EffectClass::ActiveSafe,
            )
            .map_err(|e| e.to_string())?;
        let plan = planner.plan(&target, &engine).await.map_err(|e| e.to_string())?;

        serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())
    }

    /// Analyze findings for a project using AI with structured output.
    ///
    /// Loads findings from the database, builds project context for trend
    /// awareness, runs provider-neutral AI analysis, and returns structured JSON results.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found, the AI analyst is
    /// unavailable, or the analysis subprocess fails.
    pub async fn do_analyze_findings(
        &self,
        params: AnalyzeFindingsParams,
    ) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;

        let focus = crate::ai::prompts::AnalysisFocus::parse(&params.focus);

        // Load findings: from specific scan or all project findings
        let tracked_findings = if let Some(ref scan_id_str) = params.scan_id {
            let scan_id = Uuid::parse_str(scan_id_str)
                .map_err(|e| format!("invalid scan UUID '{scan_id_str}': {e}"))?;
            findings::find_by_scan(self.require_pool()?, scan_id)
                .await
                .map_err(|e| e.to_string())?
        } else {
            findings::list_findings(self.require_pool()?, project.id)
                .await
                .map_err(|e| e.to_string())?
        };

        if tracked_findings.is_empty() {
            return Ok("{\"analysis\": {\"type\": \"raw\", \"content\": \
                       \"No findings to analyze.\"}, \"cost_usd\": null}"
                .to_string());
        }

        // Convert tracked findings back to engine Findings via raw_finding JSON
        let engine_findings: Vec<crate::engine::finding::Finding> = tracked_findings
            .iter()
            .filter_map(|tf| serde_json::from_value(tf.raw_finding.clone()).ok())
            .collect();

        // Build a minimal ScanResult for the analyzer
        let scan_records =
            scans::list_scans(self.require_pool()?, project.id).await.map_err(|e| e.to_string())?;
        let target_url = scan_records.first().map_or("unknown", |s| s.target_url.as_str());
        let target = crate::engine::target::Target::parse(target_url).map_err(|e| e.to_string())?;
        let scan_result = crate::engine::scan_result::ScanResult::new(
            Uuid::new_v4().to_string(),
            target,
            chrono::Utc::now(),
            engine_findings,
            Vec::new(),
            Vec::new(),
        );

        // Build project context for trend-aware analysis
        let project_context =
            context::build_project_context(self.require_pool()?, project.id, &project.name)
                .await
                .map_err(|e| e.to_string())?;

        // Run AI analysis
        if !self.config.ai.enabled {
            return Err("AI analysis is disabled in config".to_string());
        }

        let analyst = crate::ai::analyst::AiAnalyst::from_config(&self.config.ai);
        if !analyst.is_available() {
            return Err(format!(
                "{} not found. Install or configure the selected AI provider.",
                analyst.provider_name()
            ));
        }

        Engine::new(Arc::clone(&self.config))
            .require_authorized(
                PolicyTarget::Web(scan_result.target.url.clone()),
                Capability::ExternalTool,
                EffectClass::Passive,
            )
            .map_err(|e| e.to_string())?;

        let analysis = analyst
            .analyze(&scan_result, focus, Some(&project_context))
            .await
            .map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "project": project.name,
            "focus": analysis.focus.label(),
            "analysis": analysis.analysis,
            "cost_usd": analysis.cost_usd,
            "model": analysis.model,
        });

        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Run a full scan engagement in one call: parse target, build orchestrator,
    /// run scan with the specified profile, and optionally persist results to
    /// a project.
    ///
    /// This is the "one-shot" scanning tool — an MCP agent can call this instead of
    /// manually composing `scan` + `project_scan`. Does NOT include AI
    /// planning or analysis (use `plan_scan` and `analyze_findings` separately).
    ///
    /// # Errors
    ///
    /// Returns an error if the target URL is invalid, the HTTP client cannot
    /// be built, the scan fails, or project persistence fails.
    pub async fn do_auto_scan(&self, params: AutoScanParams) -> Result<String, String> {
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let project = if let Some(project_ref) = params.project.as_deref() {
            let project = resolve_project(self.require_pool()?, project_ref)
                .await
                .map_err(|e| e.to_string())?;
            require_registered_project_target(self.require_pool()?, project.id, &target)
                .await
                .map_err(|e| e.to_string())?;
            Some(project)
        } else {
            None
        };
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx =
            engine.dast_context_for_target(target, &params.profile).map_err(|e| e.to_string())?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(&params.profile);

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        // Optionally persist to project
        if let Some(project) = project {
            let modules_run: Vec<String> = result.modules_run.iter().map(String::clone).collect();
            let modules_skipped: Vec<String> = result
                .modules_skipped
                .iter()
                .map(|(id, reason)| format!("{id}: {reason}"))
                .collect();
            let summary_json = serde_json::to_value(&result.summary).map_err(|e| e.to_string())?;

            let scan_record = scans::save_scan_with_evidence(
                self.require_pool()?,
                project.id,
                result.target.url.as_str(),
                &params.profile,
                result.started_at,
                Some(result.completed_at),
                &modules_run,
                &modules_skipped,
                &summary_json,
                &scans::execution_evidence(&result),
            )
            .await
            .map_err(|e| e.to_string())?;
            let saved_count = findings::save_findings(
                self.require_pool()?,
                project.id,
                scan_record.id,
                &result.findings,
            )
            .await
            .map_err(|e| e.to_string())?;

            let output = serde_json::json!({
                "scan_id": result.scan_id,
                "target": crate::engine::observation::redact_url(&result.target.raw).0,
                "profile": params.profile,
                "project": project.name,
                "persisted": true,
                "findings_saved": saved_count,
                "summary": {
                    "total": result.summary.total_findings,
                    "critical": result.summary.critical,
                    "high": result.summary.high,
                    "medium": result.summary.medium,
                    "low": result.summary.low,
                    "info": result.summary.info,
                },
                "modules_run": result.modules_run.len(),
                "duration_seconds": (result.completed_at - result.started_at).num_seconds(),
            });
            return serde_json::to_string_pretty(&output).map_err(|e| e.to_string());
        }

        // No project — return full scan result
        let output = serde_json::json!({
            "scan_id": result.scan_id,
            "target": crate::engine::observation::redact_url(&result.target.raw).0,
            "profile": params.profile,
            "persisted": false,
            "summary": {
                "total": result.summary.total_findings,
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
                "info": result.summary.info,
            },
            "modules_run": result.modules_run.len(),
            "duration_seconds": (result.completed_at - result.started_at).num_seconds(),
            "top_findings": result
                .findings
                .iter()
                .take(5)
                .map(redacted_top_finding)
                .collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Run recon-only modules against a target for consolidated intelligence.
    ///
    /// Executes only modules with `ModuleCategory::Recon` — headers, tech
    /// detection, discovery, subdomain enumeration, crawling, DNS security.
    /// Returns a consolidated briefing without any active vulnerability scanning.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is invalid, the HTTP client cannot be
    /// built, or the recon scan fails.
    pub async fn do_target_intelligence(
        &self,
        params: TargetIntelligenceParams,
    ) -> Result<String, String> {
        let target = Target::parse(&params.target).map_err(|e| e.to_string())?;
        let engine = Engine::new(Arc::clone(&self.config));
        let ctx = engine.dast_context_for_target(target, "quick").map_err(|e| e.to_string())?;

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.filter_by_category(crate::engine::module_trait::ModuleCategory::Recon);

        let result = orchestrator.run(true).await.map_err(|e| e.to_string())?;

        let output = serde_json::json!({
            "target": crate::engine::observation::redact_url(&result.target.raw).0,
            "recon_modules_run": result.modules_run,
            "total_findings": result.summary.total_findings,
            "duration_seconds": (result.completed_at - result.started_at).num_seconds(),
            "intelligence": result
                .findings
                .iter()
                .map(redacted_intelligence_finding)
                .collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Get the status of the most recent scan for a project.
    ///
    /// Queries the database for the latest scan record and returns metadata
    /// including scan ID, target, timing, module count, and finding count.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database query fails.
    pub async fn do_scan_progress(&self, params: ScanProgressParams) -> Result<String, String> {
        let project = resolve_project(self.require_pool()?, &params.project)
            .await
            .map_err(|e| e.to_string())?;
        let scan_records =
            scans::list_scans(self.require_pool()?, project.id).await.map_err(|e| e.to_string())?;

        let Some(latest) = scan_records.first() else {
            return Ok(serde_json::json!({
                "project": project.name,
                "status": "no_scans",
                "message": "No scans have been run for this project yet.",
            })
            .to_string());
        };

        let finding_count = findings::list_findings(self.require_pool()?, project.id)
            .await
            .map_err(|e| e.to_string())?
            .len();

        let status = if latest.completed_at.is_some() { "complete" } else { "in_progress" };

        let output = serde_json::json!({
            "project": project.name,
            "status": status,
            "latest_scan": {
                "scan_id": latest.id.to_string(),
                "target": &latest.target_url,
                "profile": &latest.profile,
                "started_at": latest.started_at.to_rfc3339(),
                "completed_at": latest.completed_at.map(|d| d.to_rfc3339()),
                "modules_run": latest.modules_run,
            },
            "total_scans": scan_records.len(),
            "total_tracked_findings": finding_count,
        });
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// Correlate project findings into canonical source-to-runtime attack paths.
    ///
    /// Canonical paths use only typed finding-v2 evidence. The former title/module matcher remains
    /// present under an explicit compatibility-only, unverified label.
    ///
    /// # Errors
    ///
    /// Returns an error if the project is not found or the database query fails.
    pub async fn do_correlate_findings(
        &self,
        params: CorrelateFindingsParams,
    ) -> Result<String, String> {
        let pool = self.require_pool()?;
        let project = resolve_project(pool, &params.project).await.map_err(|e| e.to_string())?;
        let finding_count =
            findings::count_findings(pool, project.id).await.map_err(|e| e.to_string())?;
        if finding_count > crate::engine::attack_path::MAX_CORRELATION_FINDINGS {
            return finding_limit_correlation_output(&project.name, finding_count);
        }
        let tracked_findings =
            findings::list_findings(pool, project.id).await.map_err(|e| e.to_string())?;
        let evidence_limit = crate::engine::attack_path::MAX_CORRELATION_PROJECT_EVIDENCE;
        let mut stored_evidence =
            findings::list_project_evidence(pool, project.id, evidence_limit + 1)
                .await
                .map_err(|e| e.to_string())?;
        let evidence_limit_hit = stored_evidence.len() > evidence_limit;
        stored_evidence.truncate(evidence_limit);

        let correlation_findings: Vec<super::prompts::CorrelationFinding> = tracked_findings
            .iter()
            .map(|f| super::prompts::CorrelationFinding {
                id: f.id.to_string(),
                module_id: f.module_id.clone(),
                title: f.title.clone(),
                severity: f.severity.clone(),
            })
            .collect();

        let legacy_chains = super::prompts::correlate_attack_chains(&correlation_findings);
        let (canonical_findings, mut malformed_gaps) =
            canonical_correlation_inventory(&tracked_findings, stored_evidence);
        let canonical_finding_count = canonical_findings.len();
        if evidence_limit_hit {
            malformed_gaps.push(crate::engine::attack_path::AttackPathCorrelationGap {
                kind: crate::engine::attack_path::AttackPathCorrelationGapKind::ProjectEvidenceLimitExceeded,
                finding_identity: None,
            });
        }
        let mut correlation =
            crate::engine::attack_path::correlate_attack_paths(&canonical_findings);
        if !malformed_gaps.is_empty() {
            correlation.status =
                crate::engine::attack_path::AttackPathCorrelationStatus::Incomplete;
            correlation.gaps.append(&mut malformed_gaps);
            correlation.gaps.sort();
            correlation.gaps.dedup();
        }

        let output = serde_json::json!({
            "schema": correlation.schema,
            "project": project.name,
            "total_findings_available": tracked_findings.len(),
            "total_findings_analyzed": canonical_finding_count,
            "status": correlation.status,
            "attack_paths_found": correlation.paths.len(),
            "attack_paths": correlation.paths,
            "gaps": correlation.gaps,
            "legacy_unverified_attack_chains": {
                "status": "unverified_heuristic",
                "attack_chains_found": legacy_chains.len(),
                "chains": legacy_chains,
            },
        });

        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }

    /// List the default application code-scanning catalog as JSON.
    #[must_use]
    pub fn do_list_code_modules(&self) -> String {
        let modules = crate::runner::code_orchestrator::application_code_modules();
        let info: Vec<serde_json::Value> = modules
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id(),
                    "name": m.name(),
                    "category": m.category().to_string(),
                    "depth": m.depth(),
                    "description": m.description(),
                    "languages": m.languages(),
                    "requires_external_tool": m.requires_external_tool(),
                    "required_tool": m.required_tool(),
                    "adapter": m.descriptor().adapter,
                })
            })
            .collect();
        serde_json::to_string_pretty(&info).unwrap_or_else(|_| "[]".to_string())
    }

    /// Run a SAST code scan on a filesystem path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or the scan fails.
    pub async fn do_scan_code(
        &self,
        params: super::types::CodeScanParams,
    ) -> Result<String, String> {
        crate::facade::validate_scan_profile(&params.profile).map_err(|error| error.to_string())?;
        let path = std::path::PathBuf::from(&params.path);
        if !path.exists() {
            return Err(format!("path '{}' does not exist", params.path));
        }

        let engine = Engine::new(Arc::clone(&self.config));
        let ctx =
            engine.code_context(&path, params.language.as_deref()).map_err(|e| e.to_string())?;

        let mut orchestrator = crate::runner::code_orchestrator::CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();

        // Apply language filter if specified
        if let Some(ref lang) = params.language {
            orchestrator.filter_by_language(lang);
        }

        // Explicit module IDs may select the compatibility catalog; otherwise use the
        // application-only standard profile.
        let modules = params.modules.as_deref().map(comma_separated);
        orchestrator.apply_selection(&params.profile, modules.as_deref());
        if let Some(ref skip) = params.skip {
            let ids: Vec<String> = skip.split(',').map(|s| s.trim().to_string()).collect();
            orchestrator.exclude_by_ids(&ids);
        }

        let mut result = orchestrator.run().await.map_err(|e| e.to_string())?;
        let supply_chain = engine
            .supply_chain_scan_with_profile(
                &path,
                scorchkit_core::SupplyChainTargetKind::SourceDirectory,
                &params.profile,
                None,
            )
            .await
            .map_err(|error| error.to_string())?;
        result.merge(supply_chain);

        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
    }

    /// Run the explicit ordered offline supply-chain pipeline against one local target.
    ///
    /// # Errors
    ///
    /// Returns a typed message when the target kind, policy, scan, or result serialization fails.
    pub async fn do_supply_chain_scan(
        &self,
        params: SupplyChainScanParams,
    ) -> Result<String, String> {
        let kind = parse_supply_chain_target_kind(&params.kind)?;
        let result = Engine::new(Arc::clone(&self.config))
            .supply_chain_scan_with_profile(
                std::path::Path::new(&params.path),
                kind,
                &params.profile,
                params.revision,
            )
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    }

    /// Return typed status for every immutable local supply-chain provider snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed message when cache authorization, inspection, or serialization fails.
    pub fn do_supply_chain_cache_status(&self) -> Result<String, String> {
        let snapshots = Engine::new(Arc::clone(&self.config))
            .supply_chain_cache_status()
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&snapshots).map_err(|error| error.to_string())
    }

    /// Perform one explicitly described provider refresh outside scan-time execution.
    ///
    /// # Errors
    ///
    /// Returns a typed message when request validation, authorization, refresh, or serialization
    /// fails.
    pub async fn do_supply_chain_cache_refresh(
        &self,
        params: SupplyChainCacheRefreshParams,
    ) -> Result<String, String> {
        let request = parse_provider_refresh_request(params)?;
        let snapshot = Engine::new(Arc::clone(&self.config))
            .supply_chain_cache_refresh(&request)
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_string_pretty(&snapshot).map_err(|error| error.to_string())
    }
}

fn parse_supply_chain_target_kind(
    kind: &str,
) -> Result<scorchkit_core::SupplyChainTargetKind, String> {
    match kind {
        "source_directory" => Ok(scorchkit_core::SupplyChainTargetKind::SourceDirectory),
        "directory_artifact" => Ok(scorchkit_core::SupplyChainTargetKind::DirectoryArtifact),
        "file_artifact" => Ok(scorchkit_core::SupplyChainTargetKind::FileArtifact),
        "oci_archive" => Ok(scorchkit_core::SupplyChainTargetKind::OciArchive),
        "oci_layout" => Ok(scorchkit_core::SupplyChainTargetKind::OciLayout),
        "cyclonedx_sbom" => Ok(scorchkit_core::SupplyChainTargetKind::CycloneDxSbom),
        _ => Err(format!(
            "unknown supply-chain target kind '{kind}'; expected source_directory, directory_artifact, file_artifact, oci_archive, oci_layout, or cyclonedx_sbom"
        )),
    }
}

fn parse_provider_refresh_request(
    params: SupplyChainCacheRefreshParams,
) -> Result<crate::supply_chain::ProviderRefreshRequest, String> {
    let provider = match params.provider.as_str() {
        "osv" => crate::supply_chain::SupplyChainProvider::Osv,
        "grype" => crate::supply_chain::SupplyChainProvider::Grype,
        "trivy" => crate::supply_chain::SupplyChainProvider::Trivy,
        provider => return Err(format!("unknown supply-chain provider '{provider}'")),
    };
    let downloads = params
        .downloads
        .into_iter()
        .map(|download| {
            Ok(crate::supply_chain::ProviderDownload {
                url: url::Url::parse(&download.url)
                    .map_err(|error| format!("invalid provider URL '{}': {error}", download.url))?,
                relative_path: std::path::PathBuf::from(download.relative_path),
                sha256: download.sha256,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let upstream_built_at = params
        .upstream_built_at
        .map(|timestamp| {
            chrono::DateTime::parse_from_rfc3339(&timestamp)
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|error| format!("invalid upstream build time '{timestamp}': {error}"))
        })
        .transpose()?;
    Ok(crate::supply_chain::ProviderRefreshRequest {
        provider,
        snapshot_id: params.snapshot_id,
        schema_version: params.schema_version,
        downloads,
        upstream_built_at,
        maximum_age_seconds: params.maximum_age_seconds,
    })
}

/// `#[tool_router]` — thin wrappers that delegate to `do_*` public methods.
#[tool_router(vis = "pub(crate)")]
impl ScorchKitServer {
    #[tool(
        description = "Build one versioned provider-neutral application context from a policy-authorized local code root, optional immutable declared Git change set, host-declared routes and artifacts, configured persona labels, configured capability/effect inventory, and optional project-registered targets. The call performs bounded no-follow local discovery only; declarations and project inventory are context, never scanner evidence or authorization."
    )]
    async fn application_context(
        &self,
        context: McpCallContext,
        params: Parameters<ApplicationContextParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_application_context(params.0).await)
    }

    #[tool(
        description = "Run the policy-sealed OWASP ZAP 2.17.0 application DAST service. Select an explicit passive, standard, or active phase profile; optional digest-pinned local OpenAPI or GraphQL schemas; anonymous coverage; and configured persona IDs. Credentials are resolved only after authorization and never belong in this request. Returns findings plus typed per-persona authentication, phase, route, schema, and coverage evidence."
    )]
    async fn application_dast(
        &self,
        context: McpCallContext,
        params: Parameters<ApplicationDastParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_application_dast(params.0).await)
    }

    #[tool(
        description = "Compile inert, code-informed application test scenarios into one canonical reviewed plan. Returns exact scenario, executor, authorization-requirement, and plan identities without contacting the target, reading files, resolving credentials, or launching tools. Review the returned plan identity before calling application_pentest."
    )]
    async fn plan_application_pentest(
        &self,
        context: McpCallContext,
        params: Parameters<ApplicationPentestPlanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_plan_application_pentest(params.0))
    }

    #[tool(
        description = "Compile an inert commit, pull-request, staging, release, deep, or focused-remediation application-security workflow. Returns exact ordered host-analysis and ScorchKit-engine steps, scope identities, broadness, requirements, status, gaps, and stable identities. It executes no named step and supplies no target or effect authorization."
    )]
    async fn plan_appsec_workflow(
        &self,
        context: McpCallContext,
        params: Parameters<ApplicationSecurityWorkflowParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_plan_appsec_workflow(params.0).await)
    }

    #[tool(
        description = "Execute one exact application-pentest plan against a registered project target. ScorchKit recompiles the inert scenarios, rejects any approved-plan identity mismatch before effects, derives every exact grant, and runs only the closed application executor inventory. Results, findings, typed coverage, gaps, authorization requirements, and evidence identities are persisted."
    )]
    async fn application_pentest(
        &self,
        context: McpCallContext,
        params: Parameters<ApplicationPentestExecuteParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_application_pentest(params.0).await)
    }

    #[tool(
        description = "Import one digest-pinned local HAR or HTTP-exchange file into a registered project's existing or explicitly manual finding. The file is authorized, opened without following links, bounded, digest verified, target scoped, recursively redacted, attributed, and stored atomically with its execution record. It does not execute target traffic or promote attack-path state."
    )]
    async fn import_application_evidence(
        &self,
        context: McpCallContext,
        params: Parameters<ApplicationEvidenceImportParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_import_application_evidence(params.0).await)
    }

    #[tool(description = "List the default application-security scan modules with their adapter \
        contracts, categories, descriptions, and external tool requirements. Compatibility \
        network, enterprise, and cloud modules are excluded. Returns a JSON array.")]
    async fn list_modules(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_list_modules().await)
    }

    #[tool(description = "Check which external security tools (nmap, nuclei, sqlmap, etc.) are \
        installed on the system. Call this before using the 'thorough' scan profile to know \
        which external tool wrappers will be available. Returns JSON array with tool name and \
        installed status.")]
    async fn check_tools(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, Ok(self.do_check_tools()))
    }

    #[tool(description = "Run a security scan against a target URL without project persistence. \
        Use for quick ad-hoc testing when you don't need to track results over time. Set \
        profile to 'quick' for safe recon, 'standard' for built-in application checks, \
        'thorough' for application tools except credential/exploit effects, or 'pentest' for all \
        application modules with explicit effect grants. Compatibility modules require explicit \
        IDs. Use 'skip' to exclude specific modules. Prefer project_scan when you want results \
        persisted and deduplicated. Returns \
        JSON with findings array, summary statistics, and scan metadata.")]
    async fn scan(
        &self,
        context: McpCallContext,
        params: Parameters<ScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan(params.0).await)
    }

    #[tool(description = "Start an authorized DAST scan as a cancellable background job. Returns \
        the queued job record immediately. Poll scan_job_status with the returned id; use \
        scan_job_cancel to stop work. PostgreSQL is optional for stateless MCP sessions.")]
    async fn scan_job_start(
        &self,
        context: McpCallContext,
        params: Parameters<ScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_start(params.0).await)
    }

    #[tool(
        description = "Read one scan job's lifecycle, module progress, partial completed-module \
        findings, terminal error, and final result by job UUID."
    )]
    async fn scan_job_status(
        &self,
        context: McpCallContext,
        params: Parameters<ScanJobRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_status(params.0).await)
    }

    #[tool(
        description = "Cancel a queued or running scan job by UUID. Cancellation is idempotent \
        while pending or already cancelled and preserves completed-module evidence."
    )]
    async fn scan_job_cancel(
        &self,
        context: McpCallContext,
        params: Parameters<ScanJobRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_cancel(params.0).await)
    }

    #[tool(description = "Resume an interrupted scan job under the current unchanged engagement. \
        Creates a linked successor attempt and skips modules whose findings were durably committed.")]
    async fn scan_job_resume(
        &self,
        context: McpCallContext,
        params: Parameters<ScanJobRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_job_resume(params.0).await)
    }

    #[tool(description = "AI-guided scan planning: runs recon modules first to gather target \
        intelligence, then uses the configured AI provider to analyze the tech stack and recommend which scanner \
        modules to run. Returns a structured plan with module recommendations, priorities, and \
        rationale — does NOT execute the scan. Review the plan, then use project_scan with the \
        recommended modules. Requires AI to be enabled in config. Falls back gracefully if \
        the configured provider is unavailable.")]
    async fn plan_scan(
        &self,
        context: McpCallContext,
        params: Parameters<PlanScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_plan_scan(params.0).await)
    }

    #[tool(description = "Create a new security assessment project for tracking scans, findings, \
        and security posture over time. Projects are the foundation for persistent scanning — \
        create one before using project_scan. The name must be unique. After creating, use \
        target_add to register URLs to scan. Returns the created project as JSON with its UUID.")]
    async fn project_create(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectCreateParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_create(params.0).await)
    }

    #[tool(
        description = "List all security assessment projects. Use to discover existing projects \
        before creating a new one. Returns JSON array of projects with name, description, and \
        timestamps. You can reference projects by name (not UUID) in all other project tools."
    )]
    async fn project_list(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_list().await)
    }

    #[tool(
        description = "Show detailed information about a project including registered targets, \
        recent scans, and finding counts. Use to get an overview before running scans or \
        analyzing findings. Accepts project name or UUID. Returns JSON with project metadata, \
        targets array, scan count, finding count, and the 5 most recent scans."
    )]
    async fn project_show(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_show(params.0).await)
    }

    #[tool(description = "Delete a project and ALL associated data (targets, scans, findings, \
        schedules). This is destructive and irreversible. Set force=true to confirm deletion — \
        without it, returns a warning instead. Use only when the user explicitly asks to remove \
        a project.")]
    async fn project_delete(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectDeleteParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_delete(params.0).await)
    }

    #[tool(description = "Run a security scan within a project, automatically persisting results \
        to the database. Findings are deduplicated across scans — the same vulnerability found \
        again increments seen_count instead of creating a duplicate. This is the primary \
        scanning tool for tracked assessments. Use profile 'quick' for recon, 'standard' for \
        built-in application checks, 'thorough' for application tools except credential/exploit \
        effects, or 'pentest' for all application modules with explicit effect grants. \
        Compatibility modules require explicit IDs. Use modules for approved plan_scan \
        recommendations and skip for exclusions. Returns JSON with scan ID, actual run/skipped \
        module lists, finding \
        counts (total, new, updated), and summary.")]
    async fn project_scan(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_scan(params.0).await)
    }

    #[tool(
        description = "List vulnerability findings for a project. Filter by severity (critical, \
        high, medium, low, info) or by lifecycle status (new, acknowledged, false_positive, \
        remediated, verified). Without filters, returns all findings. Use after project_scan to \
        review results. Each finding includes module ID, severity, title, description, affected \
        target, evidence, and remediation guidance. Returns JSON array."
    )]
    async fn project_findings(
        &self,
        context: McpCallContext,
        params: Parameters<FindingListParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_findings(params.0).await)
    }

    #[tool(description = "Show full details for a single vulnerability finding by UUID. Use when \
        you need the complete evidence, remediation guidance, OWASP category, CWE ID, and raw \
        finding data for a specific issue. Get finding UUIDs from project_findings. Returns \
        JSON with all finding fields.")]
    async fn finding_show(
        &self,
        context: McpCallContext,
        params: Parameters<FindingRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_finding_show(params.0).await)
    }

    #[tool(description = "Update the lifecycle status of a vulnerability finding. Transition \
        through: new (just found) -> acknowledged (confirmed real) -> remediated (fix applied) \
        -> verified (fix confirmed by rescan). Or mark as false_positive to exclude from active \
        counts. Only update status when the user directs you to — do not auto-triage findings. \
        Returns confirmation with the new status.")]
    async fn finding_update_status(
        &self,
        context: McpCallContext,
        params: Parameters<FindingUpdateStatusParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_finding_update_status(params.0).await)
    }

    #[tool(description = "Add a target URL to a project for tracking. Targets represent the URLs \
        that will be scanned within a project. Add targets before running project_scan. Each \
        target can have an optional human-readable label. Returns the created target with its \
        UUID.")]
    async fn target_add(
        &self,
        context: McpCallContext,
        params: Parameters<TargetAddParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_add(params.0).await)
    }

    #[tool(description = "List all registered target URLs for a project. Use to see what targets \
        are configured before scanning. Returns JSON array of targets with URL, label, and \
        creation timestamp.")]
    async fn target_list(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectRefParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_list(params.0).await)
    }

    #[tool(
        description = "Remove a target URL from a project by target UUID. Get target UUIDs from \
        target_list. Does not delete any scan data or findings associated with the target."
    )]
    async fn target_remove(
        &self,
        context: McpCallContext,
        params: Parameters<TargetRemoveParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_remove(params.0).await)
    }

    #[tool(
        description = "Run pending database migrations to initialize or update the schema. Call \
        this on first use before any project or scan operations. Safe to call multiple times — \
        already-applied migrations are skipped. Returns success confirmation."
    )]
    async fn db_migrate(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_db_migrate().await)
    }

    #[tool(
        description = "Create a recurring scan schedule for a project using a cron expression. \
        Schedules are not executed automatically — use run_due_scans to trigger overdue \
        schedules (wire into system cron for automation). Example cron: '0 0 * * *' for daily \
        at midnight, '0 */6 * * *' for every 6 hours. Returns the created schedule with next \
        run time."
    )]
    async fn schedule_scan(
        &self,
        context: McpCallContext,
        params: Parameters<ScheduleScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_schedule_scan(params.0).await)
    }

    #[tool(description = "Execute all scan schedules that are currently due. This is an explicit \
        trigger, not a background daemon — call it when you want overdue schedules to run. \
        Each schedule runs independently; individual failures don't abort the batch. Returns \
        JSON with execution count and per-schedule results.")]
    async fn run_due_scans(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_run_due_scans().await)
    }

    #[tool(description = "Get security posture metrics and trend analysis for a project. Returns \
        aggregate data: severity breakdown (critical to info), status breakdown (new to \
        verified), regression detection (previously remediated findings that reappeared), trend \
        direction (improving/declining/stable), and top 10 unresolved findings ranked by \
        severity. Use after scanning to assess overall security health. Returns structured JSON.")]
    async fn project_status(
        &self,
        context: McpCallContext,
        params: Parameters<ProjectStatusParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_project_status(params.0).await)
    }

    #[tool(
        description = "Analyze project findings using the configured AI provider with structured JSON output. \
        Set focus to: 'summary' for executive overview with risk score, 'prioritize' for \
        findings ranked by exploitability with attack chains, 'remediate' for fix steps with \
        effort estimates and code examples, or 'filter' for false positive classification with \
        confidence scores. Optionally specify scan_id to analyze a specific scan's findings \
        instead of all project findings. Requires AI enabled in config."
    )]
    async fn analyze_findings(
        &self,
        context: McpCallContext,
        params: Parameters<AnalyzeFindingsParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_analyze_findings(params.0).await)
    }

    #[tool(description = "Run a complete security scan in one call. Parses the target, applies \
        the scan profile (quick/standard/thorough/pentest), executes all matching modules, and optionally \
        persists results to a project for tracking. This is the 'one-shot' scanning tool — use \
        it when you want results fast without manually composing scan + project_scan. Does NOT \
        include AI planning or analysis — compose with plan_scan and analyze_findings for a full \
        AI-driven engagement. Returns JSON with scan summary, finding counts, and top findings.")]
    async fn auto_scan(
        &self,
        context: McpCallContext,
        params: Parameters<AutoScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_auto_scan(params.0).await)
    }

    #[tool(description = "Gather consolidated target intelligence using recon-only modules. Runs \
        headers analysis, technology detection, endpoint discovery, subdomain enumeration, web \
        crawling, and DNS security checks — without any active vulnerability scanning. Use this \
        as the first step in an engagement to understand the target's attack surface before \
        deciding which scanner modules to deploy. Returns structured JSON with all recon findings \
        organized by module.")]
    async fn target_intelligence(
        &self,
        context: McpCallContext,
        params: Parameters<TargetIntelligenceParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_target_intelligence(params.0).await)
    }

    #[tool(description = "Check the status of the most recent scan for a project. Returns the \
        latest scan record with scan ID, target URL, profile used, start/completion times, \
        finding count, and modules run. Also shows total scan count and tracked finding count \
        for the project. Use after running auto_scan or project_scan to verify completion and \
        review results.")]
    async fn scan_progress(
        &self,
        context: McpCallContext,
        params: Parameters<ScanProgressParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_progress(params.0).await)
    }

    #[tool(description = "Correlate project findings into attack chains. Analyzes all findings \
        for a project and identifies compound vulnerabilities where multiple findings combine \
        to create escalated risk. Example: XSS + missing CSP = session hijacking chain. \
        Returns JSON with attack chain names, severity escalation, narrative descriptions, \
        contributing finding IDs, and remediation priority. Use after scanning to understand \
        how individual findings relate and prioritize fixes by attack path impact.")]
    async fn correlate_findings(
        &self,
        context: McpCallContext,
        params: Parameters<CorrelateFindingsParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_correlate_findings(params.0).await)
    }

    #[tool(
        description = "List the default application SAST, SCA, secret, IaC, and artifact scanning \
        modules with adapter contracts, language support, and external tool requirements. Cloud \
        account compatibility modules are excluded. Returns a JSON array."
    )]
    async fn list_code_modules(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, Ok(self.do_list_code_modules()))
    }

    #[tool(description = "Run SAST (Static Application Security Testing) on source code at the \
        given filesystem path. Auto-detects project language from manifest files (Cargo.toml, \
        package.json, go.mod, etc.). Runs built-in analyzers (dependency auditor) and external \
        tool wrappers (Semgrep, OSV-Scanner, Gitleaks, Bandit, Gosec, Checkov, Grype, etc.) \
        based on detected language and profile. Use 'language' to override auto-detection, \
        'profile' to select fast or deep analysis, and 'modules' \
        to run only specific module IDs, or 'skip' to exclude specific ones. Returns JSON with \
        findings array and scan metadata, same format as the scan tool.")]
    async fn scan_code(
        &self,
        context: McpCallContext,
        params: Parameters<super::types::CodeScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_scan_code(params.0).await)
    }

    #[tool(
        description = "Run the ordered offline application supply-chain pipeline against one explicit local source directory, artifact, OCI layout/archive, or CycloneDX 1.6 SBOM. The target kind is never inferred as a registry or daemon target. Returns typed complete, incomplete, or degraded coverage with exact SBOM and provider provenance."
    )]
    async fn supply_chain_scan(
        &self,
        context: McpCallContext,
        params: Parameters<SupplyChainScanParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_supply_chain_scan(params.0).await)
    }

    #[tool(
        description = "Show typed missing, stale, invalid, or ready status for every immutable local application supply-chain provider snapshot."
    )]
    async fn supply_chain_cache_status(&self, context: McpCallContext) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_supply_chain_cache_status())
    }

    #[tool(
        description = "Refresh one explicitly described application supply-chain provider snapshot outside scan-time execution. Every URL, relative path, digest, version, and maximum age must be supplied; policy, size, integrity, validation, and atomic-promotion checks apply."
    )]
    async fn supply_chain_cache_refresh(
        &self,
        context: McpCallContext,
        params: Parameters<SupplyChainCacheRefreshParams>,
    ) -> McpToolCallResult {
        Self::mcp_tool_result(context, self.do_supply_chain_cache_refresh(params.0).await)
    }
}

async fn require_registered_project_target(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    requested: &Target,
) -> Result<(), ScorchError> {
    let registered = projects::list_targets(pool, project_id).await?.into_iter().any(|entry| {
        Target::parse(&entry.url).is_ok_and(|candidate| candidate.url == requested.url)
    });
    if registered {
        Ok(())
    } else {
        let target = scorchkit_core::observation::redact_url(requested.url.as_str()).0;
        Err(ScorchError::Config(format!(
            "target '{target}' is not registered to project {project_id}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::engine::policy::{Engagement, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
    use chrono::Utc;

    fn job_server() -> ScorchKitServer {
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::Exact("localhost".to_string()))
            .allow_capability(Capability::DastScan)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::ActiveSafe);
        let engagement = Engagement::new("mcp-job-wrapper-test", policy);
        let config = AppConfig { engagement: Some(engagement), ..AppConfig::default() };
        ScorchKitServer::new_stateless(Arc::new(config))
    }

    fn job_request(server: &ScorchKitServer) -> DastJobRequest {
        DastJobRequest::new(
            "http://localhost:1/",
            "quick",
            server.config.engagement.clone().expect("job engagement"),
        )
        .with_modules(Some(vec!["headers".to_string()]))
    }

    fn durable_correlation_fixture() -> (
        crate::engine::finding::Finding,
        crate::storage::models::TrackedFinding,
        crate::storage::models::FindingEvidence,
    ) {
        let now = Utc::now();
        let finding = crate::engine::finding::Finding::new(
            "fixture-scanner",
            crate::engine::severity::Severity::High,
            "Fixture title",
            "Fixture description",
            "src/fixture.rs:7",
        )
        .with_evidence("fixture evidence")
        .with_remediation("fixture remediation")
        .with_owasp("A03:2021")
        .with_cwe(89)
        .with_confidence(0.75)
        .with_correlation_key(crate::engine::observation::CorrelationKey::new("route", "/fixture"));
        let appsec = finding.canonical_appsec();
        let id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let tracked = crate::storage::models::TrackedFinding {
            id,
            scan_id,
            project_id: Uuid::new_v4(),
            fingerprint: "legacy-fingerprint".to_string(),
            identity_schema: appsec.identity.schema.clone(),
            stable_identity: appsec.identity.value.clone(),
            correlation_keys: serde_json::to_value(&appsec.correlation_keys)
                .expect("serialize correlation keys"),
            module_id: finding.module_id.clone(),
            severity: finding.severity.to_string(),
            title: finding.title.clone(),
            description: finding.description.clone(),
            affected_target: finding.affected_target.clone(),
            evidence: finding.evidence.clone(),
            remediation: finding.remediation.clone(),
            owasp_category: finding.owasp_category.clone(),
            cwe_id: finding.cwe_id.and_then(|value| i32::try_from(value).ok()),
            raw_finding: serde_json::to_value(&finding).expect("serialize finding"),
            confidence: finding.confidence,
            first_seen: now,
            last_seen: now,
            seen_count: 1,
            status: "new".to_string(),
            triage_state: "needs_context".to_string(),
            status_note: None,
            found_at: now,
        };
        let record = appsec.evidence[0].clone();
        let evidence = crate::storage::models::FindingEvidence {
            id: Uuid::new_v4(),
            tracked_finding_id: id,
            scan_id,
            evidence_identity: record.identity.clone(),
            evidence_schema: record.schema.clone(),
            raw_evidence: serde_json::to_value(&record).expect("serialize evidence"),
            collected_at: record.provenance.collected_at,
            created_at: now,
        };
        (finding, tracked, evidence)
    }

    #[test]
    fn legacy_mcp_finding_projection_preserves_model_analysis_provenance() {
        let (finding, tracked, _) = durable_correlation_fixture();
        let request = scorchkit_core::ModelAnalysisRequest::analysis(
            "fixture-host",
            "exact-model",
            scorchkit_core::ModelRole::FindingValidation,
            "workflow/v1",
            vec![scorchkit_core::ModelAnalysisInput::new("1".repeat(64), "fixture evidence")
                .expect("input")],
            "validate",
        )
        .expect("request");
        let response = scorchkit_core::ModelAnalysisResponse {
            schema: scorchkit_core::MODEL_ANALYSIS_CONTRACT_V1.to_string(),
            provider: request.provider.clone(),
            model: request.model.clone(),
            role: request.role,
            payload: scorchkit_core::ModelResponsePayload::Analysis {
                summary: "Supported".to_string(),
                confidence_bps: 8_000,
                evidence_digests: request.evidence_digests(),
            },
        };
        let provenance = scorchkit_core::ModelAnalysisProvenance::from_validated_response(
            &request,
            &response,
            scorchkit_core::ModelExecutionLocation::HostManaged,
            tracked.found_at,
        )
        .expect("provenance");
        let analysis = scorchkit_core::AgentAnalysisRecord::from_model(provenance, "Supported")
            .expect("analysis");
        let canonical =
            serde_json::to_value(finding.with_agent_analysis(analysis)).expect("canonical finding");
        let projected = legacy_finding_projection(FindingViewV1 {
            id: tracked.id,
            project_id: tracked.project_id,
            scan_id: tracked.scan_id,
            fingerprint: tracked.fingerprint,
            identity_schema: tracked.identity_schema,
            stable_identity: tracked.stable_identity.clone(),
            correlation_keys: tracked.correlation_keys,
            status: tracked.status,
            status_note: tracked.status_note,
            seen_count: u32::try_from(tracked.seen_count).expect("seen count"),
            first_seen: tracked.first_seen,
            last_seen: tracked.last_seen,
            found_at: tracked.found_at,
            canonical,
            triage: Box::new(scorchkit_control::FindingTriageViewV1 {
                schema: scorchkit_core::FINDING_TRIAGE_SCHEMA_V1.to_string(),
                current_state: "needs_context".to_string(),
                subject: scorchkit_control::FindingTriageSubjectViewV1 {
                    project_identity: tracked.project_id.to_string(),
                    finding_identity: tracked.stable_identity,
                    rule_identity: None,
                    target_identity: "a".repeat(64),
                },
                transitions: Vec::new(),
                correlations: Vec::new(),
                suppressions: Vec::new(),
                active_suppression_ids: Vec::new(),
            }),
        })
        .expect("projection");
        let model = &projected["raw_finding"]["appsec"]["agent_analysis"][0];
        assert_eq!(model["schema"], scorchkit_core::MODEL_ANALYSIS_CONTRACT_V1);
        assert_eq!(model["model_provenance"]["role"], "finding_validation");
        assert_eq!(model["model_provenance"]["execution_location"], "host_managed");
    }

    #[test]
    fn durable_correlation_checks_every_evidence_and_finding_parity_field() {
        let (finding, tracked, evidence) = durable_correlation_fixture();
        let (findings, gaps) =
            canonical_correlation_inventory(std::slice::from_ref(&tracked), vec![evidence.clone()]);
        assert_eq!(findings.len(), 1);
        assert!(gaps.is_empty());

        let mut evidence_variants = Vec::new();
        let mut variant = evidence.clone();
        variant.evidence_identity = "wrong-evidence-identity".to_string();
        evidence_variants.push(variant);
        let mut variant = evidence.clone();
        variant.evidence_schema = "wrong-evidence-schema".to_string();
        evidence_variants.push(variant);
        let mut variant = evidence.clone();
        variant.collected_at += chrono::Duration::microseconds(1);
        evidence_variants.push(variant);
        let mut variant = evidence;
        variant
            .raw_evidence
            .as_object_mut()
            .expect("evidence object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        evidence_variants.push(variant);
        for variant in evidence_variants {
            let (_, gaps) =
                canonical_correlation_inventory(std::slice::from_ref(&tracked), vec![variant]);
            assert_eq!(gaps.len(), 1);
            assert_eq!(
                gaps[0].kind,
                crate::engine::attack_path::AttackPathCorrelationGapKind::MalformedFindingRecord
            );
        }

        let mut column_variants = Vec::new();
        let mut variant = tracked.clone();
        variant.module_id.push_str("-wrong");
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.severity = "low".to_string();
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.title.push_str(" wrong");
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.description.push_str(" wrong");
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.affected_target.push_str("-wrong");
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.evidence = Some("wrong evidence".to_string());
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.remediation = Some("wrong remediation".to_string());
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.owasp_category = Some("A01:2021".to_string());
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.cwe_id = Some(78);
        column_variants.push(variant);
        let mut variant = tracked.clone();
        variant.confidence = 0.5;
        column_variants.push(variant);
        for variant in &column_variants {
            assert!(!tracked_finding_columns_match(&finding, variant));
        }
        let (findings, gaps) = canonical_correlation_inventory(&column_variants[2..3], Vec::new());
        assert!(findings.is_empty());
        assert_eq!(gaps.len(), 1);

        let mut variant = tracked.clone();
        variant
            .raw_finding
            .as_object_mut()
            .expect("finding object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        let (findings, gaps) = canonical_correlation_inventory(&[variant], Vec::new());
        assert!(findings.is_empty());
        assert_eq!(gaps.len(), 1);

        let mut identity_schema = tracked.clone();
        identity_schema.identity_schema = "wrong-identity-schema".to_string();
        let mut correlation_keys = tracked;
        correlation_keys.correlation_keys = serde_json::json!([]);
        for variant in [identity_schema, correlation_keys] {
            let (findings, gaps) = canonical_correlation_inventory(&[variant], Vec::new());
            assert!(findings.is_empty());
            assert_eq!(gaps.len(), 1);
        }
    }

    #[test]
    fn finding_projections_redact_public_field_mutations() {
        let mut finding = crate::engine::finding::Finding::new(
            "fixture",
            crate::engine::severity::Severity::High,
            "safe title",
            "safe description",
            "https://example.com",
        );
        finding.title = "api_key=title-fixture-secret".to_string();
        finding.description = "password = \"description-fixture-secret\"".to_string();
        finding.affected_target =
            "https://user:target-fixture-secret@example.com/?token=query-fixture-secret"
                .to_string();
        finding.evidence = Some("secret = 'evidence-fixture-secret'".to_string());

        for projection in [redacted_top_finding(&finding), redacted_intelligence_finding(&finding)]
        {
            let encoded = serde_json::to_string(&projection).expect("serialize projection");
            for secret in [
                "title-fixture-secret",
                "description-fixture-secret",
                "target-fixture-secret",
                "query-fixture-secret",
                "evidence-fixture-secret",
            ] {
                assert!(!encoded.contains(secret), "projection leaked {secret}");
            }
        }
    }

    #[test]
    fn finding_projections_preserve_the_exact_public_schema() {
        let finding = crate::engine::finding::Finding::new(
            "fixture",
            crate::engine::severity::Severity::High,
            "safe title",
            "safe description",
            "https://example.com/path",
        )
        .with_evidence("safe evidence");

        assert_eq!(
            redacted_top_finding(&finding),
            serde_json::json!({
                "severity": "high",
                "title": "safe title",
                "target": "https://example.com/path",
            })
        );
        assert_eq!(
            redacted_intelligence_finding(&finding),
            serde_json::json!({
                "module": "fixture",
                "severity": "high",
                "title": "safe title",
                "description": "safe description",
                "target": "https://example.com/path",
                "evidence": "safe evidence",
            })
        );
    }

    #[test]
    fn supply_chain_target_kind_parser_covers_every_public_kind() {
        for (input, expected) in [
            ("source_directory", scorchkit_core::SupplyChainTargetKind::SourceDirectory),
            ("directory_artifact", scorchkit_core::SupplyChainTargetKind::DirectoryArtifact),
            ("file_artifact", scorchkit_core::SupplyChainTargetKind::FileArtifact),
            ("oci_archive", scorchkit_core::SupplyChainTargetKind::OciArchive),
            ("oci_layout", scorchkit_core::SupplyChainTargetKind::OciLayout),
            ("cyclonedx_sbom", scorchkit_core::SupplyChainTargetKind::CycloneDxSbom),
        ] {
            assert_eq!(parse_supply_chain_target_kind(input), Ok(expected));
        }
        assert!(parse_supply_chain_target_kind("registry_reference").is_err());
    }

    #[tokio::test]
    async fn supply_chain_cache_refresh_rejects_an_unknown_provider() {
        let server = ScorchKitServer::new_stateless(Arc::new(AppConfig::default()));
        let result = server
            .do_supply_chain_cache_refresh(SupplyChainCacheRefreshParams {
                provider: "unknown".to_string(),
                snapshot_id: "fixture".to_string(),
                schema_version: "v1".to_string(),
                downloads: Vec::new(),
                upstream_built_at: None,
                maximum_age_seconds: 60,
            })
            .await;
        assert_eq!(result, Err("unknown supply-chain provider 'unknown'".to_string()));
    }

    #[tokio::test]
    async fn application_dast_tool_rejects_an_unknown_profile_with_the_typed_contract() {
        let server = ScorchKitServer::new_stateless(Arc::new(AppConfig::default()));
        let result = server
            .do_application_dast(ApplicationDastParams {
                target: "https://example.com".to_string(),
                profile: "unbounded".to_string(),
                include_anonymous: true,
                personas: Vec::new(),
                schemas: Vec::new(),
            })
            .await;
        assert_eq!(
            result,
            Err(
                "unknown application DAST profile 'unbounded'; expected passive, standard, or active"
                    .to_string()
            )
        );
    }

    #[test]
    fn completed_job_result_rejects_missing_success_payload() {
        let mut job = ScanJob::new(
            DastJobRequest::new(
                "http://localhost:1",
                "quick",
                Engagement::new("result-test", EngagementPolicy::default()),
            ),
            Uuid::new_v4(),
        );
        job.state = ScanJobState::Succeeded;
        let error = completed_job_result(job).expect_err("success requires a persisted result");
        assert_eq!(error, "successful scan job has no result");
    }

    #[tokio::test]
    async fn job_tool_wrappers_preserve_cancel_and_resume_payloads() {
        let server = job_server();
        let cancelled_job = server.jobs.submit(job_request(&server)).await.expect("submit cancel");
        let cancelled_json = server
            .scan_job_cancel(
                McpCallContext::test("scan_job_cancel"),
                Parameters(ScanJobRefParams { job_id: cancelled_job.id.to_string() }),
            )
            .await;
        let cancelled: ScanJob =
            serde_json::from_str(cancelled_json.legacy_text()).expect("decode cancellation");
        assert_eq!(cancelled.id, cancelled_job.id);
        assert_eq!(cancelled.state, ScanJobState::Cancelled);

        let abandoned = server.jobs.submit(job_request(&server)).await.expect("submit resume");
        let mut running = abandoned.clone();
        running.state = ScanJobState::Running;
        running.revision = 1;
        running.started_at = Some(Utc::now());
        running.updated_at = Utc::now();
        running.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(server
            .jobs
            .store()
            .compare_and_swap(0, &running)
            .await
            .expect("persist abandoned job"));
        let recovered = server.jobs.recover_interrupted().await.expect("recover abandoned job");
        assert_eq!(recovered.len(), 1);

        let resumed_json = server
            .scan_job_resume(
                McpCallContext::test("scan_job_resume"),
                Parameters(ScanJobRefParams { job_id: abandoned.id.to_string() }),
            )
            .await;
        let resumed: ScanJob =
            serde_json::from_str(resumed_json.legacy_text()).expect("decode resumed job");
        assert_eq!(resumed.parent_job_id, Some(abandoned.id));
        assert_eq!(resumed.state, ScanJobState::Queued);
    }
}
