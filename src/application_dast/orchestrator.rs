use std::time::Duration;

use chrono::Utc;
use scorchkit_core::events::ScanEvent;
use scorchkit_core::{
    ApplicationDastAssessment, ApplicationDastAuthenticationState, ApplicationDastCoverageGap,
    ApplicationDastGapKind, ApplicationDastPersonaAssessment, ApplicationDastPhase,
    ApplicationDastPhaseOutcome, ApplicationDastPhaseStatus, ModuleOutcome, Result, ScanResult,
    ScorchError,
};

use crate::engine::scan_context::ScanContext;
use crate::runner::subprocess::{resolve_tool_path, ArtifactBudget, ToolInvocation};

use super::parser::{parse_persona_run, PersonaRunInput};
use super::plan::{compile_plan, ResolvedPersona, ZAP_VERSION};
use super::request::ApplicationDastRequest;
use super::schema::ValidatedDastSchema;
use super::workspace::DastWorkspace;

pub struct ApplicationDastOrchestrator {
    context: ScanContext,
    request: ApplicationDastRequest,
    schemas: Vec<ValidatedDastSchema>,
    personas: Vec<ResolvedPersona>,
}

struct PersonaRunFailure {
    error: ScorchError,
    plan_sha256: Option<String>,
}

impl PersonaRunFailure {
    const fn with_plan(error: ScorchError, plan_sha256: String) -> Self {
        Self { error, plan_sha256: Some(plan_sha256) }
    }
}

impl From<ScorchError> for PersonaRunFailure {
    fn from(error: ScorchError) -> Self {
        Self { error, plan_sha256: None }
    }
}

impl ApplicationDastOrchestrator {
    pub(crate) const fn new(
        context: ScanContext,
        request: ApplicationDastRequest,
        schemas: Vec<ValidatedDastSchema>,
        personas: Vec<ResolvedPersona>,
    ) -> Self {
        Self { context, request, schemas, personas }
    }

    pub(crate) async fn run(self) -> Result<ScanResult> {
        let run_started = std::time::Instant::now();
        let started_at = Utc::now();
        let scan_id = uuid::Uuid::new_v4().to_string();
        self.context.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.context.target.url.to_string(),
        });
        self.context.events.publish(ScanEvent::ModuleStarted {
            scan_id: scan_id.clone(),
            module_id: "application-dast".to_string(),
            module_name: "Authenticated schema-driven application DAST".to_string(),
        });
        let mut assessment =
            ApplicationDastAssessment::new(self.context.target.url.as_str(), self.request.profile);
        assessment.zap_version = ZAP_VERSION.to_string();
        assessment.schemas = self.schemas.iter().map(|schema| schema.identity.clone()).collect();
        let mut findings = Vec::new();

        for persona in &self.personas {
            match self.run_persona(persona).await {
                Ok(parsed) => {
                    findings.extend(parsed.findings);
                    assessment.personas.push(parsed.assessment);
                    for gap in parsed.gaps {
                        assessment.record_gap(gap);
                    }
                }
                Err(failure) => {
                    record_persona_failure(&mut assessment, persona, &failure);
                    self.context.events.publish(ScanEvent::Custom {
                        kind: "application-dast.persona-failed".to_string(),
                        data: serde_json::json!({
                            "scan_id": scan_id.clone(),
                            "persona": persona.id.clone(),
                            "error": persona.redact_known_secrets(&failure.error.to_string()),
                        }),
                    });
                }
            }
        }
        assessment.refresh_coverage_status();
        let finding_count = findings.len();
        for finding in &findings {
            self.context.events.publish(ScanEvent::FindingProduced {
                scan_id: scan_id.clone(),
                module_id: "application-dast".to_string(),
                finding: Box::new(finding.clone()),
            });
        }
        self.context.events.publish(ScanEvent::ModuleCompleted {
            scan_id: scan_id.clone(),
            module_id: "application-dast".to_string(),
            findings_count: finding_count,
            duration_ms: u64::try_from(run_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
        self.context.events.publish(ScanEvent::ScanCompleted {
            scan_id: scan_id.clone(),
            total_findings: finding_count,
            duration_ms: u64::try_from(run_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
        Ok(ScanResult::new(
            scan_id,
            self.context.target.clone(),
            started_at,
            findings,
            vec!["application-dast".to_string()],
            Vec::new(),
        )
        .with_module_outcomes(vec![ModuleOutcome::ran("application-dast", finding_count)])
        .with_application_dast(assessment))
    }

    async fn run_persona(
        &self,
        persona: &ResolvedPersona,
    ) -> std::result::Result<super::parser::ParsedPersonaRun, PersonaRunFailure> {
        let workspace = DastWorkspace::create()?;
        let schema_paths = workspace.copy_schemas(&self.schemas)?;
        let plan = compile_plan(
            &self.context.target.url,
            self.request.profile,
            persona,
            &self.schemas,
            &schema_paths,
            &self.context.config.dast,
        )?;
        let plan_sha256 = plan.sha256.clone();
        let outcome: Result<super::parser::ParsedPersonaRun> = async {
            let plan_path = workspace.write_plan(&plan.bytes)?;
            let program = self.context.config.tools.get_path("zap.sh");
            let mut environment = persona.environment(&self.context.target.url);
            if matches!(persona.kind, super::plan::ResolvedPersonaKind::Browser { .. }) {
                let (driver, property) = match self.context.config.dast.browser_id.as_str() {
                    "chrome-headless" => (
                        self.context.config.tools.get_path("chromedriver"),
                        "webdriver.chrome.driver",
                    ),
                    "firefox-headless" => (
                        self.context.config.tools.get_path("geckodriver"),
                        "webdriver.gecko.driver",
                    ),
                    _ => {
                        return Err(ScorchError::Config(
                            "application DAST browser driver is not supported".to_string(),
                        ));
                    }
                };
                let driver = resolve_tool_path(&driver)?;
                let driver = driver.to_str().ok_or_else(|| {
                    ScorchError::Config(
                        "application DAST browser driver path is not valid UTF-8".to_string(),
                    )
                })?;
                if driver.chars().any(char::is_whitespace) {
                    return Err(ScorchError::Config(
                        "application DAST browser driver path cannot contain whitespace"
                            .to_string(),
                    ));
                }
                environment
                    .insert("JAVA_TOOL_OPTIONS".to_string(), format!("-D{property}={driver}"));
            }
            let version = version_invocation(&program, &workspace, &self.context.config.dast);
            let version_output = self.context.run_invocation(version).await?;
            if exact_zap_version(&version_output.stdout) != Some(ZAP_VERSION) {
                return Err(ScorchError::Config(format!(
                    "OWASP ZAP version mismatch: required {ZAP_VERSION}; the launcher did not emit that exact standalone version"
                )));
            }
            let proxy_port = available_loopback_port()?;
            let invocation = base_invocation(
                &program,
                vec![
                    "-dir".to_string(),
                    workspace.home().display().to_string(),
                    "-host".to_string(),
                    "127.0.0.1".to_string(),
                    "-port".to_string(),
                    proxy_port.to_string(),
                    "-cmd".to_string(),
                    "-config".to_string(),
                    "autoupdate.checkOnStart=false".to_string(),
                    "-config".to_string(),
                    "autoupdate.downloadNewRelease=false".to_string(),
                    "-config".to_string(),
                    "autoupdate.installAddonUpdates=false".to_string(),
                    "-autorun".to_string(),
                    plan_path.display().to_string(),
                ],
                &workspace,
                &self.context.config.dast,
                &environment,
                &[0, 2],
                Duration::from_secs(self.context.config.dast.timeout_seconds),
            );
            let output = self.context.run_invocation(invocation).await?;
            parse_persona_run(&PersonaRunInput {
                workspace: &workspace,
                target: &self.context.target.url,
                profile: self.request.profile,
                persona,
                schemas: &self.schemas,
                plan_sha256: &plan.sha256,
                exit_code: output.exit_code,
                config: &self.context.config.dast,
            })
        }
        .await;
        outcome.map_err(|error| PersonaRunFailure::with_plan(error, plan_sha256))
    }
}

fn available_loopback_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn version_invocation(
    program: &str,
    workspace: &DastWorkspace,
    config: &crate::config::DastConfig,
) -> ToolInvocation {
    base_invocation(
        program,
        vec![
            "-dir".to_string(),
            workspace.home().display().to_string(),
            "-host".to_string(),
            "127.0.0.1".to_string(),
            "-port".to_string(),
            "0".to_string(),
            "-version".to_string(),
        ],
        workspace,
        config,
        &std::collections::BTreeMap::new(),
        &[0],
        Duration::from_secs(90),
    )
}

fn base_invocation(
    program: &str,
    args: Vec<String>,
    workspace: &DastWorkspace,
    config: &crate::config::DastConfig,
    environment: &std::collections::BTreeMap<String, String>,
    exit_codes: &[i32],
    timeout: Duration,
) -> ToolInvocation {
    let mut invocation = ToolInvocation::accepting_owned(program, args, timeout, exit_codes)
        .with_clean_environment()
        .with_environment("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
        .with_environment("HOME", workspace.home().display().to_string())
        .with_environment("TMPDIR", workspace.root().display().to_string())
        .with_working_directory(workspace.root())
        .with_output_limit(config.output_limit_bytes)
        .with_artifact_budget(ArtifactBudget::new(
            workspace.root(),
            config.artifact_limit_bytes,
            config.artifact_limit_files,
        ));
    for (name, value) in environment {
        invocation = invocation.with_environment(name, value);
    }
    invocation
}

fn exact_zap_version(stdout: &str) -> Option<&str> {
    let mut versions = stdout.lines().map(str::trim).filter(|line| {
        let mut components = line.split('.');
        let valid = (0..3).all(|_| {
            components.next().is_some_and(|component| {
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
            })
        });
        valid && components.next().is_none()
    });
    let version = versions.next()?;
    versions.next().is_none().then_some(version)
}

fn record_persona_failure(
    assessment: &mut ApplicationDastAssessment,
    persona: &ResolvedPersona,
    failure: &PersonaRunFailure,
) {
    let error = &failure.error;
    let detail = persona.redact_known_secrets(&error.to_string());
    let (kind, phase) = match error {
        ScorchError::ToolNotFound { .. } => {
            (ApplicationDastGapKind::MissingTool, ApplicationDastPhase::Authentication)
        }
        ScorchError::ToolArtifactLimit { .. } => {
            (ApplicationDastGapKind::ArtifactLimit, ApplicationDastPhase::AlertReport)
        }
        ScorchError::ToolOutputParse { reason, .. }
            if reason.contains("required artifact") && reason.contains("unavailable") =>
        {
            (ApplicationDastGapKind::ArtifactMissing, ApplicationDastPhase::AlertReport)
        }
        ScorchError::ToolOutputParse { .. } => {
            (ApplicationDastGapKind::ArtifactInvalid, ApplicationDastPhase::AlertReport)
        }
        _ => (ApplicationDastGapKind::ExecutionFailed, ApplicationDastPhase::AlertReport),
    };
    assessment.personas.push(ApplicationDastPersonaAssessment {
        persona: persona.id.clone(),
        authentication: if persona.is_anonymous() {
            ApplicationDastAuthenticationState::Anonymous
        } else {
            ApplicationDastAuthenticationState::Unknown
        },
        plan_sha256: failure.plan_sha256.clone().unwrap_or_default(),
        phases: vec![ApplicationDastPhaseOutcome {
            phase,
            status: ApplicationDastPhaseStatus::Failed,
            detail: Some(detail.clone()),
        }],
        routes: Vec::new(),
        warnings: Vec::new(),
    });
    assessment.record_gap(ApplicationDastCoverageGap::new(&persona.id, phase, kind, detail));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DastVerificationConfig;
    use crate::engine::target::Target;
    use crate::runner::subprocess::{ToolExecutor, ToolOutput};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct RecordingExecutor {
        invocations: Mutex<Vec<ToolInvocation>>,
    }

    #[async_trait]
    impl ToolExecutor for RecordingExecutor {
        async fn execute(&self, invocation: ToolInvocation) -> Result<ToolOutput> {
            self.invocations.lock().expect("invocation lock").push(invocation);
            Ok(ToolOutput {
                stdout: format!("{ZAP_VERSION}\n"),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::ZERO,
                resolved_program: std::path::PathBuf::from("/fixture/zap.sh"),
            })
        }
    }

    fn browser_persona() -> ResolvedPersona {
        ResolvedPersona {
            id: "browser-user".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Browser {
                login_url: "https://example.com/login".to_string(),
                username: "fixture-user".to_string(),
                password: "fixture-password".to_string(),
                verification: DastVerificationConfig {
                    url: "https://example.com/account".to_string(),
                    expected_status: 200,
                    logged_in_regex: "signed in".to_string(),
                    logged_out_regex: "sign in".to_string(),
                    max_logged_out: 0,
                },
            },
        }
    }

    #[test]
    fn extracts_only_one_standalone_semantic_zap_version() {
        let output = "Found Java version 21.0.11\nINFO launcher ready\n2.17.0\n";
        assert_eq!(exact_zap_version(output), Some("2.17.0"));
        assert_eq!(exact_zap_version("2.17.0\n2.16.1\n"), None);
        assert_eq!(exact_zap_version("OWASP ZAP 2.17.0\n"), None);
    }

    #[test]
    fn selects_a_nonzero_loopback_proxy_port() {
        let port = available_loopback_port().expect("loopback port");
        assert_ne!(port, 0);
        assert_ne!(port, 1);
    }

    #[tokio::test]
    async fn browser_personas_select_the_exact_reviewed_driver_property() {
        let executable = std::env::current_exe().expect("current executable");
        let executable = executable.to_string_lossy().into_owned();

        for (browser_id, property) in [
            ("chrome-headless", "webdriver.chrome.driver"),
            ("firefox-headless", "webdriver.gecko.driver"),
        ] {
            let mut config = crate::config::AppConfig::default();
            config.dast.browser_id = browser_id.to_string();
            config.tools.chromedriver = Some(executable.clone());
            config.tools.geckodriver = Some(executable.clone());
            let executor = Arc::new(RecordingExecutor::default());
            let context = ScanContext::new(
                Target::parse("https://example.com").expect("target"),
                Arc::new(config),
                reqwest::Client::new(),
                Vec::new(),
            )
            .with_tool_executor(executor.clone());
            let orchestrator = ApplicationDastOrchestrator::new(
                context,
                ApplicationDastRequest::new(
                    "https://example.com",
                    scorchkit_core::ApplicationDastProfile::Passive,
                ),
                Vec::new(),
                vec![browser_persona()],
            );

            let Err(error) = orchestrator.run_persona(&orchestrator.personas[0]).await else {
                panic!("missing report artifacts must fail after execution");
            };
            assert!(matches!(error.error, ScorchError::ToolOutputParse { .. }));
            let (invocation_count, version_probe, driver_environment) = {
                let invocations = executor.invocations.lock().expect("invocation lock");
                (
                    invocations.len(),
                    invocations[0].args.iter().any(|argument| argument == "-version"),
                    invocations[1].environment.get("JAVA_TOOL_OPTIONS").cloned(),
                )
            };
            assert_eq!(invocation_count, 2);
            assert!(version_probe);
            assert_eq!(driver_environment, Some(format!("-D{property}={executable}")));
        }
    }

    #[test]
    fn version_probe_has_no_persona_or_driver_environment() {
        let workspace = DastWorkspace::create().expect("workspace");
        let invocation =
            version_invocation("zap.sh", &workspace, &crate::config::DastConfig::default());

        assert_eq!(
            invocation.environment_policy,
            crate::runner::subprocess::EnvironmentPolicy::Clear
        );
        assert_eq!(
            invocation.environment.keys().cloned().collect::<Vec<_>>(),
            vec!["HOME".to_string(), "PATH".to_string(), "TMPDIR".to_string()]
        );
        assert!(!format!("{invocation:?}").contains("SCORCHKIT_ZAP"));
        assert!(!invocation.environment.contains_key("JAVA_TOOL_OPTIONS"));
    }

    #[test]
    fn persona_failure_distinguishes_missing_and_invalid_artifacts_and_scrubs_secrets() {
        let persona = ResolvedPersona {
            id: "user".to_string(),
            kind: super::super::plan::ResolvedPersonaKind::Header {
                header_name: "X-Session".to_string(),
                header_value: "arbitrary-fixture-secret".to_string(),
                verification: DastVerificationConfig::default(),
            },
        };
        let mut missing = ApplicationDastAssessment::new(
            "https://example.com",
            scorchkit_core::ApplicationDastProfile::Passive,
        );
        let failure = PersonaRunFailure::with_plan(
            ScorchError::ToolOutputParse {
                tool: "zap".to_string(),
                reason: "required artifact 'report' is unavailable: arbitrary-fixture-secret"
                    .to_string(),
            },
            "a".repeat(64),
        );
        record_persona_failure(&mut missing, &persona, &failure);
        assert_eq!(missing.gaps[0].kind, ApplicationDastGapKind::ArtifactMissing);
        assert_eq!(missing.personas[0].plan_sha256, "a".repeat(64));
        assert_eq!(
            missing.coverage_status,
            scorchkit_core::ApplicationDastCoverageStatus::Degraded
        );
        assert!(!serde_json::to_string(&missing)
            .expect("missing assessment JSON")
            .contains("arbitrary-fixture-secret"));

        let mut invalid = ApplicationDastAssessment::new(
            "https://example.com",
            scorchkit_core::ApplicationDastProfile::Passive,
        );
        let failure = PersonaRunFailure::from(ScorchError::ToolOutputParse {
            tool: "zap".to_string(),
            reason: "report root is malformed".to_string(),
        });
        record_persona_failure(&mut invalid, &persona, &failure);
        assert_eq!(invalid.gaps[0].kind, ApplicationDastGapKind::ArtifactInvalid);
        assert!(invalid.personas[0].plan_sha256.is_empty());
    }

    #[test]
    fn persona_failure_classification_is_exact_for_each_executor_boundary() {
        let persona = browser_persona();
        let cases = [
            (
                ScorchError::ToolNotFound { tool: "zap.sh".to_string() },
                ApplicationDastGapKind::MissingTool,
                ApplicationDastPhase::Authentication,
            ),
            (
                ScorchError::ToolArtifactLimit {
                    tool: "zap.sh".to_string(),
                    limit_bytes: 10,
                    limit_files: 2,
                },
                ApplicationDastGapKind::ArtifactLimit,
                ApplicationDastPhase::AlertReport,
            ),
            (
                ScorchError::ToolOutputParse {
                    tool: "zap.sh".to_string(),
                    reason: "required artifact is unavailable".to_string(),
                },
                ApplicationDastGapKind::ArtifactMissing,
                ApplicationDastPhase::AlertReport,
            ),
            (
                ScorchError::ToolOutputParse {
                    tool: "zap.sh".to_string(),
                    reason: "required artifact is malformed".to_string(),
                },
                ApplicationDastGapKind::ArtifactInvalid,
                ApplicationDastPhase::AlertReport,
            ),
            (
                ScorchError::ToolOutputParse {
                    tool: "zap.sh".to_string(),
                    reason: "optional artifact is unavailable".to_string(),
                },
                ApplicationDastGapKind::ArtifactInvalid,
                ApplicationDastPhase::AlertReport,
            ),
            (
                ScorchError::Config("fixture execution failure".to_string()),
                ApplicationDastGapKind::ExecutionFailed,
                ApplicationDastPhase::AlertReport,
            ),
        ];

        for (error, expected_kind, expected_phase) in cases {
            let mut assessment = ApplicationDastAssessment::new(
                "https://example.com",
                scorchkit_core::ApplicationDastProfile::Passive,
            );
            record_persona_failure(&mut assessment, &persona, &PersonaRunFailure::from(error));
            assert_eq!(assessment.gaps[0].kind, expected_kind);
            assert_eq!(assessment.gaps[0].phase, expected_phase);
            assert_eq!(assessment.personas[0].phases[0].phase, expected_phase);
            assert_eq!(
                assessment.personas[0].authentication,
                ApplicationDastAuthenticationState::Unknown
            );
        }
    }
}
