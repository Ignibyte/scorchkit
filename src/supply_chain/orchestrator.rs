//! Ordered offline application supply-chain execution.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Utc;
use scorchkit_code::SupplyChainProfile;
use scorchkit_core::{
    ModuleOutcome, ModuleOutcomeReason, ProviderSnapshot, ProviderSnapshotState, SbomArtifact,
    SupplyChainAssessment, SupplyChainCoverageGap, SupplyChainGapKind, SupplyChainPhase,
    SupplyChainTarget, SupplyChainTargetKind,
};

use crate::engine::audit_log::subscribe_audit_log_if_enabled;
use crate::engine::code_context::CodeContext;
use crate::engine::error::{Result, ScorchError};
use crate::engine::events::ScanEvent;
use crate::engine::finding::Finding;
use crate::runner::subprocess::is_tool_available;
use crate::runner::subprocess::ToolInvocation;

use super::adapters::{
    grype_config, grype_invocation, osv_config, osv_invocation, parse_grype_report,
    parse_osv_report, parse_trivy_report, syft_config, syft_invocation, trivy_config,
    trivy_invocation, version_output_matches, SupplyChainToolReport,
};
use super::cache::SupplyChainSnapshotStore;
use super::schema::{validate_cyclonedx_1_6, ValidatedSbom};
use super::target::discover_supported_lockfiles;

pub const SYFT_VERSION: &str = "1.50.0";
pub const OSV_SCANNER_VERSION: &str = "2.3.8";
pub const GRYPE_VERSION: &str = "0.116.1";
pub const TRIVY_VERSION: &str = "0.74.0";

/// Durable owner-only workspace containing exact per-run evidence and configuration.
#[derive(Debug, Clone)]
pub struct SupplyChainRunWorkspace {
    path: PathBuf,
}

impl SupplyChainRunWorkspace {
    /// Create a fresh durable run directory under an already authorized local-state root.
    pub fn create(cache_root: &Path) -> Result<Self> {
        let canonical_root = cache_root.canonicalize()?;
        let runs = canonical_root.join("runs");
        match fs::symlink_metadata(&runs) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ScorchError::Config(
                    "supply-chain run root must be a real directory".to_string(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory(&runs)?;
            }
            Err(error) => return Err(error.into()),
        }
        let canonical_runs = runs.canonicalize()?;
        if canonical_runs != runs || !canonical_runs.starts_with(&canonical_root) {
            return Err(ScorchError::Config(
                "supply-chain run root escaped the authorized cache root".to_string(),
            ));
        }
        let path = canonical_runs.join(format!("scan-{}", uuid::Uuid::new_v4()));
        create_private_directory(&path)?;
        for directory in ["home", "cache", "config", "tmp"] {
            create_private_directory(&path.join(directory))?;
        }
        Ok(Self { path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

/// Compatibility output plus the canonical supply-chain assessment.
#[derive(Debug)]
pub struct SupplyChainRun {
    pub assessment: SupplyChainAssessment,
    pub findings: Vec<Finding>,
    pub modules_run: Vec<String>,
    pub modules_skipped: Vec<(String, String)>,
    pub module_outcomes: Vec<ModuleOutcome>,
}

impl SupplyChainRun {
    fn new(target: SupplyChainTarget) -> Self {
        Self {
            assessment: SupplyChainAssessment::new(target),
            findings: Vec::new(),
            modules_run: Vec::new(),
            modules_skipped: Vec::new(),
            module_outcomes: Vec::new(),
        }
    }

    fn completed(&mut self, module: &str, report: SupplyChainToolReport) {
        let finding_count = report.findings.len();
        self.findings.extend(report.findings);
        self.assessment.observations.extend(report.observations);
        self.modules_run.push(module.to_string());
        self.module_outcomes.push(ModuleOutcome::ran(module, finding_count));
    }

    fn completed_producer(&mut self, module: &str) {
        self.modules_run.push(module.to_string());
        self.module_outcomes.push(ModuleOutcome::ran(module, 0));
    }

    fn gap(
        &mut self,
        module: &str,
        phase: SupplyChainPhase,
        kind: SupplyChainGapKind,
        detail: impl AsRef<str>,
    ) {
        let detail = scorchkit_core::observation::redact_text(detail.as_ref());
        self.assessment.record_gap(SupplyChainCoverageGap::new(
            phase,
            kind,
            Some(module.to_string()),
            &detail,
        ));
        self.modules_skipped.push((module.to_string(), detail.clone()));
        if kind.is_degraded() {
            self.module_outcomes.push(ModuleOutcome::failed(
                module,
                ModuleOutcomeReason::ExecutionFailed { message: detail },
            ));
        } else {
            self.module_outcomes.push(ModuleOutcome::skipped(
                module,
                ModuleOutcomeReason::CoverageUnavailable {
                    gap: kind.as_str().to_string(),
                    component: module.to_string(),
                },
            ));
        }
    }
}

/// Explicit producer/consumer orchestrator. It is intentionally separate from `CodeOrchestrator`.
#[derive(Debug)]
pub struct SupplyChainOrchestrator {
    context: CodeContext,
    target: SupplyChainTarget,
    profile: SupplyChainProfile,
    workspace: SupplyChainRunWorkspace,
    snapshots: SupplyChainSnapshotStore,
}

impl SupplyChainOrchestrator {
    #[must_use]
    pub const fn new(
        context: CodeContext,
        target: SupplyChainTarget,
        profile: SupplyChainProfile,
        workspace: SupplyChainRunWorkspace,
        snapshots: SupplyChainSnapshotStore,
    ) -> Self {
        Self { context, target, profile, workspace, snapshots }
    }

    /// Execute selected phases in dependency order and retain partial evidence with exact gaps.
    pub async fn run(self) -> SupplyChainRun {
        let scan_started = Instant::now();
        let scan_id = uuid::Uuid::new_v4().to_string();
        let _audit_log_handle =
            subscribe_audit_log_if_enabled(&self.context.config.audit_log, &self.context.events);
        self.context.events.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: self.target.canonical_path.display().to_string(),
        });
        let mut run = SupplyChainRun::new(self.target.clone());
        let revision = target_revision(&self.target);
        let now = Utc::now();

        if self.target.kind == SupplyChainTargetKind::SourceDirectory {
            self.run_osv(&mut run, &revision, now).await;
        } else if self.profile == SupplyChainProfile::Quick {
            run.gap(
                "osv-scanner",
                SupplyChainPhase::SourceDiscovery,
                SupplyChainGapKind::UnsupportedTarget,
                "the quick supply-chain profile requires a source directory",
            );
        }

        if self.profile.requires_sbom() {
            let validated_sbom = self.produce_or_import_sbom(&mut run).await;
            if let Some(sbom) = validated_sbom.as_ref() {
                self.run_grype(&mut run, &revision, sbom, now).await;
                if self.profile.requires_secondary_consumer() {
                    self.run_trivy(&mut run, &revision, sbom, now).await;
                }
            } else {
                run.gap(
                    "grype",
                    SupplyChainPhase::ArtifactVulnerabilityScan,
                    SupplyChainGapKind::UpstreamUnavailable,
                    "verified CycloneDX SBOM was unavailable",
                );
                if self.profile.requires_secondary_consumer() {
                    run.gap(
                        "trivy",
                        SupplyChainPhase::ArtifactVulnerabilityScan,
                        SupplyChainGapKind::UpstreamUnavailable,
                        "verified CycloneDX SBOM was unavailable",
                    );
                }
            }
        }

        run.assessment.correlate();
        run.assessment.refresh_coverage_status();
        self.context.events.publish(ScanEvent::ScanCompleted {
            scan_id,
            total_findings: run.findings.len(),
            duration_ms: u64::try_from(scan_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
        run
    }

    async fn run_osv(&self, run: &mut SupplyChainRun, revision: &str, now: chrono::DateTime<Utc>) {
        let lockfiles = match discover_supported_lockfiles(&self.target.canonical_path) {
            Ok(lockfiles) if !lockfiles.is_empty() => lockfiles,
            Ok(_) => {
                run.gap(
                    "osv-scanner",
                    SupplyChainPhase::SourceDiscovery,
                    SupplyChainGapKind::NoSupportedManifest,
                    "no supported lockfile was found",
                );
                return;
            }
            Err(error) => {
                run.gap(
                    "osv-scanner",
                    SupplyChainPhase::SourceDiscovery,
                    SupplyChainGapKind::OutputInvalid,
                    error.to_string(),
                );
                return;
            }
        };
        let program = self.context.config.tools.get_path("osv-scanner");
        if !is_tool_available(&program) {
            run.gap(
                "osv-scanner",
                SupplyChainPhase::SourceDependencyScan,
                SupplyChainGapKind::MissingTool,
                "OSV-Scanner executable is unavailable",
            );
            return;
        }
        let snapshot = self.snapshots.status(
            "osv",
            now,
            self.context.config.supply_chain.osv_maximum_age_seconds,
        );
        if !ready_snapshot(run, "osv-scanner", SupplyChainPhase::SourceDependencyScan, &snapshot) {
            return;
        }
        if let Err(error) =
            verify_pinned_tool(&self.context, &program, OSV_SCANNER_VERSION, self.workspace.path())
                .await
        {
            run.gap(
                "osv-scanner",
                SupplyChainPhase::SourceDependencyScan,
                SupplyChainGapKind::IncompatibleToolVersion,
                error.to_string(),
            );
            return;
        }
        let config_path = self.workspace.file("osv-config.toml");
        if let Err(error) = write_owned(&config_path, osv_config().as_bytes()) {
            run.gap(
                "osv-scanner",
                SupplyChainPhase::SourceDependencyScan,
                SupplyChainGapKind::ArtifactUnavailable,
                error.to_string(),
            );
            return;
        }
        let invocation = osv_invocation(
            &program,
            &lockfiles,
            &config_path,
            &snapshot.consumer_path,
            self.workspace.path(),
            self.context.config.supply_chain.artifact_limit_bytes,
        );
        match self.context.run_invocation(invocation).await {
            Ok(output) => {
                let evidence_path = self.workspace.file("osv-report.json");
                let parsed = write_owned(&evidence_path, output.stdout.as_bytes()).and_then(|()| {
                    parse_osv_report(
                        output.stdout.as_bytes(),
                        &evidence_path,
                        revision,
                        OSV_SCANNER_VERSION,
                        &snapshot.snapshot_id,
                    )
                });
                match parsed {
                    Ok(report) => run.completed("osv-scanner", report),
                    Err(error) => run.gap(
                        "osv-scanner",
                        SupplyChainPhase::SourceDependencyScan,
                        SupplyChainGapKind::OutputInvalid,
                        error.to_string(),
                    ),
                }
            }
            Err(error) => run.gap(
                "osv-scanner",
                SupplyChainPhase::SourceDependencyScan,
                SupplyChainGapKind::ConsumerFailed,
                error.to_string(),
            ),
        }
    }

    // JUSTIFICATION: SBOM production and import share one atomic evidence-acceptance boundary;
    // extraction would split validation, canonical persistence, and coverage recording.
    #[allow(clippy::too_many_lines)]
    async fn produce_or_import_sbom(&self, run: &mut SupplyChainRun) -> Option<ValidatedSbom> {
        let owned_path = self.workspace.file("application.cdx.json");
        let maximum = self.context.config.supply_chain.artifact_limit_bytes;
        let (validated, producer, producer_version) =
            if self.target.kind == SupplyChainTargetKind::CycloneDxSbom {
                let bytes = match read_bounded(&self.target.canonical_path, maximum) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        run.gap(
                            "cyclonedx-import",
                            SupplyChainPhase::SbomValidation,
                            SupplyChainGapKind::ArtifactUnavailable,
                            error.to_string(),
                        );
                        return None;
                    }
                };
                match validate_cyclonedx_1_6(&bytes, maximum) {
                    Ok(validated) => (validated, "supplied".to_string(), "1.6".to_string()),
                    Err(error) => {
                        run.gap(
                            "cyclonedx-import",
                            SupplyChainPhase::SbomValidation,
                            SupplyChainGapKind::OutputInvalid,
                            error.to_string(),
                        );
                        return None;
                    }
                }
            } else {
                let program = self.context.config.tools.get_path("syft");
                if !is_tool_available(&program) {
                    run.gap(
                        "syft",
                        SupplyChainPhase::SbomProduction,
                        SupplyChainGapKind::MissingTool,
                        "Syft executable is unavailable",
                    );
                    return None;
                }
                if let Err(error) =
                    verify_pinned_tool(&self.context, &program, SYFT_VERSION, self.workspace.path())
                        .await
                {
                    run.gap(
                        "syft",
                        SupplyChainPhase::SbomProduction,
                        SupplyChainGapKind::IncompatibleToolVersion,
                        error.to_string(),
                    );
                    return None;
                }
                let config_path = self.workspace.file("syft-config.yaml");
                if let Err(error) = write_owned(&config_path, syft_config().as_bytes()) {
                    run.gap(
                        "syft",
                        SupplyChainPhase::SbomProduction,
                        SupplyChainGapKind::ArtifactUnavailable,
                        error.to_string(),
                    );
                    return None;
                }
                let invocation = match syft_invocation(
                    &program,
                    &self.target,
                    &config_path,
                    self.workspace.path(),
                    maximum,
                ) {
                    Ok(invocation) => invocation,
                    Err(error) => {
                        run.gap(
                            "syft",
                            SupplyChainPhase::SbomProduction,
                            SupplyChainGapKind::ProducerFailed,
                            error.to_string(),
                        );
                        return None;
                    }
                };
                let output = match self.context.run_invocation(invocation).await {
                    Ok(output) => output,
                    Err(error) => {
                        run.gap(
                            "syft",
                            SupplyChainPhase::SbomProduction,
                            SupplyChainGapKind::ProducerFailed,
                            error.to_string(),
                        );
                        return None;
                    }
                };
                let bytes = output.stdout.into_bytes();
                if let Err(error) = write_owned(&owned_path, &bytes) {
                    run.gap(
                        "syft",
                        SupplyChainPhase::SbomValidation,
                        SupplyChainGapKind::ArtifactUnavailable,
                        error.to_string(),
                    );
                    return None;
                }
                match validate_cyclonedx_1_6(&bytes, maximum) {
                    Ok(validated) => (validated, "syft".to_string(), SYFT_VERSION.to_string()),
                    Err(error) => {
                        run.gap(
                            "syft",
                            SupplyChainPhase::SbomValidation,
                            SupplyChainGapKind::OutputInvalid,
                            error.to_string(),
                        );
                        return None;
                    }
                }
            };

        if self.target.kind == SupplyChainTargetKind::CycloneDxSbom {
            if let Err(error) = write_owned(&owned_path, validated.bytes()) {
                run.gap(
                    "cyclonedx-import",
                    SupplyChainPhase::SbomValidation,
                    SupplyChainGapKind::ArtifactUnavailable,
                    error.to_string(),
                );
                return None;
            }
            run.completed_producer("cyclonedx-import");
        } else {
            run.completed_producer("syft");
        }
        run.assessment.sbom = Some(SbomArtifact {
            canonical_path: owned_path,
            sha256: validated.sha256().to_string(),
            size_bytes: u64::try_from(validated.bytes().len()).unwrap_or(u64::MAX),
            format: "CycloneDX JSON".to_string(),
            specification_version: validated.document()["specVersion"]
                .as_str()
                .unwrap_or("1.6")
                .to_string(),
            producer,
            producer_version,
            produced_at: Utc::now(),
        });
        Some(validated)
    }

    // JUSTIFICATION: One consumer lifecycle owns authorization, snapshot verification, execution,
    // parsing, and typed coverage so partial success cannot escape as complete evidence.
    #[allow(clippy::too_many_lines)]
    async fn run_grype(
        &self,
        run: &mut SupplyChainRun,
        revision: &str,
        sbom: &ValidatedSbom,
        now: chrono::DateTime<Utc>,
    ) {
        let program = self.context.config.tools.get_path("grype");
        if !is_tool_available(&program) {
            run.gap(
                "grype",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::MissingTool,
                "Grype executable is unavailable",
            );
            return;
        }
        let snapshot = self.snapshots.status(
            "grype",
            now,
            self.context.config.supply_chain.grype_maximum_age_seconds,
        );
        if !ready_snapshot(run, "grype", SupplyChainPhase::ArtifactVulnerabilityScan, &snapshot) {
            return;
        }
        if let Err(error) =
            verify_pinned_tool(&self.context, &program, GRYPE_VERSION, self.workspace.path()).await
        {
            run.gap(
                "grype",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::IncompatibleToolVersion,
                error.to_string(),
            );
            return;
        }
        let config = match grype_config(
            &snapshot.consumer_path,
            self.context.config.supply_chain.grype_maximum_age_seconds,
        ) {
            Ok(config) => config,
            Err(error) => {
                run.gap(
                    "grype",
                    SupplyChainPhase::ArtifactVulnerabilityScan,
                    SupplyChainGapKind::ArtifactUnavailable,
                    error.to_string(),
                );
                return;
            }
        };
        let config_path = self.workspace.file("grype-config.yaml");
        if let Err(error) = write_owned(&config_path, config.as_bytes()) {
            run.gap(
                "grype",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::ArtifactUnavailable,
                error.to_string(),
            );
            return;
        }
        let Some(sbom_path) =
            run.assessment.sbom.as_ref().map(|artifact| artifact.canonical_path.clone())
        else {
            return;
        };
        let invocation = grype_invocation(
            &program,
            &sbom_path,
            &config_path,
            self.workspace.path(),
            self.context.config.supply_chain.artifact_limit_bytes,
        );
        match self.context.run_invocation(invocation).await {
            Ok(output) => {
                if !sbom_unchanged(
                    &sbom_path,
                    sbom,
                    self.context.config.supply_chain.artifact_limit_bytes,
                ) {
                    run.gap(
                        "grype",
                        SupplyChainPhase::ArtifactVulnerabilityScan,
                        SupplyChainGapKind::ArtifactUnavailable,
                        "verified SBOM changed during Grype consumption",
                    );
                    return;
                }
                let evidence_path = self.workspace.file("grype-report.json");
                let parsed = write_owned(&evidence_path, output.stdout.as_bytes()).and_then(|()| {
                    parse_grype_report(
                        output.stdout.as_bytes(),
                        &evidence_path,
                        revision,
                        GRYPE_VERSION,
                        &snapshot.snapshot_id,
                    )
                });
                match parsed {
                    Ok(report) => run.completed("grype", report),
                    Err(error) => run.gap(
                        "grype",
                        SupplyChainPhase::ArtifactVulnerabilityScan,
                        SupplyChainGapKind::OutputInvalid,
                        error.to_string(),
                    ),
                }
            }
            Err(error) => run.gap(
                "grype",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::ConsumerFailed,
                error.to_string(),
            ),
        }
    }

    // JUSTIFICATION: One consumer lifecycle owns authorization, snapshot verification, execution,
    // parsing, and typed coverage so partial success cannot escape as complete evidence.
    #[allow(clippy::too_many_lines)]
    async fn run_trivy(
        &self,
        run: &mut SupplyChainRun,
        revision: &str,
        sbom: &ValidatedSbom,
        now: chrono::DateTime<Utc>,
    ) {
        let program = self.context.config.tools.get_path("trivy");
        if !is_tool_available(&program) {
            run.gap(
                "trivy",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::MissingTool,
                "Trivy executable is unavailable",
            );
            return;
        }
        let snapshot = self.snapshots.status(
            "trivy",
            now,
            self.context.config.supply_chain.trivy_maximum_age_seconds,
        );
        if !ready_snapshot(run, "trivy", SupplyChainPhase::ArtifactVulnerabilityScan, &snapshot) {
            return;
        }
        if let Err(error) =
            verify_pinned_tool(&self.context, &program, TRIVY_VERSION, self.workspace.path()).await
        {
            run.gap(
                "trivy",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::IncompatibleToolVersion,
                error.to_string(),
            );
            return;
        }
        let config = match trivy_config(&snapshot.consumer_path) {
            Ok(config) => config,
            Err(error) => {
                run.gap(
                    "trivy",
                    SupplyChainPhase::ArtifactVulnerabilityScan,
                    SupplyChainGapKind::ArtifactUnavailable,
                    error.to_string(),
                );
                return;
            }
        };
        let config_path = self.workspace.file("trivy-config.yaml");
        let ignore_path = self.workspace.file("trivy-ignore");
        if let Err(error) = write_owned(&config_path, config.as_bytes())
            .and_then(|()| write_owned(&ignore_path, b""))
        {
            run.gap(
                "trivy",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::ArtifactUnavailable,
                error.to_string(),
            );
            return;
        }
        let Some(sbom_path) =
            run.assessment.sbom.as_ref().map(|artifact| artifact.canonical_path.clone())
        else {
            return;
        };
        let output_path = self.workspace.file("trivy-report.json");
        let invocation = trivy_invocation(
            &program,
            &sbom_path,
            &config_path,
            &snapshot.consumer_path,
            &ignore_path,
            self.workspace.path(),
            self.context.config.supply_chain.artifact_limit_bytes,
        );
        match self.context.run_invocation(invocation).await {
            Ok(output) => {
                if !sbom_unchanged(
                    &sbom_path,
                    sbom,
                    self.context.config.supply_chain.artifact_limit_bytes,
                ) {
                    run.gap(
                        "trivy",
                        SupplyChainPhase::ArtifactVulnerabilityScan,
                        SupplyChainGapKind::ArtifactUnavailable,
                        "verified SBOM changed during Trivy consumption",
                    );
                    return;
                }
                let bytes = output.stdout.into_bytes();
                let parsed = write_owned(&output_path, &bytes).and_then(|()| {
                    parse_trivy_report(
                        &bytes,
                        &output_path,
                        revision,
                        TRIVY_VERSION,
                        &snapshot.snapshot_id,
                    )
                });
                match parsed {
                    Ok(report) => run.completed("trivy", report),
                    Err(error) => run.gap(
                        "trivy",
                        SupplyChainPhase::ArtifactVulnerabilityScan,
                        SupplyChainGapKind::OutputInvalid,
                        error.to_string(),
                    ),
                }
            }
            Err(error) => run.gap(
                "trivy",
                SupplyChainPhase::ArtifactVulnerabilityScan,
                SupplyChainGapKind::ConsumerFailed,
                error.to_string(),
            ),
        }
    }
}

async fn verify_pinned_tool(
    context: &CodeContext,
    program: &str,
    expected_version: &str,
    workspace: &Path,
) -> Result<()> {
    let invocation = ToolInvocation::strict_owned(
        program,
        vec!["--version".to_string()],
        Duration::from_secs(10),
    )
    .with_clean_environment()
    .with_environment("HOME", workspace.join("home").display().to_string())
    .with_environment("XDG_CACHE_HOME", workspace.join("cache").display().to_string())
    .with_environment("XDG_CONFIG_HOME", workspace.join("config").display().to_string())
    .with_environment("TMPDIR", workspace.join("tmp").display().to_string())
    .with_working_directory(workspace)
    .with_output_limit(16 * 1024);
    let output = context.run_invocation(invocation).await?;
    if version_output_matches(&output.stdout, &output.stderr, expected_version) {
        Ok(())
    } else {
        Err(ScorchError::Config(format!(
            "tool version does not match the pinned {expected_version} contract"
        )))
    }
}

fn ready_snapshot(
    run: &mut SupplyChainRun,
    module: &str,
    phase: SupplyChainPhase,
    snapshot: &ProviderSnapshot,
) -> bool {
    run.assessment.provider_snapshots.push(snapshot.clone());
    let kind = match snapshot.state {
        ProviderSnapshotState::Ready => return true,
        ProviderSnapshotState::Missing => SupplyChainGapKind::MissingProviderSnapshot,
        ProviderSnapshotState::Stale => SupplyChainGapKind::StaleProviderSnapshot,
        ProviderSnapshotState::Invalid => SupplyChainGapKind::InvalidProviderSnapshot,
    };
    run.gap(
        module,
        phase,
        kind,
        snapshot.validation_error.as_deref().unwrap_or("provider snapshot is not ready"),
    );
    false
}

fn target_revision(target: &SupplyChainTarget) -> String {
    target
        .revision
        .clone()
        .or_else(|| target.sha256.clone())
        .unwrap_or_else(|| format!("unversioned:{}", target.canonical_path.display()))
}

fn sbom_unchanged(path: &Path, expected: &ValidatedSbom, maximum_bytes: usize) -> bool {
    read_bounded(path, maximum_bytes)
        .is_ok_and(|bytes| scorchkit_core::sha256_hex(&bytes) == expected.sha256())
}

fn read_bounded(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let read_limit = u64::try_from(maximum_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
    Read::by_ref(&mut file).take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(ScorchError::ToolOutputLimit {
            tool: "supply-chain-artifact".to_string(),
            stream: "artifact",
            limit_bytes: maximum_bytes,
        });
    }
    Ok(bytes)
}

fn write_owned(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::AppConfig;
    use crate::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
    use crate::engine::scope::ScopeRule;
    use crate::facade::Engine;

    const VALID_SBOM: &str = r#"{
      "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
      "components":[{"type":"library","bom-ref":"pkg:cargo/demo@1.0.0","name":"demo","version":"1.0.0","purl":"pkg:cargo/demo@1.0.0"}],
      "dependencies":[{"ref":"pkg:cargo/demo@1.0.0"}]
    }"#;

    fn test_context(source: &Path, mut config: AppConfig) -> CodeContext {
        let canonical_source = source.canonicalize().expect("source path");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&canonical_source).expect("source scope"))
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive);
        config.supply_chain.artifact_limit_bytes = 1024 * 1024;
        Engine::for_engagement(Arc::new(config), Arc::new(Engagement::new("fixture", policy)))
            .code_context(&canonical_source, None)
            .expect("authorized code context")
    }

    fn target(path: &Path, kind: SupplyChainTargetKind) -> SupplyChainTarget {
        SupplyChainTarget {
            kind,
            canonical_path: path.canonicalize().expect("target path"),
            revision: Some("fixture-revision".to_string()),
            sha256: Some(scorchkit_core::sha256_hex(b"fixture")),
        }
    }

    fn promote_provider(store: &SupplyChainSnapshotStore, provider: &str) {
        use crate::supply_chain::cache::{SnapshotArtifact, SnapshotManifest};

        let snapshot_id = format!("{provider}-fixture");
        let stage = store.create_staging(provider, &snapshot_id).expect("staging slot");
        fs::create_dir(stage.join("cache")).expect("consumer directory");
        fs::write(stage.join("cache/database.bin"), b"fixture-db").expect("provider artifact");
        store
            .promote(
                &stage,
                &SnapshotManifest {
                    provider: provider.to_string(),
                    snapshot_id,
                    schema_version: "fixture-v1".to_string(),
                    consumer_relative_path: PathBuf::from("cache"),
                    artifacts: vec![SnapshotArtifact {
                        relative_path: PathBuf::from("cache/database.bin"),
                        sha256: scorchkit_core::sha256_hex(b"fixture-db"),
                    }],
                    upstream_built_at: None,
                    checked_at: Utc::now(),
                    maximum_age_seconds: 3600,
                },
            )
            .expect("promote provider");
    }

    #[cfg(unix)]
    fn write_fake_consumer(path: &Path, version: &str, report: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(
            path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' '{version}'\nelse\n  printf '%s' '{report}'\nfi\n"
            ),
        )
        .expect("fake consumer");
        fs::set_permissions(path, PermissionsExt::from_mode(0o700)).expect("consumer mode");
    }

    #[tokio::test]
    async fn quick_profile_reports_missing_provider_as_incomplete_without_launching_a_tool() {
        let source = tempfile::tempdir().expect("source");
        fs::write(source.path().join("Cargo.lock"), "# fixture").expect("lockfile");
        let cache = tempfile::tempdir().expect("cache");
        #[cfg(unix)]
        fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let canonical_source = source.path().canonicalize().expect("source path");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&canonical_source).expect("source scope"))
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive);
        let context = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("fixture", policy)),
        )
        .code_context(&canonical_source, None)
        .expect("authorized code context");
        let target = SupplyChainTarget {
            kind: SupplyChainTargetKind::SourceDirectory,
            canonical_path: canonical_source,
            revision: Some("fixture".to_string()),
            sha256: None,
        };
        let workspace = SupplyChainRunWorkspace::create(cache.path()).expect("workspace");
        let snapshots = SupplyChainSnapshotStore::open(cache.path(), 1024).expect("snapshot store");
        let run = SupplyChainOrchestrator::new(
            context,
            target,
            SupplyChainProfile::Quick,
            workspace,
            snapshots,
        )
        .run()
        .await;

        assert_eq!(
            run.assessment.coverage_status,
            scorchkit_core::SupplyChainCoverageStatus::Incomplete
        );
        assert_eq!(run.module_outcomes.len(), 1);
        assert_eq!(run.module_outcomes[0].status, scorchkit_core::ModuleOutcomeStatus::Skipped);
    }

    #[tokio::test]
    async fn quick_artifact_profile_cannot_report_an_empty_complete_assessment() {
        let artifact_root = tempfile::tempdir().expect("artifact root");
        let artifact = artifact_root.path().join("application.tar");
        fs::write(&artifact, b"fixture artifact").expect("artifact");
        let cache = tempfile::tempdir().expect("cache");
        #[cfg(unix)]
        fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let canonical_artifact = artifact.canonicalize().expect("artifact path");
        let policy = EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(artifact_root.path()).expect("artifact scope"))
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive);
        let context = Engine::for_engagement(
            Arc::new(AppConfig::default()),
            Arc::new(Engagement::new("fixture", policy)),
        )
        .code_context(&canonical_artifact, None)
        .expect("authorized code context");
        let target = SupplyChainTarget {
            kind: SupplyChainTargetKind::FileArtifact,
            canonical_path: canonical_artifact,
            revision: Some("fixture".to_string()),
            sha256: Some(scorchkit_core::sha256_hex(b"fixture artifact")),
        };
        let workspace = SupplyChainRunWorkspace::create(cache.path()).expect("workspace");
        let snapshots = SupplyChainSnapshotStore::open(cache.path(), 1024).expect("snapshot store");

        let run = SupplyChainOrchestrator::new(
            context,
            target,
            SupplyChainProfile::Quick,
            workspace,
            snapshots,
        )
        .run()
        .await;

        assert_eq!(
            run.assessment.coverage_status,
            scorchkit_core::SupplyChainCoverageStatus::Incomplete
        );
        assert_eq!(run.assessment.gaps[0].kind, SupplyChainGapKind::UnsupportedTarget);
        assert!(run.modules_run.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn run_workspace_rejects_a_redirected_runs_directory() {
        use std::os::unix::fs::symlink;

        let cache = tempfile::tempdir().expect("cache root");
        let outside = tempfile::tempdir().expect("outside root");
        symlink(outside.path(), cache.path().join("runs")).expect("runs symlink");

        assert!(SupplyChainRunWorkspace::create(cache.path()).is_err());
        assert!(fs::read_dir(outside.path()).expect("outside inventory").next().is_none());
    }

    #[test]
    fn run_workspace_requires_a_real_runs_directory_and_creates_private_children() {
        let cache = tempfile::tempdir().expect("cache root");
        let first = SupplyChainRunWorkspace::create(cache.path()).expect("new runs root");
        assert!(first.path().is_dir());
        for child in ["home", "cache", "config", "tmp"] {
            assert!(first.path().join(child).is_dir());
        }
        let second = SupplyChainRunWorkspace::create(cache.path()).expect("existing runs root");
        assert_ne!(first.path(), second.path());

        let file_cache = tempfile::tempdir().expect("file cache root");
        fs::write(file_cache.path().join("runs"), b"not a directory").expect("runs file");
        let error = SupplyChainRunWorkspace::create(file_cache.path()).expect_err("reject file");
        assert!(error.to_string().contains("real directory"));
    }

    #[test]
    fn completed_run_bookkeeping_preserves_findings_observations_and_producers() {
        let source = tempfile::tempdir().expect("source");
        let mut run =
            SupplyChainRun::new(target(source.path(), SupplyChainTargetKind::SourceDirectory));
        let report = SupplyChainToolReport {
            findings: vec![Finding::new(
                "fixture",
                crate::engine::severity::Severity::High,
                "title",
                "description",
                "location",
            )],
            observations: Vec::new(),
        };
        run.completed("grype", report);
        run.completed_producer("syft");
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.modules_run, ["grype", "syft"]);
        assert_eq!(run.module_outcomes.len(), 2);
        assert_eq!(run.module_outcomes[0].findings_count, Some(1));
        assert_eq!(run.module_outcomes[1].findings_count, Some(0));
    }

    #[tokio::test]
    async fn osv_distinguishes_no_lockfile_from_an_unavailable_tool() {
        for (with_lockfile, expected_gap) in [
            (false, SupplyChainGapKind::NoSupportedManifest),
            (true, SupplyChainGapKind::MissingTool),
        ] {
            let source = tempfile::tempdir().expect("source");
            if with_lockfile {
                fs::write(source.path().join("Cargo.lock"), "# fixture").expect("lockfile");
            }
            let cache = tempfile::tempdir().expect("cache");
            #[cfg(unix)]
            fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("private cache");
            let mut config = AppConfig::default();
            config.tools.osv_scanner = Some(cache.path().join("missing-osv").display().to_string());
            let context = test_context(source.path(), config);
            let workspace = SupplyChainRunWorkspace::create(cache.path()).expect("workspace");
            let snapshots =
                SupplyChainSnapshotStore::open(cache.path(), 1024 * 1024).expect("snapshot store");
            let orchestrator = SupplyChainOrchestrator::new(
                context,
                target(source.path(), SupplyChainTargetKind::SourceDirectory),
                SupplyChainProfile::Quick,
                workspace,
                snapshots,
            );
            let mut run = SupplyChainRun::new(orchestrator.target.clone());
            orchestrator.run_osv(&mut run, "revision", Utc::now()).await;
            assert_eq!(run.assessment.gaps.len(), 1);
            assert_eq!(run.assessment.gaps[0].kind, expected_gap);
        }
    }

    #[tokio::test]
    async fn imported_sbom_is_persisted_and_recorded_as_the_exact_producer() {
        let source = tempfile::tempdir().expect("source");
        let sbom_path = source.path().join("input.cdx.json");
        fs::write(&sbom_path, VALID_SBOM).expect("SBOM fixture");
        let cache = tempfile::tempdir().expect("cache");
        #[cfg(unix)]
        fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let context = test_context(source.path(), AppConfig::default());
        let workspace = SupplyChainRunWorkspace::create(cache.path()).expect("workspace");
        let snapshots =
            SupplyChainSnapshotStore::open(cache.path(), 1024 * 1024).expect("snapshot store");
        let orchestrator = SupplyChainOrchestrator::new(
            context,
            target(&sbom_path, SupplyChainTargetKind::CycloneDxSbom),
            SupplyChainProfile::Standard,
            workspace,
            snapshots,
        );
        let mut run = SupplyChainRun::new(orchestrator.target.clone());
        let validated = orchestrator.produce_or_import_sbom(&mut run).await.expect("imported SBOM");
        assert_eq!(validated.bytes(), VALID_SBOM.as_bytes());
        assert_eq!(run.modules_run, ["cyclonedx-import"]);
        assert_eq!(run.assessment.sbom.as_ref().unwrap().producer, "supplied");
        assert_eq!(
            fs::read(&run.assessment.sbom.as_ref().unwrap().canonical_path).unwrap(),
            VALID_SBOM.as_bytes()
        );
    }

    #[tokio::test]
    async fn missing_syft_grype_and_trivy_are_reported_by_their_own_phase() {
        let source = tempfile::tempdir().expect("source");
        let artifact = source.path().join("artifact.bin");
        fs::write(&artifact, b"fixture").expect("artifact");
        let cache = tempfile::tempdir().expect("cache");
        #[cfg(unix)]
        fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private cache");
        let missing = cache.path().join("missing-tool").display().to_string();
        let mut config = AppConfig::default();
        config.tools.syft = Some(missing.clone());
        config.tools.grype = Some(missing.clone());
        config.tools.trivy = Some(missing);
        let context = test_context(source.path(), config);
        let workspace = SupplyChainRunWorkspace::create(cache.path()).expect("workspace");
        let snapshots =
            SupplyChainSnapshotStore::open(cache.path(), 1024 * 1024).expect("snapshot store");
        let orchestrator = SupplyChainOrchestrator::new(
            context,
            target(&artifact, SupplyChainTargetKind::FileArtifact),
            SupplyChainProfile::Thorough,
            workspace,
            snapshots,
        );
        let mut run = SupplyChainRun::new(orchestrator.target.clone());
        assert!(orchestrator.produce_or_import_sbom(&mut run).await.is_none());
        assert_eq!(run.assessment.gaps.last().unwrap().kind, SupplyChainGapKind::MissingTool);

        let validated = validate_cyclonedx_1_6(VALID_SBOM.as_bytes(), 1024 * 1024).unwrap();
        run.assessment.sbom = Some(SbomArtifact {
            canonical_path: orchestrator.workspace.file("manual.cdx.json"),
            sha256: validated.sha256().to_string(),
            size_bytes: VALID_SBOM.len() as u64,
            format: "CycloneDX JSON".to_string(),
            specification_version: "1.6".to_string(),
            producer: "fixture".to_string(),
            producer_version: "1.6".to_string(),
            produced_at: Utc::now(),
        });
        write_owned(&run.assessment.sbom.as_ref().unwrap().canonical_path, VALID_SBOM.as_bytes())
            .expect("owned SBOM");
        orchestrator.run_grype(&mut run, "revision", &validated, Utc::now()).await;
        assert_eq!(run.assessment.gaps.last().unwrap().component.as_deref(), Some("grype"));
        assert_eq!(run.assessment.gaps.last().unwrap().kind, SupplyChainGapKind::MissingTool);
        orchestrator.run_trivy(&mut run, "revision", &validated, Utc::now()).await;
        assert_eq!(run.assessment.gaps.last().unwrap().component.as_deref(), Some("trivy"));
        assert_eq!(run.assessment.gaps.last().unwrap().kind, SupplyChainGapKind::MissingTool);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pinned_tool_verification_enforces_version_and_the_16_kib_output_contract() {
        use std::os::unix::fs::PermissionsExt;

        let source = tempfile::tempdir().expect("source");
        let context = test_context(source.path(), AppConfig::default());
        let workspace = tempfile::tempdir().expect("workspace");
        for child in ["home", "cache", "config", "tmp"] {
            fs::create_dir(workspace.path().join(child)).expect("workspace child");
        }
        let valid = workspace.path().join("valid-tool");
        let padding = "x".repeat(2048);
        fs::write(&valid, format!("#!/bin/sh\nprintf 'tool 1.2.3 {padding}\\n'\n"))
            .expect("valid tool");
        fs::set_permissions(&valid, PermissionsExt::from_mode(0o700)).expect("tool mode");
        assert!(verify_pinned_tool(&context, valid.to_str().unwrap(), "1.2.3", workspace.path())
            .await
            .is_ok());
        assert!(verify_pinned_tool(&context, valid.to_str().unwrap(), "9.9.9", workspace.path())
            .await
            .is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn grype_and_trivy_consume_the_same_unchanged_verified_sbom() {
        let source = tempfile::tempdir().expect("source");
        let sbom_path = source.path().join("input.cdx.json");
        fs::write(&sbom_path, VALID_SBOM).expect("SBOM fixture");
        let validated = validate_cyclonedx_1_6(VALID_SBOM.as_bytes(), 1024 * 1024).unwrap();

        for (provider, version, report) in [
            (
                "grype",
                GRYPE_VERSION,
                r#"{"descriptor":{"name":"grype","version":"0.116.1"},"matches":[]}"#,
            ),
            ("trivy", TRIVY_VERSION, r#"{"SchemaVersion":2,"Results":[]}"#),
        ] {
            let cache = tempfile::tempdir().expect("cache");
            fs::set_permissions(cache.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("private cache");
            let tool = cache.path().join(format!("fake-{provider}"));
            write_fake_consumer(&tool, version, report);
            let mut config = AppConfig::default();
            if provider == "grype" {
                config.tools.grype = Some(tool.display().to_string());
            } else {
                config.tools.trivy = Some(tool.display().to_string());
            }
            let context = test_context(source.path(), config);
            let workspace = SupplyChainRunWorkspace::create(cache.path()).expect("workspace");
            let snapshots =
                SupplyChainSnapshotStore::open(cache.path(), 1024 * 1024).expect("snapshot store");
            promote_provider(&snapshots, provider);
            let orchestrator = SupplyChainOrchestrator::new(
                context,
                target(&sbom_path, SupplyChainTargetKind::CycloneDxSbom),
                SupplyChainProfile::Thorough,
                workspace,
                snapshots,
            );
            let owned_sbom = orchestrator.workspace.file("manual.cdx.json");
            write_owned(&owned_sbom, VALID_SBOM.as_bytes()).expect("owned SBOM");
            let mut run = SupplyChainRun::new(orchestrator.target.clone());
            run.assessment.sbom = Some(SbomArtifact {
                canonical_path: owned_sbom,
                sha256: validated.sha256().to_string(),
                size_bytes: VALID_SBOM.len() as u64,
                format: "CycloneDX JSON".to_string(),
                specification_version: "1.6".to_string(),
                producer: "fixture".to_string(),
                producer_version: "1.6".to_string(),
                produced_at: Utc::now(),
            });
            if provider == "grype" {
                orchestrator.run_grype(&mut run, "revision", &validated, Utc::now()).await;
            } else {
                orchestrator.run_trivy(&mut run, "revision", &validated, Utc::now()).await;
            }
            assert_eq!(run.modules_run, [provider]);
            assert!(run.assessment.gaps.is_empty());
            assert_eq!(run.module_outcomes.len(), 1);
        }
    }

    #[test]
    fn revision_sbom_and_owned_file_helpers_are_exact_at_boundaries() {
        let source = tempfile::tempdir().expect("source");
        let path = source.path().join("sbom.json");
        fs::write(&path, VALID_SBOM).expect("SBOM fixture");
        let validated = validate_cyclonedx_1_6(VALID_SBOM.as_bytes(), VALID_SBOM.len()).unwrap();
        assert!(sbom_unchanged(&path, &validated, VALID_SBOM.len()));
        fs::write(&path, VALID_SBOM.replace("demo", "changed")).expect("changed SBOM");
        assert!(!sbom_unchanged(&path, &validated, 1024 * 1024));

        fs::write(&path, b"1234").expect("bounded fixture");
        assert_eq!(read_bounded(&path, 4).unwrap(), b"1234");
        assert!(read_bounded(&path, 3).is_err());

        let owned = source.path().join("owned.bin");
        write_owned(&owned, b"owned").expect("owned file");
        assert_eq!(fs::read(&owned).unwrap(), b"owned");
        assert!(write_owned(&owned, b"replacement").is_err());

        let mut revision_target = target(source.path(), SupplyChainTargetKind::SourceDirectory);
        assert_eq!(target_revision(&revision_target), "fixture-revision");
        revision_target.revision = None;
        assert_eq!(target_revision(&revision_target), scorchkit_core::sha256_hex(b"fixture"));
        revision_target.sha256 = None;
        assert_eq!(
            target_revision(&revision_target),
            format!("unversioned:{}", revision_target.canonical_path.display())
        );
    }

    #[test]
    fn layered_workspace_guards_and_version_limit_remain_explicit() {
        let production = include_str!("orchestrator.rs").split("#[cfg(test)]").next().unwrap();
        let compact: String = production.split_whitespace().collect();
        for invariant in [
            "Err(error)iferror.kind()==std::io::ErrorKind::NotFound=>",
            "ifcanonical_runs!=runs||!canonical_runs.starts_with(&canonical_root)",
            ".with_output_limit(16*1024)",
        ] {
            assert!(compact.contains(invariant), "workspace guard changed: {invariant}");
        }
    }
}
