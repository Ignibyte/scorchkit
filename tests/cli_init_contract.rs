use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use scorchkit::config::AppConfig;
use scorchkit::engine::finding::Finding;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scan_result::ScanResult;
use scorchkit::engine::scope::ScopeRule;
use scorchkit::engine::severity::Severity;
use scorchkit::engine::target::Target;
use scorchkit::runner::checkpoint::{save_checkpoint, ScanCheckpoint};

fn write_config(directory: &Path, name: &str, config: &AppConfig) -> PathBuf {
    let path = directory.join(name);
    let encoded = toml::to_string_pretty(config)
        .unwrap_or_else(|error| panic!("failed to serialize fixture config: {error}"));
    std::fs::write(&path, encoded)
        .unwrap_or_else(|error| panic!("failed to write fixture config: {error}"));
    path
}

fn run_cli(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scorchkit"))
        .args(arguments)
        .env("NO_COLOR", "1")
        .current_dir(directory)
        .output()
        .unwrap_or_else(|error| panic!("failed to run ScorchKit CLI fixture: {error}"))
}

fn write_report(directory: &Path) -> PathBuf {
    write_named_report(
        directory,
        "scan-result.json",
        "cli-analysis-contract",
        "CLI analysis contract finding",
    )
}

fn write_named_report(
    directory: &Path,
    filename: &str,
    scan_id: &str,
    finding_title: &str,
) -> PathBuf {
    write_report_with_findings(
        directory,
        filename,
        scan_id,
        &[(finding_title, "http://127.0.0.1:4567")],
    )
}

fn write_report_with_findings(
    directory: &Path,
    filename: &str,
    scan_id: &str,
    findings: &[(&str, &str)],
) -> PathBuf {
    let result = ScanResult::new(
        scan_id.to_string(),
        Target::parse("http://127.0.0.1:4567")
            .unwrap_or_else(|error| panic!("failed to parse loopback target: {error}")),
        chrono::Utc::now(),
        findings
            .iter()
            .map(|(title, affected_target)| {
                Finding::new("fixture", Severity::Low, *title, "local fixture", *affected_target)
            })
            .collect(),
        vec!["fixture".to_string()],
        Vec::new(),
    );
    let path = directory.join(filename);
    let encoded = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|error| panic!("failed to serialize scan report: {error}"));
    std::fs::write(&path, encoded)
        .unwrap_or_else(|error| panic!("failed to write scan report: {error}"));
    path
}

#[test]
fn init_command_writes_a_parseable_default_configuration() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let output = Command::new(env!("CARGO_BIN_EXE_scorchkit"))
        .arg("init")
        .current_dir(directory.path())
        .output()
        .expect("run scorchkit init");

    assert!(output.status.success(), "init failed: {}", String::from_utf8_lossy(&output.stderr));
    let path = directory.path().join("config.toml");
    let content = std::fs::read_to_string(&path).expect("init must write config.toml");
    let _: AppConfig = toml::from_str(&content).expect("generated config must parse");
}

#[test]
fn targeted_init_pins_loopback_without_contacting_an_application_server() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let output = Command::new(env!("CARGO_BIN_EXE_scorchkit"))
        .args(["init", "http://127.0.0.1:4567"])
        .current_dir(directory.path())
        .output()
        .expect("run targeted scorchkit init");

    assert!(
        output.status.success(),
        "targeted init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let content = std::fs::read_to_string(directory.path().join("scorchkit.toml"))
        .expect("targeted init must write scorchkit.toml");
    let config: AppConfig = toml::from_str(&content).expect("generated config must parse");
    let engagement = config.engagement.expect("targeted init must create an engagement");

    assert_eq!(config.scan.profile, "quick");
    assert!(engagement.policy.effects.contains(&scorchkit::engine::policy::EffectClass::Passive));
    assert!(engagement
        .policy
        .effects
        .contains(&scorchkit::engine::policy::EffectClass::ActiveSafe));
    assert!(!engagement
        .policy
        .effects
        .contains(&scorchkit::engine::policy::EffectClass::Intrusive));
    assert!(engagement.policy.allowed_scope.iter().any(|rule| rule.matches("127.0.0.1")));
}

#[test]
fn terminal_scan_contract_renders_the_structured_result() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let config_path = directory.path().join("scorchkit.toml");
    let mut config = AppConfig::default();
    config.scan.profile = "quick".to_string();
    config.engagement = Some(Engagement::new(
        "CLI terminal fixture",
        EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").expect("loopback scope"))
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::Passive)
            .allow_effect(EffectClass::ActiveSafe),
    ));
    std::fs::write(
        &config_path,
        toml::to_string_pretty(&config).expect("serialize fixture config"),
    )
    .expect("write fixture config");

    let output = Command::new(env!("CARGO_BIN_EXE_scorchkit"))
        .args([
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "run",
            "http://127.0.0.1:4567",
            "--modules",
            "ssl",
            "--profile",
            "quick",
        ])
        .env("NO_COLOR", "1")
        .current_dir(directory.path())
        .output()
        .expect("run terminal scan fixture");

    assert!(
        output.status.success(),
        "terminal scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("terminal output must be UTF-8");
    assert!(stdout.contains("SCAN RESULTS"), "missing report heading: {stdout}");
    assert!(stdout.contains("No TLS/SSL Encryption"), "missing finding: {stdout}");
    assert!(
        !stdout.contains("1 target scanned"),
        "single successful target must not render the multi-target summary: {stdout}"
    );
}

#[test]
fn multi_target_dispatch_reports_each_failure_and_summary() {
    let directory = tempfile::tempdir().expect("create multi-target fixture directory");
    let config_path = write_config(directory.path(), "scorchkit.toml", &AppConfig::default());
    let targets_path = directory.path().join("targets.txt");
    std::fs::write(&targets_path, "http://\nhttps://\n").expect("write target list");

    let output = run_cli(
        directory.path(),
        &[
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "run",
            "--targets-file",
            targets_path.to_str().expect("UTF-8 targets path"),
            "--profile",
            "quick",
        ],
    );
    assert!(
        output.status.success(),
        "multi-target dispatcher must continue after per-target failures: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("terminal output must be UTF-8");
    for expected in [
        "Scanning target 1/2: http://",
        "Scanning target 2/2: https://",
        "Target http:// failed",
        "Target https:// failed",
        "2 targets scanned, 2 failed",
    ] {
        assert!(stdout.contains(expected), "missing '{expected}' in output: {stdout}");
    }
}

#[test]
fn single_target_dispatch_omits_multi_target_wrapping() {
    let directory = tempfile::tempdir().expect("create single-target fixture directory");
    let config_path = write_config(directory.path(), "scorchkit.toml", &AppConfig::default());

    let output = run_cli(
        directory.path(),
        &[
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "run",
            "http://",
            "--profile",
            "quick",
        ],
    );
    assert!(!output.status.success(), "an invalid single target must fail");
    let stdout = String::from_utf8(output.stdout).expect("terminal output must be UTF-8");
    assert!(
        !stdout.contains("Scanning target 1/1"),
        "single target must not render the multi-target banner: {stdout}"
    );
    assert!(
        !stdout.contains("1 target scanned"),
        "single target must not render the multi-target summary: {stdout}"
    );
}

#[test]
fn resume_dispatch_loads_checkpoint_then_denies_without_engagement() {
    let directory = tempfile::tempdir().expect("create resume fixture directory");
    let config_path = write_config(directory.path(), "scorchkit.toml", &AppConfig::default());
    let checkpoint_path = directory.path().join("checkpoint.json");
    let checkpoint =
        ScanCheckpoint::new("cli-resume-contract", "http://127.0.0.1:4567", "quick", 0);
    save_checkpoint(&checkpoint, &checkpoint_path).expect("write checkpoint fixture");

    let output = run_cli(
        directory.path(),
        &[
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "run",
            "--resume",
            checkpoint_path.to_str().expect("UTF-8 checkpoint path"),
        ],
    );
    assert!(!output.status.success(), "resume without an engagement must fail closed");
    let stdout = String::from_utf8(output.stdout).expect("terminal output must be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("terminal error must be UTF-8");
    assert!(
        stdout.contains("Resuming scan cli-resume-contract for http://127.0.0.1:4567"),
        "missing resume acknowledgement: {stdout}"
    );
    assert!(stderr.contains("no engagement authorization"), "unexpected resume denial: {stderr}");
}

#[test]
fn analyze_dispatch_reports_disabled_unavailable_and_unauthorized_states() {
    let directory = tempfile::tempdir().expect("create analysis fixture directory");
    let report_path = write_report(directory.path());

    let mut disabled = AppConfig::default();
    disabled.ai.enabled = false;
    let disabled_path = write_config(directory.path(), "disabled.toml", &disabled);
    let disabled_output = run_cli(
        directory.path(),
        &[
            "--config",
            disabled_path.to_str().expect("UTF-8 config path"),
            "analyze",
            report_path.to_str().expect("UTF-8 report path"),
        ],
    );

    let mut unavailable = AppConfig::default();
    unavailable.ai.binary = Some(directory.path().join("missing-provider").display().to_string());
    let unavailable_path = write_config(directory.path(), "unavailable.toml", &unavailable);
    let unavailable_output = run_cli(
        directory.path(),
        &[
            "--config",
            unavailable_path.to_str().expect("UTF-8 config path"),
            "analyze",
            report_path.to_str().expect("UTF-8 report path"),
        ],
    );

    let mut unauthorized = AppConfig::default();
    unauthorized.ai.binary = Some("/bin/sh".to_string());
    let unauthorized_path = write_config(directory.path(), "unauthorized.toml", &unauthorized);
    let unauthorized_output = run_cli(
        directory.path(),
        &[
            "--config",
            unauthorized_path.to_str().expect("UTF-8 config path"),
            "analyze",
            report_path.to_str().expect("UTF-8 report path"),
        ],
    );

    let mut provider_failure = unauthorized;
    provider_failure.engagement = Some(Engagement::new(
        "CLI AI failure fixture",
        EngagementPolicy::default()
            .allow_scope(ScopeRule::parse("127.0.0.1").expect("loopback scope"))
            .allow_capability(Capability::ExternalTool)
            .allow_effect(EffectClass::Passive),
    ));
    let provider_failure_path =
        write_config(directory.path(), "provider-failure.toml", &provider_failure);
    let provider_failure_output = run_cli(
        directory.path(),
        &[
            "--config",
            provider_failure_path.to_str().expect("UTF-8 config path"),
            "analyze",
            report_path.to_str().expect("UTF-8 report path"),
        ],
    );

    assert!(disabled_output.status.success(), "disabled AI is a reported no-op");
    assert!(
        String::from_utf8_lossy(&disabled_output.stdout)
            .contains("AI analysis is disabled in config"),
        "missing disabled-AI message"
    );
    assert!(unavailable_output.status.success(), "unavailable AI is a reported no-op");
    assert!(
        String::from_utf8_lossy(&unavailable_output.stdout).contains("not found"),
        "missing unavailable-provider message"
    );
    assert!(!unauthorized_output.status.success(), "available AI must still require policy");
    assert!(
        String::from_utf8_lossy(&unauthorized_output.stderr)
            .contains("no engagement authorization"),
        "missing AI policy denial"
    );
    assert!(
        provider_failure_output.status.success(),
        "provider failure is reported without changing scan success"
    );
    assert!(
        String::from_utf8_lossy(&provider_failure_output.stdout)
            .contains("Running Executive Summary analysis with Codex CLI"),
        "missing provider-run message"
    );
    assert!(
        String::from_utf8_lossy(&provider_failure_output.stdout).contains("AI analysis failed"),
        "missing provider-failure message"
    );
}

#[test]
fn diff_dispatch_renders_both_reports_and_their_finding_changes() {
    let directory = tempfile::tempdir().expect("create diff fixture directory");
    let baseline_path = write_named_report(
        directory.path(),
        "baseline.json",
        "cli-diff-baseline",
        "Resolved contract finding",
    );
    let current_path = write_named_report(
        directory.path(),
        "current.json",
        "cli-diff-current",
        "New contract finding",
    );

    let output = run_cli(
        directory.path(),
        &[
            "diff",
            baseline_path.to_str().expect("UTF-8 baseline path"),
            current_path.to_str().expect("UTF-8 current path"),
        ],
    );
    assert!(
        output.status.success(),
        "diff CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("diff output must be UTF-8");
    for expected in [
        "SCAN COMPARISON",
        "cli-diff-baseline",
        "cli-diff-current",
        "1 new finding",
        "1 resolved finding",
    ] {
        assert!(stdout.contains(expected), "missing '{expected}' in output: {stdout}");
    }
    assert!(
        !stdout.contains("unchanged finding"),
        "fully replaced findings must not render an unchanged count: {stdout}"
    );

    let baseline_path = write_report_with_findings(
        directory.path(),
        "complex-baseline.json",
        "cli-diff-complex-baseline",
        &[
            ("Shared A", "http://127.0.0.1/a"),
            ("Shared B", "http://127.0.0.1/b"),
            ("Shared C", "http://127.0.0.1/c"),
            ("Resolved", "http://127.0.0.1/resolved"),
            ("Retargeted", "http://127.0.0.1/old"),
        ],
    );
    let current_path = write_report_with_findings(
        directory.path(),
        "complex-current.json",
        "cli-diff-complex-current",
        &[
            ("Shared A", "http://127.0.0.1/a"),
            ("Shared B", "http://127.0.0.1/b"),
            ("Shared C", "http://127.0.0.1/c"),
            ("New", "http://127.0.0.1/new"),
            ("Retargeted", "http://127.0.0.1/new-target"),
        ],
    );
    let output = run_cli(
        directory.path(),
        &[
            "diff",
            baseline_path.to_str().expect("UTF-8 complex baseline path"),
            current_path.to_str().expect("UTF-8 complex current path"),
        ],
    );
    assert!(
        output.status.success(),
        "complex diff CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("complex diff output must be UTF-8");
    for expected in [
        "5 findings → 5 findings",
        "Trend: unchanged",
        "2 new findings",
        "2 resolved findings",
        "3 unchanged findings",
    ] {
        assert!(stdout.contains(expected), "missing '{expected}' in output: {stdout}");
    }
}

#[test]
fn code_dispatch_renders_language_manifests_and_terminal_report() {
    let directory = tempfile::tempdir().expect("create code fixture directory");
    let code_path = directory.path().join("code");
    std::fs::create_dir(&code_path).expect("create source fixture");
    std::fs::write(
        code_path.join("Cargo.toml"),
        "[package]\nname = \"cli-code-contract\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo manifest fixture");

    let cache_root = directory.path().join("supply-chain-cache");
    std::fs::create_dir(&cache_root).expect("create supply-chain cache fixture");
    #[cfg(unix)]
    std::fs::set_permissions(&cache_root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("private supply-chain cache fixture");

    let mut config = AppConfig::default();
    config.supply_chain.cache_root = cache_root.clone();
    config.tools.osv_scanner = Some("/fixture/missing-osv-scanner".to_string());
    config.engagement = Some(Engagement::new(
        "CLI code fixture",
        EngagementPolicy::default()
            .allow_scope(ScopeRule::path_prefix(&code_path).expect("canonical code scope"))
            .allow_scope(ScopeRule::path_prefix(&cache_root).expect("canonical cache scope"))
            .allow_capability(Capability::CodeScan)
            .allow_capability(Capability::ExternalTool)
            .allow_capability(Capability::LocalState)
            .allow_effect(EffectClass::Passive),
    ));
    let config_path = write_config(directory.path(), "code.toml", &config);

    let output = run_cli(
        directory.path(),
        &[
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "--output",
            "terminal",
            "code",
            code_path.to_str().expect("UTF-8 code path"),
            "--language",
            "rust",
            "--modules",
            "dep-audit",
            "--profile",
            "quick",
        ],
    );
    assert!(
        output.status.success(),
        "code CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("terminal output must be UTF-8");
    for expected in [
        "Code Analysis (SAST)",
        "Language: rust",
        "Manifests: Cargo.toml",
        "Profile: quick",
        "Running 1 code analysis module",
        "SCAN RESULTS",
    ] {
        assert!(stdout.contains(expected), "missing '{expected}' in output: {stdout}");
    }
    assert!(
        !stdout.contains("No code analysis modules available"),
        "a runnable module must not render the empty-state message: {stdout}"
    );
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn project_and_schedule_dispatchers_observe_database_state() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = scorchkit::storage::connect(&database_url).await.expect("database connection");
    scorchkit::storage::migrate::run_migrations(&pool).await.expect("database migrations");
    let suffix = uuid::Uuid::new_v4();
    let project_name = format!("cli-project-contract-{suffix}");
    let description = format!("cli-description-contract-{suffix}");
    let missing_project = format!("cli-missing-schedule-contract-{suffix}");
    let project = scorchkit::storage::projects::create_project(&pool, &project_name, &description)
        .await
        .expect("create project fixture");

    let mut config = AppConfig::default();
    config.database.url = Some(database_url);
    let directory = tempfile::tempdir().expect("create database CLI fixture directory");
    let config_path = write_config(directory.path(), "database.toml", &config);
    let project_output = run_cli(
        directory.path(),
        &[
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "project",
            "show",
            &project_name,
        ],
    );
    let schedule_output = run_cli(
        directory.path(),
        &[
            "--config",
            config_path.to_str().expect("UTF-8 config path"),
            "schedule",
            "list",
            &missing_project,
        ],
    );

    scorchkit::storage::projects::delete_project(&pool, project.id)
        .await
        .expect("clean project fixture");

    assert!(
        project_output.status.success(),
        "project show failed: {}",
        String::from_utf8_lossy(&project_output.stderr)
    );
    let project_stdout = String::from_utf8(project_output.stdout).expect("project output UTF-8");
    assert!(project_stdout.contains(&project_name), "missing project name: {project_stdout}");
    assert!(project_stdout.contains(&description), "missing project description: {project_stdout}");
    assert!(!schedule_output.status.success(), "missing schedule project must fail");
    assert!(
        String::from_utf8_lossy(&schedule_output.stderr).contains("not found"),
        "unexpected schedule error: {}",
        String::from_utf8_lossy(&schedule_output.stderr)
    );
}
