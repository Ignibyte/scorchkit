use assert_cmd::Command;
use predicates::prelude::*;

#[cfg(feature = "storage")]
fn cli_job_engagement() -> scorchkit::engine::policy::Engagement {
    use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
    use scorchkit::engine::scope::ScopeRule;

    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Cidr {
            network: u32::from(std::net::Ipv4Addr::new(127, 0, 0, 0)),
            mask: u32::MAX << 24,
        })
        .allow_scope(ScopeRule::CidrV6 { network: 1, mask: u128::MAX })
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    Engagement::new("cli-job-contract", policy)
}

#[test]
fn test_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Web application security testing toolkit"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("recon"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("analyze"))
        .stdout(predicate::str::contains("modules"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("completions"))
        .stdout(predicate::str::contains("init"));
}

#[test]
fn test_version() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("scorchkit"));
}

#[test]
fn test_modules_list() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .arg("modules")
        .assert()
        .success()
        .stdout(predicate::str::contains("headers"))
        .stdout(predicate::str::contains("tech"))
        .stdout(predicate::str::contains("discovery"))
        .stdout(predicate::str::contains("ssl"))
        .stdout(predicate::str::contains("misconfig"))
        .stdout(predicate::str::contains("injection"))
        .stdout(predicate::str::contains("xss"))
        .stdout(predicate::str::contains("ssrf"))
        .stdout(predicate::str::contains("jwt"))
        .stdout(predicate::str::contains("nuclei"))
        .stdout(predicate::str::contains("nikto"))
        .stdout(predicate::str::contains("sqlmap"))
        .stdout(predicate::str::contains("feroxbuster"))
        .stdout(predicate::str::contains("sslyze"))
        // Phase 3+ modules
        .stdout(predicate::str::contains("crawler"))
        .stdout(predicate::str::contains("waf"))
        .stdout(predicate::str::contains("csrf"))
        .stdout(predicate::str::contains("cmdi"))
        .stdout(predicate::str::contains("idor"))
        .stdout(predicate::str::contains("xxe"))
        .stdout(predicate::str::contains("sensitive"))
        .stdout(predicate::str::contains("redirect"))
        .stdout(predicate::str::contains("api-schema"))
        .stdout(predicate::str::contains("ratelimit"))
        // External tool wrappers
        .stdout(predicate::str::contains("zap"))
        .stdout(predicate::str::contains("ffuf"))
        .stdout(predicate::str::contains("wafw00f"))
        .stdout(predicate::str::contains("testssl"))
        .stdout(predicate::str::contains("wpscan"))
        .stdout(predicate::str::contains("dalfox"))
        .stdout(predicate::str::contains("httpx"))
        .stdout(predicate::str::contains("arjun"))
        .stdout(predicate::str::contains("droopescan"))
        .stdout(predicate::str::contains("nmap").not())
        .stdout(predicate::str::contains("hydra").not())
        .stdout(predicate::str::contains("metasploit").not());
}

#[test]
fn test_modules_compatibility_catalog_requires_explicit_flag() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["modules", "--include-compatibility"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nmap"))
        .stdout(predicate::str::contains("hydra"))
        .stdout(predicate::str::contains("metasploit"))
        .stdout(predicate::str::contains("prowler"));
}

#[test]
fn test_modules_check_tools() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["modules", "--check-tools"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[built-in]"));
}

#[test]
fn test_invalid_target() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["run", "not a valid target !!!"])
        .assert()
        .failure();
}

#[test]
fn test_analyze_missing_file() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["analyze", "/tmp/nonexistent-report.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("report file not found"));
}

#[test]
fn test_completions_bash() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scorchkit"));
}

#[test]
fn test_run_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--profile"))
        .stdout(predicate::str::contains("--analyze"))
        .stdout(predicate::str::contains("--modules"))
        .stdout(predicate::str::contains("--skip"));
}

#[test]
fn test_diff_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["diff", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("baseline"))
        .stdout(predicate::str::contains("current"));
}

#[test]
fn test_doctor() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("ScorchKit Doctor"))
        .stdout(predicate::str::contains("tools installed"));
}

#[test]
fn test_run_with_proxy_flag() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--proxy"))
        .stdout(predicate::str::contains("--scope"))
        .stdout(predicate::str::contains("--exclude"));
}

/// Verify the `--project` flag is always visible in `run --help`,
/// regardless of whether the `storage` feature is compiled.
#[test]
fn test_run_project_flag_in_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--project"))
        .stdout(predicate::str::contains("--database-url"));
}

/// Verify the `--plan` flag is visible in `run --help`.
#[test]
fn test_cli_plan_flag_in_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--plan"));
}

/// Verify the `project status` subcommand is visible in help when the
/// `storage` feature is compiled.
#[cfg(feature = "storage")]
#[test]
fn test_cli_project_status_subcommand() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["project", "status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("posture"))
        .stdout(predicate::str::contains("project"));
}

/// Verify `schedule create --help` shows expected fields when
/// the `storage` feature is compiled.
#[cfg(feature = "storage")]
#[test]
fn test_cli_schedule_create_in_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["schedule", "create", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CRON"))
        .stdout(predicate::str::contains("TARGET"))
        .stdout(predicate::str::contains("PROJECT"));
}

/// Verify `schedule run-due --help` works when storage feature is compiled.
#[cfg(feature = "storage")]
#[test]
fn test_cli_schedule_run_due_in_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["schedule", "run-due", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("due"));
}

/// Verify the durable job lifecycle is exposed by the storage-enabled CLI.
#[cfg(feature = "storage")]
#[test]
fn test_cli_job_lifecycle_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["job", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("cancel"))
        .stdout(predicate::str::contains("recover"))
        .stdout(predicate::str::contains("resume"));
}

/// Job commands fail explicitly when `PostgreSQL` was not configured.
#[cfg(feature = "storage")]
#[test]
fn test_cli_job_status_requires_database() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["job", "status", "00000000-0000-0000-0000-000000000001"])
        .env_remove("DATABASE_URL")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no database URL configured"));
}

/// Run and read a real PostgreSQL-backed CLI job against an authorized loopback target.
#[cfg(feature = "storage")]
#[tokio::test]
async fn test_cli_job_run_and_status_lifecycle() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping CLI job integration test");
        return;
    };
    let target = httpmock::MockServer::start_async().await;
    let _mock = target
        .mock_async(|when, then| {
            when.any_request();
            then.status(200).header("content-type", "text/html").body("<html>ok</html>");
        })
        .await;
    let directory = tempfile::tempdir().expect("create CLI job config directory");
    let config_path = directory.path().join("scorchkit.toml");
    let mut config = scorchkit::config::AppConfig {
        engagement: Some(cli_job_engagement()),
        ..scorchkit::config::AppConfig::default()
    };
    config.scan.timeout_seconds = 5;
    config.database.url = Some(database_url.clone());
    config.database.migrate_on_startup = true;
    std::fs::write(&config_path, toml::to_string_pretty(&config).expect("serialize CLI config"))
        .expect("write CLI config");

    let run_config = config_path.clone();
    let run_target = target.url("/");
    let run_output = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("scorchkit")
            .expect("resolve scorchkit binary")
            .args([
                "--config",
                run_config.to_str().expect("UTF-8 config path"),
                "job",
                "run",
                &run_target,
                "--profile",
                "quick",
                "--modules",
                "headers",
            ])
            .output()
            .expect("run CLI job")
    })
    .await
    .expect("CLI job process joined");
    assert!(
        run_output.status.success(),
        "CLI job failed: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );
    let job: scorchkit::runner::job::ScanJob =
        serde_json::from_slice(&run_output.stdout).expect("decode CLI job output");
    assert_eq!(job.state, scorchkit::runner::job::ScanJobState::Succeeded);

    let status_config = config_path.clone();
    let job_id = job.id.to_string();
    let status_output = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("scorchkit")
            .expect("resolve scorchkit binary")
            .args([
                "--config",
                status_config.to_str().expect("UTF-8 config path"),
                "job",
                "status",
                &job_id,
            ])
            .output()
            .expect("read CLI job")
    })
    .await
    .expect("CLI status process joined");
    assert!(status_output.status.success());
    let stored: scorchkit::runner::job::ScanJob =
        serde_json::from_slice(&status_output.stdout).expect("decode CLI status output");
    assert_eq!(stored.id, job.id);
    assert_eq!(stored.state, scorchkit::runner::job::ScanJobState::Succeeded);

    let pool = scorchkit::storage::connect(&database_url).await.expect("connect cleanup pool");
    sqlx::query("DELETE FROM scan_jobs WHERE id = $1")
        .bind(job.id)
        .execute(&pool)
        .await
        .expect("delete CLI job fixture");
}

/// Verify `assess --help` works when the `infra` feature is compiled and
/// surfaces the expected `--url` / `--code` / `--infra` flags.
#[cfg(feature = "infra")]
#[test]
fn test_cli_assess_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["assess", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--url"))
        .stdout(predicate::str::contains("--code"))
        .stdout(predicate::str::contains("--infra"));
}

/// Verify `infra --help` works when the `infra` feature is compiled and
/// surfaces the expected `target` argument.
#[cfg(feature = "infra")]
#[test]
fn test_cli_infra_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["infra", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("target").or(predicate::str::contains("TARGET")));
}
