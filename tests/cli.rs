use assert_cmd::Command;
use predicates::prelude::*;

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
        .stdout(predicate::str::contains("subdomain"))
        .stdout(predicate::str::contains("nmap"))
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
        .stdout(predicate::str::contains("metasploit"))
        .stdout(predicate::str::contains("wafw00f"))
        .stdout(predicate::str::contains("testssl"))
        .stdout(predicate::str::contains("wpscan"))
        .stdout(predicate::str::contains("amass"))
        .stdout(predicate::str::contains("subfinder"))
        .stdout(predicate::str::contains("dalfox"))
        .stdout(predicate::str::contains("hydra"))
        .stdout(predicate::str::contains("httpx"))
        .stdout(predicate::str::contains("theharvester"))
        .stdout(predicate::str::contains("arjun"))
        .stdout(predicate::str::contains("cewl"))
        .stdout(predicate::str::contains("droopescan"));
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
