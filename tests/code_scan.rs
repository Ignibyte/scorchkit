//! Integration tests for the `code` CLI subcommand.

use assert_cmd::Command;
use predicates::prelude::*;

/// Verify `code --help` shows expected flags.
#[test]
fn test_code_subcommand_help() {
    Command::cargo_bin("scorchkit")
        .expect("binary exists")
        .args(["code", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--language"))
        .stdout(predicate::str::contains("--profile"))
        .stdout(predicate::str::contains("--modules"));
}

/// Verify `code` without a path argument shows an error.
#[test]
fn test_code_subcommand_no_path() {
    Command::cargo_bin("scorchkit").expect("binary exists").arg("code").assert().failure();
}
