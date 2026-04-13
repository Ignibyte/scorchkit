//! CLI integration tests for project model commands.
//!
//! These tests verify the clap argument structure is wired correctly
//! by checking help output. No database connection is needed.

#![cfg(feature = "storage")]

use assert_cmd::Command;
use predicates::prelude::*;

/// Verify `db migrate` subcommand exists and shows help text.
#[test]
fn test_db_migrate_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["db", "migrate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pending database migrations"));
}

/// Verify `project create` shows the `--description` flag.
#[test]
fn test_project_create_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["project", "create", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--description"))
        .stdout(predicate::str::contains("Project name"));
}

/// Verify `project list` subcommand exists.
#[test]
fn test_project_list_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["project", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List all projects"));
}

/// Verify `project target` shows add/remove/list subcommands.
#[test]
fn test_project_target_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["project", "target", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("add"))
        .stdout(predicate::str::contains("remove"))
        .stdout(predicate::str::contains("list"));
}

/// Verify `finding list` shows `--severity` and `--status` filter flags.
#[test]
fn test_finding_list_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["finding", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--severity"))
        .stdout(predicate::str::contains("--status"));
}

/// Verify `finding status` accepts id and status positional args.
#[test]
fn test_finding_status_help() {
    Command::cargo_bin("scorchkit")
        .unwrap()
        .args(["finding", "status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Finding UUID"))
        .stdout(predicate::str::contains("New status"));
}
