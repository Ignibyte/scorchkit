//! Regression tests for the repository-owned quality-gate contract.
//!
//! These tests intentionally inspect the policy and automation as data. A gate
//! edit that changes numbering, turns a real check into a skip, or disconnects
//! CI from the canonical helpers must fail in the ordinary Rust test suite.

use std::{fs, path::Path};

const WEB_ONLY_GATES: [u8; 3] = [17, 18, 19];

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    fs::read_to_string(repository_root().join(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

#[test]
fn constitution_and_runner_keep_stable_gate_ids() {
    let constitution = read("CONSTITUTION.md");
    let runner = read("bin/gate.sh");

    for gate in 1_u8..=22 {
        let policy_prefix = format!("{gate}. ");
        let policy_count =
            constitution.lines().filter(|line| line.starts_with(&policy_prefix)).count();
        assert_eq!(policy_count, 1, "gate:{gate} must occur once in the Constitution");

        let executable = format!("run_gate \"gate:{gate} ");
        let skipped = format!("skip_gate \"gate:{gate} ");
        if WEB_ONLY_GATES.contains(&gate) {
            assert!(!runner.contains(&executable), "web-only gate:{gate} must not execute");
            assert!(runner.contains(&skipped), "web-only gate:{gate} needs a named skip");
        } else {
            assert!(runner.contains(&executable), "gate:{gate} is not executable");
        }
    }
}

#[test]
fn local_and_ci_gates_share_the_canonical_helpers() {
    let runner = read("bin/gate.sh");
    let ci = read(".github/workflows/ci.yml");
    let nextest = read(".config/nextest.toml");
    let mutants = read(".cargo/mutants.toml");
    let mutation_runner = read("bin/mutants.sh");
    let manifest = read("Cargo.toml");

    assert!(runner.contains("bash bin/feature-states.sh"));
    assert!(runner.contains("cargo clippy --workspace --all-targets"));
    assert!(runner.contains("cargo test --workspace --all-features"));
    assert!(runner.contains("cargo doc --workspace --all-features"));
    assert!(runner.contains("cargo llvm-cov --workspace --all-features"));
    assert!(runner.contains("cargo nextest run --workspace --all-features"));
    assert!(runner.contains("COVERAGE_FLOOR=62"));
    assert!(runner.contains("bash bin/mutants.sh --diff"));
    assert!(runner.contains("scorchkit_write_gate_receipt"));
    assert!(read("bin/gate-state.sh").contains("sealed_green_diff | sealed_green_scope"));
    assert!(read("bin/sealed-mutation-baseline.sh")
        .contains("sealed mutation function scope does not match raw inventory"));
    assert!(runner.contains("STATIC_FAILURES=\"$FAIL\""));
    assert!(runner.contains("\"static prerequisite failed\""));
    assert!(runner.contains("\"coverage prerequisite failed\""));
    assert!(runner.contains("git ls-files --cached --others --exclude-standard -- '*.toml'"));
    assert!(mutation_runner.contains("FLOOR=\"${SCORCHKIT_MUTATION_MSI_MIN:-95}\""));
    assert!(mutation_runner.contains("RUN_COMPLETED=0"));
    assert!(mutation_runner.contains("SCORE=\"null\""));
    assert!(mutation_runner.contains("completed: ($completed == 1)"));
    assert!(
        mutation_runner.contains(concat!("SCORCHKIT_MUTATION_DATABASE_URL:-$", "{DATABASE_URL:-}"))
    );
    assert!(mutation_runner.contains("export DATABASE_URL=\"$MUTATION_DATABASE_URL\""));
    assert!(mutation_runner.contains("cargo mutants --workspace"));
    assert!(mutation_runner.contains("--test-workspace true"));
    assert!(mutation_runner.contains("crates/scorchkit-policy/src/policy.rs"));
    assert!(!mutation_runner.contains("unset CARGO_TARGET_DIR DATABASE_URL"));
    assert!(
        !mutants.contains("exclude_re"),
        "database-backed mutation must not exclude storage functions"
    );
    assert!(mutants.contains("src/windows_support.rs"));
    assert!(mutants.contains("crates/scorchkit-tools/src/windows_owned_process.rs"));

    let incomplete_exit = mutation_runner
        .find("if [ \"$RUN_COMPLETED\" -eq 0 ]; then\n    echo \"cargo-mutants failed")
        .expect("mutation runner must reject incomplete evidence");
    let score_output = mutation_runner
        .find("echo \"mutation score:")
        .expect("mutation runner must report completed scores");
    assert!(
        incomplete_exit < score_output,
        "an incomplete mutation run must exit before reporting a score"
    );

    assert!(ci.contains("bash bin/feature-states.sh"));
    assert!(ci.contains("bash bin/pipeline.sh check"));
    assert!(ci.contains("bash bin/gate.sh --fast"));
    assert!(ci.contains("bash bin/mutants.sh --shard"));
    assert!(ci.contains("POSTGRES_DB: scorchkit_mutation"));
    assert!(ci.contains("SCORCHKIT_MUTATION_DATABASE_URL:"));
    assert!(ci.contains("cargo nextest list --workspace --all-features --message-format json"));
    assert!(!ci.contains("psql \"$DATABASE_URL\""), "SQLx owns the migration ledger");

    assert!(manifest.contains("unsafe_code = \"forbid\""));
    assert!(nextest.contains("retries = 0"));
    assert!(nextest.contains("terminate-after = 4"));
    assert!(mutants.contains("timeout_multiplier = 3.0"));
}

#[test]
fn ci_executes_the_workspace_and_process_owner_suite_on_windows() {
    let ci = read(".github/workflows/ci.yml");
    let windows = ci
        .split("  windows:\n")
        .nth(1)
        .and_then(|tail| tail.split("\n  docs:\n").next())
        .expect("dedicated Windows CI job");

    assert!(windows.contains("runs-on: windows-latest"));
    assert!(
        windows.contains("cargo clippy --workspace --all-targets --all-features -- -D warnings")
    );
    assert!(windows.contains("cargo test --workspace --all-features"));
}
