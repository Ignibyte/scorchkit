//! Executable contracts for reproducible release qualification and publication.

use std::{fs, path::Path};

const CHECKOUT_SHA: &str = "de0fac2e4500dabe0009e67214ff5f5447ce83dd";
const UPLOAD_SHA: &str = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const DOWNLOAD_SHA: &str = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

#[test]
fn release_policy_is_exact_and_bounded() {
    let policy: serde_json::Value =
        serde_json::from_str(&read("release/policy.json")).expect("release policy JSON");
    assert_eq!(policy["schema"], "scorchkit.release-policy/v1");
    assert_eq!(policy["package"], "scorchkit");
    assert_eq!(policy["repository"], "Ignibyte/scorch_kit");
    assert_eq!(policy["toolchain"], "1.96.0");
    assert_eq!(policy["features"], serde_json::json!(["infra", "cloud", "mcp"]));
    assert_eq!(policy["budgets"]["binary_bytes"], 150 * 1024 * 1024);
    assert_eq!(policy["budgets"]["startup_seconds"], 2);
    assert_eq!(policy["budgets"]["termination_seconds"], 2);
    assert_eq!(policy["budgets"]["workflow_minutes"], 45);

    let targets = policy["targets"].as_array().expect("target array");
    assert_eq!(targets.len(), 4);
    let expected = [
        ("aarch64-apple-darwin", "macos-15", "scorchkit-aarch64-apple-darwin"),
        ("x86_64-apple-darwin", "macos-15-intel", "scorchkit-x86_64-apple-darwin"),
        ("x86_64-pc-windows-msvc", "windows-2025", "scorchkit-x86_64-pc-windows-msvc.exe"),
        ("x86_64-unknown-linux-gnu", "ubuntu-24.04", "scorchkit-x86_64-unknown-linux-gnu"),
    ];
    for (entry, (target, runner, asset)) in targets.iter().zip(expected) {
        assert_eq!(entry["target"], target);
        assert_eq!(entry["runner"], runner);
        assert_eq!(entry["asset"], asset);
    }

    assert_eq!(policy["tools"]["syft"]["version"], "1.50.0");
    assert_eq!(policy["tools"]["cosign"]["version"], "3.1.2");
    for tool in ["syft", "cosign", "sigstore_trusted_root"] {
        let digest = policy["tools"][tool]["sha256"].as_str().expect("tool digest");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert!(policy["tools"][tool]["url"].as_str().expect("tool URL").starts_with("https://"));
    }
}

#[test]
fn workspace_versions_and_rust_toolchain_are_release_locked() {
    let root_manifest: toml::Value = toml::from_str(&read("Cargo.toml")).expect("root manifest");
    let version = root_manifest["package"]["version"].as_str().expect("root package version");
    assert_eq!(version, "3.0.0");
    for entry in fs::read_dir(root().join("crates")).expect("workspace crates") {
        let path = entry.expect("crate directory").path().join("Cargo.toml");
        if !path.is_file() {
            continue;
        }
        let manifest_text = fs::read_to_string(&path).expect("workspace manifest text");
        let manifest: toml::Value = toml::from_str(&manifest_text).expect("workspace manifest");
        assert_eq!(
            manifest["package"]["version"].as_str(),
            Some(version),
            "workspace package version drifted: {}",
            path.display()
        );
    }

    let toolchain: toml::Value =
        toml::from_str(&read("rust-toolchain.toml")).expect("toolchain manifest");
    assert_eq!(toolchain["toolchain"]["channel"].as_str(), Some("1.96.0"));
    assert_eq!(toolchain["toolchain"]["profile"].as_str(), Some("minimal"));
    assert_eq!(
        toolchain["toolchain"]["components"].as_array().expect("toolchain components").len(),
        3
    );
    let ci = read(".github/workflows/ci.yml");
    assert!(!ci.contains("rust-toolchain@stable"));
    assert!(!ci.contains("toolchain: stable"));
}

#[test]
fn release_manifest_schema_is_closed_and_exact() {
    let schema: serde_json::Value =
        serde_json::from_str(&read("release/scorchkit-release-manifest.schema.json"))
            .expect("manifest schema JSON");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["schema"]["const"], "scorchkit.release-manifest/v1");
    assert_eq!(schema["properties"]["name"]["const"], "scorchkit");
    assert_eq!(schema["properties"]["artifacts"]["minItems"], 4);
    assert_eq!(schema["properties"]["artifacts"]["maxItems"], 4);
    assert_eq!(
        schema["properties"]["artifacts"]["items"]["properties"]["sbom"]["properties"]
            ["spec_version"]["const"],
        "1.6"
    );
    for object in [
        &schema["properties"]["source"],
        &schema["properties"]["build"],
        &schema["properties"]["artifacts"]["items"],
        &schema["properties"]["artifacts"]["items"]["properties"]["sbom"],
    ] {
        assert_eq!(object["additionalProperties"], false);
    }
}

#[test]
fn release_workflow_is_pinned_least_privilege_and_draft_first() {
    let workflow = read(".github/workflows/release.yml");
    for line in workflow.lines().filter(|line| line.trim_start().starts_with("uses:")) {
        let reference = line
            .split('@')
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .expect("action reference SHA");
        assert_eq!(reference.len(), 40, "action is not pinned by full SHA: {line}");
        assert!(reference.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert!(workflow.contains(&format!("actions/checkout@{CHECKOUT_SHA}")));
    assert!(workflow.contains(&format!("actions/upload-artifact@{UPLOAD_SHA}")));
    assert!(workflow.contains(&format!("actions/download-artifact@{DOWNLOAD_SHA}")));
    assert_eq!(count(&workflow, "contents: write"), 1);
    assert_eq!(count(&workflow, "id-token: write"), 1);
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert!(workflow.contains("persist-credentials: false"));
    assert!(workflow.contains("rustup toolchain install \"$toolchain\" --profile minimal"));
    assert!(workflow.contains("--target \"${{ matrix.target }}\""));
    assert!(workflow.contains("fail-fast: true"));
    assert!(!workflow.contains("continue-on-error"));
    assert!(!workflow.contains("retry"));

    let build = workflow.find("  build:\n").expect("build job");
    let aggregate = workflow.find("  aggregate:\n").expect("aggregate job");
    assert!(workflow[build..aggregate].contains("timeout-minutes: 45"));
    assert!(workflow[aggregate..].contains("timeout-minutes: 45"));
    for target in [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
    ] {
        assert_eq!(count(&workflow, &format!("target: {target}")), 1);
    }

    let create = workflow.find("gh release create").expect("draft release creation");
    let readback = workflow.find("gh release download").expect("release readback");
    let publish = workflow.find("--draft=false").expect("draft publication");
    assert!(create < readback && readback < publish);
    assert!(workflow[create..readback].contains("--draft"));
    assert!(workflow.contains("verify-signature-negatives"));
    assert!(read("bin/release.sh").contains("--trusted-root"));
    assert!(read("bin/release.sh").contains("sigstore-trusted-root.json"));
    assert!(workflow.contains("GITHUB_WORKFLOW_REF"));
    assert!(read("bin/release.sh").contains("--certificate-github-workflow-sha"));
}

#[test]
fn release_qualification_is_part_of_the_existing_static_gate() {
    let gate = read("bin/gate.sh");
    let script = read("bin/release.sh");
    assert!(gate.contains("bash bin/release.sh --selftest"));
    assert!(script.contains("cargo build --release --locked"));
    assert!(script.contains("cmp --silent \"$binary_a\" \"$binary_b\""));
    assert!(script.contains("validate_binary_target \"$stage/$asset\" \"$target\""));
    assert!(script.contains("expected x86-64 PE executable"));
    assert!(script.contains("expected x86-64 executable or PIE"));
    assert!(script.contains("unexpected Mach-O CPU or file type"));
    assert!(script.contains("--remap-path-prefix"));
    assert!(script.contains("-C strip=symbols"));
    assert!(script.contains("--certificate-identity"));
    assert!(script.contains("--certificate-oidc-issuer"));
    assert!(script.contains("--certificate-github-workflow-sha"));
    assert!(script.contains("--trusted-root"));
    assert!(script.contains("wrong signing identity was accepted"));
    assert!(script.contains("wrong signing revision was accepted"));
    assert!(script.contains("tampered signed subject was accepted"));
    assert!(!script.contains("cargo mutants"));
    assert!(!script.contains("gate.sh --full"));
}

#[test]
fn release_upgrade_fixture_is_exactly_the_v2_1_schema_boundary() {
    let schema = read("tests/fixtures/release/v2.1.0/schema.sql");
    for migration in [
        "migrations/001_initial.sql",
        "migrations/002_scan_schedules.sql",
        "migrations/003_add_confidence.sql",
        "migrations/004_add_status_note.sql",
    ] {
        let statements = read(migration);
        for statement in statements.lines().filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with("--")
        }) {
            assert!(schema.contains(statement), "legacy schema omitted: {statement}");
        }
    }
    assert!(!schema.contains("scan_jobs"));
    assert!(!schema.contains("finding_evidence"));
    assert!(!schema.contains("attack_paths"));
    assert!(!schema.contains("webhook_deliveries"));
    assert!(read("tests/fixtures/release/v2.1.0/failure.sql").contains("SELECT 1 / 0"));
    assert!(fs::read_dir(root().join("migrations")).expect("migrations").all(|entry| !entry
        .expect("migration entry")
        .file_name()
        .to_string_lossy()
        .contains("down")));
}
