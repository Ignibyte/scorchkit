//! Executable contracts for the workspace dependency direction and compatibility facade.

use std::collections::BTreeSet;
use std::path::Path;

const PACKAGES: &[(&str, &[&str])] = &[
    ("scorchkit-agent", &[]),
    ("scorchkit-cli", &[]),
    ("scorchkit-cloud", &["scorchkit-core"]),
    ("scorchkit-code", &["scorchkit-core"]),
    ("scorchkit-config", &["scorchkit-core", "scorchkit-policy"]),
    ("scorchkit-control", &[]),
    ("scorchkit-core", &["scorchkit-policy"]),
    ("scorchkit-executor", &["scorchkit-config", "scorchkit-core", "scorchkit-policy"]),
    ("scorchkit-extension", &["scorchkit-core", "scorchkit-policy"]),
    ("scorchkit-infra", &["scorchkit-core"]),
    ("scorchkit-mcp", &[]),
    ("scorchkit-policy", &[]),
    ("scorchkit-storage", &[]),
    ("scorchkit-tools", &["scorchkit-core"]),
    ("scorchkit-web", &["scorchkit-core"]),
];

fn manifest(path: &Path) -> toml::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn workspace_dependencies(manifest: &toml::Value) -> BTreeSet<String> {
    manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(toml::map::Map::keys)
        .filter(|name| name.starts_with("scorchkit"))
        .cloned()
        .collect()
}

#[test]
fn lower_packages_follow_the_exact_dependency_allow_list() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root_manifest = manifest(&root.join("Cargo.toml"));
    let root_version = root_manifest["package"]["version"].as_str().expect("root package version");
    let exact_root_version = format!("={root_version}");
    let expected_packages: BTreeSet<_> = PACKAGES.iter().map(|(name, _)| *name).collect();
    let mut observed_packages = BTreeSet::new();

    for &(name, allowed) in PACKAGES {
        let path = root.join("crates").join(name).join("Cargo.toml");
        let parsed = manifest(&path);
        assert_eq!(
            parsed["package"]["name"].as_str(),
            Some(name),
            "directory and package identity drifted for {name}"
        );
        assert_eq!(
            parsed["package"]["version"].as_str(),
            Some(root_version),
            "{name} must stay versioned with the compatibility facade"
        );
        observed_packages.insert(name);

        let actual = workspace_dependencies(&parsed);
        let expected: BTreeSet<String> = allowed.iter().map(|value| (*value).to_string()).collect();
        assert_eq!(actual, expected, "forbidden or missing workspace edge for {name}");
        assert!(!actual.contains("scorchkit"), "{name} must not depend on root composition");
        for dependency in &actual {
            assert_eq!(
                parsed["dependencies"][dependency]["version"].as_str(),
                Some(exact_root_version.as_str()),
                "{name} must pin internal dependency {dependency} to the workspace version"
            );
        }
    }

    assert_eq!(observed_packages, expected_packages);
    let root_dependencies = workspace_dependencies(&root_manifest);
    for package in expected_packages {
        assert!(root_dependencies.contains(package), "root composition does not consume {package}");
        assert_eq!(
            root_manifest["dependencies"][package]["version"].as_str(),
            Some(exact_root_version.as_str()),
            "root dependency on {package} must pin the facade version exactly"
        );
    }
}

#[test]
fn compatibility_facade_reexports_the_package_owned_type_identities() {
    assert_eq!(
        std::any::TypeId::of::<scorchkit::Finding>(),
        std::any::TypeId::of::<scorchkit_core::Finding>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::engine::observation::FindingRecordV2>(),
        std::any::TypeId::of::<scorchkit_core::FindingRecordV2>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::Engagement>(),
        std::any::TypeId::of::<scorchkit_policy::Engagement>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::config::AppConfig>(),
        std::any::TypeId::of::<scorchkit_config::AppConfig>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::runner::job_executor::ExecutionBudget>(),
        std::any::TypeId::of::<scorchkit_executor::ExecutionBudget>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::runner::job::ScanJob>(),
        std::any::TypeId::of::<scorchkit_executor::job::ScanJob>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::extension::ExtensionManifestV1>(),
        std::any::TypeId::of::<scorchkit_extension::ExtensionManifestV1>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::runner::subprocess::ToolInvocation>(),
        std::any::TypeId::of::<scorchkit_tools::ToolInvocation>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::engine::module_trait::ModuleCategory>(),
        std::any::TypeId::of::<scorchkit_web::ModuleCategory>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::engine::code_module::CodeCategory>(),
        std::any::TypeId::of::<scorchkit_code::CodeCategory>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::cli::args::Cli>(),
        std::any::TypeId::of::<scorchkit_cli::Cli>()
    );
    assert_eq!(
        std::any::TypeId::of::<scorchkit::agent::config::AgentConfig>(),
        std::any::TypeId::of::<scorchkit_agent::config::AgentConfig>()
    );

    #[cfg(feature = "infra")]
    assert_eq!(
        std::any::TypeId::of::<scorchkit::engine::infra_module::InfraCategory>(),
        std::any::TypeId::of::<scorchkit_infra::InfraCategory>()
    );
    #[cfg(feature = "cloud")]
    assert_eq!(
        std::any::TypeId::of::<scorchkit::engine::cloud_module::CloudCategory>(),
        std::any::TypeId::of::<scorchkit_cloud::CloudCategory>()
    );
    #[cfg(feature = "storage")]
    assert_eq!(
        std::any::TypeId::of::<scorchkit::storage::models::VulnStatus>(),
        std::any::TypeId::of::<scorchkit_storage::VulnStatus>()
    );
    #[cfg(feature = "mcp")]
    assert_eq!(
        std::any::TypeId::of::<scorchkit::mcp::contract::McpToolEnvelope>(),
        std::any::TypeId::of::<scorchkit_mcp::contract::McpToolEnvelope>()
    );
}

#[test]
fn registries_expose_package_owned_descriptors() {
    let web = scorchkit::runner::orchestrator::all_modules();
    assert!(!web.is_empty());
    for module in web {
        let descriptor = module.descriptor();
        assert_eq!(descriptor.id, module.id());
        assert_eq!(descriptor.category, module.category());
        assert_eq!(descriptor.required_tool, module.required_tool());
    }

    let code = scorchkit::runner::code_orchestrator::all_code_modules();
    assert!(!code.is_empty());
    for module in code {
        let descriptor = module.descriptor();
        assert_eq!(descriptor.id, module.id());
        assert_eq!(descriptor.languages, module.languages());
    }

    #[cfg(feature = "infra")]
    for module in scorchkit::runner::infra_orchestrator::all_infra_modules() {
        let descriptor = module.descriptor();
        assert_eq!(descriptor.id, module.id());
        assert_eq!(descriptor.protocols, module.protocols());
    }

    #[cfg(feature = "cloud")]
    for module in scorchkit::runner::cloud_orchestrator::all_cloud_modules() {
        let descriptor = module.descriptor();
        assert_eq!(descriptor.id, module.id());
        assert_eq!(descriptor.providers, module.providers());
    }
}

#[test]
fn compatibility_facade_keeps_internal_construction_and_integration_helpers_private() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for context in ["scan_context.rs", "code_context.rs", "infra_context.rs", "cloud_context.rs"] {
        let source = std::fs::read_to_string(root.join("src/engine").join(context))
            .unwrap_or_else(|error| panic!("failed to read {context}: {error}"));
        assert!(
            source.contains("pub(crate) fn new("),
            "{context} widened its policy-sealed constructor"
        );
    }

    let subprocess = std::fs::read_to_string(root.join("src/runner/subprocess.rs"))
        .expect("read subprocess facade");
    assert!(!subprocess.contains("pub use scorchkit_tools::*"));
    assert!(subprocess.contains("pub(crate) use scorchkit_tools::"));

    let executor = std::fs::read_to_string(root.join("src/runner/job_executor.rs"))
        .expect("read executor facade");
    assert!(!executor.contains("pub use scorchkit_executor::*"));
    assert!(executor.contains("pub(crate) use scorchkit_executor::"));

    let policy = std::fs::read_to_string(root.join("crates/scorchkit-policy/src/policy.rs"))
        .expect("read package policy");
    assert!(policy.contains("pub(crate) fn grants_exactly("));

    let jobs = std::fs::read_to_string(root.join("crates/scorchkit-executor/src/job.rs"))
        .expect("read package jobs");
    for helper in [
        "pub(crate) fn normalize(",
        "pub(crate) fn transition(",
        "pub(crate) fn validate_create(",
        "pub(crate) fn validate_replacement(",
    ] {
        assert!(jobs.contains(helper), "job helper visibility widened: {helper}");
    }
}
