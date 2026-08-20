//! Source-backed registry census used by public documentation and release notes.

use std::collections::BTreeSet;

use scorchkit::adapter_catalog::{KNOWN_CODE_ADAPTER_IDS, KNOWN_WEB_ADAPTER_IDS};
use scorchkit_core::{AdapterOutputContract, TemporaryArtifactPolicy, ADAPTER_CONTRACT_V1};

#[test]
fn dast_and_sast_registry_counts_are_stable() {
    assert_eq!(scorchkit::runner::orchestrator::all_modules().len(), 91);
    assert_eq!(scorchkit::runner::code_orchestrator::all_code_modules().len(), 24);
}

#[test]
fn every_registered_module_has_one_versioned_adapter_contract() {
    let web_modules = scorchkit::runner::orchestrator::all_modules();
    let web_ids: BTreeSet<&str> = web_modules.iter().map(|module| module.id()).collect();
    let known_web_ids: BTreeSet<&str> = KNOWN_WEB_ADAPTER_IDS.iter().copied().collect();
    assert_eq!(web_ids, known_web_ids);
    assert!(web_modules
        .iter()
        .all(|module| module.descriptor().adapter.schema_version == ADAPTER_CONTRACT_V1));

    let code_modules = scorchkit::runner::code_orchestrator::all_code_modules();
    let code_ids: BTreeSet<&str> = code_modules.iter().map(|module| module.id()).collect();
    let known_code_ids: BTreeSet<&str> = KNOWN_CODE_ADAPTER_IDS.iter().copied().collect();
    assert_eq!(code_ids, known_code_ids);
    assert!(code_modules
        .iter()
        .all(|module| module.descriptor().adapter.schema_version == ADAPTER_CONTRACT_V1));
}

#[test]
fn default_catalogs_exclude_compatibility_modules_without_removing_them() {
    let application_web = scorchkit::runner::orchestrator::application_modules();
    let compatibility_web = scorchkit::runner::orchestrator::compatibility_modules();
    assert_eq!(application_web.len(), 69);
    assert_eq!(compatibility_web.len(), 22);
    assert!(application_web
        .iter()
        .all(|module| module.descriptor().adapter.is_application_security()));
    assert!(compatibility_web
        .iter()
        .all(|module| !module.descriptor().adapter.is_application_security()));
    for compatibility_id in ["nmap", "hydra", "metasploit", "prowler"] {
        assert!(!application_web.iter().any(|module| module.id() == compatibility_id));
        assert!(compatibility_web.iter().any(|module| module.id() == compatibility_id));
    }

    let application_code = scorchkit::runner::code_orchestrator::application_code_modules();
    let compatibility_code = scorchkit::runner::code_orchestrator::compatibility_code_modules();
    assert_eq!(application_code.len(), 23);
    assert_eq!(compatibility_code.len(), 1);
    assert_eq!(compatibility_code[0].id(), "scoutsuite");
}

#[test]
fn representative_adapter_contracts_match_execution_shapes() {
    let modules = scorchkit::runner::orchestrator::all_modules();
    let contract = |id: &str| {
        modules
            .iter()
            .find(|module| module.id() == id)
            .unwrap_or_else(|| panic!("missing adapter {id}"))
            .descriptor()
            .adapter
    };

    assert_eq!(contract("amass").output_contract, AdapterOutputContract::JsonLines);
    assert_eq!(contract("dnsx").output_contract, AdapterOutputContract::Text);
    assert_eq!(contract("nmap").output_contract, AdapterOutputContract::Xml);
    assert_eq!(contract("metasploit").output_contract, AdapterOutputContract::Text);
    assert_eq!(contract("sqlmap").temporary_artifacts, TemporaryArtifactPolicy::ScopedOwned);
    assert_eq!(contract("interactsh").temporary_artifacts, TemporaryArtifactPolicy::None);

    let code_modules = scorchkit::runner::code_orchestrator::all_code_modules();
    let code_contract = |id: &str| {
        code_modules
            .iter()
            .find(|module| module.id() == id)
            .unwrap_or_else(|| panic!("missing code adapter {id}"))
            .descriptor()
    };
    for id in ["codeql", "psalm"] {
        assert_eq!(
            code_contract(id).depth,
            scorchkit::engine::code_module::CodeAnalysisDepth::Deep
        );
        assert_eq!(code_contract(id).adapter.output_contract, AdapterOutputContract::Sarif);
        assert_eq!(
            code_contract(id).adapter.temporary_artifacts,
            TemporaryArtifactPolicy::ScopedOwned
        );
    }
    assert_eq!(
        code_contract("semgrep").adapter.temporary_artifacts,
        TemporaryArtifactPolicy::ScopedOwned
    );
    assert_eq!(
        code_contract("semgrep").depth,
        scorchkit::engine::code_module::CodeAnalysisDepth::Fast
    );
    assert_eq!(
        code_contract("phpstan").category,
        scorchkit::engine::code_module::CodeCategory::Correctness
    );
}

#[cfg(feature = "infra")]
#[test]
fn infrastructure_registry_has_four_core_modules() {
    let modules = scorchkit::infra::register_modules();
    assert_eq!(modules.len(), 4);
    let nmap = modules.iter().find(|module| module.id() == "nmap").expect("infra nmap adapter");
    assert_eq!(nmap.descriptor().adapter.output_contract, AdapterOutputContract::Xml);
}

#[cfg(feature = "cloud")]
#[test]
fn cloud_registry_excludes_uncontrolled_provider_sdk_transports() {
    let modules = scorchkit::cloud::register_modules();
    assert_eq!(modules.len(), 5);
    assert!(modules.iter().all(|module| module.requires_external_tool()));
    assert!(!modules.iter().any(|module| {
        module.id().starts_with("aws-")
            || module.id().starts_with("gcp-")
            || module.id().starts_with("azure-")
    }));
    assert!(!modules.iter().any(|module| module.id() == "pacu-cloud"));
    for module in modules {
        let expected = if matches!(module.id(), "cloudsplaining-cloud" | "scoutsuite-cloud") {
            TemporaryArtifactPolicy::ScopedOwned
        } else {
            TemporaryArtifactPolicy::None
        };
        assert_eq!(module.descriptor().adapter.temporary_artifacts, expected, "{}", module.id());
    }
}
