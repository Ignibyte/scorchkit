//! Source-backed registry census used by public documentation and release notes.

#[test]
fn dast_and_sast_registry_counts_are_stable() {
    assert_eq!(scorchkit::runner::orchestrator::all_modules().len(), 91);
    assert_eq!(scorchkit::runner::code_orchestrator::all_code_modules().len(), 22);
}

#[cfg(feature = "infra")]
#[test]
fn infrastructure_registry_has_four_core_modules() {
    assert_eq!(scorchkit::infra::register_modules().len(), 4);
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
}
