//! Integration tests for the hook configuration system.

/// Verify `HookConfig` deserializes from TOML correctly.
#[test]
fn test_hook_config_deserialize() {
    let toml_str = r#"
        [hooks]
        pre_scan = ["./hooks/auth.sh"]
        post_module = ["./hooks/filter.py"]
        post_scan = ["./hooks/notify.sh", "./hooks/export.sh"]
        timeout_seconds = 60
        fail_open = false
    "#;

    let config: scorchkit::config::AppConfig = toml::from_str(toml_str).expect("parse");
    assert_eq!(config.hooks.pre_scan.len(), 1);
    assert_eq!(config.hooks.post_module.len(), 1);
    assert_eq!(config.hooks.post_scan.len(), 2);
    assert_eq!(config.hooks.timeout_seconds, 60);
    assert!(!config.hooks.fail_open);
}

#[test]
fn typed_processor_config_deserializes_and_validates_as_a_complete_contract() {
    let toml_str = r#"
        [hooks]
        timeout_seconds = 30
        fail_open = true

        [[hooks.processors]]
        schema = "scorchkit.run-processor/v1"
        id = "select.modules"
        path = "/opt/scorchkit/processors/select-modules"
        phase = "preprocessing"
        input_schema = "scorchkit.run-preprocess-input/v1"
        output_schema = "scorchkit.run-preprocess-proposal/v1"
        capabilities = ["dast-scan", "external-tool"]
        failure_mode = "required"
        order = 10

        [hooks.processors.budget]
        timeout_millis = 1000
        max_input_bytes = 4096
        max_output_bytes = 4096
    "#;

    let config: scorchkit::config::AppConfig = toml::from_str(toml_str).expect("parse");
    assert_eq!(config.hooks.processors.len(), 1);
    assert!(config.hooks.validate().is_ok());
    assert_eq!(config.hooks.processors[0].id, "select.modules");
}

/// Verify default `HookConfig` has no hooks and sensible defaults.
#[test]
fn test_hook_config_default() {
    let config = scorchkit::config::HookConfig::default();
    assert!(config.processors.is_empty());
    assert!(config.pre_scan.is_empty());
    assert!(config.post_module.is_empty());
    assert!(config.post_scan.is_empty());
    assert_eq!(config.timeout_seconds, 30);
    assert!(config.fail_open);
    assert!(config.is_empty());
}
