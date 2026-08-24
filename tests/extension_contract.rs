use scorchkit::extension::{
    extension_manifest_schema_v1, EXTENSION_ABI_V1, EXTENSION_MANIFEST_SCHEMA_V1,
    EXTENSION_PROTOCOL_V1,
};

fn canonical_manifest() -> serde_json::Value {
    serde_json::json!({
        "schema_version": EXTENSION_MANIFEST_SCHEMA_V1,
        "id": "fixture.extension",
        "name": "Fixture extension",
        "description": "Public schema fixture",
        "version": "1.0.0",
        "compatibility": {
            "minimum_engine_version": "3.0.0",
            "maximum_engine_version_exclusive": "4.0.0"
        },
        "module": {
            "runtime": "wasm32_unknown_unknown",
            "protocol_version": EXTENSION_PROTOCOL_V1,
            "abi_version": EXTENSION_ABI_V1,
            "file": "fixture.wasm",
            "sha256": "a".repeat(64)
        },
        "input_schema": "fixture.input/v1",
        "output_schema": "fixture.output/v1",
        "adapter": {
            "security_domain": "application_runtime",
            "lifecycle_stage": "runtime",
            "target_kinds": ["web_application"],
            "strongest_effect": "active-safe",
            "output_contract": "json",
            "provenance": "plugin_definition",
            "temporary_artifacts": "scoped_owned"
        },
        "capabilities": ["network_http"],
        "budgets": {
            "timeout_ms": 1000,
            "fuel": 1_000_000,
            "memory_bytes": 1_048_576,
            "input_bytes": 65536,
            "output_bytes": 65536,
            "effects": 4,
            "artifact_bytes": 65536,
            "artifacts": 4
        }
    })
}

#[test]
fn public_manifest_schema_accepts_only_the_versioned_isolated_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = extension_manifest_schema_v1();
    let validator =
        jsonschema::options().with_draft(jsonschema::Draft::Draft202012).build(&schema)?;
    let canonical = canonical_manifest();
    assert!(validator.is_valid(&canonical));

    let mut native = canonical.clone();
    native["module"]["runtime"] = serde_json::json!("native");
    assert!(!validator.is_valid(&native));

    let mut unknown = canonical;
    unknown["database_url"] = serde_json::json!("postgresql://forbidden");
    assert!(!validator.is_valid(&unknown));
    Ok(())
}

#[test]
fn provider_neutral_protocol_source_has_no_host_handle_vocabulary(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("crates/scorchkit-extension/src/protocol.rs"))?;
    let production =
        source.split_once("#[cfg(test)]").map_or(source.as_str(), |(production, _)| production);
    for forbidden in [
        "PgPool",
        "sqlx",
        "Engagement",
        "PolicyTarget",
        "canonical_path",
        "std::process",
        "std::fs",
    ] {
        assert!(
            !production.contains(forbidden),
            "protocol exposed forbidden host vocabulary {forbidden}"
        );
    }
    Ok(())
}
