//! External-consumer compatibility checks for the stable control package.

use scorchkit_control::{description_v1, ControlQueryV1, ControlRequestV1};
use sha2::{Digest, Sha256};

#[test]
fn v1_description_matches_the_external_compatibility_fixture() {
    let description = description_v1().expect("generate public control description");
    let schemas = serde_json::to_vec(&description.schemas).expect("encode generated schemas");
    let actual = serde_json::json!({
        "schemaVersion": description.schema_version,
        "apiSchemaVersion": description.api_schema_version,
        "eventSchemaVersion": description.event_schema_version,
        "operations": description
            .operations
            .into_iter()
            .map(|operation| serde_json::json!([
                operation.name,
                operation.class,
                operation.behavior,
                operation.engagement_required,
            ]))
            .collect::<Vec<_>>(),
        "schemas": description
            .schemas
            .into_iter()
            .map(|schema| schema.name)
            .collect::<Vec<_>>(),
        "schemaSha256": format!("{:x}", Sha256::digest(schemas)),
    });
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/control/v1-description.json"))
            .expect("decode checked-in control fixture");
    assert_eq!(actual, expected);
}

#[test]
fn storage_cli_adapter_has_no_direct_canonical_storage_dependency() {
    let source = include_str!("../src/cli/control_adapter.rs");
    assert!(!source.contains("crate::storage"));
    assert!(!source.contains("sqlx::"));
    assert!(source.contains("ControlService"));
}

#[test]
fn external_package_consumer_can_round_trip_a_v1_request() {
    let request = ControlRequestV1::query(ControlQueryV1::Describe, None);
    let encoded = serde_json::to_vec(&request).expect("encode request");
    let decoded: ControlRequestV1 = serde_json::from_slice(&encoded).expect("decode request");
    assert_eq!(decoded, request);
    decoded.validate().expect("validate external request");
}
