//! Local-only `CycloneDX` 1.6 validation and package identity normalization.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::str::FromStr;

use jsonschema::{Retrieve, Uri};
use packageurl::PackageUrl;
use serde_json::Value;

use crate::engine::error::{Result, ScorchError};

const BOM_SCHEMA: &str = include_str!("schemas/bom-1.6.schema.json");
const SPDX_SCHEMA: &str = include_str!("schemas/spdx.schema.json");
const JSF_SCHEMA: &str = include_str!("schemas/jsf-0.82.schema.json");
const SPDX_SCHEMA_ID: &str = "http://cyclonedx.org/schema/spdx.schema.json";
const JSF_SCHEMA_ID: &str = "http://cyclonedx.org/schema/jsf-0.82.schema.json";

/// Exact validated document retained for downstream scanner handoff.
#[derive(Debug, Clone)]
pub struct ValidatedSbom {
    bytes: Vec<u8>,
    document: Value,
    sha256: String,
}

impl ValidatedSbom {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn document(&self) -> &Value {
        &self.document
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug)]
struct EmbeddedCycloneDxRetriever {
    schemas: HashMap<&'static str, Value>,
}

impl EmbeddedCycloneDxRetriever {
    fn new() -> std::result::Result<Self, serde_json::Error> {
        Ok(Self {
            schemas: HashMap::from([
                (SPDX_SCHEMA_ID, serde_json::from_str(SPDX_SCHEMA)?),
                (JSF_SCHEMA_ID, serde_json::from_str(JSF_SCHEMA)?),
            ]),
        })
    }
}

impl Retrieve for EmbeddedCycloneDxRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("external CycloneDX schema retrieval denied: {uri}").into())
    }
}

/// Parse, fully schema-validate, reference-check, and hash a bounded `CycloneDX` 1.6 document.
///
/// # Errors
///
/// Returns a typed tool-output error for empty, oversized, malformed, schema-invalid, or
/// internally inconsistent documents. No schema can be resolved from the network or filesystem.
pub fn validate_cyclonedx_1_6(bytes: &[u8], maximum_bytes: usize) -> Result<ValidatedSbom> {
    if bytes.is_empty() {
        return Err(sbom_error("empty CycloneDX output"));
    }
    if bytes.len() > maximum_bytes {
        return Err(ScorchError::ToolOutputLimit {
            tool: "syft".to_string(),
            stream: "artifact",
            limit_bytes: maximum_bytes,
        });
    }

    let document: Value = serde_json::from_slice(bytes)
        .map_err(|error| sbom_error(format!("invalid JSON: {error}")))?;
    if document.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        return Err(sbom_error("bomFormat must be CycloneDX"));
    }
    if document.get("specVersion").and_then(Value::as_str) != Some("1.6") {
        return Err(sbom_error("specVersion must be exactly 1.6"));
    }

    let schema: Value = serde_json::from_str(BOM_SCHEMA)
        .map_err(|error| sbom_error(format!("embedded BOM schema is invalid: {error}")))?;
    let retriever = EmbeddedCycloneDxRetriever::new()
        .map_err(|error| sbom_error(format!("embedded reference schema is invalid: {error}")))?;
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(retriever)
        .build(&schema)
        .map_err(|error| sbom_error(format!("embedded BOM schema did not compile: {error}")))?;
    if let Some(error) = validator.iter_errors(&document).next() {
        return Err(sbom_error(format!("CycloneDX 1.6 schema violation: {error}")));
    }

    validate_dependency_references(&document)?;
    Ok(ValidatedSbom { bytes: bytes.to_vec(), document, sha256: scorchkit_core::sha256_hex(bytes) })
}

/// Parse and serialize a supplied PURL into specification-canonical form.
///
/// `ScorchKit` calls this only for an identifier supplied by an SBOM or scanner. It never constructs
/// a PURL from package-name heuristics.
pub fn normalize_supplied_purl(value: &str) -> std::result::Result<String, String> {
    PackageUrl::from_str(value)
        .map(|package_url| package_url.to_string())
        .map_err(|error| error.to_string())
}

fn validate_dependency_references(document: &Value) -> Result<()> {
    let mut known_references = BTreeSet::new();
    collect_bom_references(
        document.get("metadata").and_then(|value| value.get("component")),
        &mut known_references,
    );
    collect_array_references(document.get("components"), &mut known_references);
    collect_array_references(document.get("services"), &mut known_references);

    let Some(dependencies) = document.get("dependencies").and_then(Value::as_array) else {
        return Ok(());
    };
    for dependency in dependencies {
        let Some(reference) = dependency.get("ref").and_then(Value::as_str) else {
            continue;
        };
        require_known_reference(reference, &known_references)?;
        if let Some(depends_on) = dependency.get("dependsOn").and_then(Value::as_array) {
            for child in depends_on.iter().filter_map(Value::as_str) {
                require_known_reference(child, &known_references)?;
            }
        }
    }
    Ok(())
}

fn collect_array_references(value: Option<&Value>, references: &mut BTreeSet<String>) {
    if let Some(items) = value.and_then(Value::as_array) {
        for item in items {
            collect_bom_references(Some(item), references);
        }
    }
}

fn collect_bom_references(value: Option<&Value>, references: &mut BTreeSet<String>) {
    let Some(value) = value else {
        return;
    };
    if let Some(reference) = value.get("bom-ref").and_then(Value::as_str) {
        references.insert(reference.to_string());
    }
    collect_array_references(value.get("components"), references);
    collect_array_references(value.get("services"), references);
}

fn require_known_reference(reference: &str, known_references: &BTreeSet<String>) -> Result<()> {
    if known_references.contains(reference) {
        Ok(())
    } else {
        Err(sbom_error(format!("dependency references unknown bom-ref '{reference}'")))
    }
}

fn sbom_error(reason: impl Into<String>) -> ScorchError {
    ScorchError::ToolOutputParse { tool: "syft".to_string(), reason: reason.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
      "bomFormat": "CycloneDX",
      "specVersion": "1.6",
      "version": 1,
      "components": [{
        "type": "library",
        "bom-ref": "pkg:npm/lodash@4.17.20",
        "name": "lodash",
        "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20",
        "licenses": [{"expression": "MIT"}]
      }],
      "dependencies": [{"ref": "pkg:npm/lodash@4.17.20"}]
    }"#;

    #[test]
    fn validates_full_embedded_schema_and_hashes_exact_bytes() {
        let validated =
            validate_cyclonedx_1_6(VALID.as_bytes(), 1024 * 1024).expect("valid CycloneDX fixture");
        assert_eq!(validated.bytes(), VALID.as_bytes());
        assert_eq!(validated.document()["specVersion"], "1.6");
        assert_eq!(validated.sha256(), scorchkit_core::sha256_hex(VALID.as_bytes()));
    }

    #[test]
    fn rejects_wrong_version_and_unknown_dependency_reference() {
        let wrong_version = VALID.replace("\"1.6\"", "\"1.5\"");
        assert!(validate_cyclonedx_1_6(wrong_version.as_bytes(), 1024 * 1024).is_err());

        let unknown = VALID
            .replace("\"ref\": \"pkg:npm/lodash@4.17.20\"", "\"ref\": \"pkg:npm/other@1.0.0\"");
        assert!(validate_cyclonedx_1_6(unknown.as_bytes(), 1024 * 1024).is_err());
    }

    #[test]
    fn supplied_purl_is_canonicalized_and_invalid_identity_stays_invalid() {
        assert_eq!(
            normalize_supplied_purl("pkg:npm/%40angular/animation@12.3.1").expect("valid PURL"),
            "pkg:npm/%40angular/animation@12.3.1"
        );
        assert!(normalize_supplied_purl("not-a-purl").is_err());
    }

    #[test]
    fn cyclonedx_size_limit_accepts_exactly_the_document_length() {
        assert!(validate_cyclonedx_1_6(VALID.as_bytes(), VALID.len()).is_ok());
        assert!(validate_cyclonedx_1_6(VALID.as_bytes(), VALID.len() - 1).is_err());
    }
}
