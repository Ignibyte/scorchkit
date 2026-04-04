use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Discovers and analyzes exposed API schemas (OpenAPI/Swagger, GraphQL).
#[derive(Debug)]
pub struct ApiSchemaModule;

#[async_trait]
impl ScanModule for ApiSchemaModule {
    fn name(&self) -> &'static str {
        "API Schema Discovery"
    }
    fn id(&self) -> &'static str {
        "api-schema"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Discover exposed OpenAPI/Swagger specs and GraphQL schemas"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base = ctx.target.base_url();
        let mut findings = Vec::new();

        // Check OpenAPI/Swagger endpoints
        for path in SWAGGER_PATHS {
            let url = format!("{base}{path}");
            if let Ok(resp) = ctx.http_client.get(&url).send().await {
                if resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    if is_swagger_spec(&body) {
                        let endpoint_count = count_api_endpoints(&body);
                        findings.push(
                            Finding::new("api-schema", Severity::Low, format!("OpenAPI/Swagger Spec Exposed: {path}"), format!("An OpenAPI specification is publicly accessible with {endpoint_count} endpoints defined."), &url)
                                .with_evidence(format!("HTTP 200 at {url} | {endpoint_count} API endpoints"))
                                .with_remediation("Restrict access to API documentation in production")
                                .with_owasp("A05:2021 Security Misconfiguration")
                                .with_cwe(200)
                                .with_confidence(0.7),
                        );
                        break;
                    }
                }
            }
        }

        // Check GraphQL introspection
        let graphql_url = format!("{base}/graphql");
        let introspection_query = serde_json::json!({
            "query": "{ __schema { types { name } } }"
        });

        if let Ok(resp) = ctx.http_client.post(&graphql_url).json(&introspection_query).send().await
        {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("__schema") && body.contains("types") {
                    let type_count = body.matches("\"name\"").count();
                    findings.push(
                        Finding::new("api-schema", Severity::Medium, "GraphQL Introspection Enabled", format!("GraphQL introspection is enabled, exposing the entire API schema ({type_count} types)."), &graphql_url)
                            .with_evidence(format!("POST {graphql_url} with introspection query returned schema"))
                            .with_remediation("Disable GraphQL introspection in production: set introspection to false")
                            .with_owasp("A05:2021 Security Misconfiguration")
                            .with_cwe(200)
                            .with_confidence(0.7),
                    );
                }
            }
        }

        Ok(findings)
    }
}

fn is_swagger_spec(body: &str) -> bool {
    (body.contains("\"swagger\"") || body.contains("\"openapi\""))
        && (body.contains("\"paths\"") || body.contains("\"info\""))
}

fn count_api_endpoints(body: &str) -> usize {
    serde_json::from_str::<serde_json::Value>(body)
        .map_or(0, |json| json["paths"].as_object().map_or(0, serde_json::Map::len))
}

const SWAGGER_PATHS: &[&str] = &[
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/api.json",
    "/_api/docs",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the API schema discovery module's pure helper functions and constants.

    /// Verify that `is_swagger_spec` correctly identifies OpenAPI/Swagger JSON bodies
    /// and rejects non-spec content.
    #[test]
    fn test_is_swagger_spec() {
        // Arrange: valid Swagger 2.0 spec
        let swagger2 = r#"{"swagger": "2.0", "info": {"title": "API"}, "paths": {}}"#;
        assert!(is_swagger_spec(swagger2));

        // Arrange: valid OpenAPI 3.0 spec
        let openapi3 = r#"{"openapi": "3.0.1", "info": {"title": "API"}, "paths": {}}"#;
        assert!(is_swagger_spec(openapi3));

        // Arrange: not a spec at all
        let html_page = "<html><body>Hello World</body></html>";
        assert!(!is_swagger_spec(html_page));

        // Arrange: has "swagger" key but no "paths" or "info"
        let incomplete = r#"{"swagger": "2.0", "definitions": {}}"#;
        assert!(!is_swagger_spec(incomplete));
    }

    /// Verify that `count_api_endpoints` correctly counts paths in a valid OpenAPI spec
    /// and returns zero for invalid or empty input.
    #[test]
    fn test_count_api_endpoints() {
        // Arrange: spec with 3 endpoints
        let spec = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/users": {},
                "/users/{id}": {},
                "/health": {}
            }
        }"#;

        // Act & Assert
        assert_eq!(count_api_endpoints(spec), 3);

        // Arrange: empty paths
        let empty_paths = r#"{"openapi": "3.0.0", "paths": {}}"#;
        assert_eq!(count_api_endpoints(empty_paths), 0);

        // Arrange: invalid JSON
        assert_eq!(count_api_endpoints("not json"), 0);

        // Arrange: no paths key
        let no_paths = r#"{"openapi": "3.0.0", "info": {}}"#;
        assert_eq!(count_api_endpoints(no_paths), 0);
    }

    /// Verify that `SWAGGER_PATHS` is non-empty, all entries start with a slash,
    /// and common discovery paths are present.
    #[test]
    fn test_swagger_paths_integrity() {
        // Arrange & Assert: minimum count
        assert!(
            SWAGGER_PATHS.len() >= 5,
            "Expected at least 5 swagger paths, found {}",
            SWAGGER_PATHS.len()
        );

        // Well-known paths present
        assert!(SWAGGER_PATHS.contains(&"/swagger.json"));
        assert!(SWAGGER_PATHS.contains(&"/openapi.json"));

        // All entries well-formed
        for path in SWAGGER_PATHS {
            assert!(!path.is_empty(), "Swagger path should not be empty");
            assert!(path.starts_with('/'), "Swagger path '{path}' should start with '/'");
        }
    }
}
