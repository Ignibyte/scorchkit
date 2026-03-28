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
                                .with_cwe(200),
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
                            .with_cwe(200),
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
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        json["paths"].as_object().map_or(0, |p| p.len())
    } else {
        0
    }
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
