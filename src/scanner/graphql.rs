//! GraphQL deep security testing module.
//!
//! Tests GraphQL endpoints for introspection exposure, query depth/complexity
//! abuse, batch query abuse, field suggestion information leaks, and mutation
//! enumeration. Complements [`super::api_schema`] (Recon — discovers schema
//! exposure) with active security testing (Scanner category).

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// GraphQL deep security testing via introspection, depth abuse, and batching.
///
/// Discovers GraphQL endpoints by probing common paths, then runs security
/// tests against confirmed endpoints. Complements the `api-schema` Recon
/// module which only discovers exposed schemas.
#[derive(Debug)]
pub struct GraphQLModule;

#[async_trait]
impl ScanModule for GraphQLModule {
    fn name(&self) -> &'static str {
        "GraphQL Security"
    }

    fn id(&self) -> &'static str {
        "graphql"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Test GraphQL for introspection, depth abuse, batching, and field suggestion leaks"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base = ctx.target.base_url();
        let mut findings = Vec::new();

        // Phase 1: Discover GraphQL endpoints
        let paths = generate_gql_paths();
        let mut endpoints: Vec<GqlEndpoint> = Vec::new();

        for path in &paths {
            let url = format!("{base}{path}");
            if probe_graphql(ctx, &url).await {
                endpoints.push(GqlEndpoint { url, path: path.to_string() });
            }
        }

        if endpoints.is_empty() {
            return Ok(findings);
        }

        // Phase 2: Test each discovered endpoint
        for endpoint in &endpoints {
            test_introspection(ctx, endpoint, &mut findings).await;
            test_depth_abuse(ctx, endpoint, &mut findings).await;
            test_batch_abuse(ctx, endpoint, &mut findings).await;
            test_field_suggestions(ctx, endpoint, &mut findings).await;
            test_mutation_enumeration(ctx, endpoint, &mut findings).await;
        }

        Ok(findings)
    }
}

/// A discovered GraphQL endpoint.
#[derive(Debug, Clone)]
struct GqlEndpoint {
    /// Full URL of the GraphQL endpoint.
    url: String,
    /// Path component (e.g., "/graphql").
    path: String,
}

/// Generate common GraphQL endpoint paths to probe.
#[must_use]
fn generate_gql_paths() -> Vec<&'static str> {
    vec![
        "/graphql",
        "/api/graphql",
        "/gql",
        "/query",
        "/v1/graphql",
        "/v2/graphql",
        "/graphql/v1",
        "/api/gql",
        "/graphql/console",
        "/playground",
    ]
}

/// Probe a URL to determine if it's a GraphQL endpoint.
///
/// Sends a `{ __typename }` query and checks for a valid GraphQL response.
async fn probe_graphql(ctx: &ScanContext, url: &str) -> bool {
    let body = json!({ "query": "{ __typename }" });

    let Ok(response) = ctx
        .http_client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    else {
        return false;
    };

    if !response.status().is_success() {
        return false;
    }

    let Ok(text) = response.text().await else {
        return false;
    };

    is_graphql_response(&text)
}

/// Check if a response body looks like a valid GraphQL response.
///
/// GraphQL responses contain a `"data"` key (success) or `"errors"` key (error).
/// Both indicate a GraphQL endpoint.
#[must_use]
fn is_graphql_response(body: &str) -> bool {
    let Ok(json) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    json.get("data").is_some() || json.get("errors").is_some()
}

/// Test if full introspection is enabled.
///
/// Full introspection reveals the entire schema including types, fields,
/// mutations, and subscriptions — a significant information disclosure.
async fn test_introspection(
    ctx: &ScanContext,
    endpoint: &GqlEndpoint,
    findings: &mut Vec<Finding>,
) {
    let query = "{ __schema { queryType { name } types { name kind fields { name } } } }";
    let body = json!({ "query": query });

    let Ok(response) = ctx
        .http_client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    else {
        return;
    };

    let Ok(text) = response.text().await else {
        return;
    };

    if has_introspection_data(&text) {
        let type_count = count_introspection_types(&text);
        findings.push(
            Finding::new(
                "graphql",
                Severity::Medium,
                format!("GraphQL Introspection Enabled: {}", endpoint.path),
                format!(
                    "The GraphQL endpoint at '{}' has full introspection enabled, \
                     exposing {} types. Attackers can discover the entire API schema \
                     including types, fields, mutations, and relationships.",
                    endpoint.url, type_count
                ),
                &endpoint.url,
            )
            .with_evidence(format!("Introspection query returned {type_count} types"))
            .with_remediation(
                "Disable introspection in production. In Apollo Server: \
                 `introspection: false`. In graphql-java: remove the introspection \
                 field from the schema. Allow introspection only in development.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }
}

/// Test for missing query depth limits.
///
/// Sends a deeply nested query. If the server processes it without error,
/// it may be vulnerable to denial-of-service via query complexity attacks.
async fn test_depth_abuse(ctx: &ScanContext, endpoint: &GqlEndpoint, findings: &mut Vec<Finding>) {
    let deep_query = build_depth_query(15);
    let body = json!({ "query": deep_query });

    let Ok(response) = ctx
        .http_client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    else {
        return;
    };

    let status = response.status().as_u16();
    let Ok(text) = response.text().await else {
        return;
    };

    // If the server processed the deep query (returned data or non-depth-error),
    // it lacks depth limiting
    if status == 200 && is_graphql_response(&text) {
        let json: Value = serde_json::from_str(&text).unwrap_or_default();
        let has_depth_error = json.get("errors").and_then(|e| e.as_array()).is_some_and(|errors| {
            errors.iter().any(|e| {
                let msg = e.get("message").and_then(|m| m.as_str()).unwrap_or("");
                let lower = msg.to_lowercase();
                lower.contains("depth")
                    || lower.contains("complexity")
                    || lower.contains("too deep")
            })
        });

        if !has_depth_error {
            findings.push(
                Finding::new(
                    "graphql",
                    Severity::High,
                    format!("No Query Depth Limit: {}", endpoint.path),
                    format!(
                        "The GraphQL endpoint at '{}' accepted a query nested 15 levels \
                         deep without returning a depth/complexity error. An attacker can \
                         craft deeply nested queries to cause denial of service.",
                        endpoint.url
                    ),
                    &endpoint.url,
                )
                .with_evidence("15-level nested query accepted without depth error")
                .with_remediation(
                    "Implement query depth limiting. In Apollo: `depthLimit(10)` plugin. \
                     In graphql-java: `MaxQueryDepthInstrumentation`. Set a reasonable \
                     maximum depth (typically 5-10 levels).",
                )
                .with_owasp("A04:2021 Insecure Design")
                .with_cwe(770)
                .with_confidence(0.7),
            );
        }
    }
}

/// Test for batch query abuse.
///
/// GraphQL batching allows sending multiple queries in one request. Without
/// rate limiting, this enables brute-force and `DoS` attacks.
async fn test_batch_abuse(ctx: &ScanContext, endpoint: &GqlEndpoint, findings: &mut Vec<Finding>) {
    let batch = build_batch_payload(25);

    let Ok(response) = ctx
        .http_client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .body(batch)
        .send()
        .await
    else {
        return;
    };

    let Ok(text) = response.text().await else {
        return;
    };

    // If response is a JSON array, batching is supported
    if let Ok(json) = serde_json::from_str::<Value>(&text) {
        if let Some(arr) = json.as_array() {
            if arr.len() > 1 {
                findings.push(
                    Finding::new(
                        "graphql",
                        Severity::Medium,
                        format!("Batch Query Abuse: {}", endpoint.path),
                        format!(
                            "The GraphQL endpoint at '{}' supports batch queries, \
                             processing {} queries in a single request. Without rate \
                             limiting, this enables brute-force attacks and DoS by \
                             multiplying query execution per HTTP request.",
                            endpoint.url,
                            arr.len()
                        ),
                        &endpoint.url,
                    )
                    .with_evidence(format!("Batch of 25 queries returned {} results", arr.len()))
                    .with_remediation(
                        "Limit batch query size. Reject batches larger than a \
                         reasonable threshold (e.g., 5-10 queries). Apply per-query \
                         rate limiting within batches.",
                    )
                    .with_owasp("A04:2021 Insecure Design")
                    .with_cwe(770)
                    .with_confidence(0.7),
                );
            }
        }
    }
}

/// Test for field suggestion information leaks.
///
/// Sends a query with a misspelled field name. If the server returns
/// "Did you mean" suggestions, it leaks valid field names to attackers.
async fn test_field_suggestions(
    ctx: &ScanContext,
    endpoint: &GqlEndpoint,
    findings: &mut Vec<Finding>,
) {
    // Intentionally misspell __typename → __typenme
    let body = json!({ "query": "{ __typenme }" });

    let Ok(response) = ctx
        .http_client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    else {
        return;
    };

    let Ok(text) = response.text().await else {
        return;
    };

    if has_field_suggestions(&text) {
        findings.push(
            Finding::new(
                "graphql",
                Severity::Low,
                format!("Field Suggestion Leak: {}", endpoint.path),
                format!(
                    "The GraphQL endpoint at '{}' returns field name suggestions \
                     for misspelled queries. Attackers can systematically discover \
                     valid field names without needing introspection access.",
                    endpoint.url
                ),
                &endpoint.url,
            )
            .with_evidence("Query with misspelled field returned 'Did you mean' suggestions")
            .with_remediation(
                "Disable field suggestions in production. In Apollo Server: \
                 set `includeStacktraceInErrorResponses: false` and customize \
                 error formatting. In graphql-js: override the validation rules.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }
}

/// Test for mutation enumeration via introspection.
///
/// Even when full introspection is disabled, querying the mutation type
/// specifically may still work and reveal available write operations.
async fn test_mutation_enumeration(
    ctx: &ScanContext,
    endpoint: &GqlEndpoint,
    findings: &mut Vec<Finding>,
) {
    let query = "{ __schema { mutationType { name fields { name } } } }";
    let body = json!({ "query": query });

    let Ok(response) = ctx
        .http_client
        .post(&endpoint.url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    else {
        return;
    };

    let Ok(text) = response.text().await else {
        return;
    };

    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return;
    };

    let mutation_fields = json
        .pointer("/data/__schema/mutationType/fields")
        .and_then(|f| f.as_array())
        .map_or(0, Vec::len);

    if mutation_fields > 0 {
        let mutation_names: Vec<&str> = json
            .pointer("/data/__schema/mutationType/fields")
            .and_then(|f| f.as_array())
            .map(|fields| {
                fields.iter().filter_map(|f| f.get("name").and_then(|n| n.as_str())).collect()
            })
            .unwrap_or_default();

        let sample: Vec<&str> = mutation_names.into_iter().take(5).collect();

        findings.push(
            Finding::new(
                "graphql",
                Severity::Medium,
                format!("Mutation Enumeration: {}", endpoint.path),
                format!(
                    "The GraphQL endpoint at '{}' exposes {} mutations via \
                     introspection. Mutations represent write operations — an \
                     attacker can discover and target state-changing API operations.",
                    endpoint.url, mutation_fields
                ),
                &endpoint.url,
            )
            .with_evidence(format!(
                "{mutation_fields} mutations exposed (sample: {})",
                sample.join(", ")
            ))
            .with_remediation(
                "Disable introspection in production or restrict mutation \
                 visibility. Apply field-level authorization to all mutations.",
            )
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }
}

/// Build a deeply nested GraphQL query for depth abuse testing.
///
/// Generates a query like `{ __typename a: __typename b: __typename ... }`
/// wrapped in nested fragments to test depth limiting.
#[must_use]
fn build_depth_query(depth: usize) -> String {
    // Use nested __type queries which are always available
    let mut query = String::from("{ __typename ");
    for _ in 0..depth {
        query.push_str("... on Query { __typename ");
    }
    for _ in 0..depth {
        query.push_str("} ");
    }
    query.push('}');
    query
}

/// Build a batch query payload (JSON array of N identical queries).
#[must_use]
fn build_batch_payload(count: usize) -> String {
    let queries: Vec<Value> = (0..count).map(|_| json!({ "query": "{ __typename }" })).collect();
    serde_json::to_string(&queries).unwrap_or_else(|_| "[]".to_string())
}

/// Check if an introspection response contains schema type data.
#[must_use]
fn has_introspection_data(body: &str) -> bool {
    let Ok(json) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    json.pointer("/data/__schema/types").and_then(|t| t.as_array()).is_some_and(|a| !a.is_empty())
}

/// Count the number of types returned by an introspection query.
#[must_use]
fn count_introspection_types(body: &str) -> usize {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|json| json.pointer("/data/__schema/types")?.as_array().map(Vec::len))
        .unwrap_or(0)
}

/// Check if a GraphQL error response contains field suggestions.
///
/// GraphQL servers often return "Did you mean" suggestions for misspelled
/// field names, leaking valid field names to attackers.
#[must_use]
fn has_field_suggestions(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("did you mean")
        || lower.contains("did_you_mean")
        || lower.contains("suggestions")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for GraphQL deep security module.
    ///
    /// Tests query building, response analysis, and endpoint detection
    /// without requiring a live GraphQL server.

    /// Verify depth query generation at various nesting levels.
    ///
    /// The generated query must contain the correct number of nested
    /// fragment spreads and produce valid GraphQL syntax.
    #[test]
    fn test_build_depth_query() {
        let q5 = build_depth_query(5);
        assert!(q5.starts_with("{ __typename "));
        assert!(q5.ends_with("} } } } } }"));
        assert_eq!(q5.matches("... on Query").count(), 5);

        let q1 = build_depth_query(1);
        assert_eq!(q1.matches("... on Query").count(), 1);

        let q0 = build_depth_query(0);
        assert_eq!(q0, "{ __typename }");
    }

    /// Verify batch payload generation produces valid JSON array.
    ///
    /// Each element must be a GraphQL query object with a "query" key.
    #[test]
    fn test_build_batch_payload() {
        let batch = build_batch_payload(3);
        let parsed: Vec<Value> = serde_json::from_str(&batch).expect("valid JSON array");
        assert_eq!(parsed.len(), 3);
        for item in &parsed {
            assert!(item.get("query").is_some());
            assert_eq!(item["query"], "{ __typename }");
        }

        // Edge case: single query
        let single = build_batch_payload(1);
        let parsed: Vec<Value> = serde_json::from_str(&single).expect("valid JSON");
        assert_eq!(parsed.len(), 1);
    }

    /// Verify GraphQL response detection distinguishes GQL from non-GQL JSON.
    ///
    /// Responses with "data" or "errors" keys are GraphQL.
    /// Regular JSON without these keys is not.
    #[test]
    fn test_is_graphql_response() {
        // Valid GraphQL success response
        assert!(is_graphql_response(r#"{"data":{"__typename":"Query"}}"#));

        // Valid GraphQL error response
        assert!(is_graphql_response(r#"{"errors":[{"message":"Syntax Error"}]}"#));

        // Both data and errors (partial success)
        assert!(is_graphql_response(r#"{"data":null,"errors":[{"message":"Auth"}]}"#));

        // Not GraphQL — regular JSON
        assert!(!is_graphql_response(r#"{"status":"ok","version":"1.0"}"#));

        // Not JSON at all
        assert!(!is_graphql_response("<html>Not Found</html>"));

        // Empty JSON object
        assert!(!is_graphql_response("{}"));
    }

    /// Verify field suggestion detection catches "Did you mean" patterns.
    ///
    /// GraphQL servers like Apollo return suggestions for misspelled fields.
    #[test]
    fn test_has_field_suggestions() {
        // Apollo-style suggestion
        assert!(has_field_suggestions(
            r#"{"errors":[{"message":"Cannot query field \"__typenme\" on type \"Query\". Did you mean \"__typename\"?"}]}"#
        ));

        // Alternative format
        assert!(has_field_suggestions(
            r#"{"errors":[{"extensions":{"did_you_mean":["__typename"]}}]}"#
        ));

        // Suggestions key
        assert!(has_field_suggestions(r#"{"errors":[{"suggestions":["__typename"]}]}"#));

        // No suggestions
        assert!(!has_field_suggestions(r#"{"errors":[{"message":"Cannot query field"}]}"#));

        // Not even an error
        assert!(!has_field_suggestions(r#"{"data":{"__typename":"Query"}}"#));
    }

    /// Verify all expected GraphQL paths are generated.
    ///
    /// Must cover standard paths used by popular frameworks.
    #[test]
    fn test_generate_gql_paths() {
        let paths = generate_gql_paths();

        assert!(paths.len() >= 8, "Expected at least 8 GQL paths, got {}", paths.len());
        assert!(paths.contains(&"/graphql"), "Missing /graphql");
        assert!(paths.contains(&"/api/graphql"), "Missing /api/graphql");
        assert!(paths.contains(&"/gql"), "Missing /gql");

        for path in &paths {
            assert!(path.starts_with('/'), "Path '{path}' doesn't start with /");
        }
    }

    /// Verify introspection data detection in response bodies.
    ///
    /// A response with `__schema.types` array indicates introspection is enabled.
    #[test]
    fn test_introspection_response() {
        // Has introspection data
        let with_types = r#"{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"}]}}}"#;
        assert!(has_introspection_data(with_types));
        assert_eq!(count_introspection_types(with_types), 1);

        // Empty types array — introspection responded but no types
        let empty = r#"{"data":{"__schema":{"types":[]}}}"#;
        assert!(!has_introspection_data(empty));

        // No introspection data
        let no_intro = r#"{"data":{"__typename":"Query"}}"#;
        assert!(!has_introspection_data(no_intro));

        // Error response (introspection disabled)
        let error = r#"{"errors":[{"message":"Introspection is not allowed"}]}"#;
        assert!(!has_introspection_data(error));
    }

    /// Verify batch payload with zero count edge case.
    #[test]
    fn test_batch_empty() {
        let batch = build_batch_payload(0);
        let parsed: Vec<Value> = serde_json::from_str(&batch).expect("valid JSON");
        assert!(parsed.is_empty());
    }

    /// Verify depth query at high depth doesn't panic.
    #[test]
    fn test_depth_query_high() {
        let q = build_depth_query(50);
        assert_eq!(q.matches("... on Query").count(), 50);
        assert!(q.len() > 500);
    }
}
