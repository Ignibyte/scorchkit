//! `vespasian` wrapper — API endpoint discovery + spec generation.
//!
//! Wraps Praetorian's [Vespasian](https://github.com/praetorian-inc/vespasian)
//! (Apache-2.0, Go) — a tool that crawls a target with a headless
//! browser (powered by katana), classifies captured HTTP traffic
//! into REST / `GraphQL` / SOAP / `WebSocket` buckets via confidence
//! heuristics, and emits structured API specs (`OpenAPI` 3.0,
//! `GraphQL` SDL, WSDL).
//!
//! ## Why we wrap it
//!
//! `ScorchKit`'s built-in `api_schema` scanner only detects exposed
//! Swagger / `OpenAPI` / `GraphQL` artifacts at known paths. Vespasian
//! goes further: it observes the actual XHR / fetch calls that the
//! application's `JavaScript` constructs at runtime, then synthesises
//! a spec from what it sees. That spec is the foundation for
//! WORK-108's spec consumer, which will pipe each discovered
//! endpoint into the existing injection / csrf / idor / graphql /
//! auth / ratelimit scanners.
//!
//! ## v1 wrapper scope
//!
//! - Invoke `vespasian scan <url> -o <yaml-tempfile>`
//! - Parse the `OpenAPI` 3.0 YAML output
//! - Surface a summary Info finding (endpoint count + total paths)
//! - Surface one Info finding per discovered endpoint with method +
//!   path + parameter count
//! - Cap per-endpoint findings at 50 to avoid flooding reports on
//!   large APIs (operators who want every endpoint can read the
//!   raw Vespasian YAML directly)
//!
//! Output spec (`scorchkit-vespasian-<scan-id>.yaml`) is left in the
//! current working directory for downstream tooling.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::api_spec::{publish_api_spec, ApiEndpoint, ApiSpec};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Cap on per-endpoint findings to keep reports readable on large APIs.
const MAX_ENDPOINT_FINDINGS: usize = 50;

/// API endpoint discovery via Vespasian.
#[derive(Debug)]
pub struct VespasianModule;

#[async_trait]
impl ScanModule for VespasianModule {
    fn name(&self) -> &'static str {
        "Vespasian API Endpoint Discovery"
    }

    fn id(&self) -> &'static str {
        "vespasian"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Headless-browser crawl + API spec synthesis (OpenAPI / GraphQL SDL / WSDL)"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("vespasian")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let Ok(tmp) = tempfile::NamedTempFile::new() else {
            return Ok(Vec::new());
        };
        let out_path = tmp.path().to_string_lossy().to_string();
        let url = ctx.target.url.as_str();
        let output = subprocess::run_tool(
            "vespasian",
            &["scan", url, "-o", &out_path],
            Duration::from_secs(300),
        )
        .await?;
        // Vespasian writes the spec to the file; we read it back.
        // If the file is missing or empty, parse_vespasian_output
        // gracefully returns an empty Vec.
        let yaml = std::fs::read_to_string(&out_path).unwrap_or_default();
        // WORK-108: publish the parsed spec to shared_data so
        // downstream scanners (injection, csrf, idor, graphql,
        // auth, ratelimit) can consume each discovered endpoint.
        let spec = build_api_spec(&yaml, url);
        publish_api_spec(&ctx.shared_data, &spec);
        Ok(parse_vespasian_output(&yaml, url, &output.stdout))
    }
}

/// Translate a Vespasian-emitted `OpenAPI` YAML into the `ApiSpec`
/// shared-data primitive. Resolves relative paths against `base_url`.
#[must_use]
pub fn build_api_spec(yaml: &str, base_url: &str) -> ApiSpec {
    let trimmed = yaml.trim();
    if trimmed.is_empty() {
        return ApiSpec::default();
    }
    let Ok(doc): std::result::Result<serde_yaml::Value, _> = serde_yaml::from_str(trimmed) else {
        return ApiSpec::default();
    };
    let title = doc
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("(untitled)")
        .to_string();
    let mut endpoints = Vec::new();
    let base = base_url.trim_end_matches('/').to_string();
    if let Some(paths) = doc.get("paths").and_then(serde_yaml::Value::as_mapping) {
        for (path, ops) in paths {
            let Some(path_str) = path.as_str() else { continue };
            let Some(ops_map) = ops.as_mapping() else { continue };
            for (method, op) in ops_map {
                let Some(method_str) = method.as_str() else { continue };
                if !matches_http_method(method_str) {
                    continue;
                }
                let parameters = extract_parameter_names(op);
                endpoints.push(ApiEndpoint {
                    method: method_str.to_uppercase(),
                    url: format!("{base}{path_str}"),
                    parameters,
                });
            }
        }
    }
    ApiSpec { title, endpoints }
}

/// Pull parameter names from an `OpenAPI` operation's `parameters`
/// array. Skips entries without a usable `name` field.
fn extract_parameter_names(op: &serde_yaml::Value) -> Vec<String> {
    let Some(params) = op.get("parameters").and_then(serde_yaml::Value::as_sequence) else {
        return Vec::new();
    };
    params
        .iter()
        .filter_map(|p| p.get("name").and_then(serde_yaml::Value::as_str).map(String::from))
        .collect()
}

/// Parse a Vespasian-emitted `OpenAPI` 3.0 YAML document into findings.
///
/// We extract every `paths.<path>.<method>` pair and emit one Info
/// finding per endpoint (capped at 50 to avoid finding floods) plus a
/// summary finding listing the total endpoint count and any notable
/// info from `info.title`.
#[must_use]
pub fn parse_vespasian_output(yaml: &str, target_url: &str, stdout: &str) -> Vec<Finding> {
    let trimmed = yaml.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(doc): std::result::Result<serde_yaml::Value, _> = serde_yaml::from_str(trimmed) else {
        return Vec::new();
    };

    let mut endpoints: Vec<(String, String)> = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(serde_yaml::Value::as_mapping) {
        for (path, ops) in paths {
            let Some(path_str) = path.as_str() else {
                continue;
            };
            let Some(ops_map) = ops.as_mapping() else {
                continue;
            };
            for (method, _) in ops_map {
                if let Some(method_str) = method.as_str() {
                    if matches_http_method(method_str) {
                        endpoints.push((method_str.to_uppercase(), path_str.to_string()));
                    }
                }
            }
        }
    }

    if endpoints.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let title = doc
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("(untitled)")
        .to_string();
    let total = endpoints.len();

    findings.push(
        Finding::new(
            "vespasian",
            Severity::Info,
            format!("Vespasian: {total} API endpoint(s) discovered"),
            format!(
                "Vespasian crawled the target via headless browser and synthesised an \
                 OpenAPI 3.0 spec covering {total} endpoint(s). Spec title: {title}."
            ),
            target_url,
        )
        .with_evidence(format!(
            "OpenAPI title: {title} | Endpoints: {total} | Vespasian stdout snippet: {}",
            stdout.lines().take(2).collect::<Vec<_>>().join(" | ")
        ))
        .with_remediation(
            "Review the discovered API surface — endpoints exposed but not in the public \
             documentation may be unintentional. Feed the OpenAPI spec into your fuzzer / \
             contract tester for deeper coverage.",
        )
        .with_owasp("A05:2021 Security Misconfiguration")
        .with_confidence(0.9),
    );

    for (method, path) in endpoints.into_iter().take(MAX_ENDPOINT_FINDINGS) {
        findings.push(
            Finding::new(
                "vespasian",
                Severity::Info,
                format!("Vespasian: discovered {method} {path}"),
                format!("Endpoint discovered via runtime traffic capture: {method} {path}"),
                target_url,
            )
            .with_evidence(format!("Method: {method} | Path: {path}"))
            .with_confidence(0.85),
        );
    }
    findings
}

/// True when `s` is a recognised `OpenAPI` HTTP method key.
fn matches_http_method(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "options" | "head" | "trace"
    )
}

#[cfg(test)]
mod tests {
    //! Coverage for the OpenAPI YAML parser. Pins the wire format
    //! Vespasian emits.

    use super::*;

    /// Real-shape OpenAPI 3.0 YAML with three endpoints yields a
    /// summary finding + one finding per endpoint.
    #[test]
    fn parse_vespasian_output_extracts_endpoints() {
        let yaml = r"openapi: 3.0.0
info:
  title: Discovered API
  version: 1.0.0
paths:
  /api/users:
    get:
      responses: {}
    post:
      responses: {}
  /api/users/{id}:
    get:
      responses: {}
    delete:
      responses: {}
";
        let findings = parse_vespasian_output(yaml, "https://example.com", "stdout");
        // 1 summary + 4 endpoints
        assert_eq!(findings.len(), 5);
        assert!(findings[0].title.contains("4 API endpoint"));
        assert!(findings.iter().any(|f| f.title.contains("GET /api/users")));
        assert!(findings.iter().any(|f| f.title.contains("DELETE /api/users/{id}")));
    }

    /// Empty YAML / non-OpenAPI input yields zero findings.
    #[test]
    fn parse_vespasian_output_empty() {
        assert!(parse_vespasian_output("", "https://example.com", "").is_empty());
        assert!(parse_vespasian_output(
            "openapi: 3.0.0\ninfo:\n  title: x\n",
            "https://example.com",
            ""
        )
        .is_empty());
    }

    /// Garbage YAML returns empty rather than panicking.
    #[test]
    fn parse_vespasian_output_garbage() {
        assert!(
            parse_vespasian_output("this is not yaml: [[[", "https://example.com", "").is_empty()
        );
    }

    /// Endpoint count above the cap truncates per-endpoint findings
    /// to MAX_ENDPOINT_FINDINGS but preserves the summary count.
    #[test]
    fn parse_vespasian_output_caps_endpoint_findings() {
        // Build a YAML with more than the cap.
        let mut yaml =
            String::from("openapi: 3.0.0\ninfo:\n  title: Big\n  version: 1.0.0\npaths:\n");
        for i in 0..(MAX_ENDPOINT_FINDINGS + 10) {
            yaml.push_str(&format!("  /endpoint/{i}:\n    get:\n      responses: {{}}\n"));
        }
        let findings = parse_vespasian_output(&yaml, "https://example.com", "");
        // 1 summary + MAX_ENDPOINT_FINDINGS endpoints
        assert_eq!(findings.len(), MAX_ENDPOINT_FINDINGS + 1);
        assert!(findings[0].title.contains(&format!("{}", MAX_ENDPOINT_FINDINGS + 10)));
    }

    /// HTTP method discriminator filters out OpenAPI keys that aren't
    /// methods (e.g. `parameters`, `summary`, `$ref`).
    #[test]
    fn matches_http_method_filters_non_methods() {
        assert!(matches_http_method("get"));
        assert!(matches_http_method("POST"));
        assert!(matches_http_method("Delete"));
        assert!(!matches_http_method("parameters"));
        assert!(!matches_http_method("summary"));
        assert!(!matches_http_method("$ref"));
    }
}
