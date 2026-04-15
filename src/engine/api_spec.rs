//! API spec data type and shared-data publishing.
//!
//! Parallel to [`crate::engine::service_fingerprint`]: a structured
//! data type that producers write to `SharedData` and consumers read
//! later in the same scan. This is how
//! [`crate::tools::vespasian::VespasianModule`] feeds the endpoint
//! list it discovers into downstream scanners (injection, csrf,
//! idor, graphql, auth, ratelimit) without those scanners needing
//! to know about Vespasian specifically.
//!
//! ## Producer side
//!
//! A module that synthesises an API spec calls
//! [`publish_api_spec`] after parsing. The spec can be empty (no
//! endpoints) — consumers see an empty `ApiSpec` rather than
//! `None`, which keeps the consumer code path uniform.
//!
//! ## Consumer side
//!
//! Downstream scanners call [`read_api_spec`] at the top of their
//! `run()` method. If the result is `None`, no producer published —
//! fall back to the scanner's existing crawl-based behaviour. If
//! `Some`, iterate `endpoints` and run the scanner's per-endpoint
//! checks against each entry.
//!
//! ## Why a separate type
//!
//! Vespasian emits `OpenAPI` / `GraphQL` SDL / WSDL — three different
//! wire formats. `ApiSpec` is the lowest-common-denominator type
//! that captures what every downstream consumer needs (URL +
//! method + parameter names). Producers translate from their
//! native format into this shape; consumers never see `OpenAPI`
//! directly.

use serde::{Deserialize, Serialize};

use super::shared_data::SharedData;

/// Well-known `SharedData` key for the published API spec. Single
/// publication per scan — last writer wins.
pub const SHARED_KEY_API_SPEC: &str = "scanner.api_spec";

/// One endpoint discovered by an API-spec-producing module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiEndpoint {
    /// HTTP method, uppercased: `"GET"`, `"POST"`, etc.
    pub method: String,
    /// Full URL including scheme + host + path. Producers resolve
    /// relative paths against the scan target before publishing.
    pub url: String,
    /// Parameter names extracted from the spec (query, path,
    /// body — collapsed into one list for v1).
    pub parameters: Vec<String>,
}

/// Aggregate spec — every endpoint a producer found, plus a
/// human-readable spec name for evidence text.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiSpec {
    /// Display name of the spec (e.g. `OpenAPI` `info.title`).
    pub title: String,
    /// Discovered endpoints.
    pub endpoints: Vec<ApiEndpoint>,
}

/// Publish an [`ApiSpec`] to [`SharedData`] under [`SHARED_KEY_API_SPEC`].
///
/// Empty specs (no endpoints) are still published — consumers want
/// to know "a producer ran but found nothing" vs "no producer ran".
pub fn publish_api_spec(shared: &SharedData, spec: &ApiSpec) {
    if let Ok(encoded) = serde_json::to_string(spec) {
        shared.publish(SHARED_KEY_API_SPEC, vec![encoded]);
    }
}

/// Read an [`ApiSpec`] from [`SharedData`].
///
/// Returns `None` if no producer published, or if the published
/// data fails to decode (which we treat as best-effort — a broken
/// publisher shouldn't deny consumers their fallback path).
#[must_use]
pub fn read_api_spec(shared: &SharedData) -> Option<ApiSpec> {
    let raw = shared.get(SHARED_KEY_API_SPEC);
    let first = raw.first()?;
    serde_json::from_str(first).ok()
}

#[cfg(test)]
mod tests {
    //! Coverage for the shared-data API spec round-trip.
    use super::*;

    fn fixture_spec() -> ApiSpec {
        ApiSpec {
            title: "Demo API".to_string(),
            endpoints: vec![
                ApiEndpoint {
                    method: "GET".into(),
                    url: "https://example.com/api/users".into(),
                    parameters: vec!["page".into(), "limit".into()],
                },
                ApiEndpoint {
                    method: "POST".into(),
                    url: "https://example.com/api/users".into(),
                    parameters: vec!["name".into(), "email".into()],
                },
            ],
        }
    }

    /// Publishing then reading yields the same spec.
    #[test]
    fn api_spec_round_trip() {
        let shared = SharedData::new();
        let spec = fixture_spec();
        publish_api_spec(&shared, &spec);
        let got = read_api_spec(&shared).expect("hit");
        assert_eq!(got.title, spec.title);
        assert_eq!(got.endpoints.len(), 2);
        assert_eq!(got.endpoints[0].method, "GET");
        assert_eq!(got.endpoints[0].parameters, vec!["page", "limit"]);
    }

    /// Reading without a publisher returns `None` so consumers
    /// fall back to their existing crawl behaviour.
    #[test]
    fn read_api_spec_returns_none_when_no_publisher() {
        let shared = SharedData::new();
        assert!(read_api_spec(&shared).is_none());
    }

    /// Publishing an empty spec is preserved — the consumer sees
    /// "producer ran, found zero endpoints" not "no producer".
    #[test]
    fn empty_spec_is_publishable_and_distinguishable() {
        let shared = SharedData::new();
        let empty = ApiSpec { title: "Empty".into(), endpoints: vec![] };
        publish_api_spec(&shared, &empty);
        let got = read_api_spec(&shared).expect("hit");
        assert!(got.endpoints.is_empty());
        assert_eq!(got.title, "Empty");
    }
}
