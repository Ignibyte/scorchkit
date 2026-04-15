# API spec shared-data primitive

`engine::api_spec` is the shared-data convention by which an API-spec-producing module (e.g. `tools::vespasian`) hands a discovered endpoint list to downstream scanners (`injection`, `csrf`, `idor`, `graphql`, `auth`, `ratelimit`).

## Shape

```rust
pub struct ApiEndpoint {
    pub method: String,        // "GET", "POST", ...
    pub url: String,           // fully-resolved URL
    pub parameters: Vec<String>,
}

pub struct ApiSpec {
    pub title: String,
    pub endpoints: Vec<ApiEndpoint>,
}
```

## Producer pattern

```rust
use crate::engine::api_spec::{publish_api_spec, ApiSpec, ApiEndpoint};

let spec = ApiSpec {
    title: "Discovered API".into(),
    endpoints: vec![/* ... */],
};
publish_api_spec(&ctx.shared_data, &spec);
```

Empty specs are still published — consumers want to distinguish "producer ran, found zero endpoints" from "no producer ran".

## Consumer pattern

```rust
use crate::engine::api_spec::read_api_spec;

if let Some(spec) = read_api_spec(&ctx.shared_data) {
    for endpoint in &spec.endpoints {
        // run module-specific tests against endpoint.url with endpoint.method
        // and endpoint.parameters
    }
}
```

Returning early on `None` gives consumers a clean fallback to their existing crawl-based behaviour.

## Wired modules

- **Producer:** `tools::vespasian` (WORK-107)
- **Consumers:**
  - `scanner::injection` (WORK-108) — appends each discovered endpoint with sentinel parameter values to its existing SQLi probe path
  - `scanner::csrf` (WORK-108b) — flags state-changing endpoints (POST/PUT/PATCH/DELETE) for operator CSRF review
  - `scanner::idor` (WORK-108b) — surfaces ID-shaped parameters via `param_looks_like_id` heuristic
  - `scanner::graphql` (WORK-108b) — adds spec endpoints whose URL contains `graphql`/`gql` to the discovered-endpoints list, then runs the existing introspection / depth-abuse / batch-abuse / field-suggestion / mutation-enum tests
  - `scanner::auth` (WORK-108b) — sends an unauthenticated request per endpoint; flags 200 responses with non-trivial bodies as "may not require auth"
  - `scanner::ratelimit` (WORK-108b) — sends 10 rapid GET requests per spec endpoint (capped at first 10 endpoints); flags absence of 429 / 503 as "no rate limit observed"

## Why a separate type

Vespasian emits OpenAPI 3.0 / GraphQL SDL / WSDL. `ApiSpec` is the lowest-common-denominator type that captures what every consumer needs (URL + method + parameter names). Producers translate from their native format into `ApiSpec`; consumers never see OpenAPI directly.

## Single publication contract

`SHARED_KEY_API_SPEC` holds exactly one publication per scan — last writer wins. If two producers run in the same scan (rare but possible), the second overwrites. A future enhancement could merge multiple publications, but v1 keeps the contract simple.
