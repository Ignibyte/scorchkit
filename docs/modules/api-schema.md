# API Schema Discovery

**Module ID:** `api-schema` | **Category:** Recon | **Type:** Built-in
**Source:** `src/scanner/api_schema.rs`

## What It Does

Discovers publicly accessible API documentation by probing 13 common OpenAPI/Swagger specification paths and testing for GraphQL introspection. Exposed API schemas reveal the full attack surface including all endpoints, parameters, and data models, significantly reducing the effort required for targeted attacks.

## Checks Performed

### Swagger/OpenAPI Paths (13)

| # | Path |
|---|------|
| 1 | `/swagger.json` |
| 2 | `/swagger/v1/swagger.json` |
| 3 | `/api-docs` |
| 4 | `/api-docs.json` |
| 5 | `/v1/api-docs` |
| 6 | `/v2/api-docs` |
| 7 | `/v3/api-docs` |
| 8 | `/openapi.json` |
| 9 | `/openapi.yaml` |
| 10 | `/api/swagger.json` |
| 11 | `/api/openapi.json` |
| 12 | `/docs/api.json` |
| 13 | `/_api/docs` |

### Swagger Validation

A response is confirmed as a Swagger/OpenAPI spec if it contains both:
- `"swagger"` or `"openapi"` (version identifier)
- `"paths"` or `"info"` (spec structure)

The number of API endpoints is counted from the `paths` object.

### GraphQL Introspection

A POST request is sent to `/graphql` with the introspection query:

```json
{"query": "{ __schema { types { name } } }"}
```

A finding is emitted if the response contains both `__schema` and `types`, indicating introspection is enabled. The number of types is estimated by counting `"name"` occurrences.

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| OpenAPI/Swagger Spec Exposed | Low | 200 | Swagger/OpenAPI JSON found at a known path |
| GraphQL Introspection Enabled | Medium | 200 | Introspection query returns schema with types |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** Exposed API documentation in production reveals the complete API surface to attackers, including internal endpoints, authentication requirements, and data structures.

## How It Works

1. **Swagger probing:** Each of the 13 paths is appended to the target base URL and requested via GET. If the response is HTTP 200, the body is validated as a Swagger/OpenAPI spec. The `paths` JSON object is parsed to count defined API endpoints. Only the first valid spec found is reported.
2. **GraphQL probing:** A POST request with the introspection query is sent to `/graphql`. If the response is HTTP 200 and contains `__schema` and `types`, the schema is considered exposed. The type count provides a rough measure of schema complexity.

## Example Output

```
[Low] OpenAPI/Swagger Spec Exposed: /swagger.json
  An OpenAPI specification is publicly accessible with 47 endpoints defined.
  Evidence: HTTP 200 at https://example.com/swagger.json | 47 API endpoints
  Remediation: Restrict access to API documentation in production
  OWASP: A05:2021 Security Misconfiguration | CWE-200
```
