# GraphQL Security

**Module ID:** `graphql` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/graphql.rs`

## What It Does

Tests GraphQL endpoints for security vulnerabilities. Discovers GraphQL endpoints by probing common paths with a `{ __typename }` query, then runs security tests for introspection exposure, query depth abuse, batch query abuse, field suggestion information leaks, and mutation enumeration.

## Checks Performed

| Check | Description |
|-------|-------------|
| Endpoint discovery | Probes 10 common paths (`/graphql`, `/api/graphql`, `/gql`, `/query`, etc.) with `{ __typename }` |
| Introspection enabled | Sends full `__schema` introspection query and checks for type data |
| Query depth abuse | Sends a 15-level nested query to test for missing depth limits |
| Batch query abuse | Sends a JSON array of 25 identical queries to test batch processing |
| Field suggestion leak | Sends misspelled field (`__typenme`) to detect "Did you mean" responses |
| Mutation enumeration | Queries `__schema.mutationType.fields` to discover available write operations |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| GraphQL Introspection Enabled | Medium | 200 | Introspection query returns schema types |
| No Query Depth Limit | High | 770 | 15-level nested query accepted without depth/complexity error |
| Batch Query Abuse | Medium | 770 | Server processes batch of 25 queries and returns multiple results |
| Field Suggestion Leak | Low | 200 | Error response contains "Did you mean", "did_you_mean", or "suggestions" |
| Mutation Enumeration | Medium | 200 | Mutation introspection returns available mutation field names |

## OWASP Coverage

- **A04:2021 -- Insecure Design.** Covers missing query depth/complexity limits and unrestricted batch queries that enable denial-of-service.
- **A05:2021 -- Security Misconfiguration.** Covers introspection enabled in production and field suggestion leaks.
- **A01:2021 -- Broken Access Control.** Covers mutation enumeration exposing write operations.

## How It Works

1. **Discovery**: Sends `{ __typename }` as a POST with `Content-Type: application/json` to 10 common GraphQL paths. A response containing `"data"` or `"errors"` keys confirms a GraphQL endpoint.
2. **Introspection**: Sends a `__schema` query requesting `queryType`, `types`, and `fields`. Checks if the response contains a non-empty types array.
3. **Depth abuse**: Builds a query with 15 nested `... on Query { __typename }` fragments. If the server returns a GraphQL response without depth/complexity error messages, it lacks depth limiting.
4. **Batch abuse**: Constructs a JSON array of 25 `{ __typename }` queries. If the response is a JSON array with more than 1 result, batching is unrestricted.
5. **Field suggestions**: Sends `{ __typenme }` (misspelled). Checks the error response for "Did you mean" patterns that leak valid field names.
6. **Mutation enumeration**: Queries `__schema.mutationType.fields` specifically. Reports discovered mutation names (up to 5 shown in evidence).

## Example Output

```
[High] No Query Depth Limit: /graphql
  The GraphQL endpoint at 'https://example.com/graphql' accepted a query nested
  15 levels deep without returning a depth/complexity error. An attacker can
  craft deeply nested queries to cause denial of service.
  Evidence: 15-level nested query accepted without depth error
  Remediation: Implement query depth limiting (typically 5-10 levels)
  OWASP: A04:2021 Insecure Design | CWE-770
```
