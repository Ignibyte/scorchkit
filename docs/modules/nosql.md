# NoSQL Injection

**Module ID:** `nosql` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/nosql.rs`

## What It Does

Tests URL query parameters, crawled links, HTML forms, and raw JSON bodies
for NoSQL injection — primarily against MongoDB but also CouchDB, Cassandra,
and Redis. Query-parameter payloads inject MongoDB operators
(`$gt`, `$ne`, `$regex`, `$exists`) in both stringified JSON and PHP /
Express bracket notation. A dedicated JSON-body probe posts classic
authentication-bypass payloads (`{"username":{"$ne":""},"password":{"$ne":""}}`)
to the target URL.

## What It Checks

**Payloads** (12 parameter payloads): stringified-JSON operator injection
(`{"$gt":""}`, `{"$ne":""}`, `{"$regex":".*"}`, `{"$exists":true}`),
bracket-notation operators (`[$gt]=`, `[$ne]=`, `[$regex]=.*`), `$where`
JavaScript injection (`';return true;//`, `1;sleep(1000)`), boolean-based
blind (`' || '1'=='1`, `' && '1'=='2`), and CouchDB probe `_all_docs`.

**Error fingerprints** (20+): MongoDB (`mongoerror`, `mongoclient`,
`bsonobj`, `$where`, `mongoose`), CouchDB (`couchdb`, `_design/`), Cassandra
(`cqlexception`), Redis (`redis.exception`), generic (`json parse error`,
`syntaxerror: unexpected`).

| Condition | Severity |
|-----------|----------|
| NoSQL error fingerprint matches query-param response | High |
| 500 response to a `$`-containing payload | Medium |
| Boolean-payload response size differs by > 50 % from baseline | Medium |
| NoSQL error triggered by JSON body injection | Critical |
| NoSQL error in form field reflection | High |

## How to Run

```
scorchkit run 'https://example.com/search?q=test' --modules nosql
scorchkit run https://example.com/api/login --modules nosql
```

The module crawls for parameterized links (up to 20) and forms (up to 10),
tests each, and additionally posts three JSON auth-bypass payloads to the
target URL.

## Limitations

- Error fingerprints are English-only and database-error-message-dependent.
  Production apps that return generic 500s will only be caught by the
  status-based or size-based blind heuristics.
- Form-field testing uses only the first four payloads per field.
- Stops at the first matching payload per parameter.
- JSON-body probing uses credentials-shaped payloads only (`username` /
  `password`). Endpoints with a different schema will reject them.

## OWASP / CWE

- **A03:2021 Injection**, CWE-943 (Improper Neutralization of Special
  Elements in Data Query Logic).
