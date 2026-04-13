# Access Control Testing

**Module ID:** `acl` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/acl.rs`

## What It Does

Tests for missing or bypassable access controls. Probes common administrative paths for unauthorized access, tests HTTP method override headers for authorization bypass, attempts path normalization tricks to circumvent path-based access controls, and checks for forced browsing to sequential resource IDs (IDOR).

## Checks Performed

| Check | Description |
|-------|-------------|
| Admin path discovery | Probes 20 common admin paths (`/admin`, `/dashboard`, `/wp-admin`, etc.) for HTTP 200 |
| HTTP method override | Sends GET with `X-HTTP-Method-Override: DELETE` and variants to detect bypass |
| Path traversal bypass | Tests URL normalization tricks: double slash, dot segments, URL-encoded dots, semicolons, case variation |
| Forced browsing | Probes sequential API resource IDs (`/api/users/1`, `/api/user/2`, etc.) for data exposure |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Admin Path Accessible | Medium | 425 | Admin path returns HTTP 200 without authentication |
| HTTP Method Override Accepted | High | 650 | Server processes method override header (405 or body contains override evidence) |
| Path-Based Auth Bypass | High | 22 | Path normalization variant (`//admin`, `/%2e/admin`, `/ADMIN`, etc.) returns HTTP 200 |
| Forced Browsing (IDOR) | Medium | 425 | API endpoint returns user data (email, username, name, id) for sequential IDs without auth |

## OWASP Coverage

**A01:2021 -- Broken Access Control.** Covers admin panel exposure, method-based authorization bypass, path normalization circumvention, and insecure direct object references via predictable resource identifiers.

## How It Works

1. **Admin paths**: Sends GET requests to 20 common administrative paths. HTTP 200 indicates the path is accessible without authentication.
2. **Method override**: Sends GET requests with `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, and `_method` headers set to `DELETE`. A 405 response or body referencing "delete" suggests the override was processed.
3. **Path bypass**: Tests 8 URL normalization variants against `/admin` (double slash, dot segments, URL encoding, semicolons, case variation, trailing spaces). HTTP 200 indicates the path-based authorization was bypassed.
4. **Forced browsing**: Probes `/api/users/`, `/api/user/`, `/api/accounts/`, `/api/profile/` with IDs 1 and 2. Checks response bodies for JSON fields indicating user data exposure.

## Example Output

```
[High] HTTP Method Override Accepted: X-HTTP-Method-Override
  The server processes the 'X-HTTP-Method-Override: DELETE' header, potentially
  allowing attackers to bypass method-based access controls.
  Evidence: GET with X-HTTP-Method-Override: DELETE -> HTTP 405
  Remediation: Disable HTTP method override headers in production
  OWASP: A01:2021 Broken Access Control | CWE-650
```
