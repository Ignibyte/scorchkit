# API Security (OWASP Top 10)

**Module ID:** `api-security` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/api.rs`

## What It Does

Tests REST APIs for vulnerabilities from the OWASP API Security Top 10. Checks for excessive data exposure in API responses, discovers shadow/undocumented API versions, tests for mass assignment via privileged field injection, verifies rate limiting on authentication endpoints, and probes for content negotiation confusion.

## Checks Performed

| Check | Description |
|-------|-------------|
| Excessive data exposure | Fetches user profile endpoints and checks for sensitive fields (password, token, api_key, ssn, etc.) |
| Shadow API discovery | Probes versioned API paths (`/api/v1/`, `/api/internal/`, `/api/legacy/`, etc.) |
| Mass assignment | POSTs to registration endpoints with extra privileged fields (`admin`, `role`, `is_superuser`) |
| Rate limiting | Sends 10 rapid POST requests to auth endpoints, checks for HTTP 429 |
| Content negotiation | Sends `Accept: application/xml` to detect XML response capability (XXE risk) |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Excessive Data Exposure | Medium | 213 | API endpoint returns sensitive fields (password, token, api_key, etc.) |
| Shadow API Versions Discovered | Low | 912 | 2+ versioned API paths respond (200, 301, or 302) |
| Potential Mass Assignment | Medium | 915 | Registration endpoint accepts and reflects privileged fields |
| No Rate Limiting on Auth Endpoint | Medium | 770 | Auth endpoint accepts 10 rapid requests without returning 429 |
| Content Negotiation Returns XML | Low | 436 | API returns XML content when requested via Accept header |

## OWASP Coverage

**OWASP API Security Top 10.** Covers API3 (Excessive Data Exposure), API4 (Lack of Resources & Rate Limiting), API6 (Mass Assignment), API8 (Injection via content negotiation), and API9 (Improper Assets Management via shadow APIs).

## How It Works

1. **Data exposure**: Fetches `/api/me`, `/api/user`, `/api/profile`, `/api/account` and scans response bodies for 12 sensitive field patterns (e.g., `"password"`, `"api_key"`, `"credit_card"`).
2. **Shadow APIs**: Probes 14 versioned/internal API paths. Flags when 2+ paths respond, indicating undocumented or deprecated API versions.
3. **Mass assignment**: POSTs JSON with legitimate fields plus 8 privileged fields (`admin`, `role`, `is_admin`, `is_staff`, `is_superuser`, `verified`, `approved`, `privilege`) to registration endpoints. Checks if privileged fields appear in the response.
4. **Rate limiting**: Sends 10 rapid POST requests with dummy credentials to `/api/login`, `/api/auth`, `/api/token`, `/api/signin`. Reports if no HTTP 429 is received.
5. **Content negotiation**: Sends a request with `Accept: application/xml`. If the response Content-Type contains `xml`, the API may be vulnerable to XXE.

## Example Output

```
[Medium] No Rate Limiting on Auth Endpoint: /api/login
  The authentication endpoint '/api/login' accepted 10 rapid requests without
  returning HTTP 429 (Too Many Requests). This enables credential brute-force attacks.
  Evidence: 10 rapid POST requests to /api/login -- no 429 response
  Remediation: Implement rate limiting on authentication endpoints
  OWASP: API4: Lack of Resources & Rate Limiting | CWE-770
```
