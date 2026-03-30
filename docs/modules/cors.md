# CORS Deep Analysis

**Module ID:** `cors-deep` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/cors.rs`

## What It Does

Performs deep CORS policy analysis beyond the basic origin reflection checks in the `misconfig` module. Tests subdomain wildcard patterns, internal network origin acceptance, preflight cache duration, overly permissive method allowlists, and sensitive header exposure via CORS.

## Checks Performed

| Check | Description |
|-------|-------------|
| Subdomain origin reflection | Sends `Origin: https://evil.{target-domain}` and checks if it is reflected in ACAO |
| Internal network origins | Tests origins from localhost, 127.0.0.1, 192.168.x.x, 10.x.x.x, 172.16.x.x |
| Preflight cache duration | Checks `Access-Control-Max-Age` for excessive values (>7200 seconds) |
| Method allowlist | Flags when 2+ dangerous methods (PUT, DELETE, PATCH) are allowed in CORS |
| Sensitive header exposure | Detects authorization, set-cookie, x-csrf-token, x-api-key in exposed headers |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Subdomain CORS Bypass | High | 942 | Server reflects subdomain origin in `Access-Control-Allow-Origin` |
| Internal Network CORS Bypass | High | 942 | Server reflects internal/private network origin (localhost, RFC 1918) |
| Excessive Preflight Cache Duration | Low | 525 | `Access-Control-Max-Age` exceeds 7200 seconds (2 hours) |
| Overly Permissive CORS Methods | Low | 942 | `Access-Control-Allow-Methods` includes 2+ of PUT, DELETE, PATCH |
| Sensitive Headers Exposed via CORS | Medium | 200 | `Access-Control-Expose-Headers` contains authorization, set-cookie, or API key headers |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** Covers CORS misconfigurations that enable cross-origin data theft via subdomain takeover, internal network attacks, and sensitive header leakage.

## How It Works

1. **Subdomain test**: Sends a request with `Origin: https://evil.{domain}`. If the response `Access-Control-Allow-Origin` header matches, the server trusts any subdomain, enabling attacks via subdomain takeover.
2. **Internal origins**: Tests 5 internal network origins (localhost, 127.0.0.1, 192.168.1.1, 10.0.0.1, 172.16.0.1). Acceptance indicates SSRF or internal network attackers can make authenticated cross-origin requests.
3. **Preflight analysis**: Sends an OPTIONS request with `Access-Control-Request-Method: POST`. Checks the response for:
   - `Access-Control-Max-Age` > 7200s (extends exploitation window)
   - `Access-Control-Allow-Methods` with multiple dangerous methods
   - `Access-Control-Expose-Headers` containing sensitive header names

## Example Output

```
[High] Subdomain CORS Bypass
  The server reflects subdomain origins in CORS, allowing any subdomain
  (including attacker-controlled ones via subdomain takeover) to make
  cross-origin requests.
  Evidence: Origin: https://evil.example.com -> Access-Control-Allow-Origin: https://evil.example.com
  Remediation: Validate origins against an exact allowlist
  OWASP: A05:2021 Security Misconfiguration | CWE-942
```
