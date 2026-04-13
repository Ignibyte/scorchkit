# HTTP Security Headers

**Module ID:** `headers` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/headers.rs`

## What It Does

Analyzes HTTP response headers to identify missing, misconfigured, or deprecated security headers. The module sends a single GET request to the target URL and evaluates the response headers against 15 specific security checks, covering transport security, content injection defenses, framing protections, and information disclosure.

## Checks Performed

| # | Header | Check | Condition |
|---|--------|-------|-----------|
| 1 | `Strict-Transport-Security` | Missing HSTS | Header absent |
| 2 | `Strict-Transport-Security` | Weak max-age | `max-age` < 31536000 (1 year) |
| 3 | `Strict-Transport-Security` | No includeSubDomains | Directive absent from value |
| 4 | `Content-Security-Policy` | Missing CSP | Header absent |
| 5 | `Content-Security-Policy` | unsafe-inline | Value contains `'unsafe-inline'` |
| 6 | `Content-Security-Policy` | unsafe-eval | Value contains `'unsafe-eval'` |
| 7 | `Content-Security-Policy` | Wildcard source | Contains `*` but not `*.` (subdomain wildcard) |
| 8 | `X-Frame-Options` | Missing framing protection | Neither `X-Frame-Options` nor CSP `frame-ancestors` is set |
| 9 | `X-Content-Type-Options` | Missing nosniff | Header absent |
| 10 | `Referrer-Policy` | Missing | Header absent |
| 11 | `Referrer-Policy` | Weak policy | Value is `unsafe-url` or `no-referrer-when-downgrade` |
| 12 | `Permissions-Policy` | Missing | Neither `Permissions-Policy` nor `Feature-Policy` is set |
| 13 | `X-XSS-Protection` | Deprecated header active | Header present with value other than `0` |
| 14 | `Server` | Version disclosure | Value contains `/` or numeric characters |
| 15 | `X-Powered-By` | Technology disclosure | Header present |

## Findings

| Title | Severity | Description |
|-------|----------|-------------|
| Missing Strict-Transport-Security (HSTS) Header | High | No HSTS header; allows HTTPS-to-HTTP downgrade attacks |
| Weak HSTS max-age Value | Low | max-age below 1 year provides limited protection |
| HSTS Missing includeSubDomains Directive | Info | Subdomains not covered by HSTS policy |
| Missing Content-Security-Policy (CSP) Header | Medium | No CSP to prevent XSS, clickjacking, and code injection |
| CSP Contains 'unsafe-inline' | Medium | Inline scripts/styles allowed, weakening XSS protection |
| CSP Contains 'unsafe-eval' | Medium | Dynamic code execution (eval) permitted by policy |
| CSP Contains Wildcard Source | Medium | Resources loadable from any origin |
| Missing X-Frame-Options Header | Medium | No clickjacking protection via framing controls |
| Missing X-Content-Type-Options Header | Low | Browser MIME-sniffing not prevented |
| Missing Referrer-Policy Header | Low | Full URLs may leak to third-party sites |
| Weak Referrer-Policy Value | Low | Policy set to unsafe-url or no-referrer-when-downgrade |
| Missing Permissions-Policy Header | Info | Browser features (camera, mic, geo) not restricted |
| Deprecated X-XSS-Protection Header Active | Info | Legacy header can introduce vulnerabilities in older browsers |
| Server Version Disclosure | Low | Server header reveals version information |
| X-Powered-By Header Disclosure | Low | Technology stack exposed via X-Powered-By |

## OWASP Coverage

- **A05:2021 -- Security Misconfiguration**: All 15 checks map to this category, which covers missing security hardening including HTTP header configuration.

### CWE References

| CWE | Name | Applies To |
|-----|------|------------|
| CWE-319 | Cleartext Transmission of Sensitive Information | Missing HSTS |
| CWE-693 | Protection Mechanism Failure | Missing/weak CSP, missing X-Content-Type-Options |
| CWE-1021 | Improper Restriction of Rendered UI Layers | Missing X-Frame-Options |
| CWE-200 | Exposure of Sensitive Information | Server version disclosure, X-Powered-By |

## How It Works

1. Sends a single GET request to the target URL using the shared HTTP client.
2. Clones the response headers and passes them through 9 independent check functions.
3. Each check function inspects a specific header or set of related headers.
4. For headers that are present, the module parses the value to identify weak configurations (e.g., short HSTS max-age, unsafe CSP directives).
5. The X-Frame-Options check is CSP-aware: it skips the finding if `frame-ancestors` is present in the Content-Security-Policy header.
6. All findings include remediation guidance and OWASP/CWE references where applicable.

## Example Output

```
[HIGH] Missing Strict-Transport-Security (HSTS) Header
  URL: https://example.com/
  The server does not set the Strict-Transport-Security header. This allows
  man-in-the-middle attacks by downgrading HTTPS to HTTP.
  Remediation: Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  OWASP: A05:2021 Security Misconfiguration
  CWE: 319

[MEDIUM] CSP Contains 'unsafe-inline'
  URL: https://example.com/
  The CSP policy allows 'unsafe-inline', which significantly weakens XSS protection.
  Evidence: Content-Security-Policy: default-src 'self' 'unsafe-inline'
  Remediation: Remove 'unsafe-inline' and use nonces or hashes for inline scripts
  OWASP: A05:2021 Security Misconfiguration
  CWE: 693

[LOW] Server Version Disclosure
  URL: https://example.com/
  The Server header discloses version information: 'Apache/2.4.52'. This helps
  attackers identify known vulnerabilities.
  Evidence: Server: Apache/2.4.52
  Remediation: Remove or minimize the Server header value
  OWASP: A05:2021 Security Misconfiguration
  CWE: 200
```
