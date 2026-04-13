# Security Misconfiguration

**Module ID:** `misconfig` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/misconfig.rs`

## What It Does

Detects common security misconfigurations across four areas: CORS policy, cookie security flags, error page information disclosure, and dangerous HTTP methods. It sends targeted probes -- a spoofed Origin header, a request for a nonexistent path, and an OPTIONS request -- to evaluate each area independently.

## Checks Performed

### CORS

| Check | Description |
|-------|-------------|
| Origin reflection | Server echoes back `https://evil-attacker.com` in `Access-Control-Allow-Origin` |
| Origin reflection + credentials | Same as above with `Access-Control-Allow-Credentials: true` |
| Wildcard + credentials | `ACAO: *` combined with `ACAC: true` (invalid/dangerous) |
| Null origin | `ACAO: null` allows sandboxed iframe bypass |

### Cookies

Only session-like cookies are checked (names containing: `session`, `sess`, `sid`, `token`, `auth`, `login`, `jwt`, `csrf`, `xsrf`, `connect.sid`, `phpsessid`, `jsessionid`, `asp.net`).

| Check | Description |
|-------|-------------|
| Missing `Secure` flag | Cookie sent over HTTPS but would also be sent over HTTP |
| Missing `HttpOnly` flag | Cookie accessible to JavaScript |
| Missing `SameSite` attribute | Cookie sent with cross-site requests |
| `SameSite=None` without `Secure` | Invalid combination rejected by modern browsers |

### Error Pages

17 stack trace and path disclosure patterns are checked against a 404 error page:

`at java.`, `at org.`, `traceback (most recent call last)`, `file "`, `in /var/www/`, `in /home/`, `stack trace:`, `stacktrace`, `microsoft.net`, `unhandled exception`, `runtime error`, `syntax error`, `fatal error`, `parse error`, `warning:</b>`, `notice:</b>`, `on line <b>`

### HTTP Methods

An OPTIONS request checks for dangerous methods in the `Allow` header: `PUT`, `DELETE`, `TRACE`, `CONNECT`. TRACE gets a separate finding for Cross-Site Tracing (XST).

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| CORS Origin Reflection | High | 942 | ACAO echoes the spoofed origin |
| CORS Origin Reflection (with credentials) | Critical | 942 | ACAO echoes origin + ACAC: true |
| CORS Wildcard with Credentials | High | 942 | ACAO: * + ACAC: true |
| CORS Allows Null Origin | Medium | 942 | ACAO: null |
| Cookie Missing Secure Flag | Medium | 614 | HTTPS target, session cookie lacks `Secure` |
| Cookie Missing HttpOnly Flag | Medium | 1004 | Session cookie lacks `HttpOnly` |
| Cookie Missing SameSite Attribute | Low | 1275 | Session cookie lacks `SameSite` |
| SameSite=None Without Secure | Medium | -- | `SameSite=None` without `Secure` flag |
| Error Page Information Disclosure | Medium | 209 | Any of the 17 patterns found in 404 body |
| Dangerous HTTP Methods Enabled | Medium | 749 | PUT, DELETE, TRACE, or CONNECT in Allow header |
| TRACE Method Enabled (Cross-Site Tracing) | Medium | 693 | TRACE specifically found in Allow header |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** Covers overly permissive CORS, missing cookie hardening, verbose error pages, and unnecessary HTTP methods -- all top indicators of misconfigured web servers and frameworks.

## How It Works

1. **CORS:** A GET request is sent with `Origin: https://evil-attacker.com`. The response headers `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` are inspected for reflection, wildcard, or null origin.
2. **Cookies:** A GET request collects all `Set-Cookie` headers. Each cookie name is tested against the session-cookie heuristic. Cookie values are truncated to 10 characters in evidence output to avoid leaking secrets.
3. **Error pages:** A GET request is sent to a random UUID path guaranteed to 404. The response body is lowercased and scanned for the 17 patterns. Only the first match is reported per error page.
4. **HTTP methods:** An OPTIONS request checks the `Allow` header. Methods are compared case-insensitively against the dangerous list.

## Example Output

```
[Critical] CORS Origin Reflection
  CORS reflects arbitrary origins AND allows credentials. An attacker can make
  authenticated cross-origin requests and read responses, leading to full account takeover.
  Evidence: Origin: https://evil-attacker.com -> Access-Control-Allow-Origin: https://evil-attacker.com | Access-Control-Allow-Credentials: true
  Remediation: Configure CORS to only allow specific trusted origins.
  OWASP: A05:2021 Security Misconfiguration | CWE-942
```
