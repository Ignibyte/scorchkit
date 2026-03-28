# Rate Limit Testing

**Module ID:** `ratelimit` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/ratelimit.rs`

## What It Does

Tests authentication endpoints for brute-force protection by sending rapid failed login attempts. It probes 11 common login paths, and when one is found, submits 10 consecutive POST requests with invalid credentials to determine whether rate limiting, CAPTCHA, or account lockout mechanisms are in place.

## Checks Performed

### Login Paths Probed (11)

| # | Path |
|---|------|
| 1 | `/login` |
| 2 | `/signin` |
| 3 | `/auth/login` |
| 4 | `/user/login` |
| 5 | `/admin/login` |
| 6 | `/wp-login.php` |
| 7 | `/administrator` |
| 8 | `/api/auth/login` |
| 9 | `/api/login` |
| 10 | `/api/v1/auth/login` |
| 11 | `/account/login` |

### Login Endpoint Detection

A path is considered a valid login endpoint if an initial GET request returns HTTP 200 or 302.

### Brute-Force Test

10 POST requests are sent with form data `username=admin&password=wrong_password_test`.

### Blocking Detection

The endpoint is considered protected if any of these occur:
- HTTP 429 (Too Many Requests) response
- HTTP 403 (Forbidden) response
- Response body contains: `captcha`, `rate limit`, `too many`, `locked`, or `try again later`
- Connection error (endpoint stops responding)

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| No Rate Limiting | Medium | 307 | All 10 failed login attempts accepted without blocking |
| Rate Limiting Active | Info | -- | Endpoint blocked before or at 10 attempts |

## OWASP Coverage

**A07:2021 -- Identification and Authentication Failures.** Missing rate limiting on authentication endpoints enables credential stuffing and brute-force attacks against user accounts.

## How It Works

1. Each of the 11 login paths is appended to the target base URL and probed with a GET request.
2. The first path returning HTTP 200 or 302 is selected as the login endpoint.
3. 10 rapid POST requests are sent with hardcoded invalid credentials (`admin` / `wrong_password_test`) as form-encoded data.
4. After each response, the module checks for blocking indicators: HTTP 429 or 403 status codes, or body text containing CAPTCHA/lockout keywords.
5. If all 10 requests complete without any blocking indicator, a Medium finding is emitted reporting the absence of brute-force protection.
6. If blocking is detected, an Info finding confirms that rate limiting is active, along with the number of requests before blocking occurred.
7. Only the first discovered login endpoint is tested.

## Example Output

```
[Medium] No Rate Limiting on /login
  The login endpoint at /login accepted 10 failed login attempts without any
  rate limiting, CAPTCHA, or account lockout.
  Evidence: Sent 10 POST requests with wrong credentials - all returned HTTP 200
  Remediation: Implement rate limiting, account lockout, or CAPTCHA after 3-5 failed attempts
  OWASP: A07:2021 Identification and Authentication Failures | CWE-307
```
