# Auth & Session Management

**Module ID:** `auth-session` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/auth.rs`

## What It Does

Tests session lifecycle security by analyzing session cookies for entropy, expiration, and fixation vulnerabilities. Passive checks (entropy, expiry, multiple cookies) run against all targets. Credential-gated checks (session fixation, logout invalidation) require `AuthConfig` to be configured and test session behavior before and after authentication.

## Checks Performed

| Check | Description |
|-------|-------------|
| Session ID entropy | Computes Shannon entropy of session cookie values; flags short or low-diversity IDs |
| Session expiry | Checks `Max-Age` and `Expires` directives for excessive lifetimes |
| Multiple session cookies | Detects fragmented session management across multiple cookies |
| Session fixation | Compares session cookies before and after authentication (requires credentials) |
| Logout invalidation | Hits logout endpoints then re-authenticates to check session reuse (requires credentials) |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Extremely Short Session ID | High | 330 | Session cookie value is fewer than 8 characters |
| Low Entropy Session ID | High | 330 | Shannon entropy below 3.0 bits/char |
| Excessive Session Lifetime | Low | 613 | `Max-Age` exceeds 86400 seconds (24 hours) |
| Effectively Permanent Session | Medium | 613 | `Expires` date set to year 2098, 2099, or 9999 |
| Multiple Session Cookies Detected | Low | 613 | More than one session cookie set by the target |
| Session Fixation | High | 384 | Session cookie unchanged after authentication |
| Session Not Invalidated After Logout | Medium | 613 | Session token still valid after hitting logout endpoint |

## OWASP Coverage

**A07:2021 -- Identification and Authentication Failures.** Covers predictable session identifiers, session fixation, missing session expiration, and incomplete logout functionality.

## How It Works

1. **Cookie discovery**: Fetches the target URL and extracts `Set-Cookie` headers. Filters for session-like cookies using a heuristic matching common names (`PHPSESSID`, `JSESSIONID`, `connect.sid`, `auth_token`, `laravel_session`, etc.).
2. **Entropy analysis**: Computes Shannon entropy (bits per character) of each session cookie value. Values below 3.0 bits/char or shorter than 8 characters are flagged as predictable.
3. **Expiry analysis**: Checks `Max-Age` (>24h = excessive) and `Expires` (far-future years = effectively permanent). Session cookies (no expiry) are considered acceptable.
4. **Session fixation**: Sends an authenticated request using configured credentials (bearer token, basic auth, cookies, or custom headers). Compares pre-auth and post-auth session cookie values. Identical values indicate fixation.
5. **Logout validation**: Hits common logout paths (`/logout`, `/signout`, `/api/auth/logout`, etc.), then re-sends the authenticated request. If the response is still HTTP 200, the session was not server-side invalidated.

## Example Output

```
[High] Session Fixation: PHPSESSID
  The session cookie 'PHPSESSID' retains the same value before and after
  authentication. An attacker can set a known session ID in the victim's
  browser, then hijack the session after the victim logs in.
  Evidence: Cookie 'PHPSESSID' unchanged after authentication
  Remediation: Regenerate the session ID after every authentication event
  OWASP: A07:2021 Identification and Authentication Failures | CWE-384
```
