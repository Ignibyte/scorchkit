# Open Redirect Detection

**Module ID:** `redirect` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/redirect.rs`

## What It Does

Detects open redirect vulnerabilities by injecting an external URL into parameters commonly used for redirection. It uses a dedicated HTTP client that does not follow redirects, allowing it to inspect the raw `Location` header and confirm whether the server redirects to the attacker-controlled domain.

## Checks Performed

### Redirect Parameter Names (17)

Parameters are tested if their name (case-insensitive) contains any of:

`url`, `redirect`, `return`, `next`, `dest`, `destination`, `rurl`, `return_url`, `redirect_uri`, `redirect_url`, `continue`, `forward`, `goto`, `target`, `redir`, `returnto`, `return_to`

### Injection Payload

The evil URL `https://evil-attacker.com/pwned` is injected into each matching parameter.

### Detection Criteria

A finding is emitted when:
1. The response status is a redirect (3xx)
2. The `Location` header contains `evil-attacker.com`

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Open Redirect | Medium | 601 | 3xx redirect to `evil-attacker.com` in Location header |

## OWASP Coverage

**A01:2021 -- Broken Access Control.** Open redirects can be chained with phishing attacks, OAuth token theft, and SSO bypass to escalate impact beyond simple URL redirection.

## How It Works

1. A custom `reqwest::Client` is built with `redirect::Policy::none()` so that 3xx responses are captured rather than followed. The same user-agent from the scan configuration is used.
2. The target URL's own query parameters are checked first. Each parameter whose name matches the 17-name heuristic is tested.
3. The target page is then fetched (using the normal following client) and its HTML is parsed with `scraper` to extract same-origin links that contain redirect-like parameters (up to 10).
4. For each candidate parameter, the original value is replaced with `https://evil-attacker.com/pwned` and a GET request is sent via the non-following client.
5. If the response is a 3xx redirect and the `Location` header contains `evil-attacker.com`, a finding is confirmed.
6. Testing stops at the first confirmed open redirect.

## Example Output

```
[Medium] Open Redirect: next
  The parameter 'next' redirects to arbitrary external URLs.
  Evidence: Parameter: next | Payload: https://evil-attacker.com/pwned | Location: https://evil-attacker.com/pwned
  Remediation: Validate redirect destinations against an allowlist of trusted domains
  OWASP: A01:2021 Broken Access Control | CWE-601
```
