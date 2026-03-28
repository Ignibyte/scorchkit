# CSRF Detection

**Module ID:** `csrf` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/csrf.rs`

## What It Does

Scans the target page for HTML forms that use the POST method and checks whether they include a CSRF token. It parses the DOM with `scraper`, inspects hidden input fields for common CSRF token names, and also checks for meta-tag-based CSRF patterns used by single-page applications.

## Checks Performed

| Check | Description |
|-------|-------------|
| Hidden input CSRF token | Looks for a hidden `<input>` with a name matching any of the 11 known CSRF token field names |
| Meta tag CSRF token | Checks for `<meta name="csrf-token">` or `<meta name="_token">` (SPA pattern) |

### CSRF Token Field Names

The following 11 field name patterns are recognized (matched as substrings against the lowercased input name):

`csrf`, `xsrf`, `_token`, `token`, `authenticity_token`, `csrfmiddlewaretoken`, `__requestverificationtoken`, `antiforgery`, `nonce`, `_csrf`, `csrf_token`

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Missing CSRF Token | Medium | 352 | A POST form has no hidden input matching any CSRF token name and no meta tag CSRF token |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** Missing CSRF protection on state-changing forms allows attackers to craft malicious pages that submit authenticated requests on behalf of victims.

## How It Works

1. A GET request fetches the target page HTML.
2. The HTML is parsed into a DOM using `scraper::Html::parse_document`.
3. All `<form>` elements are selected. Only forms with `method="post"` (case-insensitive) are evaluated.
4. For each POST form, all `<input>` elements are iterated. If any hidden input's `name` attribute contains one of the 11 CSRF token patterns, the form is considered protected.
5. If no hidden input matches, the module checks for `<meta name="csrf-token">` or `<meta name="_token">` tags in the document head (common in Rails, Laravel, and SPA frameworks).
6. If neither a hidden field nor a meta tag CSRF token is found, a finding is emitted with the form's action URL.

## Example Output

```
[Medium] Missing CSRF Token: POST form action="/account/settings"
  A POST form lacks CSRF token protection. An attacker could craft a page that
  submits this form on behalf of an authenticated user.
  Evidence: Form: method=POST action="/account/settings" | No hidden CSRF token field found
  Remediation: Add a CSRF token to all state-changing forms. Use your framework's built-in CSRF protection.
  OWASP: A05:2021 Security Misconfiguration | CWE-352
```
