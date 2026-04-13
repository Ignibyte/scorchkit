# Reflected XSS Detection

**Module ID:** `xss` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/xss.rs`

## What It Does

Detects reflected cross-site scripting (XSS) by injecting a unique canary string into URL parameters and form fields, then analyzing whether the reflection is unencoded. It uses a three-tier severity model: confirmed XSS when a full payload is reflected, unencoded reflection when HTML metacharacters survive but specific payloads are altered, and informational when the canary is reflected but HTML-encoded.

## Checks Performed

### Phase 1: Canary Injection

The canary string `scorch8x7k2<test>"'` is injected into each parameter. The response is checked for:

- Presence of the base canary `scorch8x7k2` (confirms reflection)
- Presence of `<test>` or `"'` unescaped (confirms no HTML encoding)

### Phase 2: Payload Testing (6 payloads)

If unencoded reflection is detected, real XSS payloads are tested:

| # | Payload | Type |
|---|---------|------|
| 1 | `<scorch8x7k2>` | HTML tag injection |
| 2 | `"onmouseover="alert(1)` | Event handler (double quote) |
| 3 | `'onmouseover='alert(1)` | Event handler (single quote) |
| 4 | `<img src=x onerror=alert(1)>` | IMG tag injection |
| 5 | `<svg/onload=alert(1)>` | SVG injection |
| 6 | `javascript:alert(1)` | JavaScript URI injection |

### Injection Vectors

| Vector | Description |
|--------|-------------|
| URL parameters | Tests each query parameter in the target URL |
| Spidered links | Extracts same-origin links with parameters (up to 15) |
| Form fields | Tests non-hidden, non-submit input fields (up to 10 forms) |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Reflected XSS in Parameter | High | 79 | Full XSS payload reflected unencoded in response |
| Reflected XSS in Form Field | High | 79 | Full payload reflected from form submission |
| Unencoded Reflection in Parameter | Medium | 79 | HTML metacharacters reflected unencoded but specific payloads not matched |
| Parameter Reflection Detected | Info | 79 | Canary reflected but HTML-encoded |

## OWASP Coverage

**A03:2021 -- Injection.** Covers reflected XSS via both URL parameter and form field injection with context-aware severity grading.

## How It Works

1. **Canary test:** The string `scorch8x7k2<test>"'` is injected into each parameter. If the base canary `scorch8x7k2` is not found in the response, the parameter is skipped (not reflected).
2. **Encoding check:** If the canary is reflected, the module checks whether `<test>` or `"'` appear unescaped. If they are encoded (e.g., `&lt;test&gt;`), only an Info finding is emitted.
3. **Payload confirmation:** When unencoded reflection is detected, the 6 XSS payloads are tested sequentially. The `is_payload_reflected` function checks for direct inclusion or for the key dangerous tag portions.
4. **Form testing:** Forms are parsed with `scraper`. The canary is injected into each text-type input. Both GET and POST submission methods are respected.
5. **Early termination:** Testing stops at the first confirmed High-severity XSS per parameter and per form.

## Example Output

```
[High] Reflected XSS in Parameter: q
  The parameter 'q' reflects user input without proper encoding.
  XSS payload was reflected: IMG tag injection.
  Evidence: Parameter: q | Payload: <img src=x onerror=alert(1)> | Type: IMG tag injection
  Remediation: Encode all user input before rendering in HTML.
  OWASP: A03:2021 Injection | CWE-79
```
